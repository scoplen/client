// SPDX-License-Identifier: Apache-2.0
//! Native D-154 preparation and immutable D-151 Device submissions.

mod types;
pub use types::*;

use std::{collections::BTreeSet, io::Read as _, path::Path, sync::Weak};

use scoplen_api::inventory_import::{
    InventoryImportFields, InventoryImportRequest, InventoryImportResult, InventoryImportRow,
    InventoryOpenSshCandidate, MAX_INVENTORY_CSV_BYTES, MAX_INVENTORY_IMPORT_RESULT_BYTES,
    parse_inventory_csv, parse_inventory_openssh,
};
use zeroize::Zeroizing;

use super::*;
use crate::store::team_inventory_import::TeamImportRecord;

const WINDOW_MS: u64 = 86_400_000;

pub(in crate::personal_server) struct ImportPreviewState {
    store: Weak<Store>,
    auth_generation: i64,
    view: TeamImportPreview,
    rows: Vec<Option<InventoryImportFields>>,
}

impl PersonalServer {
    /// List only saved destination ids for this Account, including lost memberships.
    /// Recovery-only destinations do not grant authority to create a new import.
    pub fn retained_team_inventory_imports(
        &self,
        store: &Store,
        cursor: Option<&str>,
    ) -> Result<TeamImportSavedPage, TeamImportError> {
        let identity = record(store)?;
        let after = cursor.map(parse_id).transpose()?;
        let mut ids = store.team_import_organizations(&identity, after).map_err(storage)?;
        let more = ids.len() > 100;
        ids.truncate(100);
        let next_cursor = if more { ids.last().map(Uuid::to_string) } else { None };
        Ok(TeamImportSavedPage {
            organization_ids: ids.iter().map(Uuid::to_string).collect(),
            next_cursor,
        })
    }

    /// Prepare one complete source through the published parser, without network or identities.
    /// The returned metadata is an intentional disclosure preview, not diagnostic text.
    pub fn preview_team_inventory_import(
        &self,
        store: &Arc<Store>,
        organization_id: &str,
        source: TeamImportSource,
        input: &[u8],
    ) -> Result<TeamImportPreview, TeamImportError> {
        let _operation = self.operation.try_lock().map_err(|_| TeamImportError::Busy)?;
        let mut current = self.import_preview.lock().map_err(|_| TeamImportError::Busy)?;
        *current = None;
        let identity = record(store)?;
        let organization = parse_id(organization_id)?;
        if store.personal_admission(&identity).map_err(storage)?.is_none() {
            return Err(PersonalServerError::AdmissionUnverified.into());
        }
        let candidates = match source {
            TeamImportSource::Csv => parse_inventory_csv(input)
                .map_err(|error| TeamImportError::Source(diagnostic(error)))?
                .into_iter()
                .enumerate()
                .map(|(index, fields)| InventoryOpenSshCandidate::Ready {
                    candidate: index + 1,
                    fields,
                })
                .collect(),
            TeamImportSource::OpenSsh => parse_inventory_openssh(input)
                .map_err(|error| TeamImportError::Source(diagnostic(error)))?,
        };
        let mut rows = Vec::with_capacity(candidates.len());
        let candidates = candidates
            .into_iter()
            .map(|candidate| match candidate {
                InventoryOpenSshCandidate::Ready { candidate, fields } => {
                    let projection = fields_view(&fields);
                    rows.push(Some(fields));
                    TeamImportCandidate::Ready { ordinal: candidate as u32, fields: projection }
                }
                InventoryOpenSshCandidate::Blocked { diagnostic: error } => {
                    rows.push(None);
                    TeamImportCandidate::Blocked {
                        ordinal: error.candidate as u32,
                        diagnostic: diagnostic(error),
                    }
                }
            })
            .collect();
        let view = TeamImportPreview {
            preview_id: new_id()?.to_string(),
            origin: identity.origin,
            account_id: identity.account_id.to_string(),
            organization_id: organization.to_string(),
            source,
            candidates,
        };
        *current = Some(ImportPreviewState {
            store: Arc::downgrade(store),
            auth_generation: identity.auth_generation,
            view: view.clone(),
            rows,
        });
        Ok(view)
    }

    /// Read only one explicitly chosen regular file, bounded before shared preparation.
    /// Filesystem paths and raw source never cross the successful native projection.
    pub fn preview_team_inventory_import_file(
        &self,
        store: &Arc<Store>,
        organization_id: &str,
        source: TeamImportSource,
        path: &Path,
    ) -> Result<TeamImportPreview, TeamImportError> {
        *self.import_preview.lock().map_err(|_| TeamImportError::Busy)? = None;
        if !std::fs::metadata(path).map_err(|_| TeamImportError::FileUnavailable)?.is_file() {
            return Err(TeamImportError::FileUnavailable);
        }
        let file = std::fs::File::open(path).map_err(|_| TeamImportError::FileUnavailable)?;
        if !file.metadata().map_err(|_| TeamImportError::FileUnavailable)?.is_file() {
            return Err(TeamImportError::FileUnavailable);
        }
        let mut input = Zeroizing::new(Vec::new());
        file.take((MAX_INVENTORY_CSV_BYTES + 1) as u64)
            .read_to_end(&mut input)
            .map_err(|_| TeamImportError::FileUnavailable)?;
        self.preview_team_inventory_import(store, organization_id, source, &input)
    }

    /// Invalidate only this captured preview; late cleanup cannot clear its replacement.
    pub fn clear_team_inventory_import_preview(
        &self,
        store: &Arc<Store>,
        preview_id: &str,
    ) -> Result<(), TeamImportError> {
        let mut current = self.import_preview.lock().map_err(|_| TeamImportError::Busy)?;
        if current.as_ref().is_some_and(|preview| {
            preview.view.preview_id == preview_id
                && preview.store.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, store))
        }) {
            *current = None;
        }
        Ok(())
    }

    /// Allocate identities once for an explicit Ready subset and durably retain canonical rows.
    pub fn prepare_team_inventory_import(
        &self,
        store: &Arc<Store>,
        organization_id: &str,
        preview_id: &str,
        selected: Vec<u32>,
    ) -> Result<TeamImportPending, TeamImportError> {
        let _operation = self.operation.try_lock().map_err(|_| TeamImportError::Busy)?;
        let identity = record(store)?;
        let organization = parse_id(organization_id)?;
        let mut current = self.import_preview.lock().map_err(|_| TeamImportError::Busy)?;
        let preview = current.as_ref().ok_or(TeamImportError::StalePreview)?;
        if preview.view.preview_id != preview_id
            || preview.view.organization_id != organization_id
            || preview.auth_generation != identity.auth_generation
            || preview.view.origin != identity.origin
            || preview.view.account_id != identity.account_id.to_string()
            || !preview.store.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, store))
        {
            return Err(TeamImportError::StalePreview);
        }
        if store.team_import_pending(&identity, organization).map_err(storage)?.is_some() {
            return Err(TeamImportError::Pending);
        }
        let chosen: BTreeSet<_> = selected.iter().copied().collect();
        if chosen.is_empty()
            || chosen.len() != selected.len()
            || chosen.iter().any(|ordinal| {
                *ordinal == 0 || preview.rows.get(*ordinal as usize - 1).is_none_or(Option::is_none)
            })
        {
            return Err(TeamImportError::InvalidSelection);
        }
        let rows = preview
            .rows
            .iter()
            .enumerate()
            .filter_map(|(index, fields)| {
                chosen.contains(&(index as u32 + 1)).then_some(fields.as_ref()).flatten()
            })
            .map(|fields| {
                Ok(InventoryImportRow {
                    host_id: new_id()?,
                    access_profile_id: new_id()?,
                    fields: fields.clone(),
                })
            })
            .collect::<Result<Vec<_>, TeamImportError>>()?;
        let request = InventoryImportRequest { rows };
        let pending = TeamImportRecord {
            organization,
            operation: new_id()?,
            payload: SecretVec::new(
                request.to_json().map_err(|_| TeamImportError::InvalidRequest)?,
            ),
            phase: 0,
            first_attempt_ms: None,
            response: None,
            reviewed_ms: None,
        };
        if !store.prepare_team_import(&identity, &pending).map_err(storage)? {
            return Err(TeamImportError::Pending);
        }
        *current = None;
        pending_view(&identity, &pending, now_ms()?)
    }

    /// Read the original batch after restart without authentication, replay or replacement.
    pub fn pending_team_inventory_import(
        &self,
        store: &Store,
        organization_id: &str,
    ) -> Result<Option<TeamImportPending>, TeamImportError> {
        let identity = record(store)?;
        store
            .team_import_pending(&identity, parse_id(organization_id)?)
            .map_err(storage)?
            .map(|pending| pending_view(&identity, &pending, now_ms()?))
            .transpose()
    }

    /// Explicitly submit or confirm only the saved original Device operation and exact rows.
    pub async fn submit_team_inventory_import(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        operation_id: &str,
    ) -> Result<TeamImportPending, TeamImportError> {
        let _operation = self.operation.try_lock().map_err(|_| TeamImportError::Busy)?;
        let identity = record(&store)?;
        let pending = load(&store, &identity, organization_id, operation_id)?;
        let current = pending_view(&identity, &pending, now_ms()?)?;
        match current.phase {
            TeamImportPhase::Confirmed => return Ok(current),
            TeamImportPhase::Expired => return Err(TeamImportError::Expired),
            _ => {}
        }
        let request = request(&pending)?;
        let path = format!("/api/v1/orgs/{}/inventory/imports", pending.organization);
        let session =
            self.team_session(&store, DeviceAccessOperation::InventoryImportCreate).await?;
        let proof = session.proof("POST", &path)?;
        let dispatch_ms = now_ms()?;
        if pending_view(&session.identity, &pending, dispatch_ms)?.phase == TeamImportPhase::Expired
        {
            return Err(TeamImportError::Expired);
        }
        if !store
            .dispatch_team_import(&session.identity, &pending, &session.access, dispatch_ms)
            .map_err(storage)?
        {
            return Err(TeamImportError::Unknown);
        }
        let sent = load(&store, &session.identity, organization_id, operation_id)?;
        let response = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_exchange(
                &session.identity.origin,
                &path,
                reqwest::Method::POST,
                Some(sent.payload.as_bytes()),
                session.token()?,
                &proof,
                Some(sent.operation),
                None,
                MAX_INVENTORY_IMPORT_RESULT_BYTES,
            )
            .await;
        store
            .invalidate_team_assets(&session.identity, pending.organization, None)
            .map_err(storage)?;
        let response = match response {
            Ok(response) => response,
            Err(PersonalServerError::ConnectionBeforeRequest) if pending.phase == 0 => {
                finish(&store, &session, &sent, None)?;
                return Err(PersonalServerError::ConnectionBeforeRequest.into());
            }
            Err(_) => return Err(TeamImportError::Unknown),
        };
        session.current(&store).map_err(|_| TeamImportError::Unknown)?;
        if response.status == 201 {
            let result = InventoryImportResult::from_http_json(
                response.body.as_bytes(),
                response.cache_control.as_deref(),
                response.pragma.as_deref(),
                &request,
            )
            .map_err(|_| TeamImportError::Unknown)?;
            let canonical = result.to_json().map_err(|_| TeamImportError::Unknown)?;
            finish(&store, &session, &sent, Some(&canonical))?;
            return self
                .pending_team_inventory_import(&store, organization_id)?
                .ok_or(TeamImportError::Missing);
        }
        let problem = problem(&response).map_err(|_| TeamImportError::Unknown)?;
        let error = super::authoring::authoring_problem(&problem)?;
        if pending.phase == 0
            && !problem.changed
            && problem.code.as_str() != "organization.conflict"
        {
            finish(&store, &session, &sent, None)?;
        }
        if problem.status == 401 {
            store
                .invalidate_personal_session(&session.identity, &session.access)
                .map_err(storage)?;
        }
        Err(error.into())
    }

    /// Explicitly review current member inventory; even a refused read can precede expired archive.
    pub async fn review_team_inventory_import(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        operation_id: &str,
    ) -> Result<TeamImportInventoryReview, TeamImportError> {
        let identity = record(&store)?;
        let original = load(&store, &identity, organization_id, operation_id)?;
        let result = self.refresh_team_assets(store.clone(), organization_id).await;
        if !store.review_team_import(&identity, &original, now_ms()?).map_err(storage)? {
            return Err(TeamImportError::Missing);
        }
        let pending = self
            .pending_team_inventory_import(&store, organization_id)?
            .ok_or(TeamImportError::Missing)?;
        Ok(match result {
            Ok(inventory) => {
                TeamImportInventoryReview { pending, inventory: Some(inventory), error: None }
            }
            Err(error) => {
                TeamImportInventoryReview { pending, inventory: None, error: Some(error) }
            }
        })
    }

    /// Cancel a prepared batch, dismiss confirmed history, or explicitly archive reviewed expiry.
    pub fn discard_team_inventory_import(
        &self,
        store: &Store,
        organization_id: &str,
        operation_id: &str,
    ) -> Result<(), TeamImportError> {
        let _operation = self.operation.try_lock().map_err(|_| TeamImportError::Busy)?;
        let identity = record(store)?;
        let pending = load(store, &identity, organization_id, operation_id)?;
        let view = pending_view(&identity, &pending, now_ms()?)?;
        match view.phase {
            TeamImportPhase::Unknown => return Err(TeamImportError::Unknown),
            TeamImportPhase::Expired if !view.can_archive => {
                return Err(TeamImportError::ReviewRequired);
            }
            _ => {}
        }
        if !store.discard_team_import(&identity, &pending, now_ms()?).map_err(storage)? {
            return Err(TeamImportError::Missing);
        }
        Ok(())
    }
}

fn new_id() -> Result<Uuid, TeamImportError> {
    scoplen_model::new_uuid_v7().map_err(|_| TeamImportError::InvalidRequest)
}

fn diagnostic(value: impl Serialize) -> TeamImportDiagnostic {
    let value = serde_json::to_value(value).unwrap_or_default();
    TeamImportDiagnostic {
        code: value["kind"].as_str().unwrap_or("invalid_input").into(),
        record: value["record"].as_u64().and_then(|value| u32::try_from(value).ok()),
        line: value["line"].as_u64().and_then(|value| u32::try_from(value).ok()),
        field: value["field"].as_str().map(str::to_owned),
    }
}

fn fields_view(fields: &InventoryImportFields) -> TeamImportFields {
    TeamImportFields {
        name: fields.name.clone(),
        address: fields.address.clone(),
        port: fields.port,
        username: fields.username.clone(),
        login_name: fields.login_name.clone(),
    }
}

fn request(pending: &TeamImportRecord) -> Result<InventoryImportRequest, TeamImportError> {
    let request = InventoryImportRequest::from_json(pending.payload.as_bytes())
        .map_err(|_| TeamImportError::InvalidRequest)?;
    if request.to_json().map_err(|_| TeamImportError::InvalidRequest)? != pending.payload.as_bytes()
    {
        return Err(TeamImportError::InvalidRequest);
    }
    Ok(request)
}

fn load(
    store: &Store,
    identity: &PersonalRecord,
    organization: &str,
    operation: &str,
) -> Result<TeamImportRecord, TeamImportError> {
    let pending = store
        .team_import_pending(identity, parse_id(organization)?)
        .map_err(storage)?
        .ok_or(TeamImportError::Missing)?;
    if pending.operation != parse_id(operation)? {
        return Err(TeamImportError::Missing);
    }
    Ok(pending)
}

fn pending_view(
    identity: &PersonalRecord,
    pending: &TeamImportRecord,
    now_ms: u64,
) -> Result<TeamImportPending, TeamImportError> {
    let request = request(pending)?;
    let expired =
        pending.first_attempt_ms.is_some_and(|first| now_ms.saturating_sub(first) >= WINDOW_MS);
    let phase = if let Some(response) = &pending.response {
        InventoryImportResult::from_json(response.as_bytes())
            .and_then(|result| result.validate_for_request(&request))
            .map_err(|_| TeamImportError::InvalidRequest)?;
        TeamImportPhase::Confirmed
    } else if expired {
        TeamImportPhase::Expired
    } else if pending.phase == 0 {
        TeamImportPhase::Prepared
    } else {
        TeamImportPhase::Unknown
    };
    Ok(TeamImportPending {
        origin: identity.origin.clone(),
        account_id: identity.account_id.to_string(),
        organization_id: pending.organization.to_string(),
        operation_id: pending.operation.to_string(),
        phase,
        rows: request
            .rows
            .iter()
            .map(|row| TeamImportRow {
                host_id: row.host_id.to_string(),
                login_id: row.access_profile_id.to_string(),
                fields: fields_view(&row.fields),
            })
            .collect(),
        can_archive: expired
            && pending
                .reviewed_ms
                .zip(pending.first_attempt_ms)
                .is_some_and(|(reviewed, first)| reviewed.saturating_sub(first) >= WINDOW_MS),
    })
}

fn finish(
    store: &Store,
    session: &TeamSession,
    sent: &TeamImportRecord,
    response: Option<&[u8]>,
) -> Result<(), TeamImportError> {
    if !store
        .finish_team_import(&session.identity, sent, &session.access, response, now_ms()?)
        .map_err(storage)?
    {
        return Err(TeamImportError::Unknown);
    }
    Ok(())
}
