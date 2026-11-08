// SPDX-License-Identifier: Apache-2.0
//! Server-authoritative team views. Personal keys, objects and cursors are never borrowed.

use std::{collections::HashSet, sync::Arc, time::Duration};

use futures_util::StreamExt as _;
use scoplen_api::sync::{
    SyncOrganizationAckRequest, SyncOrganizationAckResponse, SyncOrganizationViewQuery,
    SyncOrganizationViewResponse, SyncReadLimits, SyncSessionRequest, SyncSessionResponse,
    VaultKind,
};
use scoplen_model::{Object, ObjectType};

use super::*;
use crate::store::team_assets::{TeamAssetPublication, TeamAssetRecord};

const PAGE_BYTES: usize = 4 * 1024 * 1024;
const VIEW_BYTES: usize = 32 * 1024 * 1024;

/// Only a fully published, still-current projection exposes its assets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum TeamAssetsPhase {
    /// The user has not requested this team's assets.
    NotLoaded,
    /// A complete view is being collected; partial rows remain hidden.
    Updating,
    /// The complete current view was published atomically.
    Ready,
    /// A content, membership or permission hint invalidated the previous view.
    Stale,
    /// The current Account no longer has this team's inventory descriptor.
    Unavailable,
    /// A bounded read failed; a new complete refresh is required.
    Failed,
}

/// Safe inventory metadata from this exact Organization, without secret fields or references.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamAssetSummary {
    /// Opaque id usable only with this view's source.
    pub id: String,
    /// Existing K-1 registry name.
    pub kind: String,
    /// Existing asset name; absent names use the id in the renderer.
    pub name: Option<String>,
    /// A Host's server-readable endpoint, not another referenced asset's metadata.
    pub address: Option<String>,
}

/// Source-bound current-view status; no raw K-1 object crosses IPC.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamAssetsView {
    /// Canonical deployment used for every request.
    pub origin: String,
    /// Account owning this independent encrypted store.
    pub account_id: String,
    /// Selected team, never inferred from a bare vault id.
    pub organization_id: String,
    /// Current source-bound installation, never inferred by the renderer.
    pub device_id: String,
    /// Durable Organization inventory vault, once discovered.
    pub vault_id: Option<String>,
    /// Exact positive uint64 equality fence, represented without JavaScript precision loss.
    pub revision: Option<String>,
    /// Current publication state.
    pub phase: TeamAssetsPhase,
    /// The current complete publication's server progress is confirmed.
    pub acknowledged: bool,
    /// Present only for Ready, including a valid empty current view.
    pub assets: Vec<TeamAssetSummary>,
}

impl PersonalServer {
    /// Read only the selected team's active local projection; this performs no network I/O.
    pub fn team_assets(
        &self,
        store: &Store,
        organization_id: &str,
    ) -> Result<TeamAssetsView, TeamError> {
        let identity = record(store)?;
        let organization = parse_id(organization_id)?;
        let saved = store.team_assets_record(&identity, organization).map_err(storage)?;
        asset_view(&identity, organization, store.device_id(), saved)
    }

    /// Collect every page under one descriptor revision and publish exactly once, then ACK.
    pub async fn refresh_team_assets(
        &self,
        store: Arc<Store>,
        organization_id: &str,
    ) -> Result<TeamAssetsView, TeamError> {
        self.refresh_team_assets_inner(store, parse_id(organization_id)?, None).await
    }

    async fn refresh_team_assets_inner(
        &self,
        store: Arc<Store>,
        organization: Uuid,
        run: Option<Arc<super::super::background::Run>>,
    ) -> Result<TeamAssetsView, TeamError> {
        for attempt in 0..3 {
            let identity = record(&store)?;
            let generation = {
                let _active = super::super::background::guard(run.as_ref())?;
                store.begin_team_asset_pull(&identity, organization).map_err(storage)?
            };
            let result =
                self.collect_team_assets(&store, organization, generation, run.as_ref()).await;
            if let Err(error) = &result {
                let phase = match error {
                    TeamError::Team(TeamFailure::AssetsChanged) => 2,
                    TeamError::Team(TeamFailure::TeamNotFound) => 3,
                    TeamError::Team(TeamFailure::AssetsAcknowledgementUnknown) => {
                        return result;
                    }
                    _ => 4,
                };
                let _active = super::super::background::guard(run.as_ref())?;
                let invalidate_ssh = matches!(
                    error,
                    TeamError::Team(TeamFailure::AssetsChanged | TeamFailure::TeamNotFound)
                        | TeamError::Personal(
                            PersonalServerError::AuthenticationRequired
                                | PersonalServerError::PermissionDenied
                        )
                );
                store
                    .finish_team_asset_pull(
                        &identity,
                        organization,
                        generation,
                        phase,
                        invalidate_ssh,
                    )
                    .map_err(storage)?;
                if phase == 2 && attempt < 2 {
                    continue;
                }
            }
            return result;
        }
        Err(TeamFailure::AssetsChanged.into())
    }

    async fn collect_team_assets(
        &self,
        store: &Arc<Store>,
        organization: Uuid,
        generation: Uuid,
        run: Option<&Arc<super::super::background::Run>>,
    ) -> Result<TeamAssetsView, TeamError> {
        super::super::background::guard(run)?;
        let session = self.team_session(store, DeviceAccessOperation::SyncSession).await?;
        let transport = self.transport.as_ref().map_err(|error| *error)?;
        let request = SyncSessionRequest {
            client_version: env!("CARGO_PKG_VERSION").into(),
            model_version: scoplen_model::CURRENT_SCHEMA_VERSION,
            device_id: store.device_id(),
        }
        .to_cbor()
        .map_err(invalid)?;
        let proof = session.proof("POST", "/sync/v1/session")?;
        let response = transport
            .protected(
                &session.identity.origin,
                "/sync/v1/session",
                Some(&request),
                session.token()?,
                &proof,
                PAGE_BYTES,
            )
            .await?;
        current(store, &session, organization, generation, run)?;
        require_success(&response)?;
        let descriptor =
            SyncSessionResponse::from_cbor_with_body_limit(response.body.as_bytes(), PAGE_BYTES)
                .map_err(invalid)?;
        let matching: Vec<_> = descriptor
            .vaults
            .into_iter()
            .filter(|vault| {
                vault.kind == VaultKind::Organization
                    && vault.organization.is_some_and(|owner| owner.organization == organization)
            })
            .collect();
        let [vault] = matching.as_slice() else {
            return Err(if matching.is_empty() {
                TeamFailure::TeamNotFound
            } else {
                TeamFailure::InvalidTeamResponse
            }
            .into());
        };
        let source = vault.organization.ok_or(TeamFailure::InvalidTeamResponse)?;
        let limits = SyncReadLimits {
            max_envelope_bytes: scoplen_model::MAX_OBJECT_BYTES,
            max_body_bytes: PAGE_BYTES,
        };
        let path = format!("/sync/v1/vaults/{}/view", vault.id);
        let mut after = 0;
        let mut bytes = 0usize;
        let mut objects = Vec::new();
        let mut seen = HashSet::new();
        loop {
            current(store, &session, organization, generation, run)?;
            let query =
                SyncOrganizationViewQuery { view_revision: source.view_revision, after, limit: 16 };
            let proof = session.proof("GET", &path)?;
            let response = transport
                .protected(
                    &session.identity.origin,
                    &format!("{path}?{}", query.to_query().map_err(invalid)?),
                    None,
                    session.token()?,
                    &proof,
                    PAGE_BYTES,
                )
                .await?;
            current(store, &session, organization, generation, run)?;
            require_success(&response)?;
            let page = SyncOrganizationViewResponse::from_cbor_with_limits(
                response.body.as_bytes(),
                limits,
            )
            .map_err(invalid)?;
            page.validate_for_query_with_limits(source, vault.id, &query, limits)
                .map_err(invalid)?;
            for change in page.objects {
                bytes = bytes
                    .checked_add(change.payload.len())
                    .filter(|bytes| *bytes <= VIEW_BYTES)
                    .ok_or(TeamFailure::AssetsLimit)?;
                if objects.len() >= crate::store::MAX_OBJECTS_PER_VAULT as usize {
                    return Err(TeamFailure::AssetsLimit.into());
                }
                if !seen.insert(change.object_id) {
                    return Err(TeamFailure::InvalidTeamResponse.into());
                }
                let object = Object::decode(&change.payload).map_err(invalid)?;
                if !matches!(
                    object.object_type,
                    ObjectType::HOST
                        | ObjectType::ACCESS_PROFILE
                        | ObjectType::ROUTE
                        | ObjectType::HOST_GROUP
                        | ObjectType::TRUST_RECORD
                        | ObjectType::SNIPPET
                        | ObjectType::GATEWAY_NETWORK
                ) {
                    return Err(TeamFailure::InvalidTeamResponse.into());
                }
                objects.push(object);
            }
            after = page.next_cursor;
            if !page.more {
                break;
            }
        }
        let publication = TeamAssetPublication {
            organization,
            generation,
            vault: vault.id,
            revision: source.view_revision,
            cursor: after,
        };
        {
            let _active = super::super::background::guard(run)?;
            session.current(store)?;
            store
                .publish_team_assets(&session.identity, &publication, &objects)
                .map_err(storage)?;
        }
        let acknowledged = self.acknowledge_team_view(store, &session, &publication, run).await;
        match acknowledged {
            Ok(()) => self.team_assets(store, &organization.to_string()),
            Err(TeamError::Personal(
                PersonalServerError::Network
                | PersonalServerError::ConnectionBeforeRequest
                | PersonalServerError::Storage
                | PersonalServerError::InvalidResponse,
            ))
            | Err(TeamError::Team(
                TeamFailure::InvalidTeamResponse | TeamFailure::ServiceUnavailable,
            )) => Err(TeamFailure::AssetsAcknowledgementUnknown.into()),
            Err(error) => Err(error),
        }
    }

    async fn acknowledge_team_view(
        &self,
        store: &Store,
        session: &TeamSession,
        publication: &TeamAssetPublication,
        run: Option<&Arc<super::super::background::Run>>,
    ) -> Result<(), TeamError> {
        session.current(store)?;
        if !DeviceAccessOperation::VaultAcknowledge
            .has_accepted_scope(session.identity.auth_scope.as_deref().unwrap_or(""))
        {
            return Err(TeamFailure::MembershipScopeRequired.into());
        }
        let path = format!("/sync/v1/vaults/{}/ack", publication.vault);
        let request = SyncOrganizationAckRequest {
            cursor: publication.cursor,
            view_revision: publication.revision,
        };
        let proof = session.proof("POST", &path)?;
        let response = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .protected(
                &session.identity.origin,
                &path,
                Some(&request.to_cbor().map_err(invalid)?),
                session.token()?,
                &proof,
                16_384,
            )
            .await?;
        let _active = super::super::background::guard(run)?;
        session.current(store)?;
        require_success(&response)?;
        SyncOrganizationAckResponse::from_cbor(response.body.as_bytes())
            .map_err(invalid)?
            .validate_for_request(&request)
            .map_err(invalid)?;
        store
            .acknowledge_team_assets(
                &session.identity,
                publication.organization,
                publication.generation,
            )
            .map_err(storage)?;
        Ok(())
    }

    pub(in crate::personal_server) async fn run_team_assets(
        &self,
        store: Arc<Store>,
        run: Arc<super::super::background::Run>,
    ) {
        let mut changes = store.team_asset_changes();
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! { _ = interval.tick() => {}, _ = changes.changed() => {} }
            if run.guard().is_err() {
                return;
            }
            let Ok(identity) = record(&store) else {
                continue;
            };
            let Ok(teams) = store.tracked_team_assets(&identity) else {
                continue;
            };
            futures_util::stream::iter(teams)
                .for_each_concurrent(4, |organization| {
                    let store = store.clone();
                    let run = run.clone();
                    async move {
                        let _ =
                            self.refresh_team_assets_inner(store, organization, Some(run)).await;
                    }
                })
                .await;
        }
    }
}

fn current(
    store: &Store,
    session: &TeamSession,
    organization: Uuid,
    generation: Uuid,
    run: Option<&Arc<super::super::background::Run>>,
) -> Result<(), TeamError> {
    let _active = super::super::background::guard(run)?;
    session.current(store)?;
    if !store
        .team_asset_pull_current(&session.identity, organization, generation)
        .map_err(storage)?
    {
        return Err(PersonalServerError::Busy.into());
    }
    Ok(())
}

fn require_success(response: &Response) -> Result<(), TeamError> {
    if response.status == 200 {
        return Ok(());
    }
    if !response.problem_cbor {
        return Err(TeamFailure::InvalidTeamResponse.into());
    }
    let problem = ProblemDetails::from_cbor(response.body.as_bytes()).map_err(invalid)?;
    if problem.status != response.status || problem.changed {
        return Err(TeamFailure::InvalidTeamResponse.into());
    }
    Err(match (problem.status, problem.code.as_str(), problem.retryable) {
        (409, "sync.view_changed", true) => TeamFailure::AssetsChanged.into(),
        (404, "sync.object_not_found", false) => TeamFailure::TeamNotFound.into(),
        (401, "auth.authentication_required", false) => {
            PersonalServerError::AuthenticationRequired.into()
        }
        (403, "policy.denied", false) => PersonalServerError::PermissionDenied.into(),
        (503, "sync.storage_unavailable", true) | (429, _, true) => {
            TeamFailure::ServiceUnavailable.into()
        }
        _ => TeamFailure::InvalidTeamResponse.into(),
    })
}

fn asset_view(
    identity: &PersonalRecord,
    organization: Uuid,
    device: Uuid,
    record: Option<TeamAssetRecord>,
) -> Result<TeamAssetsView, TeamError> {
    let mut view = TeamAssetsView {
        origin: identity.origin.clone(),
        account_id: identity.account_id.to_string(),
        organization_id: organization.to_string(),
        device_id: device.to_string(),
        vault_id: None,
        revision: None,
        phase: TeamAssetsPhase::NotLoaded,
        acknowledged: false,
        assets: Vec::new(),
    };
    if let Some(record) = record {
        view.phase = match record.phase {
            0 => TeamAssetsPhase::Updating,
            1 => TeamAssetsPhase::Ready,
            2 => TeamAssetsPhase::Stale,
            3 => TeamAssetsPhase::Unavailable,
            _ => TeamAssetsPhase::Failed,
        };
        view.vault_id = record.vault.map(|id| id.to_string());
        view.revision = record.revision.map(|revision| revision.to_string());
        view.acknowledged = record.acknowledged;
        view.assets = record
            .objects
            .iter()
            .map(|object| TeamAssetSummary {
                id: object.id.to_string(),
                kind: object.object_type.to_string(),
                name: object
                    .optional_text(if object.object_type == ObjectType::ACCESS_PROFILE {
                        2
                    } else {
                        1
                    })
                    .ok()
                    .flatten()
                    .map(str::to_owned),
                address: (object.object_type == ObjectType::HOST)
                    .then(|| object.optional_text(2).ok().flatten().map(str::to_owned))
                    .flatten(),
            })
            .collect();
    }
    Ok(view)
}
