// SPDX-License-Identifier: Apache-2.0
//! Account-scoped team discovery, durable creation and conditional name updates.

use std::{fmt, sync::Arc};

use scoplen_api::{
    ProblemDetails,
    auth::DeviceAccessOperation,
    organization::{
        MAX_ORGANIZATION_PAGE_BYTES, MAX_ORGANIZATION_PROBLEM_BYTES,
        MAX_ORGANIZATION_RESOURCE_BYTES, ORGANIZATION_CREATION_RECEIPT_SECONDS,
        OrganizationCreateRequest, OrganizationListQuery, OrganizationPage, OrganizationResource,
        OrganizationUpdateRequest, parse_organization_if_match,
    },
};
use scoplen_crypto::{
    DeviceAccessToken, DpopProof, DpopTarget, DpopToken, P256SigningKey, SecretVec,
    dpop_jwk_thumbprint,
};
use scoplen_model::validate_uuid_v7;
use serde::Serialize;
use specta::Type;
use uuid::Uuid;

use super::{
    PersonalServer, PersonalServerError, identity, now, record, storage, transport::Response,
    trusted_token_keys,
};
use crate::store::{Store, personal::PersonalRecord, teams::TeamCreationRecord};

/// Current discovery metadata; role names are display values, never client authorization.
#[derive(Clone, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamSummary {
    /// Organization identity within this Account's canonical deployment.
    pub id: String,
    /// Server-provided team name.
    pub name: String,
    /// This Account's current membership role identifiers, including unknown values.
    pub roles: Vec<String>,
}

impl fmt::Debug for TeamSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeamSummary").finish_non_exhaustive()
    }
}

/// One explicit discovery request; the caller chooses whether to fetch another page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamPageView {
    /// Only the authenticated Account's current active memberships.
    pub teams: Vec<TeamSummary>,
    /// A verified ascending continuation, or None at the end.
    pub next_cursor: Option<String>,
}

/// One verified current Resource captured for an explicit name edit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamSettingsView {
    /// Current caller-specific team metadata; roles grant no frontend authority.
    pub team: TeamSummary,
    /// Exact strong Resource precondition; Save must not replace it silently.
    pub etag: String,
}

/// Local state of the one retained team-creation operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum TeamCreationPhase {
    /// No request was sent, or the first-party server confirmed no creation.
    Prepared,
    /// A dispatched creation needs its original key and payload for explicit retry.
    Unknown,
    /// A verified 201 response confirmed the original operation's outcome.
    Confirmed,
    /// The original retry window ended; review discovery before deciding on another creation.
    Expired,
}

/// Safe local recovery state; no access token, proof or canonical request crosses IPC.
#[derive(Clone, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamCreationView {
    /// Public local operation identity; it cannot authorize a server request.
    pub operation_id: String,
    /// The original team name, retained without normalization.
    pub name: String,
    /// The next allowed explicit action.
    pub phase: TeamCreationPhase,
    /// The historical confirmed projection, not current membership authority.
    pub organization: Option<TeamSummary>,
    /// Original retry deadline in Unix milliseconds, without JavaScript precision loss.
    pub retry_until: Option<String>,
}

impl fmt::Debug for TeamCreationView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeamCreationView").field("phase", &self.phase).finish_non_exhaustive()
    }
}

/// Content-free team failures supplement the existing Account/session failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub enum TeamFailure {
    /// Name is outside the exact shared request profile.
    #[error(
        "Enter a team name of 1 to 128 UTF-8 bytes, without controls or surrounding whitespace."
    )]
    InvalidName,
    /// Resolve or explicitly clear the existing operation before preparing another.
    #[error("A team creation is already retained. Resolve it before preparing another.")]
    CreationPending,
    /// No retained request exists in this Account store.
    #[error("No prepared team creation exists in this Account.")]
    OperationMissing,
    /// The supplied operation or continuation does not match its canonical identity.
    #[error("This operation no longer matches the retained request. Reload its status.")]
    OperationMismatch,
    /// The same receipt cannot be retried outside its original lifetime.
    #[error(
        "This creation's retry window ended. Refresh teams before deciding whether to create another."
    )]
    OperationExpired,
    /// A missing or uncertain result retains the original idempotency key and payload.
    #[error("The team may have been created. Retry this original operation to confirm its result.")]
    OutcomeUnknown,
    /// The complete response, HTTP metadata or Account binding was invalid.
    #[error(
        "The server returned an invalid or mismatched team response. Existing data was retained."
    )]
    InvalidTeamResponse,
    /// The server refused the key/payload binding; never replace it silently.
    #[error(
        "The server reported a conflict for the retained creation. Its original request was kept."
    )]
    Conflict,
    /// Confirmed rollback permits an explicit retry of the same operation.
    #[error("The team service is unavailable. Retry the original operation later.")]
    ServiceUnavailable,
    /// The captured edit is stale and requires an explicit Resource refresh.
    #[error("The team changed. Refresh its settings and review the name before saving again.")]
    SettingsConflict,
    /// A dispatched update cannot be confirmed; never automatically replay it.
    #[error("The name may have changed. Refresh team settings before making another edit.")]
    SettingsUnknown,
    /// This session's fixed scope ceiling does not permit Organization updates.
    #[error("Authenticate this device to obtain permission to update team settings.")]
    UpdateScopeRequired,
    /// Missing and unavailable membership share one non-disclosing outcome.
    #[error("This team is no longer available to this Account. Refresh your teams.")]
    TeamNotFound,
}

/// Safe flattened IPC errors, without arbitrary server text or diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type, thiserror::Error)]
#[serde(untagged)]
pub enum TeamError {
    /// Existing authenticated Account or local-store failure.
    #[error(transparent)]
    Personal(#[from] PersonalServerError),
    /// A failure specific to discovery or creation recovery.
    #[error(transparent)]
    Team(#[from] TeamFailure),
}

impl PersonalServer {
    /// Read the retained operation locally; opening Settings performs no network request.
    pub fn pending_team_creation(
        &self,
        store: &Store,
    ) -> Result<Option<TeamCreationView>, TeamError> {
        if store.personal_record().map_err(storage)?.is_none() {
            return Ok(None);
        }
        let identity = record(store)?;
        store
            .team_creation(&identity)
            .map_err(storage)?
            .map(|pending| view(&identity, &pending, now_ms()?))
            .transpose()
    }

    /// Retain one canonical request before any network operation, without touching Personal data.
    pub fn prepare_team_creation(
        &self,
        store: &Store,
        name: String,
    ) -> Result<TeamCreationView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(store)?;
        let request = OrganizationCreateRequest::new(name).map_err(|_| TeamFailure::InvalidName)?;
        if store.team_creation(&identity).map_err(storage)?.is_some() {
            return Err(TeamFailure::CreationPending.into());
        }
        let pending = TeamCreationRecord {
            operation_id: scoplen_model::new_uuid_v7()
                .map_err(|_| PersonalServerError::Identity)?,
            payload: SecretVec::new(request.to_json().map_err(|_| TeamFailure::InvalidName)?),
            phase: 0,
            first_attempt_ms: None,
            response: None,
        };
        if !store.prepare_team_creation(&identity, &pending).map_err(storage)? {
            return Err(TeamFailure::CreationPending.into());
        }
        view(&identity, &pending, now_ms()?)
    }

    /// Send or explicitly retry only the original retained key and canonical body.
    pub async fn submit_team_creation(
        &self,
        store: Arc<Store>,
        operation_id: &str,
    ) -> Result<TeamCreationView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(&store)?;
        let pending = load_pending(&store, &identity, operation_id)?;
        let current = view(&identity, &pending, now_ms()?)?;
        match current.phase {
            TeamCreationPhase::Confirmed => return Ok(current),
            TeamCreationPhase::Expired => return Err(TeamFailure::OperationExpired.into()),
            _ => {}
        }
        let session = self.team_session(&store, DeviceAccessOperation::OrganizationCreate).await?;
        let proof = session.proof("POST", "/api/v1/orgs")?;
        let transport = self.transport.as_ref().map_err(|error| *error)?;
        let sent_at = now_ms()?;
        if !store
            .dispatch_team_creation(&session.identity, &pending, &session.access, sent_at)
            .map_err(storage)?
        {
            return Err(PersonalServerError::Busy.into());
        }
        let sent = load_pending(&store, &session.identity, operation_id)?;
        let response = transport
            .team_create(
                &session.identity.origin,
                sent.payload.as_bytes(),
                sent.operation_id,
                session.token()?,
                &proof,
            )
            .await;
        let response = match response {
            Ok(response) => response,
            Err(PersonalServerError::ConnectionBeforeRequest) if pending.phase == 0 => {
                if !store
                    .finish_team_creation(
                        &session.identity,
                        &sent,
                        &session.access,
                        None,
                        now_ms()?,
                    )
                    .map_err(storage)?
                {
                    return Err(PersonalServerError::Storage.into());
                }
                return Err(PersonalServerError::ConnectionBeforeRequest.into());
            }
            Err(_) => return Err(TeamFailure::OutcomeUnknown.into()),
        };
        session.current(&store)?;
        if response.status == 201 {
            let resource = resource(&response, session.identity.account_id)?;
            let canonical = resource.to_json().map_err(invalid)?;
            if !store
                .finish_team_creation(
                    &session.identity,
                    &sent,
                    &session.access,
                    Some(&canonical),
                    now_ms()?,
                )
                .map_err(storage)?
            {
                return Err(PersonalServerError::Storage.into());
            }
            return self
                .pending_team_creation(&store)?
                .ok_or_else(|| TeamFailure::OperationMissing.into());
        }
        let problem = problem(&response)?;
        let error = response_error(&problem).ok_or(TeamFailure::InvalidTeamResponse)?;
        if problem.status == 404 {
            return Err(TeamFailure::InvalidTeamResponse.into());
        }
        // A denial on a retry cannot establish that a previous missing response never committed.
        if pending.phase == 0
            && !problem.changed
            && problem.code.as_str() != "organization.conflict"
            && !store
                .finish_team_creation(&session.identity, &sent, &session.access, None, now_ms()?)
                .map_err(storage)?
        {
            return Err(PersonalServerError::Storage.into());
        }
        if problem.status == 401 {
            store
                .invalidate_personal_session(&session.identity, &session.access)
                .map_err(storage)?;
        }
        Err(error)
    }

    /// Clear a prepared, confirmed or expired operation after an explicit user action.
    pub fn discard_team_creation(
        &self,
        store: &Store,
        operation_id: &str,
    ) -> Result<(), TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(store)?;
        let pending = load_pending(store, &identity, operation_id)?;
        if view(&identity, &pending, now_ms()?)?.phase == TeamCreationPhase::Unknown {
            return Err(TeamFailure::OutcomeUnknown.into());
        }
        if !store.discard_team_creation(&identity, &pending, now_ms()?).map_err(storage)? {
            return Err(PersonalServerError::Busy.into());
        }
        Ok(())
    }

    /// Query exactly one current membership page; never fetch another page automatically.
    pub async fn teams_page(
        &self,
        store: Arc<Store>,
        cursor: Option<&str>,
    ) -> Result<TeamPageView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let query = OrganizationListQuery {
            cursor: cursor.map(parse_id).transpose()?,
            ..Default::default()
        };
        query.validate().map_err(invalid)?;
        let mut path = format!("/api/v1/orgs?limit={}", query.limit);
        if let Some(cursor) = query.cursor {
            path.push_str(&format!("&cursor={cursor}"));
        }
        let session = self.team_session(&store, DeviceAccessOperation::OrganizationList).await?;
        let proof = session.proof("GET", "/api/v1/orgs")?;
        let response = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_get(
                &session.identity.origin,
                &path,
                session.token()?,
                &proof,
                MAX_ORGANIZATION_PAGE_BYTES,
            )
            .await?;
        session.current(&store)?;
        if response.status != 200 {
            return Err(read_error(&store, &session, &response)?);
        }
        let page = OrganizationPage::from_http_json(
            response.body.as_bytes(),
            response.cache_control.as_deref(),
            response.pragma.as_deref(),
        )
        .map_err(invalid)?;
        page.validate_for_account(session.identity.account_id, query).map_err(invalid)?;
        Ok(TeamPageView {
            teams: page.items.into_iter().map(summary).collect(),
            next_cursor: page.next_cursor.map(|id| id.to_string()),
        })
    }

    /// Query one current membership Resource without trusting cached roles or JWT membership.
    pub async fn team(
        &self,
        store: Arc<Store>,
        organization_id: &str,
    ) -> Result<TeamSummary, TeamError> {
        Ok(self.team_settings(store, organization_id).await?.team)
    }

    /// Capture the current Resource's exact identity and ETag without trusting cached metadata.
    pub async fn team_settings(
        &self,
        store: Arc<Store>,
        organization_id: &str,
    ) -> Result<TeamSettingsView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let id = parse_id(organization_id)?;
        let path = format!("/api/v1/orgs/{id}");
        let session = self.team_session(&store, DeviceAccessOperation::OrganizationRead).await?;
        let proof = session.proof("GET", &path)?;
        let response = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_get(
                &session.identity.origin,
                &path,
                session.token()?,
                &proof,
                MAX_ORGANIZATION_RESOURCE_BYTES,
            )
            .await?;
        session.current(&store)?;
        if response.status != 200 {
            return Err(read_error(&store, &session, &response)?);
        }
        let resource = resource(&response, session.identity.account_id)?;
        if resource.id != id {
            return Err(TeamFailure::InvalidTeamResponse.into());
        }
        Ok(settings_view(resource))
    }

    /// Perform one explicitly confirmed name update with its captured strong precondition.
    pub async fn update_team_name(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        etag: &str,
        name: String,
    ) -> Result<TeamSettingsView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let id = parse_id(organization_id)?;
        parse_organization_if_match(Some(etag)).map_err(invalid)?;
        let request = OrganizationUpdateRequest::new(name).map_err(|_| TeamFailure::InvalidName)?;
        let body = request.to_json().map_err(|_| TeamFailure::InvalidName)?;
        let path = format!("/api/v1/orgs/{id}");
        let session = self.team_session(&store, DeviceAccessOperation::OrganizationUpdate).await?;
        let proof = session.proof("PATCH", &path)?;
        let response = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_update(&session.identity.origin, &path, &body, etag, session.token()?, &proof)
            .await;
        let response = match response {
            Ok(response) => response,
            Err(PersonalServerError::ConnectionBeforeRequest) => {
                return Err(PersonalServerError::ConnectionBeforeRequest.into());
            }
            Err(_) => return Err(TeamFailure::SettingsUnknown.into()),
        };
        session.current(&store).map_err(|_| TeamFailure::SettingsUnknown)?;
        if response.status == 200 {
            let resource = resource(&response, session.identity.account_id)
                .map_err(|_| TeamFailure::SettingsUnknown)?;
            if resource.id != id || resource.name != request.name {
                return Err(TeamFailure::SettingsUnknown.into());
            }
            return Ok(settings_view(resource));
        }
        let problem = problem(&response).map_err(|_| TeamFailure::SettingsUnknown)?;
        let failure =
            match (problem.status, problem.code.as_str(), problem.changed, problem.retryable) {
                (412, "organization.precondition_failed", false, false)
                | (428, "organization.precondition_required", false, false) => {
                    TeamFailure::SettingsConflict.into()
                }
                (404, "organization.not_found", false, false) => TeamFailure::TeamNotFound.into(),
                (401, "auth.authentication_required", false, false) => {
                    store
                        .invalidate_personal_session(&session.identity, &session.access)
                        .map_err(storage)?;
                    PersonalServerError::AuthenticationRequired.into()
                }
                (403, "policy.denied", false, false) => {
                    PersonalServerError::PermissionDenied.into()
                }
                (503, "organization.storage_unavailable", false, true) => {
                    TeamFailure::ServiceUnavailable.into()
                }
                _ => TeamFailure::SettingsUnknown.into(),
            };
        Err(failure)
    }

    async fn team_session(
        &self,
        store: &Store,
        operation: DeviceAccessOperation,
    ) -> Result<TeamSession, TeamError> {
        self.refresh_for_operation(store).await?;
        let identity = record(store)?;
        let access = store
            .personal_access_token(now()?)
            .map_err(storage)?
            .ok_or(PersonalServerError::AuthenticationRequired)?;
        let signing = P256SigningKey::from_bytes(
            identity::Secrets::parse(&identity.private_material)?.signing(),
        )
        .map_err(|_| PersonalServerError::Identity)?;
        let trusted =
            trusted_token_keys(self.transport.as_ref().map_err(|error| *error)?, &identity.origin)
                .await?;
        let current = now()?;
        let verified =
            DeviceAccessToken::parse(std::str::from_utf8(access.as_bytes()).map_err(invalid)?)
                .and_then(|token| token.verify(&trusted, current))
                .map_err(|_| PersonalServerError::AuthenticationRequired)?;
        let claims = verified.claims();
        if claims.sub != identity.account_id
            || claims.did != store.device_id()
            || claims.cnf_jkt != dpop_jwk_thumbprint(&signing.public_key_sec1()).map_err(invalid)?
            || identity.auth_scope.as_deref() != Some(claims.scope.as_str())
        {
            return Err(PersonalServerError::AuthenticationRequired.into());
        }
        if !operation.required_scope().is_present_in(&claims.scope) {
            if operation == DeviceAccessOperation::OrganizationUpdate {
                return Err(TeamFailure::UpdateScopeRequired.into());
            }
            return Err(PersonalServerError::PermissionDenied.into());
        }
        let session = TeamSession { identity, access, signing, expires_at: verified.expires_at() };
        session.current(store)?;
        Ok(session)
    }
}

struct TeamSession {
    identity: PersonalRecord,
    access: SecretVec,
    signing: P256SigningKey,
    expires_at: u64,
}

impl TeamSession {
    fn token(&self) -> Result<&str, TeamError> {
        std::str::from_utf8(self.access.as_bytes()).map_err(invalid)
    }
    fn current(&self, store: &Store) -> Result<(), TeamError> {
        let now = now()?;
        if self.expires_at <= now
            || !store
                .personal_session_current(&self.identity, &self.access, now)
                .map_err(storage)?
        {
            return Err(PersonalServerError::AuthenticationRequired.into());
        }
        Ok(())
    }
    fn proof(&self, method: &str, path: &str) -> Result<DpopProof, TeamError> {
        DpopProof::sign(
            &self.signing,
            &self.signing.public_key_sec1(),
            &DpopTarget::new(method, &self.identity.origin, path).map_err(invalid)?,
            DpopToken::Protected(self.token()?),
            now()?,
            None,
        )
        .map_err(invalid)
    }
}

fn load_pending(
    store: &Store,
    identity: &PersonalRecord,
    operation_id: &str,
) -> Result<TeamCreationRecord, TeamError> {
    let id = parse_id(operation_id)?;
    let pending =
        store.team_creation(identity).map_err(storage)?.ok_or(TeamFailure::OperationMissing)?;
    if pending.operation_id != id {
        return Err(TeamFailure::OperationMismatch.into());
    }
    Ok(pending)
}

fn view(
    identity: &PersonalRecord,
    pending: &TeamCreationRecord,
    now_ms: u64,
) -> Result<TeamCreationView, TeamError> {
    validate_uuid_v7(pending.operation_id).map_err(invalid)?;
    let request =
        OrganizationCreateRequest::from_json(pending.payload.as_bytes()).map_err(invalid)?;
    let deadline = pending
        .first_attempt_ms
        .map(|time| time.saturating_add(ORGANIZATION_CREATION_RECEIPT_SECONDS * 1000));
    let organization = pending
        .response
        .as_ref()
        .map(|body| {
            let resource = OrganizationResource::from_json(body.as_bytes()).map_err(invalid)?;
            resource.validate_for_account(identity.account_id).map_err(invalid)?;
            Ok::<_, TeamError>(summary(resource))
        })
        .transpose()?;
    let phase = match (pending.phase, organization.is_some()) {
        (2, true) => TeamCreationPhase::Confirmed,
        (0 | 1, false) if deadline.is_some_and(|deadline| now_ms >= deadline) => {
            TeamCreationPhase::Expired
        }
        (0, false) => TeamCreationPhase::Prepared,
        (1, false) => TeamCreationPhase::Unknown,
        _ => return Err(TeamFailure::InvalidTeamResponse.into()),
    };
    Ok(TeamCreationView {
        operation_id: pending.operation_id.to_string(),
        name: request.name,
        phase,
        organization,
        retry_until: deadline.map(|time| time.to_string()),
    })
}

fn resource(response: &Response, account: Uuid) -> Result<OrganizationResource, TeamError> {
    let resource = OrganizationResource::from_http_json(
        response.body.as_bytes(),
        response.etag.as_deref(),
        response.cache_control.as_deref(),
        response.pragma.as_deref(),
    )
    .map_err(invalid)?;
    resource.validate_for_account(account).map_err(invalid)?;
    Ok(resource)
}

fn summary(resource: OrganizationResource) -> TeamSummary {
    TeamSummary {
        id: resource.id.to_string(),
        name: resource.name,
        roles: resource.membership.roles,
    }
}

fn settings_view(resource: OrganizationResource) -> TeamSettingsView {
    TeamSettingsView { etag: resource.etag.clone(), team: summary(resource) }
}

fn problem(response: &Response) -> Result<ProblemDetails, TeamError> {
    if !response.problem_json {
        return Err(TeamFailure::InvalidTeamResponse.into());
    }
    let problem =
        ProblemDetails::from_json(response.body.as_bytes(), MAX_ORGANIZATION_PROBLEM_BYTES)
            .map_err(invalid)?;
    if problem.status != response.status {
        return Err(TeamFailure::InvalidTeamResponse.into());
    }
    Ok(problem)
}

fn response_error(problem: &ProblemDetails) -> Option<TeamError> {
    Some(match (problem.status, problem.code.as_str(), problem.changed, problem.retryable) {
        (401, "auth.authentication_required", false, false) => {
            PersonalServerError::AuthenticationRequired.into()
        }
        (403, "policy.denied", false, false) => PersonalServerError::PermissionDenied.into(),
        (400 | 415, "organization.invalid_request", false, false)
        | (404, "organization.not_found", false, false) => TeamFailure::InvalidTeamResponse.into(),
        (409, "organization.conflict", false, false) => TeamFailure::Conflict.into(),
        (503, "organization.storage_unavailable", false, true) => {
            TeamFailure::ServiceUnavailable.into()
        }
        (503, "organization.commit_outcome_unknown", true, true) => {
            TeamFailure::OutcomeUnknown.into()
        }
        _ => return None,
    })
}

fn read_error(
    store: &Store,
    session: &TeamSession,
    response: &Response,
) -> Result<TeamError, TeamError> {
    let problem = problem(response)?;
    if (problem.status, problem.code.as_str(), problem.changed, problem.retryable)
        == (404, "organization.not_found", false, false)
    {
        return Ok(TeamFailure::TeamNotFound.into());
    }
    let error = response_error(&problem).ok_or(TeamFailure::InvalidTeamResponse)?;
    if problem.status == 401 {
        store.invalidate_personal_session(&session.identity, &session.access).map_err(storage)?;
    }
    Ok(error)
}

fn parse_id(value: &str) -> Result<Uuid, TeamError> {
    let id = Uuid::parse_str(value).map_err(|_| TeamFailure::OperationMismatch)?;
    validate_uuid_v7(id).map_err(|_| TeamFailure::OperationMismatch)?;
    if value != id.to_string() {
        return Err(TeamFailure::OperationMismatch.into());
    }
    Ok(id)
}

fn now_ms() -> Result<u64, TeamError> {
    scoplen_model::system_time_millis().map_err(|_| PersonalServerError::Identity.into())
}

fn invalid(_: impl fmt::Debug) -> TeamError {
    TeamFailure::InvalidTeamResponse.into()
}
