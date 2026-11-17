// SPDX-License-Identifier: Apache-2.0
//! Exact-input access applications and explicit original-operation recovery.

mod types;
pub use types::*;

use std::sync::{Mutex, Weak};

use reqwest::Method;
use scoplen_api::access_request::{
    ACCESS_REQUEST_PENDING_SECONDS, AccessRequestCheckRequest, AccessRequestCheckResponse,
    AccessRequestCreateRequest, AccessRequestDecisionRequest, AccessRequestFields,
    AccessRequestListQuery, AccessRequestOutcome, AccessRequestPage, AccessRequestResource,
    AccessRequestStatus, AccessRequestView, MAX_ACCESS_REQUEST_BYTES,
    MAX_ACCESS_REQUEST_PAGE_BYTES, MAX_ACCESS_REQUEST_RESOURCE_BYTES,
};

use super::*;
use crate::{
    connection::{SessionTarget, team::TeamConnectionSnapshot},
    session_manager::SessionManager,
    store::team_access_requests::TeamAccessRequestRecord,
};

struct BoundIntent<T> {
    id: Uuid,
    source: TeamSshSource,
    store: Weak<Store>,
    auth_generation: i64,
    value: T,
}

impl<T> BoundIntent<T> {
    fn current(&self, store: &Arc<Store>, identity: &PersonalRecord) -> bool {
        self.source == source(store, identity, &self.source.organization_id)
            && self.auth_generation == identity.auth_generation
            && self.store.upgrade().is_some_and(|owner| Arc::ptr_eq(&owner, store))
    }
}

#[derive(Default)]
struct Intents {
    checked: Option<BoundIntent<AccessRequestFields>>,
    reviewed: Option<BoundIntent<AccessRequestResource>>,
}

/// Retains only the current exact check and review inside the native boundary.
#[derive(Default)]
pub struct TeamAccessRequests {
    intents: Mutex<Intents>,
}

impl TeamAccessRequests {
    /// Check one actual terminal policy refusal with the person's exact duration and reason.
    pub async fn check(
        &self,
        personal: &PersonalServer,
        sessions: &SessionManager,
        store: Arc<Store>,
        session_id: &str,
        draft: TeamAccessRequestDraft,
    ) -> Result<TeamAccessRequestCheckView, TeamAccessRequestError> {
        self.intents.lock().map_err(|_| PersonalServerError::Busy)?.checked = None;
        let denial = sessions
            .team_access_request_denial(&store, session_id)
            .ok_or(TeamAccessRequestFailure::CheckRequired)?;
        let fields = AccessRequestFields {
            host: parse_id(&denial.host_id)?,
            remote_user: denial.remote_user.clone(),
            duration_seconds: draft.duration_seconds,
            reason: draft.reason,
        };
        let body = AccessRequestCheckRequest { fields: fields.clone() }
            .to_json()
            .map_err(|_| TeamAccessRequestFailure::InvalidInput)?;
        let session =
            personal.team_session(&store, DeviceAccessOperation::AccessRequestCheck).await?;
        require_source(&store, &session.identity, &denial.source)?;
        let path = format!("{}/check", collection_path(&denial.source.organization_id));
        let proof = session.proof("POST", &path)?;
        let response = personal
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_exchange(
                &session.identity.origin,
                &path,
                Method::POST,
                Some(&body),
                session.token()?,
                &proof,
                None,
                None,
                MAX_ACCESS_REQUEST_BYTES,
            )
            .await?;
        session.current(&store)?;
        require_success(&store, &session, &response, 200)?;
        let allowed = AccessRequestCheckResponse::from_http_json(
            response.body.as_bytes(),
            response.cache_control.as_deref(),
            response.pragma.as_deref(),
        )
        .map_err(invalid_response)?
        .allowed;
        if sessions.team_access_request_denial(&store, session_id).as_ref() != Some(&denial) {
            return Err(TeamAccessRequestFailure::CheckRequired.into());
        }
        let check_id = if allowed {
            let id = Uuid::now_v7();
            self.intents.lock().map_err(|_| PersonalServerError::Busy)?.checked =
                Some(BoundIntent {
                    id,
                    source: denial.source.clone(),
                    store: Arc::downgrade(&store),
                    auth_generation: session.identity.auth_generation,
                    value: fields.clone(),
                });
            Some(id.to_string())
        } else {
            None
        };
        Ok(TeamAccessRequestCheckView {
            source: denial.source,
            fields: fields_view(&fields),
            allowed,
            check_id,
        })
    }

    /// Read a real authorized page; no background request is started by this manager.
    pub async fn page(
        &self,
        personal: &PersonalServer,
        store: Arc<Store>,
        organization_id: &str,
        view: TeamAccessRequestList,
        cursor: Option<&str>,
    ) -> Result<TeamAccessRequestPageView, TeamAccessRequestError> {
        let organization = parse_id(organization_id)?;
        let query = AccessRequestListQuery {
            view: match view {
                TeamAccessRequestList::Mine => AccessRequestView::Mine,
                TeamAccessRequestList::Approvals => AccessRequestView::Approvals,
            },
            page: OrganizationListQuery {
                cursor: cursor.map(parse_id).transpose()?,
                ..Default::default()
            },
        };
        query.page.validate().map_err(invalid_response)?;
        let base = collection_path(&organization.to_string());
        let mut path = format!(
            "{base}?view={}&limit={}",
            match view {
                TeamAccessRequestList::Mine => "mine",
                TeamAccessRequestList::Approvals => "approvals",
            },
            query.page.limit
        );
        if let Some(cursor) = query.page.cursor {
            path.push_str(&format!("&cursor={cursor}"));
        }
        let session =
            personal.team_session(&store, DeviceAccessOperation::AccessRequestList).await?;
        let proof = session.proof("GET", &base)?;
        let response = personal
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_get(
                &session.identity.origin,
                &path,
                session.token()?,
                &proof,
                MAX_ACCESS_REQUEST_PAGE_BYTES,
            )
            .await?;
        session.current(&store)?;
        require_success(&store, &session, &response, 200)?;
        let page = AccessRequestPage::from_http_json(
            response.body.as_bytes(),
            response.cache_control.as_deref(),
            response.pragma.as_deref(),
        )
        .map_err(invalid_response)?;
        page.validate_for_query(session.identity.account_id, query).map_err(invalid_response)?;
        let source = source(&store, &session.identity, organization_id);
        let current = now_ms()?;
        Ok(TeamAccessRequestPageView {
            source: source.clone(),
            view,
            items: page
                .items
                .iter()
                .map(|item| resource_view(&source, item, current))
                .collect::<Result<_, _>>()?,
            next_cursor: page.next_cursor.map(|id| id.to_string()),
        })
    }

    /// GET the complete current Resource and retain its original ETag for explicit review.
    pub async fn review(
        &self,
        personal: &PersonalServer,
        store: Arc<Store>,
        organization_id: &str,
        request_id: &str,
    ) -> Result<TeamAccessRequestReviewView, TeamAccessRequestError> {
        self.intents.lock().map_err(|_| PersonalServerError::Busy)?.reviewed = None;
        parse_id(organization_id)?;
        let id = parse_id(request_id)?;
        let path = format!("{}/{id}", collection_path(organization_id));
        let session =
            personal.team_session(&store, DeviceAccessOperation::AccessRequestRead).await?;
        let proof = session.proof("GET", &path)?;
        let response = personal
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_get(
                &session.identity.origin,
                &path,
                session.token()?,
                &proof,
                MAX_ACCESS_REQUEST_RESOURCE_BYTES,
            )
            .await?;
        session.current(&store)?;
        require_success(&store, &session, &response, 200)?;
        let resource = decode_response(&response, id)?;
        let source = source(&store, &session.identity, organization_id);
        let view = resource_view(&source, &resource, now_ms()?)?;
        let intent_id = Uuid::now_v7();
        self.intents.lock().map_err(|_| PersonalServerError::Busy)?.reviewed = Some(BoundIntent {
            id: intent_id,
            source,
            store: Arc::downgrade(&store),
            auth_generation: session.identity.auth_generation,
            value: resource,
        });
        Ok(TeamAccessRequestReviewView { intent_id: intent_id.to_string(), resource: view })
    }

    /// Retain the checked immutable application before any network mutation.
    pub fn prepare_create(
        &self,
        personal: &PersonalServer,
        store: &Arc<Store>,
        check_id: &str,
    ) -> Result<TeamAccessRequestOperationView, TeamAccessRequestError> {
        let _operation = personal.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(store)?;
        let mut intents = self.intents.lock().map_err(|_| PersonalServerError::Busy)?;
        let checked = intents
            .checked
            .as_ref()
            .filter(|intent| intent.id.to_string() == check_id && intent.current(store, &identity))
            .ok_or(TeamAccessRequestFailure::CheckRequired)?;
        let request =
            AccessRequestCreateRequest { id: Uuid::now_v7(), fields: checked.value.clone() };
        let pending = TeamAccessRequestRecord {
            organization: parse_id(&checked.source.organization_id)?,
            operation: Uuid::now_v7(),
            request: request.id,
            kind: 0,
            payload: SecretVec::new(
                request.to_json().map_err(|_| TeamAccessRequestFailure::InvalidInput)?,
            ),
            original: None,
            etag: None,
            phase: 0,
            first_attempt_ms: None,
            response: None,
        };
        prepare(store, &identity, &pending)?;
        intents.checked = None;
        operation_view(store, &identity, &pending, now_ms()?)
    }

    /// Retain an explicit whole decision/cancellation with the reviewed original Resource.
    pub fn prepare_action(
        &self,
        personal: &PersonalServer,
        store: &Arc<Store>,
        intent_id: &str,
        action: TeamAccessRequestAction,
    ) -> Result<TeamAccessRequestOperationView, TeamAccessRequestError> {
        let _operation = personal.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(store)?;
        let mut intents = self.intents.lock().map_err(|_| PersonalServerError::Busy)?;
        let reviewed = intents
            .reviewed
            .as_ref()
            .filter(|intent| intent.id.to_string() == intent_id && intent.current(store, &identity))
            .ok_or(TeamAccessRequestFailure::ReviewRequired)?;
        let view = resource_view(&reviewed.source, &reviewed.value, now_ms()?)?;
        let (kind, payload) = match action {
            TeamAccessRequestAction::Approve | TeamAccessRequestAction::Deny if view.can_decide => {
                let decision = if action == TeamAccessRequestAction::Approve {
                    AccessRequestOutcome::Approve
                } else {
                    AccessRequestOutcome::Deny
                };
                (
                    if action == TeamAccessRequestAction::Approve { 1 } else { 2 },
                    AccessRequestDecisionRequest { decision }
                        .to_json()
                        .map_err(invalid_response)?,
                )
            }
            TeamAccessRequestAction::Cancel if view.can_cancel => (3, Vec::new()),
            _ => return Err(TeamAccessRequestFailure::ReviewRequired.into()),
        };
        let pending = TeamAccessRequestRecord {
            organization: parse_id(&reviewed.source.organization_id)?,
            operation: Uuid::now_v7(),
            request: reviewed.value.id,
            kind,
            payload: SecretVec::new(payload),
            original: Some(SecretVec::new(reviewed.value.to_json().map_err(invalid_response)?)),
            etag: Some(reviewed.value.etag.clone()),
            phase: 0,
            first_attempt_ms: None,
            response: None,
        };
        prepare(store, &identity, &pending)?;
        intents.reviewed = None;
        operation_view(store, &identity, &pending, now_ms()?)
    }

    /// Inspect the original local mutation without sending anything.
    pub fn pending(
        &self,
        store: &Store,
        organization_id: &str,
    ) -> Result<Option<TeamAccessRequestOperationView>, TeamAccessRequestError> {
        let identity = record(store)?;
        store
            .team_access_request_pending(&identity, parse_id(organization_id)?)
            .map_err(storage)?
            .map(|pending| operation_view(store, &identity, &pending, now_ms()?))
            .transpose()
    }

    /// Send, or explicitly confirm, only the retained key/body/path/original ETag.
    pub async fn submit(
        &self,
        personal: &PersonalServer,
        store: Arc<Store>,
        organization_id: &str,
        operation_id: &str,
    ) -> Result<TeamAccessRequestOperationView, TeamAccessRequestError> {
        let _operation = personal.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(&store)?;
        let pending = load(&store, &identity, organization_id, operation_id)?;
        let view = operation_view(&store, &identity, &pending, now_ms()?)?;
        match view.phase {
            TeamCreationPhase::Confirmed => return Ok(view),
            TeamCreationPhase::Expired => {
                return Err(TeamAccessRequestFailure::OperationExpired.into());
            }
            _ => {}
        }
        let op = match pending.kind {
            0 => DeviceAccessOperation::AccessRequestCreate,
            1 | 2 => DeviceAccessOperation::AccessRequestDecide,
            3 => DeviceAccessOperation::AccessRequestCancel,
            _ => return Err(TeamAccessRequestFailure::InvalidResponse.into()),
        };
        let session = personal.team_session(&store, op).await?;
        require_source(&store, &session.identity, &view.source)?;
        let base = collection_path(organization_id);
        let path = match pending.kind {
            0 => base,
            1 | 2 => format!("{base}/{}/decisions", pending.request),
            3 => format!("{base}/{}/cancel", pending.request),
            _ => unreachable!(),
        };
        let proof = session.proof("POST", &path)?;
        let current = now_ms()?;
        if !store
            .dispatch_team_access_request(&session.identity, &pending, &session.access, current)
            .map_err(storage)?
        {
            return Err(TeamAccessRequestFailure::OutcomeUnknown.into());
        }
        let sent = load(&store, &session.identity, organization_id, operation_id)?;
        let response = personal
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_exchange(
                &session.identity.origin,
                &path,
                Method::POST,
                (sent.kind != 3).then_some(sent.payload.as_bytes()),
                session.token()?,
                &proof,
                Some(sent.operation),
                sent.etag.as_deref(),
                MAX_ACCESS_REQUEST_RESOURCE_BYTES,
            )
            .await;
        let response = match response {
            Ok(response) => response,
            Err(PersonalServerError::ConnectionBeforeRequest) if pending.phase == 0 => {
                finish(&store, &session, &sent, None)?;
                return Err(PersonalServerError::ConnectionBeforeRequest.into());
            }
            Err(_) => return Err(TeamAccessRequestFailure::OutcomeUnknown.into()),
        };
        session.current(&store).map_err(|_| TeamAccessRequestFailure::OutcomeUnknown)?;
        if response.status == if sent.kind == 0 { 201 } else { 200 } {
            let resource = decode_response(&response, sent.request)
                .map_err(|_| TeamAccessRequestFailure::OutcomeUnknown)?;
            validate_result(&session.identity, &sent, &resource)
                .map_err(|_| TeamAccessRequestFailure::OutcomeUnknown)?;
            finish(&store, &session, &sent, Some(response.body.as_bytes()))?;
            let confirmed = load(&store, &session.identity, organization_id, operation_id)?;
            return operation_view(&store, &session.identity, &confirmed, now_ms()?);
        }
        let problem = problem(&response).map_err(|_| TeamAccessRequestFailure::OutcomeUnknown)?;
        let error =
            access_problem(&problem).map_err(|_| TeamAccessRequestFailure::OutcomeUnknown)?;
        // Only a first, verified no-change refusal can settle this dispatch. A later
        // refusal cannot prove that an earlier lost response did not commit.
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
        Err(error)
    }

    /// Clear prepared/confirmed state, or explicitly archive expired uncertainty.
    pub fn discard(
        &self,
        personal: &PersonalServer,
        store: &Store,
        organization_id: &str,
        operation_id: &str,
    ) -> Result<(), TeamAccessRequestError> {
        let _operation = personal.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(store)?;
        let pending = load(store, &identity, organization_id, operation_id)?;
        if operation_view(store, &identity, &pending, now_ms()?)?.phase
            == TeamCreationPhase::Unknown
        {
            return Err(TeamAccessRequestFailure::OutcomeUnknown.into());
        }
        if !store.discard_team_access_request(&identity, &pending, now_ms()?).map_err(storage)? {
            return Err(PersonalServerError::Busy.into());
        }
        Ok(())
    }

    /// Offer only currently visible ordinary Logins matching the approved original target.
    pub fn connection_targets(
        &self,
        personal: &PersonalServer,
        store: &Arc<Store>,
        intent_id: &str,
    ) -> Result<Vec<TeamAccessRequestLogin>, TeamAccessRequestError> {
        let identity = record(store)?;
        let intents = self.intents.lock().map_err(|_| PersonalServerError::Busy)?;
        let reviewed = intents
            .reviewed
            .as_ref()
            .filter(|intent| intent.id.to_string() == intent_id && intent.current(store, &identity))
            .ok_or(TeamAccessRequestFailure::ReviewRequired)?;
        if !resource_view(&reviewed.source, &reviewed.value, now_ms()?)?.can_connect {
            return Err(TeamAccessRequestFailure::ReviewRequired.into());
        }
        let snapshot = TeamConnectionSnapshot::load(store, personal, &reviewed.source)
            .map_err(|_| TeamAccessRequestFailure::LoginRequired)?;
        let logins = snapshot
            .matching_logins(reviewed.value.fields.host, &reviewed.value.fields.remote_user);
        Ok(logins
            .into_iter()
            .map(|(id, name)| TeamAccessRequestLogin {
                name,
                target: SessionTarget::OrganizationAccessRequest {
                    source: reviewed.source.clone(),
                    profile_id: id.to_string(),
                    host_id: reviewed.value.fields.host.to_string(),
                    remote_user: reviewed.value.fields.remote_user.clone(),
                },
            })
            .collect())
    }
}

fn source(store: &Store, identity: &PersonalRecord, organization: &str) -> TeamSshSource {
    TeamSshSource {
        origin: identity.origin.clone(),
        account_id: identity.account_id.to_string(),
        organization_id: organization.to_owned(),
        device_id: store.device_id().to_string(),
    }
}

fn require_source(
    store: &Store,
    identity: &PersonalRecord,
    supplied: &TeamSshSource,
) -> Result<(), TeamAccessRequestError> {
    parse_id(&supplied.organization_id)?;
    if *supplied != source(store, identity, &supplied.organization_id) {
        return Err(PersonalServerError::AuthenticationRequired.into());
    }
    Ok(())
}

fn collection_path(organization: &str) -> String {
    format!("/api/v1/orgs/{organization}/access-requests")
}

fn invalid_response<T>(_: T) -> TeamAccessRequestError {
    TeamAccessRequestFailure::InvalidResponse.into()
}

fn fields_view(fields: &AccessRequestFields) -> TeamAccessRequestFields {
    TeamAccessRequestFields {
        host_id: fields.host.to_string(),
        remote_user: fields.remote_user.clone(),
        duration_seconds: fields.duration_seconds,
        reason: fields.reason.clone(),
    }
}

fn resource_view(
    source: &TeamSshSource,
    value: &AccessRequestResource,
    current_ms: u64,
) -> Result<TeamAccessRequestResourceView, TeamAccessRequestError> {
    value.validate().map_err(invalid_response)?;
    let own = value.requester_account_id.to_string() == source.account_id;
    let deadline_passed = deadline_passed(&value.expires_at, current_ms);
    let pending = value.status == AccessRequestStatus::Pending && !deadline_passed;
    Ok(TeamAccessRequestResourceView {
        source: source.clone(),
        id: value.id.to_string(),
        etag: value.etag.clone(),
        created_at: value.created_at.clone(),
        updated_at: value.updated_at.clone(),
        requester_account_id: value.requester_account_id.to_string(),
        requester_membership_id: value.requester_membership_id.to_string(),
        fields: fields_view(&value.fields),
        expires_at: value.expires_at.clone(),
        status: value.status.as_str().into(),
        deadline_passed,
        can_cancel: own && pending,
        can_decide: !own && pending,
        can_connect: own
            && value.status == AccessRequestStatus::Approved
            && value.grant.as_ref().is_some_and(|grant| current_ms / 1000 < grant.valid_until),
        decision: value.decision.as_ref().map(|decision| TeamAccessRequestDecisionView {
            outcome: decision.outcome.as_str().into(),
            actor_account_id: decision.actor_account_id.to_string(),
            decided_at: decision.decided_at.clone(),
        }),
        grant: value
            .grant
            .as_ref()
            .map(|grant| {
                Ok::<_, TeamAccessRequestError>(TeamAccessRequestGrantView {
                    id: grant.id.to_string(),
                    valid_from: scoplen_api::grant::format_grant_timestamp(grant.valid_from)
                        .map_err(invalid_response)?,
                    valid_until: scoplen_api::grant::format_grant_timestamp(grant.valid_until)
                        .map_err(invalid_response)?,
                })
            })
            .transpose()?,
    })
}

fn deadline_passed(value: &str, current_ms: u64) -> bool {
    // The shared decoder already validated the complete arbitrary-precision UTC instant.
    let Ok(seconds) = scoplen_api::grant::parse_grant_timestamp(&format!("{}Z", &value[..19]))
    else {
        return true;
    };
    match (current_ms / 1000).cmp(&seconds) {
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Equal => {
            let fraction = if value.len() == 20 { "" } else { &value[20..value.len() - 1] };
            let milliseconds = format!("{:03}", current_ms % 1000);
            let precision = fraction.len().max(3);
            fraction
                .bytes()
                .chain(std::iter::repeat(b'0'))
                .take(precision)
                .cmp(milliseconds.bytes().chain(std::iter::repeat(b'0')).take(precision))
                != std::cmp::Ordering::Greater
        }
    }
}

fn prepare(
    store: &Store,
    identity: &PersonalRecord,
    pending: &TeamAccessRequestRecord,
) -> Result<(), TeamAccessRequestError> {
    if !store.prepare_team_access_request(identity, pending).map_err(storage)? {
        return Err(TeamAccessRequestFailure::OperationPending.into());
    }
    Ok(())
}

fn load(
    store: &Store,
    identity: &PersonalRecord,
    organization: &str,
    operation: &str,
) -> Result<TeamAccessRequestRecord, TeamAccessRequestError> {
    let id = parse_id(operation)?;
    let pending = store
        .team_access_request_pending(identity, parse_id(organization)?)
        .map_err(storage)?
        .filter(|pending| pending.operation == id)
        .ok_or(TeamAccessRequestFailure::OperationMissing)?;
    Ok(pending)
}

fn original(
    pending: &TeamAccessRequestRecord,
) -> Result<AccessRequestResource, TeamAccessRequestError> {
    let original = AccessRequestResource::from_json(
        pending.original.as_ref().ok_or(TeamAccessRequestFailure::InvalidResponse)?.as_bytes(),
    )
    .map_err(invalid_response)?;
    original.validate_for_id(pending.request).map_err(invalid_response)?;
    if pending.etag.as_deref() != Some(original.etag.as_str()) {
        return Err(TeamAccessRequestFailure::InvalidResponse.into());
    }
    Ok(original)
}

fn validate_result(
    identity: &PersonalRecord,
    pending: &TeamAccessRequestRecord,
    resource: &AccessRequestResource,
) -> Result<(), TeamAccessRequestError> {
    match pending.kind {
        0 => resource.validate_for_create(
            &AccessRequestCreateRequest::from_json(pending.payload.as_bytes())
                .map_err(invalid_response)?,
            identity.account_id,
        ),
        1 | 2 => resource.validate_for_decision(
            &original(pending)?,
            AccessRequestDecisionRequest::from_json(pending.payload.as_bytes())
                .map_err(invalid_response)?,
            identity.account_id,
        ),
        3 => resource.validate_for_cancel(&original(pending)?, identity.account_id),
        _ => return Err(TeamAccessRequestFailure::InvalidResponse.into()),
    }
    .map_err(invalid_response)
}

fn operation_view(
    store: &Store,
    identity: &PersonalRecord,
    pending: &TeamAccessRequestRecord,
    current: u64,
) -> Result<TeamAccessRequestOperationView, TeamAccessRequestError> {
    validate_uuid_v7(pending.operation).map_err(invalid_response)?;
    validate_uuid_v7(pending.request).map_err(invalid_response)?;
    let (action, fields) = match pending.kind {
        0 => {
            let request = AccessRequestCreateRequest::from_json(pending.payload.as_bytes())
                .map_err(invalid_response)?;
            if request.id != pending.request || pending.etag.is_some() || pending.original.is_some()
            {
                return Err(TeamAccessRequestFailure::InvalidResponse.into());
            }
            (TeamAccessRequestAction::Create, request.fields)
        }
        1 | 2 => {
            let decision = AccessRequestDecisionRequest::from_json(pending.payload.as_bytes())
                .map_err(invalid_response)?;
            let expected = if pending.kind == 1 {
                AccessRequestOutcome::Approve
            } else {
                AccessRequestOutcome::Deny
            };
            if decision.decision != expected {
                return Err(TeamAccessRequestFailure::InvalidResponse.into());
            }
            (
                if pending.kind == 1 {
                    TeamAccessRequestAction::Approve
                } else {
                    TeamAccessRequestAction::Deny
                },
                original(pending)?.fields,
            )
        }
        3 if pending.payload.as_bytes().is_empty() => {
            (TeamAccessRequestAction::Cancel, original(pending)?.fields)
        }
        _ => return Err(TeamAccessRequestFailure::InvalidResponse.into()),
    };
    let source = source(store, identity, &pending.organization.to_string());
    let result = pending
        .response
        .as_ref()
        .map(|body| {
            let resource =
                AccessRequestResource::from_json(body.as_bytes()).map_err(invalid_response)?;
            validate_result(identity, pending, &resource)?;
            resource_view(&source, &resource, current)
        })
        .transpose()?;
    let deadline = pending
        .first_attempt_ms
        .map(|first| first.saturating_add(ACCESS_REQUEST_PENDING_SECONDS * 1000));
    let phase = match (pending.phase, result.is_some()) {
        (2, true) => TeamCreationPhase::Confirmed,
        (0 | 1, false) if deadline.is_some_and(|deadline| current >= deadline) => {
            TeamCreationPhase::Expired
        }
        (0, false) => TeamCreationPhase::Prepared,
        (1, false) => TeamCreationPhase::Unknown,
        _ => return Err(TeamAccessRequestFailure::InvalidResponse.into()),
    };
    Ok(TeamAccessRequestOperationView {
        source,
        operation_id: pending.operation.to_string(),
        request_id: pending.request.to_string(),
        action,
        phase,
        retry_until: deadline.map(|deadline| deadline.to_string()),
        fields: fields_view(&fields),
        result,
    })
}

fn decode_response(
    response: &Response,
    id: Uuid,
) -> Result<AccessRequestResource, TeamAccessRequestError> {
    let resource = AccessRequestResource::from_http_json(
        response.body.as_bytes(),
        response.etag.as_deref(),
        response.cache_control.as_deref(),
        response.pragma.as_deref(),
    )
    .map_err(invalid_response)?;
    resource.validate_for_id(id).map_err(invalid_response)?;
    Ok(resource)
}

fn finish(
    store: &Store,
    session: &TeamSession,
    pending: &TeamAccessRequestRecord,
    response: Option<&[u8]>,
) -> Result<(), TeamAccessRequestError> {
    if !store
        .finish_team_access_request(
            &session.identity,
            pending,
            &session.access,
            response,
            now_ms()?,
        )
        .map_err(storage)?
    {
        return Err(TeamAccessRequestFailure::OutcomeUnknown.into());
    }
    Ok(())
}

fn access_problem(
    problem: &ProblemDetails,
) -> Result<TeamAccessRequestError, TeamAccessRequestError> {
    Ok(match (problem.status, problem.code.as_str(), problem.changed, problem.retryable) {
        (401, "auth.authentication_required", false, false) => {
            PersonalServerError::AuthenticationRequired.into()
        }
        (403, "policy.denied", false, false) => PersonalServerError::PermissionDenied.into(),
        (400 | 413 | 415, "organization.invalid_request", false, false) => {
            TeamAccessRequestFailure::InvalidInput.into()
        }
        (404, "organization.not_found", false, false) => TeamFailure::TeamNotFound.into(),
        (409, "organization.conflict", false, false)
        | (412, "organization.precondition_failed", false, false)
        | (428, "organization.precondition_required", false, false) => {
            TeamAccessRequestFailure::StaleVersion.into()
        }
        (503, "organization.commit_outcome_unknown", true, _) => {
            TeamAccessRequestFailure::OutcomeUnknown.into()
        }
        (503, "organization.storage_unavailable", false, true) | (429, _, false, true) => {
            TeamFailure::ServiceUnavailable.into()
        }
        _ => return Err(TeamAccessRequestFailure::InvalidResponse.into()),
    })
}

fn require_success(
    store: &Store,
    session: &TeamSession,
    response: &Response,
    expected: u16,
) -> Result<(), TeamAccessRequestError> {
    if response.status == expected {
        return Ok(());
    }
    let problem = problem(response)?;
    let error = access_problem(&problem)?;
    if problem.status == 401 {
        store.invalidate_personal_session(&session.identity, &session.access).map_err(storage)?;
    }
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::deadline_passed;

    #[test]
    fn deadline_checks_preserve_fractional_metadata_without_rounding() {
        let seconds = scoplen_api::grant::parse_grant_timestamp("2026-01-01T00:00:00Z").unwrap();
        let millis = seconds * 1000;
        assert!(!deadline_passed("2026-01-01T00:00:00.0000001Z", millis));
        assert!(deadline_passed("2026-01-01T00:00:00.0000001Z", millis + 1));
        assert!(!deadline_passed("2026-01-01T00:00:00.1230001Z", millis + 123));
        assert!(deadline_passed("2026-01-01T00:00:00.1230000Z", millis + 123));
        assert!(deadline_passed("2026-01-01T00:00:00Z", millis));
        assert!(!deadline_passed("2026-01-01T00:00:00Z", millis - 1));
        assert!(deadline_passed("1960-01-01T00:00:00.9Z", millis));
    }
}
