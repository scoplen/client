// SPDX-License-Identifier: Apache-2.0
//! Public access-request operations through authenticated TLS/H2 and encrypted persistence.

use std::collections::VecDeque;

use scoplen_api::access_request::{
    AccessRequestCheckRequest, AccessRequestCheckResponse, AccessRequestCreateRequest,
    AccessRequestDecision, AccessRequestDecisionRequest, AccessRequestGrant,
    AccessRequestListQuery, AccessRequestOutcome, AccessRequestPage, AccessRequestResource,
    AccessRequestStatus, AccessRequestView,
};
use uuid::Uuid;

use super::*;
use crate::{personal_server::*, session_manager::SessionManager};

#[derive(Default)]
enum Fault {
    #[default]
    None,
    Unknown,
    Denied,
    Malformed,
    Stale,
}

struct Sent {
    path: String,
    key: Uuid,
    etag: Option<String>,
    body: Vec<u8>,
}

pub(super) struct AccessPeer {
    observer: Arc<Store>,
    organization: Uuid,
    resources: BTreeMap<Uuid, AccessRequestResource>,
    receipts: BTreeMap<Uuid, (String, Option<String>, Vec<u8>, AccessRequestResource)>,
    faults: VecDeque<Fault>,
    checks: Vec<Vec<u8>>,
    sent: Vec<Sent>,
    allowed: bool,
}

impl AccessPeer {
    pub(super) fn answer(
        &mut self,
        request: &http::Request<h2::RecvStream>,
        body: &[u8],
    ) -> Result<Reply, String> {
        let prefix = format!("/api/v1/orgs/{}/access-requests", self.organization);
        let path = request.uri().path();
        let suffix = path.strip_prefix(&prefix).ok_or("foreign access-request team")?;
        let identity = record(&self.observer).unwrap();
        if request.method() == http::Method::POST && suffix == "/check" {
            if request.headers().contains_key("idempotency-key")
                || request.headers().contains_key("if-match")
            {
                return Err("check acquired a write key or precondition".into());
            }
            AccessRequestCheckRequest::from_json(body).map_err(|_| "invalid check")?;
            self.checks.push(body.to_vec());
            return Ok(json(
                AccessRequestCheckResponse { allowed: self.allowed }.to_json().unwrap(),
            ));
        }
        if request.method() == http::Method::GET {
            if !body.is_empty()
                || request.headers().contains_key("idempotency-key")
                || request.headers().contains_key("if-match")
            {
                return Err("read acquired a body/write key/precondition".into());
            }
            if suffix.is_empty() {
                let query = AccessRequestListQuery::from_parameters(
                    request
                        .uri()
                        .query()
                        .ok_or("missing view")?
                        .split('&')
                        .map(|pair| pair.split_once('=').unwrap()),
                )
                .map_err(|_| "invalid page query")?;
                let mut items = self
                    .resources
                    .values()
                    .filter(|item| match query.view {
                        AccessRequestView::Mine => item.requester_account_id == identity.account_id,
                        AccessRequestView::Approvals => {
                            item.status == AccessRequestStatus::Pending
                                && item.requester_account_id != identity.account_id
                        }
                    })
                    .filter(|item| query.page.cursor.is_none_or(|cursor| item.id > cursor))
                    .cloned()
                    .collect::<Vec<_>>();
                items.truncate(usize::from(query.page.limit));
                let page = AccessRequestPage { items, next_cursor: None };
                page.validate_for_query(identity.account_id, query).unwrap();
                return Ok(json(page.to_json().unwrap()));
            }
            let id = suffix
                .strip_prefix('/')
                .and_then(|id| Uuid::parse_str(id).ok())
                .ok_or("invalid GET id")?;
            return Ok(resource_reply(self.resources.get(&id).ok_or("missing request")?));
        }
        if request.method() != http::Method::POST || request.uri().query().is_some() {
            return Err("invalid request method".into());
        }
        let key = request
            .headers()
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or("missing original key")?;
        let etag = request
            .headers()
            .get("if-match")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let original = self
            .observer
            .team_access_request_pending(&identity, self.organization)
            .unwrap()
            .ok_or("no retained mutation")?;
        if original.operation != key
            || original.phase != 1
            || original.first_attempt_ms.is_none()
            || original.payload.as_bytes() != body
            || original.etag != etag
        {
            return Err("mutation preceded exact durable dispatch".into());
        }
        if suffix.ends_with("/cancel")
            && (request.headers().contains_key("content-type") || !body.is_empty())
        {
            return Err("cancellation acquired a body".into());
        }
        self.sent.push(Sent { path: path.into(), key, etag: etag.clone(), body: body.to_vec() });
        let fault = self.faults.pop_front().unwrap_or_default();
        if matches!(fault, Fault::Denied) {
            return Ok(problem(403, "policy.denied", false));
        }
        if matches!(fault, Fault::Stale) {
            return Ok(problem(412, "organization.precondition_failed", false));
        }
        let response = if let Some((original_path, original_etag, original_body, response)) =
            self.receipts.get(&key)
        {
            if original_path != path || original_etag != &etag || original_body != body {
                return Err("changed original mutation".into());
            }
            response.clone()
        } else {
            let mut response = if suffix.is_empty() {
                if etag.is_some() {
                    return Err("create acquired an ETag".into());
                }
                let parsed =
                    AccessRequestCreateRequest::from_json(body).map_err(|_| "invalid create")?;
                let now = now().unwrap();
                AccessRequestResource {
                    id: parsed.id,
                    etag: "\"1\"".into(),
                    created_at: timestamp(now),
                    updated_at: timestamp(now),
                    requester_account_id: identity.account_id,
                    requester_membership_id: Uuid::now_v7(),
                    fields: parsed.fields,
                    expires_at: timestamp(now + 86_400),
                    status: AccessRequestStatus::Pending,
                    decision: None,
                    grant: None,
                }
            } else {
                let id = suffix
                    .strip_prefix('/')
                    .unwrap()
                    .split('/')
                    .next()
                    .and_then(|value| Uuid::parse_str(value).ok())
                    .ok_or("invalid action id")?;
                let mut resource =
                    self.resources.get(&id).cloned().ok_or("missing original action")?;
                if etag.as_deref() != Some(resource.etag.as_str()) {
                    return Ok(problem(412, "organization.precondition_failed", false));
                }
                if suffix.ends_with("/decisions") {
                    let decision = AccessRequestDecisionRequest::from_json(body)
                        .map_err(|_| "invalid decision")?;
                    let now = now().unwrap();
                    resource.status = match decision.decision {
                        AccessRequestOutcome::Approve => AccessRequestStatus::Approved,
                        AccessRequestOutcome::Deny => AccessRequestStatus::Denied,
                    };
                    resource.decision = Some(AccessRequestDecision {
                        outcome: decision.decision,
                        actor_account_id: identity.account_id,
                        decided_at: timestamp(now),
                    });
                    resource.grant =
                        (decision.decision == AccessRequestOutcome::Approve).then(|| {
                            AccessRequestGrant {
                                id: Uuid::now_v7(),
                                valid_from: now,
                                valid_until: now + u64::from(resource.fields.duration_seconds),
                            }
                        });
                } else if suffix.ends_with("/cancel") {
                    resource.status = AccessRequestStatus::Cancelled;
                } else {
                    return Err("invalid action route".into());
                }
                resource
            };
            response.etag = format!("\"{}\"", self.receipts.len() + 2);
            response.updated_at = timestamp(now().unwrap());
            response.validate().map_err(|_| "invalid fixture response")?;
            self.resources.insert(response.id, response.clone());
            self.receipts.insert(key, (path.into(), etag, body.to_vec(), response.clone()));
            response
        };
        if matches!(fault, Fault::Unknown) {
            return Ok(problem(503, "organization.commit_outcome_unknown", true));
        }
        let mut reply = resource_reply(&response);
        if suffix.is_empty() {
            reply.status = 201;
        }
        if matches!(fault, Fault::Malformed) {
            reply.headers.retain(|(name, _)| *name != "etag");
        }
        Ok(reply)
    }
}

fn timestamp(seconds: u64) -> String {
    scoplen_api::grant::format_grant_timestamp(seconds).unwrap()
}
fn json(body: Vec<u8>) -> Reply {
    Reply {
        status: 200,
        content_type: "application/json",
        headers: vec![
            ("cache-control", "no-store".into()),
            ("pragma", "no-cache".into()),
            ("x-request-id", "request-fixture".into()),
        ],
        body,
        stall: false,
    }
}
fn resource_reply(resource: &AccessRequestResource) -> Reply {
    let mut reply = json(resource.to_json().unwrap());
    reply.headers.push(("etag", resource.etag.clone()));
    reply
}
fn problem(status: u16, code: &str, changed: bool) -> Reply {
    let value = scoplen_api::ProblemDetails::new(
        scoplen_api::ErrorCode::new(code).unwrap(),
        status,
        "Fixture",
        "Fixture",
        "request-fixture",
        changed,
        changed,
    )
    .unwrap();
    Reply {
        status,
        content_type: "application/problem+json",
        ..json(serde_json::to_vec(&value).unwrap())
    }
}

struct Fixture {
    peer: Peer,
    _directory: tempfile::TempDir,
    store: Arc<Store>,
    personal: PersonalServer,
    requests: TeamAccessRequests,
    sessions: SessionManager,
    source: TeamSshSource,
    host: Uuid,
}
impl Fixture {
    async fn new() -> Self {
        let peer = Peer::new().await;
        let directory = tempfile::tempdir().unwrap();
        let store = local(&directory);
        let personal = peer.prepare(&store).await;
        let identity = record(&store).unwrap();
        let organization = Uuid::now_v7();
        let source = TeamSshSource {
            origin: identity.origin.clone(),
            account_id: identity.account_id.to_string(),
            organization_id: organization.to_string(),
            device_id: store.device_id().to_string(),
        };
        peer.state.lock().unwrap().team_access_requests = Some(AccessPeer {
            observer: store.clone(),
            organization,
            resources: BTreeMap::new(),
            receipts: BTreeMap::new(),
            faults: VecDeque::new(),
            checks: vec![],
            sent: vec![],
            allowed: true,
        });
        let sessions = SessionManager::default();
        let host = Uuid::now_v7();
        sessions.fixture_access_request_denial(
            &store,
            "denied",
            TeamSshPolicyDenial {
                source: source.clone(),
                host_id: host.to_string(),
                remote_user: " e\u{301} ".into(),
            },
        );
        Self {
            peer,
            _directory: directory,
            store,
            personal,
            requests: TeamAccessRequests::default(),
            sessions,
            source,
            host,
        }
    }
    fn fault(&self, fault: Fault) {
        self.peer
            .state
            .lock()
            .unwrap()
            .team_access_requests
            .as_mut()
            .unwrap()
            .faults
            .push_back(fault);
    }
    async fn checked(&self) -> TeamAccessRequestCheckView {
        self.requests
            .check(
                &self.personal,
                &self.sessions,
                self.store.clone(),
                "denied",
                TeamAccessRequestDraft {
                    duration_seconds: 600,
                    reason: " Review\tthis exact input\nwithout normalization ".into(),
                },
            )
            .await
            .unwrap()
    }
    async fn prepare(&self) -> TeamAccessRequestOperationView {
        let checked = self.checked().await;
        self.requests
            .prepare_create(&self.personal, &self.store, checked.check_id.as_deref().unwrap())
            .unwrap()
    }
    async fn submit(
        &self,
        original: &TeamAccessRequestOperationView,
    ) -> Result<TeamAccessRequestOperationView, TeamAccessRequestError> {
        self.requests
            .submit(
                &self.personal,
                self.store.clone(),
                &self.source.organization_id,
                &original.operation_id,
            )
            .await
    }
    async fn review(&self, id: &str) -> TeamAccessRequestReviewView {
        self.requests
            .review(&self.personal, self.store.clone(), &self.source.organization_id, id)
            .await
            .unwrap()
    }
    fn clear(&self, original: &TeamAccessRequestOperationView) {
        self.requests
            .discard(
                &self.personal,
                &self.store,
                &self.source.organization_id,
                &original.operation_id,
            )
            .unwrap();
    }
    fn other_request(&self) -> AccessRequestResource {
        let now = now().unwrap();
        let item = AccessRequestResource {
            id: Uuid::now_v7(),
            etag: "\"reviewed\"".into(),
            created_at: timestamp(now),
            updated_at: timestamp(now),
            requester_account_id: Uuid::now_v7(),
            requester_membership_id: Uuid::now_v7(),
            fields: scoplen_api::access_request::AccessRequestFields {
                host: self.host,
                remote_user: "remote-user".into(),
                duration_seconds: 600,
                reason: "Exact request".into(),
            },
            expires_at: timestamp(now + 86_400),
            status: AccessRequestStatus::Pending,
            decision: None,
            grant: None,
        };
        self.peer
            .state
            .lock()
            .unwrap()
            .team_access_requests
            .as_mut()
            .unwrap()
            .resources
            .insert(item.id, item.clone());
        item
    }
}

#[tokio::test]
async fn check_create_mine_and_cancel_keep_exact_input_and_original_headers() {
    let fixture = Fixture::new().await;
    let checked = fixture.checked().await;
    assert_eq!(checked.source, fixture.source);
    assert_eq!(checked.fields.host_id, fixture.host.to_string());
    assert_eq!(checked.fields.remote_user, " e\u{301} ");
    assert_eq!(checked.fields.reason, " Review\tthis exact input\nwithout normalization ");
    assert!(
        fixture
            .requests
            .pending(&fixture.store, &fixture.source.organization_id)
            .unwrap()
            .is_none()
    );
    let prepared = fixture
        .requests
        .prepare_create(&fixture.personal, &fixture.store, checked.check_id.as_deref().unwrap())
        .unwrap();
    assert_eq!(prepared.phase, TeamCreationPhase::Prepared);
    assert!(
        fixture
            .requests
            .prepare_create(&fixture.personal, &fixture.store, checked.check_id.as_deref().unwrap())
            .is_err()
    );
    let confirmed = fixture.submit(&prepared).await.unwrap();
    assert_eq!(confirmed.phase, TeamCreationPhase::Confirmed);
    let page = fixture
        .requests
        .page(
            &fixture.personal,
            fixture.store.clone(),
            &fixture.source.organization_id,
            TeamAccessRequestList::Mine,
            None,
        )
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].fields, checked.fields);
    assert!(page.items[0].can_cancel);
    assert!(!page.items[0].can_decide);
    fixture.clear(&confirmed);
    let review = fixture.review(&prepared.request_id).await;
    assert!(
        fixture
            .requests
            .prepare_action(
                &fixture.personal,
                &fixture.store,
                &review.intent_id,
                TeamAccessRequestAction::Approve
            )
            .is_err()
    );
    let cancel = fixture
        .requests
        .prepare_action(
            &fixture.personal,
            &fixture.store,
            &review.intent_id,
            TeamAccessRequestAction::Cancel,
        )
        .unwrap();
    let cancelled = fixture.submit(&cancel).await.unwrap();
    assert_eq!(cancelled.result.as_ref().unwrap().status, "cancelled");
    let state = fixture.peer.state.lock().unwrap();
    let peer = state.team_access_requests.as_ref().unwrap();
    assert_eq!(peer.sent.len(), 2);
    assert!(peer.sent[0].etag.is_none());
    assert_eq!(peer.sent[1].etag.as_deref(), Some(review.resource.etag.as_str()));
    assert!(peer.sent[1].body.is_empty());
    assert!(peer.sent[1].path.ends_with("/cancel"));
    drop(state);
    fixture.peer.assert_healthy();
}

#[tokio::test]
async fn unknown_create_retains_exact_receipt_across_reopen_and_never_automatically_replays() {
    let fixture = Fixture::new().await;
    let prepared = fixture.prepare().await;
    fixture.fault(Fault::Unknown);
    assert_eq!(
        fixture.submit(&prepared).await,
        Err(TeamAccessRequestFailure::OutcomeUnknown.into())
    );
    let unknown =
        fixture.requests.pending(&fixture.store, &fixture.source.organization_id).unwrap().unwrap();
    assert_eq!(unknown.phase, TeamCreationPhase::Unknown);
    assert!(
        fixture
            .requests
            .discard(
                &fixture.personal,
                &fixture.store,
                &fixture.source.organization_id,
                &prepared.operation_id
            )
            .is_err()
    );
    let reopened = local(&fixture._directory);
    let requests = TeamAccessRequests::default();
    assert_eq!(
        requests.pending(&reopened, &fixture.source.organization_id).unwrap().unwrap(),
        unknown
    );
    assert_eq!(
        fixture.peer.state.lock().unwrap().team_access_requests.as_ref().unwrap().sent.len(),
        1
    );
    let confirmed = requests
        .submit(
            &fixture.personal,
            reopened,
            &fixture.source.organization_id,
            &prepared.operation_id,
        )
        .await
        .unwrap();
    assert_eq!(confirmed.phase, TeamCreationPhase::Confirmed);
    let state = fixture.peer.state.lock().unwrap();
    let sent = &state.team_access_requests.as_ref().unwrap().sent;
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].key, sent[1].key);
    assert_eq!(sent[0].body, sent[1].body);
    assert_eq!(sent[0].path, sent[1].path);
    drop(state);
    fixture.peer.assert_healthy();
}

#[tokio::test]
async fn malformed_success_is_unknown_and_later_policy_refusal_cannot_settle_it() {
    let fixture = Fixture::new().await;
    let prepared = fixture.prepare().await;
    fixture.fault(Fault::Malformed);
    assert_eq!(
        fixture.submit(&prepared).await,
        Err(TeamAccessRequestFailure::OutcomeUnknown.into())
    );
    fixture.fault(Fault::Denied);
    assert_eq!(fixture.submit(&prepared).await, Err(PersonalServerError::PermissionDenied.into()));
    assert_eq!(
        fixture
            .requests
            .pending(&fixture.store, &fixture.source.organization_id)
            .unwrap()
            .unwrap()
            .phase,
        TeamCreationPhase::Unknown
    );
    assert_eq!(fixture.submit(&prepared).await.unwrap().phase, TeamCreationPhase::Confirmed);
    fixture.peer.assert_healthy();
}

#[tokio::test]
async fn approval_and_denial_use_whole_original_resource_and_self_approval_is_refused() {
    let fixture = Fixture::new().await;
    for action in [TeamAccessRequestAction::Approve, TeamAccessRequestAction::Deny] {
        let item = fixture.other_request();
        let page = fixture
            .requests
            .page(
                &fixture.personal,
                fixture.store.clone(),
                &fixture.source.organization_id,
                TeamAccessRequestList::Approvals,
                None,
            )
            .await
            .unwrap();
        assert!(
            page.items
                .iter()
                .any(|resource| resource.id == item.id.to_string() && resource.can_decide)
        );
        let reviewed = fixture.review(&item.id.to_string()).await;
        assert!(
            fixture
                .requests
                .prepare_action(
                    &fixture.personal,
                    &fixture.store,
                    &reviewed.intent_id,
                    TeamAccessRequestAction::Cancel
                )
                .is_err()
        );
        let prepared = fixture
            .requests
            .prepare_action(&fixture.personal, &fixture.store, &reviewed.intent_id, action)
            .unwrap();
        let confirmed = fixture.submit(&prepared).await.unwrap();
        let result = confirmed.result.as_ref().unwrap();
        assert_eq!(result.fields, reviewed.resource.fields);
        assert_eq!(
            result.status,
            if action == TeamAccessRequestAction::Approve { "approved" } else { "denied" }
        );
        assert_eq!(result.decision.as_ref().unwrap().actor_account_id, fixture.source.account_id);
        assert_eq!(result.grant.is_some(), action == TeamAccessRequestAction::Approve);
        assert!(!result.can_connect, "another requester's approval is only history");
        fixture.clear(&confirmed);
    }
    fixture.peer.assert_healthy();
}

#[tokio::test]
async fn unknown_decision_never_substitutes_a_refreshed_etag_or_different_action() {
    let fixture = Fixture::new().await;
    let item = fixture.other_request();
    let review = fixture.review(&item.id.to_string()).await;
    let prepared = fixture
        .requests
        .prepare_action(
            &fixture.personal,
            &fixture.store,
            &review.intent_id,
            TeamAccessRequestAction::Approve,
        )
        .unwrap();
    fixture.fault(Fault::Unknown);
    assert_eq!(
        fixture.submit(&prepared).await,
        Err(TeamAccessRequestFailure::OutcomeUnknown.into())
    );
    let current = fixture.review(&item.id.to_string()).await;
    assert_ne!(current.resource.etag, review.resource.etag);
    assert_eq!(current.resource.status, "approved");
    let confirmed = fixture.submit(&prepared).await.unwrap();
    assert_eq!(confirmed.action, TeamAccessRequestAction::Approve);
    let state = fixture.peer.state.lock().unwrap();
    let sent = &state.team_access_requests.as_ref().unwrap().sent;
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].key, sent[1].key);
    assert_eq!(sent[0].etag, sent[1].etag);
    assert_eq!(sent[0].etag.as_deref(), Some(review.resource.etag.as_str()));
    assert_eq!(sent[0].body, sent[1].body);
    drop(state);
    fixture.peer.assert_healthy();
}

#[tokio::test]
async fn first_no_change_stale_refusal_preserves_original_precondition_as_prepared() {
    let fixture = Fixture::new().await;
    let item = fixture.other_request();
    let review = fixture.review(&item.id.to_string()).await;
    let prepared = fixture
        .requests
        .prepare_action(
            &fixture.personal,
            &fixture.store,
            &review.intent_id,
            TeamAccessRequestAction::Deny,
        )
        .unwrap();
    fixture.fault(Fault::Stale);
    assert_eq!(fixture.submit(&prepared).await, Err(TeamAccessRequestFailure::StaleVersion.into()));
    let retained =
        fixture.requests.pending(&fixture.store, &fixture.source.organization_id).unwrap().unwrap();
    assert_eq!(retained.phase, TeamCreationPhase::Prepared);
    assert_eq!(retained.fields, prepared.fields);
    fixture.clear(&retained);
    fixture.peer.assert_healthy();
}

#[tokio::test]
async fn eligibility_false_invalid_input_and_missing_actual_denial_never_enable_create() {
    let fixture = Fixture::new().await;
    fixture.peer.state.lock().unwrap().team_access_requests.as_mut().unwrap().allowed = false;
    let check = fixture.checked().await;
    assert!(!check.allowed && check.check_id.is_none());
    for draft in [
        TeamAccessRequestDraft { duration_seconds: 0, reason: "request".into() },
        TeamAccessRequestDraft { duration_seconds: 600, reason: " \t\n".into() },
        TeamAccessRequestDraft { duration_seconds: 600, reason: "control\u{0}".into() },
    ] {
        assert_eq!(
            fixture
                .requests
                .check(&fixture.personal, &fixture.sessions, fixture.store.clone(), "denied", draft)
                .await,
            Err(TeamAccessRequestFailure::InvalidInput.into())
        );
    }
    assert_eq!(
        fixture
            .requests
            .check(
                &fixture.personal,
                &fixture.sessions,
                fixture.store.clone(),
                "caller-authored",
                TeamAccessRequestDraft { duration_seconds: 600, reason: "request".into() }
            )
            .await,
        Err(TeamAccessRequestFailure::CheckRequired.into())
    );
    assert!(
        fixture
            .requests
            .pending(&fixture.store, &fixture.source.organization_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture.peer.state.lock().unwrap().team_access_requests.as_ref().unwrap().checks.len(),
        1
    );
    fixture.peer.assert_healthy();
}

#[tokio::test]
async fn checked_and_reviewed_intents_are_bound_to_exact_store_and_authentication_generation() {
    let fixture = Fixture::new().await;
    let check = fixture.checked().await;
    let reopened = local(&fixture._directory);
    assert_eq!(
        fixture.requests.prepare_create(
            &fixture.personal,
            &reopened,
            check.check_id.as_deref().unwrap()
        ),
        Err(TeamAccessRequestFailure::CheckRequired.into())
    );
    let other = fixture.other_request();
    let review = fixture.review(&other.id.to_string()).await;
    fixture.peer.install_token(&fixture.store, |_| {}, None);
    assert_eq!(
        fixture.requests.prepare_create(
            &fixture.personal,
            &fixture.store,
            check.check_id.as_deref().unwrap()
        ),
        Err(TeamAccessRequestFailure::CheckRequired.into())
    );
    assert_eq!(
        fixture.requests.prepare_action(
            &fixture.personal,
            &fixture.store,
            &review.intent_id,
            TeamAccessRequestAction::Approve
        ),
        Err(TeamAccessRequestFailure::ReviewRequired.into())
    );
    assert!(fixture.sessions.team_access_request_denial(&fixture.store, "denied").is_none());
    fixture.peer.assert_healthy();
}

#[tokio::test]
async fn expired_pending_and_unknown_future_history_are_inert() {
    let fixture = Fixture::new().await;
    let mut item = fixture.other_request();
    item.created_at = "2020-01-01T00:00:00.0001Z".into();
    item.updated_at = item.created_at.clone();
    item.expires_at = "2020-01-02T00:00:00.0001Z".into();
    fixture
        .peer
        .state
        .lock()
        .unwrap()
        .team_access_requests
        .as_mut()
        .unwrap()
        .resources
        .insert(item.id, item.clone());
    let review = fixture.review(&item.id.to_string()).await;
    assert!(review.resource.deadline_passed);
    assert!(
        !review.resource.can_decide && !review.resource.can_cancel && !review.resource.can_connect
    );
    assert!(
        fixture
            .requests
            .prepare_action(
                &fixture.personal,
                &fixture.store,
                &review.intent_id,
                TeamAccessRequestAction::Approve
            )
            .is_err()
    );
    item.status = AccessRequestStatus::Unknown("future_outcome".into());
    fixture
        .peer
        .state
        .lock()
        .unwrap()
        .team_access_requests
        .as_mut()
        .unwrap()
        .resources
        .insert(item.id, item.clone());
    let future = fixture.review(&item.id.to_string()).await;
    assert_eq!(future.resource.status, "future_outcome");
    assert!(
        !future.resource.can_decide && !future.resource.can_cancel && !future.resource.can_connect
    );
    fixture.peer.assert_healthy();
}

#[tokio::test]
async fn original_confirmation_deadline_survives_restart_and_expires_without_network() {
    let fixture = Fixture::new().await;
    let prepared = fixture.prepare().await;
    fixture.fault(Fault::Unknown);
    assert_eq!(
        fixture.submit(&prepared).await,
        Err(TeamAccessRequestFailure::OutcomeUnknown.into())
    );
    crate::personal_server::tests::database(&fixture._directory)
        .execute("UPDATE team_access_requests SET first_attempt_ms=0", [])
        .unwrap();
    let requests = TeamAccessRequests::default();
    let expired =
        requests.pending(&fixture.store, &fixture.source.organization_id).unwrap().unwrap();
    assert_eq!(expired.phase, TeamCreationPhase::Expired);
    assert_eq!(
        fixture.submit(&expired).await,
        Err(TeamAccessRequestFailure::OperationExpired.into())
    );
    assert_eq!(
        fixture.peer.state.lock().unwrap().team_access_requests.as_ref().unwrap().sent.len(),
        1
    );
    fixture.clear(&expired);
    assert!(requests.pending(&fixture.store, &fixture.source.organization_id).unwrap().is_none());
    fixture.peer.assert_healthy();
}

#[tokio::test]
async fn narrower_device_scope_cannot_check_or_dispatch_an_existing_request() {
    let fixture = Fixture::new().await;
    let prepared = fixture.prepare().await;
    fixture.peer.install_token(
        &fixture.store,
        |claims| claims.scope = "access-requests:read".into(),
        None,
    );
    let mut identity = record(&fixture.store).unwrap();
    identity.auth_scope = Some("access-requests:read".into());
    fixture.store.set_personal_session_metadata_for_test(&identity).unwrap();
    assert_eq!(fixture.submit(&prepared).await, Err(TeamFailure::MembershipScopeRequired.into()));
    assert!(
        fixture.peer.state.lock().unwrap().team_access_requests.as_ref().unwrap().sent.is_empty()
    );
    let own = fixture
        .requests
        .page(
            &fixture.personal,
            fixture.store.clone(),
            &fixture.source.organization_id,
            TeamAccessRequestList::Mine,
            None,
        )
        .await
        .unwrap();
    assert!(own.items.is_empty());
    fixture.peer.assert_healthy();
}
