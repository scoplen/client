// SPDX-License-Identifier: Apache-2.0
//! Public shared codecs and real authenticated TLS exercise the team consumer independently.

use std::collections::VecDeque;

use scoplen_api::{
    ErrorCode, ProblemDetails,
    organization::{
        OrganizationCreateRequest, OrganizationMembership, OrganizationPage, OrganizationResource,
    },
};

use super::*;
use crate::personal_server::{TeamCreationPhase, TeamError, TeamFailure};

#[derive(Default)]
enum Mode {
    #[default]
    Success,
    LostAfterCommit,
    UnknownBeforeCommit,
    UnknownAfterCommit,
    Rollback,
    Denied,
    InvalidProblem,
    BadMetadata,
}

pub(super) struct TeamPeer {
    observer: Arc<Store>,
    resources: BTreeMap<uuid::Uuid, OrganizationResource>,
    receipts: BTreeMap<uuid::Uuid, (Vec<u8>, uuid::Uuid)>,
    requests: Vec<(uuid::Uuid, Vec<u8>)>,
    modes: VecDeque<Mode>,
    read_reply: Option<Reply>,
}

impl TeamPeer {
    pub(super) fn answer(
        &mut self,
        request: &http::Request<h2::RecvStream>,
        body: &[u8],
    ) -> Result<Reply, String> {
        let path = request.uri().path();
        if request.method() == http::Method::POST && path == "/api/v1/orgs" {
            if request.uri().query().is_some()
                || request.headers().contains_key("if-match")
                || request.headers().get("content-type").and_then(|header| header.to_str().ok())
                    != Some("application/json")
            {
                return Err("invalid team create request".into());
            }
            let key = request
                .headers()
                .get("idempotency-key")
                .and_then(|header| header.to_str().ok())
                .and_then(|text| uuid::Uuid::parse_str(text).ok())
                .ok_or("missing team key")?;
            let parsed =
                OrganizationCreateRequest::from_json(body).map_err(|_| "invalid team body")?;
            let identity = record(&self.observer).unwrap();
            let pending = self.observer.team_creation(&identity).unwrap().unwrap();
            if pending.phase != 1
                || pending.first_attempt_ms.is_none()
                || pending.operation_id != key
                || pending.payload.as_bytes() != body
            {
                return Err("team request preceded its durable dispatch".into());
            }
            self.requests.push((key, body.to_vec()));
            let mode = self.modes.pop_front().unwrap_or_default();
            match mode {
                Mode::UnknownBeforeCommit => {
                    return Ok(problem("organization.commit_outcome_unknown", true, true, 503));
                }
                Mode::Rollback => {
                    return Ok(problem("organization.storage_unavailable", false, true, 503));
                }
                Mode::Denied => return Ok(problem("policy.denied", false, false, 403)),
                Mode::InvalidProblem => {
                    return Ok(Reply {
                        status: 503,
                        content_type: "application/problem+json",
                        ..json(br#"{"changed":false,"changed":true}"#.to_vec())
                    });
                }
                _ => {}
            }
            let id = if let Some((previous, id)) = self.receipts.get(&key) {
                if previous.as_slice() != body {
                    return Ok(problem("organization.conflict", false, false, 409));
                }
                *id
            } else {
                let resource = resource(identity.account_id, &parsed.name);
                let id = resource.id;
                self.resources.insert(id, resource);
                self.receipts.insert(key, (body.to_vec(), id));
                id
            };
            if matches!(mode, Mode::UnknownAfterCommit) {
                return Ok(problem("organization.commit_outcome_unknown", true, true, 503));
            }
            let resource = self.resources.get(&id).unwrap();
            let mut reply = resource_reply(resource);
            reply.status = 201;
            reply.stall = matches!(mode, Mode::LostAfterCommit);
            if matches!(mode, Mode::BadMetadata) {
                reply.headers.retain(|(name, _)| *name != "x-request-id");
            }
            return Ok(reply);
        }
        if request.method() != http::Method::GET
            || !body.is_empty()
            || request.headers().contains_key("idempotency-key")
            || request.headers().contains_key("if-match")
        {
            return Err("invalid team read request".into());
        }
        if let Some(reply) = &self.read_reply {
            return Ok(reply.clone());
        }
        if path == "/api/v1/orgs" {
            let parameters = request
                .uri()
                .query()
                .unwrap_or("")
                .split('&')
                .filter(|part| !part.is_empty())
                .map(|part| part.split_once('=').unwrap());
            let query =
                scoplen_api::organization::OrganizationListQuery::from_parameters(parameters)
                    .map_err(|_| "invalid team query")?;
            let mut eligible = self
                .resources
                .values()
                .filter(|resource| query.cursor.is_none_or(|cursor| resource.id > cursor));
            let items = eligible.by_ref().take(query.limit as usize).cloned().collect::<Vec<_>>();
            let next_cursor =
                eligible.next().and_then(|_| items.last().map(|resource| resource.id));
            return Ok(json(OrganizationPage { items, next_cursor }.to_json().unwrap()));
        }
        let id = path
            .strip_prefix("/api/v1/orgs/")
            .and_then(|text| uuid::Uuid::parse_str(text).ok())
            .ok_or("invalid team path")?;
        Ok(self
            .resources
            .get(&id)
            .map(resource_reply)
            .unwrap_or_else(|| problem("organization.not_found", false, false, 404)))
    }
}

fn install(peer: &Peer, store: &Arc<Store>, modes: Vec<Mode>) {
    peer.state.lock().unwrap().teams = Some(TeamPeer {
        observer: store.clone(),
        resources: BTreeMap::new(),
        receipts: BTreeMap::new(),
        requests: Vec::new(),
        modes: modes.into(),
        read_reply: None,
    });
}

fn resource(account: uuid::Uuid, name: &str) -> OrganizationResource {
    OrganizationResource {
        id: scoplen_model::new_uuid_v7().unwrap(),
        etag: "\"one\"".into(),
        created_at: "2026-10-26T00:00:00Z".into(),
        updated_at: "2026-10-26T00:00:00Z".into(),
        name: name.into(),
        membership: OrganizationMembership {
            id: scoplen_model::new_uuid_v7().unwrap(),
            account_id: account,
            roles: vec!["owner".into()],
        },
    }
}

fn json(body: Vec<u8>) -> Reply {
    Reply {
        content_type: "application/json",
        headers: vec![
            ("cache-control", "no-store".into()),
            ("pragma", "no-cache".into()),
            ("x-request-id", "fixture-request".into()),
        ],
        ..Reply::cbor(body)
    }
}

fn resource_reply(resource: &OrganizationResource) -> Reply {
    let mut reply = json(resource.to_json().unwrap());
    reply.headers.push(("etag", resource.etag.clone()));
    reply
}

fn problem(code: &str, changed: bool, retryable: bool, status: u16) -> Reply {
    let problem = ProblemDetails::new(
        ErrorCode::new(code).unwrap(),
        status,
        "Fixture",
        "Fixture denial",
        "fixture-request",
        changed,
        retryable,
    )
    .unwrap();
    Reply {
        status,
        content_type: "application/problem+json",
        ..json(serde_json::to_vec(&problem).unwrap())
    }
}

#[tokio::test]
async fn team_creation_discovery_and_read_preserve_personal_identity_and_keys() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![]);
    let before = record(&store).unwrap();
    let bootstrap = manager.bootstrap_sync(store.clone()).await.unwrap();
    let paths = peer.state.lock().unwrap().paths.len();
    assert!(manager.pending_team_creation(&store).unwrap().is_none());
    let prepared = manager.prepare_team_creation(&store, "Operations".into()).unwrap();
    assert_eq!(peer.state.lock().unwrap().paths.len(), paths);
    assert_eq!(prepared.phase, TeamCreationPhase::Prepared);
    let confirmed =
        manager.submit_team_creation(store.clone(), &prepared.operation_id).await.unwrap();
    assert_eq!(confirmed.phase, TeamCreationPhase::Confirmed);
    let created = confirmed.organization.as_ref().unwrap();
    assert_eq!(created.roles, ["owner"]);
    assert_eq!(manager.team(store.clone(), &created.id).await.unwrap(), *created);
    {
        let mut state = peer.state.lock().unwrap();
        let teams = state.teams.as_mut().unwrap();
        for _ in 0..51 {
            let mut extra = resource(before.account_id, "Another team");
            extra.membership.roles = vec!["future_role".into()];
            teams.resources.insert(extra.id, extra);
        }
    }
    let page = manager.teams_page(store.clone(), None).await.unwrap();
    assert_eq!(page.teams.len(), 50);
    assert!(page.next_cursor.is_some());
    let last = manager.teams_page(store.clone(), page.next_cursor.as_deref()).await.unwrap();
    assert_eq!(last.teams.len(), 2);
    assert!(last.next_cursor.is_none());
    assert!(last.teams.iter().all(|team| team.roles == ["future_role"]));
    let after = manager.bootstrap_sync(store.clone()).await.unwrap();
    assert_eq!(after.session(), bootstrap.session());
    assert_eq!(after.personal_vault_key().as_bytes(), bootstrap.personal_vault_key().as_bytes());
    assert_eq!(
        record(&store).unwrap().private_material.as_bytes(),
        before.private_material.as_bytes()
    );
    manager.discard_team_creation(&store, &prepared.operation_id).unwrap();
    assert!(manager.pending_team_creation(&store).unwrap().is_none());
    peer.assert_healthy();
}

#[tokio::test]
async fn uncertain_creation_reopens_and_retries_exactly_without_another_team() {
    for mode in [Mode::LostAfterCommit, Mode::UnknownBeforeCommit, Mode::UnknownAfterCommit] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = peer.prepare(&store).await;
        install(&peer, &store, vec![mode]);
        let prepared = manager.prepare_team_creation(&store, "Operations".into()).unwrap();
        assert_eq!(
            manager.submit_team_creation(store.clone(), &prepared.operation_id).await,
            Err(TeamError::Team(TeamFailure::OutcomeUnknown))
        );
        assert_eq!(
            manager.pending_team_creation(&store).unwrap().unwrap().phase,
            TeamCreationPhase::Unknown
        );
        assert_eq!(
            manager.discard_team_creation(&store, &prepared.operation_id),
            Err(TeamFailure::OutcomeUnknown.into())
        );
        drop(store);
        let store = local(&dir);
        let manager = peer.manager();
        let reopened = manager.pending_team_creation(&store).unwrap().unwrap();
        let confirmed =
            manager.submit_team_creation(store.clone(), &reopened.operation_id).await.unwrap();
        assert_eq!(confirmed.phase, TeamCreationPhase::Confirmed);
        assert_eq!(confirmed.retry_until, reopened.retry_until);
        let state = peer.state.lock().unwrap();
        let teams = state.teams.as_ref().unwrap();
        assert_eq!(teams.resources.len(), 1);
        assert_eq!(teams.receipts.len(), 1);
        assert_eq!(teams.requests.len(), 2);
        assert_eq!(teams.requests[0], teams.requests[1]);
        drop(state);
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn rollback_allows_explicit_same_request_retry_and_known_preparation_discard() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![Mode::Rollback]);
    let prepared = manager.prepare_team_creation(&store, "Operations".into()).unwrap();
    assert_eq!(
        manager.submit_team_creation(store.clone(), &prepared.operation_id).await,
        Err(TeamFailure::ServiceUnavailable.into())
    );
    let retained = manager.pending_team_creation(&store).unwrap().unwrap();
    assert_eq!(retained.phase, TeamCreationPhase::Prepared);
    assert_eq!(peer.state.lock().unwrap().teams.as_ref().unwrap().requests.len(), 1);
    let confirmed =
        manager.submit_team_creation(store.clone(), &prepared.operation_id).await.unwrap();
    assert_eq!(confirmed.retry_until, retained.retry_until);
    manager.discard_team_creation(&store, &prepared.operation_id).unwrap();
    let other = manager.prepare_team_creation(&store, "Another team".into()).unwrap();
    manager.discard_team_creation(&store, &other.operation_id).unwrap();
    assert!(manager.pending_team_creation(&store).unwrap().is_none());
    peer.assert_healthy();
}

#[tokio::test]
async fn malformed_or_unconfirmed_responses_cannot_erase_a_prior_unknown_creation() {
    for mode in [Mode::Denied, Mode::InvalidProblem, Mode::BadMetadata] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = peer.prepare(&store).await;
        install(&peer, &store, vec![Mode::UnknownBeforeCommit, mode]);
        let prepared = manager.prepare_team_creation(&store, "Operations".into()).unwrap();
        assert!(manager.submit_team_creation(store.clone(), &prepared.operation_id).await.is_err());
        let original = manager.pending_team_creation(&store).unwrap().unwrap();
        assert!(manager.submit_team_creation(store.clone(), &prepared.operation_id).await.is_err());
        assert_eq!(manager.pending_team_creation(&store).unwrap(), Some(original));
        assert!(manager.prepare_team_creation(&store, "New attempt".into()).is_err());
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn foreign_identity_and_missing_scope_never_dispatch_a_team_request() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![]);
    let prepared = manager.prepare_team_creation(&store, "Operations".into()).unwrap();
    for field in 0..4 {
        peer.install_token(
            &store,
            |claims| match field {
                0 => claims.sub = scoplen_model::new_uuid_v7().unwrap(),
                1 => claims.did = scoplen_model::new_uuid_v7().unwrap(),
                3 => claims.scope = "account:read keys:read keys:write sync:read sync:write".into(),
                _ => {}
            },
            (field == 2).then(|| P256SigningKey::from_bytes(&[77; 32]).unwrap().public_key_sec1()),
        );
        if field == 3 {
            let mut identity = record(&store).unwrap();
            identity.auth_scope =
                Some("account:read keys:read keys:write sync:read sync:write".into());
            store.set_personal_session_metadata_for_test(&identity).unwrap();
        }
        assert!(manager.submit_team_creation(store.clone(), &prepared.operation_id).await.is_err());
        assert!(manager.teams_page(store.clone(), None).await.is_err());
        assert_eq!(
            manager.pending_team_creation(&store).unwrap().unwrap().phase,
            TeamCreationPhase::Prepared
        );
        assert!(peer.state.lock().unwrap().teams.as_ref().unwrap().requests.is_empty());
    }
    peer.assert_healthy();
}

#[tokio::test]
async fn discovery_requires_account_requested_id_and_http_metadata_bindings() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![]);
    let identity = record(&store).unwrap();
    let other = resource(scoplen_model::new_uuid_v7().unwrap(), "Foreign");
    peer.state.lock().unwrap().teams.as_mut().unwrap().read_reply =
        Some(json(OrganizationPage { items: vec![other], next_cursor: None }.to_json().unwrap()));
    assert_eq!(
        manager.teams_page(store.clone(), None).await,
        Err(TeamFailure::InvalidTeamResponse.into())
    );
    let own = resource(identity.account_id, "Own team");
    peer.state.lock().unwrap().teams.as_mut().unwrap().read_reply = Some(resource_reply(&own));
    assert_eq!(
        manager.team(store.clone(), &scoplen_model::new_uuid_v7().unwrap().to_string()).await,
        Err(TeamFailure::InvalidTeamResponse.into())
    );
    for header in ["x-request-id", "cache-control", "pragma", "etag"] {
        let mut reply = resource_reply(&own);
        reply.headers.retain(|(name, _)| *name != header);
        peer.state.lock().unwrap().teams.as_mut().unwrap().read_reply = Some(reply);
        assert!(manager.team(store.clone(), &own.id.to_string()).await.is_err());
    }
    peer.assert_healthy();
}

#[tokio::test]
async fn expired_unknown_creation_is_not_sent_and_requires_explicit_discard() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![]);
    let prepared = manager.prepare_team_creation(&store, "Operations".into()).unwrap();
    let expired = scoplen_model::system_time_millis().unwrap() - 86_400_001;
    crate::personal_server::tests::database(&dir)
        .execute("UPDATE team_creation SET phase=1,first_attempt_ms=?1", [expired as i64])
        .unwrap();
    let paths = peer.state.lock().unwrap().paths.len();
    assert_eq!(
        manager.pending_team_creation(&store).unwrap().unwrap().phase,
        TeamCreationPhase::Expired
    );
    assert_eq!(
        manager.submit_team_creation(store.clone(), &prepared.operation_id).await,
        Err(TeamFailure::OperationExpired.into())
    );
    assert_eq!(peer.state.lock().unwrap().paths.len(), paths);
    manager.discard_team_creation(&store, &prepared.operation_id).unwrap();
    assert!(manager.pending_team_creation(&store).unwrap().is_none());
    peer.assert_healthy();
}

#[tokio::test]
async fn failed_dispatch_never_sends_and_failed_confirmation_retains_original_unknown() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![]);
    let prepared = manager.prepare_team_creation(&store, "Operations".into()).unwrap();
    let conn = crate::personal_server::tests::database(&dir);
    conn.execute_batch("CREATE TRIGGER fail_team_dispatch BEFORE UPDATE ON team_creation WHEN NEW.phase=1 BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(manager.submit_team_creation(store.clone(), &prepared.operation_id).await.is_err());
    assert!(peer.state.lock().unwrap().teams.as_ref().unwrap().requests.is_empty());
    assert_eq!(
        manager.pending_team_creation(&store).unwrap().unwrap().phase,
        TeamCreationPhase::Prepared
    );
    conn.execute_batch("DROP TRIGGER fail_team_dispatch; CREATE TRIGGER fail_team_confirmation BEFORE UPDATE ON team_creation WHEN NEW.phase=2 BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(manager.submit_team_creation(store.clone(), &prepared.operation_id).await.is_err());
    assert_eq!(
        manager.pending_team_creation(&store).unwrap().unwrap().phase,
        TeamCreationPhase::Unknown
    );
    conn.execute_batch("DROP TRIGGER fail_team_confirmation;").unwrap();
    assert_eq!(
        manager.submit_team_creation(store.clone(), &prepared.operation_id).await.unwrap().phase,
        TeamCreationPhase::Confirmed
    );
    assert_eq!(peer.state.lock().unwrap().teams.as_ref().unwrap().resources.len(), 1);
    peer.assert_healthy();
}
