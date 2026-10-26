// SPDX-License-Identifier: Apache-2.0
//! Public shared codecs and real authenticated TLS exercise the team consumer independently.

use std::collections::VecDeque;

use scoplen_api::{
    ErrorCode, ProblemDetails,
    organization::{
        OrganizationCreateRequest, OrganizationMembership, OrganizationPage, OrganizationResource,
        OrganizationUpdateRequest, parse_organization_if_match,
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
    update_reply: Option<Reply>,
    update_modes: VecDeque<Mode>,
    updates: Vec<(uuid::Uuid, String, Vec<u8>)>,
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
        if request.method() == http::Method::PATCH {
            let id = path
                .strip_prefix("/api/v1/orgs/")
                .and_then(|text| uuid::Uuid::parse_str(text).ok())
                .ok_or("invalid update path")?;
            if request.uri().query().is_some()
                || request.headers().contains_key("idempotency-key")
                || request.headers().get("content-type").and_then(|value| value.to_str().ok())
                    != Some("application/json")
                || request.headers().get_all("if-match").iter().count() != 1
            {
                return Err("invalid team update headers".into());
            }
            let etag = parse_organization_if_match(
                request.headers().get("if-match").and_then(|value| value.to_str().ok()),
            )
            .map_err(|_| "invalid update precondition")?;
            let parsed =
                OrganizationUpdateRequest::from_json(body).map_err(|_| "invalid update body")?;
            self.updates.push((id, etag.to_owned(), body.to_vec()));
            if let Some(reply) = &self.update_reply {
                return Ok(reply.clone());
            }
            let Some(resource) = self.resources.get_mut(&id) else {
                return Ok(problem("organization.not_found", false, false, 404));
            };
            if resource.etag != etag {
                return Ok(problem("organization.precondition_failed", false, false, 412));
            }
            let mode = self.update_modes.pop_front().unwrap_or_default();
            match mode {
                Mode::Denied => return Ok(problem("policy.denied", false, false, 403)),
                Mode::Rollback => {
                    return Ok(problem("organization.storage_unavailable", false, true, 503));
                }
                Mode::UnknownBeforeCommit => {
                    return Ok(problem("organization.commit_outcome_unknown", true, false, 503));
                }
                Mode::InvalidProblem => {
                    return Ok(Reply {
                        status: 503,
                        content_type: "application/problem+json",
                        ..json(br#"{"changed":false,"changed":true}"#.to_vec())
                    });
                }
                _ => {}
            }
            if resource.name != parsed.name {
                resource.name = parsed.name;
                resource.updated_at = "2026-10-26T00:00:01Z".into();
                resource.etag = "\"updated\"".into();
            }
            if matches!(mode, Mode::UnknownAfterCommit) {
                return Ok(problem("organization.commit_outcome_unknown", true, false, 503));
            }
            let mut reply = resource_reply(resource);
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
        update_reply: None,
        update_modes: VecDeque::new(),
        updates: Vec::new(),
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

#[tokio::test]
async fn name_settings_capture_exact_etag_update_once_and_preserve_personal_data_and_creation() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![]);
    let before = record(&store).unwrap();
    let keys = manager.bootstrap_sync(store.clone()).await.unwrap();
    let prepared = manager.prepare_team_creation(&store, "Operations".into()).unwrap();
    let confirmed =
        manager.submit_team_creation(store.clone(), &prepared.operation_id).await.unwrap();
    let original = confirmed.organization.unwrap();
    let captured = manager.team_settings(store.clone(), &original.id).await.unwrap();
    assert_eq!(captured.team, original);
    assert_eq!(captured.etag, "\"one\"");
    let updated = manager
        .update_team_name(store.clone(), &original.id, &captured.etag, "Platform".into())
        .await
        .unwrap();
    assert_eq!(updated.team.id, original.id);
    assert_eq!(updated.team.name, "Platform");
    assert_eq!(updated.etag, "\"updated\"");
    assert_eq!(manager.team_settings(store.clone(), &original.id).await.unwrap(), updated);
    assert_eq!(
        manager.teams_page(store.clone(), None).await.unwrap().teams.as_slice(),
        std::slice::from_ref(&updated.team)
    );
    {
        let state = peer.state.lock().unwrap();
        let updates = &state.teams.as_ref().unwrap().updates;
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].0.to_string(), original.id);
        assert_eq!(updates[0].1, captured.etag);
        assert_eq!(OrganizationUpdateRequest::from_json(&updates[0].2).unwrap().name, "Platform");
    }
    let retained = manager.pending_team_creation(&store).unwrap().unwrap();
    assert_eq!(retained.operation_id, prepared.operation_id);
    assert_eq!(retained.organization, Some(original));
    let after = record(&store).unwrap();
    assert_eq!(after.account_id, before.account_id);
    assert_eq!(after.personal_vault_id, before.personal_vault_id);
    assert_eq!(after.private_material.as_bytes(), before.private_material.as_bytes());
    assert_eq!(
        manager.bootstrap_sync(store.clone()).await.unwrap().personal_vault_key().as_bytes(),
        keys.personal_vault_key().as_bytes()
    );
    peer.assert_healthy();
}

#[tokio::test]
async fn invalid_name_and_precondition_or_missing_write_scope_never_dispatch_and_reads_stay_available()
 {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![]);
    let account = record(&store).unwrap().account_id;
    let own = resource(account, "Operations");
    let id = own.id.to_string();
    peer.state.lock().unwrap().teams.as_mut().unwrap().resources.insert(own.id, own);
    for name in ["", " Team ", "line\nbreak", &"界".repeat(43)] {
        assert_eq!(
            manager.update_team_name(store.clone(), &id, "\"one\"", name.into()).await,
            Err(TeamFailure::InvalidName.into())
        );
    }
    for etag in ["", "*", "W/\"one\"", "\"one\", \"two\""] {
        assert!(
            manager.update_team_name(store.clone(), &id, etag, "Platform".into()).await.is_err()
        );
    }
    let scope = scoplen_api::auth::INITIAL_DEVICE_ACCESS_SCOPE.replace(" orgs:write", "");
    peer.install_token(&store, |claims| claims.scope = scope.clone(), None);
    let mut identity = record(&store).unwrap();
    identity.auth_scope = Some(scope);
    store.set_personal_session_metadata_for_test(&identity).unwrap();
    assert_eq!(
        manager.update_team_name(store.clone(), &id, "\"one\"", "Platform".into()).await,
        Err(TeamFailure::UpdateScopeRequired.into())
    );
    assert_eq!(manager.team_settings(store.clone(), &id).await.unwrap().team.name, "Operations");
    assert_eq!(manager.teams_page(store.clone(), None).await.unwrap().teams.len(), 1);
    manager.bootstrap_sync(store.clone()).await.unwrap();
    assert!(peer.state.lock().unwrap().teams.as_ref().unwrap().updates.is_empty());
    peer.assert_healthy();
}

#[tokio::test]
async fn name_update_conflict_and_unknown_never_replay_or_substitute_a_new_etag() {
    for mode in [
        Mode::LostAfterCommit,
        Mode::UnknownBeforeCommit,
        Mode::UnknownAfterCommit,
        Mode::BadMetadata,
        Mode::InvalidProblem,
    ] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = peer.prepare(&store).await;
        install(&peer, &store, vec![]);
        let own = resource(record(&store).unwrap().account_id, "Operations");
        let id = own.id.to_string();
        {
            let mut state = peer.state.lock().unwrap();
            let teams = state.teams.as_mut().unwrap();
            teams.resources.insert(own.id, own);
            teams.update_modes.push_back(mode);
        }
        let captured = manager.team_settings(store.clone(), &id).await.unwrap();
        assert_eq!(
            manager.update_team_name(store.clone(), &id, &captured.etag, "Platform".into()).await,
            Err(TeamFailure::SettingsUnknown.into())
        );
        assert_eq!(peer.state.lock().unwrap().teams.as_ref().unwrap().updates.len(), 1);
        manager.team_settings(store.clone(), &id).await.unwrap();
        assert_eq!(peer.state.lock().unwrap().teams.as_ref().unwrap().updates.len(), 1);
        peer.assert_healthy();
    }
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![]);
    let mut own = resource(record(&store).unwrap().account_id, "Changed elsewhere");
    own.etag = "\"elsewhere\"".into();
    let id = own.id.to_string();
    peer.state.lock().unwrap().teams.as_mut().unwrap().resources.insert(own.id, own);
    assert_eq!(
        manager.update_team_name(store.clone(), &id, "\"one\"", "Platform".into()).await,
        Err(TeamFailure::SettingsConflict.into())
    );
    assert_eq!(peer.state.lock().unwrap().teams.as_ref().unwrap().updates.len(), 1);
    let current = manager.team_settings(store.clone(), &id).await.unwrap();
    let saved = manager
        .update_team_name(store.clone(), &id, &current.etag, "Platform".into())
        .await
        .unwrap();
    assert_eq!(saved.team.name, "Platform");
    assert_eq!(peer.state.lock().unwrap().teams.as_ref().unwrap().updates.len(), 2);
    peer.assert_healthy();
}

#[tokio::test]
async fn name_update_confirmed_refusals_preserve_the_name_and_missing_team_is_fixed() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![]);
    let own = resource(record(&store).unwrap().account_id, "Operations");
    let id = own.id.to_string();
    peer.state.lock().unwrap().teams.as_mut().unwrap().resources.insert(own.id, own);
    for (mode, expected) in [
        (Mode::Denied, TeamError::Personal(PersonalServerError::PermissionDenied)),
        (Mode::Rollback, TeamFailure::ServiceUnavailable.into()),
    ] {
        peer.state.lock().unwrap().teams.as_mut().unwrap().update_modes.push_back(mode);
        assert_eq!(
            manager.update_team_name(store.clone(), &id, "\"one\"", "Platform".into()).await,
            Err(expected)
        );
        assert_eq!(
            manager.team_settings(store.clone(), &id).await.unwrap().team.name,
            "Operations"
        );
    }
    let missing = scoplen_model::new_uuid_v7().unwrap().to_string();
    assert_eq!(
        manager.team_settings(store.clone(), &missing).await,
        Err(TeamFailure::TeamNotFound.into())
    );
    assert_eq!(
        manager.update_team_name(store.clone(), &missing, "\"one\"", "Platform".into()).await,
        Err(TeamFailure::TeamNotFound.into())
    );
    assert_eq!(peer.state.lock().unwrap().teams.as_ref().unwrap().updates.len(), 3);
    peer.assert_healthy();
}

#[tokio::test]
async fn name_update_requires_exact_complete_response_and_current_account_binding() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![]);
    let own = resource(record(&store).unwrap().account_id, "Operations");
    let id = own.id.to_string();
    peer.state.lock().unwrap().teams.as_mut().unwrap().resources.insert(own.id, own.clone());
    for mismatch in 0..10 {
        let mut updated = own.clone();
        updated.name = "Platform".into();
        if mismatch == 0 {
            updated.id = scoplen_model::new_uuid_v7().unwrap();
        }
        if mismatch == 1 {
            updated.membership.account_id = scoplen_model::new_uuid_v7().unwrap();
        }
        if mismatch == 2 {
            updated.name = "Another name".into();
        }
        let mut reply = resource_reply(&updated);
        match mismatch {
            3 => reply.headers.retain(|(name, _)| *name != "x-request-id"),
            4 => reply.headers.retain(|(name, _)| *name != "cache-control"),
            5 => reply.headers.push(("pragma", "no-cache".into())),
            6 => {
                reply.headers.retain(|(name, _)| *name != "etag");
                reply.headers.push(("etag", "\"different\"".into()));
            }
            7 => reply.body = vec![b' '; 4097],
            8 => reply.status = 201,
            9 => reply.headers.push(("set-cookie", "fixture=refused".into())),
            _ => {}
        }
        peer.state.lock().unwrap().teams.as_mut().unwrap().update_reply = Some(reply);
        assert_eq!(
            manager.update_team_name(store.clone(), &id, "\"one\"", "Platform".into()).await,
            Err(TeamFailure::SettingsUnknown.into())
        );
    }
    assert_eq!(peer.state.lock().unwrap().teams.as_ref().unwrap().updates.len(), 10);
    peer.assert_healthy();
}
