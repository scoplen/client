// SPDX-License-Identifier: Apache-2.0
//! Real TLS/DPoP consumer tests against the published shared team reference peer.

use scoplen_api::{
    organization::{
        OrganizationListQuery, OrganizationMembership, OrganizationPage, OrganizationResource,
    },
    organization_reference::{OrganizationReferenceError, OrganizationReferenceFault},
    team::{
        TeamInvitationAcceptRequest, TeamInvitationCreateRequest, TeamInvitationLink, TeamRole,
    },
    team_reference::{TeamReferencePeer, TeamReferenceTime},
};
use scoplen_crypto::TeamInvitationPassword;

use super::*;
use crate::personal_server::{TeamCreationPhase, TeamFailure, TeamOperationKind};

struct Sent {
    path: String,
    body: SecretVec,
    key: Option<uuid::Uuid>,
    etag: Option<String>,
}

pub(super) struct TeamLifecyclePeer {
    shared: TeamReferencePeer,
    claims: DeviceAccessTokenClaims,
    observer: Arc<Store>,
    organization: uuid::Uuid,
    clock: TeamReferenceTime,
    sent: Vec<Sent>,
    override_reply: Option<Reply>,
}

impl TeamLifecyclePeer {
    pub(super) fn answer(
        &mut self,
        request: &http::Request<h2::RecvStream>,
        body: &[u8],
    ) -> Result<Reply, String> {
        let path = request.uri().path();
        if let Some(reply) = &self.override_reply {
            return Ok(reply.clone());
        }
        let parts = path
            .trim_start_matches("/api/v1/orgs")
            .trim_matches('/')
            .split('/')
            .collect::<Vec<_>>();
        let method = request.method();
        let key = request
            .headers()
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .map(|text| uuid::Uuid::parse_str(text).map_err(|_| "bad team key"))
            .transpose()?;
        let etag = request.headers().get("if-match").and_then(|v| v.to_str().ok());
        let collection = parts.get(1).copied();
        let receipt = method == http::Method::POST;
        let conditional = method == http::Method::PATCH
            || method == http::Method::DELETE
            || collection == Some("dissolve");
        if key.is_some() != receipt
            || etag.is_some() != conditional
            || request.headers().get_all("idempotency-key").iter().count() > 1
            || request.headers().get_all("if-match").iter().count() > 1
            || method == http::Method::GET && !body.is_empty()
            || method == http::Method::DELETE && !body.is_empty()
            || (method == http::Method::POST || method == http::Method::PATCH)
                && request.headers().get("content-type").and_then(|v| v.to_str().ok())
                    != Some("application/json")
        {
            return Err("invalid lifecycle request headers".into());
        }
        if receipt {
            let kind = if collection == Some("dissolve") {
                2
            } else if parts.last() == Some(&"accept") {
                1
            } else {
                0
            };
            let identity = record(&self.observer).unwrap();
            let pending = self
                .observer
                .team_operation(&identity, kind)
                .unwrap()
                .ok_or("missing durable lifecycle request")?;
            if pending.phase != 1
                || pending.first_attempt_ms.is_none()
                || Some(pending.operation_id) != key
                || pending.payload.as_bytes() != body
                || pending.etag.as_deref() != etag
            {
                return Err("lifecycle dispatch preceded durable state".into());
            }
        }
        self.sent.push(Sent {
            path: path.into(),
            body: SecretVec::new(body.to_vec()),
            key,
            etag: etag.map(str::to_owned),
        });
        let organization = if path == "/api/v1/orgs" {
            self.organization
        } else {
            uuid::Uuid::parse_str(parts[0]).map_err(|_| "bad organization path")?
        };
        let query = || {
            OrganizationListQuery::from_parameters(
                request
                    .uri()
                    .query()
                    .unwrap_or("")
                    .split('&')
                    .filter(|part| !part.is_empty())
                    .map(|part| part.split_once('=').unwrap()),
            )
        };
        let target = || {
            parts.get(2).and_then(|text| uuid::Uuid::parse_str(text).ok()).ok_or("bad target path")
        };
        let answer: Result<Reply, OrganizationReferenceError> =
            match (method.as_str(), collection, parts.len()) {
                ("GET", None, _) if path == "/api/v1/orgs" => {
                    let page = OrganizationPage {
                        items: self
                            .shared
                            .organization(&self.claims, organization, self.clock.now)
                            .ok()
                            .into_iter()
                            .collect(),
                        next_cursor: None,
                    };
                    Ok(json(page.to_json().unwrap()))
                }
                ("GET", None, _) => self
                    .shared
                    .organization(&self.claims, organization, self.clock.now)
                    .map(|value| resource(value.to_json().unwrap(), &value.etag)),
                ("POST", Some("invitations"), 2) => self
                    .shared
                    .create_invitation(&self.claims, organization, key.unwrap(), body, &self.clock)
                    .map(|value| {
                        let mut reply = resource(value.to_json().unwrap(), &value.etag);
                        reply.status = 201;
                        reply
                    }),
                ("GET", Some("invitations"), 2) => self
                    .shared
                    .invitations(&self.claims, organization, query().unwrap(), self.clock.now)
                    .map(|value| json(value.to_json().unwrap())),
                ("GET", Some("invitations"), 3) => self
                    .shared
                    .invitation(&self.claims, organization, target()?, self.clock.now)
                    .map(|value| resource(value.to_json().unwrap(), &value.etag)),
                ("DELETE", Some("invitations"), 3) => self
                    .shared
                    .revoke_invitation(&self.claims, organization, target()?, etag, &self.clock)
                    .map(|()| no_content()),
                ("POST", Some("invitations"), 4) if parts[3] == "accept" => self
                    .shared
                    .accept_invitation(
                        &self.claims,
                        organization,
                        target()?,
                        key.unwrap(),
                        body,
                        &self.clock,
                    )
                    .map(|value| json(value.to_json().unwrap())),
                ("GET", Some("members"), 2) => self
                    .shared
                    .members(&self.claims, organization, query().unwrap(), self.clock.now)
                    .map(|value| json(value.to_json().unwrap())),
                ("GET", Some("members"), 3) => self
                    .shared
                    .member(&self.claims, organization, target()?, self.clock.now)
                    .map(|value| resource(value.to_json().unwrap(), &value.etag)),
                ("PATCH", Some("members"), 3) => self
                    .shared
                    .update_member(&self.claims, organization, target()?, etag, body, &self.clock)
                    .map(|value| resource(value.to_json().unwrap(), &value.etag)),
                ("DELETE", Some("members"), 3) => self
                    .shared
                    .remove_member(&self.claims, organization, target()?, etag, &self.clock)
                    .map(|()| no_content()),
                ("POST", Some("dissolve"), 2) => self
                    .shared
                    .dissolve(&self.claims, organization, key.unwrap(), etag, body, &self.clock)
                    .map(|value| json(value.to_json().unwrap())),
                _ => return Err("unexpected lifecycle path".into()),
            };
        Ok(match answer {
            Ok(reply) => reply,
            Err(OrganizationReferenceError::ResponseLost) => {
                Reply { stall: true, ..json(Vec::new()) }
            }
            Err(error) => {
                let problem = error.problem("fixture-team").unwrap().unwrap();
                Reply {
                    status: problem.status,
                    content_type: "application/problem+json",
                    ..json(serde_json::to_vec(&problem).unwrap())
                }
            }
        })
    }
}

fn json(body: Vec<u8>) -> Reply {
    Reply {
        content_type: "application/json",
        headers: vec![
            ("cache-control", "no-store".into()),
            ("pragma", "no-cache".into()),
            ("x-request-id", "fixture-team".into()),
        ],
        ..Reply::cbor(body)
    }
}
fn resource(body: Vec<u8>, etag: &str) -> Reply {
    let mut reply = json(body);
    reply.headers.push(("etag", etag.into()));
    reply
}
fn no_content() -> Reply {
    Reply { status: 204, ..json(Vec::new()) }
}

fn token_claims(peer: &Peer, store: &Store) -> DeviceAccessTokenClaims {
    let key = Ed25519SigningKey::from_bytes(&[55; 32]).unwrap();
    let mut trusted = TrustedDeviceAccessTokenKeys::new(&peer.origin).unwrap();
    trusted.insert("fixture", &key.public_key()).unwrap();
    let access = store.personal_access_token(now().unwrap()).unwrap().unwrap();
    DeviceAccessToken::parse(std::str::from_utf8(access.as_bytes()).unwrap())
        .unwrap()
        .verify(&trusted, now().unwrap())
        .unwrap()
        .claims()
        .clone()
}

fn install(
    peer: &Peer,
    store: &Arc<Store>,
    actual_owner: bool,
) -> (uuid::Uuid, DeviceAccessTokenClaims) {
    let claims = token_claims(peer, store);
    let mut other = claims.clone();
    other.sub = scoplen_model::new_uuid_v7().unwrap();
    other.did = scoplen_model::new_uuid_v7().unwrap();
    let mut shared = TeamReferencePeer::new(&peer.origin).unwrap();
    shared
        .set_principal(&claims, if actual_owner { "owner-user" } else { "recipient-user" }, true)
        .unwrap();
    shared
        .set_principal(&other, if actual_owner { "recipient-user" } else { "owner-user" }, true)
        .unwrap();
    let organization = scoplen_model::new_uuid_v7().unwrap();
    shared
        .seed_organization(OrganizationResource {
            id: organization,
            etag: "\"initial\"".into(),
            created_at: "2026-11-01T00:00:00Z".into(),
            updated_at: "2026-11-01T00:00:00Z".into(),
            name: "Operations".into(),
            membership: OrganizationMembership {
                id: scoplen_model::new_uuid_v7().unwrap(),
                account_id: if actual_owner { claims.sub } else { other.sub },
                roles: vec!["owner".into()],
            },
        })
        .unwrap();
    peer.state.lock().unwrap().team_lifecycle = Some(TeamLifecyclePeer {
        shared,
        claims,
        observer: store.clone(),
        organization,
        clock: TeamReferenceTime {
            now: now().unwrap(),
            timestamp: "2026-11-01T00:00:00Z".into(),
            invitation_expires_at: "2026-11-02T00:00:00Z".into(),
        },
        sent: Vec::new(),
        override_reply: None,
    });
    (organization, other)
}

fn seed_invitation(
    peer: &Peer,
    issuer: &DeviceAccessTokenClaims,
    organization: uuid::Uuid,
) -> (String, SecretVec) {
    let id = scoplen_model::new_uuid_v7().unwrap();
    let password = TeamInvitationPassword::parse(b"01234567").unwrap();
    let request = TeamInvitationCreateRequest {
        invitation_id: id,
        recipient_username: "recipient-user".into(),
        roles: vec![TeamRole::Member],
        password_verifier: password.verifier(&peer.origin, &organization, &id).unwrap(),
    };
    let mut state = peer.state.lock().unwrap();
    let lifecycle = state.team_lifecycle.as_mut().unwrap();
    lifecycle
        .shared
        .create_invitation(
            issuer,
            organization,
            scoplen_model::new_uuid_v7().unwrap(),
            request.to_json().unwrap().as_bytes(),
            &lifecycle.clock,
        )
        .unwrap();
    (
        TeamInvitationLink {
            origin: peer.origin.clone(),
            organization_id: organization,
            invitation_id: id,
        }
        .to_url()
        .unwrap(),
        SecretVec::new(password.as_bytes().to_vec()),
    )
}

#[tokio::test]
async fn named_invitation_is_durable_before_tls_dispatch_and_secret_dismissal_is_local() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let (organization, _) = install(&peer, &store, true);
    let before = record(&store).unwrap();
    let operation = manager
        .prepare_team_invitation(
            &store,
            &organization.to_string(),
            "recipient-user".into(),
            vec!["member".into()],
        )
        .unwrap();
    assert_eq!(operation.phase, TeamCreationPhase::Prepared);
    assert!(manager.team_invitation_password(&store, &operation.operation_id).is_err());
    let confirmed = manager
        .submit_team_operation(
            store.clone(),
            TeamOperationKind::Invitation,
            &operation.operation_id,
        )
        .await
        .unwrap();
    assert_eq!(confirmed.phase, TeamCreationPhase::Confirmed);
    let password = manager.team_invitation_password(&store, &operation.operation_id).unwrap();
    assert_eq!(password.len(), 8);
    assert!(
        !confirmed
            .link
            .as_ref()
            .unwrap()
            .contains(std::str::from_utf8(password.as_bytes()).unwrap())
    );
    let list =
        manager.team_invitations(store.clone(), &organization.to_string(), None).await.unwrap();
    assert_eq!(list.items.len(), 1);
    assert_eq!(list.items[0].recipient_username, "recipient-user");
    manager
        .revoke_team_invitation(
            store.clone(),
            &organization.to_string(),
            &list.items[0].id,
            &list.items[0].etag,
        )
        .await
        .unwrap();
    assert_eq!(
        manager
            .team_invitations(store.clone(), &organization.to_string(), None)
            .await
            .unwrap()
            .items[0]
            .status,
        "revoked"
    );
    manager
        .discard_team_operation(&store, TeamOperationKind::Invitation, &operation.operation_id)
        .unwrap();
    assert!(manager.team_invitation_password(&store, &operation.operation_id).is_err());
    assert!(manager.pending_team_operations(&store).unwrap().is_empty());
    assert!(record(&store).unwrap().private_material == before.private_material);
    peer.assert_healthy();
}

#[tokio::test]
async fn lost_invitation_reopens_and_confirms_exact_key_payload_and_password() {
    for fault in [
        OrganizationReferenceFault::UnknownRollback,
        OrganizationReferenceFault::UnknownCommitted,
        OrganizationReferenceFault::LostResponse,
    ] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = peer.prepare(&store).await;
        let (organization, _) = install(&peer, &store, true);
        let operation = manager
            .prepare_team_invitation(
                &store,
                &organization.to_string(),
                "recipient-user".into(),
                vec!["member".into()],
            )
            .unwrap();
        peer.state.lock().unwrap().team_lifecycle.as_mut().unwrap().shared.set_fault(fault);
        assert!(
            manager
                .submit_team_operation(
                    store.clone(),
                    TeamOperationKind::Invitation,
                    &operation.operation_id
                )
                .await
                .is_err()
        );
        assert_eq!(
            manager.pending_team_operations(&store).unwrap()[0].phase,
            TeamCreationPhase::Unknown
        );
        assert_eq!(
            manager.discard_team_operation(
                &store,
                TeamOperationKind::Invitation,
                &operation.operation_id
            ),
            Err(TeamFailure::OutcomeUnknown.into())
        );
        let reopened = local(&dir);
        let manager = peer.manager();
        peer.state.lock().unwrap().team_lifecycle.as_mut().unwrap().observer = reopened.clone();
        let confirmed = manager
            .submit_team_operation(
                reopened.clone(),
                TeamOperationKind::Invitation,
                &operation.operation_id,
            )
            .await
            .unwrap();
        assert_eq!(confirmed.phase, TeamCreationPhase::Confirmed);
        let state = peer.state.lock().unwrap();
        let lifecycle = state.team_lifecycle.as_ref().unwrap();
        let sends = lifecycle.sent.iter().filter(|send| send.key.is_some()).collect::<Vec<_>>();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[0].key, sends[1].key);
        assert!(sends[0].body == sends[1].body);
        assert_eq!(lifecycle.shared.audit_events(), 1);
        drop(state);
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn recipient_preview_acceptance_receipt_and_self_leave_preserve_personal_identity() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let (organization, owner) = install(&peer, &store, false);
    let (link, password) = seed_invitation(&peer, &owner, organization);
    let preview = manager.preview_team_invitation(store.clone(), &link).await.unwrap();
    assert_eq!(preview.organization_name, "Operations");
    assert_eq!(preview.roles, ["member"]);
    assert_eq!(
        manager
            .preview_team_invitation(
                store.clone(),
                &link.replace(&peer.origin, "https://other.example")
            )
            .await,
        Err(TeamFailure::InvitationOriginMismatch.into())
    );
    let operation = manager
        .prepare_team_acceptance(store.clone(), &link, &preview.etag, password)
        .await
        .unwrap();
    peer.state
        .lock()
        .unwrap()
        .team_lifecycle
        .as_mut()
        .unwrap()
        .shared
        .set_fault(OrganizationReferenceFault::UnknownCommitted);
    assert!(
        manager
            .submit_team_operation(
                store.clone(),
                TeamOperationKind::Acceptance,
                &operation.operation_id
            )
            .await
            .is_err()
    );
    assert_eq!(
        manager
            .submit_team_operation(
                store.clone(),
                TeamOperationKind::Acceptance,
                &operation.operation_id
            )
            .await
            .unwrap()
            .phase,
        TeamCreationPhase::Confirmed
    );
    let team = manager.team_settings(store.clone(), &organization.to_string()).await.unwrap();
    manager
        .remove_team_member(
            store.clone(),
            &organization.to_string(),
            &team.membership_id,
            &team.etag,
        )
        .await
        .unwrap();
    assert!(manager.teams_page(store.clone(), None).await.unwrap().teams.is_empty());
    // A historical acceptance remains a receipt, and cannot restore the removed membership.
    assert_eq!(
        manager
            .submit_team_operation(
                store.clone(),
                TeamOperationKind::Acceptance,
                &operation.operation_id
            )
            .await
            .unwrap()
            .phase,
        TeamCreationPhase::Confirmed
    );
    assert!(manager.teams_page(store.clone(), None).await.unwrap().teams.is_empty());
    peer.assert_healthy();
}

#[tokio::test]
async fn member_edits_reject_stale_etags_and_dissolution_retries_original_precondition() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let (organization, recipient) = install(&peer, &store, true);
    let operation = manager
        .prepare_team_invitation(
            &store,
            &organization.to_string(),
            "recipient-user".into(),
            vec!["member".into()],
        )
        .unwrap();
    manager
        .submit_team_operation(
            store.clone(),
            TeamOperationKind::Invitation,
            &operation.operation_id,
        )
        .await
        .unwrap();
    let password = manager.team_invitation_password(&store, &operation.operation_id).unwrap();
    {
        let mut state = peer.state.lock().unwrap();
        let lifecycle = state.team_lifecycle.as_mut().unwrap();
        lifecycle
            .shared
            .accept_invitation(
                &recipient,
                organization,
                uuid::Uuid::parse_str(operation.invitation_id.as_ref().unwrap()).unwrap(),
                scoplen_model::new_uuid_v7().unwrap(),
                TeamInvitationAcceptRequest {
                    password: TeamInvitationPassword::parse(password.as_bytes()).unwrap(),
                }
                .to_json()
                .unwrap()
                .as_bytes(),
                &lifecycle.clock,
            )
            .unwrap();
    }
    let members =
        manager.team_members(store.clone(), &organization.to_string(), None).await.unwrap();
    let target = members.items.iter().find(|member| !member.is_self).unwrap();
    let updated = manager
        .update_team_member(
            store.clone(),
            &organization.to_string(),
            &target.id,
            &target.etag,
            vec!["approver".into(), "member".into()],
            "suspended",
        )
        .await
        .unwrap();
    assert_eq!(updated.status, "suspended");
    assert_eq!(
        manager
            .remove_team_member(store.clone(), &organization.to_string(), &target.id, &target.etag)
            .await,
        Err(TeamFailure::MembershipConflict.into())
    );
    manager
        .remove_team_member(store.clone(), &organization.to_string(), &updated.id, &updated.etag)
        .await
        .unwrap();
    let settings = manager.team_settings(store.clone(), &organization.to_string()).await.unwrap();
    let operation = manager
        .prepare_team_dissolution(&store, &organization.to_string(), &settings.etag)
        .unwrap();
    peer.state
        .lock()
        .unwrap()
        .team_lifecycle
        .as_mut()
        .unwrap()
        .shared
        .set_fault(OrganizationReferenceFault::UnknownCommitted);
    assert!(
        manager
            .submit_team_operation(
                store.clone(),
                TeamOperationKind::Dissolution,
                &operation.operation_id
            )
            .await
            .is_err()
    );
    let reopened = local(&dir);
    peer.state.lock().unwrap().team_lifecycle.as_mut().unwrap().observer = reopened.clone();
    assert_eq!(
        manager
            .submit_team_operation(
                reopened.clone(),
                TeamOperationKind::Dissolution,
                &operation.operation_id
            )
            .await
            .unwrap()
            .phase,
        TeamCreationPhase::Confirmed
    );
    assert!(manager.teams_page(reopened, None).await.unwrap().teams.is_empty());
    let state = peer.state.lock().unwrap();
    let lifecycle = state.team_lifecycle.as_ref().unwrap();
    let requests =
        lifecycle.sent.iter().filter(|send| send.path.ends_with("/dissolve")).collect::<Vec<_>>();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].key, requests[1].key);
    assert_eq!(requests[0].etag, requests[1].etag);
    assert!(requests[0].body == requests[1].body);
    drop(state);
    peer.assert_healthy();
}

#[tokio::test]
async fn expired_original_operation_is_not_sent_or_replaced_without_explicit_discard() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let (organization, _) = install(&peer, &store, true);
    let operation = manager
        .prepare_team_invitation(
            &store,
            &organization.to_string(),
            "recipient-user".into(),
            vec!["member".into()],
        )
        .unwrap();
    let expired = scoplen_model::system_time_millis().unwrap() - 86_400_001;
    crate::personal_server::tests::database(&dir)
        .execute("UPDATE team_operation SET phase=1,first_attempt_ms=?1", [expired as i64])
        .unwrap();
    let requests = peer.state.lock().unwrap().paths.len();
    assert_eq!(
        manager.pending_team_operations(&store).unwrap()[0].phase,
        TeamCreationPhase::Expired
    );
    assert_eq!(
        manager
            .submit_team_operation(
                store.clone(),
                TeamOperationKind::Invitation,
                &operation.operation_id
            )
            .await,
        Err(TeamFailure::OperationExpired.into())
    );
    assert_eq!(peer.state.lock().unwrap().paths.len(), requests);
    assert_eq!(
        manager.prepare_team_invitation(
            &store,
            &organization.to_string(),
            "recipient-user".into(),
            vec!["member".into()]
        ),
        Err(TeamFailure::MembershipPending.into())
    );
    manager
        .discard_team_operation(&store, TeamOperationKind::Invitation, &operation.operation_id)
        .unwrap();
    assert!(manager.pending_team_operations(&store).unwrap().is_empty());
    peer.assert_healthy();
}

#[tokio::test]
async fn recipient_preview_rejects_foreign_context_and_invalid_cache_metadata() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let (organization, owner) = install(&peer, &store, false);
    let (link, _) = seed_invitation(&peer, &owner, organization);
    let parsed = TeamInvitationLink::parse(&link).unwrap();
    let value = {
        let state = peer.state.lock().unwrap();
        let lifecycle = state.team_lifecycle.as_ref().unwrap();
        lifecycle
            .shared
            .invitation(&lifecycle.claims, organization, parsed.invitation_id, lifecycle.clock.now)
            .unwrap()
    };
    let mut foreign = value.clone();
    foreign.recipient_account_id = owner.sub;
    peer.state.lock().unwrap().team_lifecycle.as_mut().unwrap().override_reply =
        Some(resource(foreign.to_json().unwrap(), &foreign.etag));
    assert_eq!(
        manager.preview_team_invitation(store.clone(), &link).await,
        Err(TeamFailure::InvalidTeamResponse.into())
    );
    for missing in ["cache-control", "pragma", "x-request-id", "etag"] {
        let mut reply = resource(value.to_json().unwrap(), &value.etag);
        reply.headers.retain(|(name, _)| *name != missing);
        peer.state.lock().unwrap().team_lifecycle.as_mut().unwrap().override_reply = Some(reply);
        assert!(manager.preview_team_invitation(store.clone(), &link).await.is_err());
    }
    assert!(manager.pending_team_operations(&store).unwrap().is_empty());
    peer.assert_healthy();
}

#[tokio::test]
async fn acceptance_confirmation_after_removal_cannot_reactivate_membership() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let (organization, owner) = install(&peer, &store, false);
    let (link, password) = seed_invitation(&peer, &owner, organization);
    let preview = manager.preview_team_invitation(store.clone(), &link).await.unwrap();
    let operation = manager
        .prepare_team_acceptance(store.clone(), &link, &preview.etag, password)
        .await
        .unwrap();
    peer.state
        .lock()
        .unwrap()
        .team_lifecycle
        .as_mut()
        .unwrap()
        .shared
        .set_fault(OrganizationReferenceFault::UnknownCommitted);
    assert!(
        manager
            .submit_team_operation(
                store.clone(),
                TeamOperationKind::Acceptance,
                &operation.operation_id
            )
            .await
            .is_err()
    );
    {
        let mut state = peer.state.lock().unwrap();
        let lifecycle = state.team_lifecycle.as_mut().unwrap();
        let member = lifecycle
            .shared
            .members(&owner, organization, OrganizationListQuery::default(), lifecycle.clock.now)
            .unwrap()
            .items
            .into_iter()
            .find(|member| member.account_id == lifecycle.claims.sub)
            .unwrap();
        lifecycle
            .shared
            .remove_member(&owner, organization, member.id, Some(&member.etag), &lifecycle.clock)
            .unwrap();
    }
    let reopened = local(&dir);
    let manager = peer.manager();
    peer.state.lock().unwrap().team_lifecycle.as_mut().unwrap().observer = reopened.clone();
    assert_eq!(
        manager
            .submit_team_operation(
                reopened.clone(),
                TeamOperationKind::Acceptance,
                &operation.operation_id
            )
            .await
            .unwrap()
            .phase,
        TeamCreationPhase::Confirmed
    );
    assert!(manager.teams_page(reopened, None).await.unwrap().teams.is_empty());
    peer.assert_healthy();
}

#[tokio::test]
async fn older_scope_ceiling_keeps_preparation_unsent_and_current_team_reads_available() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let (organization, _) = install(&peer, &store, true);
    let operation = manager
        .prepare_team_invitation(
            &store,
            &organization.to_string(),
            "recipient-user".into(),
            vec!["member".into()],
        )
        .unwrap();
    let scope = scoplen_api::auth::INITIAL_DEVICE_ACCESS_SCOPE
        .replace(" teams:join", "")
        .replace(" teams:manage", "");
    peer.install_token(&store, |claims| claims.scope = scope.clone(), None);
    let mut identity = record(&store).unwrap();
    identity.auth_scope = Some(scope);
    store.set_personal_session_metadata_for_test(&identity).unwrap();
    assert_eq!(
        manager
            .submit_team_operation(
                store.clone(),
                TeamOperationKind::Invitation,
                &operation.operation_id
            )
            .await,
        Err(TeamFailure::MembershipScopeRequired.into())
    );
    assert_eq!(
        manager.team_invitations(store.clone(), &organization.to_string(), None).await,
        Err(TeamFailure::MembershipScopeRequired.into())
    );
    assert_eq!(
        manager.pending_team_operations(&store).unwrap()[0].phase,
        TeamCreationPhase::Prepared
    );
    assert_eq!(
        manager.team_settings(store.clone(), &organization.to_string()).await.unwrap().team.name,
        "Operations"
    );
    assert!(
        peer.state
            .lock()
            .unwrap()
            .team_lifecycle
            .as_ref()
            .unwrap()
            .sent
            .iter()
            .all(|sent| sent.key.is_none())
    );
    peer.assert_healthy();
}

#[tokio::test]
async fn failed_durable_dispatch_sends_nothing_and_failed_confirmation_retains_original_request() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let (organization, _) = install(&peer, &store, true);
    let operation = manager
        .prepare_team_invitation(
            &store,
            &organization.to_string(),
            "recipient-user".into(),
            vec!["member".into()],
        )
        .unwrap();
    let database = crate::personal_server::tests::database(&dir);
    database.execute_batch("CREATE TRIGGER fail_lifecycle_dispatch BEFORE UPDATE ON team_operation WHEN NEW.phase=1 BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(
        manager
            .submit_team_operation(
                store.clone(),
                TeamOperationKind::Invitation,
                &operation.operation_id
            )
            .await
            .is_err()
    );
    assert!(peer.state.lock().unwrap().team_lifecycle.as_ref().unwrap().sent.is_empty());
    assert_eq!(
        manager.pending_team_operations(&store).unwrap()[0].phase,
        TeamCreationPhase::Prepared
    );
    database.execute_batch("DROP TRIGGER fail_lifecycle_dispatch; CREATE TRIGGER fail_lifecycle_confirmation BEFORE UPDATE ON team_operation WHEN NEW.phase=2 BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(
        manager
            .submit_team_operation(
                store.clone(),
                TeamOperationKind::Invitation,
                &operation.operation_id
            )
            .await
            .is_err()
    );
    assert_eq!(
        manager.pending_team_operations(&store).unwrap()[0].phase,
        TeamCreationPhase::Unknown
    );
    database.execute_batch("DROP TRIGGER fail_lifecycle_confirmation;").unwrap();
    assert_eq!(
        manager
            .submit_team_operation(
                store.clone(),
                TeamOperationKind::Invitation,
                &operation.operation_id
            )
            .await
            .unwrap()
            .phase,
        TeamCreationPhase::Confirmed
    );
    assert_eq!(
        peer.state.lock().unwrap().team_lifecycle.as_ref().unwrap().shared.audit_events(),
        1
    );
    peer.assert_healthy();
}
