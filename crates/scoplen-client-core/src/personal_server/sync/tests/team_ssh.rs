// SPDX-License-Identifier: Apache-2.0
//! Native CA/certificate consumption through real authenticated TLS/H2.

use scoplen_api::{
    certificate::{CertificateIssuanceRequest, CertificateIssuanceResponse, CertificateTargets},
    user_ca::{UserCaCreateRequest, UserCaPage, UserCaResource, user_ca_fingerprint},
};
use scoplen_model::{FieldEntry, FieldPath, Hlc, Object, ObjectType, cbor::Value};

use super::*;
use crate::{
    personal_server::{
        TeamAuthoringCollection, TeamAuthoringData, TeamCreationPhase, TeamSshError,
        TeamSshFailure, TeamSshOperationKind, TeamSshSource,
    },
    store::{team_assets::TeamAssetPublication, team_ssh::TeamSshOwner},
};

pub(super) struct TeamSshPeer {
    store: Arc<Store>,
    owner: TeamSshOwner,
    host: uuid::Uuid,
    ca: Option<UserCaResource>,
    key: ssh_key::PrivateKey,
    receipts: BTreeMap<uuid::Uuid, (Vec<u8>, Vec<u8>)>,
    requests: Vec<(uuid::Uuid, Vec<u8>)>,
    unknown_once: bool,
    denied: bool,
    wrong_principal: bool,
    wrong_ca: bool,
}

fn id() -> uuid::Uuid {
    scoplen_model::new_uuid_v7().unwrap()
}

fn json(body: Vec<u8>) -> Reply {
    Reply {
        status: 200,
        content_type: "application/json",
        headers: vec![
            ("cache-control", "no-store".into()),
            ("pragma", "no-cache".into()),
            ("x-request-id", "fixture-request".into()),
        ],
        body,
        stall: false,
    }
}

fn problem(code: &str, status: u16, changed: bool, retryable: bool) -> Reply {
    let problem = scoplen_api::ProblemDetails::new(
        scoplen_api::ErrorCode::new(code).unwrap(),
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

impl TeamSshPeer {
    pub(super) fn answer(
        &mut self,
        request: &http::Request<h2::RecvStream>,
        body: &[u8],
    ) -> Result<Reply, String> {
        let prefix = format!("/api/v1/orgs/{}/", self.owner.organization);
        let path = request.uri().path().strip_prefix(&prefix).ok_or("foreign team")?;
        if self.denied {
            return Ok(problem("policy.denied", 403, false, false));
        }
        if request.method() == http::Method::GET && path == "certificate-authorities" {
            let query = scoplen_api::organization::OrganizationListQuery::from_parameters(
                request
                    .uri()
                    .query()
                    .ok_or("missing CA query")?
                    .split('&')
                    .map(|pair| pair.split_once('=').unwrap_or((pair, ""))),
            )
            .map_err(|_| "invalid CA query")?;
            let page = UserCaPage { items: self.ca.iter().cloned().collect(), next_cursor: None };
            page.validate_for_query(query).map_err(|_| "invalid CA page")?;
            return Ok(json(page.to_json().unwrap()));
        }
        if request.method() != http::Method::POST
            || request.uri().query().is_some()
            || request.headers().contains_key("if-match")
        {
            return Err("invalid SSH setup method".into());
        }
        let kind = match path {
            "certificate-authorities" => 0,
            "certificates" => 1,
            _ => return Err("unknown SSH setup path".into()),
        };
        let operation = self
            .store
            .team_ssh_operation(&self.owner, kind)
            .unwrap()
            .ok_or("no durable SSH request")?;
        let key = request
            .headers()
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
            .ok_or("missing original key")?;
        if operation.id != key
            || operation.phase != 1
            || operation.first_attempt.is_none()
            || operation.payload.as_bytes() != body
        {
            return Err("SSH request preceded durable dispatch".into());
        }
        self.requests.push((key, body.to_vec()));
        let encoded = if let Some((original, response)) = self.receipts.get(&key) {
            if original != body {
                return Err("replaced original payload".into());
            }
            response.clone()
        } else {
            let response = if kind == 0 {
                let parsed =
                    UserCaCreateRequest::from_json(body).map_err(|_| "invalid CA request")?;
                let public_key = self.key.public_key().to_openssh().unwrap();
                let ca = UserCaResource {
                    id: parsed.id,
                    etag: "\"1\"".into(),
                    created_at: "2026-01-01T00:00:00Z".into(),
                    updated_at: "2026-01-01T00:00:00Z".into(),
                    fingerprint: user_ca_fingerprint(&public_key).unwrap(),
                    public_key,
                };
                self.ca = Some(ca.clone());
                ca.to_json().unwrap()
            } else {
                if self.ca.is_none() {
                    return Err("missing CA".into());
                }
                let parsed =
                    CertificateIssuanceRequest::from_json(body).map_err(|_| "invalid issuance")?;
                if parsed.targets != CertificateTargets::Hosts(vec![self.host]) {
                    return Err("foreign Host selected".into());
                }
                let subject = ssh_key::PublicKey::from_openssh(&parsed.public_key).unwrap();
                let certificate_id = id();
                let current = now().unwrap();
                let mut builder = ssh_key::certificate::Builder::new(
                    vec![4; 32],
                    &subject,
                    current - 60,
                    current + u64::from(parsed.ttl_seconds),
                )
                .unwrap();
                builder.cert_type(ssh_key::certificate::CertType::User).unwrap();
                builder.serial(self.receipts.len() as u64 + 1).unwrap();
                builder
                    .key_id(format!(
                        "spl:{}:{}:{}:{certificate_id}",
                        self.owner.organization, self.owner.account, self.owner.device
                    ))
                    .unwrap();
                builder
                    .valid_principal(format!(
                        "spl:{}:h:{}:{}",
                        self.owner.organization,
                        if self.wrong_principal { id() } else { self.host },
                        parsed.remote_user
                    ))
                    .unwrap();
                builder.extension("permit-pty", "").unwrap();
                builder.extension("permit-port-forwarding", "").unwrap();
                builder.extension("org@scoplen.com", self.owner.organization.to_string()).unwrap();
                let other = ssh_key::PrivateKey::new(
                    ssh_key::private::Ed25519Keypair::from_seed(&[71; 32]).into(),
                    "",
                )
                .unwrap();
                let certificate = builder
                    .sign(if self.wrong_ca { &other } else { &self.key })
                    .unwrap()
                    .to_openssh()
                    .unwrap();
                CertificateIssuanceResponse::new(
                    certificate_id,
                    "\"1\"",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                    certificate,
                )
                .unwrap()
                .to_json()
                .unwrap()
            };
            self.receipts.insert(key, (body.to_vec(), response.clone()));
            response
        };
        if std::mem::take(&mut self.unknown_once) {
            return Ok(problem("organization.commit_outcome_unknown", 503, true, true));
        }
        Ok(Reply {
            status: 201,
            headers: vec![
                ("etag", "\"1\"".into()),
                ("cache-control", "no-store".into()),
                ("pragma", "no-cache".into()),
                ("x-request-id", "fixture-request".into()),
            ],
            ..json(encoded)
        })
    }
}

async fn setup() -> (Peer, tempfile::TempDir, Arc<Store>, PersonalServer, TeamSshSource, uuid::Uuid)
{
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let (organization, host) = (id(), id());
    let identity = record(&store).unwrap();
    let source = TeamSshSource {
        origin: peer.origin.clone(),
        account_id: identity.account_id.to_string(),
        organization_id: organization.to_string(),
        device_id: store.device_id().to_string(),
    };
    let owner = TeamSshOwner {
        origin: peer.origin.clone(),
        account: identity.account_id,
        organization,
        device: store.device_id(),
    };
    let mut object = Object::new(host, ObjectType::HOST, 1).unwrap();
    for (field, text) in [(1, "Team Host"), (2, "host.example")] {
        object
            .insert(
                FieldPath::Field(field),
                FieldEntry::new(Value::Text(text.into()), Hlc::at(1).unwrap(), host).unwrap(),
            )
            .unwrap();
    }
    let publication = TeamAssetPublication {
        organization,
        generation: store.begin_team_asset_pull(&identity, organization).unwrap(),
        vault: id(),
        revision: 1,
        cursor: 1,
    };
    store.publish_team_assets(&identity, &publication, &[object]).unwrap();
    let key =
        ssh_key::PrivateKey::new(ssh_key::private::Ed25519Keypair::from_seed(&[70; 32]).into(), "")
            .unwrap();
    peer.state.lock().unwrap().team_ssh = Some(TeamSshPeer {
        store: store.clone(),
        owner,
        host,
        key,
        ca: None,
        receipts: BTreeMap::new(),
        requests: vec![],
        unknown_once: false,
        denied: false,
        wrong_principal: false,
        wrong_ca: false,
    });
    (peer, dir, store, manager, source, host)
}

async fn create_ca(manager: &PersonalServer, store: &Arc<Store>, source: &TeamSshSource) {
    let prepared = manager.prepare_team_user_ca(store, source).unwrap();
    let confirmed = manager
        .confirm_team_ssh_operation(
            store.clone(),
            source,
            TeamSshOperationKind::UserCa,
            &prepared.operation_id,
        )
        .await
        .unwrap();
    assert_eq!(confirmed.phase, TeamCreationPhase::Confirmed);
}

#[tokio::test]
async fn native_ca_and_certificate_use_durable_original_requests_and_offline_cache() {
    let (peer, _dir, store, manager, source, host) = setup().await;
    assert!(manager.team_user_ca(store.clone(), &source).await.unwrap().is_none());
    create_ca(&manager, &store, &source).await;
    let ca = manager.team_user_ca(store.clone(), &source).await.unwrap().unwrap();
    assert_eq!(ca.source, source);
    let certificate =
        manager.team_ssh_certificate(store.clone(), &source, host, "root").await.unwrap();
    assert!(!certificate.cached);
    let count = peer.state.lock().unwrap().paths.len();
    peer.task.abort();
    let cached = manager.team_ssh_certificate(store.clone(), &source, host, "root").await.unwrap();
    assert!(cached.cached);
    assert_eq!(cached.certificate, certificate.certificate);
    assert_eq!(peer.state.lock().unwrap().paths.len(), count);
    assert!(store.list(ObjectType::HOST).unwrap().is_empty());
    peer.assert_healthy();
}

#[tokio::test]
async fn cached_certificate_stays_available_while_another_team_save_waits_for_https() {
    let (peer, _dir, store, manager, source, host) = setup().await;
    create_ca(&manager, &store, &source).await;
    let original =
        manager.team_ssh_certificate(store.clone(), &source, host, "root").await.unwrap();
    team_authoring::install(&peer, &store);
    let another_team = id().to_string();
    let fields: TeamAuthoringData = serde_json::from_value(serde_json::json!({
        "kind":"host","fields":{"name":"Another team's Host","address":"other.example"}
    }))
    .unwrap();
    let prepared = manager.prepare_team_authoring(&store, &another_team, fields.clone()).unwrap();
    manager
        .submit_team_authoring(store.clone(), &another_team, &prepared.operation_id)
        .await
        .unwrap();
    let current = manager
        .team_authoring_resource(
            store.clone(),
            &another_team,
            TeamAuthoringCollection::Host,
            &prepared.resource_id,
        )
        .await
        .unwrap();
    let reached = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    peer.state.lock().unwrap().pause = Some((
        format!("/api/v1/orgs/{another_team}/hosts/{}", prepared.resource_id),
        reached.clone(),
        resume.clone(),
    ));
    let saving = manager.update_team_authoring(
        store.clone(),
        &another_team,
        &prepared.resource_id,
        &current.etag,
        fields,
    );
    tokio::pin!(saving);
    tokio::select! {
        _ = &mut saving => panic!("save finished before the HTTPS response was released"),
        _ = reached.notified() => {}
    }
    let before = peer.state.lock().unwrap().paths.len();
    let cached = manager.team_ssh_certificate(store.clone(), &source, host, "root").await;
    let uncached = manager.team_ssh_certificate(store.clone(), &source, host, "deploy").await;
    let after = peer.state.lock().unwrap().paths.len();
    resume.notify_one();
    assert_eq!(saving.await.unwrap().organization_id, another_team);
    let cached = cached.unwrap();
    assert!(cached.cached);
    assert_eq!(cached.certificate, original.certificate);
    cached.current(&store).unwrap();
    assert_eq!(uncached, Err(TeamSshError::Personal(PersonalServerError::Busy)));
    assert_eq!(after, before);
    peer.assert_healthy();
}

#[tokio::test]
async fn unknown_issuance_requires_explicit_original_confirmation_and_cannot_renew() {
    let (peer, _dir, store, manager, source, host) = setup().await;
    create_ca(&manager, &store, &source).await;
    peer.state.lock().unwrap().team_ssh.as_mut().unwrap().unknown_once = true;
    assert_eq!(
        manager.team_ssh_certificate(store.clone(), &source, host, "root").await,
        Err(TeamSshError::Ssh(TeamSshFailure::IssuanceUnknown))
    );
    let before = peer.state.lock().unwrap().paths.len();
    assert_eq!(
        manager.team_ssh_certificate(store.clone(), &source, host, "root").await,
        Err(TeamSshError::Ssh(TeamSshFailure::IssuanceUnknown))
    );
    assert_eq!(peer.state.lock().unwrap().paths.len(), before);
    let pending = manager
        .team_ssh_operations(&store, &source)
        .unwrap()
        .into_iter()
        .find(|operation| operation.kind == TeamSshOperationKind::Certificate)
        .unwrap();
    assert_eq!(pending.phase, TeamCreationPhase::Unknown);
    assert!(
        manager
            .discard_team_ssh_operation(&store, &source, pending.kind, &pending.operation_id)
            .is_err()
    );
    manager
        .confirm_team_ssh_operation(store.clone(), &source, pending.kind, &pending.operation_id)
        .await
        .unwrap();
    let cached = manager.team_ssh_certificate(store.clone(), &source, host, "root").await.unwrap();
    assert!(cached.cached);
    let state = peer.state.lock().unwrap();
    let requests = &state.team_ssh.as_ref().unwrap().requests;
    assert_eq!(requests[1], requests[2]);
    drop(state);
    peer.assert_healthy();
}

#[tokio::test]
async fn unknown_ca_creation_keeps_one_original_key_until_explicit_confirmation() {
    let (peer, _dir, store, manager, source, _host) = setup().await;
    peer.state.lock().unwrap().team_ssh.as_mut().unwrap().unknown_once = true;
    let prepared = manager.prepare_team_user_ca(&store, &source).unwrap();
    assert_eq!(
        manager
            .confirm_team_ssh_operation(
                store.clone(),
                &source,
                prepared.kind,
                &prepared.operation_id
            )
            .await,
        Err(TeamSshError::Ssh(TeamSshFailure::CaUnknown))
    );
    assert_eq!(
        manager.prepare_team_user_ca(&store, &source),
        Err(TeamSshError::Ssh(TeamSshFailure::PreparationPending))
    );
    let retained = manager.team_ssh_operations(&store, &source).unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].phase, TeamCreationPhase::Unknown);
    assert_eq!(retained[0].operation_id, prepared.operation_id);
    manager
        .confirm_team_ssh_operation(store.clone(), &source, prepared.kind, &prepared.operation_id)
        .await
        .unwrap();
    let state = peer.state.lock().unwrap();
    let fixture = state.team_ssh.as_ref().unwrap();
    assert_eq!(fixture.requests.len(), 2);
    assert_eq!(fixture.requests[0], fixture.requests[1]);
    assert_eq!(fixture.receipts.len(), 1);
    drop(state);
    peer.assert_healthy();
}

#[tokio::test]
async fn another_host_principal_is_rejected_and_local_invalidation_blocks_cached_use() {
    let (peer, _dir, store, manager, source, host) = setup().await;
    create_ca(&manager, &store, &source).await;
    peer.state.lock().unwrap().team_ssh.as_mut().unwrap().wrong_principal = true;
    assert_eq!(
        manager.team_ssh_certificate(store.clone(), &source, host, "root").await,
        Err(TeamSshError::Ssh(TeamSshFailure::InvalidCertificate))
    );
    assert!(
        store.team_ssh_certificate(&source.owner(&store).unwrap(), host, "root").unwrap().is_none()
    );
    let mut other = source.clone();
    other.device_id = id().to_string();
    assert_eq!(
        manager.team_ssh_certificate(store.clone(), &other, host, "root").await,
        Err(TeamSshError::Ssh(TeamSshFailure::InvalidSource))
    );
    let identity = record(&store).unwrap();
    store
        .invalidate_team_assets(
            &identity,
            uuid::Uuid::parse_str(&source.organization_id).unwrap(),
            None,
        )
        .unwrap();
    assert_eq!(
        manager.team_ssh_certificate(store.clone(), &source, host, "root").await,
        Err(TeamSshError::Ssh(TeamSshFailure::ViewRequired))
    );
    peer.assert_healthy();
}

#[tokio::test]
async fn authenticated_ca_trust_rejects_a_valid_signature_from_another_ca() {
    let (peer, _dir, store, manager, source, host) = setup().await;
    create_ca(&manager, &store, &source).await;
    peer.state.lock().unwrap().team_ssh.as_mut().unwrap().wrong_ca = true;
    assert_eq!(
        manager.team_ssh_certificate(store.clone(), &source, host, "root").await,
        Err(TeamSshError::Ssh(TeamSshFailure::InvalidCertificate))
    );
    assert!(
        store.team_ssh_certificate(&source.owner(&store).unwrap(), host, "root").unwrap().is_none()
    );
    peer.assert_healthy();
}

#[tokio::test]
async fn sqlcipher_reopen_preserves_signer_and_offline_certificate_without_displaying_stale_assets()
{
    let (peer, dir, store, manager, source, host) = setup().await;
    create_ca(&manager, &store, &source).await;
    let certificate =
        manager.team_ssh_certificate(store.clone(), &source, host, "root").await.unwrap();
    let before = peer.state.lock().unwrap().paths.len();
    peer.task.abort();
    let reopened = local(&dir);
    assert_ne!(
        manager.team_assets(&reopened, &source.organization_id).unwrap().phase,
        crate::personal_server::TeamAssetsPhase::Ready
    );
    let restored = manager.team_ssh_certificate(reopened, &source, host, "root").await.unwrap();
    assert!(restored.cached);
    assert_eq!(restored.signing_key, certificate.signing_key);
    assert_eq!(restored.certificate, certificate.certificate);
    assert_eq!(peer.state.lock().unwrap().paths.len(), before);
    peer.assert_healthy();
}

#[tokio::test]
async fn current_view_permission_denial_withdraws_the_cached_certificate() {
    let (peer, _dir, store, manager, source, host) = setup().await;
    create_ca(&manager, &store, &source).await;
    let certificate =
        manager.team_ssh_certificate(store.clone(), &source, host, "root").await.unwrap();
    let organization = uuid::Uuid::parse_str(&source.organization_id).unwrap();
    let vault = manager.team_assets(&store, &source.organization_id).unwrap().vault_id.unwrap();
    let mut response = SyncSessionResponse::from_cbor(
        &peer.state.lock().unwrap().replies["/sync/v1/session"].body,
    )
    .unwrap();
    response.vaults.push(SessionVault {
        id: uuid::Uuid::parse_str(&vault).unwrap(),
        kind: VaultKind::Organization,
        seq: 1,
        key_epoch: 1,
        rotation_pending: false,
        organization: Some(OrganizationVaultContext { organization, view_revision: 1 }),
    });
    peer.reply("/sync/v1/session", Reply::cbor(response.to_cbor().unwrap()));
    let denial = scoplen_api::ProblemDetails::new(
        scoplen_api::ErrorCode::new("policy.denied").unwrap(),
        403,
        "Fixture",
        "Fixture denial",
        "fixture-request",
        false,
        false,
    )
    .unwrap();
    peer.reply(
        &format!("/sync/v1/vaults/{vault}/view"),
        Reply {
            status: 403,
            content_type: "application/problem+cbor",
            body: denial.to_cbor().unwrap(),
            headers: vec![],
            stall: false,
        },
    );
    assert!(manager.refresh_team_assets(store.clone(), &source.organization_id).await.is_err());
    assert!(certificate.current(&store).is_err());
    assert_eq!(
        manager.team_ssh_certificate(store.clone(), &source, host, "root").await,
        Err(TeamSshError::Ssh(TeamSshFailure::ViewRequired))
    );
    peer.assert_healthy();
}
