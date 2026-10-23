// SPDX-License-Identifier: Apache-2.0
//! Independent relay and native admission peer; no Server implementation is imported.

use scoplen_api::{
    auth::{
        AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthTokenResponse,
        INITIAL_DEVICE_ACCESS_SCOPE,
    },
    pairing::{
        PairingClaimRequest, PairingClaimResponse, PairingCompleteRequest, PairingContext,
        PairingCreateRequest, PairingCreateResponse, PairingMessageAck, PairingMessageRequest,
        PairingReceipt, PairingSnapshot, PairingState, PairingStep,
    },
    sync::SyncAccountKeyBundleUpdate,
};
use scoplen_crypto::{
    DeviceAuthContext, PairingApplicationContext, PairingCompletionContext,
    PairingContext as CryptoContext, SecretBytes, ed25519_verify, p256_verify,
};

use super::*;
use crate::personal_server::{PairingError, PairingPhase};

pub(super) struct PairingPeer {
    old: Arc<Store>,
    new: Arc<Store>,
    old_token: Zeroizing<String>,
    old_jkt: String,
    context: Option<PairingContext>,
    messages: Vec<PairingMessageRequest>,
    receipt: Option<PairingReceipt>,
    certificate: Option<DeviceCertificate>,
    nonce: Option<String>,
    cancelled: bool,
    lose_acceptance: bool,
    lose_complete: bool,
    commit_before_loss: bool,
    complete_bodies: Vec<Vec<u8>>,
    bad_headers: bool,
}

fn json(body: Vec<u8>) -> Reply {
    Reply {
        content_type: "application/json",
        headers: vec![
            ("cache-control", "no-store".into()),
            ("pragma", "no-cache".into()),
            ("referrer-policy", "no-referrer".into()),
        ],
        ..Reply::cbor(body)
    }
}

impl PairingPeer {
    pub(super) fn answer(
        &mut self,
        request: &http::Request<h2::RecvStream>,
        body: &[u8],
        state: &mut PeerState,
        origin: &str,
    ) -> Result<Reply, String> {
        let path = request.uri().path();
        if matches!(path, "/api/v1/auth/challenge" | "/api/v1/auth/device") {
            return self.authenticate(request, body, state, origin);
        }
        if request.headers().contains_key("origin")
            || request.headers().contains_key("referer")
            || request.headers().get("accept").and_then(|value| value.to_str().ok())
                != Some("application/json")
        {
            return Err("unexpected pairing browser transport".into());
        }
        if path == "/api/v1/auth/pairings" {
            if request.method() != http::Method::POST
                || request.headers().contains_key("authorization")
                || request.headers().contains_key("dpop")
            {
                return Err("credential leaked to create".into());
            }
            let created = PairingCreateRequest::from_json(body).map_err(|_| "bad create")?;
            if created.device_id != self.new.device_id() {
                return Err("wrong new identity".into());
            }
            let context = PairingContext {
                origin: origin.into(),
                pairing_id: scoplen_model::new_uuid_v7().unwrap(),
                initiator_device_id: None,
                responder_device_id: created.device_id,
                expires_at: "2099-01-01T00:00:00Z".into(),
            };
            self.context = Some(context.clone());
            let mut reply = json(
                PairingCreateResponse {
                    context,
                    new_device_token: SecretBytes::from_slice(&[43; 32]).unwrap(),
                }
                .to_json()
                .unwrap(),
            );
            reply.status = 201;
            if self.bad_headers {
                reply.headers.retain(|(name, _)| *name != "referrer-policy");
            }
            return Ok(reply);
        }
        let context = self.context.as_ref().ok_or("missing relay")?.clone();
        let prefix = format!("/api/v1/auth/pairings/{}", context.pairing_id);
        let suffix = path.strip_prefix(&prefix).ok_or("wrong locator")?;
        let authorization = request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .ok_or("missing role credential")?;
        let old = if let Some(token) = authorization.strip_prefix("DPoP ") {
            if token != self.old_token.as_str() {
                return Err("wrong old token".into());
            }
            let proof = DpopProof::parse(
                request
                    .headers()
                    .get("dpop")
                    .and_then(|value| value.to_str().ok())
                    .ok_or("missing role proof")?,
            )
            .map_err(|_| "bad role proof")?;
            let verified = proof
                .verify(
                    &DpopTarget::new(request.method().as_str(), origin, path).unwrap(),
                    DpopToken::Protected(token),
                    &self.old_jkt,
                    now().unwrap(),
                    None,
                )
                .map_err(|_| "wrong role proof binding")?;
            if !state.proofs.insert(verified.jti) {
                return Err("replayed pairing proof".into());
            }
            true
        } else {
            if authorization != format!("Pairing {}", URL_SAFE_NO_PAD.encode([43; 32]))
                || request.headers().contains_key("dpop")
            {
                return Err("mixed role credentials".into());
            }
            false
        };
        match (request.method().as_str(), suffix) {
            ("POST", "/claim") if old => {
                PairingClaimRequest::from_json(body).map_err(|_| "bad claim")?;
                self.context.as_mut().unwrap().initiator_device_id = Some(self.old.device_id());
                Ok(json(
                    PairingClaimResponse { context: self.context.as_ref().unwrap().clone() }
                        .to_json()
                        .unwrap(),
                ))
            }
            ("GET", "") if body.is_empty() => {
                let state = if self.receipt.is_some() {
                    PairingState::Completed
                } else if self.cancelled {
                    PairingState::Cancelled
                } else if self.messages.len() == 7 {
                    PairingState::Ready
                } else if context.initiator_device_id.is_none() {
                    PairingState::Waiting
                } else {
                    PairingState::Exchanging
                };
                Ok(json(
                    PairingSnapshot {
                        context: self.context.as_ref().unwrap().clone(),
                        state,
                        messages: if state.is_terminal() { vec![] } else { self.messages.clone() },
                        receipt: self.receipt.clone(),
                    }
                    .to_json()
                    .unwrap(),
                ))
            }
            ("POST", "/messages") => {
                let message = PairingMessageRequest::from_json(body).map_err(|_| "bad slot")?;
                let initiator = message.step.role() == scoplen_api::pairing::PairingRole::Initiator;
                if old != initiator {
                    return Err("wrong slot role".into());
                }
                let observer = if old { &self.old } else { &self.new };
                let saved = observer.pairing_record().unwrap().ok_or("slot before checkpoint")?;
                if !saved.attempt_started {
                    return Err("share before durable attempt".into());
                }
                if message.step == PairingStep::Handoff
                    && (saved.handoff.as_ref().map(SecretVec::as_bytes)
                        != Some(message.payload.as_slice())
                        || saved.certificate.is_none()
                        || saved.key_update.is_none())
                {
                    return Err("handoff before exact plan".into());
                }
                if message.step == PairingStep::Acceptance {
                    let identity =
                        observer.personal_record().unwrap().ok_or("acceptance before identity")?;
                    if identity.enrollment_request.is_some()
                        || identity.enrollment_attempted
                        || identity.private_material.as_bytes().first() != Some(&2)
                        || saved.acceptance.as_ref().map(SecretVec::as_bytes)
                            != Some(message.payload.as_slice())
                    {
                        return Err("fabricated paired identity".into());
                    }
                }
                let index = message.step.index();
                if index < self.messages.len() {
                    if self.messages[index].payload != message.payload {
                        return Err("occupied slot changed".into());
                    }
                } else if index == self.messages.len() {
                    self.messages.push(message.clone());
                } else {
                    return Err("slot order".into());
                }
                let mut reply = json(PairingMessageAck { step: message.step }.to_json().unwrap());
                if message.step == PairingStep::Acceptance && self.lose_acceptance {
                    self.lose_acceptance = false;
                    reply.stall = true;
                }
                Ok(reply)
            }
            ("POST", "/complete") if old => {
                let saved = self.old.pairing_record().unwrap().unwrap();
                if saved.approval_request.as_ref().map(SecretVec::as_bytes) != Some(body) {
                    return Err("approval before exact durable bytes".into());
                }
                self.complete_bodies.push(body.to_vec());
                let approval =
                    PairingCompleteRequest::from_json(body).map_err(|_| "bad approval")?;
                if self.messages.len() != 7
                    || approval.new_device_signature.as_slice() != self.messages[6].payload
                {
                    return Err("approval without acceptance".into());
                }
                let certificate = DeviceCertificate::decode(&approval.device_certificate)
                    .map_err(|_| "bad certificate")?;
                let identity = record(&self.old).unwrap();
                let enrollment = PersonalEnrollmentRequest::from_json(
                    identity.enrollment_request.as_ref().unwrap().as_bytes(),
                )
                .unwrap();
                certificate
                    .verify(&enrollment.account_signing_public_key)
                    .map_err(|_| "certificate root changed")?;
                let update = SyncAccountKeyBundleUpdate::from_cbor(&approval.key_bundle_update)
                    .map_err(|_| "bad update")?;
                ed25519_verify(
                    &enrollment.account_signing_public_key,
                    &update.signature_input().unwrap(),
                    &update.signature,
                )
                .map_err(|_| "bad account approval")?;
                let application = PairingApplicationContext::new(
                    origin,
                    CryptoContext::new(
                        context.pairing_id,
                        self.old.device_id(),
                        self.new.device_id(),
                    )
                    .unwrap(),
                )
                .unwrap();
                PairingCompletionContext::new(
                    &application,
                    identity.account_id,
                    &self.messages[5].payload,
                    &approval.device_certificate,
                    &approval.key_bundle_update,
                )
                .unwrap()
                .verify(&certificate.signing_public_key, &approval.new_device_signature)
                .map_err(|_| "bad possession proof")?;
                if update.revision != 2
                    || update.device_wraps.len() != 2
                    || !update
                        .device_wraps
                        .iter()
                        .any(|wrap| wrap.device_id == self.old.device_id())
                    || update.account_signing_key
                        != enrollment.key_bundle_update.account_signing_key
                    || update.account_kem_key != enrollment.key_bundle_update.account_kem_key
                    || update.recovery_blob != enrollment.key_bundle_update.recovery_blob
                {
                    return Err("not membership-only admission".into());
                }
                let receipt = PairingReceipt {
                    account_id: identity.account_id,
                    device_id: self.new.device_id(),
                    revision: 2,
                };
                let mut reply = json(receipt.to_json().unwrap());
                let lost = self.lose_complete;
                self.lose_complete = false;
                if !lost || self.commit_before_loss {
                    let new_wrap = update
                        .device_wraps
                        .iter()
                        .find(|wrap| wrap.device_id == self.new.device_id())
                        .ok_or("missing new recipient")?;
                    state.replies.insert(
                        "/sync/v1/keys".into(),
                        Reply::cbor(
                            SyncAccountKeyBundle {
                                revision: 2,
                                wrapped_ark: new_wrap.wrapped_ark.clone(),
                                account_signing_key: update.account_signing_key,
                                account_kem_key: update.account_kem_key,
                                recovery_blob: update.recovery_blob,
                                certificates: vec![
                                    enrollment.device_certificate.encode().unwrap(),
                                    approval.device_certificate,
                                ],
                                revocations: vec![],
                            }
                            .to_cbor()
                            .unwrap(),
                        ),
                    );
                    self.receipt = Some(receipt);
                    self.certificate = Some(certificate);
                }
                reply.stall = lost;
                Ok(reply)
            }
            ("DELETE", "") if body.is_empty() => {
                self.cancelled = true;
                Ok(Reply { status: 204, content_type: "", ..json(vec![]) })
            }
            _ => Err("unknown pairing method".into()),
        }
    }

    fn authenticate(
        &mut self,
        request: &http::Request<h2::RecvStream>,
        body: &[u8],
        state: &mut PeerState,
        origin: &str,
    ) -> Result<Reply, String> {
        if request.method() != http::Method::POST
            || request.headers().contains_key("authorization")
            || request.headers().contains_key("dpop")
        {
            return Err("mixed native auth credentials".into());
        }
        let Some(certificate) = &self.certificate else {
            return Ok(Reply { status: 401, ..json(b"{}".to_vec()) });
        };
        if request.uri().path() == "/api/v1/auth/challenge" {
            let challenge =
                AuthChallengeRequest::from_json(std::str::from_utf8(body).unwrap()).unwrap();
            if challenge.device_id != self.new.device_id() {
                return Err("wrong new challenge".into());
            }
            self.nonce = Some("ab".repeat(32));
            return Ok(json(
                AuthChallengeResponse::new(self.nonce.as_ref().unwrap(), "2099-01-01T00:00:00Z")
                    .unwrap()
                    .to_json()
                    .unwrap()
                    .into_bytes(),
            ));
        }
        let device = AuthDeviceRequest::from_json(std::str::from_utf8(body).unwrap()).unwrap();
        if device.device_id != self.new.device_id() || Some(&device.nonce) != self.nonce.as_ref() {
            return Err("wrong native device".into());
        }
        let signature = (0..128)
            .step_by(2)
            .map(|offset| u8::from_str_radix(&device.signature[offset..offset + 2], 16).unwrap())
            .collect::<Vec<_>>();
        p256_verify(
            &certificate.signing_public_key,
            &DeviceAuthContext::new(origin, &device.nonce, device.device_id)
                .unwrap()
                .signature_input(),
            &signature,
        )
        .map_err(|_| "bad retained device proof")?;
        self.nonce = None;
        let authority = Ed25519SigningKey::from_bytes(&[55; 32]).unwrap();
        let mut trusted = TrustedDeviceAccessTokenKeys::new(origin).unwrap();
        trusted.insert("fixture", &authority.public_key()).unwrap();
        let jkt = dpop_jwk_thumbprint(&certificate.signing_public_key).unwrap();
        let claims = DeviceAccessTokenClaims {
            iss: origin.into(),
            sub: certificate.account_id,
            did: device.device_id,
            jti: scoplen_model::new_uuid_v7().unwrap(),
            cnf_jkt: jkt.clone(),
            org: vec![],
            scope: INITIAL_DEVICE_ACCESS_SCOPE.into(),
            iat: now().unwrap(),
            exp: now().unwrap() + 600,
        };
        let token = DeviceAccessToken::sign(
            &authority,
            &trusted,
            "fixture",
            &certificate.signing_public_key,
            &claims,
        )
        .unwrap();
        state.expected = Some(Expected {
            token: Zeroizing::new(token.as_str().into()),
            jkt,
            device: device.device_id,
            signing_public: certificate.signing_public_key.clone(),
        });
        Ok(json(
            AuthTokenResponse::new(token.as_str(), "paired-refresh")
                .unwrap()
                .to_json()
                .unwrap()
                .into_bytes(),
        ))
    }
}

async fn setup() -> (
    Peer,
    tempfile::TempDir,
    tempfile::TempDir,
    Arc<Store>,
    Arc<Store>,
    PersonalServer,
    PersonalServer,
) {
    let peer = Peer::new().await;
    let old_dir = tempfile::tempdir().unwrap();
    let new_dir = tempfile::tempdir().unwrap();
    let old = local(&old_dir);
    let new = local(&new_dir);
    let old_manager = peer.prepare(&old).await;
    let new_manager = peer.manager();
    {
        let mut state = peer.state.lock().unwrap();
        let expected = state.expected.as_ref().unwrap();
        state.pairing = Some(PairingPeer {
            old: old.clone(),
            new: new.clone(),
            old_token: Zeroizing::new(expected.token.to_string()),
            old_jkt: expected.jkt.clone(),
            context: None,
            messages: vec![],
            receipt: None,
            certificate: None,
            nonce: None,
            cancelled: false,
            lose_acceptance: false,
            lose_complete: false,
            commit_before_loss: false,
            complete_bodies: vec![],
            bad_headers: false,
        });
    }
    (peer, old_dir, new_dir, old, new, old_manager, new_manager)
}

async fn to_confirmation(
    peer: &Peer,
    old: &Arc<Store>,
    new: &Arc<Store>,
    old_manager: &PersonalServer,
    new_manager: &PersonalServer,
) {
    let started = new_manager
        .pairing_create(new.clone(), peer.origin.clone(), "New desktop".into())
        .await
        .unwrap();
    let status = serde_json::to_string(&started.status).unwrap();
    let password = std::str::from_utf8(started.password.as_bytes()).unwrap();
    assert!(!status.contains(password));
    assert!(!format!("{started:?}").contains(password));
    old_manager
        .pairing_join(
            old.clone(),
            started.status.public_link.unwrap(),
            Zeroizing::new(password.into()),
        )
        .await
        .unwrap();
    assert_eq!(
        new_manager.pairing_progress(new.clone()).await.unwrap().phase,
        PairingPhase::Exchanging
    );
    new_manager.pairing_progress(new.clone()).await.unwrap();
    old_manager.pairing_progress(old.clone()).await.unwrap();
    new_manager.pairing_progress(new.clone()).await.unwrap();
    let confirmation = old_manager.pairing_progress(old.clone()).await.unwrap();
    assert_eq!(confirmation.phase, PairingPhase::ConfirmDevice);
    assert_eq!(confirmation.peer_name.as_deref(), Some("New desktop"));
    assert_eq!(confirmation.peer_platform.as_deref(), Some(std::env::consts::OS));
    assert!(new.personal_record().unwrap().is_none());
}

#[tokio::test]
async fn both_public_managers_pair_existing_account_then_authenticate_bootstrap_and_reopen_offline()
{
    let (peer, _old_dir, new_dir, old, new, old_manager, new_manager) = setup().await;
    let host = new
        .write(crate::store::LocalWrite {
            id: None,
            object_type: scoplen_model::ObjectType::HOST,
            fields: vec![
                (
                    scoplen_model::FieldPath::Field(1),
                    scoplen_model::cbor::Value::Text("Paired host".into()),
                ),
                (
                    scoplen_model::FieldPath::Field(2),
                    scoplen_model::cbor::Value::Text("192.0.2.20".into()),
                ),
            ],
        })
        .unwrap();
    to_confirmation(&peer, &old, &new, &old_manager, &new_manager).await;
    old_manager.pairing_confirm(old.clone()).await.unwrap();
    new_manager.pairing_progress(new.clone()).await.unwrap();
    let pending = record(&new).unwrap();
    assert!(pending.enrollment_request.is_none());
    assert!(!pending.enrollment_attempted);
    assert_eq!(identity::Secrets::parse(&pending.private_material).unwrap().recovery(), None);
    assert!(new.personal_sync_record().unwrap().is_none());
    assert_eq!(
        new_manager.status(&new).unwrap().phase,
        crate::personal_server::PersonalServerPhase::AuthenticationRequired
    );
    assert_eq!(
        old_manager.pairing_progress(old.clone()).await.unwrap().phase,
        PairingPhase::Completed
    );
    assert_eq!(
        new_manager.pairing_progress(new.clone()).await.unwrap().phase,
        PairingPhase::Completed
    );
    let old_identity = record(&old).unwrap();
    let new_identity = record(&new).unwrap();
    assert_eq!(old_identity.account_id, new_identity.account_id);
    assert_eq!(old_identity.personal_vault_id, new_identity.personal_vault_id);
    let before = new_manager.load_sync_bootstrap(&new).unwrap().unwrap();
    assert_eq!(before.active_devices.len(), 2);
    assert_eq!(new.personal_sync_record().unwrap().unwrap().generation, 1);
    let inventory = new.personal_inventory_snapshot(new_identity.personal_vault_id).unwrap();
    assert_eq!(inventory.objects.len(), 1);
    assert!(
        inventory
            .objects
            .iter()
            .any(|(object, personal, dirty)| object.id == host.id && !personal && !dirty)
    );
    assert_eq!(inventory.pending, 0);
    assert_eq!(inventory.applied, 0);
    assert_eq!(inventory.acknowledged, 0);
    let paths_before = peer.state.lock().unwrap().paths.len();
    let settings = crate::personal_inventory::PersonalInventorySettings::default();
    assert_eq!(settings.status(&new).unwrap().vault_id, new_identity.personal_vault_id.to_string());
    assert_eq!(peer.state.lock().unwrap().paths.len(), paths_before);
    peer.state.lock().unwrap().inventory = Some(InventoryPeer::default());
    let progress = new_manager
        .sync_personal_inventory(
            new.clone(),
            PersonalInventoryIntent {
                vault_id: new_identity.personal_vault_id,
                adopt: vec![host.id],
            },
        )
        .await
        .unwrap();
    assert_eq!(progress.uploaded, 1);
    assert_eq!(progress.downloaded, 1);
    let profile = scoplen_api::account_profile::AccountProfile::new(
        new_identity.account_id,
        "\"paired\"",
        "2026-10-23T00:00:00Z",
        "2026-10-23T00:00:00Z",
        None,
    )
    .unwrap();
    let mut profile_reply = json(profile.to_json().unwrap());
    profile_reply.headers.push(("etag", profile.etag));
    peer.reply("/api/v1/accounts/me", profile_reply);
    let bundle =
        SyncAccountKeyBundle::from_cbor(&peer.state.lock().unwrap().replies["/sync/v1/keys"].body)
            .unwrap();
    let mut certificates = bundle.certificates;
    certificates.sort();
    let statements = scoplen_api::account_devices::AccountDeviceStatements::new(
        new_identity.account_id,
        certificates,
        vec![],
    )
    .unwrap();
    peer.reply("/api/v1/accounts/me/devices", json(statements.to_json().unwrap()));
    let account = new_manager.query_account(new.clone()).await.unwrap();
    assert_eq!(account.devices.len(), 2);
    assert!(
        account
            .devices
            .iter()
            .any(|device| device.current && device.id == new.device_id().to_string())
    );
    peer.assert_healthy();
    new.clear_personal_tokens().unwrap();
    drop(peer);
    drop(new);
    let reopened = local(&new_dir);
    let after = PersonalServer::default().load_sync_bootstrap(&reopened).unwrap().unwrap();
    assert_eq!(before.personal_vault_key(), after.personal_vault_key());
    assert_eq!(
        PersonalServer::default().pairing_status(&reopened).unwrap().phase,
        PairingPhase::Completed
    );
}

mod recovery;
