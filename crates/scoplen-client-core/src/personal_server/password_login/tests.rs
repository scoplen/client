// SPDX-License-Identifier: Apache-2.0
//! Independent TLS 1.3/H2 peer exercising the public password/admission/install boundary.

use super::*;
use crate::personal_server::registration::{
    http::tests::{Fixture, Reply},
    install::tests::{CurrentPeer, Fault},
};
use crate::{
    local_data::LocalData,
    personal_server::{PersonalServerError, PersonalSyncRuntime},
    store::LocalWrite,
    testing::MemoryKeystore,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::account_admission::{
    AccountDeviceAdmissionRequest, AccountPasswordOptionsRequest, AccountPersonalBootstrap,
    AccountPersonalEpoch, AccountRequestChallengeRequest, AccountRequestChallengeResponse,
};
use scoplen_crypto::{AccountRequestIntent, PasswordVerifier, SecretBytes};
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

struct Reference {
    initial: scoplen_api::account_admission::AccountRegistrationPayload,
    snapshot: AccountBootstrapSnapshot,
    options: Vec<AccountPasswordOptionsResponse>,
    challenges: Vec<(AccountRequestChallengeRequest, AccountRequestChallengeResponse)>,
    requests: Vec<AccountDeviceAdmissionRequest>,
    receipt: Option<AccountCommittedConfirmation>,
    current: Option<CurrentPeer>,
    submit_reply: Option<Reply>,
    options_reply: Option<Reply>,
    login_reply: Option<Reply>,
    reject_commit: bool,
    capability_lifetime: u64,
    confirmations: usize,
    proofs: HashSet<[u8; 64]>,
}

impl Reference {
    fn new(p: scoplen_api::account_admission::AccountRegistrationPayload) -> Self {
        let snapshot = AccountBootstrapSnapshot {
            origin: p.origin.clone(),
            username: p.username.clone(),
            account_id: p.account_id,
            personal_vault_id: p.personal_vault_id,
            account_signing_public_key: p.account_signing_public_key,
            account_kem_public_key: p.account_kem_public_key,
            credential_generation: 1,
            password_salt: p.password_salt,
            password_ark: p.password_ark,
            key_bundle: p.key_bundle.clone(),
            certificates: vec![p.device_certificate.clone()],
            revocations: vec![],
            personal: AccountPersonalBootstrap {
                current_epoch: 1,
                rotation_pending: false,
                epochs: vec![AccountPersonalEpoch {
                    epoch: 1,
                    wrapped_key: p.personal_wrapped_key,
                }],
            },
        };
        Self {
            initial: p,
            snapshot,
            options: vec![],
            challenges: vec![],
            requests: vec![],
            receipt: None,
            current: None,
            submit_reply: None,
            options_reply: None,
            login_reply: None,
            reject_commit: false,
            capability_lifetime: 300_000,
            confirmations: 0,
            proofs: HashSet::new(),
        }
    }

    fn answer(
        &mut self,
        request: &::http::request::Parts,
        body: &[u8],
        origin: &str,
    ) -> Result<Reply, String> {
        let op = AccountEntryOperation::from_route(request.method.as_str(), request.uri.path());
        match op {
            Some(AccountEntryOperation::PasswordOptions) => {
                let request =
                    AccountPasswordOptionsRequest::from_json(body).map_err(|_| "options codec")?;
                if request.username != "alice" {
                    return Err("fixture username".into());
                }
                let mut attempt = [0; 32];
                scoplen_crypto::random_bytes(&mut attempt).unwrap();
                let response = AccountPasswordOptionsResponse {
                    attempt_id: SecretBytes::new(attempt),
                    salt: self.initial.password_salt,
                    expires_at_ms: now_ms().unwrap() + 120_000,
                };
                let reply = self
                    .options_reply
                    .clone()
                    .unwrap_or_else(|| Reply::json(200, response.to_json().unwrap()));
                self.options.push(response);
                Ok(reply)
            }
            Some(AccountEntryOperation::PasswordLogin) => {
                let request =
                    AccountPasswordLoginRequest::from_json(body).map_err(|_| "login codec")?;
                let expected = self.options.pop().ok_or("missing options attempt")?;
                if request.attempt_id != expected.attempt_id {
                    return Err("wrong options attempt".into());
                }
                if PasswordVerifier::from_bytes(&self.initial.verifier)
                    .unwrap()
                    .verify(SecretVec::new(request.auth_secret.as_ref().to_vec()))
                    .is_err()
                {
                    return Ok(Reply::problem(401, "auth.authentication_required", false, false));
                }
                if let Some(reply) = &self.login_reply {
                    return Ok(reply.clone());
                }
                let snapshot = self.snapshot.to_cbor().map_err(|_| "snapshot codec")?;
                let body=serde_json::to_vec(&serde_json::json!({"admission_token":URL_SAFE_NO_PAD.encode([47u8;32]),
                    "expires_at_ms":(now_ms().unwrap()+self.capability_lifetime).to_string(),"snapshot":URL_SAFE_NO_PAD.encode(snapshot)})).unwrap();
                Ok(Reply::json(200, body))
            }
            Some(AccountEntryOperation::RequestChallenge) => {
                let request = AccountRequestChallengeRequest::from_json(body)
                    .map_err(|_| "admission challenge")?;
                if request.kind != AccountRequestKind::Admit {
                    return Err("wrong kind".into());
                }
                let n = u8::try_from(self.challenges.len() + 70).unwrap();
                let response = AccountRequestChallengeResponse {
                    attempt_id: SecretBytes::new([n; 32]),
                    nonce: SecretBytes::new([n + 1; 32]),
                    expires_at_ms: now_ms().unwrap() + 120_000,
                };
                let reply = Reply::json(200, response.to_json().unwrap());
                self.challenges.push((request, response));
                Ok(reply)
            }
            Some(AccountEntryOperation::DeviceAdmission) => {
                let request = AccountDeviceAdmissionRequest::from_json(body)
                    .map_err(|_| "admission codec")?;
                let p = AccountDeviceAdmissionPayload::from_cbor(request.payload.as_bytes())
                    .map_err(|_| "admission payload")?;
                let (challenge, response) =
                    self.challenges.last().ok_or("no admission challenge")?;
                if challenge.operation_id != p.operation_id
                    || challenge.device_id != p.device_id
                    || challenge.intent != request.intent
                    || request.attempt_id != response.attempt_id
                    || request.nonce != response.nonce
                    || !self.proofs.insert(request.device_proof)
                {
                    return Err("admission freshness".into());
                }
                let digest = request
                    .verify_proof(origin, &self.initial.account_signing_public_key)
                    .map_err(|_| "admission proof")?;
                if let Some(old) = self.requests.first()
                    && (old.payload != request.payload
                        || old.account_signature != request.account_signature)
                {
                    return Err("changed business bytes".into());
                }
                let reply = if request.intent == AccountRequestIntent::Submit {
                    p.validate_for_snapshot(
                        &self.snapshot,
                        &self.snapshot.to_cbor().unwrap(),
                        request.admission_token.as_ref().ok_or("no capability")?.as_bytes(),
                    )
                    .map_err(|_| "snapshot CAS")?;
                    if !self.reject_commit {
                        let bundle = SyncAccountKeyBundleUpdate::from_cbor(&p.key_bundle).unwrap();
                        self.receipt = Some(AccountCommittedConfirmation {
                            kind: AccountRequestKind::Admit,
                            operation_id: p.operation_id,
                            request_digest: digest,
                            account_id: p.account_id,
                            personal_vault_id: p.personal_vault_id,
                            device_id: p.device_id,
                            admitted_key_revision: bundle.revision,
                        });
                        let mut admitted = self.initial.clone();
                        admitted.device_id = p.device_id;
                        admitted.device_certificate = p.device_certificate.clone();
                        admitted.key_bundle = p.key_bundle.clone();
                        self.current = Some(CurrentPeer::admitted(admitted));
                    }
                    self.submit_reply.clone().unwrap_or_else(|| {
                        Reply::json(201, self.receipt.as_ref().unwrap().to_json().unwrap())
                    })
                } else {
                    self.confirmations += 1;
                    if request.admission_token.is_some() {
                        return Err("capability leaked to confirmation".into());
                    }
                    match &self.receipt {
                        Some(c) => Reply::json(200, c.to_json().unwrap()),
                        None => Reply::problem(401, "auth.authentication_required", false, false),
                    }
                };
                self.requests.push(request);
                Ok(reply)
            }
            None => {
                let current = self.current.as_mut().ok_or("no current Device")?;
                let mut reply = current.answer(request, body, origin)?;
                if request.uri.path() == "/sync/v1/keys" {
                    let mut bundle =
                        scoplen_api::sync::SyncAccountKeyBundle::from_cbor(reply.body.as_bytes())
                            .unwrap();
                    bundle.certificates.push(self.initial.device_certificate.clone());
                    bundle.certificates.sort();
                    reply.body = SecretVec::new(bundle.to_cbor().unwrap());
                }
                Ok(reply)
            }
            _ => Err("unsupported password fixture route".into()),
        }
    }
}

type Slots = Arc<Mutex<BTreeMap<PathBuf, MemoryKeystore>>>;
struct Harness {
    profiles: AccountProfiles,
    local: Arc<LocalData>,
    keys: MemoryKeystore,
    slots: Slots,
    reference: Arc<Mutex<Reference>>,
    f: Fixture,
    dir: tempfile::TempDir,
}
impl Harness {
    async fn new() -> Self {
        let f = Fixture::new().await;
        f.exchange(RegistrationAction::Submit).await.unwrap();
        let reference = Arc::new(Mutex::new(Reference::new(f.peer.payload())));
        let state = reference.clone();
        f.peer.extra(Box::new(move |r, b, o| state.lock().unwrap().answer(r, b, o)));
        let dir = tempfile::tempdir().unwrap();
        let keys = MemoryKeystore::default();
        let local = Arc::new(LocalData::start(dir.path(), Some(Box::new(keys.clone()))).unwrap());
        let slots = Slots::default();
        let profiles = catalog(local.clone(), &slots);
        Self { profiles, local, keys, slots, reference, f, dir }
    }
    async fn begin(&self) -> Result<PasswordLoginStatus, PasswordLoginError> {
        self.f
            .server
            .begin_password_login(
                &self.profiles,
                &self.profiles.current().unwrap(),
                &self.f.peer.origin,
                "alice",
                "Second device",
                SecretVec::new(b"a real account password".to_vec()),
                &RegistrationCancellation::default(),
            )
            .await
    }
    async fn exchange(
        &self,
        action: RegistrationAction,
    ) -> Result<PasswordLoginStatus, PasswordLoginError> {
        let source = self.profiles.current().unwrap();
        let id =
            self.f.server.password_login_status(&self.profiles, &source)?.unwrap().operation_id;
        self.f
            .server
            .exchange_password_login(
                &self.profiles,
                &source,
                id,
                action,
                &RegistrationCancellation::default(),
            )
            .await
    }
    async fn install(&self, operation: Uuid) -> Result<ProfileLease, AccountProfileError> {
        fn send<T: Send>(future: T) -> T {
            future
        }
        send(self.f.server.install_password_login_profile(
            &self.profiles,
            &self.profiles.current().unwrap(),
            operation,
            None,
            &RegistrationCancellation::default(),
        ))
        .await
    }
    fn root(&self) -> Arc<Store> {
        self.local.store().unwrap()
    }
    fn no_authority(&self) {
        let s = self.root();
        assert!(s.personal_record().unwrap().is_none());
        assert!(s.personal_sync_record().unwrap().is_none());
        assert!(s.device_key_pair().unwrap().is_none());
        assert!(s.personal_access_token(0).unwrap().is_none());
    }
    fn database(&self) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(self.dir.path().join("local.db")).unwrap();
        let k = self.keys.0.lock().unwrap();
        let hex = Zeroizing::new(
            k.as_ref().unwrap()[1..].iter().map(|b| format!("{b:02x}")).collect::<String>(),
        );
        let pragma = Zeroizing::new(format!("x'{}'", hex.as_str()));
        conn.pragma_update(None, "key", pragma.as_str()).unwrap();
        conn
    }
}
fn catalog(local: Arc<LocalData>, slots: &Slots) -> AccountProfiles {
    let slots = slots.clone();
    AccountProfiles::with_keystores(
        local,
        Arc::new(PersonalSyncRuntime::default()),
        Arc::new(move |p| {
            let slot = slots.lock().unwrap().entry(p.to_path_buf()).or_default().clone();
            Some(Box::new(slot))
        }),
    )
    .unwrap()
}

#[tokio::test]
async fn real_password_login_admits_independent_device_and_installs_same_account_vault() {
    let h = Harness::new().await;
    let local_id = h.root().device_id();
    let original = h.f.peer.payload();
    let local = h
        .root()
        .write(LocalWrite {
            id: None,
            object_type: scoplen_model::ObjectType::HOST,
            fields: vec![
                (
                    scoplen_model::FieldPath::Field(1),
                    scoplen_model::cbor::Value::Text("Local only".into()),
                ),
                (
                    scoplen_model::FieldPath::Field(2),
                    scoplen_model::cbor::Value::Text("host.example".into()),
                ),
            ],
        })
        .unwrap();
    let ready = h.begin().await.unwrap();
    assert_eq!(ready.phase, PasswordLoginPhase::Ready);
    assert_eq!(
        (ready.account_id, ready.personal_vault_id),
        (original.account_id, original.personal_vault_id)
    );
    assert_ne!(ready.device_id, original.device_id);
    assert_ne!(ready.device_id, local_id);
    h.no_authority();
    let pending = h.root().pending_password_login().unwrap().unwrap();
    assert_eq!(pending.entry.private_material.len(), 193);
    let new = DeviceCertificate::decode(&verify(&pending).unwrap().device_certificate).unwrap();
    let old = DeviceCertificate::decode(&original.device_certificate).unwrap();
    assert_ne!(new.signing_public_key, old.signing_public_key);
    assert_ne!(new.kem_public_key, old.kem_public_key);
    assert_ne!(new.signing_public_key, new.kem_public_key);
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await.unwrap().phase,
        PasswordLoginPhase::Committed
    );
    h.no_authority();
    let source = h.profiles.current().unwrap();
    let installed = h.install(ready.operation_id).await.unwrap();
    let profile = installed.account().unwrap();
    assert_eq!(
        (profile.account_id, profile.personal_vault_id, profile.device_id),
        (ready.account_id, ready.personal_vault_id, ready.device_id)
    );
    assert!(installed.store.personal_access_token(0).unwrap().is_some());
    assert!(installed.store.pending_password_login().unwrap().is_none());
    assert!(h.root().pending_password_login().unwrap().is_none());
    assert!(installed.store.list(scoplen_model::ObjectType::HOST).unwrap().is_empty());
    assert_eq!(
        installed.store.personal_record().unwrap().unwrap().private_material,
        pending.entry.private_material
    );
    assert!(!installed.store.personal_record().unwrap().unwrap().recovery_saved);
    assert!(h.profiles.with_current_store(&source, |_| ()).is_err());
    let account_id = profile.id;
    let local_lease = h.profiles.open_local().unwrap();
    assert_eq!(local_lease.store.get(local.id).unwrap(), Some(local));
    assert_eq!(h.begin().await.unwrap_err(), PasswordLoginError::ExistingProfile);
    assert!(h.root().pending_password_login().unwrap().is_none());
    assert_eq!(h.profiles.list().unwrap().len(), 1);
    assert_eq!(
        h.profiles.open(account_id, None).unwrap().account().unwrap().device_id,
        ready.device_id
    );
    h.f.peer.healthy();
}

#[tokio::test]
async fn wrong_password_is_common_denial_without_identity_or_retained_password() {
    let h = Harness::new().await;
    let source = h.profiles.current().unwrap();
    let result =
        h.f.server
            .begin_password_login(
                &h.profiles,
                &source,
                &h.f.peer.origin,
                "alice",
                "Second",
                SecretVec::new(b"incorrect account password".to_vec()),
                &RegistrationCancellation::default(),
            )
            .await;
    assert_eq!(result.unwrap_err(), PasswordLoginError::AuthenticationDenied);
    assert!(h.root().pending_password_login().unwrap().is_none());
    h.no_authority();
    assert_eq!(h.begin().await.unwrap().phase, PasswordLoginPhase::Ready);
    h.f.peer.healthy();
}

#[tokio::test]
async fn unknown_commit_survives_reopen_and_confirms_exact_original_with_fresh_proof() {
    let h = Harness::new().await;
    let ready = h.begin().await.unwrap();
    h.reference.lock().unwrap().submit_reply =
        Some(Reply::problem(503, "auth.commit_outcome_unknown", true, false));
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await.unwrap_err(),
        PasswordLoginError::OutcomeUnknown
    );
    let original = h.root().pending_password_login().unwrap().unwrap();
    let reopened =
        Arc::new(LocalData::start(h.dir.path(), Some(Box::new(h.keys.clone()))).unwrap());
    let catalog = catalog(reopened, &h.slots);
    let source = catalog.current().unwrap();
    assert_eq!(
        h.f.server.password_login_status(&catalog, &source).unwrap().unwrap().phase,
        PasswordLoginPhase::OutcomeUnknown
    );
    assert_eq!(
        h.f.server.cancel_password_login(&catalog, &source, ready.operation_id).unwrap_err(),
        PasswordLoginError::OutcomeUnknown
    );
    assert_eq!(
        h.f.server
            .exchange_password_login(
                &catalog,
                &source,
                ready.operation_id,
                RegistrationAction::Submit,
                &RegistrationCancellation::default()
            )
            .await
            .unwrap_err(),
        PasswordLoginError::OutcomeUnknown
    );
    let confirmed =
        h.f.server
            .exchange_password_login(
                &catalog,
                &source,
                ready.operation_id,
                RegistrationAction::Confirm,
                &RegistrationCancellation::default(),
            )
            .await
            .unwrap();
    assert_eq!(confirmed.phase, PasswordLoginPhase::Committed);
    let after = source.store.pending_password_login().unwrap().unwrap();
    assert_eq!(after.entry.payload, original.entry.payload);
    assert_eq!(after.entry.private_material, original.entry.private_material);
    assert_eq!(after.entry.account_signature, original.entry.account_signature);
    let r = h.reference.lock().unwrap();
    assert_eq!(r.requests.len(), 2);
    assert_ne!(r.requests[0].device_proof, r.requests[1].device_proof);
    assert!(r.requests[1].admission_token.is_none());
    assert_eq!(r.confirmations, 1);
    drop(r);
    h.no_authority();
    h.f.peer.healthy();
}

#[tokio::test]
async fn missing_receipt_and_current_device_revocation_do_not_grant_installation() {
    let h = Harness::new().await;
    let ready = h.begin().await.unwrap();
    {
        let mut r = h.reference.lock().unwrap();
        r.reject_commit = true;
        r.submit_reply = Some(Reply::problem(503, "auth.commit_outcome_unknown", true, false));
    }
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await.unwrap_err(),
        PasswordLoginError::OutcomeUnknown
    );
    assert_eq!(
        h.exchange(RegistrationAction::Confirm).await.unwrap_err(),
        PasswordLoginError::AuthenticationDenied
    );
    assert_eq!(
        h.f.server
            .password_login_status(&h.profiles, &h.profiles.current().unwrap())
            .unwrap()
            .unwrap()
            .phase,
        PasswordLoginPhase::OutcomeUnknown
    );
    assert_eq!(
        h.install(ready.operation_id).await.unwrap_err(),
        AccountProfileError::ConfirmationRequired
    );
    h.no_authority();
    h.f.peer.healthy();
}

#[tokio::test]
async fn historical_receipt_does_not_bypass_current_device_authentication() {
    let h = Harness::new().await;
    let ready = h.begin().await.unwrap();
    h.exchange(RegistrationAction::Submit).await.unwrap();
    h.reference.lock().unwrap().current.as_mut().unwrap().fault = Fault::Authentication;
    assert_eq!(
        h.install(ready.operation_id).await.unwrap_err(),
        AccountProfileError::Personal(PersonalServerError::Authentication)
    );
    assert_eq!(h.profiles.list().unwrap().len(), 1);
    assert!(!h.profiles.list().unwrap()[0].ready);
    assert!(h.root().pending_password_login().unwrap().is_some());
    h.no_authority();
    h.reference.lock().unwrap().current.as_mut().unwrap().fault = Fault::None;
    assert_eq!(
        h.install(ready.operation_id).await.unwrap().account().unwrap().device_id,
        ready.device_id
    );
    h.f.peer.healthy();
}

#[tokio::test]
async fn trusted_unchanged_submit_requires_explicit_retry_and_keeps_exact_payload() {
    let h = Harness::new().await;
    h.begin().await.unwrap();
    {
        let mut r = h.reference.lock().unwrap();
        r.reject_commit = true;
        r.submit_reply = Some(Reply::problem(503, "auth.storage_unavailable", false, true));
    }
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await.unwrap_err(),
        PasswordLoginError::ServiceUnavailable
    );
    assert_eq!(
        h.f.server
            .password_login_status(&h.profiles, &h.profiles.current().unwrap())
            .unwrap()
            .unwrap()
            .phase,
        PasswordLoginPhase::RetryAvailable
    );
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await.unwrap_err(),
        PasswordLoginError::ExplicitRetryRequired
    );
    {
        let mut r = h.reference.lock().unwrap();
        r.reject_commit = false;
        r.submit_reply = None;
    }
    assert_eq!(
        h.exchange(RegistrationAction::Retry).await.unwrap().phase,
        PasswordLoginPhase::Committed
    );
    let r = h.reference.lock().unwrap();
    assert_eq!(r.requests.len(), 2);
    assert_eq!(r.requests[0].payload, r.requests[1].payload);
    drop(r);
    h.f.peer.healthy();
}

#[tokio::test]
async fn changed_snapshot_or_expired_capability_requires_explicit_new_login() {
    let h = Harness::new().await;
    h.begin().await.unwrap();
    {
        let mut r = h.reference.lock().unwrap();
        r.reject_commit = true;
        r.submit_reply = Some(Reply::problem(409, "auth.admission_conflict", false, false));
    }
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await.unwrap_err(),
        PasswordLoginError::AdmissionConflict
    );
    let source = h.profiles.current().unwrap();
    let pending = h.f.server.password_login_status(&h.profiles, &source).unwrap().unwrap();
    assert_eq!(pending.phase, PasswordLoginPhase::SignInRequired);
    assert_eq!(
        h.exchange(RegistrationAction::Retry).await.unwrap_err(),
        PasswordLoginError::AdmissionConflict
    );
    h.f.server.cancel_password_login(&h.profiles, &source, pending.operation_id).unwrap();
    h.reference.lock().unwrap().capability_lifetime = 150;
    let second = h.begin().await.unwrap();
    assert_ne!(pending.device_id, second.device_id);
    assert_eq!(pending.account_id, second.account_id);
    tokio::time::sleep(Duration::from_millis(175)).await;
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await.unwrap_err(),
        PasswordLoginError::AdmissionConflict
    );
    h.no_authority();
    h.f.peer.healthy();
}

#[tokio::test]
async fn untrusted_tls_and_inexact_cache_or_duplicate_json_fail_before_identity() {
    let h = Harness::new().await;
    let source = h.profiles.current().unwrap();
    assert_eq!(
        PersonalServer::default()
            .begin_password_login(
                &h.profiles,
                &source,
                &h.f.peer.origin,
                "alice",
                "Second",
                SecretVec::new(b"a real account password".to_vec()),
                &RegistrationCancellation::default()
            )
            .await
            .unwrap_err(),
        PasswordLoginError::Network
    );
    let mut reply = Reply::json(200, b"{}".to_vec());
    reply.headers.push(("cache-control", "public".into()));
    h.reference.lock().unwrap().options_reply = Some(reply);
    assert_eq!(h.begin().await.unwrap_err(), PasswordLoginError::InvalidResponse);
    h.reference.lock().unwrap().options_reply = None;
    h.reference.lock().unwrap().login_reply =
        Some(Reply::json(200, b"{\"snapshot\":\"x\",\"snapshot\":\"y\"}".to_vec()));
    assert!(h.begin().await.is_err());
    assert!(h.root().pending_password_login().unwrap().is_none());
    h.no_authority();
    h.f.peer.healthy();
}

#[tokio::test]
async fn bootstrap_context_roots_epochs_and_rotation_are_verified_before_device_creation() {
    let h = Harness::new().await;
    let good = h.reference.lock().unwrap().snapshot.clone();
    for fault in 0..6 {
        let mut snapshot = good.clone();
        match fault {
            0 => snapshot.origin = "https://different.example".into(),
            1 => snapshot.password_ark[40] ^= 1,
            2 => snapshot.personal.epochs[0].wrapped_key[40] ^= 1,
            3 => snapshot.personal.rotation_pending = true,
            _ => {
                let private = h.f.store.pending_registration().unwrap().unwrap().private_material;
                let secrets = Secrets::parse(&private).unwrap();
                let signer = Ed25519SigningKey::from_bytes(secrets.account_signing()).unwrap();
                let mut bundle =
                    SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).unwrap();
                let artifact = if fault == 4 {
                    &mut bundle.account_signing_key
                } else {
                    &mut bundle.account_kem_key
                };
                *artifact.last_mut().unwrap() ^= 1;
                bundle.signature = signer.sign(&bundle.signature_input().unwrap()).to_vec();
                snapshot.key_bundle = bundle.to_cbor().unwrap();
            }
        }
        h.reference.lock().unwrap().snapshot = snapshot;
        assert!(h.begin().await.is_err(), "accepted bootstrap fault {fault}");
        assert!(h.root().pending_password_login().unwrap().is_none());
        h.no_authority();
    }
    h.reference.lock().unwrap().snapshot = good;
    assert_eq!(h.begin().await.unwrap().phase, PasswordLoginPhase::Ready);
    h.f.peer.healthy();
}

#[tokio::test]
async fn cancelled_and_replaced_profiles_fence_network_and_prepared_result() {
    let h = Harness::new().await;
    let source = h.profiles.current().unwrap();
    let cancel = RegistrationCancellation::default();
    let (reached, release) = h.f.peer.pause("/api/v1/auth/accounts/password/login");
    let pending = h.f.server.begin_password_login(
        &h.profiles,
        &source,
        &h.f.peer.origin,
        "alice",
        "Second",
        SecretVec::new(b"a real account password".to_vec()),
        &cancel,
    );
    tokio::pin!(pending);
    tokio::select! {r=&mut pending=>panic!("completed before pause: {r:?}"),_=reached.notified()=>{}}
    assert_eq!(h.begin().await.unwrap_err(), PasswordLoginError::Busy);
    cancel.cancel();
    assert_eq!(pending.await.unwrap_err(), PasswordLoginError::Cancelled);
    release.notify_one();
    assert!(h.root().pending_password_login().unwrap().is_none());
    h.no_authority();
    let new_source = h.profiles.open_local().unwrap();
    assert_ne!(source.generation(), new_source.generation());
    assert_eq!(
        h.f.server.password_login_status(&h.profiles, &source).unwrap_err(),
        PasswordLoginError::ContextChanged
    );
    h.f.peer.healthy();
}

#[tokio::test]
async fn submit_cancellation_retains_unknown_and_database_failure_never_dispatches() {
    let h = Harness::new().await;
    let ready = h.begin().await.unwrap();
    let source = h.profiles.current().unwrap();
    let db = h.database();
    db.execute_batch("CREATE TRIGGER reject_login_dispatch BEFORE UPDATE ON personal_password_login WHEN NEW.phase=1 BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await.unwrap_err(),
        PasswordLoginError::Storage
    );
    assert!(h.reference.lock().unwrap().requests.is_empty());
    assert_eq!(h.root().pending_password_login().unwrap().unwrap().entry.phase, 0);
    db.execute_batch("DROP TRIGGER reject_login_dispatch;").unwrap();
    let (reached, release) = h.f.peer.pause("/api/v1/auth/accounts/device-admissions");
    let cancel = RegistrationCancellation::default();
    let exchange = h.f.server.exchange_password_login(
        &h.profiles,
        &source,
        ready.operation_id,
        RegistrationAction::Submit,
        &cancel,
    );
    tokio::pin!(exchange);
    tokio::select! {r=&mut exchange=>panic!("completed before pause: {r:?}"),_=reached.notified()=>{}}
    cancel.cancel();
    assert_eq!(exchange.await.unwrap_err(), PasswordLoginError::Cancelled);
    release.notify_one();
    h.f.peer.registration_reply(None, false);
    assert_eq!(h.root().pending_password_login().unwrap().unwrap().entry.phase, 1);
    assert_eq!(
        h.exchange(RegistrationAction::Confirm).await.unwrap().phase,
        PasswordLoginPhase::Committed
    );
    h.f.peer.healthy();
}

#[tokio::test]
async fn installation_rejects_bad_current_k4_and_catalog_failure_retries_original_identity() {
    let h = Harness::new().await;
    let ready = h.begin().await.unwrap();
    h.exchange(RegistrationAction::Submit).await.unwrap();
    h.reference.lock().unwrap().current.as_mut().unwrap().fault = Fault::VaultWrap;
    assert!(h.install(ready.operation_id).await.is_err());
    assert!(h.root().pending_password_login().unwrap().is_some());
    h.no_authority();
    h.reference.lock().unwrap().current.as_mut().unwrap().fault = Fault::None;
    let db = h.database();
    db.execute_batch("CREATE TRIGGER reject_login_selection BEFORE UPDATE ON profile_selection BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(h.install(ready.operation_id).await.is_err());
    let profile = h.profiles.list().unwrap()[0].clone();
    assert!(!profile.ready);
    db.execute_batch("DROP TRIGGER reject_login_selection;").unwrap();
    let installed = h.install(ready.operation_id).await.unwrap();
    assert_eq!(installed.account().unwrap().id, profile.id);
    assert_eq!(installed.store.device_id(), ready.device_id);
    h.f.peer.healthy();
}
