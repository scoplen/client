// SPDX-License-Identifier: Apache-2.0
//! Public client facade over independent TLS 1.3/H2 and real encrypted Account stores.

use super::*;
use crate::{
    personal_server::{
        PersonalSyncRuntime, RegistrationAction,
        registration::{
            http::tests::{Fixture, Reply},
            install::tests::CurrentPeer,
        },
    },
    testing::MemoryKeystore,
};
use scoplen_api::account_admission::{
    AccountPasswordChangeRequest, AccountPersonalBootstrap, AccountPersonalEpoch,
    AccountRequestChallengeRequest, AccountRequestChallengeResponse,
};
use scoplen_crypto::{AccountRequestIntent, PasswordVerifier, SecretBytes};
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
};

const OLD: &[u8] = b"a real account password";
const NEW: &[u8] = b"a different account password";

struct Reference {
    snapshot: AccountBootstrapSnapshot,
    verifier: [u8; 32],
    options: Vec<AccountPasswordOptionsResponse>,
    challenges: Vec<(AccountRequestChallengeRequest, AccountRequestChallengeResponse)>,
    requests: Vec<AccountPasswordChangeRequest>,
    receipt: Option<AccountPasswordChangeConfirmation>,
    current: CurrentPeer,
    submit_reply: Option<Reply>,
    confirm_reply: Option<Reply>,
    login_reply: Option<Reply>,
    options_reply: Option<Reply>,
    reject_commit: bool,
    capability_lifetime: u64,
    proofs: HashSet<[u8; 64]>,
}
impl Reference {
    fn new(p: AccountRegistrationPayload) -> Self {
        Self {
            snapshot: AccountBootstrapSnapshot {
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
            },
            verifier: p.verifier,
            current: CurrentPeer::admitted(p),
            options: vec![],
            challenges: vec![],
            requests: vec![],
            receipt: None,
            submit_reply: None,
            confirm_reply: None,
            login_reply: None,
            options_reply: None,
            reject_commit: false,
            capability_lifetime: 300_000,
            proofs: HashSet::new(),
        }
    }
    fn answer(
        &mut self,
        request: &::http::request::Parts,
        body: &[u8],
        origin: &str,
    ) -> Result<Reply, String> {
        match AccountEntryOperation::from_route(request.method.as_str(), request.uri.path()) {
            Some(AccountEntryOperation::PasswordOptions) => {
                let p =
                    AccountPasswordOptionsRequest::from_json(body).map_err(|_| "options codec")?;
                if p.username != "alice" {
                    return Err("wrong username".into());
                }
                let mut id = [0; 32];
                scoplen_crypto::random_bytes(&mut id).unwrap();
                let options = AccountPasswordOptionsResponse {
                    attempt_id: SecretBytes::new(id),
                    salt: self.snapshot.password_salt,
                    expires_at_ms: now_ms().unwrap() + 120_000,
                };
                let reply = self
                    .options_reply
                    .clone()
                    .unwrap_or_else(|| Reply::json(200, options.to_json().unwrap()));
                self.options.push(options);
                Ok(reply)
            }
            Some(AccountEntryOperation::PasswordLogin) => {
                let p = AccountPasswordLoginRequest::from_json(body).map_err(|_| "login codec")?;
                let options = self.options.pop().ok_or("missing options")?;
                if p.attempt_id != options.attempt_id {
                    return Err("wrong attempt".into());
                }
                if PasswordVerifier::from_bytes(&self.verifier)
                    .unwrap()
                    .verify(SecretVec::new(p.auth_secret.as_ref().to_vec()))
                    .is_err()
                {
                    return Ok(Reply::problem(401, "auth.authentication_required", false, false));
                }
                Ok(self.login_reply.clone().unwrap_or_else(|| {
                    Reply::json(
                        200,
                        AccountPasswordLoginResponse {
                            snapshot: SecretVec::new(self.snapshot.to_cbor().unwrap()),
                            admission_token: SecretBytes::new([47; 32]),
                            expires_at_ms: now_ms().unwrap() + self.capability_lifetime,
                        }
                        .to_json()
                        .unwrap(),
                    )
                }))
            }
            Some(AccountEntryOperation::RequestChallenge) => {
                let p = AccountRequestChallengeRequest::from_json(body)
                    .map_err(|_| "challenge codec")?;
                if p.kind != AccountRequestKind::PasswordChange {
                    return Err("wrong ceremony".into());
                }
                let mut id = [0; 32];
                let mut nonce = [0; 32];
                scoplen_crypto::random_bytes(&mut id).unwrap();
                scoplen_crypto::random_bytes(&mut nonce).unwrap();
                let c = AccountRequestChallengeResponse {
                    attempt_id: SecretBytes::new(id),
                    nonce: SecretBytes::new(nonce),
                    expires_at_ms: now_ms().unwrap() + 120_000,
                };
                let reply = Reply::json(200, c.to_json().unwrap());
                self.challenges.push((p, c));
                Ok(reply)
            }
            Some(AccountEntryOperation::PasswordChange) => {
                let r =
                    AccountPasswordChangeRequest::from_json(body).map_err(|_| "change codec")?;
                let p = AccountPasswordChangePayload::from_cbor(r.payload.as_bytes())
                    .map_err(|_| "payload codec")?;
                let cert = DeviceCertificate::decode(&self.snapshot.certificates[0]).unwrap();
                let digest = r
                    .verify_proof(
                        origin,
                        &self.snapshot.account_signing_public_key,
                        &cert.signing_public_key,
                    )
                    .map_err(|_| "proof binding")?;
                let (asked, c) = self.challenges.last().ok_or("no challenge")?;
                if asked.intent != r.intent
                    || asked.operation_id != p.operation_id
                    || asked.device_id != p.device_id
                    || c.attempt_id != r.attempt_id
                    || c.nonce != r.nonce
                    || !self.proofs.insert(r.device_proof)
                {
                    return Err("stale proof".into());
                }
                let reply = if r.intent == AccountRequestIntent::Submit {
                    p.validate_for_snapshot(
                        &self.snapshot,
                        &self.snapshot.to_cbor().unwrap(),
                        r.admission_token.as_ref().ok_or("no capability")?.as_bytes(),
                    )
                    .map_err(|_| "snapshot binding")?;
                    if !self.reject_commit {
                        self.receipt = Some(AccountPasswordChangeConfirmation {
                            operation_id: p.operation_id,
                            request_digest: digest,
                            account_id: p.account_id,
                            personal_vault_id: p.personal_vault_id,
                            device_id: p.device_id,
                            credential_generation: p.new_credential_generation,
                        });
                        self.snapshot.credential_generation = p.new_credential_generation;
                        self.snapshot.password_salt = p.password_salt;
                        self.snapshot.password_ark = p.password_ark;
                        self.verifier = p.verifier;
                    }
                    self.submit_reply.clone().unwrap_or_else(|| {
                        Reply::json(201, self.receipt.as_ref().unwrap().to_json().unwrap())
                    })
                } else {
                    if r.admission_token.is_some() {
                        return Err("capability on confirm".into());
                    }
                    self.confirm_reply.clone().unwrap_or_else(|| match &self.receipt {
                        Some(c) => Reply::json(200, c.to_json().unwrap()),
                        None => Reply::problem(401, "auth.authentication_required", false, false),
                    })
                };
                self.requests.push(r);
                Ok(reply)
            }
            None => self.current.answer(request, body, origin),
            _ => Err("unsupported test route".into()),
        }
    }
}
type Slots = Arc<Mutex<BTreeMap<PathBuf, MemoryKeystore>>>;
struct Harness {
    profiles: AccountProfiles,
    slots: Slots,
    reference: Arc<Mutex<Reference>>,
    f: Fixture,
}
fn catalog(f: &Fixture, slots: &Slots) -> AccountProfiles {
    let slots = slots.clone();
    AccountProfiles::with_keystores(
        f.local.clone(),
        Arc::new(PersonalSyncRuntime::default()),
        Arc::new(move |path| {
            Some(Box::new(slots.lock().unwrap().entry(path.to_path_buf()).or_default().clone()))
        }),
    )
    .unwrap()
}
impl Harness {
    async fn new() -> Self {
        let f = Fixture::new().await;
        f.exchange(RegistrationAction::Submit).await.unwrap();
        let reference = Arc::new(Mutex::new(Reference::new(f.peer.payload())));
        let handler = reference.clone();
        f.peer.extra(Box::new(move |r, b, o| handler.lock().unwrap().answer(r, b, o)));
        let slots = Slots::default();
        let profiles = catalog(&f, &slots);
        f.server
            .install_registration_profile(
                &profiles,
                &profiles.current().unwrap(),
                f.status.operation_id,
                None,
                &RegistrationCancellation::default(),
            )
            .await
            .unwrap();
        Self { profiles, slots, reference, f }
    }
    fn source(&self) -> ProfileLease {
        self.profiles.current().unwrap()
    }
    async fn begin(&self) -> Result<PasswordChangeStatus, PasswordChangeError> {
        self.begin_with(OLD, NEW).await
    }
    async fn begin_with(
        &self,
        old: &[u8],
        new: &[u8],
    ) -> Result<PasswordChangeStatus, PasswordChangeError> {
        self.f
            .server
            .begin_password_change(
                &self.profiles,
                &self.source(),
                SecretVec::new(old.to_vec()),
                SecretVec::new(new.to_vec()),
                &RegistrationCancellation::default(),
            )
            .await
    }
    fn status(&self) -> PasswordChangeStatus {
        self.f.server.password_change_status(&self.profiles, &self.source()).unwrap().unwrap()
    }
    async fn exchange(
        &self,
        action: RegistrationAction,
    ) -> Result<PasswordChangeStatus, PasswordChangeError> {
        self.f
            .server
            .exchange_password_change(
                &self.profiles,
                &self.source(),
                self.status().operation_id,
                action,
                &RegistrationCancellation::default(),
            )
            .await
    }
    fn database(&self) -> rusqlite::Connection {
        let id = self.source().account().unwrap().id;
        let path = self.f.dir.path().join("accounts").join(id.to_string());
        let slot = self.slots.lock().unwrap().get(&path).unwrap().clone();
        let conn = rusqlite::Connection::open(path.join("local.db")).unwrap();
        let keys = slot.0.lock().unwrap();
        let hex = zeroize::Zeroizing::new(
            keys.as_ref().unwrap()[1..].iter().map(|b| format!("{b:02x}")).collect::<String>(),
        );
        let pragma = zeroize::Zeroizing::new(format!("x'{}'", hex.as_str()));
        conn.pragma_update(None, "key", pragma.as_str()).unwrap();
        conn
    }
}

#[tokio::test]
async fn same_normalized_password_has_zero_network_or_kdf_work() {
    let h = Harness::new().await;
    let before = h.f.peer.paths();
    let _derivation = PASSWORD_DERIVATION.try_acquire().unwrap();
    assert_eq!(
        h.begin_with("a long cafe\u{301} password".as_bytes(), "a long café password".as_bytes())
            .await,
        Err(PasswordChangeError::SamePassword)
    );
    assert_eq!(h.f.peer.paths(), before);
    assert!(h.source().store.pending_password_change().unwrap().is_none());
    h.f.peer.healthy();
}

#[tokio::test]
async fn installed_device_changes_only_credentials_and_old_password_stops_working() {
    let h = Harness::new().await;
    let source = h.source();
    let identity = source.store.personal_record().unwrap().unwrap();
    let binding = source.store.account_profile_binding().unwrap().unwrap();
    let previous = source.store.personal_sync_record().unwrap().unwrap();
    let before = h.reference.lock().unwrap().snapshot.clone();
    let ready = h.begin().await.unwrap();
    assert_eq!(ready.phase, PasswordChangePhase::Ready);
    let pending = source.store.pending_password_change().unwrap().unwrap();
    let payload = AccountPasswordChangePayload::from_cbor(pending.payload.as_bytes()).unwrap();
    assert_eq!(payload.device_id, source.store.device_id());
    assert_ne!(payload.password_salt, before.password_salt);
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await.unwrap().phase,
        PasswordChangePhase::Committed
    );
    let after = source.store.personal_record().unwrap().unwrap();
    assert_eq!(identity.private_material, after.private_material);
    assert_eq!(identity.auth_generation, after.auth_generation);
    let provenance = source.store.account_profile_binding().unwrap().unwrap();
    assert_eq!(binding.payload, provenance.payload);
    assert_eq!(binding.signature, provenance.signature);
    assert_eq!(binding.confirmation, provenance.confirmation);
    let sync = source.store.personal_sync_record().unwrap().unwrap();
    assert_eq!(previous.session, sync.session);
    assert_eq!(previous.account_keys, sync.account_keys);
    assert_eq!(previous.vault_keys, sync.vault_keys);
    assert_eq!(source.store.credential_generation_floor().unwrap(), Some(2));
    assert!(source.store.pending_password_change().unwrap().unwrap().token.is_none());
    let current = h.reference.lock().unwrap().snapshot.clone();
    assert_eq!(current.key_bundle, before.key_bundle);
    assert_eq!(current.certificates, before.certificates);
    assert_eq!(current.personal.epochs, before.personal.epochs);
    h.f.server.discard_password_change(&h.profiles, &source, ready.operation_id).unwrap();
    assert_eq!(h.begin().await, Err(PasswordChangeError::AuthenticationDenied));
    assert_eq!(
        h.begin_with(NEW, b"another valid new account password").await.unwrap().phase,
        PasswordChangePhase::Ready
    );
    h.f.peer.healthy();
}

#[tokio::test]
async fn unknown_reopens_and_confirm_denial_never_authorizes_retry_or_discard() {
    let h = Harness::new().await;
    let operation_id = h.begin().await.unwrap().operation_id;
    h.reference.lock().unwrap().submit_reply =
        Some(Reply::problem(503, "auth.commit_outcome_unknown", true, false));
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await,
        Err(PasswordChangeError::OutcomeUnknown)
    );
    let before = h.source().store.pending_password_change().unwrap().unwrap();
    let profile = h.source().account().unwrap().clone();
    let reopened = catalog(&h.f, &h.slots);
    reopened.open(profile.id, None).unwrap();
    let source = reopened.current().unwrap();
    assert_eq!(
        h.f.server.password_change_status(&reopened, &source).unwrap().unwrap().phase,
        PasswordChangePhase::OutcomeUnknown
    );
    h.reference.lock().unwrap().confirm_reply =
        Some(Reply::problem(401, "auth.authentication_required", false, false));
    assert_eq!(
        h.f.server
            .exchange_password_change(
                &reopened,
                &source,
                operation_id,
                RegistrationAction::Confirm,
                &RegistrationCancellation::default()
            )
            .await,
        Err(PasswordChangeError::AuthenticationDenied)
    );
    let after = source.store.pending_password_change().unwrap().unwrap();
    assert_eq!(before, after);
    assert_eq!(
        h.f.server.discard_password_change(&reopened, &source, operation_id),
        Err(PasswordChangeError::OutcomeUnknown)
    );
    assert_eq!(
        h.f.server
            .exchange_password_change(
                &reopened,
                &source,
                operation_id,
                RegistrationAction::Retry,
                &RegistrationCancellation::default()
            )
            .await,
        Err(PasswordChangeError::RetryUnavailable)
    );
    h.reference.lock().unwrap().confirm_reply = None;
    source.store.observe_credential_generation(u64::MAX).unwrap();
    let identity = source.store.personal_record().unwrap().unwrap();
    assert_eq!(
        h.f.server
            .exchange_password_change(
                &reopened,
                &source,
                operation_id,
                RegistrationAction::Confirm,
                &RegistrationCancellation::default()
            )
            .await
            .unwrap()
            .phase,
        PasswordChangePhase::Committed
    );
    assert_eq!(source.store.credential_generation_floor().unwrap(), Some(u64::MAX));
    assert_eq!(
        source.store.personal_record().unwrap().unwrap().auth_generation,
        identity.auth_generation
    );
    let reference = h.reference.lock().unwrap();
    assert_eq!(reference.requests[0].payload, reference.requests[2].payload);
    assert_eq!(reference.requests[0].account_signature, reference.requests[2].account_signature);
    assert!(reference.requests[1].admission_token.is_none());
    assert!(reference.requests[2].admission_token.is_none());
    h.f.peer.healthy();
}

#[tokio::test]
async fn late_historical_receipt_cannot_replace_second_change_or_lower_its_generation() {
    let h = Harness::new().await;
    let original = h.begin().await.unwrap();
    h.exchange(RegistrationAction::Submit).await.unwrap();
    let source = h.source();
    let (reached, release) = h.f.peer.pause("/api/v1/auth/accounts/password-changes");
    let cancellation = RegistrationCancellation::default();
    let checking = h.f.peer.manager(std::time::Duration::from_secs(120));
    let confirm = checking.exchange_password_change(
        &h.profiles,
        &source,
        original.operation_id,
        RegistrationAction::Confirm,
        &cancellation,
    );
    tokio::pin!(confirm);
    tokio::select! {result=&mut confirm=>panic!("unexpected completion {result:?}"),()=reached.notified()=>{}}
    h.f.peer.clear_pause();
    let other = h.f.peer.manager(std::time::Duration::from_secs(2));
    other.discard_password_change(&h.profiles, &source, original.operation_id).unwrap();
    let second = other
        .begin_password_change(
            &h.profiles,
            &source,
            SecretVec::new(NEW.to_vec()),
            SecretVec::new(b"a third independent account password".to_vec()),
            &RegistrationCancellation::default(),
        )
        .await
        .unwrap();
    other
        .exchange_password_change(
            &h.profiles,
            &source,
            second.operation_id,
            RegistrationAction::Submit,
            &RegistrationCancellation::default(),
        )
        .await
        .unwrap();
    let pending = source.store.pending_password_change().unwrap().unwrap();
    assert_eq!(source.store.credential_generation_floor().unwrap(), Some(3));
    release.notify_one();
    assert_eq!(confirm.await, Err(PasswordChangeError::ContextChanged));
    assert_eq!(source.store.pending_password_change().unwrap().unwrap(), pending);
    assert_eq!(source.store.credential_generation_floor().unwrap(), Some(3));
    h.f.peer.healthy();
}

#[tokio::test]
async fn unchanged_requires_explicit_fresh_proof_retry_and_conflict_requires_new_login() {
    let h = Harness::new().await;
    h.begin().await.unwrap();
    {
        let mut peer = h.reference.lock().unwrap();
        peer.reject_commit = true;
        peer.submit_reply = Some(Reply::problem(503, "auth.storage_unavailable", false, true));
    }
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await,
        Err(PasswordChangeError::ServiceUnavailable)
    );
    assert_eq!(h.status().phase, PasswordChangePhase::RetryAvailable);
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await,
        Err(PasswordChangeError::ExplicitRetryRequired)
    );
    {
        let mut peer = h.reference.lock().unwrap();
        peer.submit_reply = Some(Reply::problem(409, "auth.admission_conflict", false, false));
    }
    assert_eq!(
        h.exchange(RegistrationAction::Retry).await,
        Err(PasswordChangeError::SignInRequired)
    );
    assert_eq!(h.status().phase, PasswordChangePhase::SignInRequired);
    let original = h.source().store.pending_password_change().unwrap().unwrap();
    assert_eq!(original.dispatch_generation, 2);
    assert_eq!(original.unchanged_generation, 2);
    h.f.server.discard_password_change(&h.profiles, &h.source(), h.status().operation_id).unwrap();
    assert!(h.source().store.pending_password_change().unwrap().is_none());
    h.f.peer.healthy();
}

#[tokio::test]
async fn malformed_transport_and_write_failure_keep_correct_handoff_boundary() {
    let h = Harness::new().await;
    h.reference.lock().unwrap().options_reply = Some(Reply::json(200, b"{}".to_vec()));
    assert_eq!(h.begin().await, Err(PasswordChangeError::Verification));
    assert!(h.source().store.pending_password_change().unwrap().is_none());
    h.reference.lock().unwrap().options_reply = None;
    h.begin().await.unwrap();
    h.database().execute_batch("CREATE TRIGGER fail_password_dispatch BEFORE UPDATE ON personal_password_change WHEN NEW.phase=1 BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert_eq!(h.exchange(RegistrationAction::Submit).await, Err(PasswordChangeError::Storage));
    assert_eq!(h.status().phase, PasswordChangePhase::Ready);
    assert!(h.reference.lock().unwrap().requests.is_empty());
    h.database().execute_batch("DROP TRIGGER fail_password_dispatch;").unwrap();
    let mut reply = Reply::json(201, b"{}".to_vec());
    reply.headers.push(("set-cookie", "private=do-not-render".into()));
    h.reference.lock().unwrap().submit_reply = Some(reply);
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await,
        Err(PasswordChangeError::Verification)
    );
    assert_eq!(h.status().phase, PasswordChangePhase::OutcomeUnknown);
    h.f.peer.healthy();
}

#[tokio::test]
async fn pending_and_generation_floor_cannot_be_replaced_or_lowered() {
    let h = Harness::new().await;
    h.begin().await.unwrap();
    let db = h.database();
    assert!(db.execute("UPDATE personal_password_change SET payload=x'01'", []).is_err());
    assert!(
        db.execute("UPDATE personal_password_change SET account_signature=zeroblob(64)", [])
            .is_err()
    );
    assert!(db.execute("UPDATE personal_password_change SET certificate=x'01'", []).is_err());
    h.source().store.observe_credential_generation(u64::MAX).unwrap();
    assert!(
        db.execute("UPDATE account_credential_floor SET generation=x'0000000000000001'", [])
            .is_err()
    );
    assert!(db.execute("DELETE FROM account_credential_floor", []).is_err());
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await,
        Err(PasswordChangeError::SignInRequired)
    );
    h.f.server.discard_password_change(&h.profiles, &h.source(), h.status().operation_id).unwrap();
    assert_eq!(h.begin().await, Err(PasswordChangeError::Verification));
    assert_eq!(h.source().store.credential_generation_floor().unwrap(), Some(u64::MAX));
    h.f.peer.healthy();
}

#[tokio::test]
async fn cancellation_after_dispatch_and_profile_switch_preserve_original_unknown() {
    let h = Harness::new().await;
    let ready = h.begin().await.unwrap();
    let source = h.source();
    let (reached, release) = h.f.peer.pause("/api/v1/auth/accounts/password-changes");
    let cancel = RegistrationCancellation::default();
    let operation = h.f.server.exchange_password_change(
        &h.profiles,
        &source,
        ready.operation_id,
        RegistrationAction::Submit,
        &cancel,
    );
    tokio::pin!(operation);
    tokio::select! {result=&mut operation=>panic!("unexpected completion {result:?}"),()=reached.notified()=>{}}
    cancel.cancel();
    assert_eq!(operation.await, Err(PasswordChangeError::Cancelled));
    h.f.peer.clear_pause();
    release.notify_one();
    assert_eq!(h.status().phase, PasswordChangePhase::OutcomeUnknown);
    let id = source.account().unwrap().id;
    h.profiles.open_local().unwrap();
    assert_eq!(
        h.f.server.password_change_status(&h.profiles, &source),
        Err(PasswordChangeError::ContextChanged)
    );
    assert_eq!(
        h.f.server.password_change_status(&h.profiles, &h.source()),
        Err(PasswordChangeError::ContextChanged)
    );
    h.profiles.open(id, None).unwrap();
    assert_eq!(h.status().phase, PasswordChangePhase::OutcomeUnknown);
    assert_eq!(
        h.exchange(RegistrationAction::Confirm).await.unwrap().phase,
        PasswordChangePhase::Committed
    );
    h.f.peer.healthy();
}

#[tokio::test]
async fn expired_unknown_retains_exact_confirmation_without_native_session_or_current_device_authority()
 {
    let h = Harness::new().await;
    h.reference.lock().unwrap().capability_lifetime = 10_000;
    let ready = h.begin().await.unwrap();
    assert_eq!(ready.phase, PasswordChangePhase::Ready);
    h.reference.lock().unwrap().submit_reply =
        Some(Reply::problem(503, "auth.commit_outcome_unknown", true, false));
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await,
        Err(PasswordChangeError::OutcomeUnknown)
    );
    let source = h.source();
    let expiry = source.store.pending_password_change().unwrap().unwrap().expires_at_ms;
    source.store.clear_personal_tokens().unwrap();
    h.reference.lock().unwrap().current.fault =
        crate::personal_server::registration::install::tests::Fault::Authentication;
    assert!(h.f.server.authenticate(source.store.clone()).await.is_err());
    tokio::time::sleep(std::time::Duration::from_millis(
        expiry.saturating_sub(now_ms().unwrap()) + 10,
    ))
    .await;
    let profile = source.account().unwrap().id;
    h.profiles.open_local().unwrap();
    h.profiles.open(profile, None).unwrap();
    assert_eq!(h.status().phase, PasswordChangePhase::OutcomeUnknown);
    assert!(h.source().store.pending_password_change().unwrap().unwrap().token.is_none());
    assert_eq!(
        h.exchange(RegistrationAction::Retry).await,
        Err(PasswordChangeError::RetryUnavailable)
    );
    assert_eq!(
        h.exchange(RegistrationAction::Submit).await,
        Err(PasswordChangeError::OutcomeUnknown)
    );
    assert_eq!(
        h.exchange(RegistrationAction::Confirm).await.unwrap().phase,
        PasswordChangePhase::Committed
    );
    assert!(h.source().store.personal_access_token(0).unwrap().is_none());
    h.f.peer.healthy();
}

#[tokio::test]
async fn bootstrap_owner_generation_password_wrapper_and_personal_epochs_fail_closed() {
    let h = Harness::new().await;
    let good = h.reference.lock().unwrap().snapshot.clone();
    for fault in 0..6 {
        let mut snapshot = good.clone();
        match fault {
            0 => snapshot.origin = "https://different.example".into(),
            1 => snapshot.username = "another-user".into(),
            2 => snapshot.credential_generation = u64::MAX,
            3 => snapshot.password_ark[40] ^= 1,
            4 => snapshot.personal.epochs[0].wrapped_key[40] ^= 1,
            _ => snapshot.personal.rotation_pending = true,
        }
        h.reference.lock().unwrap().snapshot = snapshot;
        assert_eq!(h.begin().await, Err(PasswordChangeError::Verification));
        assert!(h.source().store.pending_password_change().unwrap().is_none());
        assert!(h.source().store.credential_generation_floor().unwrap().is_none());
    }
    h.reference.lock().unwrap().snapshot = good;
    h.f.peer.healthy();
}
