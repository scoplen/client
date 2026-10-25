// SPDX-License-Identifier: Apache-2.0
//! Public installation over an independent TLS 1.3/H2 shared-contract peer.

use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
    sync::Mutex as StdMutex,
    time::Duration,
};

use scoplen_api::{
    auth::{
        AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthJwk, AuthJwks,
        AuthTokenResponse,
    },
    sync::{
        SessionVault, SyncAccountKeyBundle, SyncLimits, SyncSessionRequest, SyncSessionResponse,
        SyncVaultKey, SyncVaultKeysResponse, VaultKind,
    },
};
use scoplen_client_platform::keystore::Keystore;
use scoplen_crypto::{
    DeviceAccessToken, DeviceAccessTokenClaims, DeviceAuthContext, DpopProof, DpopTarget,
    DpopToken, Ed25519SigningKey, LocalDatabaseKey, TrustedDeviceAccessTokenKeys,
    dpop_jwk_thumbprint, p256_verify,
};
use scoplen_model::{FieldPath, ObjectType, cbor::Value};

use super::super::http::tests::{Fixture, Peer, Reply};
use super::*;
use crate::{
    personal_server::{PersonalServerPhase, PersonalSyncRuntime, now},
    store::{LocalWrite, NewObject, StoreError},
    testing::MemoryKeystore,
};

type Slots = Arc<StdMutex<BTreeMap<PathBuf, MemoryKeystore>>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    None,
    Authentication,
    TokenSignature,
    TokenAccount,
    MalformedSession,
    WrongVault,
    Rotation,
    Epoch,
    DeviceWrap,
    AccountSigningWrap,
    AccountKemWrap,
    RecoveryWrap,
    Certificate,
    MissingCertificate,
    VaultWrap,
}

struct CurrentPeer {
    payload: AccountRegistrationPayload,
    fault: Fault,
    revision: u64,
    challenges: u64,
    nonce: String,
    token: String,
    proofs: HashSet<String>,
    revocations: Vec<Vec<u8>>,
}

impl CurrentPeer {
    fn attach(peer: &Peer) -> Arc<StdMutex<Self>> {
        let state = Arc::new(StdMutex::new(Self {
            payload: peer.payload(),
            fault: Fault::None,
            revision: 1,
            challenges: 0,
            nonce: String::new(),
            token: String::new(),
            proofs: HashSet::new(),
            revocations: vec![],
        }));
        let shared = state.clone();
        peer.extra(Box::new(move |request, body, origin| {
            shared.lock().unwrap().answer(request, body, origin)
        }));
        state
    }

    fn answer(
        &mut self,
        request: &::http::request::Parts,
        body: &[u8],
        origin: &str,
    ) -> Result<Reply, String> {
        let path = request.uri.path();
        let header = |name: &str| request.headers.get(name).and_then(|value| value.to_str().ok());
        if origin != self.payload.origin
            || header("accept-encoding") != Some("identity")
            || ["cookie", "idempotency-key", "if-match"]
                .iter()
                .any(|name| request.headers.contains_key(*name))
        {
            return Err("unexpected current-device metadata".into());
        }
        let certificate = DeviceCertificate::decode(&self.payload.device_certificate).unwrap();
        let signing = Ed25519SigningKey::from_bytes(&[55; 32]).unwrap();
        if !path.starts_with("/sync/") {
            if header("authorization").is_some()
                || header("dpop").is_some()
                || header("accept") != Some("application/json")
            {
                return Err("credentials leaked to authentication metadata".into());
            }
            match path {
                "/api/v1/auth/challenge" => {
                    if request.method != ::http::Method::POST
                        || header("content-type") != Some("application/json")
                    {
                        return Err("wrong challenge method or type".into());
                    }
                    let request = AuthChallengeRequest::from_json(
                        std::str::from_utf8(body).map_err(|_| "challenge UTF-8")?,
                    )
                    .map_err(|_| "challenge codec")?;
                    if request.device_id != self.payload.device_id {
                        return Err("wrong authentication Device".into());
                    }
                    self.challenges += 1;
                    self.nonce = format!("{:064x}", self.challenges);
                    return Ok(Reply::json(
                        200,
                        AuthChallengeResponse::new(self.nonce.clone(), "2026-10-25T00:00:00Z")
                            .unwrap()
                            .to_json()
                            .unwrap()
                            .into_bytes(),
                    ));
                }
                "/api/v1/auth/device" => {
                    if request.method != ::http::Method::POST
                        || header("content-type") != Some("application/json")
                    {
                        return Err("wrong authentication method or type".into());
                    }
                    let request = AuthDeviceRequest::from_json(
                        std::str::from_utf8(body).map_err(|_| "auth UTF-8")?,
                    )
                    .map_err(|_| "auth codec")?;
                    if request.device_id != self.payload.device_id || request.nonce != self.nonce {
                        return Err("wrong authentication challenge".into());
                    }
                    let signature = (0..request.signature.len())
                        .step_by(2)
                        .map(|index| {
                            u8::from_str_radix(&request.signature[index..index + 2], 16)
                                .map_err(|_| "signature hex")
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    p256_verify(
                        &certificate.signing_public_key,
                        &DeviceAuthContext::new(origin, &request.nonce, request.device_id)
                            .unwrap()
                            .signature_input(),
                        &signature,
                    )
                    .map_err(|_| "authentication signature")?;
                    if self.fault == Fault::Authentication {
                        return Ok(Reply::problem(
                            401,
                            "auth.authentication_required",
                            false,
                            false,
                        ));
                    }
                    let mut trusted = TrustedDeviceAccessTokenKeys::new(origin).unwrap();
                    trusted.insert("fixture", &signing.public_key()).unwrap();
                    let issued = now().unwrap();
                    let claims = DeviceAccessTokenClaims {
                        iss: origin.into(),
                        sub: if self.fault == Fault::TokenAccount {
                            scoplen_model::new_uuid_v7().unwrap()
                        } else {
                            self.payload.account_id
                        },
                        did: self.payload.device_id,
                        jti: scoplen_model::new_uuid_v7().unwrap(),
                        cnf_jkt: dpop_jwk_thumbprint(&certificate.signing_public_key).unwrap(),
                        org: vec![],
                        scope: scoplen_api::auth::INITIAL_DEVICE_ACCESS_SCOPE.into(),
                        iat: issued,
                        exp: issued + 600,
                    };
                    self.token = DeviceAccessToken::sign(
                        &signing,
                        &trusted,
                        "fixture",
                        &certificate.signing_public_key,
                        &claims,
                    )
                    .unwrap()
                    .as_str()
                    .to_owned();
                    if self.fault == Fault::TokenSignature {
                        let index = self.token.rfind('.').unwrap() + 1;
                        let replace = if self.token.as_bytes()[index] == b'A' { "B" } else { "A" };
                        self.token.replace_range(index..index + 1, replace);
                    }
                    return Ok(Reply::json(
                        200,
                        AuthTokenResponse::new(self.token.clone(), "fixture-refresh-credential")
                            .unwrap()
                            .to_json()
                            .unwrap()
                            .into_bytes(),
                    ));
                }
                "/.well-known/jwks.json" => {
                    if request.method != ::http::Method::GET || !body.is_empty() {
                        return Err("wrong JWKS request".into());
                    }
                    return Ok(Reply::json(
                        200,
                        AuthJwks::new(vec![AuthJwk::new("fixture", signing.public_key()).unwrap()])
                            .unwrap()
                            .to_json()
                            .unwrap(),
                    ));
                }
                _ => return Err("unsupported current-device route".into()),
            }
        }
        if header("accept") != Some("application/cbor")
            || header("authorization") != Some(format!("DPoP {}", self.token).as_str())
        {
            return Err("wrong protected transport".into());
        }
        let proof = DpopProof::parse(header("dpop").ok_or("missing DPoP proof")?)
            .map_err(|_| "DPoP codec")?;
        let target = DpopTarget::new(request.method.as_str(), origin, path).unwrap();
        let verified = proof
            .verify(
                &target,
                DpopToken::Protected(&self.token),
                &dpop_jwk_thumbprint(&certificate.signing_public_key).unwrap(),
                now().unwrap(),
                None,
            )
            .map_err(|_| "DPoP binding")?;
        if !self.proofs.insert(verified.jti) {
            return Err("reused DPoP proof".into());
        }
        let bytes = match path {
            "/sync/v1/session" => {
                if request.method != ::http::Method::POST
                    || header("content-type") != Some("application/cbor")
                {
                    return Err("wrong session transport".into());
                }
                let request = SyncSessionRequest::from_cbor(body).map_err(|_| "session codec")?;
                if request.device_id != self.payload.device_id
                    || request.model_version != scoplen_model::CURRENT_SCHEMA_VERSION
                {
                    return Err("wrong session identity".into());
                }
                if self.fault == Fault::MalformedSession {
                    vec![0xff]
                } else {
                    self.session().to_cbor().unwrap()
                }
            }
            "/sync/v1/keys" => {
                if request.method != ::http::Method::GET || !body.is_empty() {
                    return Err("wrong bundle request".into());
                }
                self.bundle().to_cbor().unwrap()
            }
            _ if path == format!("/sync/v1/vaults/{}/keys", self.payload.personal_vault_id) => {
                if request.method != ::http::Method::GET || !body.is_empty() {
                    return Err("wrong vault-key request".into());
                }
                let mut wrapped = self.payload.personal_wrapped_key.to_vec();
                if self.fault == Fault::VaultWrap {
                    *wrapped.last_mut().unwrap() ^= 1;
                }
                SyncVaultKeysResponse {
                    keys: vec![SyncVaultKey { epoch: 1, wrapped_vault_key: wrapped }],
                }
                .to_cbor()
                .unwrap()
            }
            _ => return Err("unexpected protected route".into()),
        };
        let mut reply = Reply::json(200, bytes);
        reply.headers[0].1 = "application/cbor".into();
        Ok(reply)
    }

    fn session(&self) -> SyncSessionResponse {
        SyncSessionResponse {
            server_version: "0.1.0".into(),
            max_model_version: 1,
            limits: SyncLimits {
                max_envelope_bytes: 1_048_576,
                max_batch_objects: 500,
                max_batch_bytes: 4_194_304,
                max_objects_per_vault: 100_000,
                max_shared_vaults_per_account: 100,
                max_members_per_shared_vault: 100,
                write_requests_per_second: 10,
                write_burst: 20,
            },
            vaults: vec![SessionVault {
                id: if self.fault == Fault::WrongVault {
                    scoplen_model::new_uuid_v7().unwrap()
                } else {
                    self.payload.personal_vault_id
                },
                kind: VaultKind::Personal,
                seq: 0,
                key_epoch: if self.fault == Fault::Epoch { 2 } else { 1 },
                rotation_pending: self.fault == Fault::Rotation,
            }],
        }
    }

    fn bundle(&self) -> SyncAccountKeyBundle {
        let update = SyncAccountKeyBundleUpdate::from_cbor(&self.payload.key_bundle).unwrap();
        let mut bundle = SyncAccountKeyBundle {
            revision: self.revision,
            wrapped_ark: update
                .device_wraps
                .into_iter()
                .find(|wrap| wrap.device_id == self.payload.device_id)
                .unwrap()
                .wrapped_ark,
            account_signing_key: update.account_signing_key,
            account_kem_key: update.account_kem_key,
            recovery_blob: update.recovery_blob,
            certificates: vec![self.payload.device_certificate.clone()],
            revocations: self.revocations.clone(),
        };
        let invalid = match self.fault {
            Fault::DeviceWrap => Some(&mut bundle.wrapped_ark),
            Fault::AccountSigningWrap => Some(&mut bundle.account_signing_key),
            Fault::AccountKemWrap => Some(&mut bundle.account_kem_key),
            Fault::RecoveryWrap => Some(&mut bundle.recovery_blob),
            Fault::Certificate => Some(&mut bundle.certificates[0]),
            _ => None,
        };
        if let Some(bytes) = invalid {
            *bytes.last_mut().unwrap() ^= 1;
        }
        if self.fault == Fault::MissingCertificate {
            bundle.certificates.clear();
        }
        bundle
    }
}

fn catalog(local: Arc<LocalData>, slots: &Slots) -> AccountProfiles {
    let slots = slots.clone();
    AccountProfiles::with_keystores(
        local,
        Arc::new(PersonalSyncRuntime::default()),
        Arc::new(move |path| {
            let slot = slots.lock().unwrap().entry(path.to_path_buf()).or_default().clone();
            Some(Box::new(slot) as Box<dyn Keystore>)
        }),
    )
    .unwrap()
}

struct Harness {
    // Release profile-owned database handles before Fixture removes its directory on Windows.
    profiles: AccountProfiles,
    f: Fixture,
    slots: Slots,
    peer: Arc<StdMutex<CurrentPeer>>,
}

impl Harness {
    async fn new() -> Self {
        let f = Fixture::new().await;
        f.exchange(RegistrationAction::Submit).await.unwrap();
        let peer = CurrentPeer::attach(&f.peer);
        let slots = Slots::default();
        let profiles = catalog(f.local.clone(), &slots);
        Self { f, profiles, slots, peer }
    }

    async fn install(&self) -> Result<ProfileLease, AccountProfileError> {
        fn send<T: Send>(future: T) -> T {
            future
        }
        let result = send(self.f.server.install_registration_profile(
            &self.profiles,
            &self.profiles.current().unwrap(),
            self.f.status.operation_id,
            None,
            &RegistrationCancellation::default(),
        ))
        .await;
        self.f.peer.healthy();
        result
    }

    fn candidate(&self) -> (AccountProfile, Arc<Store>) {
        let metadata = self.profiles.list().unwrap().into_iter().next().unwrap();
        let record = self.f.store.profile_record(metadata.id).unwrap().unwrap();
        let data = self.profiles.open_candidate(&record, None).unwrap();
        (metadata, data.store().unwrap())
    }

    fn database(&self, id: Uuid) -> rusqlite::Connection {
        let path = self.f.dir.path().join("accounts").join(id.to_string());
        let slot = self.slots.lock().unwrap().get(&path).unwrap().clone();
        database(&path, &slot)
    }

    fn retained_without_authority(&self) {
        let (metadata, store) = self.candidate();
        assert!(!metadata.ready);
        let identity = store.personal_record().unwrap().unwrap();
        assert!(!identity.admitted);
        assert!(!identity.authentication_allowed());
        assert!(store.personal_access_token(0).unwrap().is_none());
        assert!(store.personal_sync_record().unwrap().is_none());
        assert!(self.profiles.current().unwrap().account().is_none());
        assert_eq!(self.f.store.pending_registration().unwrap().unwrap().phase, 2);
        assert!(self.f.store.personal_record().unwrap().is_none());
        assert!(!store.personal_revalidation_current(&identity).unwrap());
        self.f.peer.healthy();
    }
}

fn database(directory: &Path, slot: &MemoryKeystore) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(directory.join("local.db")).unwrap();
    let keys = slot.0.lock().unwrap();
    let hex = Zeroizing::new(
        keys.as_ref().unwrap()[1..].iter().map(|b| format!("{b:02x}")).collect::<String>(),
    );
    let pragma = Zeroizing::new(format!("x'{}'", hex.as_str()));
    conn.pragma_update(None, "key", pragma.as_str()).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn
}

fn host(name: &str) -> Vec<(FieldPath, Value)> {
    vec![
        (FieldPath::Field(1), Value::Text(name.into())),
        (FieldPath::Field(2), Value::Text("127.0.0.1".into())),
    ]
}

#[tokio::test]
async fn confirmed_registration_installs_original_device_only_after_current_tls_auth_and_full_k4() {
    let h = Harness::new().await;
    let original = h.f.store.pending_registration().unwrap().unwrap();
    let local = h
        .f
        .store
        .write(LocalWrite { id: None, object_type: ObjectType::HOST, fields: host("local-only") })
        .unwrap();
    let source = h.profiles.current().unwrap();
    let lease = h.install().await.unwrap();
    let profile = lease.account().unwrap();
    assert!(profile.ready);
    assert_eq!(profile.account_id, h.f.status.account_id);
    assert_eq!(profile.device_id, h.f.status.device_id);
    assert_ne!(profile.device_id, h.f.store.device_id());
    assert_eq!(
        lease.store.personal_record().unwrap().unwrap().private_material,
        original.private_material
    );
    assert!(lease.store.personal_record().unwrap().unwrap().admitted);
    assert_eq!(h.f.server.status(&lease.store).unwrap().phase, PersonalServerPhase::Authenticated);
    assert_eq!(
        h.f.server.load_sync_bootstrap(&lease.store).unwrap().unwrap().session().vaults[0].id,
        profile.personal_vault_id
    );
    assert!(lease.store.personal_access_token(now().unwrap()).unwrap().is_some());
    assert!(lease.store.list(ObjectType::HOST).unwrap().is_empty());
    assert_eq!(h.f.store.get(local.id).unwrap(), Some(local));
    assert!(h.f.store.pending_registration().unwrap().is_none());
    assert!(h.f.store.personal_record().unwrap().is_none());
    assert!(h.f.store.device_key_pair().unwrap().is_none());
    assert_eq!(
        h.profiles.with_current_store(&source, |_| ()),
        Err(AccountProfileError::ContextChanged)
    );
    assert_eq!(h.profiles.last_selected().unwrap(), Some(profile.id));
    assert_eq!(h.profiles.list().unwrap(), vec![profile.clone()]);
    let bytes = std::fs::read(
        h.f.dir.path().join("accounts").join(profile.id.to_string()).join("local.db"),
    )
    .unwrap();
    assert!(!bytes.starts_with(b"SQLite format 3"));
    let slots = h.slots.lock().unwrap();
    assert_eq!(slots.len(), 1);
    assert!(
        *slots.values().next().unwrap().0.lock().unwrap() != *h.f.keys.0.lock().unwrap(),
        "Account and Local must use independent database keys"
    );
    drop(slots);
    assert_eq!(
        h.f.peer.paths(),
        vec![
            "/api/v1/auth/accounts/requests/challenge".to_owned(),
            "/api/v1/auth/accounts/register".into(),
            "/api/v1/auth/challenge".into(),
            "/api/v1/auth/device".into(),
            "/.well-known/jwks.json".into(),
            "/sync/v1/session".into(),
            "/sync/v1/keys".into(),
            format!("/sync/v1/vaults/{}/keys", profile.personal_vault_id),
        ]
    );
    h.f.peer.healthy();
}

#[tokio::test]
async fn prepared_and_unknown_registration_never_create_an_account_candidate_or_authenticate() {
    let f = Fixture::new().await;
    let slots = Slots::default();
    let profiles = catalog(f.local.clone(), &slots);
    let source = profiles.current().unwrap();
    assert_eq!(
        f.server
            .install_registration_profile(
                &profiles,
                &source,
                f.status.operation_id,
                None,
                &RegistrationCancellation::default()
            )
            .await
            .unwrap_err(),
        AccountProfileError::ConfirmationRequired
    );
    assert!(profiles.list().unwrap().is_empty());
    assert!(f.peer.paths().is_empty());
    f.peer.registration_reply(Some(Reply::json(200, b"{}".to_vec())), true);
    assert_eq!(
        f.exchange(RegistrationAction::Submit).await,
        Err(RegistrationError::InvalidResponse)
    );
    assert_eq!(
        f.server
            .install_registration_profile(
                &profiles,
                &source,
                f.status.operation_id,
                None,
                &RegistrationCancellation::default()
            )
            .await
            .unwrap_err(),
        AccountProfileError::ConfirmationRequired
    );
    assert_eq!(f.peer.paths().len(), 2);
    assert!(slots.lock().unwrap().is_empty());
    assert!(profiles.list().unwrap().is_empty());
}

#[tokio::test]
async fn fresh_auth_and_each_complete_k4_artifact_fail_closed_without_changing_registration_keys() {
    let h = Harness::new().await;
    let original = h.f.store.pending_registration().unwrap().unwrap();
    for fault in [
        Fault::Authentication,
        Fault::TokenSignature,
        Fault::TokenAccount,
        Fault::MalformedSession,
        Fault::WrongVault,
        Fault::Rotation,
        Fault::Epoch,
        Fault::DeviceWrap,
        Fault::AccountSigningWrap,
        Fault::AccountKemWrap,
        Fault::RecoveryWrap,
        Fault::Certificate,
        Fault::MissingCertificate,
        Fault::VaultWrap,
    ] {
        h.peer.lock().unwrap().fault = fault;
        assert!(h.install().await.is_err(), "accepted {fault:?}");
        h.retained_without_authority();
        assert_eq!(h.f.store.pending_registration().unwrap().unwrap(), original);
    }
    h.peer.lock().unwrap().fault = Fault::None;
    let secrets = Secrets::parse(&original.private_material).unwrap();
    let signer = Ed25519SigningKey::from_bytes(secrets.account_signing()).unwrap();
    let revoked = scoplen_crypto::RevocationStatement::issue(
        &signer,
        h.f.status.device_id,
        scoplen_model::system_time_millis().unwrap(),
        "fixture revocation".into(),
    )
    .unwrap();
    h.peer.lock().unwrap().revocations = vec![revoked.encode().unwrap()];
    assert!(h.install().await.is_err());
    h.retained_without_authority();
    h.peer.lock().unwrap().revocations.clear();
    let ready = h.install().await.unwrap();
    assert_eq!(
        ready.store.personal_record().unwrap().unwrap().private_material,
        original.private_material
    );
    assert_eq!(h.slots.lock().unwrap().len(), 1);
    h.f.peer.healthy();
}

#[tokio::test]
async fn higher_current_membership_revision_with_original_roots_and_wraps_is_accepted() {
    let h = Harness::new().await;
    h.peer.lock().unwrap().revision = 4;
    let installed = h.install().await.unwrap();
    let snapshot = installed.store.personal_sync_record().unwrap().unwrap();
    assert_eq!(
        SyncAccountKeyBundle::from_cbor(snapshot.account_keys.as_bytes()).unwrap().revision,
        4
    );
    assert!(h.f.server.load_sync_bootstrap(&installed.store).unwrap().is_some());
    h.f.peer.healthy();
}

#[tokio::test]
async fn target_commit_failure_rolls_back_tokens_admission_and_snapshot_and_retries_same_reservation()
 {
    let h = Harness::new().await;
    let (reached, release) = h.f.peer.pause("/sync/v1/keys");
    let source = h.profiles.current().unwrap();
    let cancel = RegistrationCancellation::default();
    let install = h.f.server.install_registration_profile(
        &h.profiles,
        &source,
        h.f.status.operation_id,
        None,
        &cancel,
    );
    tokio::pin!(install);
    tokio::select! { result=&mut install=>panic!("completed before fixture pause: {result:?}"),_=reached.notified()=>{} }
    let (profile, _) = h.candidate();
    let conn = h.database(profile.id);
    conn.execute_batch("CREATE TRIGGER fail_install BEFORE INSERT ON personal_sync BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    release.notify_one();
    assert_eq!(install.await.unwrap_err(), AccountProfileError::Storage);
    h.retained_without_authority();
    conn.execute_batch("DROP TRIGGER fail_install;").unwrap();
    h.f.peer.registration_reply(None, false);
    assert_eq!(h.install().await.unwrap().account().unwrap().id, profile.id);
    assert_eq!(h.peer.lock().unwrap().challenges, 2);
}

#[tokio::test]
async fn root_publication_failure_survives_process_reopen_and_reauthenticates_exact_installed_target()
 {
    let h = Harness::new().await;
    let root = h.f.database();
    root.execute_batch("CREATE TRIGGER fail_publish BEFORE UPDATE OF ready ON account_profiles BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert_eq!(h.install().await.unwrap_err(), AccountProfileError::Storage);
    let (profile, target) = h.candidate();
    assert!(!profile.ready);
    assert_eq!(
        h.profiles.open(profile.id, None).unwrap_err(),
        AccountProfileError::ConfirmationRequired
    );
    assert!(target.personal_record().unwrap().unwrap().admitted);
    let before = target.personal_record().unwrap().unwrap().private_material;
    assert!(target.personal_sync_record().unwrap().is_some());
    assert_eq!(h.f.store.pending_registration().unwrap().unwrap().phase, 2);
    assert!(h.profiles.current().unwrap().account().is_none());
    root.execute_batch("DROP TRIGGER fail_publish;").unwrap();
    drop(root);
    drop(target);
    let Harness { f, profiles, slots, peer } = h;
    drop(profiles);
    let reopened =
        Arc::new(LocalData::start(f.dir.path(), Some(Box::new(f.keys.clone()))).unwrap());
    let profiles = catalog(reopened, &slots);
    let source = profiles.current().unwrap();
    let ready = f
        .server
        .install_registration_profile(
            &profiles,
            &source,
            f.status.operation_id,
            None,
            &RegistrationCancellation::default(),
        )
        .await
        .unwrap();
    assert_eq!(ready.account().unwrap().id, profile.id);
    assert_eq!(ready.store.personal_record().unwrap().unwrap().private_material, before);
    assert_eq!(ready.store.personal_sync_record().unwrap().unwrap().generation, 2);
    assert!(f.store.pending_registration().unwrap().is_none());
    assert_eq!(peer.lock().unwrap().challenges, 2);
    let source = profiles.open_local().unwrap();
    let repeated = f
        .server
        .install_registration_profile(
            &profiles,
            &source,
            f.status.operation_id,
            None,
            &RegistrationCancellation::default(),
        )
        .await
        .unwrap();
    assert_eq!(repeated.account(), ready.account());
    assert!(!Arc::ptr_eq(&repeated.store, &ready.store));
    assert_eq!(peer.lock().unwrap().challenges, 3);
    f.peer.healthy();
}

#[tokio::test]
async fn cancellation_and_dropped_futures_at_authentication_and_k4_keep_candidates_unusable() {
    let h = Harness::new().await;
    let cancelled = RegistrationCancellation::default();
    cancelled.cancel();
    assert_eq!(
        h.f.server
            .install_registration_profile(
                &h.profiles,
                &h.profiles.current().unwrap(),
                h.f.status.operation_id,
                None,
                &cancelled
            )
            .await
            .unwrap_err(),
        AccountProfileError::Cancelled
    );
    assert!(h.profiles.list().unwrap().is_empty());
    let vault_path = format!("/sync/v1/vaults/{}/keys", h.f.status.personal_vault_id);
    for path in [
        "/api/v1/auth/challenge",
        "/api/v1/auth/device",
        "/.well-known/jwks.json",
        "/sync/v1/session",
        "/sync/v1/keys",
        vault_path.as_str(),
    ] {
        let (reached, release) = h.f.peer.pause(path);
        let source = h.profiles.current().unwrap();
        let cancel = RegistrationCancellation::default();
        let future = h.f.server.install_registration_profile(
            &h.profiles,
            &source,
            h.f.status.operation_id,
            None,
            &cancel,
        );
        tokio::pin!(future);
        tokio::select! { result=&mut future=>panic!("completed before {path}: {result:?}"),_=reached.notified()=>{} }
        cancel.cancel();
        assert_eq!(future.await.unwrap_err(), AccountProfileError::Cancelled);
        release.notify_one();
        h.retained_without_authority();
    }
    let (reached, release) = h.f.peer.pause("/sync/v1/keys");
    let source = h.profiles.current().unwrap();
    let cancel = RegistrationCancellation::default();
    {
        let future = h.f.server.install_registration_profile(
            &h.profiles,
            &source,
            h.f.status.operation_id,
            None,
            &cancel,
        );
        tokio::pin!(future);
        tokio::select! { result=&mut future=>panic!("completed before drop: {result:?}"),_=reached.notified()=>{} }
    }
    release.notify_one();
    h.retained_without_authority();
    h.f.peer.registration_reply(None, false);
    h.install().await.unwrap();
    h.f.peer.healthy();
}

#[tokio::test]
async fn root_reopen_during_auth_or_k4_fences_late_results_and_preserves_current_local_namespace() {
    let h = Harness::new().await;
    for path in ["/api/v1/auth/challenge", "/sync/v1/keys"] {
        let (reached, release) = h.f.peer.pause(path);
        let source = h.profiles.current().unwrap();
        let cancel = RegistrationCancellation::default();
        let future = h.f.server.install_registration_profile(
            &h.profiles,
            &source,
            h.f.status.operation_id,
            None,
            &cancel,
        );
        tokio::pin!(future);
        tokio::select! { result=&mut future=>panic!("completed before reopen: {result:?}"),_=reached.notified()=>{} }
        let next = h.profiles.open_local().unwrap();
        assert!(next.generation() > source.generation());
        assert!(!Arc::ptr_eq(&next.store, &source.store));
        assert_eq!(future.await.unwrap_err(), AccountProfileError::ContextChanged);
        release.notify_one();
        assert_eq!(
            h.profiles.with_current_store(&source, |_| ()),
            Err(AccountProfileError::ContextChanged)
        );
        h.retained_without_authority();
    }
    h.f.peer.registration_reply(None, false);
    let ready = h.install().await.unwrap();
    let source = h.profiles.open_local().unwrap();
    let generation = ready.store.personal_record().unwrap().unwrap().auth_generation;
    let (reached, release) = h.f.peer.pause("/sync/v1/keys");
    let cancel = RegistrationCancellation::default();
    let future = h.f.server.install_registration_profile(
        &h.profiles,
        &source,
        h.f.status.operation_id,
        None,
        &cancel,
    );
    tokio::pin!(future);
    tokio::select! { result=&mut future=>panic!("completed before replacement: {result:?}"),_=reached.notified()=>{} }
    let replacement = h.profiles.open(ready.account().unwrap().id, None).unwrap();
    assert_eq!(future.await.unwrap_err(), AccountProfileError::ContextChanged);
    release.notify_one();
    assert_eq!(h.profiles.current().unwrap().account(), replacement.account());
    assert_eq!(replacement.store.personal_record().unwrap().unwrap().auth_generation, generation);
    h.f.peer.healthy();
}

#[tokio::test]
async fn full_catalog_refuses_a_new_reservation_without_creating_keys_or_network_authority() {
    let h = Harness::new().await;
    let original = h.f.store.pending_registration().unwrap().unwrap();
    let root = h.f.database();
    for index in 0..128 {
        root.execute("INSERT INTO account_profiles(profile_id,origin,account_id,vault_id,device_id,operation_id,payload,signature,confirmation) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",rusqlite::params![scoplen_model::new_uuid_v7().unwrap().as_bytes().as_slice(),format!("https://profile-{index}.example"),scoplen_model::new_uuid_v7().unwrap().as_bytes().as_slice(),scoplen_model::new_uuid_v7().unwrap().as_bytes().as_slice(),scoplen_model::new_uuid_v7().unwrap().as_bytes().as_slice(),scoplen_model::new_uuid_v7().unwrap().as_bytes().as_slice(),original.payload.as_bytes(),original.account_signature.as_slice(),original.confirmation.as_ref().unwrap().as_bytes()]).unwrap();
    }
    assert_eq!(h.profiles.list().unwrap().len(), 128);
    assert_eq!(h.install().await.unwrap_err(), AccountProfileError::Limit);
    assert!(h.slots.lock().unwrap().is_empty());
    assert_eq!(h.f.peer.paths().len(), 2);
    assert_eq!(h.f.store.pending_registration().unwrap().unwrap(), original);
    assert!(h.profiles.current().unwrap().account().is_none());
}

#[tokio::test]
async fn unavailable_or_wrong_independent_key_slot_never_recreates_or_rebinds_existing_account_files()
 {
    let h = Harness::new().await;
    h.peer.lock().unwrap().fault = Fault::Authentication;
    assert!(h.install().await.is_err());
    let (profile, store) = h.candidate();
    let original = store.personal_record().unwrap().unwrap().private_material;
    let path = h.f.dir.path().join("accounts").join(profile.id.to_string());
    let slot = h.slots.lock().unwrap().get(&path).unwrap().clone();
    let saved = slot.0.lock().unwrap().clone();
    let requests = h.f.peer.paths().len();
    for key in [None, Some([vec![1], vec![99; 32]].concat())] {
        *slot.0.lock().unwrap() = key;
        assert_eq!(h.install().await.unwrap_err(), AccountProfileError::Storage);
        assert_eq!(h.f.peer.paths().len(), requests);
        assert_eq!(store.personal_record().unwrap().unwrap().private_material, original);
        assert!(h.f.store.pending_registration().unwrap().is_some());
        assert!(!h.profiles.list().unwrap()[0].ready);
    }
    *slot.0.lock().unwrap() = saved;
    h.peer.lock().unwrap().fault = Fault::None;
    assert_eq!(h.install().await.unwrap().account().unwrap().id, profile.id);
    h.f.peer.healthy();
}

#[tokio::test]
async fn transport_timeout_keeps_the_confirmed_registration_and_independent_candidate_retryable() {
    let mut h = Harness::new().await;
    h.f.server = h.f.peer.manager(Duration::from_millis(300));
    let (reached, release) = h.f.peer.pause("/sync/v1/keys");
    let future = h.install();
    tokio::pin!(future);
    tokio::select! { result=&mut future=>panic!("completed before timeout pause: {result:?}"),_=reached.notified()=>{} }
    assert!(matches!(
        future.await,
        Err(AccountProfileError::Personal(PersonalServerError::Network))
    ));
    release.notify_one();
    h.retained_without_authority();
}

#[tokio::test]
async fn equal_object_ids_stay_in_their_selected_store_and_every_reopen_invalidates_old_leases() {
    let h = Harness::new().await;
    let local =
        h.f.store
            .write(LocalWrite { id: None, object_type: ObjectType::HOST, fields: host("local") })
            .unwrap();
    let initial = h.profiles.current().unwrap();
    let installed = h.install().await.unwrap();
    let profile = installed.account().unwrap().id;
    h.profiles
        .with_current_store(&installed, |store| {
            store.create_batch(vec![NewObject {
                id: local.id,
                object_type: ObjectType::HOST,
                fields: host("account"),
            }])
        })
        .unwrap()
        .unwrap();
    let returned = h.profiles.open_local().unwrap();
    assert!(!Arc::ptr_eq(&initial.store, &returned.store));
    assert_eq!(
        h.profiles
            .with_current_store(&returned, |store| store
                .get(local.id)
                .unwrap()
                .unwrap()
                .required_text(1)
                .unwrap()
                .to_owned())
            .unwrap(),
        "local"
    );
    assert_eq!(
        h.profiles.with_current_store(&installed, |_| ()),
        Err(AccountProfileError::ContextChanged)
    );
    let reopened = h.profiles.open(profile, None).unwrap();
    assert!(reopened.generation() > returned.generation());
    assert!(!Arc::ptr_eq(&reopened.store, &installed.store));
    assert_eq!(
        h.profiles.with_current_store(&returned, |_| ()),
        Err(AccountProfileError::ContextChanged)
    );
    assert_eq!(
        h.profiles
            .with_current_store(&reopened, |store| store
                .get(local.id)
                .unwrap()
                .unwrap()
                .required_text(1)
                .unwrap()
                .to_owned())
            .unwrap(),
        "account"
    );
    let catalog2 = catalog(h.f.local.clone(), &h.slots);
    assert_eq!(catalog2.last_selected().unwrap(), Some(profile));
    assert_eq!(h.profiles.current().unwrap_err(), AccountProfileError::ContextChanged);
    assert_eq!(
        catalog2.with_current_store(&reopened, |_| ()),
        Err(AccountProfileError::ContextChanged)
    );
    assert!(catalog2.current().unwrap().account().is_none());
}

#[tokio::test]
async fn archival_allows_a_second_account_with_independent_keys_and_keeps_both_accounts_and_local()
{
    let h = Harness::new().await;
    let local =
        h.f.store
            .write(LocalWrite { id: None, object_type: ObjectType::HOST, fields: host("local") })
            .unwrap();
    let first = h.install().await.unwrap();
    let first_id = first.account().unwrap().id;
    first
        .store
        .write(LocalWrite { id: None, object_type: ObjectType::HOST, fields: host("first") })
        .unwrap();
    let source = h.profiles.open_local().unwrap();
    let peer = Peer::new().await;
    let server = peer.manager(Duration::from_secs(2));
    let pending = server
        .prepare_registration(
            &h.f.local,
            &source.store,
            &peer.origin,
            "bob",
            "Second",
            SecretVec::new(b"different account password".to_vec()),
        )
        .unwrap();
    server
        .save_registration_recovery(
            &h.f.local,
            &source.store,
            pending.operation_id,
            &h.f.dir.path().join("second-recovery.txt"),
        )
        .unwrap();
    server.confirm_registration_recovery(&h.f.local, &source.store, pending.operation_id).unwrap();
    server
        .exchange_registration(
            &h.f.local,
            source.store.clone(),
            pending.operation_id,
            RegistrationAction::Submit,
            &RegistrationCancellation::default(),
        )
        .await
        .unwrap();
    let _current = CurrentPeer::attach(&peer);
    let second = server
        .install_registration_profile(
            &h.profiles,
            &source,
            pending.operation_id,
            None,
            &RegistrationCancellation::default(),
        )
        .await
        .unwrap();
    assert_ne!(second.account().unwrap().id, first_id);
    assert_ne!(second.store.device_id(), first.store.device_id());
    assert_ne!(
        second.store.personal_record().unwrap().unwrap().private_material,
        first.store.personal_record().unwrap().unwrap().private_material
    );
    assert!(second.store.list(ObjectType::HOST).unwrap().is_empty());
    assert_eq!(h.profiles.list().unwrap().len(), 2);
    let slots = h.slots.lock().unwrap();
    assert_eq!(slots.len(), 2);
    let keys = slots.values().map(|slot| slot.0.lock().unwrap().clone()).collect::<Vec<_>>();
    assert!(keys[0] != keys[1], "Account profiles must use independent database keys");
    drop(slots);
    let local_again = h.profiles.open_local().unwrap();
    assert_eq!(local_again.store.get(local.id).unwrap(), Some(local));
    let first_again = h.profiles.open(first_id, None).unwrap();
    assert_eq!(first_again.store.list(ObjectType::HOST).unwrap().len(), 1);
    assert_eq!(first_again.store.personal_record().unwrap().unwrap().origin, h.f.status.origin);
    peer.healthy();
    h.f.peer.healthy();
}

#[tokio::test]
async fn bound_identity_catalog_generation_and_original_keys_resist_update_delete_and_replace() {
    let h = Harness::new().await;
    let installed = h.install().await.unwrap();
    let profile = installed.account().unwrap();
    let conn = h.database(profile.id);
    for sql in [
        "UPDATE account_profile_binding SET origin='https://other.example'",
        "DELETE FROM account_profile_binding",
        "INSERT OR REPLACE INTO account_profile_binding SELECT * FROM account_profile_binding",
        "UPDATE personal_server SET account_id=randomblob(16)",
        "UPDATE personal_server SET private_material=randomblob(225)",
        "DELETE FROM personal_server",
        "INSERT OR REPLACE INTO personal_server SELECT * FROM personal_server",
        "UPDATE device SET device_id=randomblob(16)",
        "DELETE FROM device",
        "INSERT OR REPLACE INTO device SELECT * FROM device",
        "UPDATE device_key_pair SET signing=randomblob(32)",
        "DELETE FROM device_key_pair",
        "INSERT OR REPLACE INTO device_key_pair SELECT * FROM device_key_pair",
    ] {
        assert!(conn.execute(sql, []).is_err(), "accepted {sql}");
    }
    let root = h.f.database();
    for sql in [
        "UPDATE account_profiles SET origin='https://other.example'",
        "UPDATE account_profiles SET ready=0",
        "DELETE FROM account_profiles",
        "INSERT OR REPLACE INTO account_profiles SELECT * FROM account_profiles",
        "INSERT OR REPLACE INTO account_profiles SELECT randomblob(16),origin,account_id,vault_id,device_id,operation_id,payload,signature,confirmation,0 FROM account_profiles",
        "UPDATE profile_selection SET generation=0",
        "DELETE FROM profile_selection",
        "INSERT OR REPLACE INTO profile_selection(singleton,generation) VALUES(1,0)",
    ] {
        assert!(root.execute(sql, []).is_err(), "accepted {sql}");
    }
    let path = h.f.dir.path().join("accounts").join(profile.id.to_string());
    let slot = h.slots.lock().unwrap().get(&path).unwrap().clone();
    let key =
        LocalDatabaseKey::new(slot.0.lock().unwrap().as_ref().unwrap()[1..].try_into().unwrap());
    assert!(matches!(Store::open(&path.join("local.db"), &key), Err(StoreError::AccountContext)));
    let mut wrong = h.f.store.profile_record(profile.id).unwrap().unwrap();
    wrong.profile.account_id = scoplen_model::new_uuid_v7().unwrap();
    assert!(matches!(
        Store::open_profile(&path.join("local.db"), &key, Some(&wrong)),
        Err(StoreError::AccountContext)
    ));
    let source = h.profiles.open_local().unwrap();
    assert_eq!(h.profiles.current().unwrap().generation(), source.generation());
    assert_eq!(h.profiles.open(profile.id, None).unwrap().account(), Some(profile));
}

#[tokio::test]
async fn platform_without_keystore_requires_an_independent_local_passphrase_and_reopens_it_explicitly()
 {
    let f = Fixture::new().await;
    f.exchange(RegistrationAction::Submit).await.unwrap();
    let _peer = CurrentPeer::attach(&f.peer);
    let profiles = AccountProfiles::with_keystores(
        f.local.clone(),
        Arc::new(PersonalSyncRuntime::default()),
        Arc::new(|_| None),
    )
    .unwrap();
    let source = profiles.current().unwrap();
    assert_eq!(
        f.server
            .install_registration_profile(
                &profiles,
                &source,
                f.status.operation_id,
                None,
                &RegistrationCancellation::default()
            )
            .await
            .unwrap_err(),
        AccountProfileError::PassphraseRequired
    );
    assert_eq!(f.peer.paths().len(), 2);
    let installed = f
        .server
        .install_registration_profile(
            &profiles,
            &source,
            f.status.operation_id,
            Some(SecretVec::new(b"independent local protection".to_vec())),
            &RegistrationCancellation::default(),
        )
        .await
        .unwrap();
    let id = installed.account().unwrap().id;
    let local = profiles.open_local().unwrap();
    assert_eq!(profiles.open(id, None).unwrap_err(), AccountProfileError::Locked);
    assert_eq!(
        profiles.open(id, Some(SecretVec::new(b"a real account password".to_vec()))).unwrap_err(),
        AccountProfileError::Locked
    );
    assert_eq!(profiles.current().unwrap().generation(), local.generation());
    assert_eq!(
        profiles
            .open(id, Some(SecretVec::new(b"independent local protection".to_vec())))
            .unwrap()
            .account(),
        installed.account()
    );
    f.peer.healthy();
}
