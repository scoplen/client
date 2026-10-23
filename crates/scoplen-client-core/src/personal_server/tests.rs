// SPDX-License-Identifier: Apache-2.0

use std::sync::{
    Mutex as StdMutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use scoplen_api::{
    auth::{AuthJwk, AuthJwks},
    personal_enrollment::{PersonalEnrollmentRequest, PersonalEnrollmentResponse},
};
use scoplen_crypto::{
    DeviceAccessTokenClaims, Ed25519SigningKey, PersonalEnrollmentArtifacts,
    PersonalEnrollmentContext, SymmetricKey, p256_verify,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

use super::*;

mod reinvitation;

const TOKEN: [u8; 32] = [42; 32];

fn store(dir: &tempfile::TempDir) -> Arc<Store> {
    Arc::new(Store::open(&dir.path().join("personal.db"), &SymmetricKey::new([27; 32])).unwrap())
}

fn invitation(origin: &str) -> Zeroizing<String> {
    Zeroizing::new(format!("{origin}/invite#token={}", URL_SAFE_NO_PAD.encode(TOKEN)))
}

#[test]
fn invitation_requires_exact_canonical_https_fragment() {
    assert!(Invitation::parse(&invitation("https://sync.example")).is_ok());
    for origin in [
        "http://sync.example",
        "https://SYNC.example",
        "https://sync.example:443",
        "https://sync.example/",
        "https://user@sync.example",
        "https://0x",
        "https://127.1",
    ] {
        assert!(Invitation::parse(&invitation(origin)).is_err());
    }
    for input in [
        format!("https://sync.example/invite?token={}", URL_SAFE_NO_PAD.encode(TOKEN)),
        format!("{}=", invitation("https://sync.example").as_str()),
        format!("{}&x=y", invitation("https://sync.example").as_str()),
        format!(" {}", invitation("https://sync.example").as_str()),
        "https://sync.example/invite#token=bad".into(),
    ] {
        assert!(Invitation::parse(&input).is_err());
    }
}

#[tokio::test]
async fn prepare_and_recovery_survive_restart_without_replacing_identity() {
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = PersonalServer::default();
    assert_eq!(manager.status(&local).unwrap().phase, PersonalServerPhase::NotConfigured);
    let first = manager
        .prepare(local.clone(), invitation("https://sync.example"), "My desktop".into())
        .await
        .unwrap();
    assert_eq!(first.phase, PersonalServerPhase::RecoveryRequired);
    assert_eq!(
        manager.confirm_recovery_key(local.clone()).await,
        Err(PersonalServerError::RecoveryRequired)
    );
    assert_eq!(
        manager
            .prepare(local.clone(), invitation("https://other.example"), "Replacement".into())
            .await,
        Err(PersonalServerError::AlreadyConfigured)
    );
    assert_eq!(manager.submit(local.clone()).await, Err(PersonalServerError::RecoveryRequired));
    let path = dir.path().join("recovery.txt");
    let saved = manager.save_recovery_key(local.clone(), path.clone()).await.unwrap();
    assert!(saved.recovery_key_saved);
    let contents = Zeroizing::new(std::fs::read_to_string(&path).unwrap());
    assert!(contents.contains("SPL1-"));
    assert_eq!(
        manager.save_recovery_key(local.clone(), path).await,
        Err(PersonalServerError::RecoverySave)
    );
    let ready = manager.confirm_recovery_key(local.clone()).await.unwrap();
    assert_eq!(ready.phase, PersonalServerPhase::ReadyToEnroll);
    drop(local);
    let local = store(&dir);
    assert_eq!(manager.status(&local).unwrap(), ready);
    let pending = record(&local).unwrap();
    let exported = RecoveryKey::parse_display(
        contents.lines().find(|line| line.starts_with("SPL1-")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        exported.as_bytes(),
        identity::Secrets::parse(&pending.private_material).unwrap().recovery().unwrap()
    );
    let body = pending.enrollment_request.as_ref().unwrap();
    let request = PersonalEnrollmentRequest::from_json(body.as_bytes()).unwrap();
    request.device_certificate.verify(&request.account_signing_public_key).unwrap();
    assert_eq!(request.device_certificate.device_id.to_string(), first.device_id.unwrap());
    assert!(!format!("{pending:?}").contains("SPL1-"));
    assert!(!serde_json::to_string(&ready).unwrap().contains(&URL_SAFE_NO_PAD.encode(TOKEN)));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(dir.path().join("recovery.txt")).unwrap().permissions().mode()
                & 0o777,
            0o600
        );
    }
}

#[tokio::test]
async fn prepared_wire_opens_with_shared_key_formats_and_recovery() {
    use scoplen_crypto::{
        AccountKemKeyWrap, AccountSigningKeyWrap, DeviceArkWrap, DeviceKemKeyPair,
        PersonalVaultKeyWrap, RecoveryBlob,
    };
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    PersonalServer::default()
        .prepare(local.clone(), invitation("https://sync.example"), "Desktop".into())
        .await
        .unwrap();
    let pending = record(&local).unwrap();
    let raw = pending.private_material.as_bytes();
    let request = PersonalEnrollmentRequest::from_json(
        pending.enrollment_request.as_ref().unwrap().as_bytes(),
    )
    .unwrap();
    let kem = DeviceKemKeyPair::from_private_bytes(&raw[33..65]).unwrap();
    let ark = DeviceArkWrap::decode(&request.key_bundle_update.device_wraps[0].wrapped_ark)
        .unwrap()
        .open(pending.account_id, local.device_id(), &kem)
        .unwrap();
    assert_eq!(ark.as_bytes(), &raw[65..97]);
    let signing = AccountSigningKeyWrap::decode(&request.key_bundle_update.account_signing_key)
        .unwrap()
        .open(pending.account_id, &ark, &request.account_signing_public_key)
        .unwrap();
    assert_eq!(signing.public_key(), request.account_signing_public_key);
    let account_kem = AccountKemKeyWrap::decode(&request.key_bundle_update.account_kem_key)
        .unwrap()
        .open(pending.account_id, &ark, &request.account_kem_public_key)
        .unwrap();
    assert_eq!(account_kem.public_key(), request.account_kem_public_key);
    let vault = PersonalVaultKeyWrap::decode(&request.wrapped_personal_vault_key)
        .unwrap()
        .open(pending.account_id, pending.personal_vault_id, 1, &ark)
        .unwrap();
    assert_eq!(vault.as_bytes(), &raw[161..193]);
    let recovery = RecoveryKey::from_bytes(&raw[193..225]).unwrap();
    assert_eq!(
        RecoveryBlob::decode(&request.key_bundle_update.recovery_blob)
            .unwrap()
            .open(&recovery, pending.account_id)
            .unwrap(),
        ark
    );
}

#[tokio::test]
async fn claim_is_atomic_and_restart_never_replays_enrollment() {
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = PersonalServer::default();
    manager
        .prepare(local.clone(), invitation("https://sync.example"), "Desktop".into())
        .await
        .unwrap();
    local.save_personal_recovery().unwrap();
    local.confirm_personal_recovery().unwrap();
    assert!(local.claim_personal_enrollment().unwrap());
    assert!(!local.claim_personal_enrollment().unwrap());
    drop(local);
    let local = store(&dir);
    let pending = record(&local).unwrap();
    assert!(pending.enrollment_attempted);
    assert!(pending.enrollment_request.is_some());
    assert_eq!(manager.status(&local).unwrap().phase, PersonalServerPhase::EnrollmentUnconfirmed);
    assert_eq!(manager.submit(local).await, Err(PersonalServerError::AlreadyAttempted));
}

#[tokio::test]
async fn operation_lock_rejects_concurrent_setup() {
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = PersonalServer::default();
    let _held = manager.operation.lock().await;
    assert_eq!(
        manager.prepare(local, invitation("https://sync.example"), "Desktop".into()).await,
        Err(PersonalServerError::Busy)
    );
}

#[tokio::test]
async fn prepare_never_replaces_existing_device_keys_or_leaves_partial_identity() {
    use crate::store::device::DeviceKeyPair;

    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let existing =
        DeviceKeyPair { signing: SecretVec::new(vec![11; 32]), kem: SecretVec::new(vec![12; 32]) };
    local.set_device_key_pair(&existing).unwrap();
    assert_eq!(
        PersonalServer::default()
            .prepare(local.clone(), invitation("https://sync.example"), "Desktop".into())
            .await,
        Err(PersonalServerError::Storage)
    );
    assert_eq!(local.device_key_pair().unwrap().unwrap(), existing);
    assert!(local.personal_record().unwrap().is_none());
}

#[tokio::test]
async fn invalid_device_name_leaves_no_identity_or_keys() {
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = PersonalServer::default();
    for name in [String::new(), "a".repeat(129), "Desktop\n".into(), "桌".repeat(43)] {
        assert_eq!(
            manager.prepare(local.clone(), invitation("https://sync.example"), name).await,
            Err(PersonalServerError::DeviceName)
        );
        assert!(local.device_key_pair().unwrap().is_none());
        assert!(local.personal_record().unwrap().is_none());
    }
}

#[derive(Default)]
struct FixtureState {
    enrolled: StdMutex<Option<PersonalEnrollmentRequest>>,
    enrollments: AtomicUsize,
    challenges: AtomicUsize,
    device_exchanges: AtomicUsize,
    nonces: StdMutex<Vec<String>>,
    lose_enrollment_reply: AtomicBool,
    reject_auth: AtomicBool,
    wrong_account: AtomicBool,
    mismatch_enrollment: AtomicBool,
    stall_enrollment: AtomicBool,
    tamper_access_token: AtomicBool,
    challenge_response: StdMutex<Option<String>>,
    device_response: StdMutex<Option<String>>,
    expected_device_key: StdMutex<Option<Vec<u8>>>,
    expected_invitation: StdMutex<Option<[u8; 32]>>,
    stall_device: AtomicBool,
}

struct Fixture {
    origin: String,
    certificate: reqwest::Certificate,
    task: tokio::task::JoinHandle<()>,
    state: Arc<FixtureState>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Fixture {
    async fn new() -> Self {
        Self::handler(None).await
    }

    async fn handler(fixed: Option<&'static str>) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let certificate = reqwest::Certificate::from_der(key.cert.der()).unwrap();
        let private = rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der());
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![key.cert.der().clone()], private.into())
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let state = Arc::new(FixtureState::default());
        let server_state = state.clone();
        let server_origin = origin.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let state = server_state.clone();
                let origin = server_origin.clone();
                connections.spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut request = Vec::new();
                    let mut buffer = [0; 2048];
                    let (header_end, length) = loop {
                        let Ok(count) = stream.read(&mut buffer).await else {
                            return;
                        };
                        if count == 0 {
                            return;
                        }
                        request.extend_from_slice(&buffer[..count]);
                        if request.len() > 1_048_576 {
                            return;
                        }
                        if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                        {
                            let headers = std::str::from_utf8(&request[..end]).unwrap();
                            let length = headers
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length: ")
                                        .map(|length| length.parse::<usize>().unwrap())
                                })
                                .unwrap_or(0);
                            break (end + 4, length);
                        }
                    };
                    while request.len() < header_end + length {
                        let count = stream.read(&mut buffer).await.unwrap();
                        if count == 0 {
                            return;
                        }
                        request.extend_from_slice(&buffer[..count]);
                    }
                    let headers = std::str::from_utf8(&request[..header_end]).unwrap();
                    assert!(!headers.to_ascii_lowercase().contains("authorization:"));
                    assert!(!headers.to_ascii_lowercase().contains("cookie:"));
                    assert!(!headers.to_ascii_lowercase().contains("idempotency-key:"));
                    let path = headers.lines().next().unwrap().split(' ').nth(1).unwrap();
                    if path == "/api/v1/auth/personal-enroll"
                        && state.stall_enrollment.load(Ordering::SeqCst)
                        || path == "/api/v1/auth/device"
                            && state.stall_device.load(Ordering::SeqCst)
                    {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        return;
                    }
                    let response = if let Some(fixed) = fixed {
                        Some(fixed.to_owned())
                    } else {
                        fixture_response(
                            &state,
                            &origin,
                            path,
                            &request[header_end..header_end + length],
                        )
                    };
                    if let Some(response) = response {
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self { origin, certificate, task, state }
    }

    fn transport(&self) -> Transport {
        Transport::fixture(self.certificate.clone(), Duration::from_secs(2))
    }

    fn manager(&self) -> PersonalServer {
        PersonalServer {
            operation: Mutex::new(()),
            transport: Ok(self.transport()),
            pairing: Default::default(),
        }
    }
}

fn json_response(status: u16, body: &[u8]) -> String {
    format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nPragma: no-cache\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        std::str::from_utf8(body).unwrap()
    )
}

fn fixture_response(state: &FixtureState, origin: &str, path: &str, body: &[u8]) -> Option<String> {
    let signing = Ed25519SigningKey::from_bytes(&[55; 32]).unwrap();
    match path {
        "/api/v1/auth/personal-enroll" => {
            state.enrollments.fetch_add(1, Ordering::SeqCst);
            let request = PersonalEnrollmentRequest::from_json(body).unwrap();
            let expected_token = state.expected_invitation.lock().unwrap().unwrap_or(TOKEN);
            assert_eq!(request.invitation_token, expected_token);
            request.device_certificate.verify(&request.account_signing_public_key).unwrap();
            scoplen_crypto::ed25519_verify(
                &request.account_signing_public_key,
                &request.key_bundle_update.signature_input().unwrap(),
                &request.key_bundle_update.signature,
            )
            .unwrap();
            PersonalEnrollmentContext::new(
                origin,
                &expected_token,
                request.account_id,
                request.personal_vault_id,
                PersonalEnrollmentArtifacts {
                    account_signing_public_key: &request.account_signing_public_key,
                    account_kem_public_key: &request.account_kem_public_key,
                    key_bundle_update: &request.key_bundle_update.to_cbor().unwrap(),
                    device_certificate: &request.device_certificate.encode().unwrap(),
                    wrapped_personal_vault_key: &request.wrapped_personal_vault_key,
                },
            )
            .unwrap()
            .verify(&request.device_certificate.signing_public_key, &request.device_signature)
            .unwrap();
            let response = PersonalEnrollmentResponse {
                account_id: if state.mismatch_enrollment.load(Ordering::SeqCst) {
                    scoplen_model::new_uuid_v7().unwrap()
                } else {
                    request.account_id
                },
                device_id: request.device_certificate.device_id,
                personal_vault_id: request.personal_vault_id,
            };
            *state.enrolled.lock().unwrap() = Some(request);
            if state.lose_enrollment_reply.load(Ordering::SeqCst) {
                None
            } else {
                Some(json_response(201, &response.to_json().unwrap()))
            }
        }
        "/api/v1/auth/challenge" => {
            let request =
                AuthChallengeRequest::from_json(std::str::from_utf8(body).unwrap()).unwrap();
            if let Some(enrolled) = &*state.enrolled.lock().unwrap() {
                assert_eq!(request.device_id, enrolled.device_certificate.device_id);
            }
            let index = state.challenges.fetch_add(1, Ordering::SeqCst) + 1;
            if let Some(response) = &*state.challenge_response.lock().unwrap() {
                return Some(response.clone());
            }
            let nonce = format!("{index:064x}");
            state.nonces.lock().unwrap().push(nonce.clone());
            Some(json_response(
                200,
                AuthChallengeResponse::new(nonce, "2026-10-20T00:00:00Z")
                    .unwrap()
                    .to_json()
                    .unwrap()
                    .as_bytes(),
            ))
        }
        "/api/v1/auth/device" => {
            let request = AuthDeviceRequest::from_json(std::str::from_utf8(body).unwrap()).unwrap();
            state.device_exchanges.fetch_add(1, Ordering::SeqCst);
            assert_eq!(Some(&request.nonce), state.nonces.lock().unwrap().last());
            let signature: Vec<u8> = (0..128)
                .step_by(2)
                .map(|index| u8::from_str_radix(&request.signature[index..index + 2], 16).unwrap())
                .collect();
            let enrolled = state.enrolled.lock().unwrap();
            let expected_key = state.expected_device_key.lock().unwrap();
            if let Some(key) = expected_key.as_ref().or_else(|| {
                enrolled.as_ref().map(|record| &record.device_certificate.signing_public_key)
            }) {
                p256_verify(
                    key,
                    &DeviceAuthContext::new(origin, &request.nonce, request.device_id)
                        .unwrap()
                        .signature_input(),
                    &signature,
                )
                .unwrap();
            }
            if let Some(response) = &*state.device_response.lock().unwrap() {
                return Some(response.clone());
            }
            if state.reject_auth.load(Ordering::SeqCst) {
                return Some(json_response(401, b"{}"));
            }
            let enrolled = enrolled.as_ref().unwrap();
            let mut trusted = TrustedDeviceAccessTokenKeys::new(origin).unwrap();
            trusted.insert("fixture", &signing.public_key()).unwrap();
            let issued_at = now().unwrap();
            let claims = DeviceAccessTokenClaims {
                iss: origin.into(),
                sub: if state.wrong_account.load(Ordering::SeqCst) {
                    scoplen_model::new_uuid_v7().unwrap()
                } else {
                    enrolled.account_id
                },
                did: request.device_id,
                jti: scoplen_model::new_uuid_v7().unwrap(),
                cnf_jkt: dpop_jwk_thumbprint(&enrolled.device_certificate.signing_public_key)
                    .unwrap(),
                org: vec![],
                scope: scoplen_api::auth::INITIAL_DEVICE_ACCESS_SCOPE.into(),
                iat: issued_at,
                exp: issued_at + 600,
            };
            let access = DeviceAccessToken::sign(
                &signing,
                &trusted,
                "fixture",
                &enrolled.device_certificate.signing_public_key,
                &claims,
            )
            .unwrap();
            let mut access = access.as_str().to_owned();
            if state.tamper_access_token.load(Ordering::SeqCst) {
                let start = access.rfind('.').unwrap() + 1;
                let replacement = if access.as_bytes()[start] == b'A' { "B" } else { "A" };
                access.replace_range(start..start + 1, replacement);
            }
            Some(json_response(
                200,
                AuthTokenResponse::new(access, "fixture-refresh-credential")
                    .unwrap()
                    .to_json()
                    .unwrap()
                    .as_bytes(),
            ))
        }
        "/.well-known/jwks.json" => Some(json_response(
            200,
            &AuthJwks::new(vec![AuthJwk::new("fixture", signing.public_key()).unwrap()])
                .unwrap()
                .to_json()
                .unwrap(),
        )),
        _ => Some(json_response(404, b"{}")),
    }
}

async fn ready(manager: &PersonalServer, local: &Arc<Store>, origin: &str) {
    manager.prepare(local.clone(), invitation(origin), "Desktop".into()).await.unwrap();
    local.save_personal_recovery().unwrap();
    manager.confirm_recovery_key(local.clone()).await.unwrap();
}

#[tokio::test]
async fn real_https_enrollment_authenticates_and_retains_tokens_only_in_sqlcipher() {
    let server = Fixture::new().await;
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = server.manager();
    ready(&manager, &local, &server.origin).await;
    let connected = manager.submit(local.clone()).await.unwrap();
    assert_eq!(connected.phase, PersonalServerPhase::Authenticated);
    assert_eq!(server.state.enrollments.load(Ordering::SeqCst), 1);
    let serialized = serde_json::to_string(&connected).unwrap();
    assert!(!serialized.contains("fixture-refresh"));
    assert!(!serialized.contains("access_token"));
    assert_eq!(manager.submit(local.clone()).await, Err(PersonalServerError::AlreadyAttempted));
    manager.authenticate(local.clone()).await.unwrap();
    assert_eq!(server.state.enrollments.load(Ordering::SeqCst), 1);
    assert_eq!(server.state.challenges.load(Ordering::SeqCst), 2);
    server.state.reject_auth.store(true, Ordering::SeqCst);
    assert_eq!(manager.authenticate(local.clone()).await, Err(PersonalServerError::Authentication));
    assert_eq!(manager.status(&local).unwrap().phase, PersonalServerPhase::AuthenticationRequired);
    let file = std::fs::read(dir.path().join("personal.db")).unwrap();
    assert!(
        !file
            .windows(b"fixture-refresh-credential".len())
            .any(|part| part == b"fixture-refresh-credential")
    );
}

#[tokio::test]
async fn lost_enrollment_reply_recovers_by_authentication_without_redeeming_twice() {
    let server = Fixture::new().await;
    server.state.lose_enrollment_reply.store(true, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = server.manager();
    ready(&manager, &local, &server.origin).await;
    assert_eq!(
        manager.submit(local.clone()).await.unwrap().phase,
        PersonalServerPhase::Authenticated
    );
    assert_eq!(server.state.enrollments.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn ambiguous_failure_survives_restart_and_auth_retry_uses_new_challenge() {
    let server = Fixture::new().await;
    server.state.lose_enrollment_reply.store(true, Ordering::SeqCst);
    server.state.reject_auth.store(true, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = server.manager();
    ready(&manager, &local, &server.origin).await;
    let before = manager.status(&local).unwrap();
    assert_eq!(manager.submit(local.clone()).await, Err(PersonalServerError::Authentication));
    drop(local);
    drop(manager);
    let local = store(&dir);
    let manager = server.manager();
    let pending = manager.status(&local).unwrap();
    assert_eq!(pending.phase, PersonalServerPhase::EnrollmentUnconfirmed);
    assert_eq!(pending.device_id, before.device_id);
    assert_eq!(pending.account_id, before.account_id);
    server.state.reject_auth.store(false, Ordering::SeqCst);
    assert_eq!(
        manager.authenticate(local).await.unwrap().phase,
        PersonalServerPhase::Authenticated
    );
    assert_eq!(server.state.enrollments.load(Ordering::SeqCst), 1);
    let nonces = server.state.nonces.lock().unwrap();
    assert_eq!(nonces.len(), 2);
    assert_ne!(nonces[0], nonces[1]);
}

#[tokio::test]
async fn mismatched_identity_response_never_replaces_local_identity_or_accepts_tokens() {
    let server = Fixture::new().await;
    server.state.wrong_account.store(true, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = server.manager();
    ready(&manager, &local, &server.origin).await;
    let before = manager.status(&local).unwrap();
    assert_eq!(manager.submit(local.clone()).await, Err(PersonalServerError::InvalidResponse));
    let after = manager.status(&local).unwrap();
    assert_eq!(after.account_id, before.account_id);
    assert_eq!(after.phase, PersonalServerPhase::EnrollmentUnconfirmed);
}

#[tokio::test]
async fn invalid_access_signature_is_rejected_and_no_token_is_persisted() {
    let server = Fixture::new().await;
    server.state.tamper_access_token.store(true, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = server.manager();
    ready(&manager, &local, &server.origin).await;
    assert_eq!(manager.submit(local.clone()).await, Err(PersonalServerError::InvalidResponse));
    assert_eq!(manager.status(&local).unwrap().phase, PersonalServerPhase::EnrollmentUnconfirmed);
    assert!(record(&local).unwrap().access_expires_at.is_none());
}

#[tokio::test]
async fn enrollment_response_identity_is_bound_to_pending_identity() {
    let server = Fixture::new().await;
    server.state.mismatch_enrollment.store(true, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = server.manager();
    ready(&manager, &local, &server.origin).await;
    assert_eq!(manager.submit(local.clone()).await, Err(PersonalServerError::InvalidResponse));
    assert_eq!(server.state.challenges.load(Ordering::SeqCst), 0);
    assert_eq!(manager.status(&local).unwrap().phase, PersonalServerPhase::EnrollmentUnconfirmed);
}

#[tokio::test]
async fn https_rejects_untrusted_certificates_redirects_and_oversized_bodies() {
    let server = Fixture::handler(Some(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: 2\r\n\r\n{}",
    ))
    .await;
    assert_eq!(
        Transport::new().unwrap().get(&server.origin, "/", 10).await.err(),
        Some(PersonalServerError::ConnectionBeforeRequest)
    );
    let redirect = Fixture::handler(Some("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:1/leak\r\nContent-Length: 0\r\n\r\n")).await;
    assert_eq!(
        redirect.transport().post(&redirect.origin, "/", b"secret", 10).await.err(),
        Some(PersonalServerError::InvalidResponse)
    );
    let large = Fixture::handler(Some(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: 99999\r\n\r\n",
    ))
    .await;
    assert_eq!(
        large.transport().get(&large.origin, "/", 10).await.err(),
        Some(PersonalServerError::InvalidResponse)
    );
    let chunked = Fixture::handler(Some("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nTransfer-Encoding: chunked\r\n\r\nB\r\n12345678901\r\n0\r\n\r\n")).await;
    assert_eq!(
        chunked.transport().get(&chunked.origin, "/", 10).await.err(),
        Some(PersonalServerError::InvalidResponse)
    );
}

#[tokio::test]
async fn connection_failure_before_sending_restores_ready_and_user_retries_same_identity() {
    let server = Fixture::new().await;
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let untrusted = PersonalServer::default();
    ready(&untrusted, &local, &server.origin).await;
    let before = untrusted.status(&local).unwrap();
    assert_eq!(
        untrusted.submit(local.clone()).await,
        Err(PersonalServerError::ConnectionBeforeRequest)
    );
    let ready = untrusted.status(&local).unwrap();
    assert_eq!(ready.phase, PersonalServerPhase::ReadyToEnroll);
    assert_eq!(ready.account_id, before.account_id);
    assert_eq!(ready.device_id, before.device_id);
    assert_eq!(server.state.enrollments.load(Ordering::SeqCst), 0);
    let trusted = server.manager();
    assert_eq!(trusted.submit(local).await.unwrap().phase, PersonalServerPhase::Authenticated);
    assert_eq!(server.state.enrollments.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn enrollment_timeout_keeps_claim_and_cannot_be_resubmitted() {
    let server = Fixture::new().await;
    server.state.stall_enrollment.store(true, Ordering::SeqCst);
    server.state.reject_auth.store(true, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = server.manager();
    ready(&manager, &local, &server.origin).await;
    assert_eq!(manager.submit(local.clone()).await, Err(PersonalServerError::Authentication));
    assert_eq!(manager.status(&local).unwrap().phase, PersonalServerPhase::EnrollmentUnconfirmed);
    assert!(record(&local).unwrap().enrollment_request.is_some());
    assert_eq!(manager.submit(local).await, Err(PersonalServerError::AlreadyAttempted));
}
