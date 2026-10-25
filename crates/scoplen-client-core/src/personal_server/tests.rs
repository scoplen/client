// SPDX-License-Identifier: Apache-2.0

use std::sync::{
    Mutex as StdMutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use scoplen_api::{
    auth::{AuthJwk, AuthJwks},
    sync::{
        SessionVault, SyncAccountDeviceWrap, SyncAccountKeyBundle, SyncAccountKeyBundleUpdate,
        SyncLimits, SyncSessionResponse, SyncVaultKey, SyncVaultKeysResponse, VaultKind,
    },
};
use scoplen_crypto::{
    AccountKemKeyWrap, AccountSigningKeyWrap, DeviceAccessTokenClaims, DeviceArkWrap,
    DeviceCertificate, Ed25519SigningKey, PersonalVaultKeyWrap, RecoveryBlob, RecoveryKey,
    SymmetricKey, generate_account_keys, generate_device_keys, generate_symmetric_key, p256_verify,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

use super::*;

mod admission;

fn store(dir: &tempfile::TempDir) -> Arc<Store> {
    Arc::new(Store::open(&dir.path().join("personal.db"), &SymmetricKey::new([27; 32])).unwrap())
}

pub(super) fn database(dir: &tempfile::TempDir) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(dir.path().join("personal.db")).unwrap();
    conn.pragma_update(None, "key", format!("x'{}'", "1b".repeat(32))).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn
}

#[derive(Default)]
struct FixtureState {
    enrolled: StdMutex<Option<DeviceCertificate>>,
    challenges: AtomicUsize,
    device_exchanges: AtomicUsize,
    nonces: StdMutex<Vec<String>>,
    reject_auth: AtomicBool,
    wrong_account: AtomicBool,
    tamper_access_token: AtomicBool,
    challenge_response: StdMutex<Option<String>>,
    device_response: StdMutex<Option<String>>,
    expected_device_key: StdMutex<Option<Vec<u8>>>,
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
                    if path == "/api/v1/auth/device" && state.stall_device.load(Ordering::SeqCst) {
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
        PersonalServer { operation: Mutex::new(()), transport: Ok(self.transport()) }
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
        "/api/v1/auth/challenge" => {
            let request =
                AuthChallengeRequest::from_json(std::str::from_utf8(body).unwrap()).unwrap();
            if let Some(enrolled) = &*state.enrolled.lock().unwrap() {
                assert_eq!(request.device_id, enrolled.device_id);
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
            if let Some(key) = expected_key
                .as_ref()
                .or_else(|| enrolled.as_ref().map(|record| &record.signing_public_key))
            {
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
                cnf_jkt: dpop_jwk_thumbprint(&enrolled.signing_public_key).unwrap(),
                org: vec![],
                scope: scoplen_api::auth::INITIAL_DEVICE_ACCESS_SCOPE.into(),
                iat: issued_at,
                exp: issued_at + 600,
            };
            let access = DeviceAccessToken::sign(
                &signing,
                &trusted,
                "fixture",
                &enrolled.signing_public_key,
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

pub(crate) struct FixtureProfile {
    pub record: PersonalRecord,
    pub certificate: DeviceCertificate,
    pub snapshot: crate::store::personal::PersonalSyncRecord,
}

/// Test setup uses only the public K-2/K-4 artifacts, never an archived entry codec.
pub(crate) fn fixture_profile(local: &Store, origin: &str, admitted: bool) -> FixtureProfile {
    let account_id = scoplen_model::new_uuid_v7().unwrap();
    let personal_vault_id = scoplen_model::new_uuid_v7().unwrap();
    let device = generate_device_keys().unwrap();
    let account = generate_account_keys().unwrap();
    let ark = generate_symmetric_key().unwrap();
    let vault_key = generate_symmetric_key().unwrap();
    let recovery = RecoveryKey::generate().unwrap();
    let device_id = local.device_id();
    let certificate = DeviceCertificate::issue(
        &account.signing,
        device_id,
        account_id,
        device.signing.public_key_sec1(),
        device.kem.public_key().to_vec(),
        "Desktop".into(),
        std::env::consts::OS.to_owned(),
        scoplen_model::system_time_millis().unwrap(),
    )
    .unwrap();
    let mut update = SyncAccountKeyBundleUpdate {
        revision: 1,
        device_wraps: vec![SyncAccountDeviceWrap {
            device_id,
            wrapped_ark: DeviceArkWrap::seal(account_id, device_id, device.kem.public_key(), &ark)
                .unwrap()
                .encode()
                .to_vec(),
        }],
        account_signing_key: AccountSigningKeyWrap::seal(account_id, &ark, &account.signing)
            .unwrap()
            .encode()
            .to_vec(),
        account_kem_key: AccountKemKeyWrap::seal(account_id, &ark, &account.kem)
            .unwrap()
            .encode()
            .to_vec(),
        recovery_blob: RecoveryBlob::wrap(&recovery, account_id, &ark).unwrap().encode().unwrap(),
        signature: vec![0; 64],
    };
    update.signature = account.signing.sign(&update.signature_input().unwrap()).to_vec();
    let update = SyncAccountKeyBundleUpdate::from_cbor(&update.to_cbor().unwrap()).unwrap();
    let bundle = SyncAccountKeyBundle {
        revision: update.revision,
        wrapped_ark: update.device_wraps[0].wrapped_ark.clone(),
        account_signing_key: update.account_signing_key,
        account_kem_key: update.account_kem_key,
        recovery_blob: update.recovery_blob,
        certificates: vec![certificate.encode().unwrap()],
        revocations: vec![],
    };
    let session = SyncSessionResponse {
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
        vaults: vec![
            SessionVault {
                id: personal_vault_id,
                kind: VaultKind::Personal,
                seq: 7,
                key_epoch: 1,
                rotation_pending: false,
            },
            SessionVault {
                id: scoplen_model::new_uuid_v7().unwrap(),
                kind: VaultKind::Unknown("future".into()),
                seq: 3,
                key_epoch: 4,
                rotation_pending: true,
            },
        ],
    };
    let vault = SyncVaultKeysResponse {
        keys: vec![SyncVaultKey {
            epoch: 1,
            wrapped_vault_key: PersonalVaultKeyWrap::seal(
                account_id,
                personal_vault_id,
                1,
                &ark,
                &vault_key,
            )
            .unwrap()
            .encode()
            .to_vec(),
        }],
    };
    let snapshot = crate::store::personal::PersonalSyncRecord {
        generation: 0,
        session: SecretVec::new(session.to_cbor().unwrap()),
        account_keys: SecretVec::new(bundle.to_cbor().unwrap()),
        vault_keys: SecretVec::new(vault.to_cbor().unwrap()),
    };
    let mut material = Zeroizing::new(Vec::with_capacity(225));
    material.push(1);
    material.extend_from_slice(device.signing.private_key_bytes().as_bytes());
    material.extend_from_slice(device.kem.private_key_bytes().as_bytes());
    material.extend_from_slice(ark.as_bytes());
    material.extend_from_slice(account.signing.private_key_bytes().as_bytes());
    material.extend_from_slice(account.kem.private_key_bytes().as_bytes());
    material.extend_from_slice(vault_key.as_bytes());
    material.extend_from_slice(recovery.as_bytes());
    let record = PersonalRecord {
        origin: origin.into(),
        account_id,
        personal_vault_id,
        device_name: "Desktop".into(),
        private_material: SecretVec::new(material.to_vec()),
        recovery_saved: false,
        recovery_confirmed: false,
        access_expires_at: None,
        refresh_expires_at: None,
        auth_generation: 0,
        auth_scope: None,
        refresh_available: false,
        refresh_retry_at: None,
        admitted: false,
    };
    local.insert_personal_record(&record).unwrap();
    if admitted {
        let (retained, anchors) =
            retained::RetainedAccount::from_snapshot(local, &record, &snapshot).unwrap();
        sync::validate_against(local, &record, &snapshot, None, &retained, false).unwrap();
        local.insert_personal_admission(&record, anchors.as_bytes()).unwrap();
    }
    FixtureProfile { record: local.personal_record().unwrap().unwrap(), certificate, snapshot }
}

async fn ready(_manager: &PersonalServer, local: &Arc<Store>, origin: &str, state: &FixtureState) {
    *state.enrolled.lock().unwrap() = Some(fixture_profile(local, origin, true).certificate);
}
#[tokio::test]
async fn real_https_authenticates_confirmed_identity_and_retains_tokens_only_in_sqlcipher() {
    let server = Fixture::new().await;
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = server.manager();
    ready(&manager, &local, &server.origin, &server.state).await;
    let connected = manager.authenticate(local.clone()).await.unwrap();
    assert_eq!(connected.phase, PersonalServerPhase::Authenticated);
    let serialized = serde_json::to_string(&connected).unwrap();
    assert!(!serialized.contains("fixture-refresh"));
    assert!(!serialized.contains("access_token"));
    manager.authenticate(local.clone()).await.unwrap();
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
async fn mismatched_identity_response_never_replaces_local_identity_or_accepts_tokens() {
    let server = Fixture::new().await;
    server.state.wrong_account.store(true, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = server.manager();
    ready(&manager, &local, &server.origin, &server.state).await;
    let before = manager.status(&local).unwrap();
    assert_eq!(
        manager.authenticate(local.clone()).await,
        Err(PersonalServerError::InvalidResponse)
    );
    let after = manager.status(&local).unwrap();
    assert_eq!(after.account_id, before.account_id);
    assert_eq!(after.phase, PersonalServerPhase::AuthenticationRequired);
}

#[tokio::test]
async fn invalid_access_signature_is_rejected_and_no_token_is_persisted() {
    let server = Fixture::new().await;
    server.state.tamper_access_token.store(true, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = server.manager();
    ready(&manager, &local, &server.origin, &server.state).await;
    assert_eq!(
        manager.authenticate(local.clone()).await,
        Err(PersonalServerError::InvalidResponse)
    );
    assert_eq!(manager.status(&local).unwrap().phase, PersonalServerPhase::AuthenticationRequired);
    assert!(record(&local).unwrap().access_expires_at.is_none());
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
