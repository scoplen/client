// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, HashSet},
    sync::Mutex as StdMutex,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use scoplen_api::{
    auth::{AuthJwk, AuthJwks},
    sync::{SessionVault, SyncLimits, SyncVaultKey},
};
use scoplen_crypto::{
    DeviceAccessTokenClaims, Ed25519SigningKey, SecretVec, TrustedDeviceAccessTokenKeys,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

use super::*;
use crate::personal_server::{Invitation, transport::Transport};

#[derive(Clone)]
struct Reply {
    status: u16,
    content_type: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    stall: bool,
}

impl Reply {
    fn cbor(body: Vec<u8>) -> Self {
        Self { status: 200, content_type: "application/cbor", headers: vec![], body, stall: false }
    }
}

struct Expected {
    token: Zeroizing<String>,
    jkt: String,
    device: uuid::Uuid,
    signing_public: Vec<u8>,
}

#[derive(Default)]
struct PeerState {
    replies: BTreeMap<String, Reply>,
    expected: Option<Expected>,
    paths: Vec<String>,
    proofs: HashSet<String>,
    errors: Vec<String>,
    inventory: Option<InventoryPeer>,
    refresh: Option<RefreshPeer>,
}

struct Peer {
    origin: String,
    certificate: reqwest::Certificate,
    state: Arc<StdMutex<PeerState>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Peer {
    async fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let certificate = reqwest::Certificate::from_der(key.cert.der()).unwrap();
        let private = rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der());
        let mut config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![key.cert.der().clone()], private.into())
                .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let state = Arc::new(StdMutex::new(PeerState::default()));
        let server_state = state.clone();
        let server_origin = origin.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let state = server_state.clone();
                let origin = server_origin.clone();
                connections.spawn(async move {
                    let Ok(stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    assert_eq!(
                        stream.get_ref().1.protocol_version(),
                        Some(rustls::ProtocolVersion::TLSv1_3)
                    );
                    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                    let Ok(mut connection) = h2::server::handshake(stream).await else {
                        return;
                    };
                    let mut requests = tokio::task::JoinSet::new();
                    while let Some(Ok((request, respond))) = connection.accept().await {
                        let state = state.clone();
                        let origin = origin.clone();
                        requests.spawn(async move {
                            if let Err(error) = answer(request, respond, &state, &origin).await {
                                state.lock().unwrap().errors.push(error);
                            }
                        });
                    }
                });
            }
        });
        Self { origin, certificate, state, task }
    }

    fn manager(&self) -> PersonalServer {
        PersonalServer {
            operation: tokio::sync::Mutex::new(()),
            transport: Ok(Transport::fixture(self.certificate.clone(), Duration::from_millis(700))),
        }
    }

    fn reply(&self, path: &str, reply: Reply) {
        self.state.lock().unwrap().replies.insert(path.into(), reply);
    }

    async fn prepare(&self, store: &Arc<Store>) -> PersonalServer {
        let manager = self.manager();
        manager
            .prepare(
                store.clone(),
                Zeroizing::new(format!(
                    "{}/invite#token={}",
                    self.origin,
                    URL_SAFE_NO_PAD.encode([42; 32])
                )),
                "Desktop".into(),
            )
            .await
            .unwrap();
        store.save_personal_recovery().unwrap();
        store.confirm_personal_recovery().unwrap();
        store.claim_personal_enrollment().unwrap();
        let pending = record(store).unwrap();
        let enrollment = PersonalEnrollmentRequest::from_json(
            pending.enrollment_request.as_ref().unwrap().as_bytes(),
        )
        .unwrap();
        let bundle = SyncAccountKeyBundle {
            revision: 1,
            wrapped_ark: enrollment.key_bundle_update.device_wraps[0].wrapped_ark.clone(),
            account_signing_key: enrollment.key_bundle_update.account_signing_key.clone(),
            account_kem_key: enrollment.key_bundle_update.account_kem_key.clone(),
            recovery_blob: enrollment.key_bundle_update.recovery_blob.clone(),
            certificates: vec![enrollment.device_certificate.encode().unwrap()],
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
                    id: pending.personal_vault_id,
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
        self.reply("/sync/v1/session", Reply::cbor(session.to_cbor().unwrap()));
        self.reply("/sync/v1/keys", Reply::cbor(bundle.to_cbor().unwrap()));
        self.reply(
            &format!("/sync/v1/vaults/{}/keys", pending.personal_vault_id),
            Reply::cbor(
                SyncVaultKeysResponse {
                    keys: vec![SyncVaultKey {
                        epoch: 1,
                        wrapped_vault_key: enrollment.wrapped_personal_vault_key,
                    }],
                }
                .to_cbor()
                .unwrap(),
            ),
        );
        let signing = Ed25519SigningKey::from_bytes(&[55; 32]).unwrap();
        self.reply(
            "/.well-known/jwks.json",
            Reply {
                content_type: "application/json",
                headers: vec![("cache-control", "no-store".into())],
                body: AuthJwks::new(vec![AuthJwk::new("fixture", signing.public_key()).unwrap()])
                    .unwrap()
                    .to_json()
                    .unwrap(),
                ..Reply::cbor(vec![])
            },
        );
        self.install_token(store, |_| {}, None);
        manager
    }

    fn install_token(
        &self,
        store: &Store,
        mutate: impl FnOnce(&mut DeviceAccessTokenClaims),
        foreign_device_key: Option<Vec<u8>>,
    ) {
        let pending = record(store).unwrap();
        let secrets = identity::Secrets::parse(&pending.private_material).unwrap();
        let signing = P256SigningKey::from_bytes(secrets.signing()).unwrap();
        let key = foreign_device_key.unwrap_or_else(|| signing.public_key_sec1());
        let authority = Ed25519SigningKey::from_bytes(&[55; 32]).unwrap();
        let mut trusted = TrustedDeviceAccessTokenKeys::new(&self.origin).unwrap();
        trusted.insert("fixture", &authority.public_key()).unwrap();
        let mut claims = DeviceAccessTokenClaims {
            iss: self.origin.clone(),
            sub: pending.account_id,
            did: store.device_id(),
            jti: scoplen_model::new_uuid_v7().unwrap(),
            cnf_jkt: dpop_jwk_thumbprint(&key).unwrap(),
            org: vec![],
            scope: "account:read keys:read keys:write sync:read sync:write".into(),
            iat: now().unwrap(),
            exp: now().unwrap() + 600,
        };
        mutate(&mut claims);
        let token =
            DeviceAccessToken::sign(&authority, &trusted, "fixture", &key, &claims).unwrap();
        store
            .save_personal_tokens(
                token.as_str().as_bytes(),
                b"refresh",
                now().unwrap() + 600,
                now().unwrap() + 3600,
            )
            .unwrap();
        self.state.lock().unwrap().expected = Some(Expected {
            token: Zeroizing::new(token.as_str().into()),
            jkt: dpop_jwk_thumbprint(&signing.public_key_sec1()).unwrap(),
            device: store.device_id(),
            signing_public: signing.public_key_sec1(),
        });
    }

    fn assert_healthy(&self) {
        assert!(self.state.lock().unwrap().errors.is_empty(), "reference peer rejected a request");
    }
}

async fn answer(
    mut request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    state: &StdMutex<PeerState>,
    origin: &str,
) -> Result<(), String> {
    let mut body = Vec::new();
    while let Some(chunk) = request.body_mut().data().await {
        let chunk = chunk.map_err(|_| "request body")?;
        if body.len() + chunk.len() > 4 * 1024 * 1024 {
            return Err("oversized request".into());
        }
        request.body_mut().flow_control().release_capacity(chunk.len()).unwrap();
        body.extend_from_slice(&chunk);
    }
    let reply = {
        let mut state = state.lock().unwrap();
        let path = request.uri().path();
        state.paths.push(path.into());
        if request.headers().contains_key("cookie")
            || request.headers().contains_key("idempotency-key")
        {
            return Err("unexpected credential transport".into());
        }
        if path.starts_with("/sync/") {
            let expected = state.expected.as_ref().ok_or("missing fixture identity")?;
            let token = request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("DPoP "))
                .ok_or("missing DPoP authorization")?;
            if token != expected.token.as_str() {
                return Err("wrong token".into());
            }
            if request.headers().get("accept").and_then(|value| value.to_str().ok())
                != Some("application/cbor")
            {
                return Err("wrong accept".into());
            }
            let proof = DpopProof::parse(
                request
                    .headers()
                    .get("dpop")
                    .and_then(|value| value.to_str().ok())
                    .ok_or("missing proof")?,
            )
            .map_err(|_| "invalid proof")?;
            let target = DpopTarget::new(request.method().as_str(), origin, path).unwrap();
            let verified = proof
                .verify(&target, DpopToken::Protected(token), &expected.jkt, now().unwrap(), None)
                .map_err(|_| "mismatched proof")?;
            if path == "/sync/v1/session" {
                if request.method() != http::Method::POST {
                    return Err("wrong session method".into());
                }
                let session =
                    SyncSessionRequest::from_cbor(&body).map_err(|_| "invalid session request")?;
                if session.device_id != expected.device
                    || session.model_version != scoplen_model::CURRENT_SCHEMA_VERSION
                {
                    return Err("wrong session identity".into());
                }
            } else if state.inventory.is_none()
                && (request.method() != http::Method::GET || !body.is_empty())
            {
                return Err("wrong protected request".into());
            }
            if !state.proofs.insert(verified.jti) {
                return Err("reused proof".into());
            }
        } else if path == "/api/v1/auth/refresh" {
            // This endpoint has a proof but deliberately no access-token header.
        } else if request.headers().contains_key("authorization")
            || request.headers().contains_key("dpop")
        {
            return Err("credentials leaked to JWKS".into());
        }
        if path.starts_with("/api/v1/auth/") && state.refresh.is_some() {
            let PeerState { refresh, expected, proofs, .. } = &mut *state;
            refresh.as_mut().unwrap().answer(
                &request,
                &body,
                expected.as_mut().unwrap(),
                proofs,
                origin,
            )?
        } else if state.inventory.is_some()
            && matches!(path.rsplit('/').next(), Some("changes" | "snapshot" | "objects" | "ack"))
        {
            let expected = state.expected.as_ref().ok_or("missing identity")?;
            let signing = expected.signing_public.clone();
            let device = expected.device;
            state.inventory.as_mut().unwrap().answer(&request, &body, &signing, device)?
        } else {
            state.replies.get(path).cloned().ok_or("unknown path")?
        }
    };
    if reply.stall {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    let mut response =
        http::Response::builder().status(reply.status).header("content-type", reply.content_type);
    for (name, value) in reply.headers {
        response = response.header(name, value);
    }
    let Ok(mut stream) = respond.send_response(response.body(()).unwrap(), false) else {
        return Ok(());
    };
    let _ = stream.send_data(Bytes::from(reply.body), true);
    Ok(())
}

fn local(dir: &tempfile::TempDir) -> Arc<Store> {
    Arc::new(Store::open(&dir.path().join("personal.db"), &SymmetricKey::new([27; 32])).unwrap())
}

#[tokio::test]
async fn tls13_h2_bootstrap_verifies_real_proofs_and_restores_offline() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    assert!(manager.load_sync_bootstrap(&store).unwrap().is_none());
    let result = manager.bootstrap_sync(store.clone()).await.unwrap();
    assert_eq!(result.session().vaults.len(), 2);
    assert_eq!(result.session().vaults[0].seq, 7);
    assert_eq!(result.session().vaults[1].kind, VaultKind::Unknown("future".into()));
    let key = SecretVec::new(result.personal_vault_key().as_bytes().to_vec());
    assert_eq!(peer.state.lock().unwrap().proofs.len(), 3);
    assert_eq!(peer.state.lock().unwrap().paths.len(), 4);
    store.clear_personal_tokens().unwrap();
    drop(store);
    drop(peer);
    let store = local(&dir);
    let restored = PersonalServer::default().load_sync_bootstrap(&store).unwrap().unwrap();
    assert_eq!(restored.session(), result.session());
    assert_eq!(restored.personal_vault_key().as_bytes(), key.as_bytes());
}

#[tokio::test]
async fn invalid_wrappers_and_certificates_never_replace_verified_keys() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let original = manager.bootstrap_sync(store.clone()).await.unwrap();
    let base = peer.state.lock().unwrap().replies["/sync/v1/keys"].clone();
    for field in 0..7 {
        let mut bundle = SyncAccountKeyBundle::from_cbor(&base.body).unwrap();
        match field {
            0 => bundle.wrapped_ark[90] ^= 1,
            1 => bundle.account_signing_key[40] ^= 1,
            2 => bundle.account_kem_key[40] ^= 1,
            3 => bundle.recovery_blob[40] ^= 1,
            4 => {
                let mut certificate = DeviceCertificate::decode(&bundle.certificates[0]).unwrap();
                certificate.signature[0] ^= 1;
                bundle.certificates[0] = certificate.encode().unwrap();
            }
            5 => {
                let pending = record(&store).unwrap();
                let signing = Ed25519SigningKey::from_bytes(
                    identity::Secrets::parse(&pending.private_material).unwrap().account_signing(),
                )
                .unwrap();
                bundle.revocations = vec![
                    RevocationStatement::issue(&signing, store.device_id(), 1, "revoked".into())
                        .unwrap()
                        .encode()
                        .unwrap(),
                ];
            }
            _ => bundle.certificates.clear(),
        }
        peer.reply("/sync/v1/keys", Reply::cbor(bundle.to_cbor().unwrap()));
        assert!(
            matches!(
                manager.bootstrap_sync(store.clone()).await,
                Err(PersonalSyncError::InvalidResponse)
            ),
            "field {field}"
        );
        let restored = manager.load_sync_bootstrap(&store).unwrap().unwrap();
        assert_eq!(restored.session(), original.session());
        assert_eq!(restored.personal_vault_key(), original.personal_vault_key());
    }
    peer.reply("/sync/v1/keys", base);
    let pending = record(&store).unwrap();
    let path = format!("/sync/v1/vaults/{}/keys", pending.personal_vault_id);
    let mut keys =
        SyncVaultKeysResponse::from_cbor(&peer.state.lock().unwrap().replies[&path].body).unwrap();
    let secrets = identity::Secrets::parse(&pending.private_material).unwrap();
    let ark = SymmetricKey::from_slice(secrets.ark()).unwrap();
    keys.keys[0].wrapped_vault_key = PersonalVaultKeyWrap::seal(
        pending.account_id,
        pending.personal_vault_id,
        1,
        &ark,
        &SymmetricKey::new([99; 32]),
    )
    .unwrap()
    .encode()
    .to_vec();
    peer.reply(&path, Reply::cbor(keys.to_cbor().unwrap()));
    assert!(matches!(
        manager.bootstrap_sync(store.clone()).await,
        Err(PersonalSyncError::InvalidResponse)
    ));
    assert_eq!(
        manager.load_sync_bootstrap(&store).unwrap().unwrap().personal_vault_key(),
        original.personal_vault_key()
    );
    peer.assert_healthy();
}

#[tokio::test]
async fn rotation_is_distinct_from_invalid_identity_and_preserves_snapshot() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let original = manager.bootstrap_sync(store.clone()).await.unwrap();
    let base = peer.state.lock().unwrap().replies["/sync/v1/session"].clone();
    for field in 0..4 {
        let mut session = SyncSessionResponse::from_cbor(&base.body).unwrap();
        match field {
            0 => session.vaults[0].key_epoch = 2,
            1 => session.vaults[0].rotation_pending = true,
            2 => session.vaults[0].id = scoplen_model::new_uuid_v7().unwrap(),
            _ => session.vaults[0].kind = VaultKind::Shared,
        }
        peer.reply("/sync/v1/session", Reply::cbor(session.to_cbor().unwrap()));
        let expected = if field < 2 {
            PersonalSyncError::RotationRequired
        } else {
            PersonalSyncError::InvalidResponse
        };
        assert!(
            matches!(manager.bootstrap_sync(store.clone()).await, Err(error) if error == expected)
        );
        assert_eq!(
            manager.load_sync_bootstrap(&store).unwrap().unwrap().session(),
            original.session()
        );
    }
    peer.reply("/sync/v1/session", base);
    let mut bundle =
        SyncAccountKeyBundle::from_cbor(&peer.state.lock().unwrap().replies["/sync/v1/keys"].body)
            .unwrap();
    bundle.revision = 2;
    peer.reply("/sync/v1/keys", Reply::cbor(bundle.to_cbor().unwrap()));
    assert!(matches!(
        manager.bootstrap_sync(store.clone()).await,
        Err(PersonalSyncError::RotationRequired)
    ));
    peer.assert_healthy();
}

#[tokio::test]
async fn invalid_tokens_and_scopes_send_no_protected_request() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    manager.bootstrap_sync(store.clone()).await.unwrap();
    let protected = peer.state.lock().unwrap().proofs.len();
    for field in 0..7 {
        peer.install_token(
            &store,
            |claims| match field {
                0 => claims.sub = scoplen_model::new_uuid_v7().unwrap(),
                1 => claims.did = scoplen_model::new_uuid_v7().unwrap(),
                2 => claims.scope = "keys:read".into(),
                3 => claims.scope = "sync:read".into(),
                4 => {
                    claims.iat -= 1200;
                    claims.exp = claims.iat + 600;
                }
                _ => {}
            },
            if field == 5 {
                Some(P256SigningKey::from_bytes(&[77; 32]).unwrap().public_key_sec1())
            } else {
                None
            },
        );
        if field == 6 {
            let token = store.personal_access_token(now().unwrap()).unwrap().unwrap();
            let mut token =
                Zeroizing::new(std::str::from_utf8(token.as_bytes()).unwrap().to_owned());
            let offset = token.rfind('.').unwrap() + 1;
            let replacement = if token.as_bytes()[offset] == b'A' { "B" } else { "A" };
            token.replace_range(offset..offset + 1, replacement);
            store
                .save_personal_tokens(
                    token.as_bytes(),
                    b"refresh",
                    now().unwrap() + 600,
                    now().unwrap() + 3600,
                )
                .unwrap();
        }
        let error = manager.bootstrap_sync(store.clone()).await.err().unwrap();
        let expected = if field == 2 || field == 3 {
            PersonalServerError::PermissionDenied.into()
        } else {
            PersonalSyncError::AuthenticationRequired
        };
        assert_eq!(error, expected, "field {field}");
        assert_eq!(peer.state.lock().unwrap().proofs.len(), protected);
        assert!(manager.load_sync_bootstrap(&store).unwrap().is_some());
    }
    store.clear_personal_tokens().unwrap();
    let requests = peer.state.lock().unwrap().paths.len();
    assert!(matches!(
        manager.bootstrap_sync(store.clone()).await,
        Err(PersonalSyncError::AuthenticationRequired)
    ));
    assert_eq!(peer.state.lock().unwrap().paths.len(), requests);
    peer.assert_healthy();
}

#[tokio::test]
async fn protected_transport_rejects_tls12_and_http1() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    for tls12 in [true, false] {
        let key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let certificate = reqwest::Certificate::from_der(key.cert.der()).unwrap();
        let private = rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der());
        let version = if tls12 { &rustls::version::TLS12 } else { &rustls::version::TLS13 };
        let mut config = rustls::ServerConfig::builder_with_protocol_versions(&[version])
            .with_no_client_auth()
            .with_single_cert(vec![key.cert.der().clone()], private.into())
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await
                && let Ok(mut stream) = acceptor.accept(stream).await
            {
                let mut bytes = [0; 4096];
                let _ =
                    tokio::time::timeout(Duration::from_millis(500), stream.read(&mut bytes)).await;
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\n\r\n\xa0").await;
            }
        });
        let signing = P256SigningKey::from_bytes(&[33; 32]).unwrap();
        let target = DpopTarget::new("GET", &origin, "/sync/v1/keys").unwrap();
        let proof = DpopProof::sign(
            &signing,
            &signing.public_key_sec1(),
            &target,
            DpopToken::Protected("access"),
            now().unwrap(),
            None,
        )
        .unwrap();
        let result = Transport::fixture(certificate, Duration::from_secs(1))
            .protected(&origin, "/sync/v1/keys", None, "access", &proof, BODY_LIMIT)
            .await;
        assert!(result.is_err());
        task.await.unwrap();
    }
}

#[tokio::test]
async fn malformed_cached_redirected_overbudget_and_stalled_responses_are_bounded() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let original = manager.bootstrap_sync(store.clone()).await.unwrap();
    let base = peer.state.lock().unwrap().replies["/sync/v1/session"].clone();
    for field in 0..8 {
        let mut reply = base.clone();
        match field {
            0 => reply.content_type = "application/json",
            1 => reply.headers.push(("age", "1".into())),
            2 => {
                reply.status = 307;
                reply.headers.push(("location", "https://example.invalid/".into()));
            }
            3 => reply.body = vec![0xff],
            4 => reply.headers.push(("content-length", (BODY_LIMIT + 1).to_string())),
            5 => reply.body = vec![0; BODY_LIMIT + 1],
            6 => reply.stall = true,
            _ => reply.status = 401,
        }
        peer.reply("/sync/v1/session", reply);
        assert!(manager.bootstrap_sync(store.clone()).await.is_err(), "field {field}");
        assert_eq!(
            manager.load_sync_bootstrap(&store).unwrap().unwrap().session(),
            original.session()
        );
    }
    peer.assert_healthy();
}

#[test]
fn retained_identity_and_cached_snapshot_are_revalidated() {
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let pending = identity::prepare(
        &store,
        Invitation::parse(&format!(
            "https://sync.example/invite#token={}",
            URL_SAFE_NO_PAD.encode([42; 32])
        ))
        .unwrap(),
        "Desktop".into(),
    )
    .unwrap();
    store.insert_personal_record(&pending).unwrap();
    let snapshot = PersonalSyncRecord {
        generation: 1,
        session: SecretVec::new(vec![0xff]),
        account_keys: SecretVec::new(vec![0xff]),
        vault_keys: SecretVec::new(vec![0xff]),
    };
    assert!(matches!(
        validate(&store, &pending, &snapshot),
        Err(PersonalSyncError::InvalidResponse)
    ));
    store
        .set_device_key_pair(&crate::store::device::DeviceKeyPair {
            signing: SecretVec::new(vec![44; 32]),
            kem: SecretVec::new(vec![44; 32]),
        })
        .unwrap();
    assert!(matches!(
        validate(&store, &pending, &snapshot),
        Err(PersonalSyncError::Personal(PersonalServerError::Identity))
    ));
}

mod inventory;
mod refresh;
use inventory::InventoryPeer;
use refresh::RefreshPeer;
