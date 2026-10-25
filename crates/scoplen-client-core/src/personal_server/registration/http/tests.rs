// SPDX-License-Identifier: Apache-2.0
//! Independent real TLS/H2 peer; no production server or in-memory HTTP adapter is used.

use std::{sync::Mutex as StdMutex, time::Duration};

use bytes::Bytes;
use scoplen_api::{ErrorCode, auth::AuthRateLimitHeaders};
use scoplen_crypto::SecretBytes;
use tokio::{
    net::TcpListener,
    sync::{MutexGuard, Notify},
};
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::{personal_server::transport::Transport, testing::MemoryKeystore};

#[derive(Clone)]
pub(in crate::personal_server::registration) struct Reply {
    pub(in crate::personal_server::registration) status: u16,
    pub(in crate::personal_server::registration) body: SecretVec,
    pub(in crate::personal_server::registration) headers: Vec<(&'static str, String)>,
}

impl Reply {
    pub(in crate::personal_server::registration) fn json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            body: SecretVec::new(body),
            headers: vec![
                ("content-type", "application/json".into()),
                ("cache-control", "no-store".into()),
                ("pragma", "no-cache".into()),
            ],
        }
    }

    pub(in crate::personal_server::registration) fn problem(
        status: u16,
        code: &str,
        changed: bool,
        retryable: bool,
    ) -> Self {
        let body = serde_json::to_vec(
            &ProblemDetails::new(
                ErrorCode::new(code).unwrap(),
                status,
                "Fixture",
                "private untrusted detail",
                "fixture",
                changed,
                retryable,
            )
            .unwrap(),
        )
        .unwrap();
        let mut reply = Self::json(status, body);
        reply.headers[0].1 = "application/problem+json".into();
        if status == 429 {
            let rate = AuthRateLimitHeaders::new(1).unwrap();
            reply.headers.extend([
                ("retry-after", "1".into()),
                ("ratelimit", rate.rate_limit()),
                ("ratelimit-policy", rate.rate_limit_policy().into()),
            ]);
        }
        reply
    }
}

type Extra = Box<dyn FnMut(&::http::request::Parts, &[u8], &str) -> Result<Reply, String> + Send>;

#[derive(Default)]
struct PeerState {
    paths: Vec<String>,
    challenges: Vec<(AccountRequestChallengeRequest, AccountRequestChallengeResponse)>,
    requests: Vec<AccountRegistrationRequest>,
    receipt: Option<AccountCommittedConfirmation>,
    challenge_reply: Option<Reply>,
    register_reply: Option<Reply>,
    reject_commit: bool,
    lose_reply: bool,
    pause: Option<(String, Arc<Notify>, Arc<Notify>)>,
    errors: Vec<String>,
    extra: Option<Extra>,
}

pub(in crate::personal_server::registration) struct Peer {
    pub(in crate::personal_server::registration) origin: String,
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
    pub(in crate::personal_server::registration) async fn new() -> Self {
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
        let shared = state.clone();
        let trusted_origin = origin.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let state = shared.clone();
                let origin = trusted_origin.clone();
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

    pub(in crate::personal_server::registration) fn manager(
        &self,
        timeout: Duration,
    ) -> PersonalServer {
        PersonalServer {
            operation: tokio::sync::Mutex::new(()),
            transport: Ok(Transport::fixture(self.certificate.clone(), timeout)),
        }
    }

    pub(in crate::personal_server::registration) fn registration_reply(
        &self,
        reply: Option<Reply>,
        reject_commit: bool,
    ) {
        let mut state = self.state.lock().unwrap();
        state.register_reply = reply;
        state.reject_commit = reject_commit;
        state.lose_reply = false;
        state.pause = None;
    }

    pub(in crate::personal_server::registration) fn pause(
        &self,
        path: &str,
    ) -> (Arc<Notify>, Arc<Notify>) {
        let reached = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        self.state.lock().unwrap().pause = Some((path.into(), reached.clone(), release.clone()));
        (reached, release)
    }

    pub(in crate::personal_server::registration) fn healthy(&self) {
        let state = self.state.lock().unwrap();
        assert!(state.errors.is_empty(), "independent peer rejected a request: {:?}", state.errors);
    }

    pub(in crate::personal_server::registration) fn extra(&self, handler: Extra) {
        self.state.lock().unwrap().extra = Some(handler);
    }

    pub(in crate::personal_server::registration) fn paths(&self) -> Vec<String> {
        self.state.lock().unwrap().paths.clone()
    }

    pub(in crate::personal_server::registration) fn payload(&self) -> AccountRegistrationPayload {
        let state = self.state.lock().unwrap();
        AccountRegistrationPayload::from_cbor(state.requests.first().unwrap().payload.as_bytes())
            .unwrap()
    }
}

async fn answer(
    mut request: ::http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    state: &StdMutex<PeerState>,
    origin: &str,
) -> Result<(), String> {
    let path = request.uri().path().to_owned();
    let operation = AccountEntryOperation::from_route(request.method().as_str(), &path);
    if request.uri().query().is_some()
        || operation.is_some()
            && (["authorization", "dpop", "cookie", "idempotency-key", "if-match"]
                .iter()
                .any(|h| request.headers().contains_key(*h))
                || request.headers().get("content-type").and_then(|v| v.to_str().ok())
                    != Some("application/json")
                || request.headers().get("accept-encoding").and_then(|v| v.to_str().ok())
                    != Some("identity"))
    {
        return Err("native request metadata".into());
    }
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = request.body_mut().data().await {
        let chunk = chunk.map_err(|_| "request body")?;
        if chunk.len()
            > operation
                .map_or(65_536, |operation| operation.body_limits().0)
                .saturating_sub(body.len())
        {
            return Err("request limit".into());
        }
        request.body_mut().flow_control().release_capacity(chunk.len()).unwrap();
        body.extend_from_slice(&chunk);
    }
    let (parts, _) = request.into_parts();
    let (reply, lose, pause) = {
        let mut state = state.lock().unwrap();
        state.paths.push(path.clone());
        let reply = match operation {
            Some(AccountEntryOperation::RequestChallenge) => {
                let request = AccountRequestChallengeRequest::from_json(&body)
                    .map_err(|_| "challenge codec")?;
                let n = u8::try_from(state.challenges.len() + 1)
                    .map_err(|_| "fixture challenge capacity")?;
                let response = AccountRequestChallengeResponse {
                    attempt_id: SecretBytes::new([n; 32]),
                    nonce: SecretBytes::new([n + 1; 32]),
                    expires_at_ms: now_ms().unwrap() + 120_000,
                };
                let reply = state
                    .challenge_reply
                    .clone()
                    .unwrap_or_else(|| Reply::json(200, response.to_json().unwrap()));
                state.challenges.push((request, response));
                reply
            }
            Some(AccountEntryOperation::Register) => {
                let request = AccountRegistrationRequest::from_json(&body)
                    .map_err(|_| "registration codec")?;
                let digest = request.verify_proof(origin).map_err(|_| "registration signatures")?;
                let payload = AccountRegistrationPayload::from_cbor(request.payload.as_bytes())
                    .map_err(|_| "protected payload")?;
                let (challenge, response) = state.challenges.last().ok_or("no challenge")?;
                if challenge.kind != AccountRequestKind::Register
                    || challenge.intent != request.intent
                    || challenge.operation_id != payload.operation_id
                    || challenge.device_id != payload.device_id
                    || request.attempt_id != response.attempt_id
                    || request.nonce != response.nonce
                    || state.requests.iter().any(|old| {
                        old.attempt_id == request.attempt_id
                            || old.device_proof == request.device_proof
                    })
                {
                    return Err("challenge or proof binding".into());
                }
                if let Some(original) = state.requests.first()
                    && (original.payload != request.payload
                        || original.account_signature != request.account_signature)
                {
                    return Err("business payload changed".into());
                }
                if request.intent == AccountRequestIntent::Submit && !state.reject_commit {
                    state.receipt = Some(AccountCommittedConfirmation {
                        kind: AccountRequestKind::Register,
                        operation_id: payload.operation_id,
                        request_digest: digest,
                        account_id: payload.account_id,
                        personal_vault_id: payload.personal_vault_id,
                        device_id: payload.device_id,
                        admitted_key_revision: 1,
                    });
                }
                let reply = state.register_reply.clone().unwrap_or_else(|| match &state.receipt {
                    Some(receipt) => Reply::json(
                        if request.intent == AccountRequestIntent::Submit { 201 } else { 200 },
                        receipt.to_json().unwrap(),
                    ),
                    None => Reply::problem(401, "auth.authentication_required", false, false),
                });
                state.requests.push(request);
                reply
            }
            None => {
                state.extra.as_mut().ok_or("unsupported fixture route")?(&parts, &body, origin)?
            }
            _ => return Err("unsupported fixture operation".into()),
        };
        let pause = state.pause.clone().filter(|(expected, _, _)| expected == &path);
        (reply, state.lose_reply && operation == Some(AccountEntryOperation::Register), pause)
    };
    if let Some((_, reached, release)) = pause {
        reached.notify_one();
        release.notified().await;
    }
    if lose {
        respond.send_reset(h2::Reason::INTERNAL_ERROR);
        return Ok(());
    }
    let mut response = ::http::Response::builder().status(reply.status);
    for (name, value) in reply.headers {
        response = response.header(name, value);
    }
    let Ok(mut stream) = respond.send_response(response.body(()).unwrap(), reply.body.is_empty())
    else {
        return Ok(());
    };
    // No Content-Length: aggregate checks must bound bytes arriving in DATA frames.
    let chunks = reply.body.as_bytes().chunks(256);
    let total = chunks.len();
    for (index, chunk) in chunks.enumerate() {
        if stream.send_data(Bytes::copy_from_slice(chunk), index + 1 == total).is_err() {
            break;
        }
    }
    Ok(())
}

pub(in crate::personal_server::registration) struct Fixture {
    pub(in crate::personal_server::registration) peer: Peer,
    pub(in crate::personal_server::registration) server: PersonalServer,
    pub(in crate::personal_server::registration) local: Arc<LocalData>,
    pub(in crate::personal_server::registration) store: Arc<Store>,
    pub(in crate::personal_server::registration) keys: MemoryKeystore,
    pub(in crate::personal_server::registration) status: RegistrationStatus,
    pub(in crate::personal_server::registration) dir: tempfile::TempDir,
    _serial: MutexGuard<'static, ()>,
}

impl Fixture {
    pub(in crate::personal_server::registration) async fn new() -> Self {
        let serial = TEST_SERIAL.lock().await;
        let peer = Peer::new().await;
        let server = peer.manager(Duration::from_secs(2));
        let dir = tempfile::tempdir().unwrap();
        let keys = MemoryKeystore::default();
        let local = Arc::new(LocalData::start(dir.path(), Some(Box::new(keys.clone()))).unwrap());
        let store = local.store().unwrap();
        let status = server
            .prepare_registration(
                &local,
                &store,
                &peer.origin,
                "alice",
                "Desktop",
                SecretVec::new(b"a real account password".to_vec()),
            )
            .unwrap();
        server
            .save_registration_recovery(
                &local,
                &store,
                status.operation_id,
                &dir.path().join("recovery.txt"),
            )
            .unwrap();
        server.confirm_registration_recovery(&local, &store, status.operation_id).unwrap();
        Self { peer, server, local, store, keys, status, dir, _serial: serial }
    }

    pub(in crate::personal_server::registration) async fn exchange(
        &self,
        action: RegistrationAction,
    ) -> Result<RegistrationStatus, RegistrationError> {
        self.server
            .exchange_registration(
                &self.local,
                self.store.clone(),
                self.status.operation_id,
                action,
                &RegistrationCancellation::default(),
            )
            .await
    }

    fn status(&self) -> RegistrationStatus {
        self.server.registration_status(&self.local, &self.local.store().unwrap()).unwrap().unwrap()
    }

    fn no_authority(&self) {
        let store = self.local.store().unwrap();
        assert!(store.personal_record().unwrap().is_none());
        assert!(store.device_key_pair().unwrap().is_none());
        assert!(store.personal_sync_record().unwrap().is_none());
        assert!(store.personal_access_token(0).unwrap().is_none());
        assert_ne!(store.device_id(), self.status.device_id);
    }

    pub(in crate::personal_server::registration) fn database(&self) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(self.dir.path().join("local.db")).unwrap();
        let keys = self.keys.0.lock().unwrap();
        let hex = Zeroizing::new(
            keys.as_ref().unwrap()[1..].iter().map(|b| format!("{b:02x}")).collect::<String>(),
        );
        let pragma = Zeroizing::new(format!("x'{}'", hex.as_str()));
        conn.pragma_update(None, "key", pragma.as_str()).unwrap();
        conn
    }
}

#[tokio::test]
async fn real_tls_h2_registration_records_only_historical_commit_and_reopens_without_authority() {
    let f = Fixture::new().await;
    let before = f.store.pending_registration().unwrap().unwrap();
    let result = f.exchange(RegistrationAction::Submit).await.unwrap();
    assert_eq!(result.phase, RegistrationPhase::Committed);
    assert_eq!(result.dispatch_generation, 1);
    let after = f.store.pending_registration().unwrap().unwrap();
    assert_eq!(before.payload, after.payload);
    assert_eq!(before.private_material, after.private_material);
    let reopened = LocalData::start(f.dir.path(), Some(Box::new(f.keys.clone()))).unwrap();
    assert_eq!(
        f.server.registration_status(&reopened, &reopened.store().unwrap()).unwrap().unwrap().phase,
        RegistrationPhase::Committed
    );
    assert_eq!(
        f.peer.state.lock().unwrap().paths,
        ["/api/v1/auth/accounts/requests/challenge", "/api/v1/auth/accounts/register"]
    );
    f.no_authority();
    f.peer.healthy();
}

#[tokio::test]
async fn lost_submit_response_reopens_unknown_and_only_fresh_exact_confirmation_can_finish() {
    let f = Fixture::new().await;
    f.peer.state.lock().unwrap().lose_reply = true;
    assert_eq!(f.exchange(RegistrationAction::Submit).await, Err(RegistrationError::Network));
    assert_eq!(f.status().phase, RegistrationPhase::OutcomeUnknown);
    assert_eq!(
        f.exchange(RegistrationAction::Retry).await,
        Err(RegistrationError::RetryUnavailable)
    );
    let reopened = LocalData::start(f.dir.path(), Some(Box::new(f.keys.clone()))).unwrap();
    f.peer.registration_reply(None, false);
    let result = f
        .server
        .exchange_registration(
            &reopened,
            reopened.store().unwrap(),
            f.status.operation_id,
            RegistrationAction::Confirm,
            &RegistrationCancellation::default(),
        )
        .await
        .unwrap();
    assert_eq!(result.phase, RegistrationPhase::Committed);
    let state = f.peer.state.lock().unwrap();
    assert_eq!(state.requests.len(), 2);
    assert_eq!(state.requests[0].intent, AccountRequestIntent::Submit);
    assert_eq!(state.requests[1].intent, AccountRequestIntent::Confirm);
    assert_eq!(state.requests[0].payload, state.requests[1].payload);
    assert_ne!(state.requests[0].device_proof, state.requests[1].device_proof);
    drop(state);
    f.no_authority();
    f.peer.healthy();
}

#[tokio::test]
async fn trusted_unchanged_denials_require_explicit_retry_and_keep_monotonic_original_material() {
    let f = Fixture::new().await;
    let before = f.store.pending_registration().unwrap().unwrap();
    for (index, (status, code, retryable, expected)) in [
        (409, "auth.registration_denied", false, RegistrationError::RegistrationDenied),
        (403, "policy.denied", false, RegistrationError::PolicyDenied),
        (401, "auth.authentication_required", false, RegistrationError::AuthenticationDenied),
        (413, "auth.quota_exceeded", false, RegistrationError::QuotaExceeded),
        (400, "auth.invalid_request", false, RegistrationError::RequestRejected),
        (503, "auth.storage_unavailable", true, RegistrationError::ServiceUnavailable),
    ]
    .into_iter()
    .enumerate()
    {
        f.peer.registration_reply(Some(Reply::problem(status, code, false, retryable)), true);
        assert_eq!(
            f.exchange(if index == 0 {
                RegistrationAction::Submit
            } else {
                RegistrationAction::Retry
            })
            .await,
            Err(expected)
        );
        assert_eq!(f.status().phase, RegistrationPhase::RetryAvailable);
        assert_eq!(f.status().dispatch_generation, index as u64 + 1);
        assert_eq!(
            f.exchange(RegistrationAction::Submit).await,
            Err(RegistrationError::ExplicitRetryRequired)
        );
        assert_eq!(
            f.server
                .registration_challenge(&f.local, &f.store, f.status.operation_id)
                .unwrap()
                .intent,
            AccountRequestIntent::Confirm
        );
        assert_eq!(f.peer.state.lock().unwrap().requests.len(), index + 1);
    }
    let after = f.store.pending_registration().unwrap().unwrap();
    assert_eq!(before.payload, after.payload);
    assert_eq!(before.private_material, after.private_material);
    for sql in [
        "UPDATE personal_registration SET phase=0",
        "DELETE FROM personal_registration",
        "UPDATE personal_registration SET dispatch_generation=dispatch_generation-1",
        "UPDATE personal_registration SET unchanged_generation=0",
    ] {
        assert!(f.database().execute(sql, []).is_err());
    }
    f.peer.registration_reply(None, false);
    f.peer.state.lock().unwrap().lose_reply = true;
    assert_eq!(f.exchange(RegistrationAction::Retry).await, Err(RegistrationError::Network));
    assert_eq!(f.status().dispatch_generation, 7);
    assert_eq!(f.status().phase, RegistrationPhase::OutcomeUnknown);
    assert_eq!(f.store.pending_registration().unwrap().unwrap().unchanged_generation, 6);
    f.peer.registration_reply(
        Some(Reply::problem(503, "auth.storage_unavailable", false, true)),
        false,
    );
    assert_eq!(
        f.exchange(RegistrationAction::Confirm).await,
        Err(RegistrationError::ServiceUnavailable)
    );
    assert_eq!(f.status().phase, RegistrationPhase::OutcomeUnknown);
    assert_eq!(
        f.exchange(RegistrationAction::Retry).await,
        Err(RegistrationError::RetryUnavailable)
    );
    assert_eq!(f.store.pending_registration().unwrap().unwrap().unchanged_generation, 6);
    f.peer.registration_reply(None, false);
    assert_eq!(
        f.exchange(RegistrationAction::Confirm).await.unwrap().phase,
        RegistrationPhase::Committed
    );
    f.no_authority();
    f.peer.healthy();
}

#[tokio::test]
async fn durable_rate_delay_survives_restart_and_only_later_explicit_retry_uses_fresh_proof() {
    let f = Fixture::new().await;
    f.peer.registration_reply(Some(Reply::problem(429, "auth.rate_limited", false, true)), true);
    assert_eq!(
        f.exchange(RegistrationAction::Submit).await,
        Err(RegistrationError::RateLimited { retry_after_seconds: 1 })
    );
    assert_eq!(f.exchange(RegistrationAction::Retry).await, Err(RegistrationError::RetryDeferred));
    let reopened = LocalData::start(f.dir.path(), Some(Box::new(f.keys.clone()))).unwrap();
    let status =
        f.server.registration_status(&reopened, &reopened.store().unwrap()).unwrap().unwrap();
    assert_eq!(status.phase, RegistrationPhase::RetryAvailable);
    let remaining = status.retry_not_before_ms.unwrap().saturating_sub(now_ms().unwrap());
    tokio::time::sleep(Duration::from_millis(remaining + 1)).await;
    f.peer.registration_reply(None, false);
    assert_eq!(
        f.server
            .exchange_registration(
                &reopened,
                reopened.store().unwrap(),
                f.status.operation_id,
                RegistrationAction::Retry,
                &RegistrationCancellation::default()
            )
            .await
            .unwrap()
            .phase,
        RegistrationPhase::Committed
    );
    assert_eq!(f.peer.state.lock().unwrap().requests.len(), 2);
    f.no_authority();
    f.peer.healthy();
}

#[tokio::test]
async fn unknown_commit_and_absent_receipt_denials_never_authorize_another_submit() {
    let f = Fixture::new().await;
    f.peer.registration_reply(
        Some(Reply::problem(503, "auth.commit_outcome_unknown", true, false)),
        false,
    );
    assert_eq!(
        f.exchange(RegistrationAction::Submit).await,
        Err(RegistrationError::OutcomeUnknown)
    );
    f.peer.state.lock().unwrap().receipt = None;
    for reply in [
        Reply::problem(401, "auth.authentication_required", false, false),
        Reply::problem(503, "auth.storage_unavailable", false, true),
        Reply::problem(409, "auth.registration_denied", false, false),
    ] {
        f.peer.registration_reply(Some(reply), true);
        assert!(f.exchange(RegistrationAction::Confirm).await.is_err());
        assert_eq!(f.status().phase, RegistrationPhase::OutcomeUnknown);
        assert_eq!(
            f.exchange(RegistrationAction::Retry).await,
            Err(RegistrationError::RetryUnavailable)
        );
    }
    assert_eq!(f.peer.state.lock().unwrap().requests.len(), 4);
    assert_eq!(f.status().dispatch_generation, 1);
    f.no_authority();
    f.peer.healthy();
}

#[tokio::test]
async fn malformed_or_inexact_responses_never_turn_handoff_into_retry_or_authority() {
    let f = Fixture::new().await;
    f.peer.registration_reply(Some(Reply::json(201, b"{}".to_vec())), false);
    assert_eq!(
        f.exchange(RegistrationAction::Submit).await,
        Err(RegistrationError::InvalidResponse)
    );
    let receipt = f.peer.state.lock().unwrap().receipt.clone().unwrap();
    let mut replies = vec![
        Reply::json(200, vec![b' '; 1025]),
        Reply::problem(503, "auth.storage_unavailable", true, true),
        Reply::problem(503, "future.unrecognized", false, true),
        Reply::problem(200, "auth.storage_unavailable", false, true),
    ];
    for field in 0..7 {
        let mut changed = receipt.clone();
        match field {
            0 => changed.kind = AccountRequestKind::Admit,
            1 => changed.operation_id = scoplen_model::new_uuid_v7().unwrap(),
            2 => changed.request_digest[0] ^= 1,
            3 => changed.account_id = scoplen_model::new_uuid_v7().unwrap(),
            4 => changed.personal_vault_id = scoplen_model::new_uuid_v7().unwrap(),
            5 => changed.device_id = scoplen_model::new_uuid_v7().unwrap(),
            _ => changed.admitted_key_revision = 2,
        }
        replies.push(Reply::json(200, changed.to_json().unwrap()));
    }
    for header in 0..8 {
        let mut reply = Reply::problem(503, "auth.storage_unavailable", false, true);
        match header {
            0 => {
                reply.headers.retain(|(name, _)| *name != "pragma");
            }
            1 => {
                reply.headers.retain(|(name, _)| *name != "cache-control");
            }
            2 => reply.headers.push(("cache-control", "no-store".into())),
            3 => reply.headers.push(("age", "0".into())),
            4 => reply.headers.push(("set-cookie", "untrusted=x".into())),
            5 => reply.headers.push(("content-encoding", "gzip".into())),
            6 => {
                reply.status = 307;
                reply
                    .headers
                    .push(("location", format!("{}/api/v1/auth/accounts/register", f.peer.origin)));
            }
            _ => {
                reply.body = SecretVec::new(vec![b' '; 4097]);
            }
        }
        replies.push(reply);
    }
    let mut duplicate = Reply::problem(503, "auth.storage_unavailable", false, true);
    let mut bytes = duplicate.body.as_bytes().to_vec();
    bytes.pop();
    bytes.extend_from_slice(b",\"extension\":{\"x\":1,\"x\":2}}");
    duplicate.body = SecretVec::new(bytes);
    replies.push(duplicate);
    for reply in replies {
        f.peer.registration_reply(Some(reply), false);
        assert_eq!(
            f.exchange(RegistrationAction::Confirm).await,
            Err(RegistrationError::InvalidResponse)
        );
        assert_eq!(f.status().phase, RegistrationPhase::OutcomeUnknown);
    }
    f.peer.registration_reply(None, false);
    assert_eq!(
        f.exchange(RegistrationAction::Confirm).await.unwrap().phase,
        RegistrationPhase::Committed
    );
    f.no_authority();
    f.peer.healthy();
}

#[tokio::test]
async fn untrusted_tls_and_bad_challenges_never_dispatch_the_original_registration() {
    let f = Fixture::new().await;
    let other_dir = tempfile::tempdir().unwrap();
    let other =
        LocalData::start(other_dir.path(), Some(Box::new(MemoryKeystore::default()))).unwrap();
    assert_eq!(
        f.server
            .exchange_registration(
                &other,
                f.store.clone(),
                f.status.operation_id,
                RegistrationAction::Submit,
                &RegistrationCancellation::default()
            )
            .await,
        Err(RegistrationError::ContextChanged)
    );
    assert_eq!(
        f.server
            .exchange_registration(
                &f.local,
                f.store.clone(),
                scoplen_model::new_uuid_v7().unwrap(),
                RegistrationAction::Submit,
                &RegistrationCancellation::default()
            )
            .await,
        Err(RegistrationError::NotPrepared)
    );
    assert!(f.peer.state.lock().unwrap().paths.is_empty());
    let untrusted = PersonalServer::default();
    assert_eq!(
        untrusted
            .exchange_registration(
                &f.local,
                f.store.clone(),
                f.status.operation_id,
                RegistrationAction::Submit,
                &RegistrationCancellation::default()
            )
            .await,
        Err(RegistrationError::Network)
    );
    for reply in [
        Reply::json(200, b"{}".to_vec()),
        Reply::json(200, vec![b' '; 1025]),
        Reply::json(404, vec![]),
    ] {
        f.peer.state.lock().unwrap().challenge_reply = Some(reply);
        assert!(f.exchange(RegistrationAction::Submit).await.is_err());
        assert_eq!(f.status().phase, RegistrationPhase::Ready);
        assert_eq!(f.status().dispatch_generation, 0);
    }
    f.peer.state.lock().unwrap().challenge_reply = Some(Reply::json(
        200,
        AccountRequestChallengeResponse {
            attempt_id: SecretBytes::new([55; 32]),
            nonce: SecretBytes::new([56; 32]),
            expires_at_ms: 1,
        }
        .to_json()
        .unwrap(),
    ));
    assert_eq!(
        f.exchange(RegistrationAction::Submit).await,
        Err(RegistrationError::InvalidResponse)
    );
    assert!(f.peer.state.lock().unwrap().requests.is_empty());
    assert_eq!(f.status().phase, RegistrationPhase::Ready);
    f.no_authority();
    f.peer.healthy();
}

#[tokio::test]
async fn cancellation_and_context_replacement_stop_io_and_cannot_apply_late_results() {
    let f = Fixture::new().await;
    let cancelled = RegistrationCancellation::default();
    cancelled.cancel();
    assert_eq!(
        f.server
            .exchange_registration(
                &f.local,
                f.store.clone(),
                f.status.operation_id,
                RegistrationAction::Submit,
                &cancelled
            )
            .await,
        Err(RegistrationError::Cancelled)
    );
    assert!(f.peer.state.lock().unwrap().paths.is_empty());
    let (reached, release) = f.peer.pause("/api/v1/auth/accounts/requests/challenge");
    let cancel = RegistrationCancellation::default();
    {
        let exchange = f.server.exchange_registration(
            &f.local,
            f.store.clone(),
            f.status.operation_id,
            RegistrationAction::Submit,
            &cancel,
        );
        tokio::pin!(exchange);
        tokio::select! { _ = &mut exchange => panic!("unreleased challenge completed"), _ = reached.notified() => {} }
        cancel.cancel();
        assert_eq!(exchange.await, Err(RegistrationError::Cancelled));
    }
    release.notify_one();
    assert_eq!(f.status().phase, RegistrationPhase::Ready);
    let (reached, release) = f.peer.pause("/api/v1/auth/accounts/register");
    let cancel = RegistrationCancellation::default();
    {
        let exchange = f.server.exchange_registration(
            &f.local,
            f.store.clone(),
            f.status.operation_id,
            RegistrationAction::Submit,
            &cancel,
        );
        tokio::pin!(exchange);
        tokio::select! { _ = &mut exchange => panic!("unreleased Submit completed"), _ = reached.notified() => {} }
        cancel.cancel();
        assert_eq!(exchange.await, Err(RegistrationError::Cancelled));
    }
    release.notify_one();
    assert_eq!(f.status().phase, RegistrationPhase::OutcomeUnknown);
    let (reached, release) = f.peer.pause("/api/v1/auth/accounts/register");
    let cancel = RegistrationCancellation::default();
    {
        let exchange = f.server.exchange_registration(
            &f.local,
            f.store.clone(),
            f.status.operation_id,
            RegistrationAction::Confirm,
            &cancel,
        );
        tokio::pin!(exchange);
        tokio::select! { _ = &mut exchange => panic!("unreleased Confirm completed"), _ = reached.notified() => {} }
        f.local.reopen_for_test().unwrap();
        assert_eq!(exchange.await, Err(RegistrationError::ContextChanged));
    }
    release.notify_one();
    assert_eq!(f.status().phase, RegistrationPhase::OutcomeUnknown);
    f.no_authority();
    f.peer.healthy();
}

#[tokio::test]
async fn timeout_or_dropping_the_future_after_handoff_preserves_exact_unknown_state() {
    let f = Fixture::new().await;
    let (reached, release) = f.peer.pause("/api/v1/auth/accounts/register");
    let cancel = RegistrationCancellation::default();
    {
        let exchange = f.server.exchange_registration(
            &f.local,
            f.store.clone(),
            f.status.operation_id,
            RegistrationAction::Submit,
            &cancel,
        );
        tokio::pin!(exchange);
        tokio::select! { _ = &mut exchange => panic!("unreleased Submit completed"), _ = reached.notified() => {} }
    }
    release.notify_one();
    assert_eq!(f.status().phase, RegistrationPhase::OutcomeUnknown);
    let (_, release) = f.peer.pause("/api/v1/auth/accounts/register");
    let short = f.peer.manager(Duration::from_millis(150));
    assert_eq!(
        short
            .exchange_registration(
                &f.local,
                f.store.clone(),
                f.status.operation_id,
                RegistrationAction::Confirm,
                &RegistrationCancellation::default()
            )
            .await,
        Err(RegistrationError::Timeout)
    );
    release.notify_one();
    assert_eq!(f.status().phase, RegistrationPhase::OutcomeUnknown);
    f.peer.registration_reply(None, false);
    assert_eq!(
        f.exchange(RegistrationAction::Confirm).await.unwrap().phase,
        RegistrationPhase::Committed
    );
    assert_eq!(f.status().dispatch_generation, 1);
    f.no_authority();
    f.peer.healthy();
}

#[tokio::test]
async fn failed_result_transactions_grant_neither_retry_nor_historical_success() {
    {
        let f = Fixture::new().await;
        let db = f.database();
        db.execute_batch("CREATE TRIGGER fail_unchanged BEFORE UPDATE ON personal_registration WHEN NEW.unchanged_generation>OLD.unchanged_generation BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        f.peer.registration_reply(
            Some(Reply::problem(503, "auth.storage_unavailable", false, true)),
            true,
        );
        assert_eq!(f.exchange(RegistrationAction::Submit).await, Err(RegistrationError::Storage));
        assert_eq!(f.status().phase, RegistrationPhase::OutcomeUnknown);
        assert_eq!(
            f.exchange(RegistrationAction::Retry).await,
            Err(RegistrationError::RetryUnavailable)
        );
        f.no_authority();
        f.peer.healthy();
    }
    let f = Fixture::new().await;
    let db = f.database();
    db.execute_batch("CREATE TRIGGER fail_receipt BEFORE UPDATE ON personal_registration WHEN NEW.phase=2 BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert_eq!(f.exchange(RegistrationAction::Submit).await, Err(RegistrationError::Storage));
    assert_eq!(f.status().phase, RegistrationPhase::OutcomeUnknown);
    db.execute_batch("DROP TRIGGER fail_receipt").unwrap();
    assert_eq!(
        f.exchange(RegistrationAction::Confirm).await.unwrap().phase,
        RegistrationPhase::Committed
    );
    f.no_authority();
    f.peer.healthy();
}

#[tokio::test]
async fn untrusted_first_submit_problems_cannot_grant_retry_even_when_the_body_claims_unchanged() {
    for fault in 0..11 {
        let f = Fixture::new().await;
        let mut reply = Reply::problem(503, "auth.storage_unavailable", false, true);
        match fault {
            0 => reply.headers.retain(|(name, _)| *name != "pragma"),
            1 => reply.headers.push(("cache-control", "no-store".into())),
            2 => reply.headers.push(("age", "0".into())),
            3 => reply.headers.push(("set-cookie", "untrusted=x".into())),
            4 => reply.headers.push(("content-encoding", "gzip".into())),
            5 => {
                reply.status = 307;
                reply.headers.push(("location", f.peer.origin.clone()));
            }
            6 => reply = Reply::problem(503, "future.unrecognized", false, true),
            7 => reply = Reply::problem(503, "auth.storage_unavailable", false, false),
            8 => {
                let mut body = reply.body.as_bytes().to_vec();
                body.pop();
                body.extend_from_slice(b",\"extension\":{\"x\":1,\"x\":2}}");
                reply.body = SecretVec::new(body);
            }
            9 => {
                reply = Reply::problem(429, "auth.rate_limited", false, true);
                reply.headers.retain(|(name, _)| *name != "ratelimit");
            }
            _ => reply.body = SecretVec::new(vec![b' '; 4097]),
        }
        f.peer.registration_reply(Some(reply), true);
        assert_eq!(
            f.exchange(RegistrationAction::Submit).await,
            Err(RegistrationError::InvalidResponse)
        );
        assert_eq!(f.status().phase, RegistrationPhase::OutcomeUnknown);
        assert_eq!(
            f.exchange(RegistrationAction::Retry).await,
            Err(RegistrationError::RetryUnavailable)
        );
        assert_eq!(f.peer.state.lock().unwrap().requests.len(), 1);
        f.no_authority();
        f.peer.healthy();
    }
}

#[tokio::test]
async fn timed_out_submit_requires_exact_confirmation_and_never_automatic_replay() {
    let f = Fixture::new().await;
    let (reached, release) = f.peer.pause("/api/v1/auth/accounts/register");
    let cancel = RegistrationCancellation::default();
    {
        let exchange = f.server.exchange_registration(
            &f.local,
            f.store.clone(),
            f.status.operation_id,
            RegistrationAction::Submit,
            &cancel,
        );
        tokio::pin!(exchange);
        tokio::select! { _ = &mut exchange => panic!("Submit did not reach the peer"), _ = reached.notified() => {} }
        assert_eq!(exchange.await, Err(RegistrationError::Timeout));
    }
    release.notify_one();
    assert_eq!(f.status().phase, RegistrationPhase::OutcomeUnknown);
    assert_eq!(
        f.exchange(RegistrationAction::Retry).await,
        Err(RegistrationError::RetryUnavailable)
    );
    f.peer.registration_reply(None, false);
    assert_eq!(
        f.exchange(RegistrationAction::Confirm).await.unwrap().phase,
        RegistrationPhase::Committed
    );
    assert_eq!(f.peer.state.lock().unwrap().requests.len(), 2);
    f.no_authority();
    f.peer.healthy();
}
