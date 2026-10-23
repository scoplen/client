// SPDX-License-Identifier: Apache-2.0
//! Independent TLS 1.3/H2 peer for native single-use refresh and fresh recovery.

use std::collections::VecDeque;

use scoplen_api::{
    ErrorCode, ProblemDetails,
    auth::{
        AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthRefreshRequest,
        AuthTokenResponse, INITIAL_DEVICE_ACCESS_SCOPE,
    },
};
use scoplen_crypto::{DeviceAuthContext, p256_verify};

use super::*;
use crate::personal_server::PersonalServerPhase;

#[derive(Default)]
enum Mode {
    #[default]
    Success,
    Narrow,
    MissingScope,
    ForeignAccount,
    ForeignDevice,
    ForeignKey,
    ForeignIssuer,
    InvalidSignature,
    ExpiredAccess,
    LongerLifetime,
    ShorterLifetime,
    MaximumLifetime,
    SameRefresh,
    OversizedRefresh,
    Lost,
    Nonce,
    Reply(Reply),
}

pub(super) struct RefreshPeer {
    observer: Arc<Store>,
    account: uuid::Uuid,
    current: String,
    family_expires: u64,
    modes: VecDeque<Mode>,
    calls: usize,
    nonce: Option<String>,
    challenges: usize,
    devices: usize,
}

impl RefreshPeer {
    pub(super) fn answer(
        &mut self,
        request: &http::Request<h2::RecvStream>,
        body: &[u8],
        expected: &mut Expected,
        proofs: &mut HashSet<String>,
        origin: &str,
    ) -> Result<Reply, String> {
        if request.method() != http::Method::POST
            || request.headers().contains_key("authorization")
            || request.headers().contains_key("origin")
            || request.headers().get("content-type").and_then(|value| value.to_str().ok())
                != Some("application/json")
        {
            return Err("invalid native auth request".into());
        }
        match request.uri().path() {
            "/api/v1/auth/challenge" => {
                let request =
                    AuthChallengeRequest::from_json(std::str::from_utf8(body).unwrap()).unwrap();
                if request.device_id != expected.device {
                    return Err("wrong challenge identity".into());
                }
                self.challenges += 1;
                self.nonce = Some(format!("{:064x}", self.challenges));
                Ok(json(
                    AuthChallengeResponse::new(self.nonce.clone().unwrap(), "2026-10-23T00:00:00Z")
                        .unwrap()
                        .to_json()
                        .unwrap()
                        .into_bytes(),
                ))
            }
            "/api/v1/auth/device" => {
                let request =
                    AuthDeviceRequest::from_json(std::str::from_utf8(body).unwrap()).unwrap();
                if request.device_id != expected.device
                    || Some(&request.nonce) != self.nonce.as_ref()
                {
                    return Err("wrong device exchange".into());
                }
                let signature: Vec<_> = (0..128)
                    .step_by(2)
                    .map(|offset| {
                        u8::from_str_radix(&request.signature[offset..offset + 2], 16).unwrap()
                    })
                    .collect();
                p256_verify(
                    &expected.signing_public,
                    &DeviceAuthContext::new(origin, &request.nonce, expected.device)
                        .unwrap()
                        .signature_input(),
                    &signature,
                )
                .map_err(|_| "bad device signature")?;
                self.nonce = None;
                self.devices += 1;
                self.family_expires = now().unwrap() + 3600;
                Ok(self.tokens(expected, origin, Mode::Success))
            }
            "/api/v1/auth/refresh" => {
                if record(&self.observer).unwrap().refresh_available
                    || self.observer.personal_access_token(now().unwrap()).unwrap().is_some()
                {
                    return Err("refresh reached server before durable claim".into());
                }
                let request_body =
                    AuthRefreshRequest::from_json(std::str::from_utf8(body).unwrap())
                        .map_err(|_| "bad native refresh body")?;
                if request_body.refresh_token != self.current {
                    return Err("spent or wrong refresh credential".into());
                }
                let proof = request
                    .headers()
                    .get("dpop")
                    .and_then(|value| value.to_str().ok())
                    .ok_or("missing refresh proof")?;
                let segments: Vec<_> = proof.split('.').collect();
                let claims: serde_json::Value =
                    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
                if claims.get("ath").is_some() {
                    return Err("refresh proof leaked access token hash".into());
                }
                let verified = DpopProof::parse(proof)
                    .unwrap()
                    .verify(
                        &DpopTarget::new("POST", origin, "/api/v1/auth/refresh").unwrap(),
                        DpopToken::Refresh,
                        &expected.jkt,
                        now().unwrap(),
                        self.nonce.as_deref(),
                    )
                    .map_err(|_| "bad refresh proof binding")?;
                if !proofs.insert(verified.jti) {
                    return Err("replayed refresh proof".into());
                }
                self.calls += 1;
                let mode = self.modes.pop_front().unwrap_or_default();
                match mode {
                    Mode::Nonce => {
                        self.nonce = Some("fixture-dpop-nonce".into());
                        let mut reply = problem(400, "auth.use_dpop_nonce", false, true);
                        reply.headers.push(("dpop-nonce", self.nonce.clone().unwrap()));
                        Ok(reply)
                    }
                    Mode::Reply(reply) => Ok(reply),
                    Mode::Lost => {
                        let mut reply = self.tokens(expected, origin, Mode::Success);
                        reply.stall = true;
                        Ok(reply)
                    }
                    mode => Ok(self.tokens(expected, origin, mode)),
                }
            }
            _ => Err("unknown auth route".into()),
        }
    }

    fn tokens(&mut self, expected: &mut Expected, origin: &str, mode: Mode) -> Reply {
        let authority = Ed25519SigningKey::from_bytes(&[55; 32]).unwrap();
        let issued_at = now().unwrap();
        let mut claims = DeviceAccessTokenClaims {
            iss: origin.into(),
            sub: self.account,
            did: expected.device,
            jti: scoplen_model::new_uuid_v7().unwrap(),
            cnf_jkt: expected.jkt.clone(),
            org: vec![],
            scope: INITIAL_DEVICE_ACCESS_SCOPE.into(),
            iat: issued_at,
            exp: issued_at + 600,
        };
        let mut key = expected.signing_public.clone();
        match mode {
            Mode::Narrow => claims.scope = "keys:read sync:read sync:write".into(),
            Mode::MissingScope => claims.scope = "account:read".into(),
            Mode::ForeignAccount => claims.sub = scoplen_model::new_uuid_v7().unwrap(),
            Mode::ForeignDevice => claims.did = scoplen_model::new_uuid_v7().unwrap(),
            Mode::ForeignKey => {
                key = P256SigningKey::from_bytes(&[77; 32]).unwrap().public_key_sec1();
                claims.cnf_jkt = dpop_jwk_thumbprint(&key).unwrap();
            }
            Mode::ForeignIssuer => claims.iss = "https://foreign.example".into(),
            Mode::ExpiredAccess => {
                claims.iat -= 1200;
                claims.exp = claims.iat + 600;
            }
            _ => {}
        }
        let mut trusted = TrustedDeviceAccessTokenKeys::new(&claims.iss).unwrap();
        trusted.insert("fixture", &authority.public_key()).unwrap();
        let token =
            DeviceAccessToken::sign(&authority, &trusted, "fixture", &key, &claims).unwrap();
        let mut token = token.as_str().to_owned();
        if matches!(mode, Mode::InvalidSignature) {
            let offset = token.rfind('.').unwrap() + 1;
            let replacement = if token.as_bytes()[offset] == b'A' { "B" } else { "A" };
            token.replace_range(offset..offset + 1, replacement);
        }
        let previous = self.current.clone();
        self.current = format!("fixture-refresh-{}-{}", self.challenges, self.calls);
        let mut response = AuthTokenResponse::new(&token, &self.current).unwrap();
        response.refresh_expires_in = self.family_expires.saturating_sub(claims.iat).max(1);
        if matches!(mode, Mode::LongerLifetime) {
            response.refresh_expires_in += 2;
        }
        if matches!(mode, Mode::ShorterLifetime) {
            response.refresh_expires_in -= 60;
        }
        if matches!(mode, Mode::MaximumLifetime) {
            response.refresh_expires_in = u64::MAX;
        }
        if matches!(mode, Mode::SameRefresh) {
            response.refresh_token = previous;
        }
        if matches!(mode, Mode::OversizedRefresh) {
            response.refresh_token = "x".repeat(2049);
        }
        expected.token = Zeroizing::new(token);
        json(response.to_json().unwrap().into_bytes())
    }
}

fn json(body: Vec<u8>) -> Reply {
    Reply {
        content_type: "application/json",
        headers: vec![("cache-control", "no-store".into()), ("pragma", "no-cache".into())],
        ..Reply::cbor(body)
    }
}

fn problem(status: u16, code: &str, changed: bool, retryable: bool) -> Reply {
    let body = ProblemDetails::new(
        ErrorCode::new(code).unwrap(),
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
        ..json(serde_json::to_vec(&body).unwrap())
    }
}

fn install(peer: &Peer, store: &Arc<Store>, modes: Vec<Mode>) {
    let pending = record(store).unwrap();
    peer.state.lock().unwrap().refresh = Some(RefreshPeer {
        observer: store.clone(),
        account: pending.account_id,
        current: "refresh".into(),
        family_expires: pending.refresh_expires_at.unwrap(),
        modes: modes.into(),
        calls: 0,
        nonce: None,
        challenges: 0,
        devices: 0,
    });
    due(store);
}

fn due(store: &Store) {
    let mut identity = record(store).unwrap();
    identity.access_expires_at = Some(now().unwrap().saturating_sub(1));
    store.set_personal_session_metadata_for_test(&identity).unwrap();
}
fn calls(peer: &Peer) -> usize {
    peer.state.lock().unwrap().refresh.as_ref().unwrap().calls
}

#[tokio::test]
async fn expired_access_refreshes_once_and_new_credentials_survive_restart() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    manager.bootstrap_sync(store.clone()).await.unwrap();
    let expiry = record(&store).unwrap().refresh_expires_at.unwrap();
    install(&peer, &store, vec![Mode::Narrow]);
    let paths = peer.state.lock().unwrap().paths.len();
    assert_eq!(manager.status(&store).unwrap().phase, PersonalServerPhase::Authenticated);
    assert!(manager.load_sync_bootstrap(&store).unwrap().is_some());
    assert_eq!(peer.state.lock().unwrap().paths.len(), paths);
    manager.bootstrap_sync(store.clone()).await.unwrap();
    assert_eq!(calls(&peer), 1);
    let saved = record(&store).unwrap();
    assert_eq!(saved.auth_scope.as_deref(), Some("keys:read sync:read sync:write"));
    assert_eq!(saved.refresh_expires_at, Some(expiry));
    manager.bootstrap_sync(store.clone()).await.unwrap();
    assert_eq!(calls(&peer), 1);
    drop(store);
    let store = local(&dir);
    manager.bootstrap_sync(store.clone()).await.unwrap();
    assert_eq!(calls(&peer), 1);
    assert!(!serde_json::to_string(&manager.status(&store).unwrap()).unwrap().contains("refresh"));
    let file = std::fs::read(dir.path().join("personal.db")).unwrap();
    assert!(!file.windows(b"fixture-refresh".len()).any(|window| window == b"fixture-refresh"));
    // A later issuance cannot regain a scope that this family has already lost.
    due(&store);
    assert!(matches!(
        manager.bootstrap_sync(store.clone()).await,
        Err(PersonalSyncError::Personal(PersonalServerError::InvalidResponse))
    ));
    assert_eq!(calls(&peer), 2);
    peer.assert_healthy();
}

#[tokio::test]
async fn nonce_challenge_uses_one_new_proof_and_never_reuses_a_spent_credential() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![Mode::Nonce, Mode::Success]);
    manager.bootstrap_sync(store.clone()).await.unwrap();
    assert_eq!(calls(&peer), 2);
    assert_eq!(peer.state.lock().unwrap().proofs.len(), 5);
    peer.assert_healthy();
}

#[tokio::test]
async fn rounded_refresh_lifetimes_schedule_without_extending_the_retained_family() {
    for mode in [Mode::Success, Mode::LongerLifetime, Mode::MaximumLifetime, Mode::ShorterLifetime]
    {
        let shorter = matches!(mode, Mode::ShorterLifetime);
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = peer.prepare(&store).await;
        install(&peer, &store, vec![mode]);
        let mut before = record(&store).unwrap();
        let peer_deadline = before.refresh_expires_at.unwrap();
        // Deterministically model an initial estimate one second before the server's
        // deadline, without relying on wall-clock sleeps or changing the signed JWT.
        before.refresh_expires_at = Some(peer_deadline - 1);
        store.set_personal_session_metadata_for_test(&before).unwrap();
        manager.bootstrap_sync(store.clone()).await.unwrap();
        let after = record(&store).unwrap();
        assert_eq!(
            after.refresh_expires_at,
            Some(if shorter { peer_deadline - 60 } else { peer_deadline - 1 })
        );
        assert!(after.auth_generation > before.auth_generation);
        assert!(after.refresh_available);
        assert!(store.personal_access_token(now().unwrap()).unwrap().is_some());
        manager.bootstrap_sync(store.clone()).await.unwrap();
        assert_eq!(calls(&peer), 1);
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn lost_reply_unknown_commit_and_revocation_require_fresh_challenge_without_replay() {
    for mode in [
        Mode::Lost,
        Mode::Reply(problem(503, "auth.commit_outcome_unknown", true, false)),
        Mode::Reply(problem(401, "auth.authentication_required", true, false)),
    ] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = peer.prepare(&store).await;
        manager.bootstrap_sync(store.clone()).await.unwrap();
        install(&peer, &store, vec![mode]);
        assert!(matches!(
            manager.bootstrap_sync(store.clone()).await,
            Err(PersonalSyncError::AuthenticationRequired)
        ));
        assert_eq!(calls(&peer), 1);
        assert_eq!(
            manager.status(&store).unwrap().phase,
            PersonalServerPhase::AuthenticationRequired
        );
        drop(store);
        let store = local(&dir);
        assert!(matches!(
            manager.bootstrap_sync(store.clone()).await,
            Err(PersonalSyncError::AuthenticationRequired)
        ));
        assert_eq!(calls(&peer), 1);
        assert!(manager.load_sync_bootstrap(&store).unwrap().is_some());
        let identity = record(&store).unwrap().private_material;
        manager.authenticate(store.clone()).await.unwrap();
        assert_eq!(record(&store).unwrap().private_material.as_bytes(), identity.as_bytes());
        manager.bootstrap_sync(store.clone()).await.unwrap();
        let state = peer.state.lock().unwrap();
        let auth = state.refresh.as_ref().unwrap();
        assert_eq!((auth.calls, auth.challenges, auth.devices), (1, 1, 1));
        drop(state);
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn mismatched_or_invalid_rotated_credentials_are_never_accepted_or_replayed() {
    for mode in [
        Mode::ForeignAccount,
        Mode::ForeignDevice,
        Mode::ForeignKey,
        Mode::ForeignIssuer,
        Mode::InvalidSignature,
        Mode::ExpiredAccess,
        Mode::SameRefresh,
        Mode::OversizedRefresh,
        Mode::Reply(json(b"{}".to_vec())),
    ] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = peer.prepare(&store).await;
        manager.bootstrap_sync(store.clone()).await.unwrap();
        install(&peer, &store, vec![mode]);
        assert!(matches!(
            manager.bootstrap_sync(store.clone()).await,
            Err(PersonalSyncError::Personal(PersonalServerError::InvalidResponse))
        ));
        assert_eq!(calls(&peer), 1);
        assert!(store.personal_access_token(now().unwrap()).unwrap().is_none());
        assert!(matches!(
            manager.bootstrap_sync(store.clone()).await,
            Err(PersonalSyncError::AuthenticationRequired)
        ));
        assert_eq!(calls(&peer), 1);
        assert!(manager.load_sync_bootstrap(&store).unwrap().is_some());
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn narrowed_scope_rejects_the_operation_without_sending_protected_requests() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![Mode::MissingScope]);
    assert!(matches!(
        manager.bootstrap_sync(store.clone()).await,
        Err(PersonalSyncError::Personal(PersonalServerError::PermissionDenied))
    ));
    assert_eq!(calls(&peer), 1);
    assert_eq!(record(&store).unwrap().auth_scope.as_deref(), Some("account:read"));
    assert!(!peer.state.lock().unwrap().paths.iter().any(|path| path.starts_with("/sync/")));
    peer.assert_healthy();
}

#[tokio::test]
async fn exact_unchanged_failures_restore_credentials_for_later_explicit_retry() {
    for mode in [Mode::Reply(problem(503, "auth.storage_unavailable", false, true)), Mode::Nonce] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = peer.prepare(&store).await;
        let modes =
            if matches!(mode, Mode::Nonce) { vec![Mode::Nonce, Mode::Nonce] } else { vec![mode] };
        install(&peer, &store, modes);
        assert!(matches!(
            manager.bootstrap_sync(store.clone()).await,
            Err(PersonalSyncError::Personal(PersonalServerError::RefreshDeferred))
        ));
        let count = calls(&peer);
        assert!(record(&store).unwrap().refresh_available);
        if count == 1 {
            manager.bootstrap_sync(store.clone()).await.unwrap();
            assert_eq!(calls(&peer), count + 1);
        } else {
            assert_eq!(count, 2);
        }
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn rate_limit_wait_is_durable_and_never_automatically_retried() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let mut response = problem(429, "auth.rate_limited", false, true);
    response.headers.push(("retry-after", "60".into()));
    install(&peer, &store, vec![Mode::Reply(response)]);
    assert!(matches!(
        manager.bootstrap_sync(store.clone()).await,
        Err(PersonalSyncError::Personal(PersonalServerError::RefreshDeferred))
    ));
    assert_eq!(calls(&peer), 1);
    drop(store);
    let store = local(&dir);
    assert!(matches!(
        manager.bootstrap_sync(store.clone()).await,
        Err(PersonalSyncError::Personal(PersonalServerError::RefreshDeferred))
    ));
    assert_eq!(calls(&peer), 1);
    let mut identity = record(&store).unwrap();
    identity.refresh_retry_at = None;
    store.set_personal_session_metadata_for_test(&identity).unwrap();
    manager.bootstrap_sync(store.clone()).await.unwrap();
    assert_eq!(calls(&peer), 2);
    peer.assert_healthy();
}

#[tokio::test]
async fn invalid_rate_limit_delays_never_restore_a_single_use_credential() {
    for values in [
        vec!["0"],
        vec!["301"],
        vec!["18446744073709551616"],
        vec!["Fri, 23 Oct 2026 23:59:59 GMT"],
        vec!["60", "60"],
        vec!["060"],
        vec!["+60"],
        vec!["60, 60"],
    ] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = peer.prepare(&store).await;
        let mut response = problem(429, "auth.rate_limited", false, true);
        response.headers.extend(values.into_iter().map(|value| ("retry-after", value.into())));
        install(&peer, &store, vec![Mode::Reply(response)]);
        assert!(matches!(
            manager.bootstrap_sync(store.clone()).await,
            Err(PersonalSyncError::AuthenticationRequired)
        ));
        assert_eq!(calls(&peer), 1);
        let identity = record(&store).unwrap();
        assert!(!identity.refresh_available);
        assert_eq!(identity.refresh_retry_at, None);
        assert!(matches!(
            manager.bootstrap_sync(store.clone()).await,
            Err(PersonalSyncError::AuthenticationRequired)
        ));
        assert_eq!(calls(&peer), 1);
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn competing_processes_and_cancelled_tasks_cannot_send_the_same_refresh_twice() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    manager.bootstrap_sync(store.clone()).await.unwrap();
    install(&peer, &store, vec![Mode::Lost]);
    let other = local(&dir);
    let task_store = store.clone();
    let task = tokio::spawn(async move { manager.bootstrap_sync(task_store).await });
    tokio::time::timeout(Duration::from_secs(3), async {
        while calls(&peer) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        peer.manager().bootstrap_sync(other.clone()).await,
        Err(PersonalSyncError::AuthenticationRequired)
    ));
    assert_eq!(calls(&peer), 1);
    task.abort();
    let _ = task.await;
    drop(store);
    drop(other);
    let store = local(&dir);
    assert!(matches!(
        peer.manager().bootstrap_sync(store.clone()).await,
        Err(PersonalSyncError::AuthenticationRequired)
    ));
    assert!(peer.manager().load_sync_bootstrap(&store).unwrap().is_some());
    peer.manager().authenticate(store.clone()).await.unwrap();
    peer.manager().bootstrap_sync(store.clone()).await.unwrap();
    assert_eq!(calls(&peer), 1);
    peer.assert_healthy();
}

#[tokio::test]
async fn invalid_failure_headers_or_nonce_never_allow_credential_replay() {
    let mut cached = problem(400, "auth.use_dpop_nonce", false, true);
    cached.headers.extend([("dpop-nonce", "fixture".into()), ("age", "0".into())]);
    let mut missing_nonce = problem(400, "auth.use_dpop_nonce", false, true);
    missing_nonce.headers.push(("dpop-nonce", "invalid nonce".into()));
    let mut duplicate_nonce = problem(400, "auth.use_dpop_nonce", false, true);
    duplicate_nonce
        .headers
        .extend([("dpop-nonce", "fixture".into()), ("dpop-nonce", "fixture".into())]);
    let mut no_pragma = problem(503, "auth.storage_unavailable", false, true);
    no_pragma.headers.retain(|(name, _)| *name != "pragma");
    let mut oversized = json(vec![b'x'; 16385]);
    oversized.status = 503;
    let mut non_problem = problem(400, "auth.use_dpop_nonce", false, true);
    non_problem.content_type = "application/json";
    let mut changed_nonce = problem(400, "auth.use_dpop_nonce", true, true);
    changed_nonce.headers.push(("dpop-nonce", "fixture".into()));
    for response in [
        cached,
        missing_nonce,
        duplicate_nonce,
        no_pragma,
        oversized,
        non_problem,
        changed_nonce,
        problem(503, "auth.storage_unavailable", true, true),
        problem(400, "auth.use_dpop_nonce", false, true),
        problem(429, "auth.rate_limited", false, true),
    ] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = peer.prepare(&store).await;
        install(&peer, &store, vec![Mode::Reply(response)]);
        assert!(manager.bootstrap_sync(store.clone()).await.is_err());
        assert_eq!(calls(&peer), 1);
        assert!(!record(&store).unwrap().refresh_available);
        assert!(matches!(
            manager.bootstrap_sync(store.clone()).await,
            Err(PersonalSyncError::AuthenticationRequired)
        ));
        assert_eq!(calls(&peer), 1);
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn expired_family_or_legacy_session_uses_no_refresh_and_early_refresh_waits_for_an_explicit_operation()
 {
    for legacy in [false, true] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        let manager = peer.prepare(&store).await;
        manager.bootstrap_sync(store.clone()).await.unwrap();
        install(&peer, &store, vec![]);
        let mut identity = record(&store).unwrap();
        if legacy {
            identity.auth_scope = None;
        } else {
            identity.refresh_expires_at = Some(now().unwrap());
        }
        store.set_personal_session_metadata_for_test(&identity).unwrap();
        let requests = peer.state.lock().unwrap().paths.len();
        assert_eq!(
            manager.status(&store).unwrap().phase,
            PersonalServerPhase::AuthenticationRequired
        );
        assert!(manager.load_sync_bootstrap(&store).unwrap().is_some());
        assert!(matches!(
            manager.bootstrap_sync(store.clone()).await,
            Err(PersonalSyncError::AuthenticationRequired)
        ));
        assert_eq!(calls(&peer), 0);
        assert_eq!(peer.state.lock().unwrap().paths.len(), requests);
        peer.assert_healthy();
    }
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store, vec![]);
    let mut identity = record(&store).unwrap();
    identity.access_expires_at = Some(now().unwrap() + 59);
    store.set_personal_session_metadata_for_test(&identity).unwrap();
    assert_eq!(calls(&peer), 0);
    manager.status(&store).unwrap();
    assert_eq!(calls(&peer), 0);
    manager.bootstrap_sync(store.clone()).await.unwrap();
    assert_eq!(calls(&peer), 1);
    peer.assert_healthy();
}
