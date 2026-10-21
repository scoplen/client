// SPDX-License-Identifier: Apache-2.0

use super::*;

const REPLACEMENT: [u8; 32] = [81; 32];

fn replacement(origin: &str) -> Zeroizing<String> {
    Zeroizing::new(format!("{origin}/invite#token={}", URL_SAFE_NO_PAD.encode(REPLACEMENT)))
}

fn denial(status: u16, code: &str, changed: bool, retryable: bool) -> String {
    let problem = scoplen_api::ProblemDetails::new(
        scoplen_api::ErrorCode::new(code).unwrap(),
        status,
        "Authentication failed",
        "The identity is retained. Obtain a fresh challenge before trying again.",
        "fixture-request",
        changed,
        retryable,
    )
    .unwrap();
    problem_response(status, &serde_json::to_vec(&problem).unwrap())
}

fn problem_response(status: u16, body: &[u8]) -> String {
    json_response(status, body)
        .replace("Content-Type: application/json", "Content-Type: application/problem+json")
}

async fn unresolved(server: &Fixture) -> (tempfile::TempDir, Arc<Store>, PersonalServer) {
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = server.manager();
    ready(&manager, &local, &server.origin).await;
    let pending = record(&local).unwrap();
    let request = PersonalEnrollmentRequest::from_json(
        pending.enrollment_request.as_ref().unwrap().as_bytes(),
    )
    .unwrap();
    *server.state.expected_device_key.lock().unwrap() =
        Some(request.device_certificate.signing_public_key);
    assert!(local.claim_personal_enrollment().unwrap());
    (dir, local, manager)
}

#[tokio::test]
async fn explicit_replacement_retains_all_identity_material_across_restart_and_waits_for_join() {
    for changed in [false, true] {
        let server = Fixture::new().await;
        *server.state.device_response.lock().unwrap() =
            Some(denial(401, "auth.authentication_required", changed, false));
        let (dir, local, manager) = unresolved(&server).await;
        let recovery_path = dir.path().join("recovery.txt");
        manager.save_recovery_key(local.clone(), recovery_path.clone()).await.unwrap();
        let recovery = SecretVec::new(std::fs::read(&recovery_path).unwrap());
        let before = record(&local).unwrap();
        let device = local.device_key_pair().unwrap();
        let old_request = PersonalEnrollmentRequest::from_json(
            before.enrollment_request.as_ref().unwrap().as_bytes(),
        )
        .unwrap();

        let ready =
            manager.update_invitation(local.clone(), replacement(&server.origin)).await.unwrap();
        assert_eq!(ready.phase, PersonalServerPhase::ReadyToEnroll);
        assert!(ready.recovery_key_saved && ready.recovery_key_confirmed);
        assert_eq!(server.state.enrollments.load(Ordering::SeqCst), 0);
        assert_eq!(server.state.challenges.load(Ordering::SeqCst), 1);
        assert_eq!(server.state.device_exchanges.load(Ordering::SeqCst), 1);
        assert!(
            !serde_json::to_string(&ready).unwrap().contains(&URL_SAFE_NO_PAD.encode(REPLACEMENT))
        );
        drop(local);
        drop(manager);

        let local = store(&dir);
        let manager = server.manager();
        let after = record(&local).unwrap();
        assert_eq!(manager.status(&local).unwrap(), ready);
        assert_eq!(after.private_material, before.private_material);
        assert_eq!(local.device_key_pair().unwrap(), device);
        assert_eq!(SecretVec::new(std::fs::read(recovery_path).unwrap()), recovery);
        let updated = PersonalEnrollmentRequest::from_json(
            after.enrollment_request.as_ref().unwrap().as_bytes(),
        )
        .unwrap();
        assert_eq!(updated.invitation_token, REPLACEMENT);
        assert_ne!(updated.device_signature, old_request.device_signature);
        let mut expected = old_request;
        expected.invitation_token = REPLACEMENT;
        expected.device_signature = updated.device_signature;
        assert_eq!(updated, expected);

        *server.state.device_response.lock().unwrap() = None;
        *server.state.expected_invitation.lock().unwrap() = Some(REPLACEMENT);
        assert_eq!(manager.submit(local).await.unwrap().phase, PersonalServerPhase::Authenticated);
        assert_eq!(server.state.enrollments.load(Ordering::SeqCst), 1);
        let nonces = server.state.nonces.lock().unwrap();
        assert_eq!(nonces.len(), 2);
        assert_ne!(nonces[0], nonces[1]);
    }
}

#[tokio::test]
async fn fresh_success_authenticates_without_replacing_or_redeeming_the_supplied_link() {
    let server = Fixture::new().await;
    server.state.lose_enrollment_reply.store(true, Ordering::SeqCst);
    server.state.reject_auth.store(true, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let manager = server.manager();
    ready(&manager, &local, &server.origin).await;
    assert_eq!(manager.submit(local.clone()).await, Err(PersonalServerError::Authentication));
    let before = record(&local).unwrap();
    server.state.reject_auth.store(false, Ordering::SeqCst);

    let status =
        manager.update_invitation(local.clone(), replacement(&server.origin)).await.unwrap();
    assert_eq!(status.phase, PersonalServerPhase::Authenticated);
    let after = record(&local).unwrap();
    assert_eq!(after.enrollment_request, before.enrollment_request);
    assert_eq!(after.private_material, before.private_material);
    assert!(after.enrollment_attempted);
    assert_eq!(server.state.enrollments.load(Ordering::SeqCst), 1);
    assert_eq!(server.state.challenges.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn only_the_parsed_device_denial_can_replace_an_invitation() {
    let valid = denial(401, "auth.authentication_required", false, false);
    let body = valid.split_once("\r\n\r\n").unwrap().1;
    let cases = [
        (true, valid.clone()),
        (false, denial(403, "auth.authentication_required", false, false)),
        (false, denial(429, "auth.rate_limited", false, true)),
        (false, denial(500, "auth.authentication_required", false, false)),
        (false, denial(503, "auth.commit_outcome_unknown", true, false)),
        (false, denial(401, "auth.device_revoked", false, false)),
        (false, denial(401, "auth.future_failure", false, false)),
        (false, denial(401, "auth.authentication_required", false, true)),
        (false, problem_response(401, body.replace("\"status\":401", "\"status\":403").as_bytes())),
        (false, problem_response(401, body.replace(",\"changed\":false", "").as_bytes())),
        (false, problem_response(401, body.replace("\"retryable\":false", "\"retryable\":\"false\"").as_bytes())),
        (false, problem_response(401, body.replace("\"code\":", "\"code\":\"auth.device_revoked\",\"code\":").as_bytes())),
        (false, problem_response(401, body.replace("\"title\":\"Authentication failed\"", "\"title\":\"\"").as_bytes())),
        (false, problem_response(401, b"{}")),
        (false, problem_response(401, b"{")),
        (false, valid.replace("application/problem+json", "application/json")),
        (false, valid.replace("Cache-Control: no-store\r\n", "")),
        (false, valid.replace("Pragma: no-cache", "Age: 0\r\nPragma: no-cache")),
        (false, "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/problem+json\r\nCache-Control: no-store\r\nContent-Length: 20000\r\nConnection: close\r\n\r\n".into()),
        (false, "HTTP/1.1 307 Redirect\r\nLocation: https://127.0.0.1:1/leak\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()),
    ];
    for (index, (challenge_stage, response)) in cases.into_iter().enumerate() {
        let server = Fixture::new().await;
        if challenge_stage {
            *server.state.challenge_response.lock().unwrap() = Some(response);
        } else {
            *server.state.device_response.lock().unwrap() = Some(response);
        }
        let (_dir, local, manager) = unresolved(&server).await;
        let before = record(&local).unwrap();
        assert!(
            manager.update_invitation(local.clone(), replacement(&server.origin)).await.is_err(),
            "case {index}"
        );
        let after = record(&local).unwrap();
        assert_eq!(after.enrollment_request, before.enrollment_request, "case {index}");
        assert_eq!(after.private_material, before.private_material, "case {index}");
        assert_eq!(
            manager.status(&local).unwrap().phase,
            PersonalServerPhase::EnrollmentUnconfirmed
        );
        assert_eq!(server.state.enrollments.load(Ordering::SeqCst), 0);
        assert_eq!(server.state.challenges.load(Ordering::SeqCst), 1);
        if challenge_stage {
            assert_eq!(server.state.device_exchanges.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn a_replacement_checks_origin_and_pending_state_before_network_access() {
    let server = Fixture::new().await;
    let (_dir, local, manager) = unresolved(&server).await;
    let before = record(&local).unwrap();
    for link in [replacement("https://other.example"), Zeroizing::new("malformed".into())] {
        assert_eq!(
            manager.update_invitation(local.clone(), link).await,
            Err(PersonalServerError::Invitation)
        );
    }
    assert_eq!(server.state.challenges.load(Ordering::SeqCst), 0);
    assert_eq!(record(&local).unwrap().enrollment_request, before.enrollment_request);
    let held = manager.operation.lock().await;
    assert_eq!(
        manager.update_invitation(local.clone(), replacement(&server.origin)).await,
        Err(PersonalServerError::Busy)
    );
    drop(held);
    local.release_unsent_personal_enrollment().unwrap();
    assert_eq!(
        manager.update_invitation(local, replacement(&server.origin)).await,
        Err(PersonalServerError::AlreadyConfigured)
    );
    assert_eq!(server.state.challenges.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn untrusted_tls_connection_loss_and_timeout_never_replace_the_request() {
    let mut server = Fixture::new().await;
    let (_dir, local, manager) = unresolved(&server).await;
    let before = record(&local).unwrap();
    assert_eq!(
        PersonalServer::default()
            .update_invitation(local.clone(), replacement(&server.origin))
            .await,
        Err(PersonalServerError::ConnectionBeforeRequest)
    );
    assert_eq!(server.state.challenges.load(Ordering::SeqCst), 0);
    server.state.stall_device.store(true, Ordering::SeqCst);
    assert_eq!(
        manager.update_invitation(local.clone(), replacement(&server.origin)).await,
        Err(PersonalServerError::Network)
    );
    let origin = server.origin.clone();
    server.task.abort();
    assert!((&mut server.task).await.unwrap_err().is_cancelled());
    drop(server);
    assert!(matches!(
        manager.update_invitation(local.clone(), replacement(&origin)).await,
        Err(PersonalServerError::ConnectionBeforeRequest | PersonalServerError::Network)
    ));
    assert_eq!(record(&local).unwrap().enrollment_request, before.enrollment_request);
    assert_eq!(manager.status(&local).unwrap().phase, PersonalServerPhase::EnrollmentUnconfirmed);
}

#[tokio::test]
async fn invalid_or_mismatched_access_tokens_do_not_enable_replacement() {
    for wrong_account in [false, true] {
        let server = Fixture::new().await;
        let dir = tempfile::tempdir().unwrap();
        let local = store(&dir);
        let manager = server.manager();
        ready(&manager, &local, &server.origin).await;
        manager.submit(local.clone()).await.unwrap();
        let before = record(&local).unwrap();
        if wrong_account {
            server.state.wrong_account.store(true, Ordering::SeqCst);
        } else {
            server.state.tamper_access_token.store(true, Ordering::SeqCst);
        }
        assert_eq!(
            manager.update_invitation(local.clone(), replacement(&server.origin)).await,
            Err(PersonalServerError::InvalidResponse)
        );
        let after = record(&local).unwrap();
        assert_eq!(after.enrollment_request, before.enrollment_request);
        assert_eq!(after.private_material, before.private_material);
        assert_eq!(after.access_expires_at, None);
        assert_eq!(server.state.enrollments.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn replacement_cannot_overwrite_a_changed_request_or_verified_credentials() {
    let server = Fixture::new().await;
    let (_dir, local, manager) = unresolved(&server).await;
    let before = record(&local).unwrap();
    let expected = before.enrollment_request.as_ref().unwrap();
    let replacement = identity::replace_invitation(
        &local,
        &before,
        Invitation::parse(&replacement(&server.origin)).unwrap(),
    )
    .unwrap();
    assert!(
        !local
            .replace_personal_invitation(&SecretVec::new(b"stale".to_vec()), &replacement)
            .unwrap()
    );
    local
        .save_personal_tokens(b"access", b"refresh", now().unwrap() + 600, now().unwrap() + 3600)
        .unwrap();
    assert!(!local.replace_personal_invitation(expected, &replacement).unwrap());
    assert_eq!(manager.status(&local).unwrap().phase, PersonalServerPhase::Authenticated);
    assert_eq!(record(&local).unwrap().enrollment_request.as_ref(), Some(expected));
}

#[tokio::test]
async fn missing_retained_artifacts_never_regenerate_identity() {
    let server = Fixture::new().await;
    *server.state.device_response.lock().unwrap() =
        Some(denial(401, "auth.authentication_required", false, false));
    let (dir, local, manager) = unresolved(&server).await;
    let before = record(&local).unwrap();
    let connection = rusqlite::Connection::open(dir.path().join("personal.db")).unwrap();
    connection.pragma_update(None, "key", format!("x'{}'", "1b".repeat(32))).unwrap();
    connection.execute("UPDATE personal_server SET enrollment_request = NULL", []).unwrap();
    drop(connection);
    assert_eq!(
        manager.update_invitation(local.clone(), replacement(&server.origin)).await,
        Err(PersonalServerError::Identity)
    );
    let after = record(&local).unwrap();
    assert_eq!(after.private_material, before.private_material);
    assert_eq!(after.account_id, before.account_id);
    assert_eq!(after.personal_vault_id, before.personal_vault_id);
    assert!(after.enrollment_attempted);
    assert!(after.enrollment_request.is_none());
    assert_eq!(server.state.enrollments.load(Ordering::SeqCst), 0);
}
