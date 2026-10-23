// SPDX-License-Identifier: Apache-2.0

use super::*;

#[tokio::test]
async fn failed_first_create_allows_correcting_metadata_with_the_same_durable_device_keys() {
    let (peer, _old_dir, _new_dir, _old, new, _old_manager, new_manager) = setup().await;
    let wrong_origin = peer.origin.replacen("127.0.0.1", "localhost", 1);
    assert!(matches!(
        new_manager.pairing_create(new.clone(), wrong_origin, "Mistyped name".into()).await,
        Err(PairingError::Personal(_))
    ));
    let original = new.pairing_device().unwrap().unwrap();
    assert!(new.pairing_record().unwrap().is_none());
    assert!(new.personal_record().unwrap().is_none());
    assert_eq!(new_manager.pairing_status(&new).unwrap().phase, PairingPhase::Idle);
    peer.state.lock().unwrap().pairing.as_mut().unwrap().bad_headers = true;
    assert!(matches!(
        new_manager.pairing_create(new.clone(), peer.origin.clone(), "New desktop".into()).await,
        Err(PairingError::Personal(PersonalServerError::InvalidResponse))
    ));
    assert!(new.pairing_record().unwrap().is_none());
    peer.state.lock().unwrap().pairing.as_mut().unwrap().bad_headers = false;
    let started = new_manager
        .pairing_create(new.clone(), peer.origin.clone(), "New desktop".into())
        .await
        .unwrap();
    assert_eq!(started.status.phase, PairingPhase::Waiting);
    assert_eq!(started.status.device_name.as_deref(), Some("New desktop"));
    let retained = new.pairing_device().unwrap().unwrap();
    assert_eq!(retained.origin, peer.origin);
    assert_eq!(retained.device_name, "New desktop");
    assert!(retained.signing.as_bytes() == original.signing.as_bytes());
    assert!(retained.kem.as_bytes() == original.kem.as_bytes());
    assert_eq!(retained.created_at, original.created_at);
    let requests = peer.state.lock().unwrap().paths.len();
    assert!(matches!(
        new_manager.pairing_create(new.clone(), peer.origin.clone(), "Changed name".into()).await,
        Err(PairingError::InvalidInput)
    ));
    assert!(matches!(
        new_manager
            .pairing_create(new.clone(), "https://other.example".into(), "New desktop".into())
            .await,
        Err(PairingError::InvalidInput)
    ));
    assert_eq!(peer.state.lock().unwrap().paths.len(), requests);
    peer.assert_healthy();
}

#[tokio::test]
async fn unclaimed_cancelled_session_stops_before_password_attempt() {
    let (peer, _old_dir, _new_dir, _old, new, _old_manager, new_manager) = setup().await;
    new_manager
        .pairing_create(new.clone(), peer.origin.clone(), "New desktop".into())
        .await
        .unwrap();
    peer.state.lock().unwrap().pairing.as_mut().unwrap().cancelled = true;
    assert_eq!(new_manager.pairing_progress(new.clone()).await, Err(PairingError::Expired));
    assert_eq!(new_manager.pairing_status(&new).unwrap().phase, PairingPhase::RestartRequired);
    assert!(!new.pairing_record().unwrap().unwrap().attempt_started);
    assert!(new.personal_record().unwrap().is_none());
    peer.assert_healthy();
}

#[tokio::test]
async fn old_restart_after_handoff_accepts_only_saved_plan_and_new_possession() {
    let (peer, _old_dir, _new_dir, old, new, old_manager, new_manager) = setup().await;
    to_confirmation(&peer, &old, &new, &old_manager, &new_manager).await;
    old_manager.pairing_confirm(old.clone()).await.unwrap();
    drop(old_manager);
    new_manager.pairing_progress(new.clone()).await.unwrap();
    let restarted = peer.manager();
    assert_eq!(
        restarted.pairing_recover(old.clone()).await.unwrap().phase,
        PairingPhase::Completed
    );
    assert_eq!(
        new_manager.pairing_progress(new.clone()).await.unwrap().phase,
        PairingPhase::Completed
    );
    let saved = old.pairing_record().unwrap().unwrap();
    assert!(saved.acceptance.is_some());
    assert_eq!(
        saved.approval_request.as_ref().unwrap().as_bytes(),
        peer.state.lock().unwrap().pairing.as_ref().unwrap().complete_bodies[0]
    );
    peer.assert_healthy();
}

async fn uncertain_complete(committed: bool) {
    let (peer, _old_dir, _new_dir, old, new, old_manager, new_manager) = setup().await;
    to_confirmation(&peer, &old, &new, &old_manager, &new_manager).await;
    old_manager.pairing_confirm(old.clone()).await.unwrap();
    new_manager.pairing_progress(new.clone()).await.unwrap();
    {
        let mut state = peer.state.lock().unwrap();
        let relay = state.pairing.as_mut().unwrap();
        relay.lose_complete = true;
        relay.commit_before_loss = committed;
    }
    assert_eq!(
        old_manager.pairing_progress(old.clone()).await,
        Err(PairingError::Personal(PersonalServerError::Network))
    );
    let saved = old.pairing_record().unwrap().unwrap();
    assert_eq!(saved.phase, "admission_unconfirmed");
    let approved = saved.approval_request.unwrap();
    drop(old_manager);
    assert_eq!(
        peer.manager().pairing_recover(old.clone()).await.unwrap().phase,
        PairingPhase::Completed
    );
    {
        let state = peer.state.lock().unwrap();
        let relay = state.pairing.as_ref().unwrap();
        assert_eq!(relay.complete_bodies.len(), if committed { 1 } else { 2 });
        assert!(relay.complete_bodies.iter().all(|body| body == approved.as_bytes()));
    }
    assert_eq!(
        new_manager.pairing_progress(new.clone()).await.unwrap().phase,
        PairingPhase::Completed
    );
    peer.assert_healthy();
}

#[tokio::test]
async fn unknown_complete_reads_receipt_before_replaying_exact_saved_json() {
    uncertain_complete(false).await;
}

#[tokio::test]
async fn committed_complete_with_lost_reply_recovers_receipt_without_replay() {
    uncertain_complete(true).await;
}

#[tokio::test]
async fn new_restart_after_atomic_checkpoint_replays_only_exact_saved_acceptance() {
    let (peer, _old_dir, _new_dir, old, new, old_manager, new_manager) = setup().await;
    to_confirmation(&peer, &old, &new, &old_manager, &new_manager).await;
    old_manager.pairing_confirm(old.clone()).await.unwrap();
    peer.state.lock().unwrap().pairing.as_mut().unwrap().lose_acceptance = true;
    assert_eq!(
        new_manager.pairing_progress(new.clone()).await,
        Err(PairingError::Personal(PersonalServerError::Network))
    );
    let before = record(&new).unwrap();
    let acceptance = new.pairing_record().unwrap().unwrap().acceptance.unwrap();
    drop(new_manager);
    let restarted = peer.manager();
    assert_eq!(
        restarted.pairing_recover(new.clone()).await.unwrap().phase,
        PairingPhase::WaitingAcceptance
    );
    assert_eq!(
        old_manager.pairing_progress(old.clone()).await.unwrap().phase,
        PairingPhase::Completed
    );
    assert_eq!(
        restarted.pairing_progress(new.clone()).await.unwrap().phase,
        PairingPhase::Completed
    );
    let after = record(&new).unwrap();
    assert!(before.private_material.as_bytes() == after.private_material.as_bytes());
    assert_eq!(
        peer.state.lock().unwrap().pairing.as_ref().unwrap().messages[6].payload,
        acceptance.as_bytes()
    );
    assert!(after.enrollment_request.is_none());
    peer.assert_healthy();
}

#[tokio::test]
async fn restart_before_handoff_requires_fresh_session_but_retains_new_device_keys() {
    let (peer, _old_dir, _new_dir, _old, new, _old_manager, manager) = setup().await;
    let first = manager
        .pairing_create(new.clone(), peer.origin.clone(), "New desktop".into())
        .await
        .unwrap();
    let before = new.pairing_device().unwrap().unwrap();
    drop(manager);
    let restarted = peer.manager();
    assert_eq!(restarted.pairing_status(&new).unwrap().phase, PairingPhase::RestartRequired);
    assert_eq!(restarted.pairing_recover(new.clone()).await, Err(PairingError::RestartRequired));
    let second = restarted
        .pairing_create(new.clone(), peer.origin.clone(), "New desktop".into())
        .await
        .unwrap();
    assert_ne!(first.status.public_link, second.status.public_link);
    let after = new.pairing_device().unwrap().unwrap();
    assert!(before.signing.as_bytes() == after.signing.as_bytes());
    assert!(before.kem.as_bytes() == after.kem.as_bytes());
    assert_eq!(before.created_at, after.created_at);
    peer.assert_healthy();
}

#[tokio::test]
async fn wrong_password_fails_confirmation_before_any_device_material_or_identity() {
    let (peer, _old_dir, _new_dir, old, new, old_manager, new_manager) = setup().await;
    let started = new_manager
        .pairing_create(new.clone(), peer.origin.clone(), "New desktop".into())
        .await
        .unwrap();
    let wrong = if started.password.as_bytes() == b"12345678" { "23456789" } else { "12345678" };
    old_manager
        .pairing_join(
            old.clone(),
            started.status.public_link.unwrap(),
            Zeroizing::new(wrong.into()),
        )
        .await
        .unwrap();
    let first_poll = std::time::Instant::now();
    new_manager.pairing_progress(new.clone()).await.unwrap();
    new_manager.pairing_progress(new.clone()).await.unwrap();
    assert!(first_poll.elapsed() >= Duration::from_secs(2));
    assert_eq!(old_manager.pairing_progress(old.clone()).await, Err(PairingError::InvalidResponse));
    assert!(new.personal_record().unwrap().is_none());
    assert_eq!(peer.state.lock().unwrap().pairing.as_ref().unwrap().messages.len(), 3);
    assert_eq!(old_manager.pairing_status(&old).unwrap().phase, PairingPhase::RestartRequired);
    peer.assert_healthy();
}

#[tokio::test]
async fn changed_duplicate_is_rejected_before_frame_opening_and_missing_cache_header_fails_closed()
{
    let (peer, _old_dir, _new_dir, old, new, old_manager, new_manager) = setup().await;
    peer.state.lock().unwrap().pairing.as_mut().unwrap().bad_headers = true;
    assert!(matches!(
        new_manager.pairing_create(new.clone(), peer.origin.clone(), "New desktop".into()).await,
        Err(PairingError::Personal(PersonalServerError::InvalidResponse))
    ));
    peer.state.lock().unwrap().pairing.as_mut().unwrap().bad_headers = false;
    let started = new_manager
        .pairing_create(new.clone(), peer.origin.clone(), "New desktop".into())
        .await
        .unwrap();
    old_manager
        .pairing_join(
            old.clone(),
            started.status.public_link.unwrap(),
            Zeroizing::new(std::str::from_utf8(started.password.as_bytes()).unwrap().into()),
        )
        .await
        .unwrap();
    new_manager.pairing_progress(new.clone()).await.unwrap();
    peer.state.lock().unwrap().pairing.as_mut().unwrap().messages[0].payload[0] ^= 1;
    assert_eq!(new_manager.pairing_progress(new.clone()).await, Err(PairingError::InvalidResponse));
    assert!(new.personal_record().unwrap().is_none());
    assert!(new.pairing_record().unwrap().unwrap().attempt_started);
    peer.assert_healthy();
}

#[tokio::test]
async fn first_bootstrap_enforces_paired_floor_and_exact_projection_before_publishing_snapshot() {
    let (peer, _old_dir, _new_dir, old, new, old_manager, new_manager) = setup().await;
    to_confirmation(&peer, &old, &new, &old_manager, &new_manager).await;
    old_manager.pairing_confirm(old.clone()).await.unwrap();
    new_manager.pairing_progress(new.clone()).await.unwrap();
    old_manager.pairing_progress(old.clone()).await.unwrap();
    let original = peer.state.lock().unwrap().replies["/sync/v1/keys"].clone();
    let mut bundle = SyncAccountKeyBundle::from_cbor(&original.body).unwrap();
    bundle.revision = 1;
    peer.reply("/sync/v1/keys", Reply::cbor(bundle.to_cbor().unwrap()));
    assert_eq!(new_manager.pairing_progress(new.clone()).await, Err(PairingError::InvalidResponse));
    assert!(new.personal_sync_record().unwrap().is_none());
    let identity = record(&new).unwrap();
    let secrets = identity::Secrets::parse(&identity.private_material).unwrap();
    let kem = DeviceKemKeyPair::from_private_bytes(secrets.device_kem()).unwrap();
    bundle.revision = 2;
    bundle.wrapped_ark = DeviceArkWrap::seal(
        identity.account_id,
        new.device_id(),
        kem.public_key(),
        &SymmetricKey::from_slice(secrets.ark()).unwrap(),
    )
    .unwrap()
    .encode()
    .to_vec();
    peer.reply("/sync/v1/keys", Reply::cbor(bundle.to_cbor().unwrap()));
    assert_eq!(new_manager.pairing_recover(new.clone()).await, Err(PairingError::InvalidResponse));
    assert!(new.personal_sync_record().unwrap().is_none());
    bundle.revision = 3;
    peer.reply("/sync/v1/keys", Reply::cbor(bundle.to_cbor().unwrap()));
    assert_eq!(
        new_manager.pairing_recover(new.clone()).await.unwrap().phase,
        PairingPhase::Completed
    );
    assert!(new.personal_sync_record().unwrap().is_some());
    peer.assert_healthy();
}

#[tokio::test]
async fn restarted_checkpoint_keeps_original_local_expiry_despite_later_relay_expiry() {
    let (peer, _old_dir, _new_dir, old, new, old_manager, new_manager) = setup().await;
    to_confirmation(&peer, &old, &new, &old_manager, &new_manager).await;
    old_manager.pairing_confirm(old.clone()).await.unwrap();
    let mut saved = old.pairing_record().unwrap().unwrap();
    let certificate = SecretVec::new(saved.certificate.as_ref().unwrap().as_bytes().to_vec());
    saved.local_expires_at = now().unwrap() - 1;
    assert!(old.save_pairing(Some(saved.generation), &saved).unwrap());
    drop(old_manager);
    assert_eq!(peer.manager().pairing_recover(old.clone()).await, Err(PairingError::Expired));
    let retained = old.pairing_record().unwrap().unwrap();
    assert!(retained.certificate.unwrap().as_bytes() == certificate.as_bytes());
    assert!(retained.approval_request.is_none());
    assert_eq!(peer.state.lock().unwrap().pairing.as_ref().unwrap().messages.len(), 6);
    peer.assert_healthy();
}

#[tokio::test]
async fn old_claim_requires_verified_local_account_device_key_binding_and_keys_write_scope() {
    let (peer, _old_dir, _new_dir, old, new, old_manager, new_manager) = setup().await;
    let started = new_manager
        .pairing_create(new.clone(), peer.origin.clone(), "New desktop".into())
        .await
        .unwrap();
    let link = started.status.public_link.unwrap();
    for field in 0..4 {
        peer.install_token(
            &old,
            |claims| match field {
                0 => claims.scope = "account:read keys:read sync:read sync:write".into(),
                1 => claims.sub = scoplen_model::new_uuid_v7().unwrap(),
                2 => claims.did = scoplen_model::new_uuid_v7().unwrap(),
                _ => {}
            },
            if field == 3 {
                Some(P256SigningKey::from_bytes(&[77; 32]).unwrap().public_key_sec1())
            } else {
                None
            },
        );
        assert_eq!(
            old_manager
                .pairing_join(
                    old.clone(),
                    link.clone(),
                    Zeroizing::new(
                        std::str::from_utf8(started.password.as_bytes()).unwrap().into()
                    )
                )
                .await,
            Err(PairingError::AuthenticationRequired)
        );
        assert!(old.pairing_record().unwrap().is_none());
    }
    assert!(!peer.state.lock().unwrap().paths.iter().any(|path| path.ends_with("/claim")));
    peer.assert_healthy();
}
