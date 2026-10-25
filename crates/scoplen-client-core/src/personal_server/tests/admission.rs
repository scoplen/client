// SPDX-License-Identifier: Apache-2.0
//! Offline conversion never redeems or resumes a historical entry ceremony.

use rusqlite::params;
use scoplen_api::sync::{SyncVaultKey, SyncVaultKeysResponse};
use scoplen_crypto::{
    PairingApplicationContext, PairingContext, PairingHandoff, pairing_key_anchor,
};
use sha2::{Digest as _, Sha256};

use super::*;

fn admission_count(dir: &tempfile::TempDir) -> i64 {
    database(dir).query_row("SELECT count(*) FROM personal_admission", [], |r| r.get(0)).unwrap()
}

#[test]
fn confirmed_profile_converts_once_and_runtime_no_longer_decodes_archived_ceremonies() {
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let before = legacy_profile(&local, "https://example.test", true);
    let manager = PersonalServer::default();
    assert_eq!(manager.status(&local).unwrap().phase, PersonalServerPhase::AuthenticationRequired);
    assert_eq!(admission_count(&dir), 1);
    let after = local.personal_record().unwrap().unwrap();
    assert!(after.admitted);
    assert!(before.private_material.as_bytes() == after.private_material.as_bytes());
    assert!(
        before.enrollment_request.as_ref().unwrap().as_bytes()
            == after.enrollment_request.as_ref().unwrap().as_bytes()
    );
    let anchors = local.personal_admission(&after).unwrap().unwrap();
    assert!(anchors.len() < 4096, "admission stores compact anchors, not all epoch ciphertexts");
    database(&dir).execute("UPDATE personal_server SET enrollment_request=X'ff'", []).unwrap();
    drop(local);
    let reopened = store(&dir);
    assert_eq!(
        manager.status(&reopened).unwrap().phase,
        PersonalServerPhase::AuthenticationRequired
    );
    assert!(
        reopened
            .personal_admission(&reopened.personal_record().unwrap().unwrap())
            .unwrap()
            .is_some_and(|saved| saved.as_bytes() == anchors.as_bytes())
    );
    assert_eq!(admission_count(&dir), 1);
}

#[tokio::test]
async fn pending_and_attempted_invitations_never_migrate_or_send_a_challenge() {
    let server = Fixture::new().await;
    for attempted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let local = store(&dir);
        let before = legacy_profile(&local, &server.origin, false);
        database(&dir)
            .execute(
                "UPDATE personal_server SET enrollment_attempted=?1,
            recovery_saved=1, recovery_confirmed=1",
                [attempted],
            )
            .unwrap();
        let manager = server.manager();
        assert_eq!(manager.status(&local).unwrap().phase, PersonalServerPhase::RetiredEntry);
        assert_eq!(
            manager.authenticate(local.clone()).await,
            Err(PersonalServerError::RetiredEntry)
        );
        assert_eq!(admission_count(&dir), 0);
        let after = local.personal_record().unwrap().unwrap();
        assert!(
            before.enrollment_request.as_ref().unwrap().as_bytes()
                == after.enrollment_request.as_ref().unwrap().as_bytes()
        );
        assert!(before.private_material.as_bytes() == after.private_material.as_bytes());
    }
    assert_eq!(server.state.challenges.load(Ordering::SeqCst), 0);
    assert_eq!(server.state.device_exchanges.load(Ordering::SeqCst), 0);
}

#[test]
fn confirmed_but_mismatched_or_unbounded_evidence_is_preserved_without_admission() {
    for fault in 0..9 {
        let dir = tempfile::tempdir().unwrap();
        let local = store(&dir);
        let initial = legacy_profile(&local, "https://example.test", true);
        let conn = database(&dir);
        match fault {
            0 => {
                conn.execute("UPDATE personal_server SET origin='https://other.test'", []).unwrap();
            }
            1 => {
                conn.execute(
                    "UPDATE personal_server SET account_id=?1",
                    [scoplen_model::new_uuid_v7().unwrap().as_bytes().as_slice()],
                )
                .unwrap();
            }
            2 => {
                conn.execute(
                    "UPDATE personal_server SET personal_vault_id=?1",
                    [scoplen_model::new_uuid_v7().unwrap().as_bytes().as_slice()],
                )
                .unwrap();
            }
            3 => {
                conn.execute(
                    "UPDATE device SET device_id=?1",
                    [scoplen_model::new_uuid_v7().unwrap().as_bytes().as_slice()],
                )
                .unwrap();
            }
            4 => {
                conn.execute("UPDATE device_key_pair SET signing=?1", [vec![3; 32]]).unwrap();
            }
            5 => {
                conn.execute(
                    "UPDATE personal_server SET enrollment_request=?1",
                    [vec![b' '; 1_048_577]],
                )
                .unwrap();
            }
            6 => {
                conn.execute("UPDATE personal_server SET private_material=?1", [vec![1; 225]])
                    .unwrap();
            }
            7 | 8 => {
                let mut request = PersonalEnrollmentRequest::from_json(
                    initial.enrollment_request.as_ref().unwrap().as_bytes(),
                )
                .unwrap();
                if fault == 7 {
                    request.device_signature[0] ^= 1;
                } else {
                    request.key_bundle_update.signature[0] ^= 1;
                }
                conn.execute(
                    "UPDATE personal_server SET enrollment_request=?1",
                    [request.to_json().unwrap()],
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        drop(conn);
        drop(local);
        let reopened = store(&dir);
        if fault == 5 {
            assert_eq!(
                PersonalServer::default().status(&reopened).unwrap_err(),
                PersonalServerError::AdmissionUnverified
            );
            assert_eq!(admission_count(&dir), 0);
            continue;
        }
        let before = reopened.personal_record().unwrap().unwrap();
        assert_eq!(
            PersonalServer::default().status(&reopened).unwrap_err(),
            PersonalServerError::AdmissionUnverified,
            "fault {fault}"
        );
        assert_eq!(admission_count(&dir), 0);
        let after = reopened.personal_record().unwrap().unwrap();
        assert!(
            before.enrollment_request.as_ref().unwrap().as_bytes()
                == after.enrollment_request.as_ref().unwrap().as_bytes()
        );
        assert!(before.private_material.as_bytes() == after.private_material.as_bytes());
    }
}

#[test]
fn conversion_rolls_back_failed_publication_and_rejects_stale_or_unconfirmed_claims() {
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let pending = legacy_profile(&local, "https://example.test", false);
    assert!(!local.save_personal_admission(&pending, b"untrusted", None, None).unwrap());
    local.save_personal_tokens(b"historical", b"historical", 1, 2).unwrap();
    let stale = local.personal_record().unwrap().unwrap();
    local.clear_personal_tokens().unwrap();
    assert!(!local.save_personal_admission(&stale, b"stale", None, None).unwrap());
    database(&dir)
        .execute_batch(
            "CREATE TRIGGER fail_admission BEFORE INSERT ON personal_admission
        BEGIN SELECT RAISE(ABORT, 'fixture'); END;",
        )
        .unwrap();
    assert_eq!(PersonalServer::default().status(&local).unwrap_err(), PersonalServerError::Storage);
    assert_eq!(admission_count(&dir), 0);
    assert!(
        local.personal_record().unwrap().unwrap().enrollment_request.as_ref().unwrap().as_bytes()
            == pending.enrollment_request.as_ref().unwrap().as_bytes()
    );
    database(&dir).execute_batch("DROP TRIGGER fail_admission;").unwrap();
    assert_eq!(
        PersonalServer::default().status(&local).unwrap().phase,
        PersonalServerPhase::AuthenticationRequired
    );
}

#[test]
fn admitted_account_origin_vault_device_and_secret_ownership_are_immutable() {
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    legacy_profile(&local, "https://example.test", true);
    PersonalServer::default().status(&local).unwrap();
    let conn = database(&dir);
    for statement in [
        "UPDATE personal_server SET origin='https://other.test'",
        "UPDATE personal_server SET account_id=randomblob(16)",
        "UPDATE personal_server SET personal_vault_id=randomblob(16)",
        "UPDATE personal_server SET private_material=randomblob(225)",
        "DELETE FROM personal_server",
        "DELETE FROM device",
        "DELETE FROM device_key_pair",
        "UPDATE device SET device_id=randomblob(16)",
        "UPDATE device_key_pair SET signing=randomblob(32)",
        "UPDATE device_key_pair SET kem=randomblob(32)",
        "UPDATE personal_admission SET anchors=X'ff'",
        "DELETE FROM personal_admission",
        "INSERT OR REPLACE INTO personal_admission SELECT * FROM personal_admission",
        "INSERT OR REPLACE INTO personal_server SELECT * FROM personal_server",
        "INSERT OR REPLACE INTO device SELECT singleton,randomblob(16),clock,created_at FROM device",
        "INSERT OR REPLACE INTO device_key_pair SELECT singleton,randomblob(32),kem,created_at FROM device_key_pair",
    ] {
        assert!(conn.execute(statement, []).is_err(), "{statement}");
    }
    let mut foreign = local.personal_record().unwrap().unwrap();
    foreign.origin = "https://other.test".into();
    assert!(local.begin_personal_authentication(&foreign).is_err());
    assert!(local.claim_personal_refresh(&foreign, 0).is_err());
}

fn paired_fixture(dir: &tempfile::TempDir, phase: &str, matching: bool) -> Arc<Store> {
    let local = store(dir);
    let identity = legacy_profile(&local, "https://example.test", false);
    let enrollment = PersonalEnrollmentRequest::from_json(
        identity.enrollment_request.as_ref().unwrap().as_bytes(),
    )
    .unwrap();
    let pairing_id = scoplen_model::new_uuid_v7().unwrap();
    let peer = scoplen_model::new_uuid_v7().unwrap();
    let mut handoff = PairingHandoff {
        context: PairingApplicationContext::new(
            &identity.origin,
            PairingContext::new(pairing_id, peer, local.device_id()).unwrap(),
        )
        .unwrap(),
        account_id: identity.account_id,
        personal_vault_id: identity.personal_vault_id,
        account_signing_public_key: enrollment.account_signing_public_key,
        account_kem_public_key: enrollment.account_kem_public_key,
        device_certificate: enrollment.device_certificate.encode().unwrap(),
        revision: 1,
        key_bundle_update_hash: Sha256::digest(enrollment.key_bundle_update.to_cbor().unwrap())
            .into(),
        key_anchor: [0; 32],
        wrapped_ark: enrollment.key_bundle_update.device_wraps[0].wrapped_ark.clone(),
        account_signing_key: enrollment.key_bundle_update.account_signing_key,
        account_kem_key: enrollment.key_bundle_update.account_kem_key,
        recovery_blob: enrollment.key_bundle_update.recovery_blob,
        personal_vault_keys: SyncVaultKeysResponse {
            keys: vec![SyncVaultKey {
                epoch: 1,
                wrapped_vault_key: enrollment.wrapped_personal_vault_key,
            }],
        }
        .to_cbor()
        .unwrap(),
    };
    handoff.key_anchor = pairing_key_anchor(handoff.projection()).unwrap();
    let mut material = Zeroizing::new(identity.private_material.as_bytes()[..193].to_vec());
    material[0] = 2;
    let conn = database(dir);
    conn.execute("UPDATE personal_server SET enrollment_request=NULL, paired_handoff=?1, private_material=?2",
        params![handoff.encode().unwrap().as_bytes(), &*material]).unwrap();
    conn.execute(
        "INSERT INTO personal_pairing (singleton,generation,side,origin,pairing_id,peer_id,
        expires_at,local_expires_at,attempt_started,phase,transcript,certificate)
        VALUES (1,1,2,?1,?2,?3,1000,1000,1,?4,X'00',?5)",
        params![
            identity.origin,
            pairing_id.as_bytes().as_slice(),
            if matching { peer } else { scoplen_model::new_uuid_v7().unwrap() }
                .as_bytes()
                .as_slice(),
            phase,
            handoff.device_certificate
        ],
    )
    .unwrap();
    local
}

#[test]
fn completed_new_device_pairing_is_bound_evidence_but_pending_or_foreign_handoffs_are_not() {
    for (phase, matching, expected) in [
        ("completed", true, PersonalServerPhase::AuthenticationRequired),
        ("admission_pending", true, PersonalServerPhase::RetiredEntry),
        ("completed", false, PersonalServerPhase::RetiredEntry),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let local = paired_fixture(&dir, phase, matching);
        let before = local.personal_record().unwrap().unwrap();
        assert_eq!(PersonalServer::default().status(&local).unwrap().phase, expected);
        assert_eq!(admission_count(&dir), i64::from(expected != PersonalServerPhase::RetiredEntry));
        let after = local.personal_record().unwrap().unwrap();
        assert!(
            before.paired_handoff.as_ref().unwrap().as_bytes()
                == after.paired_handoff.as_ref().unwrap().as_bytes()
        );
        assert!(before.private_material.as_bytes() == after.private_material.as_bytes());
    }
}
