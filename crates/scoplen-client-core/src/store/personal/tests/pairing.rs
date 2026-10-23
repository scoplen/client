// SPDX-License-Identifier: Apache-2.0

use super::*;

fn pending(id: Uuid) -> PairingRecord {
    PairingRecord {
        generation: 0,
        side: 2,
        origin: "https://sync.example".into(),
        pairing_id: id,
        peer_id: Some(scoplen_model::new_uuid_v7().unwrap()),
        expires_at: 2000,
        local_expires_at: 1500,
        attempt_started: false,
        phase: "exchanging".into(),
        capability: Some(SecretVec::new(vec![42; 32])),
        transcript: SecretVec::new(vec![0x80]),
        certificate: None,
        key_update: None,
        handoff: None,
        acceptance: None,
        approval_request: None,
    }
}

fn open(dir: &tempfile::TempDir) -> Store {
    Store::open(&dir.path().join("pairing.db"), &SymmetricKey::new([32; 32])).unwrap()
}

#[test]
fn unbound_metadata_corrections_preserve_keys_and_cannot_replace_a_concurrent_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let first = open(&dir);
    let second = open(&dir);
    let original = PairingDeviceRecord {
        origin: "https://mistyped.example".into(),
        device_name: "Mistyped name".into(),
        signing: SecretVec::new(vec![3; 32]),
        kem: SecretVec::new(vec![4; 32]),
        created_at: 100,
    };
    assert!(first.insert_pairing_device(&original).unwrap());
    assert!(
        first
            .correct_unbound_pairing_device(&original, "https://sync.example", "New desktop")
            .unwrap()
    );
    assert!(
        !second
            .correct_unbound_pairing_device(&original, "https://stale.example", "Stale name")
            .unwrap()
    );
    let corrected = second.pairing_device().unwrap().unwrap();
    assert_eq!(corrected.origin, "https://sync.example");
    assert_eq!(corrected.device_name, "New desktop");
    assert!(corrected.signing.as_bytes() == original.signing.as_bytes());
    assert!(corrected.kem.as_bytes() == original.kem.as_bytes());
    assert_eq!(corrected.created_at, original.created_at);
    let session = pending(scoplen_model::new_uuid_v7().unwrap());
    assert!(!first.save_pairing_for_device(None, &session, &original).unwrap());
    assert!(first.save_pairing_for_device(None, &session, &corrected).unwrap());
    assert!(
        !second
            .correct_unbound_pairing_device(&corrected, "https://other.example", "Other")
            .unwrap()
    );
    let retained = second.pairing_device().unwrap().unwrap();
    assert_eq!(retained.origin, corrected.origin);
    assert_eq!(retained.device_name, corrected.device_name);
    assert!(retained.signing.as_bytes() == original.signing.as_bytes());
    assert!(retained.kem.as_bytes() == original.kem.as_bytes());
    assert_eq!(retained.created_at, original.created_at);
}

#[test]
fn one_attempt_survives_competing_connections_restart_and_switching_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let first = open(&dir);
    let second = open(&dir);
    let session_a = pending(scoplen_model::new_uuid_v7().unwrap());
    assert!(first.save_pairing(None, &session_a).unwrap());
    let claimed = second.pairing_record().unwrap().unwrap();
    assert!(first.claim_pairing_attempt(&claimed).unwrap());
    assert!(!second.claim_pairing_attempt(&claimed).unwrap());
    assert!(!second.save_pairing(Some(claimed.generation), &session_a).unwrap());
    let session_b = pending(scoplen_model::new_uuid_v7().unwrap());
    let generation = first.pairing_record().unwrap().unwrap().generation;
    assert!(second.save_pairing(Some(generation), &session_b).unwrap());
    let claimed = second.pairing_record().unwrap().unwrap();
    assert!(second.claim_pairing_attempt(&claimed).unwrap());
    let generation = second.pairing_record().unwrap().unwrap().generation;
    assert!(first.save_pairing(Some(generation), &session_a).unwrap());
    drop(first);
    drop(second);
    let restarted = open(&dir);
    let attempted_again = restarted.pairing_record().unwrap().unwrap();
    assert_eq!(attempted_again.pairing_id, session_a.pairing_id);
    assert!(!restarted.claim_pairing_attempt(&attempted_again).unwrap());
    assert!(!restarted.pairing_record().unwrap().unwrap().attempt_started);
}

#[test]
fn paired_identity_and_exact_acceptance_publish_atomically_without_enrollment_or_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir);
    let device = PairingDeviceRecord {
        origin: "https://sync.example".into(),
        device_name: "New desktop".into(),
        signing: SecretVec::new(vec![3; 32]),
        kem: SecretVec::new(vec![4; 32]),
        created_at: 100,
    };
    assert!(store.insert_pairing_device(&device).unwrap());
    assert!(!store.insert_pairing_device(&device).unwrap());
    let mut pending = pending(scoplen_model::new_uuid_v7().unwrap());
    assert!(store.save_pairing(None, &pending).unwrap());
    pending = store.pairing_record().unwrap().unwrap();
    assert!(store.claim_pairing_attempt(&pending).unwrap());
    pending = store.pairing_record().unwrap().unwrap();
    pending.handoff = Some(SecretVec::new(vec![5; 41]));
    pending.certificate = Some(SecretVec::new(vec![6]));
    let mut private = vec![2; 193];
    private[1..33].copy_from_slice(device.signing.as_bytes());
    private[33..65].copy_from_slice(device.kem.as_bytes());
    let identity = PersonalRecord {
        origin: device.origin,
        account_id: scoplen_model::new_uuid_v7().unwrap(),
        personal_vault_id: scoplen_model::new_uuid_v7().unwrap(),
        device_name: device.device_name,
        private_material: SecretVec::new(private),
        enrollment_request: None,
        paired_handoff: Some(SecretVec::new(vec![7])),
        recovery_saved: false,
        recovery_confirmed: false,
        enrollment_attempted: false,
        access_expires_at: None,
        refresh_expires_at: None,
        auth_generation: 0,
        auth_scope: None,
        refresh_available: false,
        session_established: false,
        refresh_retry_at: None,
    };
    let signature = [8; 64];
    let transcript = SecretVec::new(vec![9]);
    store.conn().execute_batch("CREATE TRIGGER fail_pair BEFORE INSERT ON device_key_pair BEGIN SELECT RAISE(ABORT, 'fixture'); END;").unwrap();
    assert!(store.save_paired_identity(&pending, &identity, &signature, &transcript).is_err());
    assert!(store.personal_record().unwrap().is_none());
    assert!(store.device_key_pair().unwrap().is_none());
    assert!(store.pairing_record().unwrap().unwrap().acceptance.is_none());
    store.conn().execute_batch("DROP TRIGGER fail_pair;").unwrap();
    assert!(store.save_paired_identity(&pending, &identity, &signature, &transcript).unwrap());
    assert!(!store.save_paired_identity(&pending, &identity, &signature, &transcript).unwrap());
    drop(store);
    let store = open(&dir);
    let identity = store.personal_record().unwrap().unwrap();
    assert!(identity.enrollment_request.is_none());
    assert!(identity.paired_handoff.is_some());
    assert!(!identity.enrollment_attempted);
    assert!(!identity.recovery_saved);
    assert!(!identity.recovery_confirmed);
    assert_eq!(identity.private_material.as_bytes().len(), 193);
    assert_eq!(
        store
            .conn()
            .query_row("SELECT created_at FROM device_key_pair", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        100
    );
    let pending = store.pairing_record().unwrap().unwrap();
    assert_eq!(pending.acceptance.unwrap().as_bytes(), signature);
    assert_eq!(pending.transcript.as_bytes(), transcript.as_bytes());
    assert_eq!(pending.handoff.unwrap().as_bytes(), &[5; 41]);
    assert_eq!(pending.certificate.unwrap().as_bytes(), &[6]);
    assert_eq!(pending.local_expires_at, 1500);
    assert_eq!(pending.phase, "admission_unconfirmed");
}
