// SPDX-License-Identifier: Apache-2.0

use scoplen_crypto::SymmetricKey;

use super::*;

mod auth;
mod pairing;

fn fixture() -> (tempfile::TempDir, Store, PersonalRecord, SecretVec, PersonalSyncRecord) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("sync.db"), &SymmetricKey::new([32; 32])).unwrap();
    let identity = PersonalRecord {
        origin: "https://sync.example".into(),
        account_id: scoplen_model::new_uuid_v7().unwrap(),
        personal_vault_id: scoplen_model::new_uuid_v7().unwrap(),
        device_name: "Desktop".into(),
        private_material: SecretVec::new(vec![1; 225]),
        enrollment_request: Some(SecretVec::new(vec![2; 16])),
        paired_handoff: None,
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
    store.insert_personal_record(&identity).unwrap();
    store.save_personal_recovery().unwrap();
    store.confirm_personal_recovery().unwrap();
    store.claim_personal_enrollment().unwrap();
    let access = SecretVec::new(b"access".to_vec());
    store.save_personal_tokens(access.as_bytes(), b"refresh", 1_000, 2_000).unwrap();
    let snapshot = PersonalSyncRecord {
        generation: 0,
        session: SecretVec::new(vec![3]),
        account_keys: SecretVec::new(vec![4]),
        vault_keys: SecretVec::new(vec![5]),
    };
    (dir, store, identity, access, snapshot)
}

#[test]
fn sync_snapshot_cas_rejects_stale_identity_credentials_generation_and_device() {
    let (_dir, store, identity, access, snapshot) = fixture();
    assert!(store.save_personal_sync(&identity, &access, None, &snapshot, 100).unwrap());
    assert_eq!(store.personal_sync_record().unwrap().unwrap().generation, 1);
    assert!(!store.save_personal_sync(&identity, &access, None, &snapshot, 100).unwrap());
    assert!(!store.save_personal_sync(&identity, &access, Some(1), &snapshot, 1_000).unwrap());
    store.save_personal_tokens(b"replacement", b"refresh", 1_000, 2_000).unwrap();
    assert!(!store.save_personal_sync(&identity, &access, Some(1), &snapshot, 100).unwrap());
    store.save_personal_tokens(access.as_bytes(), b"refresh", 1_000, 2_000).unwrap();
    store.conn().execute("UPDATE personal_server SET enrollment_request = X'00'", []).unwrap();
    assert!(!store.save_personal_sync(&identity, &access, Some(1), &snapshot, 100).unwrap());
    store
        .conn()
        .execute(
            "UPDATE personal_server SET enrollment_request = ?1",
            params![identity.enrollment_request.as_ref().unwrap().as_bytes()],
        )
        .unwrap();
    store.conn().execute("UPDATE device_key_pair SET signing = X'00'", []).unwrap();
    assert!(!store.save_personal_sync(&identity, &access, Some(1), &snapshot, 100).unwrap());
    assert_eq!(store.personal_sync_record().unwrap().unwrap().generation, 1);
}

#[test]
fn sync_snapshot_rolls_back_storage_failures_and_survives_reopen() {
    let (dir, store, identity, access, mut snapshot) = fixture();
    assert!(store.save_personal_sync(&identity, &access, None, &snapshot, 100).unwrap());
    snapshot.session = SecretVec::new(vec![9]);
    store.conn().execute_batch("CREATE TRIGGER fail_sync BEFORE UPDATE ON personal_sync BEGIN SELECT RAISE(ABORT, 'fixture'); END;").unwrap();
    assert!(store.save_personal_sync(&identity, &access, Some(1), &snapshot, 100).is_err());
    let retained = store.personal_sync_record().unwrap().unwrap();
    assert_eq!(retained.generation, 1);
    assert_eq!(retained.session.as_bytes(), &[3]);
    assert_eq!(retained.account_keys.as_bytes(), &[4]);
    assert_eq!(retained.vault_keys.as_bytes(), &[5]);
    store.conn().execute_batch("DROP TRIGGER fail_sync;").unwrap();
    snapshot.vault_keys = SecretVec::new(vec![]);
    assert!(store.save_personal_sync(&identity, &access, Some(1), &snapshot, 100).is_err());
    assert_eq!(store.personal_sync_record().unwrap().unwrap().session.as_bytes(), &[3]);
    drop(store);
    let store = Store::open(&dir.path().join("sync.db"), &SymmetricKey::new([32; 32])).unwrap();
    assert_eq!(store.personal_sync_record().unwrap().unwrap().generation, 1);
    assert_eq!(store.personal_access_token(100).unwrap().unwrap().as_bytes(), access.as_bytes());
    assert!(store.personal_access_token(1_000).unwrap().is_none());
}

#[test]
fn competing_store_cannot_publish_an_outdated_snapshot() {
    let (dir, store, identity, access, snapshot) = fixture();
    assert!(store.save_personal_sync(&identity, &access, None, &snapshot, 100).unwrap());
    let other = Store::open(&dir.path().join("sync.db"), &SymmetricKey::new([32; 32])).unwrap();
    let generation = other.personal_sync_record().unwrap().unwrap().generation;
    assert!(
        store.save_personal_sync(&identity, &access, Some(generation), &snapshot, 100).unwrap()
    );
    assert!(
        !other.save_personal_sync(&identity, &access, Some(generation), &snapshot, 100).unwrap()
    );
    assert_eq!(other.personal_sync_record().unwrap().unwrap().generation, 2);
}
