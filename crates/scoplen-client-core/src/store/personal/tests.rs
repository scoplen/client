// SPDX-License-Identifier: Apache-2.0

use scoplen_crypto::SymmetricKey;

use super::*;

mod auth;

fn fixture() -> (tempfile::TempDir, Store, PersonalRecord, SecretVec, PersonalSyncRecord) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("sync.db"), &SymmetricKey::new([32; 32])).unwrap();
    let identity = PersonalRecord {
        origin: "https://sync.example".into(),
        account_id: scoplen_model::new_uuid_v7().unwrap(),
        personal_vault_id: scoplen_model::new_uuid_v7().unwrap(),
        device_name: "Desktop".into(),
        private_material: SecretVec::new(vec![1; 225]),
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
    store.insert_personal_record(&identity).unwrap();

    let access = SecretVec::new(b"access".to_vec());
    store.save_personal_tokens(access.as_bytes(), b"refresh", 1_000, 2_000).unwrap();
    let current = store.personal_record().unwrap().unwrap();
    store.insert_personal_admission(&current, b"store-fixture").unwrap();
    let snapshot = PersonalSyncRecord {
        generation: 0,
        session: SecretVec::new(vec![3]),
        account_keys: SecretVec::new(vec![4]),
        vault_keys: SecretVec::new(vec![5]),
    };
    (dir, store, current, access, snapshot)
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
    assert!(!store.save_personal_sync(&identity, &access, Some(1), &snapshot, 100).unwrap());
    let identity = store.personal_record().unwrap().unwrap();
    store.conn().execute("UPDATE personal_server SET enrollment_request = X'00'", []).unwrap();
    assert!(store.save_personal_sync(&identity, &access, Some(1), &snapshot, 100).unwrap());
    assert!(store.conn().execute("UPDATE device_key_pair SET signing = X'00'", []).is_err());
    assert!(
        store
            .conn()
            .execute("UPDATE personal_server SET origin = 'https://other.example'", [])
            .is_err()
    );
    assert_eq!(store.personal_sync_record().unwrap().unwrap().generation, 2);
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
fn damaged_sync_snapshots_preserve_each_payload_byte_limit() {
    let (_dir, store, identity, access, snapshot) = fixture();
    assert!(store.save_personal_sync(&identity, &access, None, &snapshot, 100).unwrap());
    store.conn().pragma_update(None, "ignore_check_constraints", "ON").unwrap();
    for column in ["session", "account_keys", "vault_keys"] {
        for size in [0, 4_194_304, 4_194_305] {
            store
                .conn()
                .execute(&format!("UPDATE personal_sync SET {column}=zeroblob(?1)"), [size])
                .unwrap();
            let result = store.personal_sync_record();
            if size == 4_194_304 {
                let record = result.unwrap().unwrap();
                assert_eq!(record.generation, 1);
                assert_eq!(
                    match column {
                        "session" => record.session.len(),
                        "account_keys" => record.account_keys.len(),
                        _ => record.vault_keys.len(),
                    },
                    size as usize
                );
            } else {
                assert!(matches!(result, Err(StoreError::Sqlite(rusqlite::Error::InvalidQuery))));
            }
            assert_eq!(
                store
                    .conn()
                    .query_row(
                        &format!("SELECT length(CAST({column} AS BLOB)) FROM personal_sync"),
                        [],
                        |row| row.get::<_, i64>(0)
                    )
                    .unwrap(),
                i64::from(size)
            );
        }
        store.conn().execute(&format!("UPDATE personal_sync SET {column}=X'01'"), []).unwrap();
    }
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
