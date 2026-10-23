// SPDX-License-Identifier: Apache-2.0
//! Cross-connection claims, response fencing and SQLCipher restart behavior.

use super::*;

fn replacement() -> PersonalTokens {
    PersonalTokens {
        access: SecretVec::new(b"next-access".to_vec()),
        refresh: SecretVec::new(b"next-refresh".to_vec()),
        access_expires_at: 1600,
        refresh_expires_at: 2000,
        scope: "keys:read sync:read".into(),
    }
}

#[test]
fn a_legacy_session_keeps_its_identity_and_bootstrap_without_inventing_a_scope_ceiling() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    let account = scoplen_model::new_uuid_v7().unwrap();
    let vault = scoplen_model::new_uuid_v7().unwrap();
    let device = scoplen_model::new_uuid_v7().unwrap();
    let key = SymmetricKey::new([32; 32]);
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        crate::store::apply_key(&conn, &key).unwrap();
        for migration in &crate::store::migrations::MIGRATIONS[..7] {
            conn.execute_batch(migration).unwrap();
        }
        conn.pragma_update(None, "user_version", 7).unwrap();
        conn.execute("INSERT INTO device VALUES (1, ?1, 0, 0)", [device.as_bytes().as_slice()])
            .unwrap();
        conn.execute(
            "INSERT INTO personal_server (singleton, origin, account_id, personal_vault_id,
                device_name, private_material, enrollment_request, recovery_saved,
                recovery_confirmed, enrollment_attempted, access_token, refresh_token,
                access_expires_at, refresh_expires_at)
             VALUES (1, 'https://sync.example', ?1, ?2, 'Desktop', X'01', X'02',
                1, 1, 1, X'03', X'04', 1000, 2000)",
            params![account.as_bytes().as_slice(), vault.as_bytes().as_slice()],
        )
        .unwrap();
        conn.execute("INSERT INTO personal_sync VALUES (1, 1, X'01', X'02', X'03')", []).unwrap();
    }
    let store = Store::open(&path, &key).unwrap();
    let identity = store.personal_record().unwrap().unwrap();
    assert_eq!(store.device_id(), device);
    assert_eq!(identity.account_id, account);
    assert_eq!(identity.personal_vault_id, vault);
    assert_eq!(identity.private_material.as_bytes(), &[1]);
    assert!(identity.session_established);
    assert!(identity.auth_scope.is_none());
    assert!(store.claim_personal_refresh(&identity, 100).unwrap().is_none());
    assert_eq!(store.personal_sync_record().unwrap().unwrap().session.as_bytes(), &[1]);
}

#[test]
fn refresh_claim_is_single_use_across_connections_and_restart() {
    let (dir, store, _, access, _) = fixture();
    let identity = store.personal_record().unwrap().unwrap();
    let other = Store::open(&dir.path().join("sync.db"), &SymmetricKey::new([32; 32])).unwrap();
    let stale = other.personal_record().unwrap().unwrap();
    let claim = store.claim_personal_refresh(&identity, 100).unwrap().unwrap();
    assert!(!other.personal_session_current(&stale, &access, 100).unwrap());
    assert!(other.claim_personal_refresh(&stale, 100).unwrap().is_none());
    assert!(other.personal_access_token(100).unwrap().is_none());
    drop(store);
    drop(other);
    let reopened = Store::open(&dir.path().join("sync.db"), &SymmetricKey::new([32; 32])).unwrap();
    let retained = reopened.personal_record().unwrap().unwrap();
    assert!(!retained.refresh_available);
    assert!(reopened.claim_personal_refresh(&retained, 100).unwrap().is_none());
    // A fresh challenge invalidates any late successful or unchanged refresh response.
    let fresh = reopened.begin_personal_authentication(&retained).unwrap().unwrap();
    assert!(
        !reopened
            .finish_personal_session(&identity, claim.generation, true, &replacement(), None)
            .unwrap()
    );
    assert!(
        !reopened
            .finish_personal_session(&identity, claim.generation, true, &claim.previous, None)
            .unwrap()
    );
    assert!(
        reopened.finish_personal_session(&retained, fresh, false, &replacement(), None).unwrap()
    );
    assert!(
        !reopened.finish_personal_session(&retained, fresh, false, &replacement(), None).unwrap()
    );
    assert_eq!(reopened.personal_access_token(100).unwrap().unwrap().as_bytes(), b"next-access");
}

#[test]
fn fresh_authentication_responses_are_generation_fenced() {
    let (dir, store, _, _, _) = fixture();
    let identity = store.personal_record().unwrap().unwrap();
    let first = store.begin_personal_authentication(&identity).unwrap().unwrap();
    let other = Store::open(&dir.path().join("sync.db"), &SymmetricKey::new([32; 32])).unwrap();
    assert!(other.begin_personal_authentication(&identity).unwrap().is_none());
    let current = other.personal_record().unwrap().unwrap();
    let second = other.begin_personal_authentication(&current).unwrap().unwrap();
    assert!(!store.finish_personal_session(&identity, first, false, &replacement(), None).unwrap());
    assert!(other.finish_personal_session(&current, second, false, &replacement(), None).unwrap());
    assert!(!store.finish_personal_session(&identity, first, false, &replacement(), None).unwrap());
}

#[test]
fn failed_claim_rolls_back_and_failed_publication_retains_the_durable_claim() {
    let (dir, store, _, access, _) = fixture();
    let identity = store.personal_record().unwrap().unwrap();
    store.conn().execute_batch("CREATE TRIGGER fail_claim BEFORE UPDATE ON personal_server WHEN NEW.refresh_claimed = 1 BEGIN SELECT RAISE(ABORT, 'fixture'); END;").unwrap();
    assert!(store.claim_personal_refresh(&identity, 100).is_err());
    assert!(store.personal_session_current(&identity, &access, 100).unwrap());
    store.conn().execute_batch("DROP TRIGGER fail_claim;").unwrap();
    let claim = store.claim_personal_refresh(&identity, 100).unwrap().unwrap();
    store.conn().execute_batch("CREATE TRIGGER fail_publish BEFORE UPDATE ON personal_server WHEN NEW.refresh_claimed = 0 BEGIN SELECT RAISE(ABORT, 'fixture'); END;").unwrap();
    assert!(
        store
            .finish_personal_session(&identity, claim.generation, true, &replacement(), None)
            .is_err()
    );
    assert!(store.personal_access_token(100).unwrap().is_none());
    assert!(!store.personal_record().unwrap().unwrap().refresh_available);
    drop(store);
    let reopened = Store::open(&dir.path().join("sync.db"), &SymmetricKey::new([32; 32])).unwrap();
    assert!(!reopened.personal_record().unwrap().unwrap().refresh_available);
}

#[test]
fn an_expired_or_deferred_refresh_is_not_claimed_and_a_completion_checks_device_identity() {
    let (_dir, store, _, _, _) = fixture();
    let identity = store.personal_record().unwrap().unwrap();
    assert!(store.claim_personal_refresh(&identity, 2000).unwrap().is_none());
    let claim = store.claim_personal_refresh(&identity, 1999).unwrap().unwrap();
    assert!(
        store
            .finish_personal_session(&identity, claim.generation, true, &claim.previous, Some(1500))
            .unwrap()
    );
    let current = store.personal_record().unwrap().unwrap();
    assert!(store.claim_personal_refresh(&current, 1499).unwrap().is_none());
    let next = store.claim_personal_refresh(&current, 1500).unwrap().unwrap();
    assert!(
        !store
            .finish_personal_session(&identity, claim.generation, true, &replacement(), None)
            .unwrap()
    );
    store.conn().execute("UPDATE device_key_pair SET signing = X'00'", []).unwrap();
    assert!(
        !store
            .finish_personal_session(&current, next.generation, true, &replacement(), None)
            .unwrap()
    );
    assert!(store.personal_access_token(100).unwrap().is_none());
}
