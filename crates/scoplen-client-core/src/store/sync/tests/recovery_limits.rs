// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::personal_inventory::{PersonalInventoryError, PersonalInventorySettings};

#[test]
fn recovery_history_limits_are_checked_before_decoding_and_reported_explicitly() {
    for oversized_bytes in [false, true] {
        let (_dir, store, vault) = local();
        let original = host(&store, "local inventory remains available");
        store.adopt_personal_objects(vault, &[]).unwrap();
        if oversized_bytes {
            store
                .conn()
                .execute(
                    "INSERT INTO personal_sync_recovery VALUES(?1,?2,?3,zeroblob(33554433),0)",
                    params![
                        scoplen_model::new_uuid_v7().unwrap().as_bytes().as_slice(),
                        vault.as_bytes().as_slice(),
                        original.id.as_bytes().as_slice()
                    ],
                )
                .unwrap();
        } else {
            store.conn().execute("WITH RECURSIVE ids(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM ids WHERE n<100000)
                INSERT INTO personal_sync_recovery SELECT randomblob(16),?1,?2,X'00',0 FROM ids",params![vault.as_bytes().as_slice(),original.id.as_bytes().as_slice()]).unwrap();
        }
        assert!(matches!(store.personal_inventory_snapshot(vault), Err(StoreError::RecoveryLimit)));
        assert_eq!(
            PersonalInventorySettings::default().status(&store).unwrap_err(),
            PersonalInventoryError::ResourceLimit
        );
        assert_eq!(store.get(original.id).unwrap(), Some(original));
        assert_eq!(store.personal_sync_cursor(vault).unwrap(), 0);
    }
}

#[test]
fn reconciliation_that_would_overfill_recovery_history_rolls_back_and_leaves_copies_restorable() {
    let (_dir, store, vault) = local();
    let object = host(&store, "keep this unsynced edit");
    store.adopt_personal_objects(vault, &[object.id]).unwrap();
    let copy = scoplen_model::new_uuid_v7().unwrap();
    store
        .conn()
        .execute(
            "INSERT INTO personal_sync_recovery VALUES(?1,?2,?3,?4,0)",
            params![
                copy.as_bytes().as_slice(),
                vault.as_bytes().as_slice(),
                object.id.as_bytes().as_slice(),
                object.encode().unwrap()
            ],
        )
        .unwrap();
    store
        .conn()
        .execute(
            "WITH RECURSIVE ids(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM ids WHERE n<99999)
        INSERT INTO personal_sync_recovery SELECT randomblob(16),?1,?2,?3,0 FROM ids",
            params![
                vault.as_bytes().as_slice(),
                object.id.as_bytes().as_slice(),
                object.encode().unwrap()
            ],
        )
        .unwrap();
    assert!(matches!(
        store.reconcile_personal_snapshot(vault, 0, 1, &[]),
        Err(StoreError::RecoveryLimit)
    ));
    assert_eq!(store.get(object.id).unwrap(), Some(object));
    assert_eq!(store.personal_sync_cursor(vault).unwrap(), 0);
    assert_eq!(store.personal_acknowledged_cursor(vault).unwrap(), 0);
    assert_eq!(store.pending_personal_objects(vault, 10).unwrap().len(), 1);
    assert_eq!(
        store
            .conn()
            .query_row("SELECT count(*) FROM personal_sync_recovery", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        100000
    );
    let restored = store.restore_personal_recovery(vault, &[copy]).unwrap();
    assert!(store.get(restored[0].1).unwrap().is_some());
}
