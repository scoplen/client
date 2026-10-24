// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::sync::Arc;

#[test]
fn history_restoration_preserves_tombstoned_source_unknown_content_and_device_secrets() {
    let (_dir, store, vault) = local();
    let object = store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::CREDENTIAL,
            fields: vec![
                (FieldPath::Field(2), Value::UInt(1)),
                (FieldPath::Field(3), Value::UInt(2)),
                (FieldPath::Field(999), Value::Bytes(vec![19; 16])),
            ],
        })
        .unwrap();
    store.set_device_secret(object.id, b"device-only").unwrap();
    store.adopt_personal_objects(vault, &[object.id]).unwrap();
    store.delete(object.id).unwrap();
    let deleted = store.get(object.id).unwrap().unwrap();
    let account = store.personal_record().unwrap().unwrap().account_id;
    store.restore_personal_history(account, vault, deleted.clone()).unwrap();
    assert_eq!(store.get(object.id).unwrap(), Some(deleted.clone()));
    let restored = store
        .list(ObjectType::CREDENTIAL)
        .unwrap()
        .into_iter()
        .find(|value| value.id != object.id)
        .unwrap();
    assert!(!restored.is_tombstoned());
    assert_eq!(restored.required_bytes(999).unwrap(), [19; 16]);
    assert!(
        restored.fields.values().all(|field| field.origin == store.device_id()
            && field.clock > object.field(2).unwrap().clock)
    );
    assert!(store.device_credential(restored.id).unwrap().is_none());
    assert!(store.device_credential(object.id).unwrap().is_some());
    assert_eq!(object_vault(&store.conn(), restored.id).unwrap(), None);
    assert_eq!(store.pending_personal_objects(vault, 10).unwrap().len(), 1);
    assert_eq!(store.personal_sync_cursor(vault).unwrap(), 0);
}

#[test]
fn history_restoration_requires_exact_account_vault_and_adopted_source() {
    let (_dir, store, vault) = local();
    let object = host(&store, "Local source");
    let account = store.personal_record().unwrap().unwrap().account_id;
    assert!(store.personal_history_object(vault, object.id).is_err());
    assert!(store.restore_personal_history(account, vault, object.clone()).is_err());
    store.adopt_personal_objects(vault, &[object.id]).unwrap();
    assert!(
        store
            .restore_personal_history(scoplen_model::new_uuid_v7().unwrap(), vault, object.clone())
            .is_err()
    );
    assert!(
        store
            .restore_personal_history(
                account,
                scoplen_model::new_uuid_v7().unwrap(),
                object.clone()
            )
            .is_err()
    );
    assert_eq!(store.list(ObjectType::HOST).unwrap(), [object]);
}

#[test]
fn history_restoration_rolls_back_clock_object_and_notifications_at_local_capacity() {
    let (_dir, store, vault) = local();
    let store = Arc::new(store);
    let object = host(&store, "Original remains");
    store.adopt_personal_objects(vault, &[object.id]).unwrap();
    let account = store.personal_record().unwrap().unwrap().account_id;
    store.conn().execute("WITH RECURSIVE ids(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM ids WHERE n<100000)
        INSERT INTO objects(id,vault,type,envelope,deleted,updated_at) SELECT randomblob(16),NULL,1,X'00',0,0 FROM ids", []).unwrap();
    let clock = store
        .conn()
        .query_row("SELECT clock FROM device WHERE singleton=1", [], |row| row.get::<_, i64>(0))
        .unwrap();
    let notices = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = notices.clone();
    let _subscription = store.subscribe(move |_| {
        count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    });
    assert!(matches!(
        store.restore_personal_history(account, vault, object.clone()),
        Err(StoreError::VaultFull)
    ));
    assert_eq!(
        store
            .conn()
            .query_row("SELECT clock FROM device WHERE singleton=1", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        clock
    );
    assert_eq!(notices.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(store.get(object.id).unwrap(), Some(object));
}
