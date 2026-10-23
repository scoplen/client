// SPDX-License-Identifier: Apache-2.0
use super::*;

fn apply(store: &Store, vault: Uuid, objects: &[Object]) {
    store
        .adopt_personal_objects(vault, &objects.iter().map(|object| object.id).collect::<Vec<_>>())
        .unwrap();
    let objects = objects
        .iter()
        .enumerate()
        .map(|(i, object)| RemoteObject { object: object.clone(), seq: i as u64 + 1 })
        .collect::<Vec<_>>();
    store.apply_personal_page(vault, 0, objects.len() as u64, &objects).unwrap();
    store.save_personal_acknowledgement(vault, objects.len() as u64).unwrap();
}

#[test]
fn failed_reconciliation_rolls_back_removals_copies_clocks_progress_and_notifications() {
    let (_dir, store, vault) = local();
    let store = std::sync::Arc::new(store);
    let clean = host(&store, "clean");
    let dirty = host(&store, "dirty");
    apply(&store, vault, &[clean.clone(), dirty.clone()]);
    let dirty = store
        .write(LocalWrite {
            id: Some(dirty.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("preserve this".into()))],
        })
        .unwrap();
    let unowned = host(&store, "unowned collision");
    let mut remote = unowned.clone();
    remote.id = scoplen_model::new_uuid_v7().unwrap();
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = count.clone();
    let _subscription = store.subscribe(move |_| {
        observed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    });
    let clock: i64 =
        store.conn().query_row("SELECT clock FROM device", [], |row| row.get(0)).unwrap();
    assert!(matches!(
        store.reconcile_personal_snapshot(
            vault,
            2,
            4,
            &[
                RemoteObject { object: remote.clone(), seq: 3 },
                RemoteObject { object: unowned.clone(), seq: 4 },
            ]
        ),
        Err(StoreError::SyncSelection)
    ));
    assert_eq!(store.get(clean.id).unwrap(), Some(clean));
    assert_eq!(store.get(dirty.id).unwrap(), Some(dirty));
    assert_eq!(store.get(unowned.id).unwrap(), Some(unowned));
    assert!(store.get(remote.id).unwrap().is_none());
    let status = store.personal_inventory_snapshot(vault).unwrap();
    assert_eq!((status.applied, status.acknowledged, status.pending), (2, 2, 1));
    assert!(status.recovery.is_empty());
    assert_eq!(
        clock,
        store.conn().query_row("SELECT clock FROM device", [], |row| row.get::<_, i64>(0)).unwrap()
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(matches!(
        store.reconcile_personal_snapshot(vault, 1, 0, &[]),
        Err(StoreError::SyncChanged)
    ));
    assert_eq!(store.personal_sync_cursor(vault).unwrap(), 2);
}

#[test]
fn reconciliation_preserves_confirmed_writes_with_unconfirmed_ack_and_rereads_current_edits() {
    let (dir, store, vault) = local();
    let first = host(&store, "first");
    let second = host(&store, "second");
    apply(&store, vault, &[first.clone(), second.clone()]);
    let another = Store::open(&dir.path().join("sync.db"), &SymmetricKey::new([71; 32])).unwrap();
    let edited = another
        .write(LocalWrite {
            id: Some(second.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("concurrent edit".into()))],
        })
        .unwrap();
    store
        .conn()
        .execute(
            "UPDATE personal_sync_objects SET base=?2,dirty=0 WHERE object_id=?1",
            params![first.id.as_bytes().as_slice(), 3_u64.to_be_bytes().as_slice()],
        )
        .unwrap();
    store
        .reconcile_personal_snapshot(
            vault,
            2,
            3,
            &[RemoteObject { object: second.clone(), seq: 3 }],
        )
        .unwrap();
    assert_eq!(store.get(second.id).unwrap(), Some(edited));
    assert!(store.get(first.id).unwrap().is_none());
    let status = store.personal_inventory_snapshot(vault).unwrap();
    assert_eq!((status.applied, status.acknowledged, status.pending), (3, 2, 1));
    assert_eq!(status.recovery.len(), 1);
    assert_eq!(status.recovery[0].1, first);
    assert_eq!(store.pending_personal_objects(vault, 10).unwrap()[0].base, Some(3));
}

#[test]
fn recovery_restore_remaps_exact_references_without_copying_device_secrets_or_uploading() {
    let (dir, store, vault) = local();
    let original = host(&store, "first");
    let credential = store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::CREDENTIAL,
            fields: vec![
                (FieldPath::Field(2), Value::UInt(1)),
                (FieldPath::Field(3), Value::UInt(2)),
            ],
        })
        .unwrap();
    store.set_device_secret(credential.id, b"device-local-secret").unwrap();
    let login = store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::ACCESS_PROFILE,
            fields: vec![
                (FieldPath::Field(1), Value::Bytes(original.id.as_bytes().to_vec())),
                (FieldPath::Field(3), Value::Text("alice".into())),
                (FieldPath::Field(4), Value::Bytes(credential.id.as_bytes().to_vec())),
            ],
        })
        .unwrap();
    let original = store
        .write(LocalWrite {
            id: Some(original.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(8), Value::Bytes(login.id.as_bytes().to_vec()))],
        })
        .unwrap();
    store.adopt_personal_objects(vault, &[original.id, credential.id, login.id]).unwrap();
    store.reconcile_personal_snapshot(vault, 0, 0, &[]).unwrap();
    let copies = store.personal_inventory_snapshot(vault).unwrap().recovery;
    assert_eq!(copies.len(), 3);
    let ids = copies.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    let restored = store
        .restore_personal_recovery(vault, &ids)
        .unwrap()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let restored_host = store.get(restored[&original.id]).unwrap().unwrap();
    let restored_login = store.get(restored[&login.id]).unwrap().unwrap();
    let restored_credential = store.get(restored[&credential.id]).unwrap().unwrap();
    assert_eq!(restored_host.required_uuid(8).unwrap(), restored[&login.id]);
    assert_eq!(restored_login.required_uuid(1).unwrap(), restored[&original.id]);
    assert_eq!(restored_login.required_uuid(4).unwrap(), restored[&credential.id]);
    assert!(store.device_credential(restored_credential.id).unwrap().is_none());
    assert!(store.device_credential(credential.id).unwrap().is_some());
    assert!(!restored_host.is_tombstoned());
    assert!(restored_host.field(1).unwrap().clock > original.field(1).unwrap().clock);
    assert!(store.pending_personal_objects(vault, 10).unwrap().is_empty());
    assert!(
        store
            .personal_inventory_snapshot(vault)
            .unwrap()
            .objects
            .iter()
            .all(|(_, personal, _)| !*personal)
    );
    let count = store.list(ObjectType::HOST).unwrap().len();
    assert!(store.restore_personal_recovery(vault, &[ids[0], ids[0]]).is_err());
    assert!(
        store
            .restore_personal_recovery(vault, &[ids[0], scoplen_model::new_uuid_v7().unwrap()])
            .is_err()
    );
    assert_eq!(store.list(ObjectType::HOST).unwrap().len(), count);
    drop(store);
    let reopened = Store::open(&dir.path().join("sync.db"), &SymmetricKey::new([71; 32])).unwrap();
    assert_eq!(reopened.personal_inventory_snapshot(vault).unwrap().recovery, copies);
    assert!(reopened.device_credential(credential.id).unwrap().is_some());
    let database = std::fs::read(dir.path().join("sync.db")).unwrap();
    assert!(
        !database
            .windows(b"device-local-secret".len())
            .any(|bytes| bytes == b"device-local-secret")
    );
}

#[test]
fn historical_recovery_copies_are_immutable_and_cannot_restore_one_original_twice_in_one_selection()
{
    let (_dir, store, vault) = local();
    let object = host(&store, "first");
    store.adopt_personal_objects(vault, &[object.id]).unwrap();
    store.reconcile_personal_snapshot(vault, 0, 0, &[]).unwrap();
    let first = store.personal_inventory_snapshot(vault).unwrap().recovery;
    store
        .reconcile_personal_snapshot(
            vault,
            0,
            1,
            &[RemoteObject { object: object.clone(), seq: 1 }],
        )
        .unwrap();
    store
        .write(LocalWrite {
            id: Some(object.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("second version".into()))],
        })
        .unwrap();
    store.reconcile_personal_snapshot(vault, 1, 1, &[]).unwrap();
    let copies = store.personal_inventory_snapshot(vault).unwrap().recovery;
    assert_eq!(copies.len(), 2);
    assert_eq!(copies[0], first[0]);
    assert_ne!(copies[0].0, copies[1].0);
    assert!(matches!(
        store.restore_personal_recovery(vault, &[copies[0].0, copies[1].0]),
        Err(StoreError::SyncSelection)
    ));
    assert!(store.list(ObjectType::HOST).unwrap().is_empty());
    store.restore_personal_recovery(vault, &[copies[1].0]).unwrap();
    assert_eq!(
        store.list(ObjectType::HOST).unwrap()[0].required_text(1).unwrap(),
        "second version"
    );
    assert_eq!(store.personal_inventory_snapshot(vault).unwrap().recovery, copies);
}
