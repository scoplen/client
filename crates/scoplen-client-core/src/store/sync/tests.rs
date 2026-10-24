// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::SyncWriteAssignment;
use scoplen_crypto::SymmetricKey;
use scoplen_model::{FieldEntry, FieldPath, ObjectType, cbor::Value};

use super::*;
use crate::store::LocalWrite;

mod history;
mod reconciliation;
mod recovery_limits;

fn local() -> (tempfile::TempDir, Store, Uuid) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("sync.db"), &SymmetricKey::new([71; 32])).unwrap();
    let vault = scoplen_model::new_uuid_v7().unwrap();
    store.conn().execute(
        "INSERT INTO personal_server(singleton,origin,account_id,personal_vault_id,device_name,private_material,enrollment_attempted)
         VALUES (1,'https://example.test',?1,?2,'test',X'00',1)",
        params![scoplen_model::new_uuid_v7().unwrap().as_bytes().as_slice(), vault.as_bytes().as_slice()],
    ).unwrap();
    store.conn().execute("INSERT INTO personal_sync VALUES(1,1,X'01',X'01',X'01')", []).unwrap();
    (dir, store, vault)
}

fn host(store: &Store, name: &str) -> Object {
    store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text(name.into())),
                (FieldPath::Field(2), Value::Text("127.0.0.1".into())),
            ],
        })
        .unwrap()
}

#[test]
fn adoption_is_explicit_atomic_and_never_replaces_original_copies() {
    let (_dir, store, vault) = local();
    let original = host(&store, "first");
    let unselected = host(&store, "local");
    assert!(
        store
            .adopt_personal_objects(vault, &[original.id, scoplen_model::new_uuid_v7().unwrap()])
            .is_err()
    );
    assert!(store.personal_adoption_backup(vault, original.id).unwrap().is_none());
    assert!(store.pending_personal_objects(vault, 10).unwrap().is_empty());
    store.adopt_personal_objects(vault, &[original.id]).unwrap();
    assert_eq!(store.personal_adoption_backup(vault, original.id).unwrap().unwrap(), original);
    store
        .write(LocalWrite {
            id: Some(original.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("edited".into()))],
        })
        .unwrap();
    store.adopt_personal_objects(vault, &[original.id]).unwrap();
    assert_eq!(store.personal_adoption_backup(vault, original.id).unwrap().unwrap(), original);
    assert_eq!(store.pending_personal_objects(vault, 10).unwrap().len(), 1);
    assert_eq!(object_vault(&store.conn(), unselected.id).unwrap(), None);
    let new_local = host(&store, "new local");
    assert_eq!(object_vault(&store.conn(), new_local.id).unwrap(), None);
}

#[test]
fn a_page_merges_offline_edits_and_advances_hlc_and_cursor_atomically() {
    let (_dir, store, vault) = local();
    let original = host(&store, "first");
    store.adopt_personal_objects(vault, &[original.id]).unwrap();
    let mut remote = original.clone();
    let clock = Hlc::new(scoplen_model::system_time_millis().unwrap() + 10_000, 0).unwrap();
    remote
        .insert(
            FieldPath::Field(2),
            FieldEntry::new(Value::Text("remote.example".into()), clock, store.device_id())
                .unwrap(),
        )
        .unwrap();
    let local = store
        .write(LocalWrite {
            id: Some(original.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("offline".into()))],
        })
        .unwrap();
    store
        .apply_personal_page(
            vault,
            0,
            u64::MAX,
            &[RemoteObject { object: remote.clone(), seq: u64::MAX }],
        )
        .unwrap();
    let merged = store.get(original.id).unwrap().unwrap();
    assert_eq!(merged.field(1), local.field(1));
    assert_eq!(merged.field(2), remote.field(2));
    assert_eq!(store.personal_sync_cursor(vault).unwrap(), u64::MAX);
    let pending = store.pending_personal_objects(vault, 10).unwrap();
    assert_eq!(pending[0].base, Some(u64::MAX));
    let edited = store
        .write(LocalWrite {
            id: Some(original.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(7), Value::Text("next".into()))],
        })
        .unwrap();
    assert!(edited.field(7).unwrap().clock > clock);
    assert!(store.apply_personal_page(vault, 0, 1, &[]).is_err());
    assert_eq!(store.personal_sync_cursor(vault).unwrap(), u64::MAX);
}

#[test]
fn malformed_later_object_rolls_back_the_whole_page_and_notifications() {
    let (_dir, store, vault) = local();
    let store = std::sync::Arc::new(store);
    store.adopt_personal_objects(vault, &[]).unwrap();
    let first = host(&store, "first");
    let notifications = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = notifications.clone();
    let _subscription = store.subscribe(move |_| {
        count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    });
    let mut remote = first.clone();
    remote.id = scoplen_model::new_uuid_v7().unwrap();
    let mut malformed = remote.clone();
    malformed.id = scoplen_model::new_uuid_v7().unwrap();
    malformed.fields.remove(&FieldPath::Field(1));
    assert!(
        store
            .apply_personal_page(
                vault,
                0,
                2,
                &[
                    RemoteObject { object: remote.clone(), seq: 1 },
                    RemoteObject { object: malformed, seq: 2 },
                ]
            )
            .is_err()
    );
    assert!(store.get(remote.id).unwrap().is_none());
    assert_eq!(store.personal_sync_cursor(vault).unwrap(), 0);
    assert_eq!(notifications.load(std::sync::atomic::Ordering::Relaxed), 0);
    store.apply_personal_page(vault, 0, 1, &[RemoteObject { object: remote, seq: 1 }]).unwrap();
    assert_eq!(notifications.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[test]
fn confirmed_writes_preserve_concurrent_edits_without_advancing_applied_cursor() {
    let (_dir, store, vault) = local();
    let first = host(&store, "first");
    store.adopt_personal_objects(vault, &[first.id]).unwrap();
    let submitted = store.pending_personal_objects(vault, 10).unwrap();
    store
        .write(LocalWrite {
            id: Some(first.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("concurrent".into()))],
        })
        .unwrap();
    let response = SyncWriteBatchResponse {
        assignments: vec![SyncWriteAssignment { object_id: first.id, seq: 7 }],
    };
    store.settle_personal_write(vault, &submitted, &response).unwrap();
    let pending = store.pending_personal_objects(vault, 10).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].base, Some(7));
    assert_eq!(store.personal_sync_cursor(vault).unwrap(), 0);
    store
        .settle_personal_write(
            vault,
            &pending,
            &SyncWriteBatchResponse {
                assignments: vec![SyncWriteAssignment { object_id: first.id, seq: 8 }],
            },
        )
        .unwrap();
    assert!(store.pending_personal_objects(vault, 10).unwrap().is_empty());
    store.delete(first.id).unwrap();
    assert!(store.pending_personal_objects(vault, 10).unwrap()[0].object.is_tombstoned());
}

#[test]
fn adoption_requires_explicit_existing_references_and_restoration_remaps_only_object_references() {
    let (_dir, store, vault) = local();
    let original = host(&store, "first");
    let credential = store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::CREDENTIAL,
            fields: vec![
                (FieldPath::Field(2), Value::UInt(1)),
                (FieldPath::Field(3), Value::UInt(1)),
                // These are opaque secret bytes, even when they happen to look like an object id.
                (FieldPath::Field(4), Value::Bytes(original.id.as_bytes().to_vec())),
                (FieldPath::Field(999), Value::Bytes(original.id.as_bytes().to_vec())),
            ],
        })
        .unwrap();
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
    let host = store
        .write(LocalWrite {
            id: Some(original.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(8), Value::Bytes(login.id.as_bytes().to_vec()))],
        })
        .unwrap();
    assert!(matches!(
        store.adopt_personal_objects(vault, &[login.id]),
        Err(StoreError::SyncSelection)
    ));
    assert!(store.personal_adoption_backup(vault, login.id).unwrap().is_none());
    let ids = [host.id, login.id, credential.id];
    store.adopt_personal_objects(vault, &ids).unwrap();
    let restored = store
        .restore_personal_adoption(vault, &ids)
        .unwrap()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let restored_host = store.get(restored[&host.id]).unwrap().unwrap();
    let restored_login = store.get(restored[&login.id]).unwrap().unwrap();
    let restored_credential = store.get(restored[&credential.id]).unwrap().unwrap();
    assert_eq!(restored_host.required_uuid(8).unwrap(), restored[&login.id]);
    assert_eq!(restored_login.required_uuid(1).unwrap(), restored[&host.id]);
    assert_eq!(restored_login.required_uuid(4).unwrap(), restored[&credential.id]);
    assert_eq!(restored_credential.required_bytes(4).unwrap(), original.id.as_bytes());
    assert_eq!(restored_credential.required_bytes(999).unwrap(), original.id.as_bytes());
    assert_eq!(object_vault(&store.conn(), restored_host.id).unwrap(), None);
    assert_eq!(store.pending_personal_objects(vault, 10).unwrap().len(), 3);
    assert_eq!(store.get(host.id).unwrap().unwrap(), host);
    let count = store.list(ObjectType::HOST).unwrap().len();
    assert!(
        store
            .restore_personal_adoption(vault, &[host.id, scoplen_model::new_uuid_v7().unwrap()])
            .is_err()
    );
    assert_eq!(store.list(ObjectType::HOST).unwrap().len(), count);
    assert_eq!(store.pending_personal_objects(vault, 10).unwrap().len(), 3);
}

#[test]
fn concurrent_store_keeps_edits_and_stale_pages_cannot_roll_back_progress() {
    let (dir, store, vault) = local();
    let first = host(&store, "first");
    store.adopt_personal_objects(vault, &[first.id]).unwrap();
    let submitted = store.pending_personal_objects(vault, 10).unwrap();
    let another = Store::open(&dir.path().join("sync.db"), &SymmetricKey::new([71; 32])).unwrap();
    another
        .write(LocalWrite {
            id: Some(first.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(7), Value::Text("another store".into()))],
        })
        .unwrap();
    store
        .settle_personal_write(
            vault,
            &submitted,
            &SyncWriteBatchResponse {
                assignments: vec![SyncWriteAssignment { object_id: first.id, seq: 1 }],
            },
        )
        .unwrap();
    assert_eq!(store.pending_personal_objects(vault, 10).unwrap().len(), 1);
    another.apply_personal_page(vault, 0, 2, &[]).unwrap();
    assert!(matches!(store.apply_personal_page(vault, 0, 1, &[]), Err(StoreError::SyncChanged)));
    assert_eq!(store.personal_sync_cursor(vault).unwrap(), 2);
}
