// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use scoplen_crypto::LocalDatabaseKey;
use scoplen_model::{FieldPath, MapKey, ObjectType, cbor::Value};

use super::*;

fn key(byte: u8) -> LocalDatabaseKey {
    LocalDatabaseKey::new([byte; 32])
}

fn host(name: &str, address: &str) -> LocalWrite {
    LocalWrite {
        id: None,
        object_type: ObjectType::HOST,
        fields: vec![
            (FieldPath::Field(1), Value::Text(name.into())),
            (FieldPath::Field(2), Value::Text(address.into())),
        ],
    }
}

fn text(object: &Object, field: u64) -> &str {
    object.required_text(field).unwrap()
}

#[test]
fn a_new_store_is_migrated_and_given_a_device_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("local.db");
    let store = Store::open(&path, &key(1)).unwrap();
    assert_eq!(store.schema_version().unwrap(), MIGRATIONS.len() as u32);
    let device = store.device_id();
    assert_eq!(device.get_version_num(), 7);
    drop(store);

    let reopened = Store::open(&path, &key(1)).unwrap();
    assert_eq!(reopened.device_id(), device, "the device identity is stable");
}

#[test]
fn the_file_is_encrypted_and_only_the_right_key_opens_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("local.db");
    let store = Store::open(&path, &key(1)).unwrap();
    store.write(host("prod-db-01", "db.internal.example")).unwrap();
    drop(store);

    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.starts_with(b"SQLite format 3"), "the header is encrypted");
    assert!(!bytes.windows(10).any(|w| w == b"prod-db-01"), "contents are encrypted");

    assert!(matches!(Store::open(&path, &key(2)), Err(StoreError::WrongKey)));
    assert_eq!(Store::open(&path, &key(1)).unwrap().list(ObjectType::HOST).unwrap().len(), 1);
}

#[test]
fn a_store_from_a_newer_version_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("local.db");
    let store = Store::open(&path, &key(1)).unwrap();
    store.conn().pragma_update(None, "user_version", MIGRATIONS.len() as u32 + 1).unwrap();
    drop(store);
    match Store::open(&path, &key(1)) {
        Err(StoreError::NewerSchema { found, supported }) => {
            assert_eq!(found, supported + 1);
        }
        other => panic!("expected NewerSchema, got {other:?}"),
    }
}

#[test]
fn writes_merge_field_by_field_with_increasing_clocks() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("local.db"), &key(1)).unwrap();
    let created = store.write(host("api", "10.0.0.5")).unwrap();
    let first_clock = created.field(1).unwrap().clock;
    assert_eq!(created.field(1).unwrap().origin, store.device_id());

    let renamed = store
        .write(LocalWrite {
            id: Some(created.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("api-1".into()))],
        })
        .unwrap();
    assert_eq!(text(&renamed, 1), "api-1");
    assert_eq!(text(&renamed, 2), "10.0.0.5", "untouched fields are kept");
    assert!(renamed.field(1).unwrap().clock > first_clock);
    assert_eq!(store.get(created.id).unwrap().unwrap(), renamed);
}

#[test]
fn map_entries_are_added_and_removed_individually() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("local.db"), &key(1)).unwrap();
    let tag = |k: &str| FieldPath::map_entry(4, MapKey::Text(k.into())).unwrap();
    let mut write = host("web", "web.example");
    write.fields.push((tag("env"), Value::Text("prod".into())));
    write.fields.push((tag("team"), Value::Text("edge".into())));
    let host = store.write(write).unwrap();

    let updated = store
        .write(LocalWrite {
            id: Some(host.id),
            object_type: ObjectType::HOST,
            fields: vec![(tag("team"), Value::Null)],
        })
        .unwrap();
    assert_eq!(updated.fields.get(&tag("env")).unwrap().value, Value::Text("prod".into()));
    assert_eq!(updated.fields.get(&tag("team")).unwrap().value, Value::Null);
}

#[test]
fn snapshot_writes_hold_the_store_transaction_until_commit() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("local.db"), &key(1)).unwrap());
    let original = store.write(host("initial", "example.test")).unwrap();
    let (started, snapshot_ready) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let first = std::thread::spawn({
        let store = store.clone();
        move || {
            store
                .write_batch_with_snapshot::<StoreError>(ObjectType::HOST, |objects| {
                    assert_eq!(text(&objects[0], 1), "initial");
                    started.send(()).unwrap();
                    released.recv().unwrap();
                    Ok(vec![LocalWrite {
                        id: Some(original.id),
                        object_type: ObjectType::HOST,
                        fields: vec![(FieldPath::Field(1), Value::Text("first".into()))],
                    }])
                })
                .unwrap()
        }
    });
    snapshot_ready.recv().unwrap();
    assert!(store.conn.try_lock().is_err(), "snapshot and writes share the Store lock");
    let (attempting, attempted) = std::sync::mpsc::channel();
    let second = std::thread::spawn({
        let store = store.clone();
        move || {
            attempting.send(()).unwrap();
            store
                .write_batch_with_snapshot::<StoreError>(ObjectType::HOST, |objects| {
                    assert_eq!(
                        text(&objects[0], 1),
                        "first",
                        "later snapshot observes committed write"
                    );
                    Ok(vec![LocalWrite {
                        id: Some(original.id),
                        object_type: ObjectType::HOST,
                        fields: vec![(FieldPath::Field(1), Value::Text("second".into()))],
                    }])
                })
                .unwrap()
        }
    });
    attempted.recv().unwrap();
    release.send(()).unwrap();
    first.join().unwrap();
    second.join().unwrap();
    assert_eq!(text(&store.get(original.id).unwrap().unwrap(), 1), "second");
}

#[test]
fn invalid_objects_are_rejected_and_nothing_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("local.db"), &key(1)).unwrap();
    let missing_address = LocalWrite {
        id: None,
        object_type: ObjectType::HOST,
        fields: vec![(FieldPath::Field(1), Value::Text("no-address".into()))],
    };
    assert!(matches!(store.write(missing_address), Err(StoreError::Model(_))));
    let too_long = host(&"x".repeat(scoplen_model::MAX_TEXT_BYTES + 1), "a.example");
    assert!(store.write(too_long).is_err());
    assert!(store.list(ObjectType::HOST).unwrap().is_empty());
}

#[test]
fn create_batch_rolls_back_when_a_later_object_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("local.db"), &key(1)).unwrap();
    let first_id = scoplen_model::new_uuid_v7().unwrap();
    let second_id = scoplen_model::new_uuid_v7().unwrap();

    let result = store.create_batch(vec![
        NewObject {
            id: first_id,
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text("valid".into())),
                (FieldPath::Field(2), Value::Text("valid.example".into())),
            ],
        },
        NewObject {
            id: second_id,
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("missing address".into()))],
        },
    ]);

    assert!(matches!(result, Err(StoreError::Model(_))));
    assert!(store.get(first_id).unwrap().is_none());
    assert!(store.get(second_id).unwrap().is_none());
}

#[test]
fn create_and_promotion_roll_back_together_when_a_promotion_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("local.db"), &key(1)).unwrap();
    let host_id = scoplen_model::new_uuid_v7().unwrap();
    let missing_id = scoplen_model::new_uuid_v7().unwrap();
    let result = store.create_batch_with_implicit_and_promotions(
        vec![NewObject {
            id: host_id,
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text("one".into())),
                (FieldPath::Field(2), Value::Text("one.example".into())),
            ],
        }],
        vec![(ObjectType::HOST, host_id)],
        vec![(ObjectType::CREDENTIAL, missing_id)],
    );
    assert!(matches!(result, Err(StoreError::NotFound(id)) if id == missing_id));
    assert!(store.get(host_id).unwrap().is_none());
    assert!(!store.is_implicit(host_id).unwrap());
}

#[test]
fn initial_inventory_batch_refuses_a_second_host_transactionally() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("local.db"), &key(1)).unwrap();
    store.write(host("existing", "existing.example")).unwrap();
    let new_id = scoplen_model::new_uuid_v7().unwrap();
    let result = store.create_initial_inventory_batch(
        vec![NewObject {
            id: new_id,
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text("new".into())),
                (FieldPath::Field(2), Value::Text("new.example".into())),
            ],
        }],
        Vec::new(),
        Vec::new(),
    );
    assert!(matches!(result, Err(StoreError::InventoryNotEmpty)));
    assert!(store.get(new_id).unwrap().is_none());
    assert_eq!(store.list(ObjectType::HOST).unwrap().len(), 1);
}

#[test]
fn changing_a_missing_object_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("local.db"), &key(1)).unwrap();
    let id = scoplen_model::new_uuid_v7().unwrap();
    let write = LocalWrite { id: Some(id), object_type: ObjectType::HOST, fields: vec![] };
    assert!(matches!(store.write(write), Err(StoreError::NotFound(missing)) if missing == id));
    assert!(matches!(store.delete(id), Err(StoreError::NotFound(_))));
}

#[test]
fn deleted_objects_leave_lists_but_remain_restorable() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("local.db"), &key(1)).unwrap();
    let host = store.write(host("old", "old.example")).unwrap();
    store.delete(host.id).unwrap();
    assert!(store.list(ObjectType::HOST).unwrap().is_empty());
    assert!(!store.live_ids().unwrap().contains(&host.id));
    let kept = store.get(host.id).unwrap().unwrap();
    assert!(kept.is_tombstoned());

    // A later field write resurrects it (`04-object-model.md` §5 rule 3).
    let restored = store
        .write(LocalWrite {
            id: Some(host.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("old".into()))],
        })
        .unwrap();
    assert!(restored.is_resurrected());
    assert_eq!(store.list(ObjectType::HOST).unwrap().len(), 1);
}

#[test]
fn subscribers_hear_committed_changes_until_unsubscribed() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("local.db"), &key(1)).unwrap());
    let heard = Arc::new(Mutex::new(Vec::new()));
    let sink = heard.clone();
    let subscription = store.subscribe(move |change| sink.lock().unwrap().push(change.clone()));

    let host = store.write(host("a", "a.example")).unwrap();
    store.delete(host.id).unwrap();
    let _ = store.write(LocalWrite { id: None, object_type: ObjectType::HOST, fields: vec![] });
    assert_eq!(
        *heard.lock().unwrap(),
        vec![
            Change { object_type: ObjectType::HOST, ids: vec![host.id] },
            Change { object_type: ObjectType::HOST, ids: vec![host.id] },
        ],
        "a failed write is not announced"
    );

    drop(subscription);
    store.write(self::host("b", "b.example")).unwrap();
    assert_eq!(heard.lock().unwrap().len(), 2);
}

#[test]
fn the_vault_limit_stops_new_objects() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("local.db"), &key(1)).unwrap();
    let existing = store.write(host("a", "a.example")).unwrap();
    // Fill the collection directly; writing 100,000 objects one by one is slow.
    {
        let conn = store.conn();
        let mut insert = conn
            .prepare("INSERT INTO objects (id, vault, type, envelope, deleted, updated_at) VALUES (?1, NULL, 1, x'00', 0, 0)")
            .unwrap();
        for i in 1..MAX_OBJECTS_PER_VAULT {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&i.to_be_bytes());
            insert.execute(params![id.as_slice()]).unwrap();
        }
    }
    assert!(matches!(store.write(host("b", "b.example")), Err(StoreError::VaultFull)));
    // Changing an existing object is still allowed.
    let rename = LocalWrite {
        id: Some(existing.id),
        object_type: ObjectType::HOST,
        fields: vec![(FieldPath::Field(1), Value::Text("a2".into()))],
    };
    assert!(store.write(rename).is_ok());
}

mod device_local {
    use super::*;
    use crate::store::device::{DeviceKeyPair, SESSION_HISTORY_LIMIT, SessionKind, SessionOutcome};
    use scoplen_crypto::SecretVec;

    fn open() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("local.db"), &key(1)).unwrap();
        (dir, store)
    }

    #[test]
    fn device_credentials_hold_a_secret_or_a_keystore_handle() {
        let (_dir, store) = open();
        let credential = scoplen_model::new_uuid_v7().unwrap();
        assert!(store.device_credential(credential).unwrap().is_none());

        store.set_device_secret(credential, b"-----BEGIN OPENSSH PRIVATE KEY-----").unwrap();
        let held = store.device_credential(credential).unwrap().unwrap();
        assert_eq!(held.secret.unwrap().as_bytes(), b"-----BEGIN OPENSSH PRIVATE KEY-----");
        assert_eq!(held.keystore_handle, None);

        store.set_device_keystore_handle(credential, "se:0f3a").unwrap();
        let held = store.device_credential(credential).unwrap().unwrap();
        assert_eq!(
            (held.secret, held.keystore_handle.as_deref()),
            (None, Some("se:0f3a")),
            "the secret is replaced"
        );
        assert!(!format!("{:?}", store.device_credential(credential).unwrap()).contains("OPENSSH"));

        store.remove_device_credential(credential).unwrap();
        assert!(store.device_credential(credential).unwrap().is_none());
    }

    #[test]
    fn device_records_are_not_replicated_objects() {
        let (_dir, store) = open();
        store.set_device_secret(scoplen_model::new_uuid_v7().unwrap(), b"x").unwrap();
        store.save_window_state("main", b"{}").unwrap();
        assert!(
            store.live_ids().unwrap().is_empty(),
            "nothing device-local is an object a sync could send"
        );
    }

    #[test]
    fn the_device_key_pair_is_kept() {
        let (_dir, store) = open();
        assert!(store.device_key_pair().unwrap().is_none());
        let pair = DeviceKeyPair {
            signing: SecretVec::new(vec![1; 32]),
            kem: SecretVec::new(vec![2; 32]),
        };
        store.set_device_key_pair(&pair).unwrap();
        assert_eq!(store.device_key_pair().unwrap().unwrap(), pair);
    }

    #[test]
    fn session_history_records_starts_and_ends_newest_first() {
        let (_dir, store) = open();
        let profile = scoplen_model::new_uuid_v7().unwrap();
        let first = store.record_session_start(profile, SessionKind::Terminal).unwrap();
        let second = store.record_session_start(profile, SessionKind::Files).unwrap();
        store.record_session_end(first, SessionOutcome::Failed).unwrap();
        assert!(matches!(
            store.record_session_end(first, SessionOutcome::Closed),
            Err(StoreError::NotFound(_))
        ));

        let recent = store.recent_sessions(10).unwrap();
        assert_eq!(recent.iter().map(|e| e.id).collect::<Vec<_>>(), [second, first]);
        assert_eq!(recent[1].outcome, Some(SessionOutcome::Failed));
        assert!(recent[1].ended_at.is_some());
        assert_eq!((recent[0].kind, recent[0].outcome), (SessionKind::Files, None));
    }

    #[test]
    fn session_forgetting_requires_an_ended_session_and_removes_scrollback() {
        let (_dir, store) = open();
        let profile = scoplen_model::new_uuid_v7().unwrap();
        let active = store.record_session_start(profile, SessionKind::Terminal).unwrap();
        store.save_scrollback(active, b"secret terminal output").unwrap();
        assert!(
            matches!(store.forget_session(active), Err(StoreError::SessionActive(id)) if id == active)
        );
        assert!(store.session(active).unwrap().is_some());

        store.record_session_end(active, SessionOutcome::Closed).unwrap();
        store.forget_session(active).unwrap();
        assert!(store.session(active).unwrap().is_none());
        assert!(store.scrollback(active).unwrap().is_none());
        assert!(
            matches!(store.forget_session(active), Err(StoreError::NotFound(id)) if id == active)
        );
    }

    #[test]
    fn session_history_is_bounded() {
        let (_dir, store) = open();
        let profile = scoplen_model::new_uuid_v7().unwrap();
        let first = store.record_session_start(profile, SessionKind::Terminal).unwrap();
        for _ in 0..SESSION_HISTORY_LIMIT {
            store.record_session_start(profile, SessionKind::Terminal).unwrap();
        }
        let recent = store.recent_sessions(SESSION_HISTORY_LIMIT + 10).unwrap();
        assert_eq!(recent.len(), SESSION_HISTORY_LIMIT);
        assert!(!recent.iter().any(|e| e.id == first), "the oldest entry was removed");
    }

    #[test]
    fn scrollback_and_window_state_are_saved_and_replaced() {
        let (_dir, store) = open();
        let session = scoplen_model::new_uuid_v7().unwrap();
        store.save_scrollback(session, b"$ ls\r\n").unwrap();
        store.save_scrollback(session, b"$ ls\r\nREADME\r\n").unwrap();
        assert_eq!(store.scrollback(session).unwrap().unwrap(), b"$ ls\r\nREADME\r\n");
        store.remove_scrollback(session).unwrap();
        assert!(store.scrollback(session).unwrap().is_none());

        assert!(store.window_state("main").unwrap().is_none());
        store.save_window_state("main", b"{\"width\":1200}").unwrap();
        assert_eq!(store.window_state("main").unwrap().unwrap(), b"{\"width\":1200}");
    }

    #[test]
    fn a_store_from_before_device_records_is_migrated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("local.db");
        {
            // A store created by a build that knew only migration 1.
            let conn = rusqlite::Connection::open(&path).unwrap();
            apply_key(&conn, &key(1)).unwrap();
            conn.execute_batch(MIGRATIONS[0]).unwrap();
            conn.pragma_update(None, "user_version", 1).unwrap();
            conn.execute(
                "INSERT INTO device (singleton, device_id, clock, created_at) VALUES (1, ?1, 0, 0)",
                params![scoplen_model::new_uuid_v7().unwrap().as_bytes().as_slice()],
            )
            .unwrap();
        }
        let store = Store::open(&path, &key(1)).unwrap();
        assert_eq!(store.schema_version().unwrap(), MIGRATIONS.len() as u32);
        store.save_window_state("main", b"{}").unwrap();
    }
}
