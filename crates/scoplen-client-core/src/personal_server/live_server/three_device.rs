// SPDX-License-Identifier: Apache-2.0
//! Real third-device admission and bounded convergence of independently edited stores.

use scoplen_model::Object;

use super::*;
use crate::personal_inventory::{PersonalInventoryResult, PersonalInventoryStatus};

pub(super) async fn verify(
    deployment: &Deployment,
    old_manager: &PersonalServer,
    old: Arc<Store>,
    paired: pairing::PairedDevice,
) -> (PersonalAccountSnapshot, [Object; 2], String) {
    let ca = bounded_file(&deployment.ca_certificate, 65_536);
    let third_manager = PersonalServer {
        operation: Mutex::new(()),
        transport: Ok(trusted_transport(&ca)),
        pairing: Default::default(),
    };
    let directory = tempfile::tempdir().expect("independent third-device directory");
    let path = directory.path().join("third.sqlite");
    let key = SymmetricKey::new([61; 32]);
    let third = Arc::new(Store::open(&path, &key).expect("independent encrypted third device"));
    assert_ne!(third.device_id(), old.device_id());
    assert_ne!(third.device_id(), paired.store.device_id());
    host(&third, "Third-device local-only host", "192.0.2.73");
    pairing::admit(
        deployment,
        (old_manager, &old),
        (&third_manager, &third),
        directory.path(),
        "Live third device",
    )
    .await;

    let (first, second, last) = tokio::join!(
        old_manager.query_account(old.clone()),
        paired.manager.query_account(paired.store.clone()),
        third_manager.query_account(third.clone()),
    );
    let accounts = [
        first.expect("original device verifies three-device membership"),
        second.expect("paired device verifies three-device membership"),
        last.expect("third device verifies three-device membership"),
    ];
    let settings = PersonalInventorySettings::default();
    let stores = [&*old, &*paired.store, &*third];
    for (account, store) in accounts.iter().zip(stores) {
        assert_eq!(account.account_id, accounts[0].account_id);
        assert_eq!(account.devices.len(), 3);
        assert_eq!(account.devices.iter().filter(|device| device.current).count(), 1);
        for expected in stores {
            assert!(
                account.devices.iter().any(|device| device.id == expected.device_id().to_string())
            );
        }
        assert!(
            account
                .devices
                .iter()
                .any(|device| { device.current && device.id == store.device_id().to_string() })
        );
    }

    // Independent hosts leave the existing exact three-version history scenario untouched.
    let original = host(&old, "Three-device merge host", "192.0.2.70");
    let removable = host(&old, "Three-device deletion host", "192.0.2.71");
    let preview = settings
        .preview(&old, vec![original.id.to_string(), removable.id.to_string()])
        .expect("review only the two new synchronization targets");
    assert!(preview.missing.is_empty());
    assert!(preview.token.is_some());
    let uploaded = settings
        .synchronize(old_manager, old.clone(), preview.token)
        .await
        .expect("explicitly adopt the independent convergence targets");
    assert_eq!(uploaded.uploaded, 2);
    let devices = [(old_manager, &old), (&paired.manager, &paired.store), (&third_manager, &third)];
    for result in synchronize(devices).await {
        assert_eq!(result.uploaded, 0);
        assert!(!result.more);
    }
    let before = stores.map(|store| settings.status(store).expect("common starting progress"));
    for (store, status) in stores.iter().zip(&before) {
        assert_eq!(store.get(original.id).unwrap(), Some(original.clone()));
        assert_eq!(store.get(removable.id).unwrap(), Some(removable.clone()));
        assert_eq!(status.pending, 0);
        assert_eq!(status.applied_cursor, before[0].applied_cursor);
        assert_eq!(status.applied_cursor, status.acknowledged_cursor);
    }
    let private = stores.map(|store| {
        settings
            .status(store)
            .unwrap()
            .objects
            .iter()
            .filter(|object| !object.personal)
            .map(|object| store.get(object.id.parse().unwrap()).unwrap().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(private.iter().all(|objects| !objects.is_empty()));

    // No background owner or explicit network intent runs during these local mutations.
    let edits = [
        edit(&old, original.id, "Original offline name", (2, Value::Text("192.0.2.72".into()))),
        edit(
            &paired.store,
            original.id,
            "Paired offline name",
            (7, Value::Text("Paired offline notes".into())),
        ),
        edit(&third, original.id, "Third offline name", (6, Value::Bool(true))),
    ];
    let expected =
        scoplen_model::merge(&scoplen_model::merge(&edits[0], &edits[1]).unwrap(), &edits[2])
            .expect("the contract merges independent offline field entries");
    let winner = edits
        .iter()
        .max_by_key(|object| {
            let field = object.field(1).unwrap();
            (field.clock, field.origin)
        })
        .unwrap();
    assert_eq!(expected.required_text(1).unwrap(), winner.required_text(1).unwrap());
    assert_eq!(expected.required_text(2).unwrap(), "192.0.2.72");
    assert_eq!(expected.required_text(7).unwrap(), "Paired offline notes");
    assert_eq!(expected.field(6).unwrap().value, Value::Bool(true));
    let edited = paired
        .store
        .write(LocalWrite {
            id: Some(removable.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(7), Value::Text("Offline edit before deletion".into()))],
        })
        .expect("edit the removable host while synchronization is stopped");
    paired.store.delete(removable.id).expect("delete offline through the production local intent");
    let deleted = paired.store.get(removable.id).unwrap().unwrap();
    assert!(deleted.is_tombstoned());
    assert!(deleted.tombstone.as_ref().unwrap().clock > edited.field(7).unwrap().clock);
    assert_eq!(old.get(removable.id).unwrap(), Some(removable.clone()));
    assert_eq!(third.get(removable.id).unwrap(), Some(removable));
    for (index, store) in stores.iter().enumerate() {
        assert_eq!(store.get(original.id).unwrap(), Some(edits[index].clone()));
        let offline = settings.status(store).expect("durable offline outbox");
        assert_eq!(offline.pending, if index == 1 { 2 } else { 1 });
        assert_eq!(offline.applied_cursor, before[index].applied_cursor);
        assert_eq!(offline.acknowledged_cursor, before[index].acknowledged_cursor);
    }

    tokio::time::timeout(Duration::from_secs(30), async {
        let first = synchronize(devices).await;
        for (index, result) in first.iter().enumerate() {
            assert!(!result.more);
            assert!(result.uploaded >= if index == 1 { 2 } else { 1 });
        }
        // Every first-round Result succeeded. This fixed catch-up performs no new local writes
        // and must not resend a failed or uncertain commit.
        for result in synchronize(devices).await {
            assert_eq!(result.uploaded, 0);
            assert!(!result.more);
        }
    })
    .await
    .expect("bounded parallel publication and one successful catch-up round");

    let expected = [expected, deleted];
    let saved = stores.map(|store| settings.status(store).expect("converged durable progress"));
    for (index, store) in stores.iter().enumerate() {
        assert_contents(store, &expected);
        assert_eq!(saved[index].pending, 0);
        assert_eq!(saved[index].applied_cursor, saved[index].acknowledged_cursor);
        assert_eq!(saved[index].applied_cursor, saved[0].applied_cursor);
        assert!(
            saved[index].applied_cursor.parse::<u64>().unwrap()
                > before[index].applied_cursor.parse::<u64>().unwrap()
        );
        assert_private(store, &private[index]);
        for (other, objects) in private.iter().enumerate() {
            if other != index {
                for object in objects {
                    assert!(store.get(object.id).unwrap().is_none());
                }
            }
        }
    }

    let paired = paired.reopen();
    offline(&paired.store, &accounts[1], &expected, &saved[1]);
    assert_private(&paired.store, &private[1]);
    drop(third_manager);
    drop(third);
    let third = Store::open(&path, &key).expect("reopen encrypted third device offline");
    offline(&third, &accounts[2], &expected, &saved[2]);
    assert_private(&third, &private[2]);
    (accounts.into_iter().next().unwrap(), expected, saved[0].applied_cursor.clone())
}

fn host(store: &Store, name: &str, address: &str) -> Object {
    store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text(name.into())),
                (FieldPath::Field(2), Value::Text(address.into())),
            ],
        })
        .expect("create an independent local host")
}

fn edit(store: &Store, id: uuid::Uuid, name: &str, additional: (u64, Value)) -> Object {
    store
        .write(LocalWrite {
            id: Some(id),
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text(name.into())),
                (FieldPath::Field(additional.0), additional.1),
            ],
        })
        .expect("edit concurrent fields locally without a network request")
}

async fn synchronize(devices: [(&PersonalServer, &Arc<Store>); 3]) -> [PersonalInventoryResult; 3] {
    let settings = PersonalInventorySettings::default();
    let (first, second, third) = tokio::join!(
        settings.synchronize(devices[0].0, devices[0].1.clone(), None),
        settings.synchronize(devices[1].0, devices[1].1.clone(), None),
        settings.synchronize(devices[2].0, devices[2].1.clone(), None),
    );
    [
        first.expect("original device completes its exact public synchronization intent"),
        second.expect("paired device completes its exact public synchronization intent"),
        third.expect("third device completes its exact public synchronization intent"),
    ]
}

fn assert_contents(store: &Store, expected: &[Object; 2]) {
    for object in expected {
        assert_eq!(store.get(object.id).unwrap().as_ref(), Some(object));
    }
    assert!(!store.list(ObjectType::HOST).unwrap().iter().any(|host| host.id == expected[1].id));
    assert!(expected[1].is_tombstoned());
}

fn assert_private(store: &Store, private: &[Object]) {
    let status = PersonalInventorySettings::default().status(store).unwrap();
    for object in private {
        assert_eq!(store.get(object.id).unwrap().as_ref(), Some(object));
        assert!(
            status
                .objects
                .iter()
                .any(|entry| entry.id == object.id.to_string() && !entry.personal && !entry.dirty)
        );
    }
}

fn offline(
    store: &Store,
    account: &PersonalAccountSnapshot,
    expected: &[Object; 2],
    saved: &PersonalInventoryStatus,
) {
    let offline = PersonalServer::default();
    assert!(
        offline
            .load_sync_bootstrap(store)
            .expect("offline three-device key verification")
            .is_some()
    );
    assert_eq!(
        offline
            .account_snapshot(store)
            .expect("offline three-device account verification")
            .as_ref(),
        Some(account)
    );
    assert_contents(store, expected);
    let status = PersonalInventorySettings::default().status(store).unwrap();
    assert_eq!(status.pending, 0);
    assert_eq!(status.applied_cursor, saved.applied_cursor);
    assert_eq!(status.acknowledged_cursor, saved.acknowledged_cursor);
}
