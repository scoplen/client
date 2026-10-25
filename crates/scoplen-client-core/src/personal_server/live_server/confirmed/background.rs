// SPDX-License-Identifier: Apache-2.0
//! Two production owners converge without a foreground synchronization intent.

use scoplen_model::Object;

use super::*;

pub(super) async fn verify(
    old_manager: &PersonalServer,
    new_manager: &PersonalServer,
    old: &Arc<Store>,
    new: &Arc<Store>,
    old_host: uuid::Uuid,
    paired_host: uuid::Uuid,
) -> (Object, Object) {
    let old_runtime = PersonalSyncRuntime::default();
    let new_runtime = PersonalSyncRuntime::default();
    old_runtime.set_store(Some(old.clone()));
    new_runtime.set_store(Some(new.clone()));
    let owners = async {
        tokio::join!(old_runtime.run(old_manager), new_runtime.run(new_manager));
    };
    tokio::pin!(owners);
    let scenario = async {
        tokio::time::timeout(Duration::from_secs(15), async {
            while old_runtime.status() != PersonalBackgroundStatus::Connected
                || new_runtime.status() != PersonalBackgroundStatus::Connected
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("both production owners authenticate real notification connections");

        let settings = PersonalInventorySettings::default();
        let old_unshared = local_only(old, "Original-device local-only host");
        let new_unshared = local_only(new, "Paired-device local-only host");
        let before = cursors(&settings, [old, new]);
        let edit = old
            .write(LocalWrite {
                id: Some(paired_host),
                object_type: ObjectType::HOST,
                fields: vec![(
                    FieldPath::Field(1),
                    Value::Text("Edited on original device".into()),
                )],
            })
            .expect("original device edits paired-device object locally");
        converge([old, new], [&old_runtime, &new_runtime], &edit, before).await;
        unshared_stays_local(&settings, [old, new], [&old_unshared, &new_unshared]);

        let before = cursors(&settings, [old, new]);
        let edit = new
            .write(LocalWrite {
                id: Some(old_host),
                object_type: ObjectType::HOST,
                fields: vec![(FieldPath::Field(1), Value::Text("Edited on paired device".into()))],
            })
            .expect("paired device edits original-device object locally");
        converge([old, new], [&old_runtime, &new_runtime], &edit, before).await;
        unshared_stays_local(&settings, [old, new], [&old_unshared, &new_unshared]);
        old_runtime.shutdown();
        new_runtime.shutdown();
        (old_unshared, new_unshared)
    };
    let unshared = tokio::select! {
        biased;
        _ = &mut owners => panic!("background owners ended before explicit shutdown"),
        result = scenario => result,
    };
    tokio::time::timeout(Duration::from_secs(5), owners)
        .await
        .expect("both production owners shut down normally");
    assert_eq!(old_runtime.status(), PersonalBackgroundStatus::Inactive);
    assert_eq!(new_runtime.status(), PersonalBackgroundStatus::Inactive);
    unshared
}

fn local_only(store: &Store, name: &str) -> Object {
    store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text(name.into())),
                (FieldPath::Field(2), Value::Text("192.0.2.99".into())),
            ],
        })
        .expect("create unadopted inventory while the background owner runs")
}

fn cursors(settings: &PersonalInventorySettings, stores: [&Store; 2]) -> [u64; 2] {
    stores.map(|store| {
        settings
            .status(store)
            .expect("read local progress")
            .applied_cursor
            .parse()
            .expect("decimal applied cursor")
    })
}

async fn converge(
    stores: [&Store; 2],
    runtimes: [&PersonalSyncRuntime; 2],
    expected: &Object,
    before: [u64; 2],
) {
    let settings = PersonalInventorySettings::default();
    let mut old_status = runtimes[0].subscribe();
    let mut new_status = runtimes[1].subscribe();
    // Fifteen seconds cannot be satisfied by the sixty-second polling fallback.
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            assert_eq!(*old_status.borrow_and_update(), PersonalBackgroundStatus::Connected);
            assert_eq!(*new_status.borrow_and_update(), PersonalBackgroundStatus::Connected);
            let complete = stores.iter().enumerate().all(|(index, store)| {
                let progress = settings.status(store).expect("automatic durable progress");
                store.get(expected.id).expect("automatically replicated object").as_ref()
                    == Some(expected)
                    && progress.pending == 0
                    && progress.applied_cursor == progress.acknowledged_cursor
                    && progress.applied_cursor.parse::<u64>().unwrap() > before[index]
            });
            if complete {
                assert_eq!(cursors(&settings, stores)[0], cursors(&settings, stores)[1]);
                return;
            }
            tokio::select! {
                result = old_status.changed() => result.expect("original owner stays available"),
                result = new_status.changed() => result.expect("paired owner stays available"),
                _ = tokio::time::sleep(Duration::from_millis(25)) => {},
            }
        }
    })
    .await
    .expect("local edit uploads and the connected peer pulls and acknowledges automatically");
}

fn unshared_stays_local(
    settings: &PersonalInventorySettings,
    stores: [&Store; 2],
    unshared: [&Object; 2],
) {
    for (index, store) in stores.iter().enumerate() {
        assert_eq!(store.get(unshared[index].id).unwrap().as_ref(), Some(unshared[index]));
        assert!(store.get(unshared[1 - index].id).unwrap().is_none());
        let progress = settings.status(store).expect("local-only inventory status");
        assert_eq!(progress.pending, 0);
        assert!(progress.objects.iter().any(|object| {
            object.id == unshared[index].id.to_string() && !object.personal && !object.dirty
        }));
    }
}
