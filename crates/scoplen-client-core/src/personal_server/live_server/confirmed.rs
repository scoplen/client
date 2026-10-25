// SPDX-License-Identifier: Apache-2.0
//! Confirmed legacy devices retain public HTTPS synchronization and reopen coverage.

use super::*;

mod background;

pub(super) struct PairedDevice {
    pub(super) manager: PersonalServer,
    pub(super) store: Arc<Store>,
    profile: ConfirmedProfile,
    key: SymmetricKey,
}

impl PairedDevice {
    pub(super) fn reopen(self) -> Self {
        let Self { manager, store, profile, key } = self;
        drop(store);
        let store =
            Arc::new(Store::open(&profile.store, &key).expect("reopen independent paired device"));
        Self { manager, store, profile, key }
    }
}

pub(super) async fn verify(
    deployment: &Deployment,
    old_manager: &PersonalServer,
    old: Arc<Store>,
    old_host: uuid::Uuid,
) -> (PairedDevice, scoplen_model::Object) {
    let ca = bounded_file(&deployment.ca_certificate, 65_536);
    let new_manager =
        PersonalServer { operation: Mutex::new(()), transport: Ok(trusted_transport(&ca)) };
    let profile = deployment.profiles[1].clone();
    let path = &profile.store;
    let key = profile.key();
    let new = profile.open();
    assert_eq!(record(&new).unwrap().origin, deployment.origin);
    assert_ne!(old.device_id(), new.device_id());
    let local_host = new
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text("Unshared paired-device host".into())),
                (FieldPath::Field(2), Value::Text("192.0.2.42".into())),
            ],
        })
        .expect("retain pre-existing local inventory on the new device");
    new_manager
        .authenticate(new.clone())
        .await
        .expect("authenticate already confirmed second device");
    new_manager.bootstrap_sync(new.clone()).await.expect("verify retained second-device keys");

    let old_account = old_manager.query_account(old.clone()).await.expect("original device list");
    let new_account = new_manager.query_account(new.clone()).await.expect("paired device list");
    assert_eq!(old_account.account_id, new_account.account_id);
    for (account, current) in [(&old_account, old.device_id()), (&new_account, new.device_id())] {
        assert_eq!(account.devices.len(), 3);
        assert_eq!(account.devices.iter().filter(|device| device.current).count(), 1);
        assert!(
            account.devices.iter().any(|device| device.current && device.id == current.to_string())
        );
    }
    let settings = PersonalInventorySettings::default();
    let before = settings.status(&new).expect("local state after account setup");
    assert_eq!(before.pending, 0);
    assert_eq!(before.applied_cursor, "0");
    assert_eq!(before.acknowledged_cursor, "0");
    assert!(
        before.objects.iter().any(|object| object.id == local_host.id.to_string()
            && !object.personal
            && !object.dirty)
    );
    assert_eq!(new.get(local_host.id).unwrap(), Some(local_host.clone()));
    assert!(old.get(local_host.id).unwrap().is_none());
    assert!(new.get(old_host).unwrap().is_none());

    settings
        .synchronize(&new_manager, new.clone(), None)
        .await
        .expect("pull original-device ciphertext");
    assert_eq!(new.get(old_host).unwrap(), old.get(old_host).unwrap());
    assert!(old.get(local_host.id).unwrap().is_none());
    let preview =
        settings.preview(&new, vec![local_host.id.to_string()]).expect("review new upload");
    assert!(preview.missing.is_empty());
    assert!(preview.token.is_some());
    let uploaded = settings
        .synchronize(&new_manager, new.clone(), preview.token)
        .await
        .expect("explicitly adopt and upload new-device host");
    assert_eq!(uploaded.uploaded, 1);
    settings
        .synchronize(old_manager, old.clone(), None)
        .await
        .expect("original device decrypts paired-device host");
    assert_eq!(old.get(local_host.id).unwrap(), new.get(local_host.id).unwrap());

    let (old_unshared, new_unshared) =
        background::verify(old_manager, &new_manager, &old, &new, old_host, local_host.id).await;
    let saved = settings.status(&new).expect("paired device durable progress");
    assert_eq!(saved.pending, 0);
    assert_eq!(saved.applied_cursor, saved.acknowledged_cursor);
    assert_ne!(saved.applied_cursor, "0");
    let host = new.get(old_host).unwrap().expect("retained synchronized host");
    let local_host = new.get(local_host.id).unwrap().expect("retained adopted host");
    drop(new);
    let reopened = Store::open(path, &key).expect("reopen encrypted paired device offline");
    let offline = PersonalServer::default();
    assert!(offline.load_sync_bootstrap(&reopened).expect("paired offline keys").is_some());
    assert_eq!(
        offline.account_snapshot(&reopened).expect("paired offline account"),
        Some(new_account)
    );
    assert_eq!(reopened.get(host.id).unwrap(), Some(host));
    assert_eq!(reopened.get(local_host.id).unwrap(), Some(local_host));
    assert_eq!(reopened.get(new_unshared.id).unwrap(), Some(new_unshared));
    assert!(reopened.get(old_unshared.id).unwrap().is_none());
    let restored = settings.status(&reopened).expect("paired offline progress");
    assert_eq!(restored.applied_cursor, saved.applied_cursor);
    assert_eq!(restored.applied_cursor, restored.acknowledged_cursor);
    (PairedDevice { manager: new_manager, store: Arc::new(reopened), profile, key }, old_unshared)
}
