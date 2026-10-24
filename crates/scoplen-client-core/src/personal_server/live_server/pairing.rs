// SPDX-License-Identifier: Apache-2.0
//! Two independent device stores use only the public HTTPS and Client intent surfaces.

use super::*;

mod background;

pub(super) async fn verify(
    deployment: &Deployment,
    old_manager: &PersonalServer,
    old: Arc<Store>,
    old_host: uuid::Uuid,
) -> (PersonalAccountSnapshot, scoplen_model::Object) {
    let ca = bounded_file(&deployment.ca_certificate, 65_536);
    let new_manager = PersonalServer {
        operation: Mutex::new(()),
        transport: Ok(trusted_transport(&ca)),
        pairing: Default::default(),
    };
    let directory = tempfile::tempdir().expect("independent paired device directory");
    let path = directory.path().join("paired.sqlite");
    let key = SymmetricKey::new([41; 32]);
    let new = Arc::new(Store::open(&path, &key).expect("independent encrypted new-device store"));
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
    let started = new_manager
        .pairing_create(new.clone(), deployment.origin.clone(), "Live paired device".into())
        .await
        .expect("create public locator and separate password through real HTTPS");
    assert_eq!(started.status.phase, PairingPhase::Waiting);
    let public_link = started.status.public_link.as_ref().expect("public pairing locator");
    let password =
        std::str::from_utf8(started.password.as_bytes()).expect("ASCII pairing password");
    assert_eq!(password.len(), 8);
    assert!(!public_link.contains(password));
    assert!(!serde_json::to_string(&started.status).unwrap().contains(password));
    if std::env::var("SCOPLEN_LIVE_PAIRING_MODE").as_deref() == Ok("png") {
        let screenshot = directory.path().join("pairing.png");
        crate::personal_server::pairing::qr::tests::write_png(
            started.qr.as_ref().expect("native QR rendering"),
            &screenshot,
        );
        old_manager
            .pairing_join_png(old.clone(), screenshot.clone(), || true)
            .await
            .expect("existing device recognizes local PNG and claims through genuine DPoP");
        std::fs::remove_file(screenshot).expect("remove transient screenshot");
    } else {
        old_manager
            .pairing_join(old.clone(), public_link.clone(), Zeroizing::new(password.into()))
            .await
            .expect("existing device claims with its genuine DPoP session");
    }
    drop(started);

    tokio::time::timeout(Duration::from_secs(90), async {
        new_manager.pairing_progress(new.clone()).await.expect("new CPace share");
        new_manager.pairing_progress(new.clone()).await.expect("new CPace confirmation");
        old_manager.pairing_progress(old.clone()).await.expect("old CPace confirmation");
        new_manager.pairing_progress(new.clone()).await.expect("authenticated new-device claims");
        let review = old_manager.pairing_progress(old.clone()).await.expect("review new device");
        assert_eq!(review.phase, PairingPhase::ConfirmDevice);
        assert_eq!(review.peer_name.as_deref(), Some("Live paired device"));
        assert_eq!(review.peer_platform.as_deref(), Some(std::env::consts::OS));
        assert!(new_manager.load_sync_bootstrap(&new).expect("no pre-approval keys").is_none());
        old_manager.pairing_confirm(old.clone()).await.expect("explicitly approve exact claims");
        new_manager.pairing_progress(new.clone()).await.expect("durably accept exact handoff");
        assert_eq!(
            new_manager.status(&new).expect("retained new identity").phase,
            PersonalServerPhase::AuthenticationRequired
        );
        assert_eq!(
            old_manager.pairing_progress(old.clone()).await.expect("complete real admission").phase,
            PairingPhase::Completed
        );
        assert_eq!(
            new_manager
                .pairing_progress(new.clone())
                .await
                .expect("authenticate admitted device and verify complete K-4 keys")
                .phase,
            PairingPhase::Completed
        );
    })
    .await
    .expect("bounded public pairing ceremony");

    let old_account = old_manager.query_account(old.clone()).await.expect("original device list");
    let new_account = new_manager.query_account(new.clone()).await.expect("paired device list");
    assert_eq!(old_account.account_id, new_account.account_id);
    for (account, current) in [(&old_account, old.device_id()), (&new_account, new.device_id())] {
        assert_eq!(account.devices.len(), 2);
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
    drop(new_manager);
    drop(new);
    let reopened = Store::open(&path, &key).expect("reopen encrypted paired device offline");
    let offline = PersonalServer::default();
    assert!(offline.load_sync_bootstrap(&reopened).expect("paired offline keys").is_some());
    assert_eq!(
        offline.account_snapshot(&reopened).expect("paired offline account"),
        Some(new_account)
    );
    assert_eq!(offline.pairing_status(&reopened).unwrap().phase, PairingPhase::Completed);
    assert_eq!(reopened.get(host.id).unwrap(), Some(host));
    assert_eq!(reopened.get(local_host.id).unwrap(), Some(local_host));
    assert_eq!(reopened.get(new_unshared.id).unwrap(), Some(new_unshared));
    assert!(reopened.get(old_unshared.id).unwrap().is_none());
    let restored = settings.status(&reopened).expect("paired offline progress");
    assert_eq!(restored.applied_cursor, saved.applied_cursor);
    assert_eq!(restored.applied_cursor, restored.acknowledged_cursor);
    (old_account, old_unshared)
}
