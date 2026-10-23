// SPDX-License-Identifier: Apache-2.0
//! Membership-only K-4 advancement through the public TLS bootstrap operation.

use super::*;

fn bundle(peer: &Peer) -> SyncAccountKeyBundle {
    SyncAccountKeyBundle::from_cbor(&peer.state.lock().unwrap().replies["/sync/v1/keys"].body)
        .unwrap()
}

fn publish(peer: &Peer, bundle: &SyncAccountKeyBundle) {
    peer.reply("/sync/v1/keys", Reply::cbor(bundle.to_cbor().unwrap()));
}

fn another_device(store: &Store) -> DeviceCertificate {
    let pending = record(store).unwrap();
    let secrets = identity::Secrets::parse(&pending.private_material).unwrap();
    let account = Ed25519SigningKey::from_bytes(secrets.account_signing()).unwrap();
    let device = scoplen_crypto::generate_device_keys().unwrap();
    DeviceCertificate::issue(
        &account,
        scoplen_model::new_uuid_v7().unwrap(),
        pending.account_id,
        device.signing.public_key_sec1(),
        device.kem.public_key().to_vec(),
        "Other desktop".into(),
        "macos".into(),
        scoplen_model::system_time_millis().unwrap(),
    )
    .unwrap()
}

fn rewrap_ark(store: &Store) -> Vec<u8> {
    let pending = record(store).unwrap();
    let secrets = identity::Secrets::parse(&pending.private_material).unwrap();
    let kem = DeviceKemKeyPair::from_private_bytes(secrets.device_kem()).unwrap();
    let ark = SymmetricKey::from_slice(secrets.ark()).unwrap();
    DeviceArkWrap::seal(pending.account_id, store.device_id(), kem.public_key(), &ark)
        .unwrap()
        .encode()
        .to_vec()
}

fn assert_retained(store: &Store, expected: &PersonalSyncRecord) {
    let actual = store.personal_sync_record().unwrap().unwrap();
    assert_eq!(actual.generation, expected.generation);
    assert!(actual.session.as_bytes() == expected.session.as_bytes());
    assert!(actual.account_keys.as_bytes() == expected.account_keys.as_bytes());
    assert!(actual.vault_keys.as_bytes() == expected.vault_keys.as_bytes());
}

#[tokio::test]
async fn membership_advances_with_real_certificates_and_independent_signed_statements() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let mut update = bundle(&peer);
    let other = another_device(&store);
    update.certificates.push(other.encode().unwrap());
    update.certificates.sort();
    update.revision = 2;
    publish(&peer, &update);
    let first = manager.bootstrap_sync(store.clone()).await.unwrap();
    assert_eq!(first.active_devices.len(), 2);
    assert!(first.active_devices.iter().any(|certificate| certificate == &other));
    peer.state.lock().unwrap().inventory = Some(InventoryPeer::default());
    let host = store
        .write(crate::store::LocalWrite {
            id: None,
            object_type: scoplen_model::ObjectType::HOST,
            fields: vec![
                (
                    scoplen_model::FieldPath::Field(1),
                    scoplen_model::cbor::Value::Text("Reviewed local host".into()),
                ),
                (
                    scoplen_model::FieldPath::Field(2),
                    scoplen_model::cbor::Value::Text("192.0.2.12".into()),
                ),
            ],
        })
        .unwrap();
    let settings = crate::personal_inventory::PersonalInventorySettings::default();
    let preview = settings.preview(&store, vec![host.id.to_string()]).unwrap();
    let transfer = settings.synchronize(&manager, store.clone(), preview.token).await.unwrap();
    assert_eq!(transfer.uploaded, 1);
    assert_eq!(settings.status(&store).unwrap().acknowledged_cursor, "8");

    // Statement replacement does not itself advance the account-key revision.
    let pending = record(&store).unwrap();
    let account = Ed25519SigningKey::from_bytes(
        identity::Secrets::parse(&pending.private_material).unwrap().account_signing(),
    )
    .unwrap();
    update.revocations.push(
        RevocationStatement::issue(&account, other.device_id, 1, "removed".into())
            .unwrap()
            .encode()
            .unwrap(),
    );
    publish(&peer, &update);
    let refreshed = manager.bootstrap_sync(store.clone()).await.unwrap();
    assert_eq!(refreshed.active_devices.len(), 1);
    assert_eq!(refreshed.active_devices[0].device_id, store.device_id());

    update.revision = 8;
    update.wrapped_ark = rewrap_ark(&store);
    publish(&peer, &update);
    let advanced = manager.bootstrap_sync(store.clone()).await.unwrap();
    assert!(advanced.personal_vault_key() == first.personal_vault_key());
    let cached = store.personal_sync_record().unwrap().unwrap();
    assert_eq!(SyncAccountKeyBundle::from_cbor(cached.account_keys.as_bytes()).unwrap(), update);
    drop(store);
    let store = local(&dir);
    let offline = PersonalServer::default().load_sync_bootstrap(&store).unwrap().unwrap();
    assert!(offline.personal_vault_key() == first.personal_vault_key());
    assert_eq!(offline.active_devices.len(), 1);
    update.revision = 7;
    publish(&peer, &update);
    assert!(matches!(
        manager.bootstrap_sync(store.clone()).await,
        Err(PersonalSyncError::InvalidResponse)
    ));
    assert_retained(&store, &cached);
    peer.assert_healthy();
}

#[tokio::test]
async fn later_membership_cannot_rewrap_the_personal_key_without_rotation_support() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    manager.bootstrap_sync(store.clone()).await.unwrap();
    let retained = store.personal_sync_record().unwrap().unwrap();
    let mut update = bundle(&peer);
    update.revision = 2;
    publish(&peer, &update);
    let pending = record(&store).unwrap();
    let secrets = identity::Secrets::parse(&pending.private_material).unwrap();
    let ark = SymmetricKey::from_slice(secrets.ark()).unwrap();
    let vault = SymmetricKey::from_slice(secrets.vault()).unwrap();
    let path = format!("/sync/v1/vaults/{}/keys", pending.personal_vault_id);
    let mut keys = SyncVaultKeysResponse::from_cbor(retained.vault_keys.as_bytes()).unwrap();
    keys.keys[0].wrapped_vault_key =
        PersonalVaultKeyWrap::seal(pending.account_id, pending.personal_vault_id, 1, &ark, &vault)
            .unwrap()
            .encode()
            .to_vec();
    peer.reply(&path, Reply::cbor(keys.to_cbor().unwrap()));
    assert!(matches!(
        manager.bootstrap_sync(store.clone()).await,
        Err(PersonalSyncError::RotationRequired)
    ));
    assert_retained(&store, &retained);
    peer.assert_healthy();
}

#[tokio::test]
async fn revision_rollback_and_same_revision_rewrapping_preserve_the_complete_snapshot() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let initial = bundle(&peer);
    let mut update = initial.clone();
    // Even the signed initial revision cannot silently replace its own wrapping.
    update.wrapped_ark = rewrap_ark(&store);
    publish(&peer, &update);
    assert!(matches!(
        manager.bootstrap_sync(store.clone()).await,
        Err(PersonalSyncError::InvalidResponse)
    ));
    assert!(store.personal_sync_record().unwrap().is_none());
    update.revision = 2;
    publish(&peer, &update);
    manager.bootstrap_sync(store.clone()).await.unwrap();
    let retained = store.personal_sync_record().unwrap().unwrap();
    for replacement in [initial, SyncAccountKeyBundle { wrapped_ark: rewrap_ark(&store), ..update }]
    {
        publish(&peer, &replacement);
        assert!(matches!(
            manager.bootstrap_sync(store.clone()).await,
            Err(PersonalSyncError::InvalidResponse)
        ));
        assert_retained(&store, &retained);
    }
    peer.assert_healthy();
}

#[tokio::test]
async fn later_membership_cannot_replace_keys_or_the_retained_device_certificate() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    manager.bootstrap_sync(store.clone()).await.unwrap();
    let retained = store.personal_sync_record().unwrap().unwrap();
    let base = bundle(&peer);
    let pending = record(&store).unwrap();
    let secrets = identity::Secrets::parse(&pending.private_material).unwrap();
    let ark = SymmetricKey::from_slice(secrets.ark()).unwrap();
    let account = Ed25519SigningKey::from_bytes(secrets.account_signing()).unwrap();
    for field in 0..8 {
        let mut update = base.clone();
        update.revision = 3;
        match field {
            0 => {
                update.account_signing_key =
                    AccountSigningKeyWrap::seal(pending.account_id, &ark, &account)
                        .unwrap()
                        .encode()
                        .to_vec();
            }
            1 => {
                let foreign = Ed25519SigningKey::from_bytes(&[83; 32]).unwrap();
                update.account_signing_key =
                    AccountSigningKeyWrap::seal(pending.account_id, &ark, &foreign)
                        .unwrap()
                        .encode()
                        .to_vec();
            }
            2 => {
                let kem = DeviceKemKeyPair::from_private_bytes(secrets.device_kem()).unwrap();
                update.wrapped_ark = DeviceArkWrap::seal(
                    pending.account_id,
                    store.device_id(),
                    kem.public_key(),
                    &SymmetricKey::new([91; 32]),
                )
                .unwrap()
                .encode()
                .to_vec();
            }
            3 => {
                let original = DeviceCertificate::decode(&update.certificates[0]).unwrap();
                update.certificates = vec![
                    DeviceCertificate::issue(
                        &account,
                        original.device_id,
                        original.account_id,
                        original.signing_public_key,
                        original.kem_public_key,
                        "Replacement name".into(),
                        original.platform,
                        original.created_at,
                    )
                    .unwrap()
                    .encode()
                    .unwrap(),
                ];
            }
            4 => {
                let recovery = RecoveryKey::from_bytes(secrets.recovery().unwrap()).unwrap();
                update.recovery_blob = RecoveryBlob::wrap(&recovery, pending.account_id, &ark)
                    .unwrap()
                    .encode()
                    .unwrap();
            }
            5 => {
                let mut certificate = another_device(&store);
                certificate.signature[0] ^= 1;
                update.certificates.push(certificate.encode().unwrap());
                update.certificates.sort();
            }
            6 => {
                let kem =
                    scoplen_crypto::AccountKemKeyPair::from_private_bytes(secrets.account_kem())
                        .unwrap();
                update.account_kem_key = AccountKemKeyWrap::seal(pending.account_id, &ark, &kem)
                    .unwrap()
                    .encode()
                    .to_vec();
            }
            _ => {
                update.revocations = vec![
                    RevocationStatement::issue(&account, store.device_id(), 1, "removed".into())
                        .unwrap()
                        .encode()
                        .unwrap(),
                ];
            }
        }
        publish(&peer, &update);
        let expected = if matches!(field, 0 | 4 | 6) {
            PersonalSyncError::RotationRequired
        } else {
            PersonalSyncError::InvalidResponse
        };
        assert!(
            matches!(manager.bootstrap_sync(store.clone()).await, Err(error) if error == expected),
            "field {field}"
        );
        assert_retained(&store, &retained);
    }
    peer.assert_healthy();
}

#[tokio::test]
async fn competing_public_bootstrap_cannot_lower_a_revision_after_validation() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    manager.bootstrap_sync(store.clone()).await.unwrap();
    let mut update = bundle(&peer);
    update.revision = 2;
    publish(&peer, &update);
    let reached = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let path = format!("/sync/v1/vaults/{}/keys", record(&store).unwrap().personal_vault_id);
    peer.state.lock().unwrap().pause = Some((path, reached.clone(), resume.clone()));
    let delayed = PersonalServer {
        operation: tokio::sync::Mutex::new(()),
        transport: Ok(Transport::fixture(peer.certificate.clone(), Duration::from_secs(5))),
        pairing: Default::default(),
    };
    let concurrent_store = store.clone();
    let task = tokio::spawn(async move { delayed.bootstrap_sync(concurrent_store).await });
    tokio::time::timeout(Duration::from_secs(3), reached.notified()).await.unwrap();
    update.revision = 6;
    publish(&peer, &update);
    peer.manager().bootstrap_sync(store.clone()).await.unwrap();
    let retained = store.personal_sync_record().unwrap().unwrap();
    resume.notify_one();
    assert!(matches!(
        task.await.unwrap(),
        Err(PersonalSyncError::Personal(PersonalServerError::Storage))
    ));
    assert_retained(&store, &retained);
    assert_eq!(
        SyncAccountKeyBundle::from_cbor(retained.account_keys.as_bytes()).unwrap().revision,
        6
    );
    peer.assert_healthy();
}
