// SPDX-License-Identifier: Apache-2.0
//! Public sync and SSH adoption facades keep replication separate from authority.

use super::*;
use crate::connection::{HostKeyPresentation, HostKeyReview, HostKeyStatus, assess_host_key};
use crate::personal_inventory::PersonalInventorySettings;
use crate::repository::{Edit, Provenance, Repository, TrustRecord, TrustRecordChange};
use scoplen_crypto::ObjectEnvelope;

fn key() -> HostKeyPresentation {
    HostKeyPresentation::from_host_key(&scoplen_ssh::HostKey::Raw {
        algorithm: "ssh-ed25519".into(),
        key_blob: vec![17; 32],
    })
}

fn trust(
    store: &Store,
    host: uuid::Uuid,
    device: uuid::Uuid,
    account: uuid::Uuid,
    provenance: Provenance,
) -> TrustRecord {
    let key = key();
    Repository::<TrustRecord>::new(store)
        .create(TrustRecordChange {
            host: Edit::Set(host),
            key: Edit::Set(key.key),
            fingerprint: Edit::Set(key.fingerprint),
            provenance: Some(provenance),
            accepted_at: Edit::Set(1_792_800_000_000),
            accepted_by_device: Edit::Set(device),
            accepted_by_account: Edit::Set(account),
            ..Default::default()
        })
        .unwrap()
}

fn source_devices(
    statements: &scoplen_api::account_devices::AccountDeviceStatements,
    store: &Store,
) -> (DeviceCertificate, DeviceCertificate) {
    let revoked = statements
        .revocations
        .iter()
        .map(|encoded| RevocationStatement::decode(encoded).unwrap().device_id)
        .collect::<HashSet<_>>();
    let devices = statements
        .certificates
        .iter()
        .map(|encoded| DeviceCertificate::decode(encoded).unwrap())
        .collect::<Vec<_>>();
    (
        devices
            .iter()
            .find(|device| {
                device.device_id != store.device_id() && !revoked.contains(&device.device_id)
            })
            .unwrap()
            .clone(),
        devices.into_iter().find(|device| revoked.contains(&device.device_id)).unwrap(),
    )
}

fn publish_devices(
    peer: &Peer,
    statements: &scoplen_api::account_devices::AccountDeviceStatements,
) {
    let mut bundle =
        SyncAccountKeyBundle::from_cbor(&peer.state.lock().unwrap().replies["/sync/v1/keys"].body)
            .unwrap();
    bundle.certificates = statements.certificates.clone();
    bundle.revocations = statements.revocations.clone();
    peer.reply("/sync/v1/keys", Reply::cbor(bundle.to_cbor().unwrap()));
}

#[tokio::test]
async fn personal_trust_sources_are_verified_offline_and_unknown_claims_never_authorize_ssh() {
    let peer = Peer::new().await;
    let directory = tempfile::tempdir().unwrap();
    let store = local(&directory);
    let manager = peer.prepare(&store).await;
    let statements = account::install(&peer, &store);
    let (active, revoked) = source_devices(&statements, &store);
    manager.query_account(store.clone()).await.unwrap();
    let account = record(&store).unwrap().account_id;
    let requests = peer.state.lock().unwrap().paths.len();
    for provenance in [Provenance::Manual, Provenance::Imported] {
        let host = inventory::make_host(&store).id;
        trust(&store, host, active.device_id, account, provenance);
        let assessment = assess_host_key(&store, host, &key()).unwrap();
        assert_eq!(assessment.status, HostKeyStatus::Trusted);
        let source = assessment.source.unwrap();
        assert_eq!(source.device_id, Some(active.device_id.to_string()));
        assert_eq!(source.device_name, Some(active.display_name.clone()));
        assert_eq!(source.accepted_at.as_deref(), Some("1792800000000"));
        assert_eq!(source.imported, provenance == Provenance::Imported);
        assert!(!source.current);
    }
    for (device, account, provenance) in [
        (uuid::Uuid::now_v7(), account, Provenance::Manual),
        (active.device_id, uuid::Uuid::now_v7(), Provenance::Manual),
        (active.device_id, account, Provenance::OrganizationPolicy),
        (active.device_id, account, Provenance::HostCa),
    ] {
        let host = inventory::make_host(&store).id;
        trust(&store, host, device, account, provenance);
        let assessment = assess_host_key(&store, host, &key()).unwrap();
        assert_ne!(assessment.status, HostKeyStatus::Trusted);
        assert_eq!(assessment.review, Some(HostKeyReview::UnverifiedSource));
        assert!(assessment.source.is_none(), "unverified names/times must not reach the UI");
    }
    let host = inventory::make_host(&store).id;
    trust(&store, host, revoked.device_id, account, Provenance::Manual);
    let review = assess_host_key(&store, host, &key()).unwrap();
    assert_eq!(review.review, Some(HostKeyReview::RevokedDevice));
    assert_ne!(review.status, HostKeyStatus::Trusted);
    assert_eq!(review.source.unwrap().device_name, Some(revoked.display_name));
    trust(&store, host, active.device_id, account, Provenance::Imported);
    assert_eq!(assess_host_key(&store, host, &key()).unwrap().status, HostKeyStatus::Trusted);
    assert_eq!(peer.state.lock().unwrap().paths.len(), requests, "assessment stays offline");
    drop(store);
    let reopened = local(&directory);
    assert_eq!(assess_host_key(&reopened, host, &key()).unwrap().status, HostKeyStatus::Trusted);
    peer.assert_healthy();
}

#[tokio::test]
async fn known_revocations_dominate_older_active_snapshots_in_both_directions() {
    for revoke_in_account in [true, false] {
        let peer = Peer::new().await;
        let directory = tempfile::tempdir().unwrap();
        let store = local(&directory);
        let manager = peer.prepare(&store).await;
        let mut statements = account::install(&peer, &store);
        let (_, revoked) = source_devices(&statements, &store);
        if revoke_in_account {
            let mut active = statements.clone();
            active.revocations.clear();
            publish_devices(&peer, &active);
            manager.bootstrap_sync(store.clone()).await.unwrap();
            manager.query_account(store.clone()).await.unwrap();
        } else {
            publish_devices(&peer, &statements);
            manager.bootstrap_sync(store.clone()).await.unwrap();
            statements.revocations.clear();
            peer.reply("/api/v1/accounts/me/devices", account::json(statements.to_json().unwrap()));
            manager.query_account(store.clone()).await.unwrap();
        }
        let host = inventory::make_host(&store).id;
        trust(
            &store,
            host,
            revoked.device_id,
            record(&store).unwrap().account_id,
            Provenance::Manual,
        );
        let assessment = assess_host_key(&store, host, &key()).unwrap();
        assert_eq!(assessment.review, Some(HostKeyReview::RevokedDevice));
        assert_ne!(assessment.status, HostKeyStatus::Trusted);
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn replayed_signed_active_lists_cannot_forget_observed_revocations() {
    let peer = Peer::new().await;
    let directory = tempfile::tempdir().unwrap();
    let store = local(&directory);
    let manager = peer.prepare(&store).await;
    let mut statements = account::install(&peer, &store);
    let (_, revoked) = source_devices(&statements, &store);
    publish_devices(&peer, &statements);
    let account = manager.query_account(store.clone()).await.unwrap();
    manager.bootstrap_sync(store.clone()).await.unwrap();
    let previous = store.personal_sync_record().unwrap().unwrap();
    statements.revocations.clear();
    peer.reply("/api/v1/accounts/me/devices", account::json(statements.to_json().unwrap()));
    assert_eq!(
        manager.query_account(store.clone()).await.unwrap_err(),
        PersonalServerError::InvalidAccountResponse
    );
    assert_eq!(manager.account_snapshot(&store).unwrap(), Some(account));
    publish_devices(&peer, &statements);
    assert!(matches!(
        manager.bootstrap_sync(store.clone()).await,
        Err(PersonalSyncError::InvalidResponse)
    ));
    let saved = store.personal_sync_record().unwrap().unwrap();
    assert_eq!(saved.generation, previous.generation);
    assert!(saved.account_keys.as_bytes() == previous.account_keys.as_bytes());
    let host = inventory::make_host(&store).id;
    trust(&store, host, revoked.device_id, record(&store).unwrap().account_id, Provenance::Manual);
    assert_eq!(
        assess_host_key(&store, host, &key()).unwrap().review,
        Some(HostKeyReview::RevokedDevice)
    );
    peer.assert_healthy();
}

#[tokio::test]
async fn a_concurrent_snapshot_cannot_overwrite_a_newer_verified_revocation() {
    let peer = Peer::new().await;
    let directory = tempfile::tempdir().unwrap();
    let store = local(&directory);
    let manager = peer.prepare(&store).await;
    let statements = account::install(&peer, &store);
    let (_, revoked) = source_devices(&statements, &store);
    let mut active = statements.clone();
    active.revocations.clear();
    peer.reply("/api/v1/accounts/me/devices", account::json(active.to_json().unwrap()));
    manager.query_account(store.clone()).await.unwrap();
    let identity = record(&store).unwrap();
    let access = store.personal_access_token(now().unwrap()).unwrap().unwrap();
    let stale = store.personal_account_snapshot(&identity).unwrap().unwrap();
    peer.reply("/api/v1/accounts/me/devices", account::json(statements.to_json().unwrap()));
    let latest = manager.query_account(store.clone()).await.unwrap();
    assert!(
        !store
            .save_personal_account_snapshot(
                &identity,
                &access,
                &stale,
                Some(stale.devices.as_bytes()),
                now().unwrap(),
            )
            .unwrap()
    );
    assert_eq!(manager.account_snapshot(&store).unwrap(), Some(latest));
    let host = inventory::make_host(&store).id;
    trust(&store, host, revoked.device_id, identity.account_id, Provenance::Manual);
    assert_eq!(
        assess_host_key(&store, host, &key()).unwrap().review,
        Some(HostKeyReview::RevokedDevice)
    );
    peer.assert_healthy();
}

#[tokio::test]
async fn revoked_source_requires_confirmation_before_real_ssh_auth_and_records_the_new_source() {
    use crate::connection::preparation::{
        PreparationControl, PreparationEvent, PreparationResponse, prepare_connection,
    };
    use crate::inventory::{Inventory, NewHost, SignIn};
    use std::sync::atomic::Ordering;

    let peer = Peer::new().await;
    let directory = tempfile::tempdir().unwrap();
    let store = local(&directory);
    let manager = peer.prepare(&store).await;
    let statements = account::install(&peer, &store);
    let (_, revoked) = source_devices(&statements, &store);
    manager.query_account(store.clone()).await.unwrap();
    let ssh = crate::connection::test_peer::Peer::start().await;
    let host = Inventory::new(store.clone())
        .add_host(NewHost {
            name: Some("Trust verification peer".into()),
            address: "127.0.0.1".into(),
            port: Some(ssh.port),
            username: "trust-fixture".into(),
            sign_in: SignIn::Password { password: "disposable-trust-password".into() },
        })
        .unwrap();
    let host_id = uuid::Uuid::parse_str(&host.summary.id).unwrap();
    let profile = uuid::Uuid::parse_str(&host.logins[0].id).unwrap();
    let previous = trust(
        &store,
        host_id,
        revoked.device_id,
        record(&store).unwrap().account_id,
        Provenance::Manual,
    );
    Repository::<TrustRecord>::new(&store)
        .update(
            previous.meta.id,
            TrustRecordChange {
                key: Edit::Set(ssh.key.key.clone()),
                fingerprint: Edit::Set(ssh.key.fingerprint.clone()),
                ..Default::default()
            },
        )
        .unwrap();
    let cancelled = PreparationControl::default();
    let result = prepare_connection(&store, profile, &cancelled, |event| {
        if let PreparationEvent::Trust { host_key, .. } = event {
            assert_eq!(host_key.review, Some(HostKeyReview::RevokedDevice));
            assert!(!host_key.changed);
            assert_eq!(ssh.authentications.load(Ordering::SeqCst), 0);
            cancelled.cancel();
        }
        Ok(())
    })
    .await;
    assert!(result.is_err());
    assert_eq!(ssh.authentications.load(Ordering::SeqCst), 0);
    assert_eq!(Repository::<TrustRecord>::new(&store).list().unwrap().len(), 1);

    let control = PreparationControl::default();
    let confirmations = std::sync::atomic::AtomicUsize::new(0);
    let connection = prepare_connection(&store, profile, &control, |event| {
        match event {
            PreparationEvent::Trust { prompt_id, host_key, .. } => {
                assert_eq!(ssh.authentications.load(Ordering::SeqCst), 0);
                assert_eq!(host_key.review, Some(HostKeyReview::RevokedDevice));
                confirmations.fetch_add(1, Ordering::SeqCst);
                control.respond(&prompt_id, PreparationResponse::AcceptHostKey)?;
            }
            PreparationEvent::Verified { source, .. } => {
                assert!(source.current);
                assert_eq!(source.device_id, Some(store.device_id().to_string()));
                assert!(source.accepted_at.is_some());
            }
            _ => {}
        }
        Ok(())
    })
    .await
    .unwrap();
    connection.close().await.unwrap();
    assert_eq!(confirmations.load(Ordering::SeqCst), 1);
    let records = Repository::<TrustRecord>::new(&store).list().unwrap();
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|record| record.accepted_by_device == Some(store.device_id())
        && record.accepted_by_account == Some(super::record(&store).unwrap().account_id)));
    assert!(
        !Repository::<TrustRecord>::new(&store).get(previous.meta.id).unwrap().unwrap().revoked
    );
    let connection = prepare_connection(&store, profile, &PreparationControl::default(), |event| {
        assert!(
            !matches!(event, PreparationEvent::Trust { .. }),
            "the new active source confirms the same key"
        );
        Ok(())
    })
    .await
    .unwrap();
    connection.close().await.unwrap();
    assert_eq!(ssh.authentications.load(Ordering::SeqCst), 2);
    peer.assert_healthy();
}

#[tokio::test]
async fn revoked_origin_can_replicate_but_never_authorizes_ssh_or_a_revoked_envelope_signer() {
    let peer = Peer::new().await;
    let directory = tempfile::tempdir().unwrap();
    let store = local(&directory);
    let manager = peer.prepare(&store).await;
    let statements = account::install(&peer, &store);
    let (_, revoked) = source_devices(&statements, &store);
    publish_devices(&peer, &statements);
    peer.state.lock().unwrap().inventory = Some(InventoryPeer::default());
    manager.bootstrap_sync(store.clone()).await.unwrap();
    let host = inventory::make_host(&store).id;
    let record = trust(
        &store,
        host,
        revoked.device_id,
        record(&store).unwrap().account_id,
        Provenance::Manual,
    );
    let settings = PersonalInventorySettings::default();
    let preview =
        settings.preview(&store, vec![host.to_string(), record.meta.id.to_string()]).unwrap();
    let result = settings.synchronize(&manager, store.clone(), preview.token).await.unwrap();
    assert_eq!(result.uploaded, 2);
    assert_eq!(
        assess_host_key(&store, host, &key()).unwrap().review,
        Some(HostKeyReview::RevokedDevice)
    );

    let mut incoming = store.get(record.meta.id).unwrap().unwrap();
    incoming.id = uuid::Uuid::now_v7();
    let change = inventory::change(&store, &incoming, 10);
    let mut inventory = InventoryPeer::default();
    inventory.seq = 10;
    inventory.objects.insert(incoming.id, change);
    peer.state.lock().unwrap().inventory = Some(inventory);
    let result = settings.synchronize(&manager, store.clone(), None).await.unwrap();
    assert_eq!(result.downloaded, 1);
    assert!(store.get(incoming.id).unwrap().is_some());
    assert_ne!(assess_host_key(&store, host, &key()).unwrap().status, HostKeyStatus::Trusted);

    incoming.id = uuid::Uuid::now_v7();
    let identity = super::record(&store).unwrap();
    let secrets = identity::Secrets::parse(&identity.private_material).unwrap();
    let envelope = ObjectEnvelope::encrypt(
        identity.personal_vault_id,
        1,
        &incoming,
        &SymmetricKey::new(secrets.vault().try_into().unwrap()),
        revoked.device_id,
        &P256SigningKey::from_bytes(secrets.signing()).unwrap(),
    )
    .unwrap();
    // The reference device certificates use the same fixture public key. This is
    // a valid cryptographic signature by an explicitly revoked device identity.
    let change = scoplen_api::sync::SyncChange {
        object_id: incoming.id,
        seq: 11,
        payload: envelope.encode().unwrap(),
        tombstone: false,
        signer_device_id: Some(revoked.device_id),
    };
    let mut inventory = InventoryPeer::default();
    inventory.seq = 11;
    inventory.objects.insert(incoming.id, change);
    peer.state.lock().unwrap().inventory = Some(inventory);
    let before = settings.status(&store).unwrap();
    let acknowledgements =
        || peer.state.lock().unwrap().paths.iter().filter(|path| path.ends_with("/ack")).count();
    let acknowledged = acknowledgements();
    assert_eq!(
        settings.synchronize(&manager, store.clone(), None).await.unwrap_err(),
        PersonalSyncError::InvalidResponse.into()
    );
    assert!(store.get(incoming.id).unwrap().is_none());
    let after = settings.status(&store).unwrap();
    assert_eq!(after.objects, before.objects);
    assert_eq!(after.pending, before.pending);
    assert_eq!(after.applied_cursor, before.applied_cursor);
    assert_eq!(after.acknowledged_cursor, before.acknowledged_cursor);
    assert_eq!(acknowledgements(), acknowledged);
    peer.assert_healthy();
}
