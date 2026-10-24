// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
async fn revoked_history_signer_needs_valid_current_root_statements_and_signature_but_never_authorizes_restore()
 {
    for fault in 0..6 {
        let peer = Peer::new().await;
        let (_dir, store, manager, object) = fixture(&peer).await;
        let vault = record(&store).unwrap().personal_vault_id;
        let settings = PersonalInventorySettings::default();
        let active = inventory::change(&store, &object, 1);
        reply(&peer, &store, object.id, vec![active.clone()]);
        let prior =
            settings.query_history(&manager, store.clone(), object.id.to_string()).await.unwrap();
        let before = store.personal_inventory_snapshot(vault).unwrap();
        let pending = record(&store).unwrap();
        let secrets = identity::Secrets::parse(&pending.private_material).unwrap();
        let account = Ed25519SigningKey::from_bytes(secrets.account_signing()).unwrap();
        let foreign_account = Ed25519SigningKey::from_bytes(&[83; 32]).unwrap();
        let other = scoplen_model::new_uuid_v7().unwrap();
        let signing = P256SigningKey::from_bytes(&[81; 32]).unwrap();
        let kem = DeviceKemKeyPair::from_private_bytes(&[82; 32]).unwrap();
        let certificate = DeviceCertificate::issue(
            if fault == 2 { &foreign_account } else { &account },
            other,
            pending.account_id,
            signing.public_key_sec1(),
            kem.public_key().to_vec(),
            "Retired device".into(),
            "macos".into(),
            1,
        )
        .unwrap();
        let mut revocation =
            RevocationStatement::issue(&account, other, 5_000, "Retired".into()).unwrap();
        if fault == 1 {
            revocation.signature[0] ^= 1;
        }
        let mut bundle = SyncAccountKeyBundle::from_cbor(
            &peer.state.lock().unwrap().replies["/sync/v1/keys"].body,
        )
        .unwrap();
        if !matches!(fault, 3 | 5) {
            bundle.certificates.push(certificate.encode().unwrap());
            bundle.certificates.sort();
        }
        if fault != 5 {
            bundle.revocations.push(revocation.encode().unwrap());
        }
        peer.reply("/sync/v1/keys", Reply::cbor(bundle.to_cbor().unwrap()));
        let mut historical = object.clone();
        for field in historical.fields.values_mut() {
            // A compromised signer can backdate fields; this is deliberately before revoked_at.
            field.clock = scoplen_model::Hlc::new(2, 0).unwrap();
            field.origin = other;
        }
        let mut envelope = ObjectEnvelope::encrypt(
            vault,
            1,
            &historical,
            &SymmetricKey::new(secrets.vault().try_into().unwrap()),
            other,
            &signing,
        )
        .unwrap();
        if fault == 4 {
            envelope.signature[0] ^= 1;
        }
        let revoked = SyncChange {
            object_id: object.id,
            seq: 2,
            payload: envelope.encode().unwrap(),
            tombstone: false,
            signer_device_id: Some(other),
        };
        reply(&peer, &store, object.id, vec![active, revoked.clone()]);
        assert_eq!(
            settings
                .query_history(&manager, store.clone(), object.id.to_string())
                .await
                .unwrap_err(),
            if fault == 0 {
                PersonalInventoryError::HistorySignerUnavailable
            } else {
                PersonalInventoryError::InvalidSyncResponse
            },
            "fault {fault}"
        );
        assert_eq!(
            settings.restore_history(&manager, store.clone(), prior.token, "1".into()),
            Err(PersonalInventoryError::PreviewExpired)
        );
        let after = store.personal_inventory_snapshot(vault).unwrap();
        assert_eq!(after.objects, before.objects);
        assert_eq!(
            (after.applied, after.acknowledged, after.pending),
            (before.applied, before.acknowledged, before.pending)
        );
        if fault == 0 {
            let mut inventory = InventoryPeer::default();
            inventory.objects.insert(object.id, revoked);
            peer.state.lock().unwrap().inventory = Some(inventory);
            assert_eq!(
                manager
                    .sync_personal_inventory(
                        store.clone(),
                        PersonalInventoryIntent { vault_id: vault, adopt: vec![] }
                    )
                    .await
                    .unwrap_err(),
                PersonalSyncError::InvalidResponse
            );
            assert_eq!(store.get(object.id).unwrap(), Some(object.clone()));
            assert_eq!(store.personal_sync_cursor(vault).unwrap(), before.applied);
            assert_eq!(peer.state.lock().unwrap().inventory.as_ref().unwrap().writes, 0);
        }
        peer.assert_healthy();
    }
}
