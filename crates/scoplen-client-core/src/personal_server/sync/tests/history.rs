// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{
    personal_inventory::{PersonalInventoryError, PersonalInventorySettings},
    store::LocalWrite,
};
use scoplen_api::sync::{SyncChange, SyncVersionsResponse};
use scoplen_crypto::ObjectEnvelope;
use scoplen_model::{
    FieldPath, Object, ObjectType,
    cbor::{self, Value},
};

async fn fixture(peer: &Peer) -> (tempfile::TempDir, Arc<Store>, PersonalServer, Object) {
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    manager.bootstrap_sync(store.clone()).await.unwrap();
    let object = inventory::make_host(&store);
    let vault = record(&store).unwrap().personal_vault_id;
    store.adopt_personal_objects(vault, &[object.id]).unwrap();
    (dir, store, manager, object)
}

fn path(store: &Store, id: uuid::Uuid) -> String {
    format!("/sync/v1/vaults/{}/objects/{id}/versions", record(store).unwrap().personal_vault_id)
}

fn reply(peer: &Peer, store: &Store, id: uuid::Uuid, versions: Vec<SyncChange>) {
    peer.reply(&path(store, id), Reply::cbor(SyncVersionsResponse { versions }.to_cbor().unwrap()));
}

#[tokio::test]
async fn personal_history_rejects_invalid_or_unadopted_selection_before_network() {
    let peer = Peer::new().await;
    let (_dir, store, manager, _) = fixture(&peer).await;
    let local_object = inventory::make_host(&store);
    let before = peer.state.lock().unwrap().paths.clone();
    let settings = PersonalInventorySettings::default();
    for id in [
        "invalid".into(),
        local_object.id.to_string(),
        scoplen_model::new_uuid_v7().unwrap().to_string(),
    ] {
        assert_eq!(
            settings.query_history(&manager, store.clone(), id).await.unwrap_err(),
            PersonalInventoryError::Selection
        );
    }
    assert_eq!(peer.state.lock().unwrap().paths, before);
    peer.assert_healthy();
}

#[tokio::test]
async fn personal_history_verifies_all_versions_and_restores_only_a_fresh_local_copy() {
    let peer = Peer::new().await;
    let (_dir, store, manager, old) = fixture(&peer).await;
    let current = store
        .write(LocalWrite {
            id: Some(old.id),
            object_type: old.object_type,
            fields: vec![(FieldPath::Field(1), Value::Text("Current edit".into()))],
        })
        .unwrap();
    let vault = record(&store).unwrap().personal_vault_id;
    let before = store.personal_inventory_snapshot(vault).unwrap();
    reply(
        &peer,
        &store,
        old.id,
        vec![
            inventory::change(&store, &old, 1),
            inventory::change(&store, &current, 9_007_199_254_740_993),
        ],
    );
    let settings = PersonalInventorySettings::default();
    let history =
        settings.query_history(&manager, store.clone(), old.id.to_string()).await.unwrap();
    assert_eq!(
        history.versions.iter().map(|v| v.sequence.as_str()).collect::<Vec<_>>(),
        ["1", "9007199254740993"]
    );
    let json = serde_json::to_string(&history).unwrap();
    assert!(!json.contains("192.0.2.12"));
    assert!(!json.contains("payload"));
    let queried = store.personal_inventory_snapshot(vault).unwrap();
    assert_eq!(
        (queried.applied, queried.acknowledged, queried.pending),
        (before.applied, before.acknowledged, before.pending)
    );
    assert_eq!(queried.objects, before.objects);
    let paths = peer.state.lock().unwrap().paths.clone();
    let concurrent = store
        .write(LocalWrite {
            id: Some(old.id),
            object_type: old.object_type,
            fields: vec![(FieldPath::Field(7), Value::Text("Concurrent note".into()))],
        })
        .unwrap();
    settings.restore_history(&manager, store.clone(), history.token.clone(), "1".into()).unwrap();
    assert_eq!(peer.state.lock().unwrap().paths, paths);
    assert_eq!(store.get(old.id).unwrap(), Some(concurrent));
    let restored = store
        .list(ObjectType::HOST)
        .unwrap()
        .into_iter()
        .find(|object| object.id != old.id)
        .unwrap();
    assert_eq!(restored.required_text(1).unwrap(), old.required_text(1).unwrap());
    assert!(restored.field(1).unwrap().clock > old.field(1).unwrap().clock);
    let after = store.personal_inventory_snapshot(vault).unwrap();
    assert!(!after.objects.iter().find(|(object, ..)| object.id == restored.id).unwrap().1);
    assert_eq!(after.pending, before.pending);
    assert_eq!(
        settings.restore_history(&manager, store.clone(), history.token, "1".into()),
        Err(PersonalInventoryError::PreviewExpired)
    );
    peer.assert_healthy();
}

#[tokio::test]
async fn personal_history_invalid_final_entry_never_returns_a_partial_review() {
    let peer = Peer::new().await;
    let (_dir, store, manager, object) = fixture(&peer).await;
    let valid = inventory::change(&store, &object, 1);
    let settings = PersonalInventorySettings::default();
    for fault in 0..8 {
        reply(&peer, &store, object.id, vec![valid.clone()]);
        let prior =
            settings.query_history(&manager, store.clone(), object.id.to_string()).await.unwrap();
        let mut bad = inventory::change(&store, &object, 2);
        let mut envelope = ObjectEnvelope::decode(&bad.payload).unwrap();
        match fault {
            0 => envelope.signature[0] ^= 1,
            1 => {
                let pending = record(&store).unwrap();
                let secrets = identity::Secrets::parse(&pending.private_material).unwrap();
                envelope = ObjectEnvelope::encrypt(
                    pending.personal_vault_id,
                    1,
                    &object,
                    &SymmetricKey::new([99; 32]),
                    store.device_id(),
                    &P256SigningKey::from_bytes(secrets.signing()).unwrap(),
                )
                .unwrap();
            }
            2 => envelope.key_epoch = 2,
            3 => bad.signer_device_id = Some(scoplen_model::new_uuid_v7().unwrap()),
            4 => bad.tombstone = true,
            5 => {
                let pending = record(&store).unwrap();
                let secrets = identity::Secrets::parse(&pending.private_material).unwrap();
                envelope = ObjectEnvelope::encrypt(
                    scoplen_model::new_uuid_v7().unwrap(),
                    1,
                    &object,
                    &SymmetricKey::new(secrets.vault().try_into().unwrap()),
                    store.device_id(),
                    &P256SigningKey::from_bytes(secrets.signing()).unwrap(),
                )
                .unwrap();
            }
            6 => {
                let mut other = object.clone();
                other.id = scoplen_model::new_uuid_v7().unwrap();
                bad = inventory::change(&store, &other, 2);
                bad.object_id = object.id;
                envelope = ObjectEnvelope::decode(&bad.payload).unwrap();
            }
            _ => {
                let mut other = object.clone();
                other.object_type = ObjectType::from_wire(999).unwrap();
                bad = inventory::change(&store, &other, 2);
                envelope = ObjectEnvelope::decode(&bad.payload).unwrap();
            }
        }
        bad.payload = envelope.encode().unwrap();
        reply(&peer, &store, object.id, vec![valid.clone(), bad]);
        assert_eq!(
            settings
                .query_history(&manager, store.clone(), object.id.to_string())
                .await
                .unwrap_err(),
            PersonalInventoryError::InvalidSyncResponse,
            "fault {fault}"
        );
        assert_eq!(
            settings.restore_history(&manager, store.clone(), prior.token, "1".into()),
            Err(PersonalInventoryError::PreviewExpired)
        );
        assert_eq!(store.list(ObjectType::HOST).unwrap().as_slice(), std::slice::from_ref(&object));
    }
    peer.assert_healthy();
}

#[tokio::test]
async fn personal_history_rejects_mixed_ids_order_count_and_response_budget() {
    let peer = Peer::new().await;
    let (_dir, store, manager, object) = fixture(&peer).await;
    let settings = PersonalInventorySettings::default();
    let valid = SyncVersionsResponse { versions: vec![inventory::change(&store, &object, 1)] }
        .to_cbor()
        .unwrap();
    for fault in 0..6 {
        let mut wire = cbor::decode(&valid).unwrap();
        let Value::Map(fields) = &mut wire else { unreachable!() };
        let Value::Array(versions) = &mut fields[0].1 else { unreachable!() };
        match fault {
            0 => versions.clear(),
            1 => versions.push(versions[0].clone()),
            2 => *versions = vec![versions[0].clone(); 22],
            3 => {
                let Value::Map(entry) = &mut versions[0] else { unreachable!() };
                entry.iter_mut().find(|(key, _)| *key == Value::UInt(1)).unwrap().1 =
                    Value::Bytes(scoplen_model::new_uuid_v7().unwrap().as_bytes().to_vec());
            }
            4 => {
                let Value::Map(entry) = &mut versions[0] else { unreachable!() };
                entry.iter_mut().find(|(key, _)| *key == Value::UInt(3)).unwrap().1 =
                    Value::Bytes(vec![0; 1_048_577]);
            }
            _ => fields.push((
                Value::Text("ignored-extension".into()),
                Value::Bytes(vec![0; 9 * 1024 * 1024]),
            )),
        }
        peer.reply(&path(&store, object.id), Reply::cbor(cbor::encode(&wire).unwrap()));
        assert!(
            settings.query_history(&manager, store.clone(), object.id.to_string()).await.is_err(),
            "fault {fault}"
        );
        assert_eq!(store.get(object.id).unwrap(), Some(object.clone()));
    }
    peer.assert_healthy();
}

#[tokio::test]
async fn personal_history_only_accepts_typed_unchanged_not_found() {
    let peer = Peer::new().await;
    let (_dir, store, manager, object) = fixture(&peer).await;
    let settings = PersonalInventorySettings::default();
    for fault in 0..4 {
        let problem = scoplen_api::ProblemDetails::new(
            scoplen_api::ErrorCode::new(if fault == 1 {
                "sync.other"
            } else {
                "sync.object_not_found"
            })
            .unwrap(),
            404,
            "Missing",
            "Missing",
            "/request/fixture",
            fault == 2,
            fault == 3,
        )
        .unwrap();
        peer.reply(
            &path(&store, object.id),
            Reply {
                status: 404,
                content_type: "application/problem+cbor",
                body: problem.to_cbor().unwrap(),
                ..Reply::cbor(vec![])
            },
        );
        let error = settings
            .query_history(&manager, store.clone(), object.id.to_string())
            .await
            .unwrap_err();
        assert_eq!(
            error,
            if fault == 0 {
                PersonalInventoryError::HistoryNotFound
            } else {
                PersonalInventoryError::InvalidSyncResponse
            }
        );
        assert_eq!(store.get(object.id).unwrap(), Some(object.clone()));
    }
    peer.assert_healthy();
}

#[tokio::test]
async fn personal_history_rechecks_rotation_and_authentication_after_delayed_response() {
    for rotation in [false, true] {
        let peer = Peer::new().await;
        let (_dir, store, manager, object) = fixture(&peer).await;
        reply(&peer, &store, object.id, vec![inventory::change(&store, &object, 1)]);
        let reached = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        peer.state.lock().unwrap().pause =
            Some((path(&store, object.id), reached.clone(), resume.clone()));
        let query_store = store.clone();
        let task = tokio::spawn(async move {
            PersonalInventorySettings::default()
                .query_history(&manager, query_store, object.id.to_string())
                .await
        });
        reached.notified().await;
        if rotation {
            store.require_personal_keys();
        } else {
            store.clear_personal_tokens().unwrap();
        }
        resume.notify_one();
        assert_eq!(
            task.await.unwrap().unwrap_err(),
            if rotation {
                PersonalInventoryError::RotationRequired
            } else {
                PersonalInventoryError::AuthenticationRequired
            }
        );
        assert_eq!(store.list(ObjectType::HOST).unwrap().len(), 1);
        peer.assert_healthy();
    }
}
