// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::personal_inventory::PersonalInventorySettings;

fn announce(peer: &Peer, seq: u64) {
    let mut state = peer.state.lock().unwrap();
    let reply = state.replies.get_mut("/sync/v1/session").unwrap();
    let mut session = SyncSessionResponse::from_cbor(&reply.body).unwrap();
    session.vaults.iter_mut().find(|vault| vault.kind == VaultKind::Personal).unwrap().seq = seq;
    reply.body = session.to_cbor().unwrap();
}

fn offline_name(store: &Store, id: Uuid, value: &str) -> Object {
    store
        .write(LocalWrite {
            id: Some(id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text(value.into()))],
        })
        .unwrap()
}

fn remote_hosts(
    store: &Store,
    anchor: &Object,
    first: u64,
    count: usize,
) -> BTreeMap<Uuid, SyncChange> {
    (first..first + count as u64)
        .map(|seq| {
            let mut object = anchor.clone();
            object.id = scoplen_model::new_uuid_v7().unwrap();
            (object.id, change(store, &object, seq))
        })
        .collect()
}

#[tokio::test]
async fn full_snapshot_merges_concurrent_edits_and_quarantines_missing_dirty_objects_until_explicit_restore()
 {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    peer.state.lock().unwrap().inventory = Some(InventoryPeer::default());
    let clean = make_host(&store);
    let dirty = make_host(&store);
    let present = make_host(&store);
    cycle(&peer, &store, vec![clean.id, dirty.id, present.id]).await.unwrap();
    let edited = offline_name(&store, dirty.id, "Offline edit must remain recoverable");
    let untouched = make_host(&store);
    let mut remote = present.clone();
    remote
        .insert(
            FieldPath::Field(7),
            FieldEntry::new(
                Value::Text("Remote note".into()),
                Hlc::at(scoplen_model::system_time_millis().unwrap()).unwrap(),
                store.device_id(),
            )
            .unwrap(),
        )
        .unwrap();
    let mut objects = remote_hosts(&store, &present, 12, 35);
    objects.insert(remote.id, change(&store, &remote, 11));
    peer.state.lock().unwrap().inventory = Some(InventoryPeer {
        seq: 46,
        objects,
        purge_horizon: 11,
        snapshot_local_edit: Some((
            store.clone(),
            LocalWrite {
                id: Some(present.id),
                object_type: ObjectType::HOST,
                fields: vec![(FieldPath::Field(1), Value::Text("Edited during snapshot".into()))],
            },
        )),
        ..InventoryPeer::default()
    });
    announce(&peer, 46);
    let result =
        manager.sync_personal_inventory(store.clone(), intent(&store, vec![])).await.unwrap();
    assert_eq!(result.downloaded, 37);
    assert_eq!(result.uploaded, 1);
    assert_eq!(result.applied_cursor, 47);
    assert_eq!(result.acknowledged_cursor, 47);
    assert!(store.get(clean.id).unwrap().is_none());
    assert!(store.get(dirty.id).unwrap().is_none());
    let present = store.get(present.id).unwrap().unwrap();
    assert_eq!(present.required_text(1).unwrap(), "Edited during snapshot");
    assert_eq!(present.required_text(7).unwrap(), "Remote note");
    let settings = PersonalInventorySettings::default();
    let status = settings.status(&store).unwrap();
    assert_eq!(status.recovery.len(), 1);
    assert_eq!(
        status.recovery[0].object.name.as_deref(),
        Some("Offline edit must remain recoverable")
    );
    assert!(
        status
            .objects
            .iter()
            .any(|object| object.id == untouched.id.to_string() && !object.personal)
    );
    assert_eq!(status.backups.len(), 3);
    {
        let state = peer.state.lock().unwrap();
        let inventory = state.inventory.as_ref().unwrap();
        assert_eq!(inventory.snapshot_queries, [0, 42]);
        assert_eq!(inventory.acks, [46, 47]);
        assert_eq!(inventory.writes, 1);
        assert!(!inventory.objects.contains_key(&dirty.id));
    }
    peer.assert_healthy();
    drop(peer);
    drop(store);
    let reopened = local(&dir);
    let copies = settings.status(&reopened).unwrap().recovery;
    let ids = manager
        .restore_personal_reconciliation_copies(
            &reopened,
            record(&reopened).unwrap().personal_vault_id,
            &[Uuid::parse_str(&copies[0].id).unwrap()],
        )
        .unwrap();
    assert_ne!(ids[0].0, ids[0].1);
    assert_eq!(ids[0].0, edited.id);
    assert_eq!(
        reopened.get(ids[0].1).unwrap().unwrap().required_text(1).unwrap(),
        edited.required_text(1).unwrap()
    );
    let restored = settings.status(&reopened).unwrap();
    assert_eq!(restored.recovery.len(), 1);
    assert!(
        restored.objects.iter().any(|object| object.id == ids[0].1.to_string() && !object.personal)
    );
    assert_eq!(restored.pending, 0);
}

#[tokio::test]
async fn a_later_invalid_or_moving_snapshot_never_changes_inventory_copies_or_progress_and_can_retry()
 {
    for mode in 0..7 {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        peer.prepare(&store).await;
        peer.state.lock().unwrap().inventory = Some(InventoryPeer::default());
        let clean = make_host(&store);
        let dirty = make_host(&store);
        cycle(&peer, &store, vec![clean.id, dirty.id]).await.unwrap();
        let edited = offline_name(&store, dirty.id, "Preserve on failed snapshot");
        let mut objects = remote_hosts(&store, &clean, 10, 35);
        let first = objects.values().min_by_key(|change| change.seq).unwrap().clone();
        let mut second = objects.values().max_by_key(|change| change.seq).unwrap().clone();
        let mut inventory = InventoryPeer {
            seq: 44,
            objects: objects.clone(),
            purge_horizon: 10,
            ..InventoryPeer::default()
        };
        let reply = match mode {
            0 => Reply::cbor(vec![0xff]),
            1 => {
                let mut envelope = ObjectEnvelope::decode(&second.payload).unwrap();
                envelope.signature[0] ^= 1;
                second.payload = envelope.encode().unwrap();
                Reply::cbor(
                    SyncSnapshotResponse { objects: vec![second], next_cursor: 44, more: false }
                        .to_cbor()
                        .unwrap(),
                )
            }
            2 => {
                let mut duplicate = first;
                duplicate.seq = 44;
                Reply::cbor(
                    SyncSnapshotResponse { objects: vec![duplicate], next_cursor: 44, more: false }
                        .to_cbor()
                        .unwrap(),
                )
            }
            3 => Reply::cbor(
                SyncSnapshotResponse { objects: vec![], next_cursor: 43, more: false }
                    .to_cbor()
                    .unwrap(),
            ),
            4 => {
                let mut mutation = second;
                mutation.seq = 45;
                inventory.snapshot_mutation = Some(mutation);
                Reply::cbor(vec![])
            }
            5 => problem_reply(&problem(403, "auth.authentication_required", false)),
            _ => Reply { stall: true, ..Reply::cbor(vec![]) },
        };
        if mode != 4 {
            inventory.snapshot_replies.insert(2, reply);
        }
        peer.state.lock().unwrap().inventory = Some(inventory);
        announce(&peer, 44);
        let error = cycle(&peer, &store, vec![]).await.unwrap_err();
        assert_eq!(
            error,
            match mode {
                4 => PersonalSyncError::ConcurrentChanges,
                5 => PersonalSyncError::AuthenticationRequired,
                6 => PersonalServerError::Network.into(),
                _ => PersonalSyncError::InvalidResponse,
            }
        );
        let status = PersonalInventorySettings::default().status(&store).unwrap();
        assert!(status.recovery.is_empty());
        assert_eq!(status.applied_cursor, "9");
        assert_eq!(status.acknowledged_cursor, "9");
        assert_eq!(store.get(clean.id).unwrap().unwrap(), clean);
        assert_eq!(store.get(dirty.id).unwrap().unwrap(), edited);
        assert_eq!(status.pending, 1);
        assert_eq!(peer.state.lock().unwrap().inventory.as_ref().unwrap().writes, 0);
        assert!(peer.state.lock().unwrap().inventory.as_ref().unwrap().acks.is_empty());
        drop(store);
        let store = local(&dir);
        assert_eq!(
            PersonalInventorySettings::default().status(&store).unwrap().applied_cursor,
            "9"
        );
        let seq = if mode == 4 { 45 } else { 44 };
        if mode == 4 {
            let mut last = second_change(&objects);
            last.seq = 45;
            objects.insert(last.object_id, last);
        }
        peer.state.lock().unwrap().inventory =
            Some(InventoryPeer { seq, objects, purge_horizon: 10, ..InventoryPeer::default() });
        announce(&peer, seq);
        if mode == 5 {
            assert_eq!(
                cycle(&peer, &store, vec![]).await.unwrap_err(),
                PersonalSyncError::AuthenticationRequired
            );
            // A server authentication rejection requires a newly authenticated session.
            peer.install_token(&store, |_| {}, None);
        }
        cycle(&peer, &store, vec![]).await.unwrap();
        assert_eq!(PersonalInventorySettings::default().status(&store).unwrap().recovery.len(), 1);
        peer.assert_healthy();
    }
}

fn second_change(objects: &BTreeMap<Uuid, SyncChange>) -> SyncChange {
    objects.values().max_by_key(|change| change.seq).unwrap().clone()
}

#[tokio::test]
async fn reconciliation_recovers_unknown_writes_and_unknown_acknowledgements_without_replaying_a_batch()
 {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    peer.prepare(&store).await;
    peer.state.lock().unwrap().inventory =
        Some(InventoryPeer { uncertain_once: true, ..InventoryPeer::default() });
    let object = make_host(&store);
    assert_eq!(
        cycle(&peer, &store, vec![object.id]).await.unwrap_err(),
        PersonalSyncError::WriteOutcomeUnknown
    );
    {
        let mut state = peer.state.lock().unwrap();
        let inventory = state.inventory.as_mut().unwrap();
        inventory.purge_horizon = 8;
        inventory.reject_ack = true;
    }
    announce(&peer, 8);
    assert_eq!(
        cycle(&peer, &store, vec![]).await.unwrap_err(),
        PersonalSyncError::AcknowledgementUnknown
    );
    let status = PersonalInventorySettings::default().status(&store).unwrap();
    assert_eq!(status.applied_cursor, "8");
    assert_eq!(status.acknowledged_cursor, "7");
    assert_eq!(status.pending, 0);
    assert!(status.recovery.is_empty());
    drop(store);
    let store = local(&dir);
    peer.state.lock().unwrap().inventory.as_mut().unwrap().reject_ack = false;
    let result = cycle(&peer, &store, vec![]).await.unwrap();
    assert_eq!(result.uploaded, 0);
    assert_eq!(result.acknowledged_cursor, 8);
    assert_eq!(peer.state.lock().unwrap().inventory.as_ref().unwrap().writes, 1);
    peer.assert_healthy();
}

#[tokio::test]
async fn empty_restored_server_snapshot_rebases_an_ahead_cursor_without_losing_dirty_edits() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    peer.prepare(&store).await;
    peer.state.lock().unwrap().inventory = Some(InventoryPeer::default());
    let clean = make_host(&store);
    let dirty = make_host(&store);
    cycle(&peer, &store, vec![clean.id, dirty.id]).await.unwrap();
    offline_name(&store, dirty.id, "Restore this edit");
    peer.state.lock().unwrap().inventory =
        Some(InventoryPeer { seq: 0, ..InventoryPeer::default() });
    announce(&peer, 0);
    let result = cycle(&peer, &store, vec![]).await.unwrap();
    assert_eq!(result.applied_cursor, 0);
    assert_eq!(result.acknowledged_cursor, 0);
    assert_eq!(result.uploaded, 0);
    let status = PersonalInventorySettings::default().status(&store).unwrap();
    assert!(status.objects.is_empty());
    assert_eq!(status.recovery.len(), 1);
    assert_eq!(status.recovery[0].object.id, dirty.id.to_string());
    peer.assert_healthy();
}

#[tokio::test]
async fn aggregate_snapshot_body_budget_includes_ignored_extensions_and_never_applies_a_prefix() {
    use scoplen_model::cbor;

    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let mut manager = peer.prepare(&store).await;
    manager.transport = Ok(Transport::fixture(peer.certificate.clone(), Duration::from_secs(10)));
    peer.state.lock().unwrap().inventory = Some(InventoryPeer::default());
    let original = make_host(&store);
    cycle(&peer, &store, vec![original.id]).await.unwrap();
    let edited = offline_name(&store, original.id, "Retain during bounded download");
    let remote = remote_hosts(&store, &original, 9, 5);
    let mut entries = remote.values().cloned().collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.seq);
    let mut inventory =
        InventoryPeer { seq: 13, objects: remote, purge_horizon: 9, ..InventoryPeer::default() };
    for (index, entry) in entries.into_iter().take(4).enumerate() {
        let response =
            SyncSnapshotResponse { next_cursor: entry.seq, objects: vec![entry], more: true };
        let Value::Map(mut fields) = cbor::decode(&response.to_cbor().unwrap()).unwrap() else {
            panic!("snapshot map")
        };
        fields.push((Value::Text("future".into()), Value::Bytes(vec![0; 8 * 1024 * 1024])));
        inventory
            .snapshot_replies
            .insert(index + 1, Reply::cbor(cbor::encode(&Value::Map(fields)).unwrap()));
    }
    peer.state.lock().unwrap().inventory = Some(inventory);
    announce(&peer, 13);
    assert_eq!(
        manager.sync_personal_inventory(store.clone(), intent(&store, vec![])).await.unwrap_err(),
        PersonalSyncError::ResourceLimit
    );
    let status = PersonalInventorySettings::default().status(&store).unwrap();
    assert_eq!(status.applied_cursor, "8");
    assert_eq!(status.acknowledged_cursor, "8");
    assert_eq!(status.pending, 1);
    assert!(status.recovery.is_empty());
    assert_eq!(store.get(original.id).unwrap(), Some(edited));
    let state = peer.state.lock().unwrap();
    let inventory = state.inventory.as_ref().unwrap();
    assert_eq!(inventory.snapshot_queries, [0, 9, 10, 11]);
    assert!(inventory.acks.is_empty());
    assert_eq!(inventory.writes, 0);
    drop(state);
    peer.assert_healthy();
}
