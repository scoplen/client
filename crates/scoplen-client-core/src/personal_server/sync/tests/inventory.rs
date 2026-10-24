// SPDX-License-Identifier: Apache-2.0
//! An opaque K-4 reference peer over real TLS/H2. This is independent of server source.

use scoplen_api::{
    ErrorCode, ProblemDetails,
    sync::{
        SyncAckRequest, SyncAckResponse, SyncChange, SyncChangesQuery, SyncChangesResponse,
        SyncConflictEntry, SyncConflictProblem, SyncSnapshotResponse, SyncWriteAssignment,
        SyncWriteBatch, SyncWriteBatchResponse,
    },
};
use scoplen_crypto::ObjectEnvelope;
use scoplen_model::{FieldEntry, FieldPath, Hlc, Object, ObjectType, cbor::Value};
use uuid::Uuid;

use super::*;
use crate::{
    personal_server::{PersonalInventoryIntent, PersonalInventoryProgress},
    store::LocalWrite,
};

mod reconciliation;

pub(super) struct InventoryPeer {
    pub(super) seq: u64,
    pub(super) objects: BTreeMap<Uuid, SyncChange>,
    pub(super) writes: usize,
    acks: Vec<u64>,
    pub(super) queries: Vec<u64>,
    uncertain_once: bool,
    lost_once: bool,
    invalid_assignment_once: bool,
    conflict_once: Option<SyncChange>,
    expire_cursor: bool,
    reject_ack: bool,
    date: Option<String>,
    ack_reported_cursor: Option<u64>,
    purge_horizon: u64,
    snapshot_queries: Vec<u64>,
    snapshot_replies: BTreeMap<usize, Reply>,
    snapshot_mutation: Option<SyncChange>,
    snapshot_local_edit: Option<(Arc<Store>, LocalWrite)>,
}

impl Default for InventoryPeer {
    fn default() -> Self {
        Self {
            seq: 7,
            objects: BTreeMap::new(),
            writes: 0,
            acks: vec![],
            queries: vec![],
            uncertain_once: false,
            lost_once: false,
            invalid_assignment_once: false,
            conflict_once: None,
            expire_cursor: false,
            reject_ack: false,
            date: Some(httpdate::fmt_http_date(std::time::SystemTime::now())),
            ack_reported_cursor: None,
            purge_horizon: 0,
            snapshot_queries: vec![],
            snapshot_replies: BTreeMap::new(),
            snapshot_mutation: None,
            snapshot_local_edit: None,
        }
    }
}

fn problem(status: u16, code: &str, changed: bool) -> ProblemDetails {
    ProblemDetails::new(
        ErrorCode::new(code).unwrap(),
        status,
        "Fixture",
        "Opaque fixture response",
        "/fixture",
        changed,
        !changed,
    )
    .unwrap()
}

fn problem_reply(problem: &ProblemDetails) -> Reply {
    Reply {
        status: problem.status,
        content_type: "application/problem+cbor",
        body: problem.to_cbor().unwrap(),
        ..Reply::cbor(vec![])
    }
}

impl InventoryPeer {
    pub(super) fn answer(
        &mut self,
        request: &http::Request<h2::RecvStream>,
        body: &[u8],
        signing: &[u8],
        device: Uuid,
    ) -> Result<Reply, String> {
        let path = request.uri().path();
        let vault =
            path.split('/').nth(4).and_then(|id| Uuid::parse_str(id).ok()).ok_or("vault path")?;
        let mut reply = match path.rsplit('/').next().unwrap() {
            "changes" => {
                if request.method() != http::Method::GET || !body.is_empty() {
                    return Err("change method".into());
                }
                let query = SyncChangesQuery::from_query(request.uri().query().ok_or("query")?)
                    .map_err(|_| "change query")?;
                self.queries.push(query.after);
                if self.expire_cursor || query.after < self.purge_horizon || query.after > self.seq
                {
                    problem_reply(&problem(410, "sync.cursor_expired", false))
                } else {
                    let mut changes = self
                        .objects
                        .values()
                        .filter(|change| change.seq > query.after)
                        .cloned()
                        .collect::<Vec<_>>();
                    changes.sort_by_key(|change| change.seq);
                    let more = changes.len() > usize::from(query.limit);
                    changes.truncate(usize::from(query.limit));
                    let next_cursor = if more { changes.last().unwrap().seq } else { self.seq };
                    Reply::cbor(
                        SyncChangesResponse { changes, next_cursor, more }.to_cbor().unwrap(),
                    )
                }
            }
            "snapshot" => {
                if request.method() != http::Method::GET || !body.is_empty() {
                    return Err("snapshot method".into());
                }
                let query = SyncChangesQuery::from_query(request.uri().query().ok_or("query")?)
                    .map_err(|_| "snapshot query")?;
                self.snapshot_queries.push(query.after);
                if query.after > 0 {
                    if let Some(change) = self.snapshot_mutation.take() {
                        self.seq = self.seq.max(change.seq);
                        self.objects.insert(change.object_id, change);
                    }
                    if let Some((store, write)) = self.snapshot_local_edit.take() {
                        store.write(write).map_err(|_| "concurrent local edit")?;
                    }
                }
                if let Some(reply) = self.snapshot_replies.get(&self.snapshot_queries.len()) {
                    reply.clone()
                } else {
                    let mut objects = self
                        .objects
                        .values()
                        .filter(|change| change.seq > query.after)
                        .cloned()
                        .collect::<Vec<_>>();
                    objects.sort_by_key(|change| change.seq);
                    let more = objects.len() > usize::from(query.limit);
                    objects.truncate(usize::from(query.limit));
                    let next_cursor = if more { objects.last().unwrap().seq } else { self.seq };
                    Reply::cbor(
                        SyncSnapshotResponse { objects, next_cursor, more }.to_cbor().unwrap(),
                    )
                }
            }
            "objects" => {
                if request.method() != http::Method::POST {
                    return Err("write method".into());
                }
                self.writes += 1;
                let batch = SyncWriteBatch::from_cbor(body).map_err(|_| "write batch")?;
                for write in &batch.writes {
                    let envelope =
                        ObjectEnvelope::decode(&write.payload).map_err(|_| "envelope")?;
                    if envelope.signer_device_id != device || envelope.key_epoch != 1 {
                        return Err("write signer".into());
                    }
                    envelope
                        .verify_signature(vault, write.object_id, signing)
                        .map_err(|_| "write signature")?;
                }
                if let Some(change) = self.conflict_once.take() {
                    self.seq = self.seq.max(change.seq);
                    self.objects.insert(change.object_id, change);
                }
                let conflicts = batch
                    .writes
                    .iter()
                    .filter(|write| {
                        self.objects.get(&write.object_id).map(|object| object.seq)
                            != write.base_seq
                    })
                    .map(|write| SyncConflictEntry {
                        object_id: write.object_id,
                        current: self.objects.get(&write.object_id).cloned(),
                    })
                    .collect::<Vec<_>>();
                if !conflicts.is_empty() {
                    Reply {
                        status: 409,
                        content_type: "application/problem+cbor",
                        body: SyncConflictProblem {
                            problem: problem(409, "sync.conflict", false),
                            conflicts,
                        }
                        .to_cbor()
                        .unwrap(),
                        ..Reply::cbor(vec![])
                    }
                } else {
                    let mut assignments = Vec::new();
                    for write in batch.writes {
                        self.seq += 1;
                        self.objects.insert(
                            write.object_id,
                            SyncChange {
                                object_id: write.object_id,
                                seq: self.seq,
                                payload: write.payload,
                                tombstone: write.tombstone,
                                signer_device_id: Some(device),
                            },
                        );
                        assignments.push(SyncWriteAssignment {
                            object_id: write.object_id,
                            seq: self.seq,
                        });
                    }
                    if std::mem::take(&mut self.uncertain_once) {
                        problem_reply(&problem(503, "sync.storage_unavailable", true))
                    } else if std::mem::take(&mut self.lost_once) {
                        Reply { stall: true, ..Reply::cbor(vec![]) }
                    } else if std::mem::take(&mut self.invalid_assignment_once) {
                        Reply::cbor(vec![0xff])
                    } else {
                        Reply::cbor(SyncWriteBatchResponse { assignments }.to_cbor().unwrap())
                    }
                }
            }
            "ack" => {
                if request.method() != http::Method::POST {
                    return Err("ack method".into());
                }
                let request = SyncAckRequest::from_cbor(body).map_err(|_| "ack")?;
                if request.cursor > self.seq {
                    return Err("ack ahead".into());
                }
                if self.reject_ack {
                    problem_reply(&problem(503, "sync.storage_unavailable", true))
                } else {
                    self.acks.push(request.cursor);
                    Reply::cbor(
                        SyncAckResponse {
                            cursor: self.ack_reported_cursor.unwrap_or(request.cursor),
                        }
                        .to_cbor()
                        .unwrap(),
                    )
                }
            }
            _ => return Err("unknown inventory path".into()),
        };
        if let Some(date) = &self.date {
            reply.headers.push(("date", date.clone()));
        }
        Ok(reply)
    }
}

pub(super) fn make_host(store: &Store) -> Object {
    store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text("Private production host".into())),
                (FieldPath::Field(2), Value::Text("192.0.2.12".into())),
            ],
        })
        .unwrap()
}

fn intent(store: &Store, ids: Vec<Uuid>) -> PersonalInventoryIntent {
    PersonalInventoryIntent { vault_id: record(store).unwrap().personal_vault_id, adopt: ids }
}

pub(super) fn change(store: &Store, object: &Object, seq: u64) -> SyncChange {
    let identity = record(store).unwrap();
    let secrets = identity::Secrets::parse(&identity.private_material).unwrap();
    let key = SymmetricKey::new(secrets.vault().try_into().unwrap());
    let signing = P256SigningKey::from_bytes(secrets.signing()).unwrap();
    let envelope = ObjectEnvelope::encrypt(
        identity.personal_vault_id,
        1,
        object,
        &key,
        store.device_id(),
        &signing,
    )
    .unwrap();
    SyncChange {
        object_id: object.id,
        seq,
        payload: envelope.encode().unwrap(),
        tombstone: object.is_tombstoned(),
        signer_device_id: Some(store.device_id()),
    }
}

async fn cycle(
    peer: &Peer,
    store: &Arc<Store>,
    ids: Vec<Uuid>,
) -> Result<PersonalInventoryProgress, PersonalSyncError> {
    peer.manager().sync_personal_inventory(store.clone(), intent(store, ids)).await
}

#[tokio::test]
async fn settings_facade_reviews_exact_ids_redacts_secrets_and_restores_offline() {
    use crate::personal_inventory::PersonalInventorySettings;
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    peer.state.lock().unwrap().inventory = Some(InventoryPeer::default());
    let settings = PersonalInventorySettings::default();
    let host = make_host(&store);
    let shared = store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::CREDENTIAL,
            fields: vec![
                (FieldPath::Field(1), Value::Text("Shared password".into())),
                (FieldPath::Field(2), Value::UInt(1)),
                (FieldPath::Field(3), Value::UInt(1)),
                (FieldPath::Field(4), Value::Bytes(b"secret-must-not-cross-ipc".to_vec())),
            ],
        })
        .unwrap();
    let device = store
        .write_with_device_credential(
            LocalWrite {
                id: None,
                object_type: ObjectType::CREDENTIAL,
                fields: vec![
                    (FieldPath::Field(2), Value::UInt(1)),
                    (FieldPath::Field(3), Value::UInt(2)),
                ],
            },
            Some(b"device-secret-must-not-cross-ipc"),
            false,
        )
        .unwrap();
    let login = store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::ACCESS_PROFILE,
            fields: vec![
                (FieldPath::Field(1), Value::Bytes(host.id.as_bytes().to_vec())),
                (FieldPath::Field(3), Value::Text("operator".into())),
                (FieldPath::Field(4), Value::Bytes(shared.id.as_bytes().to_vec())),
            ],
        })
        .unwrap();
    let before = peer.state.lock().unwrap().paths.len();
    let incomplete = settings.preview(&store, vec![login.id.to_string()]).unwrap();
    assert!(incomplete.token.is_none());
    assert_eq!(incomplete.objects.len(), 1);
    assert_eq!(incomplete.missing.len(), 2);
    let ids = [host.id, shared.id, login.id, device.id].map(|id| id.to_string()).to_vec();
    let preview = settings.preview(&store, ids.clone()).unwrap();
    assert_eq!(preview.objects.len(), 4);
    assert!(
        preview
            .objects
            .iter()
            .find(|object| object.id == shared.id.to_string())
            .unwrap()
            .shared_secret
    );
    assert!(
        !preview
            .objects
            .iter()
            .find(|object| object.id == device.id.to_string())
            .unwrap()
            .shared_secret
    );
    let json = serde_json::to_string(&preview).unwrap();
    assert!(!json.contains("secret-must-not-cross-ipc"));
    assert!(!json.contains("operator"));
    assert_eq!(peer.state.lock().unwrap().paths.len(), before);
    let result = settings.synchronize(&manager, store.clone(), preview.token).await.unwrap();
    assert_eq!(result.uploaded, 4);
    let status = settings.status(&store).unwrap();
    assert_eq!(status.pending, 0);
    assert_eq!(status.backups.len(), 4);
    assert_eq!(status.applied_cursor, "11");
    assert_eq!(status.acknowledged_cursor, "11");
    assert!(status.objects.iter().all(|object| object.personal));
    store
        .write(LocalWrite {
            id: Some(host.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("Offline edit".into()))],
        })
        .unwrap();
    let future = make_host(&store);
    let unknown = store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::from_wire(50_000).unwrap(),
            fields: vec![(
                FieldPath::Field(1),
                Value::Text("future-sensitive-content-must-not-cross-ipc".into()),
            )],
        })
        .unwrap();
    assert_eq!(settings.status(&store).unwrap().pending, 1);
    let metadata = settings.status(&store).unwrap();
    assert!(
        metadata
            .objects
            .iter()
            .find(|object| object.id == unknown.id.to_string())
            .unwrap()
            .name
            .is_none()
    );
    assert!(!serde_json::to_string(&metadata).unwrap().contains("future-sensitive-content"));
    peer.assert_healthy();
    drop(peer);
    assert_eq!(settings.restore(&manager, &store, ids).unwrap(), 4);
    let status = settings.status(&store).unwrap();
    assert_eq!(status.pending, 1);
    assert_eq!(status.backups.len(), 4);
    assert_eq!(status.objects.iter().filter(|object| !object.personal).count(), 6);
    assert!(
        status
            .objects
            .iter()
            .find(|object| object.id == future.id.to_string())
            .is_some_and(|object| !object.personal)
    );
    assert_eq!(
        store.device_credential(device.id).unwrap().unwrap().secret.unwrap().as_bytes(),
        b"device-secret-must-not-cross-ipc"
    );
    drop(store);
    let reopened = local(&dir);
    let status = PersonalInventorySettings::default().status(&reopened).unwrap();
    assert_eq!(status.pending, 1);
    assert_eq!(status.applied_cursor, "11");
    assert_eq!(status.backups.len(), 4);
}

#[tokio::test]
async fn settings_facade_rejects_stale_reviews_atomically_and_consumes_them_once() {
    use crate::personal_inventory::{PersonalInventoryError, PersonalInventorySettings};
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    peer.state.lock().unwrap().inventory = Some(InventoryPeer::default());
    let first = make_host(&store);
    let second = make_host(&store);
    let settings = PersonalInventorySettings::default();
    let ids = vec![first.id.to_string(), second.id.to_string()];
    assert_eq!(
        settings.preview(&store, vec!["bad id".into()]).unwrap_err(),
        PersonalInventoryError::Selection
    );
    assert_eq!(
        settings.preview(&store, vec![first.id.to_string(); 2]).unwrap_err(),
        PersonalInventoryError::Selection
    );
    let review = settings.preview(&store, ids).unwrap();
    store
        .write(LocalWrite {
            id: Some(second.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(7), Value::Text("Changed after review".into()))],
        })
        .unwrap();
    assert_eq!(
        settings.synchronize(&manager, store.clone(), review.token.clone()).await.unwrap_err(),
        PersonalInventoryError::Selection
    );
    let status = settings.status(&store).unwrap();
    assert!(status.backups.is_empty());
    assert!(status.objects.iter().all(|object| !object.personal));
    assert_eq!(status.pending, 0);
    assert_eq!(
        settings.synchronize(&manager, store.clone(), review.token).await.unwrap_err(),
        PersonalInventoryError::PreviewExpired
    );
    assert_eq!(settings.synchronize(&manager, store.clone(), None).await.unwrap().uploaded, 0);
    assert!(settings.status(&store).unwrap().backups.is_empty());
    assert_eq!(peer.state.lock().unwrap().inventory.as_ref().unwrap().writes, 0);
    peer.assert_healthy();
}

#[tokio::test]
async fn settings_facade_reports_uncertain_commits_and_keeps_durable_progress_for_manual_recovery()
{
    use crate::personal_inventory::{PersonalInventoryError, PersonalInventorySettings};
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    peer.state.lock().unwrap().inventory =
        Some(InventoryPeer { uncertain_once: true, ..InventoryPeer::default() });
    let object = make_host(&store);
    let settings = PersonalInventorySettings::default();
    let preview = settings.preview(&store, vec![object.id.to_string()]).unwrap();
    assert_eq!(
        settings.synchronize(&manager, store.clone(), preview.token).await.unwrap_err(),
        PersonalInventoryError::WriteOutcomeUnknown
    );
    let status = settings.status(&store).unwrap();
    assert_eq!(status.pending, 1);
    assert_eq!(status.backups.len(), 1);
    assert_eq!(status.applied_cursor, "7");
    assert_eq!(status.acknowledged_cursor, "7");
    settings.synchronize(&manager, store.clone(), None).await.unwrap();
    assert_eq!(settings.status(&store).unwrap().pending, 0);
    assert_eq!(peer.state.lock().unwrap().inventory.as_ref().unwrap().writes, 1);
    peer.assert_healthy();
}

#[tokio::test]
async fn explicit_inventory_roundtrip_encrypts_secrets_and_survives_restart_and_offline_edits() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    peer.prepare(&store).await;
    peer.state.lock().unwrap().inventory = Some(InventoryPeer::default());
    let host = make_host(&store);
    let shared = store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::CREDENTIAL,
            fields: vec![
                (FieldPath::Field(2), Value::UInt(1)),
                (FieldPath::Field(3), Value::UInt(1)),
                (FieldPath::Field(4), Value::Bytes(b"private password fixture".to_vec())),
            ],
        })
        .unwrap();
    let device = store
        .write_with_device_credential(
            LocalWrite {
                id: None,
                object_type: ObjectType::CREDENTIAL,
                fields: vec![
                    (FieldPath::Field(2), Value::UInt(1)),
                    (FieldPath::Field(3), Value::UInt(2)),
                ],
            },
            Some(b"device only password fixture"),
            false,
        )
        .unwrap();
    let result = cycle(&peer, &store, vec![host.id, shared.id, device.id]).await.unwrap();
    assert_eq!(result.uploaded, 3);
    assert_eq!(result.applied_cursor, 10);
    assert!(!result.more);
    {
        let state = peer.state.lock().unwrap();
        let inventory = state.inventory.as_ref().unwrap();
        assert_eq!(inventory.writes, 1);
        assert_eq!(inventory.acks, [7, 10]);
        for object in inventory.objects.values() {
            assert!(!object.payload.windows(7).any(|bytes| bytes == b"private"));
            assert!(!object.payload.windows(11).any(|bytes| bytes == b"device only"));
        }
    }
    let identity = record(&store).unwrap();
    let bootstrap = peer.manager().load_sync_bootstrap(&store).unwrap().unwrap();
    let key = bootstrap.personal_vault_key();
    let device_payload =
        peer.state.lock().unwrap().inventory.as_ref().unwrap().objects[&device.id].payload.clone();
    let decrypted = ObjectEnvelope::decode(&device_payload)
        .unwrap()
        .decrypt(
            identity.personal_vault_id,
            device.id,
            key,
            &bootstrap.active_devices[0].signing_public_key,
        )
        .unwrap();
    assert!(decrypted.set_field(4).is_none());
    drop(store);
    let store = local(&dir);
    store
        .write(LocalWrite {
            id: Some(host.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(7), Value::Text("offline note".into()))],
        })
        .unwrap();
    let unselected = make_host(&store);
    let result = cycle(&peer, &store, vec![]).await.unwrap();
    assert_eq!(result.uploaded, 1);
    assert_eq!(result.applied_cursor, 11);
    assert!(
        !peer
            .state
            .lock()
            .unwrap()
            .inventory
            .as_ref()
            .unwrap()
            .objects
            .contains_key(&unselected.id)
    );
    assert_eq!(
        store.personal_adoption_backup(identity.personal_vault_id, host.id).unwrap().unwrap(),
        host
    );
    peer.assert_healthy();
}

#[tokio::test]
async fn uncertain_commits_lost_responses_and_bad_assignments_are_pulled_without_replay() {
    for mode in 0..3 {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        peer.prepare(&store).await;
        peer.state.lock().unwrap().inventory = Some(InventoryPeer {
            uncertain_once: mode == 0,
            lost_once: mode == 1,
            invalid_assignment_once: mode == 2,
            ..InventoryPeer::default()
        });
        let object = make_host(&store);
        assert_eq!(
            cycle(&peer, &store, vec![object.id]).await.unwrap_err(),
            PersonalSyncError::WriteOutcomeUnknown
        );
        let vault = record(&store).unwrap().personal_vault_id;
        assert_eq!(store.personal_sync_cursor(vault).unwrap(), 7);
        assert_eq!(store.pending_personal_objects(vault, 10).unwrap().len(), 1);
        drop(store);
        let store = local(&dir);
        let result = cycle(&peer, &store, vec![]).await.unwrap();
        assert_eq!(result.uploaded, 0);
        assert_eq!(result.applied_cursor, 8);
        assert!(store.pending_personal_objects(vault, 10).unwrap().is_empty());
        assert_eq!(peer.state.lock().unwrap().inventory.as_ref().unwrap().writes, 1);
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn atomic_conflicts_merge_concurrent_fields_and_retry_with_the_current_base() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    peer.prepare(&store).await;
    let original = make_host(&store);
    let mut remote = original.clone();
    remote
        .insert(
            FieldPath::Field(7),
            FieldEntry::new(
                Value::Text("other-device field".into()),
                Hlc::new(scoplen_model::system_time_millis().unwrap() + 5000, 0).unwrap(),
                store.device_id(),
            )
            .unwrap(),
        )
        .unwrap();
    let conflict = change(&store, &remote, 8);
    peer.state.lock().unwrap().inventory =
        Some(InventoryPeer { conflict_once: Some(conflict), ..InventoryPeer::default() });
    store
        .write(LocalWrite {
            id: Some(original.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("offline name".into()))],
        })
        .unwrap();
    let result = cycle(&peer, &store, vec![original.id]).await.unwrap();
    assert_eq!(result.uploaded, 1);
    assert_eq!(peer.state.lock().unwrap().inventory.as_ref().unwrap().writes, 2);
    let merged = store.get(original.id).unwrap().unwrap();
    assert_eq!(merged.required_text(1).unwrap(), "offline name");
    assert_eq!(merged.required_text(7).unwrap(), "other-device field");
    peer.assert_healthy();
}

#[tokio::test]
async fn cursor_expiry_ack_failure_clock_and_scope_boundaries_never_upload() {
    for mode in 0..5 {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        peer.prepare(&store).await;
        let object = make_host(&store);
        peer.state.lock().unwrap().inventory = Some(InventoryPeer {
            expire_cursor: mode == 0,
            snapshot_replies: if mode == 0 {
                [(1, Reply::cbor(vec![0xff]))].into_iter().collect()
            } else {
                BTreeMap::new()
            },
            reject_ack: mode == 1,
            date: match mode {
                2 => None,
                3 => Some(httpdate::fmt_http_date(
                    std::time::SystemTime::now() - Duration::from_secs(24 * 60 * 60 + 10),
                )),
                _ => InventoryPeer::default().date,
            },
            ..InventoryPeer::default()
        });
        if mode == 4 {
            peer.install_token(&store, |claims| claims.scope = "keys:read sync:read".into(), None);
        }
        let error = cycle(&peer, &store, vec![object.id]).await.unwrap_err();
        assert_eq!(
            error,
            match mode {
                0 => PersonalSyncError::InvalidResponse,
                1 => PersonalSyncError::AcknowledgementUnknown,
                4 => PersonalServerError::PermissionDenied.into(),
                _ => PersonalSyncError::Clock,
            }
        );
        assert_eq!(peer.state.lock().unwrap().inventory.as_ref().unwrap().writes, 0);
        let vault = record(&store).unwrap().personal_vault_id;
        if mode != 4 {
            assert_eq!(store.pending_personal_objects(vault, 10).unwrap().len(), 1);
            assert!(store.personal_adoption_backup(vault, object.id).unwrap().is_some());
        }
        if mode == 1 {
            assert_eq!(store.personal_sync_cursor(vault).unwrap(), 7);
            assert_eq!(store.personal_acknowledged_cursor(vault).unwrap(), 0);
            peer.state.lock().unwrap().inventory.as_mut().unwrap().reject_ack = false;
            let completed = cycle(&peer, &store, vec![]).await.unwrap();
            assert_eq!(completed.acknowledged_cursor, completed.applied_cursor);
            assert_eq!(completed.uploaded, 1);
        }
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn pagination_retains_future_objects_and_ack_maximum_cannot_skip_unapplied_sequences() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    peer.prepare(&store).await;
    let original = make_host(&store);
    let mut objects = BTreeMap::new();
    for seq in 8..28 {
        let mut object = original.clone();
        object.id = scoplen_model::new_uuid_v7().unwrap();
        objects.insert(object.id, change(&store, &object, seq));
    }
    let mut future =
        Object::new(scoplen_model::new_uuid_v7().unwrap(), ObjectType::from_wire(999).unwrap(), 23)
            .unwrap();
    future
        .insert(
            FieldPath::Field(44),
            FieldEntry::new(Value::Bytes(vec![1, 2, 3]), Hlc::at(1).unwrap(), store.device_id())
                .unwrap(),
        )
        .unwrap();
    objects.insert(future.id, change(&store, &future, 28));
    peer.state.lock().unwrap().inventory = Some(InventoryPeer {
        seq: 28,
        objects,
        ack_reported_cursor: Some(1000),
        ..InventoryPeer::default()
    });
    let result = cycle(&peer, &store, vec![]).await.unwrap();
    assert_eq!(result.applied_cursor, 28);
    assert_eq!(result.acknowledged_cursor, 28);
    assert_eq!(result.downloaded, 21);
    assert_eq!(result.uploaded, 0);
    assert_eq!(store.get(future.id).unwrap().unwrap(), future);
    let state = peer.state.lock().unwrap();
    let inventory = state.inventory.as_ref().unwrap();
    assert_eq!(inventory.queries, [0, 15, 23]);
    assert_eq!(inventory.acks, [15, 23, 28]);
    drop(state);
    peer.assert_healthy();
}

#[tokio::test]
async fn trust_records_require_verified_same_user_provenance_before_adoption_or_apply() {
    for mode in 0..5 {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        peer.prepare(&store).await;
        peer.state.lock().unwrap().inventory = Some(InventoryPeer::default());
        let identity = record(&store).unwrap();
        let mut fields = vec![
            (FieldPath::Field(2), Value::Text("*.example.test".into())),
            (FieldPath::Field(3), Value::Text("public key fixture".into())),
            (FieldPath::Field(4), Value::Text("fingerprint fixture".into())),
            (FieldPath::Field(5), Value::UInt(if mode == 3 { 3 } else { 1 })),
            (FieldPath::Field(6), Value::UInt(1)),
            (
                FieldPath::Field(7),
                Value::Bytes(
                    if mode == 2 {
                        scoplen_model::new_uuid_v7().unwrap()
                    } else {
                        store.device_id()
                    }
                    .as_bytes()
                    .to_vec(),
                ),
            ),
        ];
        if mode != 0 {
            fields.push((
                FieldPath::Field(8),
                Value::Bytes(
                    if mode == 1 {
                        scoplen_model::new_uuid_v7().unwrap()
                    } else {
                        identity.account_id
                    }
                    .as_bytes()
                    .to_vec(),
                ),
            ));
        }
        let trust = store
            .write(LocalWrite { id: None, object_type: ObjectType::TRUST_RECORD, fields })
            .unwrap();
        if mode == 4 {
            let result = cycle(&peer, &store, vec![trust.id]).await.unwrap();
            assert_eq!(result.uploaded, 1);
        } else {
            assert_eq!(
                cycle(&peer, &store, vec![trust.id]).await.unwrap_err(),
                PersonalSyncError::TrustReviewRequired
            );
            assert!(
                store
                    .personal_adoption_backup(identity.personal_vault_id, trust.id)
                    .unwrap()
                    .is_none()
            );
            let mut remote = trust.clone();
            remote.id = scoplen_model::new_uuid_v7().unwrap();
            let remote = change(&store, &remote, 8);
            peer.state.lock().unwrap().inventory = Some(InventoryPeer {
                seq: 8,
                objects: [(remote.object_id, remote.clone())].into_iter().collect(),
                ..InventoryPeer::default()
            });
            assert_eq!(
                cycle(&peer, &store, vec![]).await.unwrap_err(),
                PersonalSyncError::TrustReviewRequired
            );
            assert!(store.get(remote.object_id).unwrap().is_none());
            assert!(peer.state.lock().unwrap().inventory.as_ref().unwrap().acks.is_empty());
        }
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn unauthenticated_envelopes_and_misbound_metadata_never_apply_or_ack_any_page() {
    for mode in 0..5 {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let store = local(&dir);
        peer.prepare(&store).await;
        let mut object = make_host(&store);
        object.id = scoplen_model::new_uuid_v7().unwrap();
        let first = change(&store, &object, 8);
        object.id = scoplen_model::new_uuid_v7().unwrap();
        let mut invalid = change(&store, &object, 9);
        match mode {
            0 => {
                let mut envelope = ObjectEnvelope::decode(&invalid.payload).unwrap();
                envelope.signature[0] ^= 1;
                invalid.payload = envelope.encode().unwrap();
            }
            1 => {
                let mut envelope = ObjectEnvelope::decode(&invalid.payload).unwrap();
                envelope.key_epoch = 2;
                invalid.payload = envelope.encode().unwrap();
            }
            2 => invalid.signer_device_id = None,
            3 => invalid.signer_device_id = Some(scoplen_model::new_uuid_v7().unwrap()),
            _ => invalid.tombstone = true,
        }
        let first_id = first.object_id;
        peer.state.lock().unwrap().inventory = Some(InventoryPeer {
            seq: 9,
            objects: [(first.object_id, first), (invalid.object_id, invalid)].into_iter().collect(),
            ..InventoryPeer::default()
        });
        assert_eq!(
            cycle(&peer, &store, vec![]).await.unwrap_err(),
            PersonalSyncError::InvalidResponse
        );
        let vault = record(&store).unwrap().personal_vault_id;
        assert_eq!(store.personal_sync_cursor(vault).unwrap(), 0);
        assert_eq!(store.personal_acknowledged_cursor(vault).unwrap(), 0);
        assert!(store.get(first_id).unwrap().is_none());
        assert!(peer.state.lock().unwrap().inventory.as_ref().unwrap().acks.is_empty());
        peer.assert_healthy();
    }
}
