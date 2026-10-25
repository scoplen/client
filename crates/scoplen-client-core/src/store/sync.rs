// SPDX-License-Identifier: Apache-2.0
//! Personal synchronization metadata and objects commit in the same SQLCipher transaction.

use std::collections::{BTreeMap, HashMap, HashSet};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use scoplen_api::sync::SyncWriteBatchResponse;
use scoplen_model::{FieldPath, Hlc, MapKey, Object, ObjectType, cbor::Value};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::{Store, StoreError, grouped_changes, read_object, store_object};

mod reconciliation;

pub(crate) struct PendingObject {
    pub object: Object,
    pub base: Option<u64>,
}

pub(crate) struct RemoteObject {
    pub object: Object,
    pub seq: u64,
}

pub(crate) struct InventorySnapshot {
    pub objects: Vec<(Object, bool, bool)>,
    pub backups: Vec<Object>,
    pub recovery: Vec<(Uuid, Object)>,
    pub pending: u32,
    pub applied: u64,
    pub acknowledged: u64,
}

impl Store {
    pub(crate) fn object_vault(&self, id: Uuid) -> Result<Option<Uuid>, StoreError> {
        object_vault(&self.conn(), id)
    }

    /// Adopt only the confirmed selection. New local objects remain local until selected.
    pub(crate) fn adopt_personal_objects(
        &self,
        vault: Uuid,
        selected: &[Uuid],
    ) -> Result<(), StoreError> {
        self.adopt_personal_objects_reviewed(vault, selected, None)
    }

    pub(crate) fn adopt_personal_objects_reviewed(
        &self,
        vault: Uuid,
        selected: &[Uuid],
        reviewed: Option<&HashMap<Uuid, [u8; 32]>>,
    ) -> Result<(), StoreError> {
        if selected.len() > super::MAX_OBJECTS_PER_VAULT as usize {
            return Err(StoreError::SyncSelection);
        }
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_identity(&tx, vault)?;
        tx.execute(
            "INSERT OR IGNORE INTO personal_sync_progress(vault, cursor, acknowledged) VALUES (?1, ?2, ?2)",
            params![vault.as_bytes().as_slice(), 0_u64.to_be_bytes().as_slice()],
        )?;
        let selection = selected.iter().copied().collect::<HashSet<_>>();
        if selection.len() != selected.len() {
            return Err(StoreError::SyncSelection);
        }
        let now = scoplen_model::system_time_millis()?;
        for id in selected {
            let object = read_object(&tx, *id)?.ok_or(StoreError::NotFound(*id))?;
            let current = object_vault(&tx, *id)?;
            if let Some(reviewed) = reviewed
                && (current.is_some()
                    || reviewed.get(id) != Some(&Sha256::digest(object.encode()?).into()))
            {
                return Err(StoreError::SyncSelection);
            }
            if current.is_some_and(|current| current != vault) {
                return Err(StoreError::SyncSelection);
            }
            // Existing unresolved references remain unresolved. Every referenced object that
            // does exist locally must be explicitly selected or already in this Personal vault.
            for reference in scoplen_model::references(&object) {
                if read_object(&tx, reference)?.is_some()
                    && !selection.contains(&reference)
                    && object_vault(&tx, reference)? != Some(vault)
                {
                    return Err(StoreError::SyncSelection);
                }
            }
            if current.is_none() {
                super::ensure_vault_capacity(&tx, Some(vault))?;
                tx.execute(
                    "INSERT INTO personal_sync_backups(object_id, vault, envelope, adopted_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        id.as_bytes().as_slice(),
                        vault.as_bytes().as_slice(),
                        object.encode()?,
                        now as i64
                    ],
                )?;
                tx.execute(
                    "UPDATE objects SET vault = ?2 WHERE id = ?1 AND vault IS NULL",
                    params![id.as_bytes().as_slice(), vault.as_bytes().as_slice()],
                )?;
                tx.execute(
                    "INSERT INTO personal_sync_objects(object_id, vault, base, dirty) VALUES (?1, ?2, NULL, 1)",
                    params![id.as_bytes().as_slice(), vault.as_bytes().as_slice()],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn personal_inventory_snapshot(
        &self,
        vault: Uuid,
    ) -> Result<InventorySnapshot, StoreError> {
        let conn = self.conn();
        let conn = conn.unchecked_transaction()?;
        let mut query = conn.prepare_cached(
            "SELECT objects.id, objects.envelope, objects.vault, coalesce(personal_sync_objects.dirty, 0)
             FROM objects LEFT JOIN personal_sync_objects ON objects.id = personal_sync_objects.object_id
             WHERE objects.vault IS NULL OR objects.vault = ?1 ORDER BY objects.id",
        )?;
        let rows = query.query_map(params![vault.as_bytes().as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, bool>(3)?,
            ))
        })?;
        let objects = rows
            .map(|row| {
                let (id, envelope, owner, dirty) = row?;
                Ok((super::decode(&id, &envelope)?, owner.is_some(), dirty))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let mut query = conn.prepare_cached("SELECT object_id, envelope FROM personal_sync_backups WHERE vault = ?1 ORDER BY object_id")?;
        let rows = query.query_map(params![vault.as_bytes().as_slice()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let backups = rows
            .map(|row| {
                let (id, envelope) = row?;
                super::decode(&id, &envelope)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let progress = conn
            .query_row(
                "SELECT cursor, acknowledged FROM personal_sync_progress WHERE vault = ?1",
                params![vault.as_bytes().as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let (applied, acknowledged) = match progress {
            Some((applied, acknowledged)) => (sequence(&applied)?, sequence(&acknowledged)?),
            None => (0, 0),
        };
        Ok(InventorySnapshot {
            pending: objects.iter().filter(|(_, _, dirty)| *dirty).count() as u32,
            objects,
            backups,
            recovery: reconciliation::read_recovery_copies(&conn, vault)?,
            applied,
            acknowledged,
        })
    }

    #[cfg(test)]
    pub(crate) fn personal_adoption_backup(
        &self,
        vault: Uuid,
        id: Uuid,
    ) -> Result<Option<Object>, StoreError> {
        let conn = self.conn();
        require_identity(&conn, vault)?;
        read_adoption_backup(&conn, vault, id)
    }

    pub(crate) fn personal_sync_cursor(&self, vault: Uuid) -> Result<u64, StoreError> {
        cursor(&self.conn(), vault)
    }

    pub(crate) fn personal_acknowledged_cursor(&self, vault: Uuid) -> Result<u64, StoreError> {
        let conn = self.conn();
        require_identity(&conn, vault)?;
        let bytes: Vec<u8> = conn.query_row(
            "SELECT acknowledged FROM personal_sync_progress WHERE vault = ?1",
            params![vault.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        sequence(&bytes)
    }

    /// Save only the requested, applied cursor after a validated acknowledgement. A server's
    /// larger stored maximum never becomes authority to skip unapplied changes.
    pub(crate) fn save_personal_acknowledgement(
        &self,
        vault: Uuid,
        requested: u64,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if cursor(&tx, vault)? < requested {
            return Err(StoreError::SyncChanged);
        }
        tx.execute(
            "UPDATE personal_sync_progress SET acknowledged = max(acknowledged, ?2) WHERE vault = ?1",
            params![vault.as_bytes().as_slice(), requested.to_be_bytes().as_slice()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Restore selected adoption snapshots as fresh local objects. Remap only known K-1
    /// object references; secret bytes, device ids, and unknown fields are never rewritten.
    pub(crate) fn restore_personal_adoption(
        &self,
        vault: Uuid,
        selected: &[Uuid],
    ) -> Result<Vec<(Uuid, Uuid)>, StoreError> {
        self.restore_personal_copies(vault, selected, false)
    }

    pub(crate) fn restore_personal_recovery(
        &self,
        vault: Uuid,
        selected: &[Uuid],
    ) -> Result<Vec<(Uuid, Uuid)>, StoreError> {
        self.restore_personal_copies(vault, selected, true)
    }

    pub(crate) fn personal_history_object(
        &self,
        vault: Uuid,
        id: Uuid,
    ) -> Result<Object, StoreError> {
        let conn = self.conn();
        require_identity(&conn, vault)?;
        if object_vault(&conn, id)? != Some(vault) {
            return Err(StoreError::SyncSelection);
        }
        read_object(&conn, id)?.ok_or(StoreError::NotFound(id))
    }

    pub(crate) fn restore_personal_history(
        &self,
        account: Uuid,
        vault: Uuid,
        source: Object,
    ) -> Result<(), StoreError> {
        let changes = {
            let mut conn = self.conn();
            conn.pragma_update(None, "synchronous", "FULL")?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            require_identity(&tx, vault)?;
            let matches: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM personal_server WHERE account_id=?1 AND personal_vault_id=?2)",
                params![account.as_bytes().as_slice(), vault.as_bytes().as_slice()],
                |row| row.get(0),
            )?;
            if !matches || object_vault(&tx, source.id)? != Some(vault) {
                return Err(StoreError::SyncSelection);
            }
            let (_, changes) = insert_restored_objects(&tx, self.device_id, vec![source])?;
            tx.commit()?;
            changes
        };
        for change in changes {
            self.notify(&change);
        }
        Ok(())
    }

    fn restore_personal_copies(
        &self,
        vault: Uuid,
        selected: &[Uuid],
        recovery: bool,
    ) -> Result<Vec<(Uuid, Uuid)>, StoreError> {
        if selected.len() > super::MAX_OBJECTS_PER_VAULT as usize {
            return Err(StoreError::SyncSelection);
        }
        if selected.iter().collect::<HashSet<_>>().len() != selected.len() {
            return Err(StoreError::SyncSelection);
        }
        let ids;
        let changes = {
            let mut conn = self.conn();
            conn.pragma_update(None, "synchronous", "FULL")?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            require_identity(&tx, vault)?;
            let originals = selected
                .iter()
                .map(|id| {
                    let original = if recovery {
                        reconciliation::read_recovery_copy(&tx, vault, *id)?
                    } else {
                        read_adoption_backup(&tx, vault, *id)?
                    };
                    original.ok_or(StoreError::NotFound(*id))
                })
                .collect::<Result<Vec<_>, StoreError>>()?;
            let (restored, changes) = insert_restored_objects(&tx, self.device_id, originals)?;
            ids = restored;
            tx.commit()?;
            changes
        };
        for change in changes {
            self.notify(&change);
        }
        Ok(ids.into_iter().collect())
    }

    pub(crate) fn pending_personal_objects(
        &self,
        vault: Uuid,
        limit: usize,
    ) -> Result<Vec<PendingObject>, StoreError> {
        let conn = self.conn();
        require_identity(&conn, vault)?;
        let mut query = conn.prepare_cached(
            "SELECT objects.id, objects.envelope, personal_sync_objects.base
             FROM personal_sync_objects JOIN objects ON objects.id = object_id
             WHERE personal_sync_objects.vault = ?1 AND dirty = 1 ORDER BY object_id LIMIT ?2",
        )?;
        let rows = query.query_map(params![vault.as_bytes().as_slice(), limit as i64], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?;
        rows.map(|row| {
            let (id, envelope, base) = row?;
            Ok(PendingObject {
                object: super::decode(&id, &envelope)?,
                base: base.as_deref().map(sequence).transpose()?,
            })
        })
        .collect()
    }

    /// Only the applied page moves the cursor. Server write assignments never move it.
    pub(crate) fn apply_personal_page(
        &self,
        vault: Uuid,
        expected: u64,
        next: u64,
        objects: &[RemoteObject],
    ) -> Result<(), StoreError> {
        if next < expected {
            return Err(StoreError::SyncChanged);
        }
        self.merge_personal(vault, Some((expected, next)), objects)
    }

    pub(crate) fn merge_personal_conflicts(
        &self,
        vault: Uuid,
        objects: &[RemoteObject],
    ) -> Result<(), StoreError> {
        self.merge_personal(vault, None, objects)
    }

    fn merge_personal(
        &self,
        vault: Uuid,
        progress: Option<(u64, u64)>,
        objects: &[RemoteObject],
    ) -> Result<(), StoreError> {
        let changes = {
            let mut conn = self.conn();
            conn.pragma_update(None, "synchronous", "FULL")?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            require_identity(&tx, vault)?;
            if let Some((expected, _)) = progress
                && cursor(&tx, vault)? != expected
            {
                return Err(StoreError::SyncChanged);
            }
            let mut changed = Vec::new();
            let mut seen = HashSet::new();
            for remote in objects {
                if !seen.insert(remote.object.id) || remote.seq == 0 {
                    return Err(StoreError::SyncChanged);
                }
                let id = remote.object.id;
                let local = read_object(&tx, id)?;
                if local.is_some() && object_vault(&tx, id)? != Some(vault) {
                    return Err(StoreError::SyncSelection);
                }
                let base = object_base(&tx, id)?;
                if base.is_some_and(|base| base >= remote.seq) {
                    continue;
                }
                remote.object.validate()?;
                let merged = match &local {
                    Some(local) => scoplen_model::merge(local, &remote.object)?,
                    None => {
                        super::ensure_vault_capacity(&tx, Some(vault))?;
                        remote.object.clone()
                    }
                };
                observe_clock(&tx, &remote.object)?;
                store_object(&tx, &merged, Some(vault))?;
                tx.execute(
                    "INSERT INTO personal_sync_objects(object_id, vault, base, dirty) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(object_id) DO UPDATE SET base = excluded.base, dirty = excluded.dirty",
                    params![id.as_bytes().as_slice(), vault.as_bytes().as_slice(), remote.seq.to_be_bytes().as_slice(), merged != remote.object],
                )?;
                if local.as_ref() != Some(&merged) {
                    changed.push(merged);
                }
            }
            if let Some((_, next)) = progress {
                tx.execute(
                    "UPDATE personal_sync_progress SET cursor = ?2 WHERE vault = ?1",
                    params![vault.as_bytes().as_slice(), next.to_be_bytes().as_slice()],
                )?;
            }
            tx.commit()?;
            grouped_changes(&changed)
        };
        for change in changes {
            self.notify(&change);
        }
        Ok(())
    }

    pub(crate) fn settle_personal_write(
        &self,
        vault: Uuid,
        submitted: &[PendingObject],
        response: &SyncWriteBatchResponse,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_identity(&tx, vault)?;
        if submitted.len() != response.assignments.len() {
            return Err(StoreError::SyncChanged);
        }
        for (sent, assignment) in submitted.iter().zip(&response.assignments) {
            if sent.object.id != assignment.object_id
                || assignment.seq == 0
                || object_vault(&tx, sent.object.id)? != Some(vault)
            {
                return Err(StoreError::SyncChanged);
            }
            if object_base(&tx, sent.object.id)?.is_some_and(|base| base >= assignment.seq) {
                continue;
            }
            let current = read_object(&tx, sent.object.id)?.ok_or(StoreError::SyncChanged)?;
            tx.execute(
                "UPDATE personal_sync_objects SET base = ?2, dirty = ?3 WHERE object_id = ?1 AND vault = ?4",
                params![sent.object.id.as_bytes().as_slice(), assignment.seq.to_be_bytes().as_slice(), current != sent.object, vault.as_bytes().as_slice()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

fn insert_restored_objects(
    tx: &Connection,
    device: Uuid,
    originals: Vec<Object>,
) -> Result<(BTreeMap<Uuid, Uuid>, Vec<super::Change>), StoreError> {
    let mut ids = BTreeMap::new();
    for object in &originals {
        if ids.insert(object.id, scoplen_model::new_uuid_v7()?).is_some() {
            return Err(StoreError::SyncSelection);
        }
    }
    let mut changed = Vec::with_capacity(originals.len());
    for mut object in originals {
        object.id = ids[&object.id];
        object.tombstone = None;
        let clock = super::next_clock(tx)?;
        let mut fields = BTreeMap::new();
        for (mut path, mut entry) in std::mem::take(&mut object.fields) {
            remap_reference(object.object_type, &mut path, &mut entry.value, &ids);
            entry.clock = clock;
            entry.origin = device;
            fields.insert(path, entry);
        }
        object.fields = fields;
        object.validate()?;
        super::ensure_vault_capacity(tx, None)?;
        store_object(tx, &object, None)?;
        changed.push((object.object_type, object.id));
    }
    Ok((ids, super::grouped_changes_from_pairs(changed)))
}

fn read_adoption_backup(
    conn: &Connection,
    vault: Uuid,
    id: Uuid,
) -> Result<Option<Object>, StoreError> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT envelope FROM personal_sync_backups WHERE vault = ?1 AND object_id = ?2",
            params![vault.as_bytes().as_slice(), id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    bytes.map(|bytes| super::decode(id.as_bytes(), &bytes)).transpose()
}

fn cursor(conn: &Connection, vault: Uuid) -> Result<u64, StoreError> {
    require_identity(conn, vault)?;
    let bytes: Vec<u8> = conn.query_row(
        "SELECT cursor FROM personal_sync_progress WHERE vault = ?1",
        params![vault.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    sequence(&bytes)
}

fn object_vault(conn: &Connection, id: Uuid) -> Result<Option<Uuid>, StoreError> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT vault FROM objects WHERE id = ?1",
            params![id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    bytes.as_deref().map(super::uuid_from).transpose()
}

fn object_base(conn: &Connection, id: Uuid) -> Result<Option<u64>, StoreError> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT base FROM personal_sync_objects WHERE object_id = ?1",
            params![id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    bytes.as_deref().map(sequence).transpose()
}

fn require_identity(conn: &Connection, vault: Uuid) -> Result<(), StoreError> {
    let matches: bool = conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM personal_server p JOIN personal_admission a
            ON a.singleton=p.singleton AND a.origin=p.origin AND a.account_id=p.account_id
                AND a.personal_vault_id=p.personal_vault_id
            WHERE p.personal_vault_id = ?1)
         AND EXISTS (SELECT 1 FROM personal_sync)",
        params![vault.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if matches { Ok(()) } else { Err(StoreError::SyncChanged) }
}

fn sequence(bytes: &[u8]) -> Result<u64, StoreError> {
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| StoreError::SyncChanged)?))
}

fn observe_clock(conn: &Connection, object: &Object) -> Result<(), StoreError> {
    let remote = object
        .fields
        .values()
        .map(|entry| entry.clock)
        .chain(object.tombstone.map(|entry| entry.clock))
        .max();
    if let Some(remote) = remote {
        let previous: i64 =
            conn.query_row("SELECT clock FROM device WHERE singleton = 1", [], |row| row.get(0))?;
        let previous = if previous == 0 { None } else { Some(Hlc::from_wire(previous as u64)?) };
        let next = Hlc::observe(previous, remote, scoplen_model::system_time_millis()?)?;
        conn.execute(
            "UPDATE device SET clock = ?1 WHERE singleton = 1",
            params![next.to_wire() as i64],
        )?;
    }
    Ok(())
}

fn remap_reference(
    kind: ObjectType,
    path: &mut FieldPath,
    value: &mut Value,
    ids: &BTreeMap<Uuid, Uuid>,
) {
    let field = path.field_number();
    let scalar = match kind {
        ObjectType::HOST => field == 8,
        ObjectType::ACCESS_PROFILE => matches!(field, 1 | 4 | 5),
        ObjectType::ROUTE => matches!(field, 5 | 7),
        ObjectType::HOST_GROUP => field == 2,
        ObjectType::TRUST_RECORD => field == 1,
        ObjectType::FORWARD => field == 7,
        _ => false,
    };
    if scalar && matches!(path, FieldPath::Field(_)) {
        remap_value(value, ids);
    } else if (kind == ObjectType::HOST && field == 5)
        || (kind == ObjectType::ACCESS_PROFILE && field == 8)
    {
        if let FieldPath::MapEntry { key: MapKey::Bytes(bytes), .. } = path {
            remap_bytes(bytes, ids);
        }
    } else if kind == ObjectType::ROUTE && field == 3 {
        if let Value::Array(hops) = value {
            for hop in hops {
                remap_value(hop, ids);
            }
        }
    } else if kind == ObjectType::WORKSPACE
        && field == 3
        && let Value::Map(spec) = value
    {
        for (key, value) in spec {
            if matches!(key, Value::UInt(1 | 3)) {
                remap_value(value, ids);
            }
        }
    }
}

fn remap_value(value: &mut Value, ids: &BTreeMap<Uuid, Uuid>) {
    if let Value::Bytes(bytes) = value {
        remap_bytes(bytes, ids);
    }
}

fn remap_bytes(bytes: &mut Vec<u8>, ids: &BTreeMap<Uuid, Uuid>) {
    if let Ok(id) = Uuid::from_slice(bytes)
        && let Some(replacement) = ids.get(&id)
    {
        *bytes = replacement.as_bytes().to_vec();
    }
}

#[cfg(test)]
mod tests;
