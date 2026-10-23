// SPDX-License-Identifier: Apache-2.0
//! A complete authenticated snapshot replaces progress and inventory in one transaction.

use super::*;

const MAX_RECOVERY_BYTES: i64 = 32 * 1024 * 1024;
const MAX_RECOVERY_COPIES: i64 = super::super::MAX_OBJECTS_PER_VAULT as i64;

impl Store {
    pub(crate) fn reconcile_personal_snapshot(
        &self,
        vault: Uuid,
        expected: u64,
        next: u64,
        objects: &[RemoteObject],
    ) -> Result<(), StoreError> {
        let changes = {
            let mut conn = self.conn();
            conn.pragma_update(None, "synchronous", "FULL")?;
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            require_identity(&tx, vault)?;
            if cursor(&tx, vault)? != expected {
                return Err(StoreError::SyncChanged);
            }
            let acknowledged: Vec<u8> = tx.query_row(
                "SELECT acknowledged FROM personal_sync_progress WHERE vault = ?1",
                params![vault.as_bytes().as_slice()],
                |row| row.get(0),
            )?;
            let acknowledged = sequence(&acknowledged)?;
            let (mut recovery_count, mut recovery_bytes) = recovery_budget(&tx, vault)?;
            let mut seen = HashSet::new();
            for remote in objects {
                if remote.seq == 0 || remote.seq > next || !seen.insert(remote.object.id) {
                    return Err(StoreError::SyncChanged);
                }
                remote.object.validate()?;
            }
            let local = {
                let mut query = tx.prepare_cached(
                    "SELECT objects.id, personal_sync_objects.dirty, personal_sync_objects.base
                     FROM objects LEFT JOIN personal_sync_objects ON objects.id = object_id
                     WHERE objects.vault = ?1 ORDER BY objects.id",
                )?;
                query
                    .query_map(params![vault.as_bytes().as_slice()], |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, bool>(1)?,
                            row.get::<_, Option<Vec<u8>>>(2)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?
            };
            let mut changed = Vec::new();
            for (id, dirty, base) in local {
                let id = super::super::uuid_from(&id)?;
                if seen.contains(&id) {
                    continue;
                }
                let object = read_object(&tx, id)?.ok_or(StoreError::SyncChanged)?;
                // An unconfirmed acknowledgement cannot prove the object was unchanged
                // after our last confirmed position. Preserve that case conservatively.
                let unacknowledged = base
                    .as_deref()
                    .map(sequence)
                    .transpose()?
                    .is_none_or(|base| base > acknowledged);
                if dirty || unacknowledged {
                    let envelope = object.encode()?;
                    let bytes =
                        i64::try_from(envelope.len()).map_err(|_| StoreError::RecoveryLimit)?;
                    if recovery_count >= MAX_RECOVERY_COPIES
                        || bytes > MAX_RECOVERY_BYTES - recovery_bytes
                    {
                        return Err(StoreError::RecoveryLimit);
                    }
                    recovery_count += 1;
                    recovery_bytes += bytes;
                    tx.execute(
                        "INSERT INTO personal_sync_recovery(id,vault,object_id,envelope,recovered_at)
                         VALUES (?1,?2,?3,?4,?5)",
                        params![scoplen_model::new_uuid_v7()?.as_bytes().as_slice(), vault.as_bytes().as_slice(), id.as_bytes().as_slice(), envelope, scoplen_model::system_time_millis()? as i64],
                    )?;
                }
                tx.execute(
                    "DELETE FROM personal_sync_objects WHERE object_id = ?1",
                    params![id.as_bytes().as_slice()],
                )?;
                tx.execute(
                    "DELETE FROM implicit_objects WHERE object_id = ?1",
                    params![id.as_bytes().as_slice()],
                )?;
                tx.execute(
                    "DELETE FROM objects WHERE id = ?1 AND vault = ?2",
                    params![id.as_bytes().as_slice(), vault.as_bytes().as_slice()],
                )?;
                changed.push((object.object_type, id));
            }
            for remote in objects {
                let id = remote.object.id;
                let local = read_object(&tx, id)?;
                if local.is_some() && object_vault(&tx, id)? != Some(vault) {
                    return Err(StoreError::SyncSelection);
                }
                let merged = match &local {
                    Some(local) => scoplen_model::merge(local, &remote.object)?,
                    None => {
                        super::super::ensure_vault_capacity(&tx, Some(vault))?;
                        remote.object.clone()
                    }
                };
                observe_clock(&tx, &remote.object)?;
                store_object(&tx, &merged, Some(vault))?;
                tx.execute(
                    "INSERT INTO personal_sync_objects(object_id,vault,base,dirty) VALUES(?1,?2,?3,?4)
                     ON CONFLICT(object_id) DO UPDATE SET base=excluded.base,dirty=excluded.dirty",
                    params![id.as_bytes().as_slice(),vault.as_bytes().as_slice(),remote.seq.to_be_bytes().as_slice(),merged != remote.object],
                )?;
                if local.as_ref() != Some(&merged) {
                    changed.push((merged.object_type, id));
                }
            }
            // A restored server may legitimately have a sequence below the expired cursor.
            // Keep only acknowledgement evidence that still fits the completed snapshot.
            tx.execute(
                "UPDATE personal_sync_progress SET cursor=?2, acknowledged=?3 WHERE vault=?1",
                params![
                    vault.as_bytes().as_slice(),
                    next.to_be_bytes().as_slice(),
                    acknowledged.min(next).to_be_bytes().as_slice()
                ],
            )?;
            tx.commit()?;
            super::super::grouped_changes_from_pairs(changed)
        };
        for change in changes {
            self.notify(&change);
        }
        Ok(())
    }
}

fn recovery_budget(conn: &Connection, vault: Uuid) -> Result<(i64, i64), StoreError> {
    let (count, bytes): (i64, i64) = conn.query_row(
        "SELECT count(*),coalesce(sum(bytes),0) FROM (
            SELECT length(envelope) AS bytes FROM personal_sync_recovery WHERE vault=?1 LIMIT ?2
         )",
        params![vault.as_bytes().as_slice(), MAX_RECOVERY_COPIES + 1],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if count > MAX_RECOVERY_COPIES || bytes > MAX_RECOVERY_BYTES {
        return Err(StoreError::RecoveryLimit);
    }
    Ok((count, bytes))
}

pub(super) fn read_recovery_copies(
    conn: &Connection,
    vault: Uuid,
) -> Result<Vec<(Uuid, Object)>, StoreError> {
    recovery_budget(conn, vault)?;
    let mut query = conn.prepare_cached(
        "SELECT id,object_id,envelope FROM personal_sync_recovery WHERE vault=?1 ORDER BY id LIMIT ?2",
    )?;
    query
        .query_map(params![vault.as_bytes().as_slice(), MAX_RECOVERY_COPIES], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?))
        })?
        .map(|row| {
            let (id, original, envelope) = row?;
            Ok((super::super::uuid_from(&id)?, super::super::decode(&original, &envelope)?))
        })
        .collect()
}

pub(super) fn read_recovery_copy(
    conn: &Connection,
    vault: Uuid,
    id: Uuid,
) -> Result<Option<Object>, StoreError> {
    let row = conn
        .query_row(
            "SELECT object_id,envelope FROM personal_sync_recovery WHERE vault=?1 AND id=?2",
            params![vault.as_bytes().as_slice(), id.as_bytes().as_slice()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    row.map(|(original, envelope)| super::super::decode(&original, &envelope)).transpose()
}
