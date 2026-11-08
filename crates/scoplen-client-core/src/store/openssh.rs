// SPDX-License-Identifier: Apache-2.0

//! Local import identities commit together with the corresponding inventory changes.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::*;

pub(crate) struct ImportSnapshot {
    pub mappings: BTreeMap<String, Uuid>,
    pub objects: BTreeMap<Uuid, Object>,
    pub revision: String,
}

pub(crate) struct ImportWrite {
    pub key: String,
    pub file: String,
    pub object: NewObject,
    pub existing: bool,
    pub changed: bool,
    pub implicit: bool,
}

fn snapshot(
    conn: &Connection,
    source: &str,
    credentials: &[Uuid],
) -> Result<ImportSnapshot, StoreError> {
    let mut query = conn.prepare(
        "SELECT source_key,object_id FROM openssh_import_sources WHERE source=?1 ORDER BY source_key",
    )?;
    let rows = query.query_map(params![source], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut mappings = BTreeMap::new();
    let mut objects = BTreeMap::new();
    let mut digest = Sha256::new();
    for row in rows {
        let (key, bytes) = row?;
        let id = Uuid::from_slice(&bytes).map_err(|_| StoreError::InvalidIdentifier)?;
        digest.update((key.len() as u64).to_be_bytes());
        digest.update(key.as_bytes());
        digest.update(id.as_bytes());
        mappings.insert(key, id);
        if let Some(object) = read_object(conn, id)? {
            objects.insert(id, object);
        }
    }
    for id in credentials {
        if let Some(object) = read_object(conn, *id)? {
            objects.insert(*id, object);
        }
    }
    for (id, object) in &objects {
        digest.update(id.as_bytes());
        digest.update(object.encode()?);
    }
    Ok(ImportSnapshot { mappings, objects, revision: format!("{:x}", digest.finalize()) })
}

impl Store {
    pub(crate) fn openssh_import_snapshot(
        &self,
        source: &str,
        credentials: &[Uuid],
    ) -> Result<ImportSnapshot, StoreError> {
        snapshot(&self.conn(), source, credentials)
    }

    pub(crate) fn commit_openssh_import(
        &self,
        source: &str,
        credentials: &[Uuid],
        revision: &str,
        writes: Vec<ImportWrite>,
        removed_trust: Vec<Uuid>,
    ) -> Result<bool, StoreError> {
        let changes = {
            let mut conn = self.conn();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if snapshot(&tx, source, credentials)?.revision != revision {
                return Ok(false);
            }
            let mut objects = Vec::new();
            let now = scoplen_model::system_time_millis()? as i64;
            for write in writes {
                let id = write.object.id;
                let object_type = write.object.object_type;
                if write.changed {
                    let object = if write.existing {
                        apply_write(
                            &tx,
                            self.device_id,
                            LocalWrite { id: Some(id), object_type, fields: write.object.fields },
                        )?
                    } else {
                        apply_create(&tx, self.device_id, write.object)?
                    };
                    objects.push(object);
                }
                if write.implicit && !write.existing {
                    tx.execute(
                        "INSERT INTO implicit_objects(object_id,object_type,created_at) VALUES(?1,?2,?3)",
                        params![id.as_bytes().as_slice(), object_type.to_wire() as i64, now],
                    )?;
                }
                tx.execute(
                    "INSERT INTO openssh_import_sources(source,source_key,source_file,object_id) VALUES(?1,?2,?3,?4)
                     ON CONFLICT(source,source_key) DO UPDATE SET source_file=excluded.source_file,object_id=excluded.object_id",
                    params![source, write.key, write.file, id.as_bytes().as_slice()],
                )?;
            }
            for id in removed_trust {
                let object = read_object(&tx, id)?.ok_or(StoreError::NotFound(id))?;
                let mut deletion = object.clone();
                deletion.set_tombstone(Some(Tombstone::new(next_clock(&tx)?, self.device_id)?));
                let deleted = scoplen_model::merge(&object, &deletion)?;
                store_object(&tx, &deleted, None)?;
                objects.push(deleted);
            }
            tx.commit()?;
            grouped_changes(&objects)
        };
        for change in changes {
            self.notify(&change);
        }
        Ok(true)
    }
}
