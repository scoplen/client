// SPDX-License-Identifier: Apache-2.0

//! The encrypted local store (`scoplen-docs/11-client-architecture.md` §2).
//!
//! One SQLCipher database per device, keyed by the local database key
//! (`05-cryptography-and-keys.md` §9). It holds replicated objects in their
//! merged form with per-field clocks, and the device's own records. Every
//! local write is merged with the stored object through `scoplen-model`, so
//! that a local edit and a later remote change combine by the same rules.

pub mod device;
mod migrations;
pub(crate) mod personal;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use scoplen_crypto::LocalDatabaseKey;
use scoplen_model::{
    FieldEntry, FieldPath, Hlc, MergeError, ModelError, Object, ObjectType, Tombstone, cbor,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use self::migrations::MIGRATIONS;

/// Objects per vault (`04-object-model.md` §7). The store enforces it because
/// it is a collection limit, which a single object cannot check (D-36).
pub const MAX_OBJECTS_PER_VAULT: u64 = 100_000;

/// A failure of the local store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The key does not open the database: it is the wrong key, or the file is
    /// not a Scoplen store.
    #[error("the local database key does not open this store")]
    WrongKey,
    /// The store was last written by a newer version of Scoplen.
    #[error(
        "the store has schema version {found}; this version of Scoplen supports up to {supported}"
    )]
    NewerSchema {
        /// The store's schema version.
        found: u32,
        /// The newest version this build knows.
        supported: u32,
    },
    /// Creating an object would exceed the objects-per-vault limit.
    #[error("a vault holds at most {MAX_OBJECTS_PER_VAULT} objects")]
    VaultFull,
    /// The object to change does not exist.
    #[error("object {0} does not exist")]
    NotFound(Uuid),
    /// A device-local session is still open and cannot be forgotten.
    #[error("session {0} is still active")]
    SessionActive(Uuid),
    /// A create operation supplied an identifier already in the store.
    #[error("object {0} already exists")]
    AlreadyExists(Uuid),
    /// An onboarding import raced with another host creation.
    #[error("the inventory already contains hosts")]
    InventoryNotEmpty,
    /// A stored object could not be decoded.
    #[error("stored object {id} is unreadable")]
    Corrupt {
        /// The object's identifier.
        id: Uuid,
        /// Why it could not be decoded.
        #[source]
        source: ModelError,
    },
    /// A stored identifier is not 16 bytes.
    #[error("the store holds a malformed identifier")]
    InvalidIdentifier,
    /// The object violates the object model.
    #[error(transparent)]
    Model(#[from] ModelError),
    /// The local and stored versions of an object cannot be merged.
    #[error(transparent)]
    Merge(#[from] MergeError),
    /// The device clock cannot produce a valid timestamp.
    #[error(transparent)]
    Clock(#[from] scoplen_model::clock::ClockError),
    /// The database failed.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

/// A local change to one object: the fields to set, all under one clock.
///
/// A map-entry path with a `null` value removes that entry
/// (`04-object-model.md` §4).
#[derive(Debug, Clone)]
pub struct LocalWrite {
    /// The object to change; `None` creates a new object.
    pub id: Option<Uuid>,
    /// The object's type.
    pub object_type: ObjectType,
    /// The fields to set.
    pub fields: Vec<(FieldPath, cbor::Value)>,
}

/// A new object to create as part of one atomic write.
///
/// The identifier is supplied by the caller so that related objects can refer
/// to one another before the transaction is committed. It must be a UUIDv7.
#[derive(Debug, Clone)]
pub struct NewObject {
    /// The identifier of the new object.
    pub id: Uuid,
    /// The object's type.
    pub object_type: ObjectType,
    /// The fields to set.
    pub fields: Vec<(FieldPath, cbor::Value)>,
}

/// Objects that changed in one committed write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The type of the changed objects.
    pub object_type: ObjectType,
    /// The changed objects.
    pub ids: Vec<Uuid>,
}

type Listener = Arc<dyn Fn(&Change) + Send + Sync>;

/// The local store. Cheap to share behind an `Arc`; calls are serialized.
pub struct Store {
    conn: Mutex<Connection>,
    data_dir: PathBuf,
    device_id: Uuid,
    listeners: Mutex<Vec<(u64, Listener)>>,
    next_listener: Mutex<u64>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("device_id", &self.device_id).finish_non_exhaustive()
    }
}

/// Removes its listener when dropped.
#[must_use = "the listener is removed when the subscription is dropped"]
pub struct Subscription {
    store: std::sync::Weak<Store>,
    id: u64,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(store) = self.store.upgrade() {
            store.listeners().retain(|(id, _)| *id != self.id);
        }
    }
}

impl Store {
    /// Opens the store at `path`, creating it if it does not exist, and runs
    /// any pending migrations. A new store is given a new device identity.
    pub fn open(path: &Path, key: &LocalDatabaseKey) -> Result<Store, StoreError> {
        let mut conn = Connection::open(path)?;
        apply_key(&conn, key)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        migrate(&mut conn)?;
        let device_id = ensure_device(&conn)?;
        Ok(Store {
            conn: Mutex::new(conn),
            data_dir: path.parent().unwrap_or_else(|| Path::new(".")).to_owned(),
            device_id,
            listeners: Mutex::new(Vec::new()),
            next_listener: Mutex::new(0),
        })
    }

    /// The identity of this device, used as the origin of its writes.
    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    /// Directory used to select this store's platform credential slots.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// The store's schema version.
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        Ok(self.conn().pragma_query_value(None, "user_version", |row| row.get(0))?)
    }

    /// Calls `listener` after every committed change, until the returned
    /// subscription is dropped.
    pub fn subscribe(
        self: &Arc<Self>,
        listener: impl Fn(&Change) + Send + Sync + 'static,
    ) -> Subscription {
        let mut next = self.next_listener.lock().unwrap_or_else(|e| e.into_inner());
        *next += 1;
        let id = *next;
        self.listeners().push((id, Arc::new(listener)));
        Subscription { store: Arc::downgrade(self), id }
    }

    /// Returns an object, including a deleted one, or `None`.
    pub fn get(&self, id: Uuid) -> Result<Option<Object>, StoreError> {
        let conn = self.conn();
        read_object(&conn, id)
    }

    /// Returns every object of a type that is not deleted, oldest first.
    pub fn list(&self, object_type: ObjectType) -> Result<Vec<Object>, StoreError> {
        let conn = self.conn();
        list_objects(&conn, object_type)
    }

    /// Returns the identifiers of every object that is not deleted, for
    /// resolving references (`04-object-model.md` §5 rule 6).
    pub fn live_ids(&self) -> Result<HashSet<Uuid>, StoreError> {
        let conn = self.conn();
        let mut statement = conn.prepare_cached("SELECT id FROM objects WHERE deleted = 0")?;
        let ids = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        ids.map(|id| uuid_from(&id?)).collect()
    }

    /// Applies a local change and returns the merged object.
    ///
    /// The change is stamped with the next device clock, merged with the
    /// stored object, validated against the object model, and committed.
    pub fn write(&self, write: LocalWrite) -> Result<Object, StoreError> {
        self.write_batch(vec![write]).map(|mut objects| objects.remove(0))
    }

    /// Applies several local changes in one transaction.
    ///
    /// Every object is validated before the transaction commits. Listeners are
    /// notified only after the commit, once per object type.
    pub fn write_batch(&self, writes: Vec<LocalWrite>) -> Result<Vec<Object>, StoreError> {
        if writes.is_empty() {
            return Ok(Vec::new());
        }
        let (objects, changes) = {
            let mut conn = self.conn();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut objects = Vec::with_capacity(writes.len());
            for write in writes {
                objects.push(apply_write(&tx, self.device_id, write)?);
            }
            tx.commit()?;
            let changes = grouped_changes(&objects);
            (objects, changes)
        };
        for change in changes {
            self.notify(&change);
        }
        Ok(objects)
    }

    /// Computes writes from a live snapshot under the same immediate transaction.
    /// The callback must not reenter this Store. Notifications follow commit.
    pub(crate) fn write_batch_with_snapshot<E>(
        &self,
        object_type: ObjectType,
        prepare: impl FnOnce(Vec<Object>) -> Result<Vec<LocalWrite>, E>,
    ) -> Result<Vec<Object>, E>
    where
        E: From<StoreError>,
    {
        let (objects, changes) = {
            let mut conn = self.conn();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(StoreError::from)?;
            let snapshot = list_objects(&tx, object_type)?;
            let writes = prepare(snapshot)?;
            let mut objects = Vec::with_capacity(writes.len());
            for write in writes {
                objects.push(apply_write(&tx, self.device_id, write)?);
            }
            tx.commit().map_err(StoreError::from)?;
            let changes = grouped_changes(&objects);
            (objects, changes)
        };
        for change in changes {
            self.notify(&change);
        }
        Ok(objects)
    }

    /// Applies one credential object change and optionally updates its
    /// device-local material in the same transaction. The local row is
    /// deliberately not part of the replicated envelope.
    pub(crate) fn write_with_device_credential(
        &self,
        write: LocalWrite,
        secret: Option<&[u8]>,
        remove_device_secret: bool,
    ) -> Result<Object, StoreError> {
        self.write_with_device_material(write, secret, None, remove_device_secret)
    }

    /// Applies a credential object change and stores an opaque platform
    /// keystore handle in the device-local table in the same transaction.
    pub(crate) fn write_with_device_keystore_handle(
        &self,
        write: LocalWrite,
        handle: &str,
    ) -> Result<Object, StoreError> {
        self.write_with_device_material(write, None, Some(handle), false)
    }

    /// Creates a credential object and stores its opaque platform keystore
    /// handle in the device-local table in one transaction.
    pub(crate) fn create_with_device_keystore_handle(
        &self,
        create: NewObject,
        handle: &str,
    ) -> Result<Object, StoreError> {
        debug_assert_eq!(create.object_type, ObjectType::CREDENTIAL);
        let (object, change) = {
            let mut conn = self.conn();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let object = apply_create(&tx, self.device_id, create)?;
            let updated_at = scoplen_model::system_time_millis()? as i64;
            tx.execute(
                "INSERT INTO device_credentials (credential, secret, keystore_handle, updated_at) VALUES (?1, NULL, ?2, ?3)",
                params![object.id.as_bytes().as_slice(), handle, updated_at],
            )?;
            tx.commit()?;
            (object.clone(), Change { object_type: object.object_type, ids: vec![object.id] })
        };
        self.notify(&change);
        Ok(object)
    }

    fn write_with_device_material(
        &self,
        write: LocalWrite,
        secret: Option<&[u8]>,
        handle: Option<&str>,
        remove_device_secret: bool,
    ) -> Result<Object, StoreError> {
        debug_assert_eq!(write.object_type, ObjectType::CREDENTIAL);
        let (object, change) = {
            let mut conn = self.conn();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let object = apply_write(&tx, self.device_id, write)?;
            if let Some(secret) = secret {
                let updated_at = scoplen_model::system_time_millis()? as i64;
                tx.execute(
                    "INSERT INTO device_credentials (credential, secret, keystore_handle, updated_at) VALUES (?1, ?2, NULL, ?3)
                     ON CONFLICT (credential) DO UPDATE SET secret = excluded.secret, keystore_handle = NULL, updated_at = excluded.updated_at",
                    params![object.id.as_bytes().as_slice(), secret, updated_at],
                )?;
            } else if let Some(handle) = handle {
                let updated_at = scoplen_model::system_time_millis()? as i64;
                tx.execute(
                    "INSERT INTO device_credentials (credential, secret, keystore_handle, updated_at) VALUES (?1, NULL, ?2, ?3)
                     ON CONFLICT (credential) DO UPDATE SET secret = NULL, keystore_handle = excluded.keystore_handle, updated_at = excluded.updated_at",
                    params![object.id.as_bytes().as_slice(), handle, updated_at],
                )?;
            } else if remove_device_secret {
                tx.execute(
                    "DELETE FROM device_credentials WHERE credential = ?1",
                    params![object.id.as_bytes().as_slice()],
                )?;
            }
            tx.commit()?;
            (object.clone(), Change { object_type: object.object_type, ids: vec![object.id] })
        };
        self.notify(&change);
        Ok(object)
    }

    /// Creates several related objects in one transaction.
    pub fn create_batch(&self, creates: Vec<NewObject>) -> Result<Vec<Object>, StoreError> {
        self.create_batch_with_implicit(creates, Vec::new())
    }

    /// Creates new objects and applies updates to existing objects in one
    /// transaction. This is used by inventory operations whose object
    /// identity must be referenced by a related existing record (for example
    /// selecting a newly created AccessProfile as a Host's default profile).
    /// Every object is validated before the transaction commits and listeners
    /// are notified only after the complete operation succeeds.
    pub fn create_and_write_batch(
        &self,
        creates: Vec<NewObject>,
        writes: Vec<LocalWrite>,
    ) -> Result<Vec<Object>, StoreError> {
        if creates.is_empty() && writes.is_empty() {
            return Ok(Vec::new());
        }
        let (objects, changes) = {
            let mut conn = self.conn();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut objects = Vec::with_capacity(creates.len() + writes.len());
            for create in creates {
                objects.push(apply_create(&tx, self.device_id, create)?);
            }
            for write in writes {
                objects.push(apply_write(&tx, self.device_id, write)?);
            }
            tx.commit()?;
            let changes = grouped_changes(&objects);
            (objects, changes)
        };
        for change in changes {
            self.notify(&change);
        }
        Ok(objects)
    }

    /// Creates several related objects and records the subset that starts as
    /// implicit in one transaction. The metadata is local to this device;
    /// object envelopes remain unchanged and therefore continue to sync.
    pub fn create_batch_with_implicit(
        &self,
        creates: Vec<NewObject>,
        implicit: Vec<(ObjectType, Uuid)>,
    ) -> Result<Vec<Object>, StoreError> {
        self.create_batch_with_implicit_and_promotions(creates, implicit, Vec::new())
    }

    /// Creates related objects, marks newly implicit objects, and promotes
    /// reused objects in one transaction.
    pub fn create_batch_with_implicit_and_promotions(
        &self,
        creates: Vec<NewObject>,
        implicit: Vec<(ObjectType, Uuid)>,
        promotions: Vec<(ObjectType, Uuid)>,
    ) -> Result<Vec<Object>, StoreError> {
        self.create_batch_with_implicit_and_promotions_inner(creates, implicit, promotions, false)
    }

    /// Creates an initial inventory only if no live Host exists at commit
    /// time. The empty-inventory check shares the creation transaction.
    pub fn create_initial_inventory_batch(
        &self,
        creates: Vec<NewObject>,
        implicit: Vec<(ObjectType, Uuid)>,
        promotions: Vec<(ObjectType, Uuid)>,
    ) -> Result<Vec<Object>, StoreError> {
        self.create_batch_with_implicit_and_promotions_inner(creates, implicit, promotions, true)
    }

    fn create_batch_with_implicit_and_promotions_inner(
        &self,
        creates: Vec<NewObject>,
        implicit: Vec<(ObjectType, Uuid)>,
        promotions: Vec<(ObjectType, Uuid)>,
        require_empty_hosts: bool,
    ) -> Result<Vec<Object>, StoreError> {
        if creates.is_empty() {
            return Ok(Vec::new());
        }
        let (objects, changes) = {
            let mut conn = self.conn();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if require_empty_hosts {
                let host_count: i64 = tx.query_row(
                    "SELECT count(*) FROM objects WHERE type = ?1 AND deleted = 0",
                    params![ObjectType::HOST.to_wire() as i64],
                    |row| row.get(0),
                )?;
                if host_count != 0 {
                    return Err(StoreError::InventoryNotEmpty);
                }
            }
            let mut objects = Vec::with_capacity(creates.len());
            for create in creates {
                objects.push(apply_create(&tx, self.device_id, create)?);
            }
            let now = scoplen_model::system_time_millis()?;
            for (_, id) in &implicit {
                if !objects.iter().any(|object| object.id == *id) {
                    return Err(StoreError::NotFound(*id));
                }
            }
            for (object_type, id) in implicit {
                let object = objects
                    .iter()
                    .find(|object| object.id == id)
                    .ok_or(StoreError::NotFound(id))?;
                if object.object_type != object_type {
                    return Err(StoreError::Merge(MergeError::TypeMismatch {
                        local: object.object_type,
                        remote: object_type,
                    }));
                }
                tx.execute(
                    "INSERT INTO implicit_objects (object_id, object_type, created_at) VALUES (?1, ?2, ?3)",
                    params![id.as_bytes().as_slice(), object_type.to_wire() as i64, now as i64],
                )?;
            }
            let mut promoted = Vec::new();
            for (object_type, id) in promotions {
                let object = match objects.iter().find(|object| object.id == id) {
                    Some(object) => Some(object.clone()),
                    None => read_object(&tx, id)?,
                }
                .ok_or(StoreError::NotFound(id))?;
                if object.object_type != object_type {
                    return Err(StoreError::Merge(MergeError::TypeMismatch {
                        local: object.object_type,
                        remote: object_type,
                    }));
                }
                if tx.execute(
                    "DELETE FROM implicit_objects WHERE object_id = ?1 AND object_type = ?2",
                    params![id.as_bytes().as_slice(), object_type.to_wire() as i64],
                )? > 0
                {
                    promoted.push((object_type, id));
                }
            }
            tx.commit()?;
            let changes = grouped_changes_from_pairs(
                objects.iter().map(|object| (object.object_type, object.id)).chain(promoted),
            );
            (objects, changes)
        };
        for change in changes {
            self.notify(&change);
        }
        Ok(objects)
    }

    /// Returns whether a live or tombstoned object is still implicit on this
    /// device. Unknown objects are explicit, which keeps objects created by
    /// older versions visible after the metadata migration.
    pub fn is_implicit(&self, id: Uuid) -> Result<bool, StoreError> {
        let conn = self.conn();
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM implicit_objects WHERE object_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(exists.is_some())
    }

    /// Promotes an implicit object to an explicit object. Promotion is
    /// idempotent and emits a local change so the interface refreshes areas.
    pub fn promote(&self, object_type: ObjectType, id: Uuid) -> Result<(), StoreError> {
        let changed = {
            let conn = self.conn();
            let changed = conn.execute(
                "DELETE FROM implicit_objects WHERE object_id = ?1 AND object_type = ?2",
                params![id.as_bytes().as_slice(), object_type.to_wire() as i64],
            )?;
            changed > 0
        };
        if changed {
            self.notify(&Change { object_type, ids: vec![id] });
        }
        Ok(())
    }

    /// Promotes several objects after one inspection. A single notification
    /// per type avoids redundant frontend reloads while retaining the normal
    /// `storeChanged` contract.
    pub fn promote_batch<I>(&self, objects: I) -> Result<(), StoreError>
    where
        I: IntoIterator<Item = (ObjectType, Uuid)>,
    {
        let objects = objects.into_iter().collect::<Vec<_>>();
        if objects.is_empty() {
            return Ok(());
        }
        let changed = {
            let mut conn = self.conn();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut changed = Vec::new();
            for (object_type, id) in objects {
                if tx.execute(
                    "DELETE FROM implicit_objects WHERE object_id = ?1 AND object_type = ?2",
                    params![id.as_bytes().as_slice(), object_type.to_wire() as i64],
                )? > 0
                {
                    changed.push((object_type, id));
                }
            }
            tx.commit()?;
            grouped_changes_from_pairs(changed)
        };
        for change in changed {
            self.notify(&change);
        }
        Ok(())
    }

    /// Returns the number of implicit objects of a type. This is used by
    /// inventory visibility rules without exposing local metadata to the UI.
    pub fn implicit_count(&self, object_type: ObjectType) -> Result<u64, StoreError> {
        let conn = self.conn();
        let count: i64 = conn.query_row(
            "SELECT count(*) FROM implicit_objects WHERE object_type = ?1",
            params![object_type.to_wire() as i64],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Deletes an object by giving it a tombstone. It can be restored from
    /// version history; the object stays in the store until sync purges it.
    pub fn delete(&self, id: Uuid) -> Result<(), StoreError> {
        self.delete_batch([id])?;
        Ok(())
    }

    /// Tombstones several objects in one transaction.
    pub fn delete_batch<I>(&self, ids: I) -> Result<(), StoreError>
    where
        I: IntoIterator<Item = Uuid>,
    {
        self.delete_batch_inner(ids.into_iter().collect(), false)
    }

    /// Tombstones objects and removes any device-local credential rows in the
    /// same transaction. This is used by host deletion, where unnamed
    /// credentials are removed along with their only login.
    pub(crate) fn delete_batch_with_device_credentials<I>(&self, ids: I) -> Result<(), StoreError>
    where
        I: IntoIterator<Item = Uuid>,
    {
        self.delete_batch_inner(ids.into_iter().collect(), true)
    }

    fn delete_batch_inner(
        &self,
        ids: Vec<Uuid>,
        remove_device_credentials: bool,
    ) -> Result<(), StoreError> {
        if ids.is_empty() {
            return Ok(());
        }
        let changes = {
            let mut conn = self.conn();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut changed = Vec::with_capacity(ids.len());
            for id in ids {
                let object = read_object(&tx, id)?.ok_or(StoreError::NotFound(id))?;
                let clock = next_clock(&tx)?;
                let mut deletion = object.clone();
                deletion.set_tombstone(Some(Tombstone::new(clock, self.device_id)?));
                let deleted = scoplen_model::merge(&object, &deletion)?;
                store_object(&tx, &deleted, None)?;
                if remove_device_credentials {
                    tx.execute(
                        "DELETE FROM device_credentials WHERE credential = ?1",
                        params![id.as_bytes().as_slice()],
                    )?;
                }
                changed.push((deleted.object_type, id));
            }
            tx.commit()?;
            grouped_changes_from_pairs(changed)
        };
        for change in changes {
            self.notify(&change);
        }
        Ok(())
    }

    /// Tombstones one object and removes any device-local credential material
    /// in the same transaction. This keeps deleting a credential from leaving
    /// a secret that could be read if the tombstone is later inspected.
    pub(crate) fn delete_with_device_credential(&self, id: Uuid) -> Result<(), StoreError> {
        let change = {
            let mut conn = self.conn();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let object = read_object(&tx, id)?.ok_or(StoreError::NotFound(id))?;
            let clock = next_clock(&tx)?;
            let mut deletion = object.clone();
            deletion.set_tombstone(Some(Tombstone::new(clock, self.device_id)?));
            let deleted = scoplen_model::merge(&object, &deletion)?;
            store_object(&tx, &deleted, None)?;
            tx.execute(
                "DELETE FROM device_credentials WHERE credential = ?1",
                params![id.as_bytes().as_slice()],
            )?;
            tx.commit()?;
            Change { object_type: deleted.object_type, ids: vec![id] }
        };
        self.notify(&change);
        Ok(())
    }

    /// Restores several tombstoned objects in one transaction.
    ///
    /// A fresh write to the first field makes the restoration a normal model
    /// merge, so it also propagates correctly when sync is enabled.
    pub fn restore_batch<I>(&self, ids: I) -> Result<(), StoreError>
    where
        I: IntoIterator<Item = Uuid>,
    {
        let ids = ids.into_iter().collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(());
        }
        let changes = {
            let mut conn = self.conn();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let mut changed = Vec::with_capacity(ids.len());
            for id in ids {
                let object = read_object(&tx, id)?.ok_or(StoreError::NotFound(id))?;
                if object.is_tombstoned() {
                    let (path, value) = object
                        .fields
                        .iter()
                        .next()
                        .map(|(path, entry)| (path.clone(), entry.value.clone()))
                        .ok_or(StoreError::NotFound(id))?;
                    let clock = next_clock(&tx)?;
                    let mut restoration = object.clone();
                    restoration.insert(path, FieldEntry::new(value, clock, self.device_id)?)?;
                    let restored = scoplen_model::merge(&object, &restoration)?;
                    store_object(&tx, &restored, None)?;
                    changed.push((restored.object_type, id));
                }
            }
            tx.commit()?;
            grouped_changes_from_pairs(changed)
        };
        for change in changes {
            self.notify(&change);
        }
        Ok(())
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn listeners(&self) -> MutexGuard<'_, Vec<(u64, Listener)>> {
        self.listeners.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn notify(&self, change: &Change) {
        let listeners: Vec<Listener> = self.listeners().iter().map(|(_, l)| l.clone()).collect();
        for listener in listeners {
            listener(change);
        }
    }
}

fn list_objects(conn: &Connection, object_type: ObjectType) -> Result<Vec<Object>, StoreError> {
    let mut statement = conn.prepare_cached(
        "SELECT id, envelope FROM objects WHERE type = ?1 AND deleted = 0 ORDER BY id",
    )?;
    let rows = statement.query_map(params![object_type.to_wire() as i64], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    rows.map(|row| {
        let (id, envelope) = row?;
        decode(&id, &envelope)
    })
    .collect()
}

fn apply_write(
    conn: &rusqlite::Transaction<'_>,
    device_id: Uuid,
    write: LocalWrite,
) -> Result<Object, StoreError> {
    let object_type = write.object_type;
    let existing = match write.id {
        Some(id) => Some(read_object(conn, id)?.ok_or(StoreError::NotFound(id))?),
        None => None,
    };
    let id = match write.id {
        Some(id) => id,
        None => scoplen_model::new_uuid_v7()?,
    };
    apply_fields(conn, device_id, existing, id, object_type, write.fields)
}

fn apply_create(
    conn: &rusqlite::Transaction<'_>,
    device_id: Uuid,
    create: NewObject,
) -> Result<Object, StoreError> {
    if read_object(conn, create.id)?.is_some() {
        return Err(StoreError::AlreadyExists(create.id));
    }
    apply_fields(conn, device_id, None, create.id, create.object_type, create.fields)
}

fn apply_fields(
    conn: &rusqlite::Transaction<'_>,
    device_id: Uuid,
    existing: Option<Object>,
    id: Uuid,
    object_type: ObjectType,
    fields: Vec<(FieldPath, cbor::Value)>,
) -> Result<Object, StoreError> {
    let clock = next_clock(conn)?;
    // The written version is the stored object with the new entries applied;
    // merging it with the stored version applies the model's merge rules.
    let mut written = match &existing {
        Some(stored) => stored.clone(),
        None => Object::new(id, object_type, scoplen_model::CURRENT_SCHEMA_VERSION)?,
    };
    if written.object_type != object_type {
        return Err(StoreError::Merge(MergeError::TypeMismatch {
            local: written.object_type,
            remote: object_type,
        }));
    }
    for (path, value) in fields {
        written.insert(path, FieldEntry::new(value, clock, device_id)?)?;
    }
    let merged = match &existing {
        Some(stored) => scoplen_model::merge(stored, &written)?,
        None => {
            written.validate()?;
            ensure_vault_capacity(conn, None)?;
            written
        }
    };
    store_object(conn, &merged, None)?;
    Ok(merged)
}

fn grouped_changes(objects: &[Object]) -> Vec<Change> {
    grouped_changes_from_pairs(objects.iter().map(|object| (object.object_type, object.id)))
}

fn grouped_changes_from_pairs<I>(pairs: I) -> Vec<Change>
where
    I: IntoIterator<Item = (ObjectType, Uuid)>,
{
    let mut changes: Vec<Change> = Vec::new();
    for (object_type, id) in pairs {
        if let Some(change) = changes.iter_mut().find(|change| change.object_type == object_type) {
            change.ids.push(id);
        } else {
            changes.push(Change { object_type, ids: vec![id] });
        }
    }
    changes
}

fn apply_key(conn: &Connection, key: &LocalDatabaseKey) -> Result<(), StoreError> {
    // A raw key, so SQLCipher does not run its own key derivation.
    let mut hex = Zeroizing::new(String::with_capacity(67));
    hex.push_str("x'");
    for byte in key.as_bytes() {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0xf), 16).unwrap_or('0'));
    }
    hex.push('\'');
    conn.pragma_update(None, "key", hex.as_str())?;
    // Reading the schema fails if the key does not decrypt the first page.
    match conn.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get::<_, i64>(0)) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(error, _))
            if error.code == rusqlite::ErrorCode::NotADatabase =>
        {
            Err(StoreError::WrongKey)
        }
        Err(error) => Err(error.into()),
    }
}

fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    let supported = MIGRATIONS.len() as u32;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Exclusive)?;
    let current: u32 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current > supported {
        return Err(StoreError::NewerSchema { found: current, supported });
    }
    for migration in &MIGRATIONS[current as usize..] {
        tx.execute_batch(migration)?;
    }
    if current < supported {
        tx.pragma_update(None, "user_version", supported)?;
    }
    tx.commit()?;
    Ok(())
}

fn ensure_device(conn: &Connection) -> Result<Uuid, StoreError> {
    let existing: Option<Vec<u8>> = conn
        .query_row("SELECT device_id FROM device WHERE singleton = 1", [], |row| row.get(0))
        .optional()?;
    if let Some(id) = existing {
        return uuid_from(&id);
    }
    let id = scoplen_model::new_uuid_v7()?;
    let now = scoplen_model::system_time_millis()?;
    conn.execute(
        "INSERT INTO device (singleton, device_id, clock, created_at) VALUES (1, ?1, 0, ?2)",
        params![id.as_bytes().as_slice(), now as i64],
    )?;
    Ok(id)
}

/// Advances and persists the device clock for one local write.
fn next_clock(conn: &Connection) -> Result<Hlc, StoreError> {
    let stored: i64 =
        conn.query_row("SELECT clock FROM device WHERE singleton = 1", [], |row| row.get(0))?;
    let previous = if stored == 0 { None } else { Some(Hlc::from_wire(stored as u64)?) };
    let clock = Hlc::tick(previous, scoplen_model::system_time_millis()?)?;
    conn.execute(
        "UPDATE device SET clock = ?1 WHERE singleton = 1",
        params![clock.to_wire() as i64],
    )?;
    Ok(clock)
}

fn ensure_vault_capacity(conn: &Connection, vault: Option<Uuid>) -> Result<(), StoreError> {
    let vault = vault.map(|v| v.as_bytes().to_vec());
    let count: i64 =
        conn.query_row("SELECT count(*) FROM objects WHERE vault IS ?1", params![vault], |row| {
            row.get(0)
        })?;
    if count as u64 >= MAX_OBJECTS_PER_VAULT { Err(StoreError::VaultFull) } else { Ok(()) }
}

fn store_object(conn: &Connection, object: &Object, vault: Option<Uuid>) -> Result<(), StoreError> {
    let envelope = object.encode()?;
    let now = scoplen_model::system_time_millis()?;
    conn.execute(
        "INSERT INTO objects (id, vault, type, envelope, deleted, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT (id) DO UPDATE SET envelope = excluded.envelope, deleted = excluded.deleted, updated_at = excluded.updated_at",
        params![
            object.id.as_bytes().as_slice(),
            vault.map(|v| v.as_bytes().to_vec()),
            object.object_type.to_wire() as i64,
            envelope,
            object.is_tombstoned(),
            now as i64
        ],
    )?;
    Ok(())
}

fn read_object(conn: &Connection, id: Uuid) -> Result<Option<Object>, StoreError> {
    let envelope: Option<Vec<u8>> = conn
        .prepare_cached("SELECT envelope FROM objects WHERE id = ?1")?
        .query_row(params![id.as_bytes().as_slice()], |row| row.get(0))
        .optional()?;
    envelope.map(|bytes| decode(id.as_bytes(), &bytes)).transpose()
}

fn decode(id: &[u8], envelope: &[u8]) -> Result<Object, StoreError> {
    let id = uuid_from(id)?;
    Object::decode(envelope).map_err(|source| StoreError::Corrupt { id, source })
}

fn uuid_from(bytes: &[u8]) -> Result<Uuid, StoreError> {
    Uuid::from_slice(bytes).map_err(|_| StoreError::InvalidIdentifier)
}

#[cfg(test)]
mod tests;
