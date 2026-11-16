// SPDX-License-Identifier: Apache-2.0
//! Streaming archive staging and destination-bound receipts in one SQLCipher transaction.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};

use scoplen_crypto::{PortableExportPassphrase, PortableExportReader, PortableExportWriter};
use scoplen_model::portable::{self, Entry, Header, SecretMode, SourceKind};
use scoplen_model::{FieldEntry, FieldPath, Hlc, MapKey, Object, ObjectType, cbor::Value};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use super::{Connection, OptionalExtension as _, Store, TransactionBehavior, Uuid, params};
use crate::portable_archive::{
    ArchiveDestination, ArchiveSecretMode, ExportOptions, ExportResult, ImportAction,
    ImportConsent, ImportEntryPreview, ImportPreview, ImportProblem, ImportResult,
    ImportTrustPreview, PortableArchiveError as Error,
};

struct Context {
    key: Vec<u8>,
    vault: Option<Uuid>,
    account: Option<Uuid>,
    destination: ArchiveDestination,
    generation: Vec<u8>,
}

struct PersonalContext {
    origin: String,
    account: Vec<u8>,
    vault: Vec<u8>,
    auth: i64,
    sync: Option<i64>,
}

struct Staged {
    entry: Entry,
    target: Uuid,
    existing: bool,
}

struct Prepared {
    fields: BTreeMap<FieldPath, Value>,
    existing: Option<Object>,
    preview: ImportEntryPreview,
}

impl Drop for Prepared {
    fn drop(&mut self) {
        wipe_fields(&mut self.fields);
        if let Some(object) = &mut self.existing {
            for field in object.fields.values_mut() {
                wipe(&mut field.value);
            }
        }
    }
}

impl Store {
    pub(crate) fn portable_export(
        &self,
        writer: impl Write,
        options: ExportOptions,
        passphrase: Option<&PortableExportPassphrase>,
    ) -> Result<ExportResult, Error> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred).map_err(storage)?;
        let context = context(&tx, self.device_id)?;
        let secrets = secret_mode(options.secrets);
        let header = Header {
            exported_at: scoplen_model::system_time_millis().map_err(|_| Error::Storage)?,
            source_kind: SourceKind::Device,
            source_id: self.device_id,
            secrets,
        };
        let mut query = tx
            .prepare("SELECT id,envelope FROM objects WHERE vault IS ?1 AND deleted=0 ORDER BY id")
            .map_err(storage)?;
        let mut rows = query
            .query(params![context.vault.map(|id| id.as_bytes().to_vec())])
            .map_err(storage)?;
        let entries = std::iter::from_fn(|| match rows.next() {
            Ok(Some(row)) => Some((|| {
                let id: Vec<u8> = row.get(0).map_err(|_| portable::Error::Consumer)?;
                let bytes = Zeroizing::new(
                    row.get::<_, Vec<u8>>(1).map_err(|_| portable::Error::Consumer)?,
                );
                let mut object =
                    super::decode(&id, &bytes).map_err(|_| portable::Error::Consumer)?;
                let entry = Entry::from_object(&object, secrets)
                    .and_then(|entry| entry.ok_or(portable::Error::Value));
                for field in object.fields.values_mut() {
                    wipe(&mut field.value);
                }
                entry
            })()),
            Ok(None) => None,
            Err(_) => Some(Err(portable::Error::Consumer)),
        });
        let count = if options.secrets == ArchiveSecretMode::Included {
            let passphrase = passphrase.ok_or(Error::PassphraseRequired)?;
            let mut writer =
                PortableExportWriter::new(writer, passphrase).map_err(|_| Error::Encryption)?;
            let count = portable::write_archive(&mut writer, &header, entries).map_err(model)?;
            writer.finish().map_err(|_| Error::Encryption)?;
            count
        } else {
            portable::write_archive(writer, &header, entries).map_err(model)?
        };
        Ok(ExportResult {
            destination: context.destination,
            objects: count as u32,
            secrets: options.secrets,
        })
    }

    pub(crate) fn portable_preview(
        &self,
        reader: impl Read,
        passphrase: Option<&PortableExportPassphrase>,
    ) -> Result<ImportPreview, Error> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
        let context = context(&tx, self.device_id)?;
        let destination_revision = revision(&tx, &context)?;
        let source_revision = stage(&tx, &context, reader, passphrase)?;
        let mut entries = Vec::new();
        each_staged(&tx, |staged| {
            let retain = staged.entry.object_type() == ObjectType::CREDENTIAL;
            let prepared = prepare(&tx, &context, &staged, self.device_id, retain)?;
            entries.push(prepared.preview.clone());
            Ok(())
        })?;
        let can_import = entries.iter().all(|entry| entry.problem.is_none());
        Ok(ImportPreview {
            id: scoplen_model::new_uuid_v7().map_err(|_| Error::Storage)?.to_string(),
            source_revision,
            destination_revision,
            destination: context.destination,
            entries,
            can_import,
        })
        // No preview payload or receipt is retained in the database.
    }

    pub(crate) fn portable_import(
        &self,
        reader: impl Read,
        passphrase: Option<&PortableExportPassphrase>,
        preview: &ImportPreview,
        consent: &ImportConsent,
    ) -> Result<ImportResult, Error> {
        if !preview.can_import {
            return Err(Error::Blocked);
        }
        let (retain, trust) = choices(preview, consent)?;
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL").map_err(storage)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
        let context = context(&tx, self.device_id)?;
        if context.destination != preview.destination {
            return Err(Error::ContextChanged);
        }
        if revision(&tx, &context)? != preview.destination_revision {
            return Err(Error::DestinationChanged);
        }
        let source_revision = stage(&tx, &context, reader, passphrase)?;
        if source_revision != preview.source_revision {
            return Err(Error::SourceChanged);
        }
        if let Some(vault) = context.vault {
            tx.execute(
                "INSERT OR IGNORE INTO personal_sync_progress(vault,cursor,acknowledged) VALUES(?1,?2,?2)",
                params![vault.as_bytes().as_slice(),0_u64.to_be_bytes().as_slice()],
            ).map_err(storage)?;
        }
        // The immediate transaction and the native profile-use guard hold the reviewed owner
        // and target state through authentication, all object writes, and final commit.
        let mut result = ImportResult::default();
        let mut changes = Vec::new();
        each_staged(&tx, |staged| {
            let retaining = retain.contains(&staged.entry.id());
            let mut prepared = prepare(&tx, &context, &staged, self.device_id, retaining)?;
            if prepared.preview.problem.is_some() {
                return Err(Error::Blocked);
            }
            if prepared.preview.trust.as_ref().is_some_and(|key| key.requires_consent)
                && !trust.contains(&staged.entry.id())
            {
                return Err(Error::ConsentRequired);
            }
            if prepared.preview.action == ImportAction::Unchanged {
                result.unchanged += 1;
                return Ok(());
            }
            let clock = replacement_clock(&tx, prepared.existing.as_ref())?;
            let mut object = match &prepared.existing {
                Some(object) => object.clone(),
                None => {
                    super::ensure_vault_capacity(&tx, context.vault).map_err(storage)?;
                    Object::new(staged.target, staged.entry.object_type(), 1)
                        .map_err(|_| Error::InvalidArchive)?
                }
            };
            for path in object.fields.keys() {
                prepared.fields.entry(path.clone()).or_insert(Value::Null);
            }
            for (path, value) in &prepared.fields {
                object
                    .insert(
                        path.clone(),
                        FieldEntry::new(value.clone(), clock, self.device_id)
                            .map_err(|_| Error::InvalidArchive)?,
                    )
                    .map_err(|_| Error::InvalidArchive)?;
            }
            object.validate().map_err(|_| Error::InvalidArchive)?;
            super::store_object(&tx, &object, context.vault).map_err(storage)?;
            for field in object.fields.values_mut() {
                wipe(&mut field.value);
            }
            if let Some(vault) = context.vault {
                tx.execute(
                    "INSERT INTO personal_sync_objects(object_id,vault,base,dirty) VALUES(?1,?2,NULL,1)
                     ON CONFLICT(object_id) DO UPDATE SET dirty=1 WHERE vault=excluded.vault",
                    params![staged.target.as_bytes().as_slice(), vault.as_bytes().as_slice()],
                ).map_err(storage)?;
            }
            tx.execute(
                "INSERT INTO portable_import_receipts(context,source_id,object_id,object_type) VALUES(?1,?2,?3,?4)
                 ON CONFLICT(context,source_id) DO NOTHING",
                params![context.key,staged.entry.id().as_bytes().as_slice(),staged.target.as_bytes().as_slice(),staged.entry.object_type().to_wire() as i64],
            ).map_err(storage)?;
            changes.push((staged.entry.object_type(), staged.target));
            if staged.existing {
                result.updated += 1;
            } else {
                result.created += 1;
            }
            Ok(())
        })?;
        tx.execute("DELETE FROM portable_import_stage", []).map_err(storage)?;
        tx.execute("DELETE FROM portable_import_preferences", []).map_err(storage)?;
        tx.commit().map_err(storage)?;
        drop(conn);
        for change in super::grouped_changes_from_pairs(changes) {
            self.notify(&change);
        }
        if context.vault.is_some() {
            self.personal_changed();
        }
        Ok(result)
    }
}

fn context(conn: &Connection, device: Uuid) -> Result<Context, Error> {
    let personal: Option<PersonalContext> = conn
        .query_row(
            "SELECT p.origin,p.account_id,p.personal_vault_id,p.auth_generation,s.generation
         FROM personal_server p LEFT JOIN personal_sync s ON s.singleton=p.singleton
         WHERE EXISTS(SELECT 1 FROM personal_admission a WHERE a.origin=p.origin
             AND a.account_id=p.account_id AND a.personal_vault_id=p.personal_vault_id)",
            [],
            |row| {
                Ok(PersonalContext {
                    origin: row.get(0)?,
                    account: row.get(1)?,
                    vault: row.get(2)?,
                    auth: row.get(3)?,
                    sync: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(storage)?;
    if let Some(PersonalContext { origin, account, vault, auth, sync }) = personal {
        let account = id(&account)?;
        let vault = id(&vault)?;
        let sync = sync.ok_or(Error::UnsupportedDestination)?;
        let mut key = b"personal\0".to_vec();
        key.extend_from_slice(&(origin.len() as u64).to_be_bytes());
        key.extend_from_slice(origin.as_bytes());
        key.extend_from_slice(account.as_bytes());
        key.extend_from_slice(vault.as_bytes());
        let mut generation = auth.to_be_bytes().to_vec();
        generation.extend_from_slice(&sync.to_be_bytes());
        let binding: Option<(String, Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT origin,account_id,vault_id FROM account_profile_binding WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage)?;
        if binding.is_some_and(|(bound_origin, bound_account, bound_vault)| {
            bound_origin != origin
                || bound_account != account.as_bytes()
                || bound_vault != vault.as_bytes()
        }) {
            return Err(Error::ContextChanged);
        }
        return Ok(Context {
            key,
            vault: Some(vault),
            account: Some(account),
            generation,
            destination: ArchiveDestination::Personal {
                owner_id: account.to_string(),
                vault_id: vault.to_string(),
            },
        });
    }
    let account: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM personal_server) OR EXISTS(SELECT 1 FROM account_profile_binding)", [], |row| row.get(0),
    ).map_err(storage)?;
    if account {
        return Err(Error::UnsupportedDestination);
    }
    let mut key = b"local\0".to_vec();
    key.extend_from_slice(device.as_bytes());
    let generation: i64 = conn
        .query_row("SELECT generation FROM profile_selection WHERE singleton=1", [], |row| {
            row.get(0)
        })
        .map_err(storage)?;
    Ok(Context {
        key,
        vault: None,
        account: None,
        generation: generation.to_be_bytes().to_vec(),
        destination: ArchiveDestination::Local,
    })
}

fn revision(conn: &Connection, context: &Context) -> Result<String, Error> {
    let mut digest = Sha256::new();
    hash_part(&mut digest, &context.key);
    hash_part(&mut digest, &context.generation);
    let mut query = conn
        .prepare("SELECT id,envelope FROM objects WHERE vault IS ?1 ORDER BY id")
        .map_err(storage)?;
    let mut rows =
        query.query(params![context.vault.map(|id| id.as_bytes().to_vec())]).map_err(storage)?;
    while let Some(row) = rows.next().map_err(storage)? {
        hash_part(&mut digest, &row.get::<_, Vec<u8>>(0).map_err(storage)?);
        let bytes = Zeroizing::new(row.get::<_, Vec<u8>>(1).map_err(storage)?);
        hash_part(&mut digest, &bytes);
    }
    let mut query = conn.prepare("SELECT source_id,object_id,object_type FROM portable_import_receipts WHERE context=?1 ORDER BY source_id").map_err(storage)?;
    let mut rows = query.query(params![context.key]).map_err(storage)?;
    while let Some(row) = rows.next().map_err(storage)? {
        hash_part(&mut digest, &row.get::<_, Vec<u8>>(0).map_err(storage)?);
        hash_part(&mut digest, &row.get::<_, Vec<u8>>(1).map_err(storage)?);
        hash_part(&mut digest, &row.get::<_, i64>(2).map_err(storage)?.to_be_bytes());
    }
    Ok(hex(&digest.finalize()))
}

fn stage(
    conn: &Connection,
    context: &Context,
    reader: impl Read,
    passphrase: Option<&PortableExportPassphrase>,
) -> Result<String, Error> {
    conn.execute("DELETE FROM portable_import_stage", []).map_err(storage)?;
    conn.execute("DELETE FROM portable_import_preferences", []).map_err(storage)?;
    let mut query = conn
        .prepare("SELECT id,envelope FROM objects WHERE type=10 AND deleted=0 AND vault IS ?1")
        .map_err(storage)?;
    let mut rows =
        query.query(params![context.vault.map(|id| id.as_bytes().to_vec())]).map_err(storage)?;
    while let Some(row) = rows.next().map_err(storage)? {
        let bytes = Zeroizing::new(row.get::<_, Vec<u8>>(1).map_err(storage)?);
        let mut object = Object::decode(&bytes).map_err(|_| Error::Storage)?;
        let key = object.required_text(1).map_err(|_| Error::Storage)?;
        conn.execute(
            "INSERT INTO portable_import_preferences(object_id,key) VALUES(?1,?2)",
            params![object.id.as_bytes().as_slice(), key],
        )
        .map_err(storage)?;
        for field in object.fields.values_mut() {
            wipe(&mut field.value);
        }
    }
    let mut ordinal = 0_u32;
    let mut failure = None;
    let mut consume = |entry: Entry| {
        let result = (|| {
            let source = entry.id();
            let kind = entry.object_type();
            let preference_key = if kind == ObjectType::PREFERENCE {
                match entry.fields().get(&FieldPath::Field(1)) {
                    Some(Value::Text(key)) => Some(key.clone()),
                    _ => return Err(Error::InvalidArchive),
                }
            } else {
                None
            };
            let receipt: Option<Vec<u8>> = conn.query_row(
                "SELECT object_id FROM portable_import_receipts WHERE context=?1 AND source_id=?2",
                params![context.key,source.as_bytes().as_slice()], |row|row.get(0),
            ).optional().map_err(storage)?;
            let target = match &receipt {
                Some(bytes) => id(bytes)?,
                None => scoplen_model::new_uuid_v7().map_err(|_| Error::Storage)?,
            };
            let header = Header {
                exported_at: 0,
                source_kind: SourceKind::Device,
                source_id: source,
                secrets: if entry.omitted_secrets().is_empty() {
                    SecretMode::Included
                } else {
                    SecretMode::Omitted
                },
            };
            let mut bytes = Zeroizing::new(Vec::new());
            portable::write_archive(&mut *bytes, &header, std::iter::once(Ok(entry)))
                .map_err(model)?;
            conn.execute("INSERT INTO portable_import_stage(source_id,ordinal,object_type,entry,target_id,existing,preference_key) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![source.as_bytes().as_slice(),ordinal,kind.to_wire() as i64,bytes.as_slice(),target.as_bytes().as_slice(),receipt.is_some(),preference_key]).map_err(storage)?;
            ordinal += 1;
            Ok(())
        })();
        result.map_err(|error| {
            failure = Some(error);
            portable::Error::Consumer
        })
    };
    let mut reader = HashReader { reader, digest: Sha256::new() };
    let mut prefix = [0_u8; 22];
    reader.read_exact(&mut prefix).map_err(|_| Error::InvalidArchive)?;
    let encrypted = &prefix == b"age-encryption.org/v1\n";
    let mut input = Cursor::new(prefix).chain(&mut reader);
    let summary = if encrypted {
        let passphrase = passphrase.ok_or(Error::PassphraseRequired)?;
        let mut decrypted =
            PortableExportReader::new(&mut input, passphrase).map_err(|_| Error::Decryption)?;
        let result = portable::read_archive(&mut decrypted, &mut consume);
        let summary = result.map_err(|error| {
            failure.take().unwrap_or_else(|| {
                if error == portable::Error::Io { Error::Decryption } else { model(error) }
            })
        })?;
        decrypted.finish().map_err(|_| Error::Decryption)?;
        summary
    } else {
        portable::read_archive(&mut input, &mut consume)
            .map_err(|error| failure.take().unwrap_or_else(|| model(error)))?
    };
    if summary.header.source_kind != SourceKind::Device {
        return Err(Error::UnsupportedDestination);
    }
    if summary.header.secrets == SecretMode::Included && !encrypted {
        return Err(Error::PassphraseRequired);
    }
    Ok(hex(&reader.digest.finalize()))
}

fn each_staged(
    conn: &Connection,
    mut operation: impl FnMut(Staged) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut query = conn
        .prepare("SELECT entry,target_id,existing FROM portable_import_stage ORDER BY ordinal")
        .map_err(storage)?;
    let mut rows = query.query([]).map_err(storage)?;
    while let Some(row) = rows.next().map_err(storage)? {
        let bytes = Zeroizing::new(row.get::<_, Vec<u8>>(0).map_err(storage)?);
        let mut entry = None;
        portable::read_archive(bytes.as_slice(), |value| {
            entry = Some(value);
            Ok(())
        })
        .map_err(model)?;
        operation(Staged {
            entry: entry.ok_or(Error::Storage)?,
            target: id(&row.get::<_, Vec<u8>>(1).map_err(storage)?)?,
            existing: row.get(2).map_err(storage)?,
        })?;
    }
    Ok(())
}

fn prepare(
    conn: &Connection,
    context: &Context,
    staged: &Staged,
    device: Uuid,
    retain: bool,
) -> Result<Prepared, Error> {
    let entry = &staged.entry;
    let existing = if staged.existing {
        super::read_object(conn, staged.target).map_err(storage)?
    } else {
        None
    };
    let mut preview = ImportEntryPreview {
        source_id: entry.id().to_string(),
        target_id: staged.existing.then(|| staged.target.to_string()),
        object_type: entry.object_type().to_string(),
        action: if staged.existing { ImportAction::Replace } else { ImportAction::Create },
        omitted_secrets: entry.omitted_secrets().to_vec(),
        retain_secret_available: false,
        requires_device_setup: entry.object_type() == ObjectType::CREDENTIAL
            && entry.fields().get(&FieldPath::Field(3)) == Some(&Value::UInt(2)),
        trust: None,
        problem: None,
    };
    if unsupported(entry.object_type(), entry.fields()) {
        preview.problem = Some(ImportProblem::UnsupportedData);
    }
    if staged.existing {
        let receipt_type:i64=conn.query_row("SELECT object_type FROM portable_import_receipts WHERE context=?1 AND source_id=?2",params![context.key,entry.id().as_bytes().as_slice()],|row|row.get(0)).map_err(storage)?;
        if receipt_type != entry.object_type().to_wire() as i64
            || existing.as_ref().is_none_or(|object| object.object_type != entry.object_type())
            || super::sync::object_vault(conn, staged.target).map_err(storage)? != context.vault
        {
            preview.problem = Some(ImportProblem::IncompatibleTarget);
        } else if existing.as_ref().is_some_and(Object::is_tombstoned) {
            preview.problem = Some(ImportProblem::DeletedTarget);
        }
    }
    let mut fields = entry.fields().clone();
    if let Err(problem) = remap(conn, context, entry.object_type(), &mut fields) {
        preview.problem.get_or_insert(problem);
    }
    let retained = retain_secrets(entry, existing.as_ref(), &mut fields, retain);
    preview.retain_secret_available = retained;
    if entry.omitted_secrets().iter().any(|pointer| pointer == "/secret") && (!retained || !retain)
    {
        preview.problem.get_or_insert(ImportProblem::MissingSecret);
    }
    if entry.object_type() == ObjectType::TRUST_RECORD {
        match trust_fields(&mut fields, existing.as_ref(), device, context.account) {
            Ok(trust) => preview.trust = Some(trust),
            Err(problem) => {
                preview.problem.get_or_insert(problem);
            }
        }
    }
    if entry.object_type() == ObjectType::PREFERENCE
        && preference_conflict(conn, entry.id(), staged.target, &fields)?
    {
        preview.problem.get_or_insert(ImportProblem::PreferenceConflict);
    }
    if preview.problem.is_some() {
        preview.action = ImportAction::Blocked;
    } else if existing.as_ref().is_some_and(|object| live_fields(object) == fields) {
        preview.action = ImportAction::Unchanged;
    }
    Ok(Prepared { fields, existing, preview })
}

fn unsupported(kind: ObjectType, fields: &BTreeMap<FieldPath, Value>) -> bool {
    kind == ObjectType::GATEWAY_NETWORK
        || kind == ObjectType::ROUTE && fields.get(&FieldPath::Field(2)) == Some(&Value::UInt(5))
}

fn remap(
    conn: &Connection,
    context: &Context,
    kind: ObjectType,
    fields: &mut BTreeMap<FieldPath, Value>,
) -> Result<(), ImportProblem> {
    let mut remapped = BTreeMap::new();
    for (mut path, mut value) in std::mem::take(fields) {
        let scalar = match (kind, path.field_number()) {
            (ObjectType::HOST, 8) => Some(ObjectType::ACCESS_PROFILE),
            (ObjectType::ACCESS_PROFILE, 1) | (ObjectType::TRUST_RECORD, 1) => {
                Some(ObjectType::HOST)
            }
            (ObjectType::ACCESS_PROFILE, 4) | (ObjectType::ROUTE, 5) => {
                Some(ObjectType::CREDENTIAL)
            }
            (ObjectType::ACCESS_PROFILE, 5) => Some(ObjectType::ROUTE),
            (ObjectType::HOST_GROUP, 2) => Some(ObjectType::HOST_GROUP),
            (ObjectType::ROUTE, 7) => Some(ObjectType::GATEWAY_NETWORK),
            (ObjectType::FORWARD, 7) => Some(ObjectType::ACCESS_PROFILE),
            _ => None,
        };
        if matches!(path, FieldPath::Field(_))
            && let Some(expected) = scalar
            && let Value::Bytes(bytes) = &mut value
        {
            *bytes = reference(conn, context, bytes, expected)?.as_bytes().to_vec();
        }
        if let FieldPath::MapEntry { field, key: MapKey::Bytes(bytes) } = &mut path {
            let expected = match (kind, *field) {
                (ObjectType::HOST, 5) => Some(ObjectType::HOST_GROUP),
                (ObjectType::ACCESS_PROFILE, 8) => Some(ObjectType::FORWARD),
                _ => None,
            };
            if let Some(expected) = expected {
                *bytes = reference(conn, context, bytes, expected)?.as_bytes().to_vec();
            }
        }
        if kind == ObjectType::ROUTE
            && path == FieldPath::Field(3)
            && let Value::Array(hops) = &mut value
        {
            for hop in hops {
                if let Value::Bytes(bytes) = hop {
                    *bytes = reference(conn, context, bytes, ObjectType::ACCESS_PROFILE)?
                        .as_bytes()
                        .to_vec();
                }
            }
        }
        if kind == ObjectType::HOST_GROUP
            && let FieldPath::MapEntry { field: 4, key: MapKey::Text(key) } = &path
            && let Value::Text(text) = &mut value
        {
            let expected = match key.as_str() {
                "route" => Some(ObjectType::ROUTE),
                "credential" => Some(ObjectType::CREDENTIAL),
                _ => None,
            };
            if let Some(expected) = expected {
                let source = Uuid::parse_str(text).map_err(|_| ImportProblem::MissingReference)?;
                *text = reference(conn, context, source.as_bytes(), expected)?.to_string();
            }
        }
        if kind == ObjectType::WORKSPACE
            && matches!(path, FieldPath::MapEntry { field: 3, .. })
            && let Value::Map(spec) = &mut value
        {
            for (field, value) in spec {
                let expected = match field {
                    Value::UInt(1) => Some(ObjectType::ACCESS_PROFILE),
                    Value::UInt(3) => Some(ObjectType::FORWARD),
                    _ => None,
                };
                if let Some(expected) = expected
                    && let Value::Bytes(bytes) = value
                {
                    *bytes = reference(conn, context, bytes, expected)?.as_bytes().to_vec();
                }
            }
        }
        remapped.insert(path, value);
    }
    *fields = remapped;
    Ok(())
}

fn reference(
    conn: &Connection,
    context: &Context,
    source: &[u8],
    expected: ObjectType,
) -> Result<Uuid, ImportProblem> {
    let staged: Option<(Vec<u8>, i64)> = conn
        .query_row(
            "SELECT target_id,object_type FROM portable_import_stage WHERE source_id=?1",
            params![source],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| ImportProblem::MissingReference)?;
    if let Some((target, kind)) = staged {
        return if kind == expected.to_wire() as i64 {
            Uuid::from_slice(&target).map_err(|_| ImportProblem::MissingReference)
        } else {
            Err(ImportProblem::MissingReference)
        };
    }
    let target:Option<Vec<u8>>=conn.query_row("SELECT r.object_id FROM portable_import_receipts r JOIN objects o ON o.id=r.object_id WHERE r.context=?1 AND r.source_id=?2 AND r.object_type=?3 AND o.type=?3 AND o.deleted=0 AND o.vault IS ?4",
        params![context.key,source,expected.to_wire() as i64,context.vault.map(|id|id.as_bytes().to_vec())],|row|row.get(0)).optional().map_err(|_|ImportProblem::MissingReference)?;
    Uuid::from_slice(&target.ok_or(ImportProblem::MissingReference)?)
        .map_err(|_| ImportProblem::MissingReference)
}

fn retain_secrets(
    entry: &Entry,
    existing: Option<&Object>,
    fields: &mut BTreeMap<FieldPath, Value>,
    retain: bool,
) -> bool {
    let Some(existing) = existing
        .filter(|object| !object.is_tombstoned() && object.object_type == entry.object_type())
    else {
        return false;
    };
    if entry.object_type() == ObjectType::CREDENTIAL
        && entry.omitted_secrets().iter().any(|pointer| pointer == "/secret")
    {
        let compatible = existing.set_field(2).map(|entry| &entry.value)
            == fields.get(&FieldPath::Field(2))
            && existing.set_field(3).map(|entry| &entry.value) == Some(&Value::UInt(1));
        if compatible && let Some(secret) = existing.set_field(4) {
            if retain {
                fields.insert(FieldPath::Field(4), secret.value.clone());
            }
            return true;
        }
    }
    let mut available = false;
    if entry.object_type() == ObjectType::SNIPPET {
        for pointer in entry.omitted_secrets() {
            let Some(name) =
                pointer.strip_prefix("/variables/").and_then(|name| name.strip_suffix("/default"))
            else {
                continue;
            };
            let path = FieldPath::MapEntry {
                field: 3,
                key: MapKey::Text(name.replace("~1", "/").replace("~0", "~")),
            };
            if let Some(old) = existing.fields.get(&path)
                && let Value::Map(old_spec) = &old.value
                && old_spec.contains(&(Value::UInt(1), Value::UInt(4)))
                && let Some((_, default)) = old_spec.iter().find(|(key, _)| *key == Value::UInt(2))
                && let Some(Value::Map(spec)) = fields.get_mut(&path)
            {
                available = true;
                if retain {
                    spec.push((Value::UInt(2), default.clone()));
                }
            }
        }
    }
    available
}

fn trust_fields(
    fields: &mut BTreeMap<FieldPath, Value>,
    existing: Option<&Object>,
    device: Uuid,
    account: Option<Uuid>,
) -> Result<ImportTrustPreview, ImportProblem> {
    let Some(Value::Text(text)) = fields.get(&FieldPath::Field(3)) else {
        return Err(ImportProblem::InvalidTrust);
    };
    let mut key =
        ssh_key::PublicKey::from_openssh(text).map_err(|_| ImportProblem::InvalidTrust)?;
    let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
    if fields
        .get(&FieldPath::Field(4))
        .is_some_and(|value| *value != Value::Text(fingerprint.clone()))
    {
        return Err(ImportProblem::InvalidTrust);
    }
    fields.insert(FieldPath::Field(4), Value::Text(fingerprint.clone()));
    key.set_comment("");
    fields.insert(
        FieldPath::Field(3),
        Value::Text(key.to_openssh().map_err(|_| ImportProblem::InvalidTrust)?),
    );
    let unchanged = existing.is_some_and(|existing| {
        existing.set_field(5).map(|entry| &entry.value) == Some(&Value::UInt(2))
            && existing.set_field(6).is_some()
            && existing.set_field(7).is_some()
            && existing.set_field(8).map(|entry| &entry.value)
                == account.as_ref().map(|id| Value::Bytes(id.as_bytes().to_vec())).as_ref()
            && [1, 2, 3, 4].iter().all(|field| {
                existing.set_field(*field).map(|entry| &entry.value)
                    == fields.get(&FieldPath::Field(*field))
            })
            && [9, 10].iter().all(|field| {
                existing.set_field(*field).is_some_and(|entry| entry.value == Value::Bool(true))
                    == (fields.get(&FieldPath::Field(*field)) == Some(&Value::Bool(true)))
            })
    });
    for field in 5..=8 {
        fields.remove(&FieldPath::Field(field));
    }
    if unchanged {
        if let Some(existing) = existing {
            for field in 5..=8 {
                if let Some(value) = existing.set_field(field) {
                    fields.insert(FieldPath::Field(field), value.value.clone());
                }
            }
        }
    } else {
        fields.insert(FieldPath::Field(5), Value::UInt(2));
        fields.insert(
            FieldPath::Field(6),
            Value::UInt(
                scoplen_model::system_time_millis().map_err(|_| ImportProblem::InvalidTrust)?,
            ),
        );
        fields.insert(FieldPath::Field(7), Value::Bytes(device.as_bytes().to_vec()));
        if let Some(account) = account {
            fields.insert(FieldPath::Field(8), Value::Bytes(account.as_bytes().to_vec()));
        }
    }
    Ok(ImportTrustPreview {
        algorithm: key.algorithm().to_string(),
        fingerprint,
        requires_consent: !unchanged,
        is_ca: fields.get(&FieldPath::Field(10)) == Some(&Value::Bool(true)),
        revoked: fields.get(&FieldPath::Field(9)) == Some(&Value::Bool(true)),
    })
}

fn preference_conflict(
    conn: &Connection,
    source: Uuid,
    target: Uuid,
    fields: &BTreeMap<FieldPath, Value>,
) -> Result<bool, Error> {
    let Some(Value::Text(key)) = fields.get(&FieldPath::Field(1)) else {
        return Err(Error::InvalidArchive);
    };
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM portable_import_preferences WHERE key=?1 AND object_id<>?2)
            OR EXISTS(SELECT 1 FROM portable_import_stage WHERE preference_key=?1 AND source_id<>?3)",
        params![key,target.as_bytes().as_slice(),source.as_bytes().as_slice()],|row|row.get(0),
    ).map_err(storage)
}

fn choices(
    preview: &ImportPreview,
    consent: &ImportConsent,
) -> Result<(BTreeSet<Uuid>, BTreeSet<Uuid>), Error> {
    let mut retain = BTreeSet::new();
    let mut trust = BTreeSet::new();
    let rows: BTreeMap<_, _> =
        preview.entries.iter().map(|entry| (entry.source_id.as_str(), entry)).collect();
    for (values, selected, is_trust) in [
        (&consent.retain_secret_source_ids, &mut retain, false),
        (&consent.trust_source_ids, &mut trust, true),
    ] {
        for value in values {
            let id = Uuid::parse_str(value).map_err(|_| Error::ConsentRequired)?;
            let row = rows.get(value.as_str()).ok_or(Error::ConsentRequired)?;
            let eligible = if is_trust {
                row.trust.as_ref().is_some_and(|key| key.requires_consent)
            } else {
                row.retain_secret_available
            };
            if !eligible || !selected.insert(id) {
                return Err(Error::ConsentRequired);
            }
        }
    }
    for entry in &preview.entries {
        if entry.trust.as_ref().is_some_and(|key| key.requires_consent)
            && !trust
                .contains(&Uuid::parse_str(&entry.source_id).map_err(|_| Error::ConsentRequired)?)
        {
            return Err(Error::ConsentRequired);
        }
        if entry.omitted_secrets.iter().any(|pointer| pointer == "/secret")
            && !retain
                .contains(&Uuid::parse_str(&entry.source_id).map_err(|_| Error::ConsentRequired)?)
        {
            return Err(Error::ConsentRequired);
        }
    }
    Ok((retain, trust))
}

fn replacement_clock(conn: &Connection, existing: Option<&Object>) -> Result<Hlc, Error> {
    let mut clock = super::next_clock(conn).map_err(storage)?;
    if let Some(last) =
        existing.and_then(|object| object.fields.values().map(|entry| entry.clock).max())
        && last >= clock
    {
        clock =
            Hlc::tick(Some(last), scoplen_model::system_time_millis().map_err(|_| Error::Storage)?)
                .map_err(|_| Error::Storage)?;
        conn.execute(
            "UPDATE device SET clock=?1 WHERE singleton=1",
            params![clock.to_wire() as i64],
        )
        .map_err(storage)?;
    }
    Ok(clock)
}

fn live_fields(object: &Object) -> BTreeMap<FieldPath, Value> {
    object
        .fields
        .iter()
        .filter(|(_, entry)| !matches!(entry.value, Value::Null))
        .map(|(path, entry)| (path.clone(), entry.value.clone()))
        .collect()
}
fn secret_mode(mode: ArchiveSecretMode) -> SecretMode {
    match mode {
        ArchiveSecretMode::Omitted => SecretMode::Omitted,
        ArchiveSecretMode::Included => SecretMode::Included,
    }
}
fn id(bytes: &[u8]) -> Result<Uuid, Error> {
    Uuid::from_slice(bytes).map_err(|_| Error::Storage)
}
fn storage(_: impl std::fmt::Display) -> Error {
    Error::Storage
}
fn model(error: portable::Error) -> Error {
    match error {
        portable::Error::Unsupported => Error::UnsupportedData,
        portable::Error::Io => Error::Io,
        _ => Error::InvalidArchive,
    }
}
fn hash_part(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    value
}
fn wipe_fields(fields: &mut BTreeMap<FieldPath, Value>) {
    for value in fields.values_mut() {
        wipe(value);
    }
}
fn wipe(value: &mut Value) {
    match value {
        Value::Bytes(bytes) => bytes.zeroize(),
        Value::Text(text) => text.zeroize(),
        Value::Array(values) => {
            for value in values {
                wipe(value);
            }
        }
        Value::Map(values) => {
            for (key, value) in values {
                wipe(key);
                wipe(value);
            }
        }
        _ => {}
    }
}
struct HashReader<R> {
    reader: R,
    digest: Sha256,
}
impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let read = self.reader.read(output)?;
        self.digest.update(&output[..read]);
        Ok(read)
    }
}

#[cfg(test)]
mod tests;
