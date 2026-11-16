// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use super::*;
use crate::portable_archive::PortableArchives;

fn store() -> (tempfile::TempDir, Arc<Store>) {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::open(
            &directory.path().join("local.db"),
            &scoplen_crypto::LocalDatabaseKey::new([42; 32]),
        )
        .unwrap(),
    );
    (directory, store)
}
fn object(kind: ObjectType, fields: Vec<(u64, Value)>) -> Object {
    let mut object = Object::new(scoplen_model::new_uuid_v7().unwrap(), kind, 1).unwrap();
    let clock = Hlc::from_wire(1).unwrap();
    for (field, value) in fields {
        object
            .insert(FieldPath::Field(field), FieldEntry::new(value, clock, object.id).unwrap())
            .unwrap();
    }
    object.validate().unwrap();
    object
}
fn host(name: &str) -> Object {
    object(
        ObjectType::HOST,
        vec![(1, Value::Text(name.into())), (2, Value::Text("host.test".into()))],
    )
}
fn archive(objects: &[Object], mode: SecretMode) -> Vec<u8> {
    let mut bytes = Vec::new();
    portable::write_archive(
        &mut bytes,
        &Header {
            exported_at: 1,
            source_kind: SourceKind::Device,
            source_id: scoplen_model::new_uuid_v7().unwrap(),
            secrets: mode,
        },
        objects.iter().map(|object| Entry::from_object(object, mode).map(Option::unwrap)),
    )
    .unwrap();
    bytes
}
fn encrypted(objects: &[Object], password: &PortableExportPassphrase) -> Vec<u8> {
    let mut writer = PortableExportWriter::new(Vec::new(), password).unwrap();
    writer.write_all(&archive(objects, SecretMode::Included)).unwrap();
    writer.finish().unwrap()
}
fn counts(store: &Store) -> (i64, i64, i64) {
    let conn = store.conn();
    (
        conn.query_row("SELECT count(*) FROM objects", [], |row| row.get(0)).unwrap(),
        conn.query_row("SELECT count(*) FROM portable_import_receipts", [], |row| row.get(0))
            .unwrap(),
        conn.query_row("SELECT count(*) FROM portable_import_stage", [], |row| row.get(0)).unwrap(),
    )
}

#[test]
fn creates_fresh_ids_and_reimports_complete_state_after_reopen() {
    let (dir, destination) = store();
    let service = PortableArchives::default();
    let mut source = host("first");
    source.fields.insert(
        FieldPath::Field(7),
        FieldEntry::new(Value::Text("remove me".into()), Hlc::from_wire(1).unwrap(), source.id)
            .unwrap(),
    );
    let bytes = archive(std::slice::from_ref(&source), SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert_eq!(preview.entries[0].action, ImportAction::Create);
    assert!(preview.entries[0].target_id.is_none());
    assert_eq!(counts(&destination), (0, 0, 0));
    assert_eq!(
        service
            .import(&destination, bytes.as_slice(), None, &preview.id, ImportConsent::default())
            .unwrap()
            .created,
        1
    );
    let target = destination.list(ObjectType::HOST).unwrap().remove(0);
    assert_ne!(target.id, source.id);
    assert_eq!(target.id.get_version_num(), 7);
    drop(destination);
    let destination = Arc::new(
        Store::open(&dir.path().join("local.db"), &scoplen_crypto::LocalDatabaseKey::new([42; 32]))
            .unwrap(),
    );
    destination.conn().execute("UPDATE profile_selection SET generation=generation+1", []).unwrap();
    source.fields.remove(&FieldPath::Field(7));
    source.fields.get_mut(&FieldPath::Field(1)).unwrap().value = Value::Text("changed".into());
    let bytes = archive(std::slice::from_ref(&source), SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert_eq!(preview.entries[0].target_id, Some(target.id.to_string()));
    assert_eq!(preview.entries[0].action, ImportAction::Replace);
    assert_eq!(
        service
            .import(&destination, bytes.as_slice(), None, &preview.id, ImportConsent::default())
            .unwrap()
            .updated,
        1
    );
    let target = destination.get(target.id).unwrap().unwrap();
    assert_eq!(target.required_text(1).unwrap(), "changed");
    assert!(matches!(target.field(7).unwrap().value, Value::Null));
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert_eq!(preview.entries[0].action, ImportAction::Unchanged);
    let previous = target.clone();
    assert_eq!(
        service
            .import(&destination, bytes.as_slice(), None, &preview.id, ImportConsent::default())
            .unwrap()
            .unchanged,
        1
    );
    assert_eq!(destination.get(target.id).unwrap().unwrap(), previous);
    assert_eq!(counts(&destination), (1, 1, 0));
    let empty = archive(&[], SecretMode::Omitted);
    let preview = service.preview(&destination, empty.as_slice(), None).unwrap();
    service
        .import(&destination, empty.as_slice(), None, &preview.id, ImportConsent::default())
        .unwrap();
    assert_eq!(counts(&destination), (1, 1, 0));
}

#[test]
fn stale_source_target_and_foreign_store_never_write() {
    let (_dir, destination) = store();
    let service = PortableArchives::default();
    let bytes = archive(&[host("first")], SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    let changed = archive(&[host("different")], SecretMode::Omitted);
    assert_eq!(
        service.import(
            &destination,
            changed.as_slice(),
            None,
            &preview.id,
            ImportConsent::default()
        ),
        Err(Error::SourceChanged)
    );
    assert_eq!(counts(&destination), (0, 0, 0));
    let (_other_dir, other) = store();
    assert_eq!(
        service.import(&other, bytes.as_slice(), None, &preview.id, ImportConsent::default()),
        Err(Error::ContextChanged)
    );
    destination
        .write(super::super::LocalWrite {
            id: None,
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text("local".into())),
                (FieldPath::Field(2), Value::Text("local.test".into())),
            ],
        })
        .unwrap();
    assert_eq!(
        service.import(&destination, bytes.as_slice(), None, &preview.id, ImportConsent::default()),
        Err(Error::DestinationChanged)
    );
    assert_eq!(counts(&destination), (1, 0, 0));
}

#[test]
fn rejects_late_malformed_json_and_unmapped_references() {
    let (_dir, destination) = store();
    let service = PortableArchives::default();
    let source = host("first");
    let mut bytes = archive(std::slice::from_ref(&source), SecretMode::Omitted);
    bytes.extend_from_slice(b"x");
    assert_eq!(service.preview(&destination, bytes.as_slice(), None), Err(Error::InvalidArchive));
    assert_eq!(counts(&destination), (0, 0, 0));
    let profile = object(
        ObjectType::ACCESS_PROFILE,
        vec![(1, Value::Bytes(source.id.as_bytes().to_vec())), (3, Value::Text("user".into()))],
    );
    let bytes = archive(&[profile], SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert!(!preview.can_import);
    assert_eq!(preview.entries[0].problem, Some(ImportProblem::MissingReference));
    assert_eq!(
        service.import(&destination, bytes.as_slice(), None, &preview.id, ImportConsent::default()),
        Err(Error::Blocked)
    );
    assert_eq!(counts(&destination), (0, 0, 0));
}

#[test]
fn shared_secrets_require_encryption_and_explicit_receipt_owned_retention() {
    let (_dir, destination) = store();
    let service = PortableArchives::default();
    let source = object(
        ObjectType::CREDENTIAL,
        vec![
            (2, Value::UInt(1)),
            (3, Value::UInt(1)),
            (4, Value::Bytes(b"private fixture".to_vec())),
        ],
    );
    let omitted = archive(std::slice::from_ref(&source), SecretMode::Omitted);
    let preview = service.preview(&destination, omitted.as_slice(), None).unwrap();
    assert_eq!(preview.entries[0].problem, Some(ImportProblem::MissingSecret));
    assert!(!preview.can_import);
    let plaintext = archive(std::slice::from_ref(&source), SecretMode::Included);
    assert_eq!(
        service.preview(&destination, plaintext.as_slice(), None),
        Err(Error::PassphraseRequired)
    );
    assert_eq!(counts(&destination), (0, 0, 0));
    let password = PortableExportPassphrase::new("archive fixture passphrase".into()).unwrap();
    let bytes = encrypted(std::slice::from_ref(&source), &password);
    let preview = service.preview(&destination, bytes.as_slice(), Some(&password)).unwrap();
    service
        .import(
            &destination,
            bytes.as_slice(),
            Some(&password),
            &preview.id,
            ImportConsent::default(),
        )
        .unwrap();
    let preview = service.preview(&destination, omitted.as_slice(), None).unwrap();
    assert!(preview.can_import);
    assert!(preview.entries[0].retain_secret_available);
    assert_eq!(preview.entries[0].action, ImportAction::Unchanged);
    assert_eq!(
        service.import(
            &destination,
            omitted.as_slice(),
            None,
            &preview.id,
            ImportConsent::default()
        ),
        Err(Error::ConsentRequired)
    );
    service
        .import(
            &destination,
            omitted.as_slice(),
            None,
            &preview.id,
            ImportConsent {
                retain_secret_source_ids: vec![source.id.to_string()],
                trust_source_ids: vec![],
            },
        )
        .unwrap();
    assert_eq!(
        destination.list(ObjectType::CREDENTIAL).unwrap()[0].set_field(4).unwrap().value,
        Value::Bytes(b"private fixture".to_vec())
    );
    assert_eq!(counts(&destination), (1, 1, 0));
}

#[test]
fn encrypted_final_authentication_failure_rolls_back_all_staging() {
    let (_dir, destination) = store();
    let service = PortableArchives::default();
    let password = PortableExportPassphrase::new("archive fixture passphrase".into()).unwrap();
    let bytes = encrypted(&[host("first"), host("second")], &password);
    let preview = service.preview(&destination, bytes.as_slice(), Some(&password)).unwrap();
    for broken in [
        bytes[..bytes.len() - 1].to_vec(),
        {
            let mut value = bytes.clone();
            *value.last_mut().unwrap() ^= 1;
            value
        },
        {
            let mut value = bytes.clone();
            value.push(0);
            value
        },
    ] {
        assert!(
            service
                .import(
                    &destination,
                    broken.as_slice(),
                    Some(&password),
                    &preview.id,
                    ImportConsent::default()
                )
                .is_err()
        );
        assert_eq!(counts(&destination), (0, 0, 0));
    }
}

fn set(object: &mut Object, path: FieldPath, value: Value) {
    object
        .insert(path, FieldEntry::new(value, Hlc::from_wire(1).unwrap(), object.id).unwrap())
        .unwrap();
}

fn mapped(store: &Store, source: Uuid) -> Object {
    let target: Vec<u8> = store
        .conn()
        .query_row(
            "SELECT object_id FROM portable_import_receipts WHERE source_id=?1",
            params![source.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    store.get(Uuid::from_slice(&target).unwrap()).unwrap().unwrap()
}

#[test]
fn remaps_typed_references_and_group_defaults_without_changing_opaque_identities() {
    let (_dir, destination) = store();
    let service = PortableArchives::default();
    let organization = scoplen_model::new_uuid_v7().unwrap();
    let device = scoplen_model::new_uuid_v7().unwrap();
    let slot = scoplen_model::new_uuid_v7().unwrap();
    let mut credential = object(
        ObjectType::CREDENTIAL,
        vec![
            (2, Value::UInt(3)),
            (3, Value::UInt(2)),
            (8, Value::Bytes(organization.as_bytes().to_vec())),
        ],
    );
    set(
        &mut credential,
        FieldPath::MapEntry { field: 5, key: MapKey::Bytes(device.as_bytes().to_vec()) },
        Value::Map(vec![
            (Value::UInt(1), Value::Text("public binding".into())),
            (Value::UInt(2), Value::Text("device label".into())),
        ]),
    );
    let route = object(
        ObjectType::ROUTE,
        vec![
            (1, Value::Text("command".into())),
            (2, Value::UInt(4)),
            (6, Value::Text("ssh -W %h:%p relay".into())),
        ],
    );
    let mut group = object(ObjectType::HOST_GROUP, vec![(1, Value::Text("group".into()))]);
    for (key, source) in [("route", route.id), ("credential", credential.id)] {
        set(
            &mut group,
            FieldPath::MapEntry { field: 4, key: MapKey::Text(key.into()) },
            Value::Text(source.to_string()),
        );
    }
    let mut host = host("host");
    set(
        &mut host,
        FieldPath::MapEntry { field: 5, key: MapKey::Bytes(group.id.as_bytes().to_vec()) },
        Value::Bool(true),
    );
    let mut profile = object(
        ObjectType::ACCESS_PROFILE,
        vec![
            (1, Value::Bytes(host.id.as_bytes().to_vec())),
            (3, Value::Text("user".into())),
            (4, Value::Bytes(credential.id.as_bytes().to_vec())),
            (5, Value::Bytes(route.id.as_bytes().to_vec())),
        ],
    );
    set(&mut host, FieldPath::Field(8), Value::Bytes(profile.id.as_bytes().to_vec()));
    let forward = object(
        ObjectType::FORWARD,
        vec![
            (1, Value::Text("forward".into())),
            (2, Value::UInt(1)),
            (3, Value::Text("127.0.0.1".into())),
            (4, Value::UInt(8080)),
            (5, Value::Text("service.test".into())),
            (6, Value::UInt(80)),
            (7, Value::Bytes(profile.id.as_bytes().to_vec())),
        ],
    );
    set(
        &mut profile,
        FieldPath::MapEntry { field: 8, key: MapKey::Bytes(forward.id.as_bytes().to_vec()) },
        Value::Bool(true),
    );
    let mut workspace = object(
        ObjectType::WORKSPACE,
        vec![(1, Value::Text("workspace".into())), (2, Value::Bytes(host.id.as_bytes().to_vec()))],
    );
    set(
        &mut workspace,
        FieldPath::MapEntry { field: 3, key: MapKey::Bytes(slot.as_bytes().to_vec()) },
        Value::Map(vec![
            (Value::UInt(1), Value::Bytes(profile.id.as_bytes().to_vec())),
            (Value::UInt(2), Value::UInt(3)),
            (Value::UInt(3), Value::Bytes(forward.id.as_bytes().to_vec())),
        ]),
    );
    let preference = object(
        ObjectType::PREFERENCE,
        vec![(1, Value::Text("opaque".into())), (2, Value::Bytes(host.id.as_bytes().to_vec()))],
    );
    let source = [
        credential.clone(),
        route.clone(),
        group.clone(),
        host.clone(),
        profile.clone(),
        forward.clone(),
        workspace.clone(),
        preference.clone(),
    ];
    let bytes = archive(&source, SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert!(preview.can_import, "{preview:?}");
    assert!(preview.entries[0].requires_device_setup);
    assert_eq!(
        service
            .import(&destination, bytes.as_slice(), None, &preview.id, ImportConsent::default())
            .unwrap()
            .created,
        8
    );
    let new_host = mapped(&destination, host.id);
    let new_profile = mapped(&destination, profile.id);
    let new_group = mapped(&destination, group.id);
    let new_route = mapped(&destination, route.id);
    let new_credential = mapped(&destination, credential.id);
    let new_forward = mapped(&destination, forward.id);
    let new_workspace = mapped(&destination, workspace.id);
    assert_eq!(new_profile.required_bytes(1).unwrap(), new_host.id.as_bytes());
    assert_eq!(new_profile.required_bytes(4).unwrap(), new_credential.id.as_bytes());
    assert_eq!(new_profile.required_bytes(5).unwrap(), new_route.id.as_bytes());
    assert_eq!(new_host.required_bytes(8).unwrap(), new_profile.id.as_bytes());
    assert!(new_host.fields.contains_key(&FieldPath::MapEntry {
        field: 5,
        key: MapKey::Bytes(new_group.id.as_bytes().to_vec())
    }));
    assert!(new_profile.fields.contains_key(&FieldPath::MapEntry {
        field: 8,
        key: MapKey::Bytes(new_forward.id.as_bytes().to_vec())
    }));
    for (key, target) in [("route", new_route.id), ("credential", new_credential.id)] {
        assert_eq!(
            new_group.fields[&FieldPath::MapEntry { field: 4, key: MapKey::Text(key.into()) }]
                .value,
            Value::Text(target.to_string())
        );
    }
    assert_eq!(new_credential.required_bytes(8).unwrap(), organization.as_bytes());
    assert!(new_credential.fields.contains_key(&FieldPath::MapEntry {
        field: 5,
        key: MapKey::Bytes(device.as_bytes().to_vec())
    }));
    assert_eq!(new_workspace.required_bytes(2).unwrap(), host.id.as_bytes());
    let Value::Map(spec) = &new_workspace.fields
        [&FieldPath::MapEntry { field: 3, key: MapKey::Bytes(slot.as_bytes().to_vec()) }]
        .value
    else {
        panic!()
    };
    assert!(spec.contains(&(Value::UInt(1), Value::Bytes(new_profile.id.as_bytes().to_vec()))));
    assert!(spec.contains(&(Value::UInt(3), Value::Bytes(new_forward.id.as_bytes().to_vec()))));
    assert_eq!(mapped(&destination, preference.id).required_bytes(2).unwrap(), host.id.as_bytes());
    let another = object(
        ObjectType::ACCESS_PROFILE,
        vec![(1, Value::Bytes(host.id.as_bytes().to_vec())), (3, Value::Text("another".into()))],
    );
    let bytes = archive(&[another], SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert!(preview.can_import);
    service
        .import(&destination, bytes.as_slice(), None, &preview.id, ImportConsent::default())
        .unwrap();
}

#[test]
fn verifies_full_trust_fingerprint_and_keeps_actual_acceptance_on_reimport() {
    let (_dir, destination) = store();
    let service = PortableArchives::default();
    let key = ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[19; 32]).into(),
        "fixture",
    )
    .unwrap();
    let fingerprint = key.public_key().fingerprint(ssh_key::HashAlg::Sha256).to_string();
    let claimed = scoplen_model::new_uuid_v7().unwrap();
    let mut trust = object(
        ObjectType::TRUST_RECORD,
        vec![
            (2, Value::Text("*.test".into())),
            (3, Value::Text(key.public_key().to_openssh().unwrap())),
            (4, Value::Text(fingerprint.clone())),
            (5, Value::UInt(4)),
            (6, Value::UInt(1)),
            (7, Value::Bytes(claimed.as_bytes().to_vec())),
            (8, Value::Bytes(claimed.as_bytes().to_vec())),
            (9, Value::Bool(true)),
            (10, Value::Bool(true)),
        ],
    );
    let bytes = archive(std::slice::from_ref(&trust), SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    let key_preview = preview.entries[0].trust.as_ref().unwrap();
    assert_eq!(key_preview.algorithm, "ssh-ed25519");
    assert_eq!(key_preview.fingerprint, fingerprint);
    assert!(key_preview.requires_consent && key_preview.is_ca && key_preview.revoked);
    assert_eq!(
        service.import(&destination, bytes.as_slice(), None, &preview.id, ImportConsent::default()),
        Err(Error::ConsentRequired)
    );
    assert_eq!(counts(&destination), (0, 0, 0));
    service
        .import(
            &destination,
            bytes.as_slice(),
            None,
            &preview.id,
            ImportConsent {
                retain_secret_source_ids: vec![],
                trust_source_ids: vec![trust.id.to_string()],
            },
        )
        .unwrap();
    let target = mapped(&destination, trust.id);
    assert_eq!(target.required_uint(5).unwrap(), 2);
    assert!(target.required_uint(6).unwrap() > 1);
    assert_eq!(target.required_bytes(7).unwrap(), destination.device_id().as_bytes());
    assert!(target.set_field(8).is_none());
    assert_eq!(target.set_field(9).unwrap().value, Value::Bool(true));
    assert_eq!(target.set_field(10).unwrap().value, Value::Bool(true));
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert_eq!(preview.entries[0].action, ImportAction::Unchanged);
    assert!(!preview.entries[0].trust.as_ref().unwrap().requires_consent);
    service
        .import(&destination, bytes.as_slice(), None, &preview.id, ImportConsent::default())
        .unwrap();
    assert_eq!(mapped(&destination, trust.id), target);
    set(&mut trust, FieldPath::Field(9), Value::Bool(false));
    let bytes = archive(std::slice::from_ref(&trust), SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert!(preview.entries[0].trust.as_ref().unwrap().requires_consent);
    assert!(!preview.entries[0].trust.as_ref().unwrap().revoked);
    set(&mut trust, FieldPath::Field(4), Value::Text("SHA256:wrong".into()));
    let bytes = archive(&[trust], SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert_eq!(preview.entries[0].problem, Some(ImportProblem::InvalidTrust));
    assert!(!preview.can_import);
}

#[test]
fn snippet_omissions_clear_by_default_or_explicitly_retain_matching_secret_defaults() {
    let (_dir, destination) = store();
    let service = PortableArchives::default();
    let mut snippet = object(
        ObjectType::SNIPPET,
        vec![(1, Value::Text("snippet".into())), (2, Value::Text("{{token}}".into()))],
    );
    let path = FieldPath::MapEntry { field: 3, key: MapKey::Text("token".into()) };
    set(
        &mut snippet,
        path.clone(),
        Value::Map(vec![
            (Value::UInt(1), Value::UInt(4)),
            (Value::UInt(2), Value::Text("fixture secret".into())),
        ]),
    );
    let password = PortableExportPassphrase::new("archive fixture passphrase".into()).unwrap();
    let bytes = encrypted(std::slice::from_ref(&snippet), &password);
    let preview = service.preview(&destination, bytes.as_slice(), Some(&password)).unwrap();
    service
        .import(
            &destination,
            bytes.as_slice(),
            Some(&password),
            &preview.id,
            ImportConsent::default(),
        )
        .unwrap();
    let redacted = archive(std::slice::from_ref(&snippet), SecretMode::Omitted);
    let preview = service.preview(&destination, redacted.as_slice(), None).unwrap();
    assert!(preview.entries[0].retain_secret_available);
    service
        .import(
            &destination,
            redacted.as_slice(),
            None,
            &preview.id,
            ImportConsent {
                retain_secret_source_ids: vec![snippet.id.to_string()],
                trust_source_ids: vec![],
            },
        )
        .unwrap();
    assert_eq!(mapped(&destination, snippet.id).fields[&path].value, snippet.fields[&path].value);
    let preview = service.preview(&destination, redacted.as_slice(), None).unwrap();
    service
        .import(&destination, redacted.as_slice(), None, &preview.id, ImportConsent::default())
        .unwrap();
    assert_eq!(
        mapped(&destination, snippet.id).fields[&path].value,
        Value::Map(vec![(Value::UInt(1), Value::UInt(4))])
    );
}

fn personal(store: &Store) -> (Uuid, Uuid) {
    let account = scoplen_model::new_uuid_v7().unwrap();
    let vault = scoplen_model::new_uuid_v7().unwrap();
    let conn = store.conn();
    conn.execute("INSERT INTO personal_server(singleton,origin,account_id,personal_vault_id,device_name,private_material,enrollment_attempted) VALUES(1,'https://example.test',?1,?2,'test',X'00',1)",params![account.as_bytes().as_slice(),vault.as_bytes().as_slice()]).unwrap();
    conn.execute("INSERT INTO personal_sync VALUES(1,1,X'01',X'01',X'01')", []).unwrap();
    conn.execute("INSERT INTO personal_admission SELECT 1,p.origin,p.account_id,p.personal_vault_id,d.device_id,X'01' FROM personal_server p,device d WHERE p.singleton=1 AND d.singleton=1",[]).unwrap();
    (account, vault)
}

#[test]
fn personal_ownership_dirty_queue_and_receipts_commit_together_and_rollback_on_sql_failure() {
    let (_dir, destination) = store();
    let (account, vault) = personal(&destination);
    let service = PortableArchives::default();
    let bytes = archive(&[host("first"), host("second")], SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert_eq!(
        preview.destination,
        ArchiveDestination::Personal { owner_id: account.to_string(), vault_id: vault.to_string() }
    );
    destination.conn().execute_batch("CREATE TEMP TRIGGER fail_second_dirty BEFORE INSERT ON personal_sync_objects WHEN (SELECT count(*) FROM personal_sync_objects)>0 BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert_eq!(
        service.import(&destination, bytes.as_slice(), None, &preview.id, ImportConsent::default()),
        Err(Error::Storage)
    );
    assert_eq!(counts(&destination), (0, 0, 0));
    assert_eq!(
        destination
            .conn()
            .query_row("SELECT count(*) FROM personal_sync_objects", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        0
    );
    destination.conn().execute_batch("DROP TRIGGER fail_second_dirty").unwrap();
    assert_eq!(
        service
            .import(&destination, bytes.as_slice(), None, &preview.id, ImportConsent::default())
            .unwrap()
            .created,
        2
    );
    assert_eq!(destination.conn().query_row("SELECT count(*) FROM objects o JOIN personal_sync_objects s ON s.object_id=o.id WHERE o.vault=?1 AND s.vault=?1 AND dirty=1 AND base IS NULL",params![vault.as_bytes().as_slice()],|row|row.get::<_,i64>(0)).unwrap(),2);
    assert_eq!(counts(&destination), (2, 2, 0));
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    destination
        .conn()
        .execute("UPDATE personal_server SET auth_generation=auth_generation+1", [])
        .unwrap();
    assert_eq!(
        service.import(&destination, bytes.as_slice(), None, &preview.id, ImportConsent::default()),
        Err(Error::DestinationChanged)
    );
    assert_eq!(counts(&destination), (2, 2, 0));
    let purged: Vec<u8> = destination
        .conn()
        .query_row("SELECT object_id FROM portable_import_receipts LIMIT 1", [], |row| row.get(0))
        .unwrap();
    destination
        .conn()
        .execute("DELETE FROM personal_sync_objects WHERE object_id=?1", params![purged])
        .unwrap();
    destination.conn().execute("DELETE FROM objects WHERE id=?1", params![purged]).unwrap();
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert!(!preview.can_import);
    assert!(
        preview.entries.iter().any(|row| row.problem == Some(ImportProblem::IncompatibleTarget))
    );
    assert_eq!(counts(&destination), (1, 2, 0));
}

#[test]
fn personal_trust_acceptance_records_current_account_and_device_not_archive_claims() {
    let (_dir, destination) = store();
    let (account, _vault) = personal(&destination);
    let service = PortableArchives::default();
    let key =
        ssh_key::PrivateKey::new(ssh_key::private::Ed25519Keypair::from_seed(&[29; 32]).into(), "")
            .unwrap();
    let claimed = scoplen_model::new_uuid_v7().unwrap();
    let trust = object(
        ObjectType::TRUST_RECORD,
        vec![
            (2, Value::Text("*.test".into())),
            (3, Value::Text(key.public_key().to_openssh().unwrap())),
            (5, Value::UInt(4)),
            (6, Value::UInt(1)),
            (7, Value::Bytes(claimed.as_bytes().to_vec())),
            (8, Value::Bytes(claimed.as_bytes().to_vec())),
        ],
    );
    let bytes = archive(std::slice::from_ref(&trust), SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    service
        .import(
            &destination,
            bytes.as_slice(),
            None,
            &preview.id,
            ImportConsent {
                retain_secret_source_ids: vec![],
                trust_source_ids: vec![trust.id.to_string()],
            },
        )
        .unwrap();
    let target = mapped(&destination, trust.id);
    assert_eq!(target.required_uuid(8).unwrap(), account);
    assert_eq!(target.required_uuid(7).unwrap(), destination.device_id());
    assert_eq!(target.required_uint(5).unwrap(), 2);
    assert!(target.required_uint(6).unwrap() > 1);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert!(!preview.entries[0].trust.as_ref().unwrap().requires_consent);
    assert_eq!(preview.entries[0].action, ImportAction::Unchanged);
}

#[test]
fn unrelated_preference_key_and_deleted_receipt_target_block_the_whole_batch() {
    let (_dir, destination) = store();
    let service = PortableArchives::default();
    let preference = object(
        ObjectType::PREFERENCE,
        vec![(1, Value::Text("theme".into())), (2, Value::Text("dark".into()))],
    );
    destination
        .write(super::super::LocalWrite {
            id: None,
            object_type: ObjectType::PREFERENCE,
            fields: vec![
                (FieldPath::Field(1), Value::Text("theme".into())),
                (FieldPath::Field(2), Value::Text("light".into())),
            ],
        })
        .unwrap();
    let bytes = archive(&[preference], SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert_eq!(preview.entries[0].problem, Some(ImportProblem::PreferenceConflict));
    assert_eq!(counts(&destination), (1, 0, 0));
    let source = host("host");
    let bytes = archive(std::slice::from_ref(&source), SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    service
        .import(&destination, bytes.as_slice(), None, &preview.id, ImportConsent::default())
        .unwrap();
    let target = mapped(&destination, source.id);
    destination.delete(target.id).unwrap();
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert_eq!(preview.entries[0].problem, Some(ImportProblem::DeletedTarget));
    assert!(!preview.can_import);
}

#[test]
fn export_defaults_to_redacted_stream_and_includes_all_selected_live_types() {
    let (_dir, source) = store();
    let service = PortableArchives::default();
    source
        .write(super::super::LocalWrite {
            id: None,
            object_type: ObjectType::CREDENTIAL,
            fields: vec![
                (FieldPath::Field(2), Value::UInt(1)),
                (FieldPath::Field(3), Value::UInt(1)),
                (FieldPath::Field(4), Value::Bytes(b"fixture secret".to_vec())),
            ],
        })
        .unwrap();
    let mut bytes = Vec::new();
    let result = service.export(&source, &mut bytes, ExportOptions::default(), None).unwrap();
    assert_eq!(result.objects, 1);
    assert_eq!(result.destination, ArchiveDestination::Local);
    assert!(!String::from_utf8(bytes.clone()).unwrap().contains("fixture secret"));
    let mut entry = None;
    portable::read_archive(bytes.as_slice(), |value| {
        entry = Some(value);
        Ok(())
    })
    .unwrap();
    let entry = entry.unwrap();
    assert_eq!(entry.omitted_secrets(), ["/secret"]);
    assert!(!entry.fields().contains_key(&FieldPath::Field(4)));
    assert_eq!(
        service.export(
            &source,
            Vec::new(),
            ExportOptions { secrets: ArchiveSecretMode::Included },
            None
        ),
        Err(Error::PassphraseRequired)
    );
    let password = PortableExportPassphrase::new("archive fixture passphrase".into()).unwrap();
    let mut bytes = Vec::new();
    service
        .export(
            &source,
            &mut bytes,
            ExportOptions { secrets: ArchiveSecretMode::Included },
            Some(&password),
        )
        .unwrap();
    assert!(bytes.starts_with(b"age-encryption.org/v1\n"));
    let mut reader = PortableExportReader::new(bytes.as_slice(), &password).unwrap();
    let summary = portable::read_archive(&mut reader, |entry| {
        assert_eq!(entry.fields()[&FieldPath::Field(4)], Value::Bytes(b"fixture secret".to_vec()));
        Ok(())
    })
    .unwrap();
    reader.finish().unwrap();
    assert_eq!(summary.header.secrets, SecretMode::Included);
    source
        .write(super::super::LocalWrite {
            id: None,
            object_type: ObjectType::GATEWAY_NETWORK,
            fields: vec![(FieldPath::Field(1), Value::Text("managed".into()))],
        })
        .unwrap();
    assert_eq!(
        service.export(&source, Vec::new(), ExportOptions::default(), None).unwrap().objects,
        2
    );
}

#[test]
fn export_keeps_one_database_snapshot_even_if_another_connection_changes_the_source() {
    struct MutatingWriter {
        database: Connection,
        id: Uuid,
        replacement: Option<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Write for MutatingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if let Some(replacement) = self.replacement.take() {
                self.database
                    .execute(
                        "UPDATE objects SET envelope=?1 WHERE id=?2",
                        params![replacement, self.id.as_bytes().as_slice()],
                    )
                    .unwrap();
            }
            self.output.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (dir, source) = store();
    let original = source
        .create_batch(vec![super::super::NewObject {
            id: scoplen_model::new_uuid_v7().unwrap(),
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text("original".into())),
                (FieldPath::Field(2), Value::Text("host.test".into())),
            ],
        }])
        .unwrap()
        .remove(0);
    let mut changed = original.clone();
    changed.fields.get_mut(&FieldPath::Field(1)).unwrap().value = Value::Text("changed".into());
    let database = Connection::open(dir.path().join("local.db")).unwrap();
    super::super::apply_key(&database, &scoplen_crypto::LocalDatabaseKey::new([42; 32])).unwrap();
    let mut writer = MutatingWriter {
        database,
        id: original.id,
        replacement: Some(changed.encode().unwrap()),
        output: Vec::new(),
    };
    PortableArchives::default()
        .export(&source, &mut writer, ExportOptions::default(), None)
        .unwrap();
    portable::read_archive(writer.output.as_slice(), |entry| {
        assert_eq!(entry.fields()[&FieldPath::Field(1)], Value::Text("original".into()));
        Ok(())
    })
    .unwrap();
    assert_eq!(source.get(original.id).unwrap().unwrap().required_text(1).unwrap(), "changed");
}

#[test]
fn original_uuid_is_never_an_unrelated_target_and_duplicate_preferences_block_together() {
    let (_dir, destination) = store();
    let service = PortableArchives::default();
    let source = host("source");
    destination
        .create_batch(vec![super::super::NewObject {
            id: source.id,
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text("unrelated".into())),
                (FieldPath::Field(2), Value::Text("other.test".into())),
            ],
        }])
        .unwrap();
    let bytes = archive(std::slice::from_ref(&source), SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    service
        .import(&destination, bytes.as_slice(), None, &preview.id, ImportConsent::default())
        .unwrap();
    assert_ne!(mapped(&destination, source.id).id, source.id);
    assert_eq!(destination.get(source.id).unwrap().unwrap().required_text(1).unwrap(), "unrelated");
    let preferences = [
        object(ObjectType::PREFERENCE, vec![(1, Value::Text("duplicate".into()))]),
        object(ObjectType::PREFERENCE, vec![(1, Value::Text("duplicate".into()))]),
    ];
    let bytes = archive(&preferences, SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    assert!(!preview.can_import);
    assert!(
        preview.entries.iter().all(|row| row.problem == Some(ImportProblem::PreferenceConflict))
    );
}

#[test]
fn unknown_fields_are_reported_and_organization_sources_never_write_personal_data() {
    let (_dir, destination) = store();
    let service = PortableArchives::default();
    destination
        .write(super::super::LocalWrite {
            id: None,
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text("host".into())),
                (FieldPath::Field(2), Value::Text("host.test".into())),
                (FieldPath::Field(99), Value::Null),
            ],
        })
        .unwrap();
    assert_eq!(
        service.export(&destination, Vec::new(), ExportOptions::default(), None),
        Err(Error::UnsupportedData)
    );
    let bytes = archive(&[host("source")], SecretMode::Omitted);
    let text = String::from_utf8(bytes)
        .unwrap()
        .replace("\"kind\":\"device\"", "\"kind\":\"organization\"");
    assert_eq!(
        service.preview(&destination, text.as_bytes(), None),
        Err(Error::UnsupportedDestination)
    );
    assert_eq!(counts(&destination), (1, 0, 0));
}

#[test]
fn consented_imported_host_key_is_usable_with_ordinary_ssh_public_key_comments() {
    let (_dir, destination) = store();
    let service = PortableArchives::default();
    let source = host("host");
    let key = ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[27; 32]).into(),
        "ordinary key comment",
    )
    .unwrap();
    let fingerprint = key.public_key().fingerprint(ssh_key::HashAlg::Sha256).to_string();
    let trust = object(
        ObjectType::TRUST_RECORD,
        vec![
            (1, Value::Bytes(source.id.as_bytes().to_vec())),
            (3, Value::Text(key.public_key().to_openssh().unwrap())),
            (4, Value::Text(fingerprint.clone())),
        ],
    );
    let bytes = archive(&[source.clone(), trust.clone()], SecretMode::Omitted);
    let preview = service.preview(&destination, bytes.as_slice(), None).unwrap();
    service
        .import(
            &destination,
            bytes.as_slice(),
            None,
            &preview.id,
            ImportConsent {
                retain_secret_source_ids: vec![],
                trust_source_ids: vec![trust.id.to_string()],
            },
        )
        .unwrap();
    let mut public = key.public_key().clone();
    public.set_comment("");
    let presentation = crate::connection::HostKeyPresentation {
        algorithm: public.algorithm().to_string(),
        key: public.to_openssh().unwrap(),
        fingerprint,
    };
    assert_eq!(
        crate::connection::assess_host_key(
            &destination,
            mapped(&destination, source.id).id,
            &presentation
        )
        .unwrap()
        .status,
        crate::connection::HostKeyStatus::Trusted
    );
}

#[tokio::test]
async fn generated_software_key_survives_encrypted_export_import_reopen_and_real_ssh() {
    use crate::connection::preparation::{
        PreparationControl, PreparationEvent, PreparationResponse, prepare_connection,
    };
    use crate::connection::test_peer::{Authentication, Peer};
    use crate::inventory::{Inventory, NewHost, SignIn};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let peer = Peer::with_authentication(Authentication::KeyThenInteractive).await;
    let (_source_dir, source) = store();
    let inventory = Inventory::new(source.clone());
    let details = inventory
        .add_host(NewHost {
            name: Some("archive SSH fixture".into()),
            address: "127.0.0.1".into(),
            port: Some(peer.port),
            username: "trust-fixture".into(),
            sign_in: SignIn::GenerateKey,
        })
        .unwrap();
    let source_host = Uuid::parse_str(&details.summary.id).unwrap();
    let source_profile = Uuid::parse_str(&details.logins[0].id).unwrap();
    source
        .write(super::super::LocalWrite {
            id: None,
            object_type: ObjectType::TRUST_RECORD,
            fields: vec![
                (FieldPath::Field(1), Value::Bytes(source_host.as_bytes().to_vec())),
                (FieldPath::Field(3), Value::Text(peer.key.key.clone())),
                (FieldPath::Field(4), Value::Text(peer.key.fingerprint.clone())),
            ],
        })
        .unwrap();
    let password =
        PortableExportPassphrase::new("archive generated-key fixture passphrase".into()).unwrap();
    let service = PortableArchives::default();
    let mut bytes = Vec::new();
    service
        .export(
            &source,
            &mut bytes,
            ExportOptions { secrets: ArchiveSecretMode::Included },
            Some(&password),
        )
        .unwrap();
    let (dir, destination) = store();
    let preview = service.preview(&destination, bytes.as_slice(), Some(&password)).unwrap();
    assert!(preview.can_import);
    assert!(!serde_json::to_string(&preview).unwrap().contains("PRIVATE KEY"));
    let trust_source_ids = preview
        .entries
        .iter()
        .filter(|entry| entry.trust.as_ref().is_some_and(|trust| trust.requires_consent))
        .map(|entry| entry.source_id.clone())
        .collect();
    service
        .import(
            &destination,
            bytes.as_slice(),
            Some(&password),
            &preview.id,
            ImportConsent { retain_secret_source_ids: vec![], trust_source_ids },
        )
        .unwrap();
    let target_profile = mapped(&destination, source_profile).id;
    let before = crate::connection::resolve_connection_plan(&source, source_profile).unwrap();
    let after = crate::connection::resolve_connection_plan(&destination, target_profile).unwrap();
    assert_eq!(before.credential, after.credential);
    drop(destination);
    let destination =
        Store::open(&dir.path().join("local.db"), &scoplen_crypto::LocalDatabaseKey::new([42; 32]))
            .unwrap();
    let control = PreparationControl::default();
    let rounds = AtomicUsize::new(0);
    let connection = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        prepare_connection(&destination, target_profile, &control, |event| {
            match event {
                PreparationEvent::Trust { .. } => {
                    panic!("confirmed imported trust must already authorize this exact SSH peer")
                }
                PreparationEvent::KeyboardInteractive { prompt_id, prompts, .. } => {
                    let answers = match rounds.fetch_add(1, Ordering::SeqCst) {
                        0 => vec![b"visible".to_vec(), vec![]],
                        1 => vec![],
                        _ => vec![b"123456".to_vec()],
                    };
                    assert_eq!(prompts.len(), answers.len());
                    control.respond(
                        &prompt_id,
                        PreparationResponse::keyboard_interactive(answers).unwrap(),
                    )?;
                }
                _ => {}
            }
            Ok(())
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let mut session = connection.open_session().await.unwrap();
    let result = session.exec(b"printf scoplen-interactive-ok", None).await.unwrap();
    assert_eq!(result.stdout, b"scoplen-interactive-ok");
    assert_eq!(result.exit_status, Some(0));
    connection.close().await.unwrap();
    assert_eq!(rounds.load(Ordering::SeqCst), 3);
}
