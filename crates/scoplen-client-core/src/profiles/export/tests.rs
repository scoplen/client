// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    inventory::{Inventory, NewHost, SignIn},
    testing::{FAST, MemoryKeystore},
};

fn factory(slot: &MemoryKeystore) -> KeyStoreFactory {
    let slot = slot.clone();
    Arc::new(move |_| Some(Box::new(slot.clone())))
}

#[test]
fn existing_export_refuses_a_keychain_prompt_without_replacing_the_slot() {
    use scoplen_client_platform::keystore::{Keystore, KeystoreError};
    use zeroize::Zeroizing;

    struct RefusedRead(fn() -> KeystoreError);
    impl Keystore for RefusedRead {
        fn name(&self) -> &'static str {
            "test keystore"
        }
        fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeystoreError> {
            Err(self.0())
        }
        fn store(&self, _: &[u8]) -> Result<(), KeystoreError> {
            panic!("export attempted to replace a protected key")
        }
        fn delete(&self) -> Result<(), KeystoreError> {
            panic!("export attempted to delete a protected key")
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(STORE_FILE);
    std::fs::write(&path, b"existing store").unwrap();
    let failures = [
        (
            RefusedRead(|| KeystoreError::InteractionRequired),
            OpenSshExportProfileError::InteractionRequired,
            "interactive session",
        ),
        (
            RefusedRead(|| KeystoreError::AuthorizationFailed(MacKeychain::DataProtection)),
            OpenSshExportProfileError::KeyAuthorizationFailed(MacKeychain::DataProtection),
            "both executables' Keychain entitlements",
        ),
        (
            RefusedRead(|| KeystoreError::AuthorizationFailed(MacKeychain::Login)),
            OpenSshExportProfileError::KeyAuthorizationFailed(MacKeychain::Login),
            "verify the helper and item",
        ),
        (
            RefusedRead(|| KeystoreError::Platform {
                keystore: "private keystore detail",
                operation: "read",
                detail: "private system error".into(),
            }),
            OpenSshExportProfileError::KeyReadFailed,
            "desktop client",
        ),
    ];
    for (RefusedRead(failure), expected, action) in failures {
        let keys: KeyStoreFactory = Arc::new(move |_| Some(Box::new(RefusedRead(failure))));
        assert_eq!(
            OpenSshExportProfile::with_keystores(
                directory.path(),
                None,
                None,
                Some("passphrase"),
                &keys
            )
            .err(),
            Some(expected)
        );
        assert_eq!(
            OpenSshExportProfile::list_with_keystores(directory.path(), None, &keys),
            Err(expected)
        );
        let message = expected.to_string();
        assert!(message.contains(action));
        assert!(!message.contains("private"));
    }
    assert_eq!(std::fs::read(path).unwrap(), b"existing store");
}

fn database(directory: &Path, slot: &MemoryKeystore) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(directory.join(STORE_FILE)).unwrap();
    let keys = slot.0.lock().unwrap();
    let key = zeroize::Zeroizing::new(
        keys.as_ref().unwrap()[1..].iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
    );
    let pragma = zeroize::Zeroizing::new(format!("x'{}'", key.as_str()));
    conn.pragma_update(None, "key", pragma.as_str()).unwrap();
    conn
}

#[test]
fn local_export_is_read_only_and_keeps_the_desktop_owner_and_team_view_usable() {
    let directory = tempfile::tempdir().unwrap();
    let slot = MemoryKeystore::default();
    let local = Arc::new(LocalData::start(directory.path(), Some(Box::new(slot.clone()))).unwrap());
    let desktop =
        AccountProfiles::new(local.clone(), Arc::new(PersonalSyncRuntime::default())).unwrap();
    let lease = desktop.current().unwrap();
    let original = local.store().unwrap();
    let conn = database(directory.path(), &slot);
    let account = scoplen_model::new_uuid_v7().unwrap();
    let organization = scoplen_model::new_uuid_v7().unwrap();
    let generation = scoplen_model::new_uuid_v7().unwrap();
    let vault = scoplen_model::new_uuid_v7().unwrap();
    conn.execute(
        "INSERT INTO team_asset_views(origin,account_id,organization_id,generation,vault_id,revision,cursor,phase,acknowledged)
         VALUES('https://example.test',?1,?2,?3,?4,?5,?5,1,1)",
        rusqlite::params![account.as_bytes().as_slice(), organization.as_bytes().as_slice(),
            generation.as_bytes().as_slice(), vault.as_bytes().as_slice(), 1_u64.to_be_bytes().as_slice()],
    ).unwrap();
    let opening =
        OpenSshExportProfile::with_keystores(directory.path(), None, None, None, &factory(&slot))
            .unwrap();
    assert!(!Arc::ptr_eq(&opening.store(), &original));
    assert!(
        OpenSshExportProfile::list_with_keystores(directory.path(), None, &factory(&slot))
            .unwrap()
            .is_empty()
    );
    assert!(
        opening
            .store()
            .write(crate::store::LocalWrite {
                id: None,
                object_type: scoplen_model::ObjectType::HOST,
                fields: vec![(
                    scoplen_model::FieldPath::Field(1),
                    scoplen_model::cbor::Value::Text("refused".into())
                )],
            })
            .is_err()
    );
    assert_eq!(desktop.current().unwrap().generation(), lease.generation());
    desktop
        .with_current_store(&lease, |store| {
            Inventory::new(store.clone())
                .add_host(NewHost {
                    name: Some("Desktop after CLI".into()),
                    address: "example.test".into(),
                    port: None,
                    username: "deploy".into(),
                    sign_in: SignIn::Password { password: "local-export-fixture".into() },
                })
                .unwrap();
        })
        .unwrap();
    let preview = Inventory::new(opening.store()).preview_generated_open_ssh(vec![]).unwrap();
    assert_eq!(preview.report.entries.len(), 1);
    opening.recheck().unwrap();
    let state: (i64, bool) = conn
        .query_row("SELECT phase,acknowledged FROM team_asset_views", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(state, (1, true));
    assert!(!directory.path().join("openssh").exists());
}

#[test]
fn missing_store_never_creates_directories_keys_or_replacement_data() {
    let parent = tempfile::tempdir().unwrap();
    let directory = parent.path().join("missing");
    let slot = MemoryKeystore::default();
    assert!(matches!(
        OpenSshExportProfile::with_keystores(&directory, None, None, None, &factory(&slot)),
        Err(OpenSshExportProfileError::MissingData)
    ));
    assert!(!directory.exists());
    assert!(slot.0.lock().unwrap().is_none());
    assert_eq!(
        OpenSshExportProfile::list_with_keystores(&directory, None, &factory(&slot)),
        Err(OpenSshExportProfileError::MissingData)
    );
}

#[test]
fn existing_local_key_is_required_without_creating_a_missing_slot() {
    let directory = tempfile::tempdir().unwrap();
    let slot = MemoryKeystore::default();
    let local = LocalData::start(directory.path(), Some(Box::new(slot.clone()))).unwrap();
    drop(local);
    *slot.0.lock().unwrap() = None;
    assert!(matches!(
        OpenSshExportProfile::with_keystores(directory.path(), None, None, None, &factory(&slot)),
        Err(OpenSshExportProfileError::KeyUnavailable)
    ));
    assert!(slot.0.lock().unwrap().is_none());
}

#[test]
fn export_distinguishes_malformed_key_material_from_an_unreadable_encrypted_store() {
    let directory = tempfile::tempdir().unwrap();
    let slot = MemoryKeystore::default();
    let local = LocalData::start(directory.path(), Some(Box::new(slot.clone()))).unwrap();
    let original = slot.0.lock().unwrap().clone().unwrap();
    let mut other = original.clone();
    other[1] ^= 1;
    for (key, expected) in [
        (vec![0], OpenSshExportProfileError::MalformedKey),
        (other, OpenSshExportProfileError::StoreKeyRejected),
    ] {
        *slot.0.lock().unwrap() = Some(key.clone());
        assert_eq!(
            OpenSshExportProfile::list_with_keystores(directory.path(), None, &factory(&slot)),
            Err(expected)
        );
        assert!(slot.0.lock().unwrap().as_ref() == Some(&key));
    }
    *slot.0.lock().unwrap() = Some(original);
    assert!(
        OpenSshExportProfile::list_with_keystores(directory.path(), None, &factory(&slot)).is_ok()
    );
    assert!(local.store().is_some());
}

#[test]
fn an_account_export_never_accepts_an_unbound_candidate_with_the_expected_device() {
    let directory = tempfile::tempdir().unwrap();
    let slot = MemoryKeystore::default();
    let data = LocalData::start(directory.path(), Some(Box::new(slot.clone()))).unwrap();
    let store = data.store().unwrap();
    let expected = ProfileRecord {
        profile: AccountProfile {
            id: scoplen_model::new_uuid_v7().unwrap(),
            origin: "https://example.test".into(),
            account_id: scoplen_model::new_uuid_v7().unwrap(),
            personal_vault_id: scoplen_model::new_uuid_v7().unwrap(),
            device_id: store.device_id(),
            operation_id: scoplen_model::new_uuid_v7().unwrap(),
            ready: true,
        },
        payload: SecretVec::new(vec![1]),
        signature: [0; 64],
        confirmation: SecretVec::new(vec![1]),
    };
    let Unlock::Ready(key, _) =
        LocalKeys::new(directory.path(), Some(Box::new(slot))).existing().unwrap()
    else {
        panic!("fixture key");
    };
    assert!(matches!(
        Store::open_export_profile(&directory.path().join(STORE_FILE), &key, Some(&expected)),
        Err(StoreError::AccountContext)
    ));
    assert!(store.account_profile_binding().unwrap().is_none());
}

#[test]
fn exact_local_passphrase_unlocks_without_changing_its_protection() {
    let directory = tempfile::tempdir().unwrap();
    let slot = MemoryKeystore::default();
    let keys = LocalKeys::new(directory.path(), Some(Box::new(slot.clone()))).with_params(FAST);
    let data = LocalData::with_profile(keys, None).unwrap();
    let passphrase = " local export \n";
    data.set_passphrase(passphrase).unwrap();
    let before = slot.0.lock().unwrap().clone();
    assert!(matches!(
        OpenSshExportProfile::with_keystores(directory.path(), None, None, None, &factory(&slot)),
        Err(OpenSshExportProfileError::Locked)
    ));
    assert!(matches!(
        OpenSshExportProfile::with_keystores(
            directory.path(),
            None,
            None,
            Some(passphrase.trim()),
            &factory(&slot)
        ),
        Err(OpenSshExportProfileError::WrongPassphrase)
    ));
    let opening = OpenSshExportProfile::with_keystores(
        directory.path(),
        None,
        None,
        Some(passphrase),
        &factory(&slot),
    )
    .unwrap();
    opening.recheck().unwrap();
    assert_eq!(*slot.0.lock().unwrap(), before);
}

#[test]
fn older_newer_schema_missing_device_and_unknown_profile_are_refused_without_repair() {
    for version in [0, i32::MAX as u32] {
        let directory = tempfile::tempdir().unwrap();
        let slot = MemoryKeystore::default();
        let data = LocalData::start(directory.path(), Some(Box::new(slot.clone()))).unwrap();
        let store = data.store().unwrap();
        database(directory.path(), &slot).pragma_update(None, "user_version", version).unwrap();
        assert!(matches!(
            OpenSshExportProfile::with_keystores(
                directory.path(),
                None,
                None,
                None,
                &factory(&slot)
            ),
            Err(OpenSshExportProfileError::Schema)
        ));
        assert_eq!(store.schema_version().unwrap(), version);
    }
    let directory = tempfile::tempdir().unwrap();
    let slot = MemoryKeystore::default();
    let data = LocalData::start(directory.path(), Some(Box::new(slot.clone()))).unwrap();
    assert!(data.store().is_some());
    assert!(matches!(
        OpenSshExportProfile::with_keystores(
            directory.path(),
            Some(scoplen_model::new_uuid_v7().unwrap()),
            None,
            None,
            &factory(&slot)
        ),
        Err(OpenSshExportProfileError::ProfileUnavailable)
    ));
    let conn = database(directory.path(), &slot);
    conn.execute("DELETE FROM device", []).unwrap();
    assert!(matches!(
        OpenSshExportProfile::with_keystores(directory.path(), None, None, None, &factory(&slot)),
        Err(OpenSshExportProfileError::Verification)
    ));
    let devices: i64 = conn.query_row("SELECT count(*) FROM device", [], |row| row.get(0)).unwrap();
    assert_eq!(devices, 0);
}
