// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::repository::{Provenance, TrustRecord, TrustRecordChange};
use scoplen_model::ObjectType;
use std::path::{Path, PathBuf};

fn inventory() -> (tempfile::TempDir, Inventory) {
    let dir = tempfile::tempdir().unwrap();
    let inventory = Inventory::new(Arc::new(
        Store::open(
            &dir.path().join("inventory.db"),
            &scoplen_crypto::LocalDatabaseKey::new([49; 32]),
        )
        .unwrap(),
    ));
    (dir, inventory)
}

fn key(dir: &Path, name: &str, seed: u8) -> PathBuf {
    let key = ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]).into(),
        "",
    )
    .unwrap();
    let path = dir.join(name);
    std::fs::write(&path, key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes()).unwrap();
    path
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn config(dir: &Path, text: &str) -> String {
    let path = dir.join("config");
    std::fs::write(&path, format!("{text}\nHost *\n UserKnownHostsFile none\n")).unwrap();
    path_text(&path)
}

fn password(inventory: &Inventory) -> Credential {
    Repository::<Credential>::new(&inventory.store)
        .create(CredentialChange {
            name: Edit::Set("Fixture password".into()),
            kind: Some(CredentialKind::Password),
            binding: Some(CredentialBinding::Shared),
            secret: Edit::Set(SecretVec::new(b"fixture-only-password".to_vec())),
            ..Default::default()
        })
        .unwrap()
}

#[test]
fn password_only_alias_can_choose_an_existing_usable_credential() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    let credential = password(&inventory);
    let source =
        config(dir.path(), "Host password-host\n HostName password.example\n IdentityFile none\n");
    let preview = inventory.preview_open_ssh_config(source.clone()).unwrap();
    assert!(preview.entries[0].needs_credential);
    assert!(preview.eligible_credentials.iter().any(|c| c.id == credential.meta.id.to_string()));
    let choices = vec![OpenSshImportChoice {
        alias: "password-host".into(),
        identity_file: None,
        credential_id: Some(credential.meta.id.to_string()),
    }];
    let preview = inventory.preview_open_ssh_config_with_choices(source.clone(), choices).unwrap();
    assert!(!preview.entries[0].needs_credential);
    let imported = inventory.import_open_ssh_config(preview).unwrap();
    let host_id = imported.hosts[0].summary.id.clone();
    let again = inventory.preview_open_ssh_config(source).unwrap();
    assert_eq!(again.entries[0].credential_id, Some(credential.meta.id.to_string()));
    assert_eq!(again.entries[0].action, OpenSshImportAction::Unchanged);
    let again = inventory.import_open_ssh_config(again).unwrap();
    assert_eq!((again.created, again.updated, again.unchanged), (0, 0, 1));
    assert_eq!(again.hosts[0].summary.id, host_id);
    assert_eq!(inventory.credentials_objects().unwrap().len(), 1);
}

#[test]
fn real_private_keys_import_into_nonempty_inventory_and_reimport_without_writes() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    inventory
        .add_host(NewHost {
            name: Some("existing".into()),
            address: "existing.example".into(),
            port: None,
            username: "existing".into(),
            sign_in: SignIn::Password { password: "fixture-only".into() },
        })
        .unwrap();
    let identity = key(dir.path(), "identity key", 4);
    let source = config(
        dir.path(),
        &format!(
            "Host prod\n HostName prod.example\n User deploy\n IdentityFile \"{}\"\n",
            path_text(&identity)
        ),
    );
    let source_bytes = std::fs::read(&source).unwrap();
    let preview = inventory.preview_open_ssh_config(source.clone()).unwrap();
    assert_eq!(preview.entries[0].action, OpenSshImportAction::Create);
    assert!(!serde_json::to_string(&preview).unwrap().contains("PRIVATE KEY"));
    let result = inventory.import_open_ssh_config(preview).unwrap();
    let host_id = result.hosts[0].summary.id.clone();
    let before = inventory.store.list(ObjectType::HOST).unwrap();
    let preview = inventory.preview_open_ssh_config(source).unwrap();
    assert_eq!(preview.entries[0].action, OpenSshImportAction::Unchanged);
    inventory.import_open_ssh_config(preview).unwrap();
    assert_eq!(before, inventory.store.list(ObjectType::HOST).unwrap());
    assert_eq!(inventory.hosts(HostSource::All, String::new()).unwrap().len(), 2);
    assert!(inventory.host(host_id).unwrap().is_some());
    assert_eq!(std::fs::read(dir.path().join("config")).unwrap(), source_bytes);
}

#[test]
fn include_order_wildcards_repeated_alias_and_outer_state_follow_openssh() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("10.conf"), "Host prod\n HostName first.example\n User first\n")
        .unwrap();
    std::fs::write(dir.path().join("20.conf"), "Host prod\n HostName second.example\n Port 2222\n")
        .unwrap();
    let source = config(
        dir.path(),
        &format!(
            "Include \"{}/*.conf\"\nUser parent-default\nHost *.example !excluded.example\n Port 2200\nHost prod excluded.example\n IdentityFile none\nHost *\n User final-default\n",
            path_text(dir.path())
        ),
    );
    let preview = inventory.preview_open_ssh_config(source).unwrap();
    let prod = preview.entries.iter().find(|row| row.alias == "prod").unwrap();
    assert_eq!((&*prod.address, &*prod.username, prod.port), ("first.example", "first", 2222));
    let excluded = preview.entries.iter().find(|row| row.alias == "excluded.example").unwrap();
    assert_eq!(excluded.port, 22);
    assert_eq!(excluded.username, "parent-default");
    assert_eq!(preview.files, 3);
    assert!(preview.unsupported.is_empty());
    assert_eq!(preview.entries.len(), 2);
}

#[test]
fn explicit_identity_choice_is_retained_and_key_file_changes_require_new_preview() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    let first = key(dir.path(), "first", 5);
    let second = key(dir.path(), "second", 6);
    let source = config(
        dir.path(),
        &format!(
            "Host prod\n IdentityFile {}\n IdentityFile {}\n",
            path_text(&first),
            path_text(&second)
        ),
    );
    let preview = inventory.preview_open_ssh_config(source.clone()).unwrap();
    assert!(preview.entries[0].needs_credential);
    let choice = vec![OpenSshImportChoice {
        alias: "prod".into(),
        identity_file: Some(path_text(&second)),
        credential_id: None,
    }];
    let preview = inventory.preview_open_ssh_config_with_choices(source.clone(), choice).unwrap();
    inventory.import_open_ssh_config(preview).unwrap();
    let again = inventory.preview_open_ssh_config(source.clone()).unwrap();
    assert_eq!(again.entries[0].identity_file, Some(path_text(&second)));
    assert_eq!(again.entries[0].action, OpenSshImportAction::Unchanged);
    key(dir.path(), "second", 7);
    assert_eq!(inventory.import_open_ssh_config(again), Err(OpenSshImportError::SourceChanged));
    let next = inventory.preview_open_ssh_config(source).unwrap();
    assert_eq!(next.entries[0].action, OpenSshImportAction::Update);
    let before = inventory.store.list(ObjectType::CREDENTIAL).unwrap();
    inventory.import_open_ssh_config(next).unwrap();
    let after = inventory.store.list(ObjectType::CREDENTIAL).unwrap();
    assert_eq!(before.len(), after.len());
    assert_eq!(before[0].id, after[0].id);
    assert_ne!(before, after);
}

#[test]
fn ordinary_known_hosts_becomes_host_bound_imported_trust() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    let identity = key(dir.path(), "identity", 8);
    let server = key(dir.path(), "server", 9);
    let server = ssh_key::PrivateKey::from_openssh(std::fs::read(&server).unwrap()).unwrap();
    let known = dir.path().join("known_hosts");
    std::fs::write(
        &known,
        format!("[prod.example]:2222 {}\n", server.public_key().to_openssh().unwrap()),
    )
    .unwrap();
    let source = config(
        dir.path(),
        &format!(
            "UserKnownHostsFile {}\nHost prod\n HostName prod.example\n Port 2222\n IdentityFile {}\n",
            path_text(&known),
            path_text(&identity)
        ),
    );
    let preview = inventory.preview_open_ssh_config(source.clone()).unwrap();
    assert_eq!(preview.entries[0].trust_records, 1);
    let result = inventory.import_open_ssh_config(preview).unwrap();
    let trust = Repository::<TrustRecord>::new(&inventory.store).list().unwrap();
    assert_eq!(trust.len(), 1);
    assert_eq!(trust[0].provenance, Some(Provenance::Imported));
    assert_eq!(trust[0].accepted_by_device, Some(inventory.store.device_id()));
    assert_eq!(trust[0].host, Some(Uuid::parse_str(&result.hosts[0].summary.id).unwrap()));
    let presentation = crate::connection::HostKeyPresentation {
        algorithm: server.public_key().algorithm().as_str().into(),
        key: server.public_key().to_openssh().unwrap(),
        fingerprint: server.public_key().fingerprint(ssh_key::HashAlg::Sha256).to_string(),
    };
    assert_eq!(
        crate::connection::assess_host_key(&inventory.store, trust[0].host.unwrap(), &presentation)
            .unwrap()
            .status,
        crate::connection::HostKeyStatus::Trusted
    );
    let repeated = inventory.preview_open_ssh_config(source).unwrap();
    assert_eq!(repeated.entries[0].action, OpenSshImportAction::Unchanged);
    inventory.import_open_ssh_config(repeated).unwrap();
    assert_eq!(trust, Repository::<TrustRecord>::new(&inventory.store).list().unwrap());
}

#[test]
fn config_and_target_changes_require_fresh_review_without_partial_import() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    let identity = key(dir.path(), "identity", 10);
    let text = format!(
        "UserKnownHostsFile none\nHost prod\n HostName first.example\n IdentityFile {}\n",
        path_text(&identity)
    );
    let source = config(dir.path(), &text);
    let preview = inventory.preview_open_ssh_config(source.clone()).unwrap();
    std::fs::write(&source, text.replace("first.example", "next.example")).unwrap();
    assert_eq!(inventory.import_open_ssh_config(preview), Err(OpenSshImportError::SourceChanged));
    assert!(inventory.hosts(HostSource::All, String::new()).unwrap().is_empty());
    let result = inventory
        .import_open_ssh_config(inventory.preview_open_ssh_config(source.clone()).unwrap())
        .unwrap();
    let host_id = Uuid::parse_str(&result.hosts[0].summary.id).unwrap();
    let preview = inventory.preview_open_ssh_config(source).unwrap();
    Repository::<Host>::new(&inventory.store)
        .update(
            host_id,
            HostChange { address: Some("edited.example".into()), ..Default::default() },
        )
        .unwrap();
    assert_eq!(
        inventory.import_open_ssh_config(preview),
        Err(OpenSshImportError::InventoryChanged)
    );
    assert_eq!(
        Repository::<Host>::new(&inventory.store).get(host_id).unwrap().unwrap().address,
        "edited.example"
    );
}

#[test]
fn jump_and_proxy_command_resolve_to_the_existing_route_model() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    let identity = key(dir.path(), "identity", 11);
    let source = config(
        dir.path(),
        &format!(
            "IdentityFile {}\nHost jump\n User gateway\nHost prod\n ProxyJump jump\nHost command\n ProxyCommand helper %h %p\n",
            path_text(&identity)
        ),
    );
    let preview = inventory.preview_open_ssh_config(source).unwrap();
    assert_eq!(preview.entries.len(), 3);
    let result = inventory.import_open_ssh_config(preview).unwrap();
    let target = result.hosts.iter().find(|host| host.summary.name == "prod").unwrap();
    let plan =
        resolve_connection_plan(&inventory.store, Uuid::parse_str(&target.logins[0].id).unwrap())
            .unwrap();
    assert!(
        matches!(plan.route,crate::connection::ConnectionRoute::Jump { ref hops } if hops.len()==1)
    );
    let target = result.hosts.iter().find(|host| host.summary.name == "command").unwrap();
    let plan =
        resolve_connection_plan(&inventory.store, Uuid::parse_str(&target.logins[0].id).unwrap())
            .unwrap();
    assert!(
        matches!(plan.route,crate::connection::ConnectionRoute::Command { ref command } if command=="helper %h %p")
    );
    assert_eq!(inventory.credentials_objects().unwrap().len(), 1);
}

#[test]
fn complete_unsupported_report_keeps_safe_aliases_and_names_included_sources() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    let child = dir.path().join("child");
    std::fs::write(
        &child,
        "Host blocked\n ForwardAgent yes\n ForwardX11 yes\nHost safe\n IdentityFile none\n",
    )
    .unwrap();
    let source = config(dir.path(), &format!("Include {}\n", path_text(&child)));
    let preview = inventory.preview_open_ssh_config(source).unwrap();
    assert_eq!(preview.entries.len(), 1);
    assert_eq!(preview.entries[0].alias, "safe");
    assert_eq!(preview.skipped_hosts.len(), 1);
    assert_eq!(preview.skipped_hosts[0].alias, "blocked");
    assert_eq!(preview.unsupported.len(), 2);
    assert!(preview.unsupported.iter().all(|row| row.source_file.ends_with("child")));
    assert_eq!(preview.unsupported.iter().map(|row| row.line).collect::<Vec<_>>(), vec![2, 3]);
}

#[test]
fn recursive_include_and_oversized_sources_are_rejected_without_writes() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    let source = config(dir.path(), "");
    std::fs::write(&source, format!("Include {}\nHost prod\n", source)).unwrap();
    assert!(matches!(
        inventory.preview_open_ssh_config(source.clone()),
        Err(OpenSshImportError::Failed { .. })
    ));
    std::fs::write(&source, "#".repeat(1024 * 1024 + 1)).unwrap();
    assert_eq!(inventory.preview_open_ssh_config(source), Err(OpenSshImportError::TooLarge));
    assert!(inventory.hosts(HostSource::All, String::new()).unwrap().is_empty());
}

#[test]
fn pending_identity_is_visible_without_creating_an_empty_agent() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config");
    std::fs::write(
        &path,
        "UserKnownHostsFile none\nHost prod\n HostName prod.example\n IdentityFile none\n",
    )
    .unwrap();
    let preview = inventory.preview_open_ssh_config(path.to_string_lossy().into()).unwrap();
    assert_eq!(preview.entries.len(), 1);
    assert!(preview.entries[0].needs_credential);
    assert_eq!(
        inventory.import_open_ssh_config(preview),
        Err(OpenSshImportError::CredentialsRequired)
    );
    assert!(inventory.hosts(HostSource::All, String::new()).unwrap().is_empty());
}

#[test]
fn invalid_implicit_identity_keeps_the_credential_picker_and_other_hosts_available() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    let invalid = dir.path().join("unsupported-pem");
    std::fs::write(&invalid, "-----BEGIN RSA PRIVATE KEY-----\ninvalid\n").unwrap();
    let valid = key(dir.path(), "valid", 13);
    let source = config(
        dir.path(),
        &format!(
            "Host invalid\n IdentityFile {}\nHost valid\n IdentityFile {}\n",
            path_text(&invalid),
            path_text(&valid)
        ),
    );
    let credential = password(&inventory);
    let preview = inventory.preview_open_ssh_config(source.clone()).unwrap();
    assert_eq!(preview.entries.len(), 2);
    assert!(preview.entries.iter().find(|row| row.alias == "invalid").unwrap().needs_credential);
    assert!(!preview.entries.iter().find(|row| row.alias == "valid").unwrap().needs_credential);
    let explicit = vec![OpenSshImportChoice {
        alias: "invalid".into(),
        identity_file: Some(path_text(&invalid)),
        credential_id: None,
    }];
    assert_eq!(
        inventory.preview_open_ssh_config_with_choices(source.clone(), explicit),
        Err(OpenSshImportError::CredentialUnavailable { alias: "invalid".into() })
    );
    let choice = vec![OpenSshImportChoice {
        alias: "invalid".into(),
        identity_file: None,
        credential_id: Some(credential.meta.id.to_string()),
    }];
    let preview = inventory.preview_open_ssh_config_with_choices(source, choice).unwrap();
    assert!(preview.entries.iter().all(|row| !row.needs_credential));
    assert_eq!(inventory.import_open_ssh_config(preview).unwrap().created, 2);
}

#[test]
fn unrepresentable_include_and_proxy_command_are_reported_without_silent_conversion() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    let source = config(
        dir.path(),
        &format!(
            "Host bracket\n Include {}/[0-9].conf\nHost shell\n ProxyCommand helper %h | other\nHost token\n ProxyCommand helper %n\nHost safe\n IdentityFile none\n",
            path_text(dir.path())
        ),
    );
    let preview = inventory.preview_open_ssh_config(source).unwrap();
    assert_eq!(
        preview.entries.iter().map(|row| row.alias.as_str()).collect::<Vec<_>>(),
        vec!["safe"]
    );
    assert_eq!(preview.skipped_hosts.len(), 3);
    assert_eq!(preview.unsupported.iter().map(|row| row.line).collect::<Vec<_>>(), vec![2, 4, 6]);
}

#[test]
fn ambiguous_and_revoked_known_keys_never_import_as_ordinary_trust() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    let identity = key(dir.path(), "identity", 14);
    let first = key(dir.path(), "first-server", 15);
    let second = key(dir.path(), "second-server", 16);
    let public = |file: &Path| {
        ssh_key::PrivateKey::from_openssh(std::fs::read(file).unwrap())
            .unwrap()
            .public_key()
            .to_openssh()
            .unwrap()
    };
    let first = public(&first);
    let second = public(&second);
    let known = dir.path().join("known_hosts");
    std::fs::write(
        &known,
        format!("prod.example {first}\nprod.example {second}\nprod.example {first}\n"),
    )
    .unwrap();
    let source = config(
        dir.path(),
        &format!(
            "UserKnownHostsFile {}\nHost prod\n HostName prod.example\n IdentityFile {}\n",
            path_text(&known),
            path_text(&identity)
        ),
    );
    let preview = inventory.preview_open_ssh_config(source.clone()).unwrap();
    assert_eq!(preview.entries[0].trust_records, 0);
    assert_eq!(preview.unsupported.len(), 1);
    inventory.import_open_ssh_config(preview).unwrap();
    assert!(Repository::<TrustRecord>::new(&inventory.store).list().unwrap().is_empty());
    std::fs::write(&known, format!("prod.example {first}\n")).unwrap();
    inventory
        .import_open_ssh_config(inventory.preview_open_ssh_config(source.clone()).unwrap())
        .unwrap();
    assert_eq!(Repository::<TrustRecord>::new(&inventory.store).list().unwrap().len(), 1);
    for text in [
        format!("prod.example {first}\n@revoked prod.example {first}\n"),
        format!("@revoked *.example {first}\nprod.example {first}\n"),
    ] {
        std::fs::write(&known, text).unwrap();
        let preview = inventory.preview_open_ssh_config(source.clone()).unwrap();
        assert_eq!(preview.entries[0].trust_records, 0);
        assert!(!preview.unsupported.is_empty());
        inventory.import_open_ssh_config(preview).unwrap();
        assert!(Repository::<TrustRecord>::new(&inventory.store).list().unwrap().is_empty());
    }
}

#[test]
fn reimport_refreshes_source_trust_for_retained_aliases_and_preserves_manual_trust() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    let identity = key(dir.path(), "identity", 17);
    let server = key(dir.path(), "server", 18);
    let server = ssh_key::PrivateKey::from_openssh(std::fs::read(server).unwrap()).unwrap();
    let known = dir.path().join("known_hosts");
    std::fs::write(&known, format!("prod.example {}\n", server.public_key().to_openssh().unwrap()))
        .unwrap();
    let text = format!(
        "UserKnownHostsFile {}\nHost prod\n HostName prod.example\n IdentityFile {}\n",
        path_text(&known),
        path_text(&identity)
    );
    let source = config(dir.path(), &text);
    let imported = inventory
        .import_open_ssh_config(inventory.preview_open_ssh_config(source.clone()).unwrap())
        .unwrap();
    let host = Uuid::parse_str(&imported.hosts[0].summary.id).unwrap();
    let records = Repository::<TrustRecord>::new(&inventory.store);
    let manual = records
        .create(TrustRecordChange {
            host: Edit::Set(host),
            key: Edit::Set(server.public_key().to_openssh().unwrap()),
            fingerprint: Edit::Set(
                server.public_key().fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            ),
            provenance: Some(Provenance::Manual),
            accepted_at: Edit::Set(1),
            accepted_by_device: Edit::Set(inventory.store.device_id()),
            ..Default::default()
        })
        .unwrap();
    std::fs::write(&source, text.replace("prod.example", "next.example")).unwrap();
    let preview = inventory.preview_open_ssh_config(source.clone()).unwrap();
    assert_eq!(preview.entries[0].trust_records, 0);
    assert_eq!(preview.entries[0].action, OpenSshImportAction::Update);
    inventory.import_open_ssh_config(preview).unwrap();
    assert_eq!(records.list().unwrap(), vec![manual]);
    let preview = inventory.preview_open_ssh_config(source.clone()).unwrap();
    assert_eq!(preview.entries[0].action, OpenSshImportAction::Unchanged);
    std::fs::write(&source, &text).unwrap();
    inventory
        .import_open_ssh_config(inventory.preview_open_ssh_config(source.clone()).unwrap())
        .unwrap();
    assert_eq!(records.list().unwrap().len(), 2);
    std::fs::write(&known, "").unwrap();
    let preview = inventory.preview_open_ssh_config(source.clone()).unwrap();
    assert_eq!(preview.entries[0].action, OpenSshImportAction::Update);
    inventory.import_open_ssh_config(preview).unwrap();
    assert_eq!(records.list().unwrap().len(), 1);
    assert!(inventory.host(host.to_string()).unwrap().is_some());
    std::fs::write(&known, format!("prod.example {}\n", server.public_key().to_openssh().unwrap()))
        .unwrap();
    inventory
        .import_open_ssh_config(inventory.preview_open_ssh_config(source.clone()).unwrap())
        .unwrap();
    assert_eq!(records.list().unwrap().len(), 2);
    std::fs::write(&source, text.replace("Host prod", "Host other")).unwrap();
    inventory.import_open_ssh_config(inventory.preview_open_ssh_config(source).unwrap()).unwrap();
    assert!(inventory.host(host.to_string()).unwrap().is_some());
    assert_eq!(records.list().unwrap().len(), 3);
}

#[test]
fn encrypted_and_public_identity_files_keep_the_existing_authentication_models() {
    let (_store, inventory) = inventory();
    let dir = tempfile::tempdir().unwrap();
    let identity = key(dir.path(), "encrypted", 19);
    let key = ssh_key::PrivateKey::from_openssh(std::fs::read(&identity).unwrap()).unwrap();
    let public = dir.path().join("agent.pub");
    std::fs::write(&public, key.public_key().to_openssh().unwrap()).unwrap();
    let encrypted = key
        .encrypt(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            b"disposable-passphrase",
        )
        .unwrap();
    std::fs::write(&identity, encrypted.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes())
        .unwrap();
    let source = config(
        dir.path(),
        &format!(
            "Host encrypted\n IdentityFile {}\nHost agent\n IdentityFile {}\n",
            path_text(&identity),
            path_text(&public)
        ),
    );
    let imported = inventory
        .import_open_ssh_config(inventory.preview_open_ssh_config(source).unwrap())
        .unwrap();
    for host in imported.hosts {
        let plan =
            resolve_connection_plan(&inventory.store, Uuid::parse_str(&host.logins[0].id).unwrap())
                .unwrap();
        if host.summary.name == "encrypted" {
            assert!(crate::connection::private_key_passphrase_required(&plan.credential).unwrap());
            assert!(matches!(
                plan.credential,
                crate::connection::CredentialMaterial::PrivateKey(_)
            ));
        } else {
            assert!(matches!(
                plan.credential,
                crate::connection::CredentialMaterial::Agent { public_key: Some(_) }
            ));
        }
    }
}
