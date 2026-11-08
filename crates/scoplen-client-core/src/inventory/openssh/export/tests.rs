// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    inventory::SignIn,
    repository::{Provenance, TrustRecordChange},
};

fn fixture() -> (tempfile::TempDir, Inventory) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(
        &dir.path().join("inventory.db"),
        &scoplen_crypto::LocalDatabaseKey::new([51; 32]),
    )
    .unwrap();
    (dir, Inventory::new(Arc::new(store)))
}

fn password(inventory: &Inventory, name: &str) -> HostDetails {
    inventory
        .add_host(NewHost {
            name: Some(name.into()),
            address: "fixture.example".into(),
            port: Some(2200),
            username: "deploy".into(),
            sign_in: SignIn::Password { password: "disposable-export-password".into() },
        })
        .unwrap()
}

fn private(seed: u8) -> ssh_key::PrivateKey {
    ssh_key::PrivateKey::new(ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]).into(), "")
        .unwrap()
}

fn add_private(inventory: &Inventory, file: &Path, seed: u8) -> HostDetails {
    let key = private(seed);
    std::fs::write(file, key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes()).unwrap();
    let source = file.with_extension("conf");
    std::fs::write(
        &source,
        format!(
            "Host imported\n HostName fixture.example\n User deploy\n IdentityFile {}\n",
            quoted(&export_path(file))
        ),
    )
    .unwrap();
    let preview = inventory.preview_open_ssh_config(parse::display(&source)).unwrap();
    inventory.import_open_ssh_config(preview).unwrap().hosts.remove(0)
}

#[test]
fn password_export_is_read_only_and_does_not_emit_secret_or_infer_a_key() {
    let (dir, inventory) = fixture();
    password(&inventory, "Fixture\nHost injected");
    let before = inventory.store.list(scoplen_model::ObjectType::CREDENTIAL).unwrap();
    let preview = inventory.preview_open_ssh_export(vec![]).unwrap();
    assert_eq!(preview.entries.len(), 1);
    assert_eq!(preview.trust_records, 0);
    assert!(!serde_json::to_string(&preview).unwrap().contains("disposable-export-password"));
    let output = inventory.export_open_ssh_config(preview, dir.path().into()).unwrap();
    let config = std::fs::read_to_string(Path::new(&output.directory).join("config")).unwrap();
    assert!(config.contains("PreferredAuthentications password\n  IdentityFile none"));
    assert!(config.contains("# Fixture Host injected / deploy"));
    assert_eq!(config.lines().filter(|line| line.starts_with("Host ")).count(), 1);
    assert!(!config.contains("disposable-export-password"));
    assert_eq!(before, inventory.store.list(scoplen_model::ObjectType::CREDENTIAL).unwrap());
    assert_eq!(output.files, 2);
}

#[test]
fn imported_source_is_discovered_and_actual_saved_key_controls_matching() {
    let (dir, inventory) = fixture();
    let file = dir.path().join("source identity");
    let host = add_private(&inventory, &file, 6);
    let profile = Uuid::parse_str(&host.logins[0].id).unwrap();
    let credential = Repository::<AccessProfile>::new(&inventory.store)
        .get(profile)
        .unwrap()
        .unwrap()
        .credential
        .unwrap();
    Repository::<Credential>::new(&inventory.store)
        .update(
            credential,
            CredentialChange {
                public_key: Edit::Set(private(7).public_key().to_openssh().unwrap()),
                ..Default::default()
            },
        )
        .unwrap();
    let preview = inventory.preview_open_ssh_export(vec![]).unwrap();
    assert_eq!(preview.entries[0].authentication, OpenSshExportAuthentication::IdentityFile);
    assert_eq!(preview.entries[0].identity_file, Some(export_path(&file.canonicalize().unwrap())));
    let wrong = dir.path().join("wrong");
    std::fs::write(&wrong, private(7).to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes())
        .unwrap();
    let refused = inventory
        .preview_open_ssh_export(vec![OpenSshExportChoice {
            profile_id: profile.to_string(),
            identity_file: parse::display(&wrong),
        }])
        .unwrap();
    assert!(refused.entries.is_empty());
    assert_eq!(refused.skipped[0].reason, OpenSshExportSkipReason::IdentityFileMismatch);
    std::fs::remove_file(&file).unwrap();
    let missing = inventory.preview_open_ssh_export(vec![]).unwrap();
    assert_eq!(missing.skipped[0].reason, OpenSshExportSkipReason::IdentityFileRequired);
}

#[test]
fn reviewed_source_and_inventory_changes_refuse_before_creating_a_directory() {
    let (dir, inventory) = fixture();
    let file = dir.path().join("source identity");
    let host = add_private(&inventory, &file, 8);
    let preview = inventory.preview_open_ssh_export(vec![]).unwrap();
    let mut changed = private(8);
    changed.set_comment("changed source comment");
    std::fs::write(&file, changed.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes()).unwrap();
    let target = dir.path().join("uncreated");
    assert_eq!(
        inventory.export_open_ssh_into(preview, target.clone()),
        Err(OpenSshExportError::SourceChanged)
    );
    assert!(!target.exists());
    let preview = inventory.preview_open_ssh_export(vec![]).unwrap();
    Repository::<Host>::new(&inventory.store)
        .update(
            Uuid::parse_str(&host.summary.id).unwrap(),
            HostChange { address: Some("changed.example".into()), ..Default::default() },
        )
        .unwrap();
    assert_eq!(
        inventory.export_open_ssh_into(preview, target.clone()),
        Err(OpenSshExportError::InventoryChanged)
    );
    assert!(!target.exists());
}

#[test]
fn existing_destination_is_untouched_and_tampered_review_is_rejected() {
    let (dir, inventory) = fixture();
    password(&inventory, "Fixture");
    let preview = inventory.preview_open_ssh_export(vec![]).unwrap();
    let target = dir.path().join("existing");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("keep"), "preserve").unwrap();
    assert_eq!(
        inventory.export_open_ssh_into(preview.clone(), target.clone()),
        Err(OpenSshExportError::DestinationExists)
    );
    assert_eq!(std::fs::read_to_string(target.join("keep")).unwrap(), "preserve");
    let mut tampered = preview;
    tampered.entries[0].address = "other.example".into();
    assert_eq!(
        inventory.export_open_ssh_into(tampered, dir.path().join("absent")),
        Err(OpenSshExportError::InvalidSelection)
    );
}

#[test]
fn unsupported_hop_blocks_dependent_target_without_direct_downgrade() {
    let (_dir, inventory) = fixture();
    let hop = password(&inventory, "Hop");
    let target = password(&inventory, "Target");
    let hop_id = Uuid::parse_str(&hop.logins[0].id).unwrap();
    let target_id = Uuid::parse_str(&target.logins[0].id).unwrap();
    let route = Repository::<Route>::new(&inventory.store)
        .create(RouteChange {
            name: Some("Jump".into()),
            kind: Some(RouteKind::Jump { hops: vec![hop_id] }),
        })
        .unwrap();
    Repository::<AccessProfile>::new(&inventory.store)
        .update(
            target_id,
            AccessProfileChange {
                route: Some(RouteChoice::Route(route.meta.id)),
                ..Default::default()
            },
        )
        .unwrap();
    let preview = inventory.preview_open_ssh_export(vec![]).unwrap();
    assert_eq!(preview.entries.len(), 2);
    Repository::<AccessProfile>::new(&inventory.store)
        .update(hop_id, AccessProfileChange { agent_forwarding: Some(true), ..Default::default() })
        .unwrap();
    let refused = inventory.preview_open_ssh_export(vec![]).unwrap();
    assert!(refused.entries.is_empty());
    assert!(
        refused.skipped.iter().any(|row| row.reason == OpenSshExportSkipReason::RouteDependency)
    );
    assert!(
        refused.skipped.iter().any(|row| row.reason == OpenSshExportSkipReason::UnsupportedOptions)
    );
}

fn trust(inventory: &Inventory, host: &HostDetails, seed: u8, revoked: bool) {
    let key = private(seed).public_key().clone();
    Repository::<TrustRecord>::new(&inventory.store)
        .create(TrustRecordChange {
            host: Edit::Set(Uuid::parse_str(&host.summary.id).unwrap()),
            key: Edit::Set(key.to_openssh().unwrap()),
            fingerprint: Edit::Set(key.fingerprint(ssh_key::HashAlg::Sha256).to_string()),
            provenance: Some(Provenance::Manual),
            revoked: Some(revoked),
            ..Default::default()
        })
        .unwrap();
}

#[test]
fn independent_hosts_at_the_same_endpoint_keep_distinct_trust_aliases() {
    let (dir, inventory) = fixture();
    let first = password(&inventory, "First");
    let second = password(&inventory, "Second");
    trust(&inventory, &first, 11, false);
    trust(&inventory, &second, 12, false);
    let preview = inventory.preview_open_ssh_export(vec![]).unwrap();
    assert_eq!(preview.trust_records, 2);
    let result = inventory.export_open_ssh_config(preview, dir.path().into()).unwrap();
    let path = Path::new(&result.directory).join("config");
    let known = std::fs::read_to_string(Path::new(&result.directory).join("known_hosts")).unwrap();
    assert_eq!(
        known
            .lines()
            .map(|line| line.split_whitespace().next().unwrap())
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
    let preview = inventory.preview_open_ssh_config(parse::display(&path)).unwrap();
    assert!(preview.unsupported.is_empty());
    assert!(preview.entries.iter().all(|row| row.trust_records == 1 && row.needs_credential));
}

#[test]
fn revoked_saved_trust_is_diagnosed_instead_of_exported_as_ordinary_trust() {
    let (_dir, inventory) = fixture();
    let host = password(&inventory, "Fixture");
    trust(&inventory, &host, 14, true);
    let preview = inventory.preview_open_ssh_export(vec![]).unwrap();
    assert!(preview.entries.is_empty());
    assert_eq!(preview.skipped[0].reason, OpenSshExportSkipReason::UnsupportedOptions);
}

#[test]
fn password_round_trip_requires_password_choice_and_rejects_key_choice() {
    let (dir, inventory) = fixture();
    let original = password(&inventory, "Fixture");
    let exported = inventory
        .export_open_ssh_config(
            inventory.preview_open_ssh_export(vec![]).unwrap(),
            dir.path().into(),
        )
        .unwrap();
    let path = parse::display(&Path::new(&exported.directory).join("config"));
    let preview = inventory.preview_open_ssh_config(path.clone()).unwrap();
    let alias = preview.entries[0].alias.clone();
    let profile = Repository::<AccessProfile>::new(&inventory.store)
        .get(Uuid::parse_str(&original.logins[0].id).unwrap())
        .unwrap()
        .unwrap();
    assert!(preview.entries[0].identity_files.is_empty());
    let selected = inventory
        .preview_open_ssh_config_with_choices(
            path.clone(),
            vec![OpenSshImportChoice {
                alias: alias.clone(),
                identity_file: None,
                credential_id: Some(profile.credential.unwrap().to_string()),
            }],
        )
        .unwrap();
    assert!(!selected.entries[0].needs_credential);
    let agent = Repository::<Credential>::new(&inventory.store)
        .create(CredentialChange {
            kind: Some(CredentialKind::Agent),
            binding: Some(CredentialBinding::None),
            public_key: Edit::Set(private(15).public_key().to_openssh().unwrap()),
            ..Default::default()
        })
        .unwrap();
    assert!(matches!(
        inventory.preview_open_ssh_config_with_choices(
            path,
            vec![OpenSshImportChoice {
                alias,
                identity_file: None,
                credential_id: Some(agent.meta.id.to_string())
            }]
        ),
        Err(OpenSshImportError::CredentialUnavailable { .. })
    ));
}

#[test]
fn empty_export_and_invalid_selection_never_create_output() {
    let (dir, inventory) = fixture();
    let preview = inventory.preview_open_ssh_export(vec![]).unwrap();
    let target = dir.path().join("empty");
    assert_eq!(
        inventory.export_open_ssh_into(preview, target.clone()),
        Err(OpenSshExportError::Empty)
    );
    assert!(!target.exists());
    assert_eq!(
        inventory.preview_open_ssh_export(vec![OpenSshExportChoice {
            profile_id: Uuid::nil().to_string(),
            identity_file: "unused".into()
        }]),
        Err(OpenSshExportError::InvalidSelection)
    );
}

#[test]
fn missing_login_unsupported_credential_route_and_invalid_values_have_explicit_rows() {
    let (_dir, inventory) = fixture();
    let no_login = Repository::<Host>::new(&inventory.store)
        .create(HostChange {
            name: Some("No Login".into()),
            address: Some("empty.example".into()),
            ..Default::default()
        })
        .unwrap();
    let unsupported = password(&inventory, "Interactive");
    let profile = Repository::<AccessProfile>::new(&inventory.store)
        .get(Uuid::parse_str(&unsupported.logins[0].id).unwrap())
        .unwrap()
        .unwrap();
    Repository::<Credential>::new(&inventory.store)
        .update(
            profile.credential.unwrap(),
            CredentialChange {
                kind: Some(CredentialKind::KeyboardInteractive),
                binding: Some(CredentialBinding::None),
                secret: Edit::Clear,
                ..Default::default()
            },
        )
        .unwrap();
    let routed = password(&inventory, "Command route");
    let route = Repository::<Route>::new(&inventory.store)
        .create(RouteChange {
            name: Some("Command".into()),
            kind: Some(RouteKind::Command { command: "helper %h %p".into() }),
        })
        .unwrap();
    Repository::<AccessProfile>::new(&inventory.store)
        .update(
            Uuid::parse_str(&routed.logins[0].id).unwrap(),
            AccessProfileChange {
                route: Some(RouteChoice::Route(route.meta.id)),
                ..Default::default()
            },
        )
        .unwrap();
    let invalid = password(&inventory, "Invalid");
    Repository::<Host>::new(&inventory.store)
        .update(
            Uuid::parse_str(&invalid.summary.id).unwrap(),
            HostChange { address: Some("host\nHost injected".into()), ..Default::default() },
        )
        .unwrap();
    let preview = inventory.preview_open_ssh_export(vec![]).unwrap();
    assert!(preview.entries.is_empty());
    assert!(preview.skipped.iter().any(|row| row.host_id == no_login.meta.id.to_string()
        && row.profile_id.is_none()
        && row.reason == OpenSshExportSkipReason::MissingLogin));
    for reason in [
        OpenSshExportSkipReason::UnsupportedCredential,
        OpenSshExportSkipReason::UnsupportedRoute,
        OpenSshExportSkipReason::InvalidValue,
    ] {
        assert!(preview.skipped.iter().any(|row| row.reason == reason));
    }
}

#[test]
fn importer_rejects_unrepresentable_auth_and_alias_forms_and_does_not_choose_agent_when_disabled() {
    let (dir, inventory) = fixture();
    let source = dir.path().join("config");
    for directive in [
        "PreferredAuthentications publickey,password",
        "IdentitiesOnly no",
        "IdentityAgent another-agent",
        "HostKeyAlias %h",
    ] {
        std::fs::write(&source,format!("Host checked\n HostName fixture.example\n User deploy\n IdentityFile none\n {directive}\n")).unwrap();
        let preview = inventory.preview_open_ssh_config(parse::display(&source)).unwrap();
        assert!(preview.entries.is_empty());
        assert_eq!(preview.skipped_hosts.len(), 1);
    }
    let public = dir.path().join("identity.pub");
    std::fs::write(&public, private(21).public_key().to_openssh().unwrap()).unwrap();
    std::fs::write(&source,format!("Host checked\n HostName fixture.example\n User deploy\n PreferredAuthentications publickey\n IdentityAgent none\n IdentityFile {}\n",quoted(&export_path(&public)))).unwrap();
    let preview = inventory.preview_open_ssh_config(parse::display(&source)).unwrap();
    assert!(preview.entries[0].needs_credential);
    assert!(inventory.credentials_objects().unwrap().is_empty());
}
