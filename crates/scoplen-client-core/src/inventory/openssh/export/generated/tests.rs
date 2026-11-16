// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::inventory::SignIn;

fn fixture() -> (tempfile::TempDir, Inventory) {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(
        &directory.path().join("inventory.db"),
        &scoplen_crypto::LocalDatabaseKey::new([41; 32]),
    )
    .unwrap();
    (directory, Inventory::new(Arc::new(store)))
}

fn password(inventory: &Inventory, name: &str) -> HostDetails {
    inventory
        .add_host(NewHost {
            name: Some(name.into()),
            address: "fixture.example".into(),
            port: Some(2200),
            username: "deploy".into(),
            sign_in: SignIn::Password { password: "generated-fixture-secret".into() },
        })
        .unwrap()
}

#[test]
fn friendly_aliases_use_complete_names_and_collision_checks_include_hosts_without_logins() {
    let (directory, inventory) = fixture();
    let unique = password(&inventory, "Production.DB-1");
    password(&inventory, "Duplicate");
    let no_login = password(&inventory, "DUPLICATE");
    inventory.store.delete(Uuid::parse_str(&no_login.logins[0].id).unwrap()).unwrap();
    for name in
        ["contains space", " leading", "bad/name", "scoplen-0123456789ABCDEF0123456789abcdef"]
    {
        password(&inventory, name);
    }
    let preview = inventory.preview_generated_open_ssh(vec![]).unwrap();
    assert_eq!(preview.aliases.iter().filter(|alias| alias.alias.is_some()).count(), 1);
    let alias = preview.aliases.iter().find(|alias| alias.alias.is_some()).unwrap();
    assert_eq!(alias.alias.as_deref(), Some("production.db-1"));
    assert_eq!(alias.profile_id.as_deref(), Some(unique.logins[0].id.as_str()));
    assert_eq!(
        preview
            .aliases
            .iter()
            .filter(|alias| alias.problem == Some(OpenSshGeneratedAliasProblem::DuplicateName))
            .count(),
        2
    );
    assert_eq!(
        preview
            .aliases
            .iter()
            .filter(|alias| alias.problem == Some(OpenSshGeneratedAliasProblem::InvalidName))
            .count(),
        3
    );
    assert!(
        preview
            .aliases
            .iter()
            .any(|alias| alias.problem == Some(OpenSshGeneratedAliasProblem::ReservedName))
    );
    let output = directory.path().join("generated");
    inventory.write_generated_open_ssh(&preview, &output).unwrap();
    let config = std::fs::read_to_string(output.join("config")).unwrap();
    assert!(config.contains(&format!(
            "Host {} production.db-1\n",
            preview
                .report
                .entries
                .iter()
                .find(|entry| entry.profile_id == unique.logins[0].id)
                .unwrap()
                .alias
        )));
    assert!(!config.contains("generated-fixture-secret"));
    // Ordinary export retains its UUID-only contract.
    let standard = inventory.preview_open_ssh_export(vec![]).unwrap();
    let ordinary = inventory.export_open_ssh_config(standard, directory.path().into()).unwrap();
    assert!(
        !std::fs::read_to_string(Path::new(&ordinary.directory).join("config"))
            .unwrap()
            .contains(" production.db-1\n")
    );
}

#[test]
fn default_login_is_selected_before_compatibility_and_never_changes_username_silently() {
    let (directory, inventory) = fixture();
    let host = password(&inventory, "Application");
    let host_id = Uuid::parse_str(&host.summary.id).unwrap();
    let first = Uuid::parse_str(&host.logins[0].id).unwrap();
    let credential = Repository::<AccessProfile>::new(&inventory.store)
        .get(first)
        .unwrap()
        .unwrap()
        .credential
        .unwrap();
    let second = Repository::<AccessProfile>::new(&inventory.store)
        .create(AccessProfileChange {
            host: Some(host_id),
            username: Some("other-user".into()),
            credential: Edit::Set(credential),
            ..Default::default()
        })
        .unwrap();
    Repository::<Host>::new(&inventory.store)
        .update(
            host_id,
            HostChange { default_profile: Edit::Set(second.meta.id), ..Default::default() },
        )
        .unwrap();
    let preview = inventory.preview_generated_open_ssh(vec![]).unwrap();
    assert_eq!(preview.aliases[0].profile_id, Some(second.meta.id.to_string()));
    inventory.write_generated_open_ssh(&preview, &directory.path().join("first")).unwrap();
    Repository::<AccessProfile>::new(&inventory.store)
        .update(
            second.meta.id,
            AccessProfileChange { agent_forwarding: Some(true), ..Default::default() },
        )
        .unwrap();
    let refused = inventory.preview_generated_open_ssh(vec![]).unwrap();
    assert_eq!(refused.report.entries.len(), 1);
    assert_eq!(refused.aliases[0].profile_id, Some(second.meta.id.to_string()));
    assert_eq!(refused.aliases[0].problem, Some(OpenSshGeneratedAliasProblem::IncompatibleLogin));
    assert!(refused.aliases[0].alias.is_none());
    Repository::<Host>::new(&inventory.store)
        .update(host_id, HostChange { default_profile: Edit::Clear, ..Default::default() })
        .unwrap();
    let fallback = inventory.preview_generated_open_ssh(vec![]).unwrap();
    assert_eq!(fallback.aliases[0].profile_id, Some(first.min(second.meta.id).to_string()));
    Repository::<Host>::new(&inventory.store)
        .update(
            host_id,
            HostChange { default_profile: Edit::Set(Uuid::now_v7()), ..Default::default() },
        )
        .unwrap();
    assert_eq!(
        inventory.preview_generated_open_ssh(vec![]).unwrap().aliases[0].profile_id,
        Some(first.min(second.meta.id).to_string())
    );
}

#[test]
fn friendly_aliases_do_not_change_jump_references() {
    let (directory, inventory) = fixture();
    let hop = password(&inventory, "Gateway");
    let target = password(&inventory, "Application");
    let hop_id = Uuid::parse_str(&hop.logins[0].id).unwrap();
    let route = Repository::<Route>::new(&inventory.store)
        .create(RouteChange {
            name: Some("Jump".into()),
            kind: Some(RouteKind::Jump { hops: vec![hop_id] }),
        })
        .unwrap();
    Repository::<AccessProfile>::new(&inventory.store)
        .update(
            Uuid::parse_str(&target.logins[0].id).unwrap(),
            AccessProfileChange {
                route: Some(RouteChoice::Route(route.meta.id)),
                ..Default::default()
            },
        )
        .unwrap();
    let preview = inventory.preview_generated_open_ssh(vec![]).unwrap();
    let output = directory.path().join("jump");
    inventory.write_generated_open_ssh(&preview, &output).unwrap();
    let config = std::fs::read_to_string(output.join("config")).unwrap();
    assert!(config.contains(&format!("ProxyJump scoplen-{}\n", hop_id.simple())));
    assert!(!config.contains("ProxyJump gateway"));
    assert_eq!(preview.aliases.iter().filter(|alias| alias.alias.is_some()).count(), 2);
}

#[test]
fn empty_generation_and_last_login_deletion_do_not_retain_old_entries() {
    let (directory, inventory) = fixture();
    let empty = inventory.preview_generated_open_ssh(vec![]).unwrap();
    let result =
        inventory.write_generated_open_ssh(&empty, &directory.path().join("empty")).unwrap();
    assert_eq!(result.hosts, 0);
    assert!(
        !std::fs::read_to_string(Path::new(&result.directory).join("config"))
            .unwrap()
            .contains("\nHost ")
    );
    let host = password(&inventory, "Last");
    let old = inventory.preview_generated_open_ssh(vec![]).unwrap();
    inventory.store.delete(Uuid::parse_str(&host.logins[0].id).unwrap()).unwrap();
    assert_eq!(
        inventory.write_generated_open_ssh(&old, &directory.path().join("stale")),
        Err(OpenSshGeneratedError::InventoryChanged)
    );
    let current = inventory.preview_generated_open_ssh(vec![]).unwrap();
    assert_eq!(current.aliases[0].problem, Some(OpenSshGeneratedAliasProblem::MissingLogin));
    assert_eq!(
        inventory
            .write_generated_open_ssh(&current, &directory.path().join("current"))
            .unwrap()
            .hosts,
        0
    );
}

#[test]
fn selected_source_changes_and_tampered_reports_refuse_before_output() {
    let (directory, inventory) = fixture();
    let key =
        ssh_key::PrivateKey::new(ssh_key::private::Ed25519Keypair::from_seed(&[19; 32]).into(), "")
            .unwrap();
    let source = directory.path().join("source identity");
    std::fs::write(&source, key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes()).unwrap();
    let host = inventory
        .add_host(NewHost {
            name: Some("Source".into()),
            address: "fixture.example".into(),
            port: None,
            username: "deploy".into(),
            sign_in: SignIn::KeyText {
                key: key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string(),
            },
        })
        .unwrap();
    let preview = inventory
        .preview_generated_open_ssh(vec![OpenSshExportChoice {
            profile_id: host.logins[0].id.clone(),
            identity_file: source.to_string_lossy().into_owned(),
        }])
        .unwrap();
    let mut modified = key;
    modified.set_comment("changed");
    std::fs::write(&source, modified.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes())
        .unwrap();
    let target = directory.path().join("refused");
    assert_eq!(
        inventory.write_generated_open_ssh(&preview, &target),
        Err(OpenSshGeneratedError::SourceChanged)
    );
    assert!(!target.exists());
    let mut tampered = inventory.preview_generated_open_ssh(vec![]).unwrap();
    tampered.aliases[0].alias = Some("forged".into());
    assert_eq!(
        inventory.write_generated_open_ssh(&tampered, &target),
        Err(OpenSshGeneratedError::InvalidSelection)
    );
}

#[test]
fn include_paths_preserve_spaces_and_unicode_without_glob_expansion() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("space \u{914d}\u{7f6e}").join("active.conf");
    let line = generated_open_ssh_include_line(&path).unwrap();
    assert!(line.starts_with("Include \""));
    assert!(line.contains("space \u{914d}\u{7f6e}"));
    assert_eq!(
        generated_open_ssh_include_line(&directory.path().join("[glob]")),
        Err(OpenSshGeneratedError::InvalidSelection)
    );
}
