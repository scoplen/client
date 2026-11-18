// SPDX-License-Identifier: Apache-2.0
//! Exercise the actual console binary with an independently protected Local store.

#![cfg(any(windows, target_os = "macos"))]

use scoplen_client_core::{
    inventory::{Inventory, NewHost, SignIn},
    local_data::LocalData,
    personal_server::PersonalSyncRuntime,
    profiles::AccountProfiles,
};
use scoplen_client_platform::keystore::local_key_store;
use std::{
    path::Path,
    process::{Command, Output, Stdio},
    sync::Arc,
};

struct Fixture {
    data: Arc<LocalData>,
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let data = Arc::new(
            LocalData::start(directory.path(), local_key_store(directory.path())).unwrap(),
        );
        assert!(data.store().is_some());
        Self { data, directory }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(slot) = local_key_store(self.directory.path()) {
            slot.delete().expect("remove the test-owned key slot");
        }
    }
}

fn helper(directory: &Path, args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_spl"))
        .env("SPL_DATA_DIR", directory)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn run(directory: &Path, args: &[&str]) -> Output {
    helper(directory, &args.iter().map(std::ffi::OsStr::new).collect::<Vec<_>>())
}

fn text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn help_version_usage_and_missing_data_never_initialize_a_store() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("not-created");
    for args in [vec!["--help"], vec!["--version"], vec!["config", "generate", "--help"]] {
        let output = run(&missing, &args);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert!(!text(&output).is_empty());
    }
    for args in [
        vec!["config", "generate"],
        vec!["config", "generate", "--profile", "local"],
        vec!["config", "generate", "--clear"],
    ] {
        let output = run(&missing, &args);
        assert_eq!(output.status.code(), Some(2));
    }
    for args in [
        vec!["config", "generate", "--profile", "local", "--yes"],
        vec!["config", "generate", "--list-profiles"],
    ] {
        let output = run(&missing, &args);
        assert_eq!(output.status.code(), Some(1));
    }
    assert!(!missing.exists());
}

#[test]
fn actual_local_process_reviews_publishes_regenerates_and_keeps_the_desktop_lease_usable() {
    let fixture = Fixture::new();
    let directory = fixture.directory.path();
    let desktop =
        AccountProfiles::new(fixture.data.clone(), Arc::new(PersonalSyncRuntime::default()))
            .unwrap();
    let lease = desktop.current().unwrap();
    let store = fixture.data.store().unwrap();
    let inventory = Inventory::new(store.clone());
    let host = inventory
        .add_host(NewHost {
            name: Some("Production".into()),
            address: "fixture.example".into(),
            port: Some(2200),
            username: "deploy".into(),
            sign_in: SignIn::Password { password: "never-export-this-password".into() },
        })
        .unwrap();
    inventory
        .add_host(NewHost {
            name: Some("Unusual\n\u{1b}[31m".into()),
            address: "second.example".into(),
            port: None,
            username: "deploy".into(),
            sign_in: SignIn::Password { password: "second-test-password".into() },
        })
        .unwrap();
    inventory
        .add_host(NewHost {
            name: Some("Interactive".into()),
            address: "interactive.example".into(),
            port: None,
            username: "deploy".into(),
            sign_in: SignIn::KeyboardInteractive,
        })
        .unwrap();
    let listing = run(directory, &["config", "generate", "--list-profiles"]);
    assert!(listing.status.success());
    assert!(text(&listing).contains("local\tLocal"));
    let review = run(directory, &["config", "generate", "--profile", "local", "--dry-run"]);
    assert!(review.status.success(), "{}", String::from_utf8_lossy(&review.stderr));
    let review = text(&review);
    assert!(review.contains("Compatible Logins (2):"));
    assert!(review.contains("Excluded rows (1):"));
    assert!(review.contains("Friendly alias outcomes (3):"));
    assert!(review.contains("The Credential cannot be represented without exporting a secret."));
    assert!(review.contains("OpenSSH prompts for the password"));
    assert!(review.contains("Unusual\\n\\u{1b}[31m"));
    assert!(!review.contains('\u{1b}'));
    assert!(!review.contains("never-export-this-password"));
    assert!(!directory.join("openssh").exists());
    desktop.with_current_store(&lease, |_| ()).unwrap();
    let published = run(directory, &["config", "generate", "--profile", "local", "--yes"]);
    assert!(published.status.success(), "{}", String::from_utf8_lossy(&published.stderr));
    let active = directory.join("openssh/local/active.conf");
    assert!(active.is_file());
    assert_eq!(text(&published).lines().filter(|line| line.starts_with("Include \"")).count(), 1);
    let first = std::fs::read(&active).unwrap();
    inventory.delete_host(host.summary.id).unwrap();
    let again = run(directory, &["config", "generate", "--profile", "local", "--yes"]);
    assert!(again.status.success());
    assert!(text(&again).contains("Compatible Logins (1):"));
    assert_ne!(std::fs::read(&active).unwrap(), first);
    desktop.with_current_store(&lease, |_| ()).unwrap();
    assert_eq!(desktop.current().unwrap().generation(), lease.generation());
}

#[test]
fn actual_local_process_requires_exact_nonempty_utf8_passphrase_files_and_accepts_empty_generation()
{
    let fixture = Fixture::new();
    let directory = fixture.directory.path();
    let secret = " exact local passphrase \n";
    fixture.data.set_passphrase(secret).unwrap();
    let passphrase = directory.join("local passphrase.txt");
    for contents in [vec![], vec![0xff], b"exact local passphrase".to_vec()] {
        std::fs::write(&passphrase, contents).unwrap();
        let output = helper(
            directory,
            &[
                "config".as_ref(),
                "generate".as_ref(),
                "--profile".as_ref(),
                "local".as_ref(),
                "--yes".as_ref(),
                "--passphrase-file".as_ref(),
                passphrase.as_os_str(),
            ],
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(!directory.join("openssh").exists());
    }
    let locked = run(directory, &["config", "generate", "--profile", "local", "--yes"]);
    assert_eq!(locked.status.code(), Some(1));
    std::fs::write(&passphrase, secret).unwrap();
    let generated = helper(
        directory,
        &[
            "config".as_ref(),
            "generate".as_ref(),
            "--profile".as_ref(),
            "local".as_ref(),
            "--yes".as_ref(),
            "--passphrase-file".as_ref(),
            passphrase.as_os_str(),
        ],
    );
    assert!(generated.status.success(), "{}", String::from_utf8_lossy(&generated.stderr));
    assert!(text(&generated).contains("Compatible Logins (0):"));
    assert!(text(&generated).contains("Published 0 compatible Logins"));
    assert!(!text(&generated).contains(secret));
    assert!(directory.join("openssh/local/active.conf").is_file());
    let listing = helper(
        directory,
        &[
            "config".as_ref(),
            "generate".as_ref(),
            "--list-profiles".as_ref(),
            "--catalog-passphrase-file".as_ref(),
            passphrase.as_os_str(),
        ],
    );
    assert!(listing.status.success());
}
