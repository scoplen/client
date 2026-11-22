// SPDX-License-Identifier: Apache-2.0

//! Standard OpenSSH consumes reviewed exports with password, source-key and exact-agent auth.

use scoplen_client_core::{
    inventory::{
        Inventory, NewHost, OpenSshExportAuthentication, OpenSshExportEntry,
        OpenSshGeneratedPreview, OpenSshImportChoice, SignIn, generated_open_ssh_include_line,
    },
    local_data::{LocalData, LocalDataError, Status},
    repository::{
        AccessProfile, AccessProfileChange, Credential, CredentialBinding, CredentialChange,
        CredentialKind, Edit, Host, HostChange, Provenance, Repository, Route, RouteChange,
        RouteChoice, RouteKind, TrustRecord, TrustRecordChange,
    },
    store::Store,
};
use scoplen_client_platform::keystore::local_key_store;
use scoplen_crypto::{Ed25519SigningKey, LocalDatabaseKey};
use scoplen_ssh::{AgentIdentity, AgentMessage};
use std::{
    collections::BTreeMap,
    env, fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    if let Some(file) = env::var_os("SCOPLEN_EXPORT_ASKPASS_FILE") {
        print!("{}", fs::read_to_string(file)?);
        return Ok(());
    }
    let args = env::args().collect::<Vec<_>>();
    if args.len() == 4 && args[1] == "--packaged-helper" {
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(packaged_helper(Path::new(&args[2]), Path::new(&args[3])));
    }
    if args.len() != 7 {
        return Err("usage: openssh_export_smoke <port> <source-key> <key-passphrase-file> <password-file> <known-hosts> <scratch-directory>".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(run(&args)))
}

async fn packaged_helper(helper: &Path, directory: &Path) -> Result<()> {
    eprintln!("packaged-helper: phase=fixture");
    let local = fixture_local_data(directory)?;
    let inventory = fixture_step("inventory-open", || {
        Ok(Inventory::new(local.store().ok_or("packaged fixture store did not open")?))
    })?;
    let preview =
        fixture_step("inventory-preview", || Ok(inventory.preview_generated_open_ssh(vec![])?))?;
    assert!(preview.report.entries.is_empty());
    // Publication resolves the destination; keep the original directory for the keystore.
    let wrapper = fixture_step("resolve-directory", || Ok(directory.canonicalize()?))?
        .join("openssh/local/active.conf");
    eprintln!("packaged-helper: phase=helper");
    let generation = publish_generation(
        &inventory,
        &preview,
        directory,
        "packaged-helper",
        Some(helper),
        &wrapper,
    )
    .await?;
    assert!(!fs::read_to_string(generation.join("config"))?.contains("Host "));
    eprintln!("packaged-helper: phase=openssh");
    let effective = effective_config(&wrapper, "unconfigured.example").await?;
    assert!(effective.lines().any(|line| line == "hostname unconfigured.example"));
    assert!(!effective.contains("hostkeyalias scoplen-host-"));
    eprintln!("packaged-helper: phase=recheck");
    assert!(inventory.preview_generated_open_ssh(vec![])?.report.entries.is_empty());
    drop(inventory);
    drop(local);
    eprintln!("packaged-helper: phase=cleanup");
    clear_fixture_key(directory)?;
    println!("Packaged helper generated a complete empty Include consumed by unmodified OpenSSH.");
    Ok(())
}

async fn run(args: &[String]) -> Result<()> {
    let scratch = tempfile::tempdir_in(&args[6])?.keep();
    run_in_directory(args, &scratch).await?;
    if env::var_os("SCOPLEN_EXPORT_HELPER").is_some() {
        clear_fixture_key(&scratch)?;
    }
    fs::remove_dir_all(scratch)?;
    Ok(())
}

fn fixture_local_data(directory: &Path) -> Result<LocalData> {
    fixture_step("create-directory", || Ok(fs::create_dir_all(directory)?))?;
    let local = fixture_step("local-data-start", || {
        Ok(LocalData::start(directory, local_key_store(directory))?)
    })?;
    let passphrase = "disposable local export passphrase";
    eprintln!("packaged-helper: step=local-data-status");
    match local.status() {
        Status::Open { .. } => {
            fixture_step("passphrase-set", || Ok(local.set_passphrase(passphrase)?))?;
        }
        Status::NeedsNewPassphrase => {
            fixture_step("passphrase-create", || Ok(local.create(passphrase)?))?;
        }
        _ => {
            eprintln!("packaged-helper: error=local-data-invalid-state");
            return Err("fresh fixture local data did not open".into());
        }
    };
    fixture_step("passphrase-write", || {
        Ok(fs::write(directory.join("local-passphrase"), passphrase)?)
    })?;
    Ok(local)
}

fn fixture_step<T>(step: &'static str, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    eprintln!("packaged-helper: step={step}");
    operation().inspect_err(|error| {
        let category = if let Some(error) = error.downcast_ref::<LocalDataError>() {
            match error {
                LocalDataError::WrongPassphrase => "local-data-wrong-passphrase",
                LocalDataError::EmptyPassphrase => "local-data-empty-passphrase",
                LocalDataError::PassphraseRequired => "local-data-passphrase-required",
                LocalDataError::InvalidState => "local-data-invalid-state",
                LocalDataError::Failed { .. } => "local-data-failed",
            }
        } else if let Some(error) = error.downcast_ref::<io::Error>() {
            match error.kind() {
                io::ErrorKind::NotFound => "io-not-found",
                io::ErrorKind::PermissionDenied => "io-permission-denied",
                _ => "io-other",
            }
        } else {
            "unexpected"
        };
        eprintln!("packaged-helper: error={category}");
    })
}

fn clear_fixture_key(directory: &Path) -> Result<()> {
    if let Some(keystore) = local_key_store(directory) {
        keystore.delete()?;
    }
    Ok(())
}

async fn run_in_directory(args: &[String], scratch: &Path) -> Result<()> {
    let local = if env::var_os("SCOPLEN_EXPORT_HELPER").is_some() {
        Some(fixture_local_data(scratch)?)
    } else {
        None
    };
    let store = if let Some(local) = &local {
        local.store().ok_or("fixture Local store did not open")?
    } else {
        Arc::new(Store::open(&scratch.join("inventory.db"), &LocalDatabaseKey::new([52; 32]))?)
    };
    let inventory = Inventory::new(store.clone());
    let port = args[1].parse::<u16>()?;
    let password_host = inventory.add_host(NewHost {
        name: Some("Password fixture".into()),
        address: "127.0.0.1".into(),
        port: Some(port),
        username: "smoke".into(),
        sign_in: SignIn::Password { password: fs::read_to_string(&args[4])? },
    })?;
    let password_profile = Uuid::parse_str(&password_host.logins[0].id)?;
    let password_credential = Repository::<AccessProfile>::new(&store)
        .get(password_profile)?
        .unwrap()
        .credential
        .unwrap();
    let source = scratch.join("import.conf");
    let quote = |file: &str| format!("\"{}\"", file.replace('\\', "/"));
    fs::write(
        &source,
        format!(
            "Host source-key\n HostName 127.0.0.1\n Port {port}\n User smoke\n IdentityFile {}\n UserKnownHostsFile {}\n",
            quote(&args[2]),
            quote(&args[5])
        ),
    )?;
    let imported = inventory.import_open_ssh_config(
        inventory.preview_open_ssh_config(source.to_string_lossy().into_owned())?,
    )?;
    let source_host = &imported.hosts[0];
    let key =
        ssh_key::PrivateKey::from_openssh(fs::read(&args[2])?)?.decrypt(fs::read(&args[3])?)?;
    let public = key.public_key().to_openssh()?;
    let agent_credential = Repository::<Credential>::new(&store).create(CredentialChange {
        kind: Some(CredentialKind::Agent),
        binding: Some(CredentialBinding::None),
        public_key: Edit::Set(public),
        ..Default::default()
    })?;
    let agent_host = inventory.add_host(NewHost {
        name: Some("Agent fixture".into()),
        address: "127.0.0.1".into(),
        port: Some(port),
        username: "smoke".into(),
        sign_in: SignIn::Password { password: "unused disposable value".into() },
    })?;
    Repository::<AccessProfile>::new(&store).update(
        Uuid::parse_str(&agent_host.logins[0].id)?,
        AccessProfileChange {
            credential: Edit::Set(agent_credential.meta.id),
            ..Default::default()
        },
    )?;
    let no_trust = inventory.add_host(NewHost {
        name: Some("No saved trust".into()),
        address: "127.0.0.1".into(),
        port: Some(port),
        username: "smoke".into(),
        sign_in: SignIn::Password { password: "unused disposable value".into() },
    })?;
    let independent = inventory.add_host(NewHost {
        name: Some("Independent wrong trust".into()),
        address: "127.0.0.1".into(),
        port: Some(port),
        username: "smoke".into(),
        sign_in: SignIn::Password { password: "unused disposable value".into() },
    })?;
    let jump_host = inventory.add_host(NewHost {
        name: Some("Jump source-key fixture".into()),
        address: "127.0.0.1".into(),
        port: Some(2222),
        username: "smoke".into(),
        sign_in: SignIn::Password { password: "unused disposable value".into() },
    })?;
    let jump = Repository::<Route>::new(&store).create(RouteChange {
        name: Some("Exact Agent hop".into()),
        kind: Some(RouteKind::Jump { hops: vec![Uuid::parse_str(&agent_host.logins[0].id)?] }),
    })?;
    let source_credential = Repository::<AccessProfile>::new(&store)
        .get(Uuid::parse_str(&source_host.logins[0].id)?)?
        .unwrap()
        .credential
        .unwrap();
    Repository::<AccessProfile>::new(&store).update(
        Uuid::parse_str(&jump_host.logins[0].id)?,
        AccessProfileChange {
            credential: Edit::Set(source_credential),
            route: Some(RouteChoice::Route(jump.meta.id)),
            ..Default::default()
        },
    )?;
    let actual = Repository::<TrustRecord>::new(&store)
        .list()?
        .into_iter()
        .find(|t| t.host == Some(Uuid::parse_str(&source_host.summary.id).unwrap()))
        .unwrap();
    for host in [&password_host, &agent_host, &jump_host] {
        Repository::<TrustRecord>::new(&store).create(TrustRecordChange {
            host: Edit::Set(Uuid::parse_str(&host.summary.id)?),
            key: Edit::Set(actual.key.clone().unwrap()),
            fingerprint: Edit::Set(actual.fingerprint.clone().unwrap()),
            provenance: Some(Provenance::Manual),
            ..Default::default()
        })?;
    }
    let wrong = ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[91; 32]).into(),
        "",
    )?;
    Repository::<TrustRecord>::new(&store).create(TrustRecordChange {
        host: Edit::Set(Uuid::parse_str(&independent.summary.id)?),
        key: Edit::Set(wrong.public_key().to_openssh()?),
        fingerprint: Edit::Set(
            wrong.public_key().fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        ),
        provenance: Some(Provenance::Manual),
        ..Default::default()
    })?;
    let preview = inventory.preview_open_ssh_export(vec![])?;
    assert_eq!(preview.entries.len(), 6);
    assert!(preview.skipped.is_empty());
    let entries = preview.entries.clone();
    let expected_trust = preview.trust_records;
    let exported = inventory.export_open_ssh_config(preview, scratch.into())?;
    assert_eq!(exported.files, 3);
    let config = Path::new(&exported.directory).join("config");
    let signs = Arc::new(AtomicUsize::new(0));
    let agent = start_agent(key, wrong, signs.clone()).await?;
    let rejected_hosts = [no_trust.summary.id.clone(), independent.summary.id.clone()];
    check_connections(&config, &entries, args, &rejected_hosts, &BTreeMap::new()).await?;
    assert_eq!(signs.load(Ordering::SeqCst), 2);
    // Fresh imports recover key and exact-Agent rows; passwords require a saved explicit choice.
    let fresh_store =
        Arc::new(Store::open(&scratch.join("fresh.db"), &LocalDatabaseKey::new([53; 32]))?);
    let fresh = Inventory::new(fresh_store.clone());
    let password_copy = fresh.add_host(NewHost {
        name: Some("Password choice".into()),
        address: "placeholder.example".into(),
        port: None,
        username: "smoke".into(),
        sign_in: SignIn::Password { password: fs::read_to_string(&args[4])? },
    })?;
    let password_id = Repository::<AccessProfile>::new(&fresh_store)
        .get(Uuid::parse_str(&password_copy.logins[0].id)?)?
        .unwrap()
        .credential
        .unwrap();
    let path = config.to_string_lossy().into_owned();
    let round = fresh.preview_open_ssh_config(path.clone())?;
    assert!(round.unsupported.is_empty());
    assert!(round.skipped_hosts.is_empty());
    assert_eq!(round.entries.iter().filter(|r| r.needs_credential).count(), 3);
    let choices = round
        .entries
        .iter()
        .filter(|r| r.needs_credential)
        .map(|r| OpenSshImportChoice {
            alias: r.alias.clone(),
            identity_file: None,
            credential_id: Some(password_id.to_string()),
        })
        .collect();
    let round = fresh.preview_open_ssh_config_with_choices(path, choices)?;
    assert!(round.entries.iter().all(|r| !r.needs_credential));
    assert_eq!(round.entries.iter().map(|r| r.trust_records).sum::<u32>(), expected_trust);
    let result = fresh.import_open_ssh_config(round)?;
    assert_eq!(result.created, 6);
    assert!(
        Repository::<Route>::new(&fresh_store)
            .list()?
            .iter()
            .any(|route| matches!(route.kind, RouteKind::Jump { .. }))
    );
    let kinds = Repository::<Credential>::new(&fresh_store).list()?;
    assert!(kinds.iter().any(|c| c.kind == CredentialKind::Agent));
    assert!(kinds.iter().any(|c| c.kind == CredentialKind::PrivateKey));
    assert_eq!(
        Repository::<AccessProfile>::new(&store).get(password_profile)?.unwrap().credential,
        Some(password_credential)
    );
    assert!(fs::read_to_string(&config)?.contains("IdentityFile none"));
    // Endpoint change after review refuses without writing a second export.
    let reviewed = inventory.preview_open_ssh_export(vec![])?;
    Repository::<Host>::new(&store).update(
        Uuid::parse_str(&password_host.summary.id)?,
        HostChange { address: Some("changed.example".into()), ..Default::default() },
    )?;
    assert!(matches!(
        inventory.export_open_ssh_config(reviewed, scratch.into()),
        Err(scoplen_client_core::inventory::OpenSshExportError::InventoryChanged)
    ));
    Repository::<Host>::new(&store).update(
        Uuid::parse_str(&password_host.summary.id)?,
        HostChange { address: Some("127.0.0.1".into()), ..Default::default() },
    )?;
    generated_include(
        &inventory,
        &store,
        scratch,
        args,
        &[
            (password_host.summary.id.as_str(), "prod-api"),
            (source_host.summary.id.as_str(), "source-key"),
            (agent_host.summary.id.as_str(), "jump-entry"),
            (jump_host.summary.id.as_str(), "jump-target"),
        ],
        &rejected_hosts,
    )
    .await?;
    assert_eq!(signs.load(Ordering::SeqCst), 4);
    agent.abort();
    println!(
        "OpenSSH password, encrypted source-key, exact isolated-agent and Jump export; independent host trust, first-use refusal and explicit-password import round-trip passed"
    );
    Ok(())
}

async fn check_connections(
    config: &Path,
    entries: &[OpenSshExportEntry],
    args: &[String],
    rejected_hosts: &[String],
    aliases: &BTreeMap<String, String>,
) -> Result<()> {
    for row in entries {
        let alias = aliases.get(&row.profile_id).unwrap_or(&row.alias);
        let effective = tokio::process::Command::new("ssh")
            .args(["-G", "-F"])
            .arg(config)
            .arg(alias)
            .output()
            .await?;
        assert!(effective.status.success());
        let text = String::from_utf8(effective.stdout)?;
        assert!(text.contains(&format!(
            "hostkeyalias scoplen-host-{}",
            Uuid::parse_str(&row.host_id)?.simple()
        )));
        assert!(text.contains(&format!("port {}", row.port)));
        let input = match row.authentication {
            OpenSshExportAuthentication::Password => Some(args[4].as_str()),
            OpenSshExportAuthentication::IdentityFile => Some(args[3].as_str()),
            OpenSshExportAuthentication::Agent => None,
        };
        let mut command = tokio::process::Command::new("ssh");
        command
            .args(["-F"])
            .arg(config)
            .args([
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "NumberOfPasswordPrompts=1",
            ])
            .kill_on_drop(true);
        if let Some(file) = input {
            command
                .env("SSH_ASKPASS", env::current_exe()?)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .env("DISPLAY", "scoplen-fixture")
                .env("SCOPLEN_EXPORT_ASKPASS_FILE", file);
        } else {
            command.args(["-o", "BatchMode=yes"]);
        }
        command.arg(alias).arg("printf scoplen-export-ok");
        let output = tokio::time::timeout(Duration::from_secs(20), command.output()).await??;
        if rejected_hosts.contains(&row.host_id) {
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("Host key verification failed")
            );
        } else if !output.status.success() || output.stdout != b"scoplen-export-ok" {
            return Err(format!(
                "exported {:?} SSH failed: {}",
                row.authentication,
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
    }
    Ok(())
}

async fn generated_include(
    inventory: &Inventory,
    store: &Arc<Store>,
    scratch: &Path,
    args: &[String],
    host_names: &[(&str, &str)],
    rejected_hosts: &[String],
) -> Result<()> {
    for (id, name) in host_names {
        Repository::<Host>::new(store).update(
            Uuid::parse_str(id)?,
            HostChange { name: Some((*name).into()), ..Default::default() },
        )?;
    }
    let helper = env::var_os("SCOPLEN_EXPORT_HELPER").map(PathBuf::from);
    let wrapper = if helper.is_some() {
        scratch.canonicalize()?.join("openssh/local/active.conf")
    } else {
        scratch.join("active.conf")
    };
    let user_config = scratch.join("user-config");
    let user_bytes =
        format!("# Owned fixture user config.\n{}\n", generated_open_ssh_include_line(&wrapper)?);
    fs::write(&user_config, &user_bytes)?;
    let preview = inventory.preview_generated_open_ssh(vec![])?;
    let aliases = preview
        .aliases
        .iter()
        .filter_map(|alias| Some((alias.profile_id.clone()?, alias.alias.clone()?)))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(aliases.len(), 4);
    publish_generation(inventory, &preview, scratch, "generated-one", helper.as_deref(), &wrapper)
        .await?;
    check_connections(&user_config, &preview.report.entries, args, rejected_hosts, &aliases)
        .await?;

    let password = host_names[0].0;
    let password_profile = Uuid::parse_str(
        &preview.report.entries.iter().find(|row| row.host_id == password).unwrap().profile_id,
    )?;
    Repository::<Host>::new(store).update(
        Uuid::parse_str(password)?,
        HostChange { port: Edit::Set(2299), ..Default::default() },
    )?;
    Repository::<AccessProfile>::new(store).update(
        password_profile,
        AccessProfileChange { username: Some("regenerated-user".into()), ..Default::default() },
    )?;
    let removed_host = host_names[1].0;
    let removed_login =
        preview.report.entries.iter().find(|row| row.host_id == removed_host).unwrap();
    store.delete(Uuid::parse_str(&removed_login.profile_id)?)?;
    let trust = Repository::<TrustRecord>::new(store)
        .list()?
        .into_iter()
        .find(|record| record.host == Some(Uuid::parse_str(password).unwrap()))
        .unwrap();
    let replacement = ssh_key::PrivateKey::new(
        ssh_key::private::Ed25519Keypair::from_seed(&[92; 32]).into(),
        "",
    )?;
    Repository::<TrustRecord>::new(store).update(
        trust.meta.id,
        TrustRecordChange {
            key: Edit::Set(replacement.public_key().to_openssh()?),
            fingerprint: Edit::Set(
                replacement.public_key().fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            ),
            ..Default::default()
        },
    )?;
    let preview = inventory.preview_generated_open_ssh(vec![])?;
    let generated = publish_generation(
        inventory,
        &preview,
        scratch,
        "generated-two",
        helper.as_deref(),
        &wrapper,
    )
    .await?;
    let effective = effective_config(&user_config, "prod-api").await?;
    assert!(effective.lines().any(|line| line == "port 2299"));
    assert!(effective.lines().any(|line| line == "user regenerated-user"));
    assert!(effective.lines().any(|line| line == "hostname 127.0.0.1"));
    let removed = effective_config(&user_config, "source-key").await?;
    assert!(removed.lines().any(|line| line == "hostname source-key"));
    assert!(!removed.contains("hostkeyalias scoplen-host-"));
    assert!(effective_config(&user_config, "jump-target").await?.contains("hostname 127.0.0.1"));
    assert!(
        fs::read_to_string(generated.join("known_hosts"))?
            .contains(&replacement.public_key().to_openssh()?)
    );
    Repository::<Host>::new(store).update(
        Uuid::parse_str(password)?,
        HostChange { port: Edit::Set(args[1].parse()?), ..Default::default() },
    )?;
    Repository::<AccessProfile>::new(store).update(
        password_profile,
        AccessProfileChange { username: Some("smoke".into()), ..Default::default() },
    )?;
    let preview = inventory.preview_generated_open_ssh(vec![])?;
    publish_generation(
        inventory,
        &preview,
        scratch,
        "generated-trust",
        helper.as_deref(),
        &wrapper,
    )
    .await?;
    let password_entry = preview.report.entries.iter().find(|row| row.host_id == password).unwrap();
    check_connections(
        &user_config,
        std::slice::from_ref(password_entry),
        args,
        &[password.to_owned()],
        &aliases,
    )
    .await?;
    for login in Repository::<AccessProfile>::new(store).list()? {
        store.delete(login.meta.id)?;
    }
    let empty = inventory.preview_generated_open_ssh(vec![])?;
    assert!(empty.report.entries.is_empty());
    publish_generation(inventory, &empty, scratch, "generated-empty", helper.as_deref(), &wrapper)
        .await?;
    let effective = effective_config(&user_config, "prod-api").await?;
    assert!(effective.lines().any(|line| line == "hostname prod-api"));
    assert!(!effective.contains("hostkeyalias scoplen-host-"));
    if helper.is_none() {
        fs::write(&wrapper, "# Cleared fixture Include.\n")?;
        assert_eq!(effective_config(&user_config, "prod-api").await?, effective);
    }
    assert_eq!(fs::read(&user_config)?, user_bytes.as_bytes());
    println!(
        "Generated OpenSSH Include: friendly password/key/Agent/Jump connections, port/user/trust regeneration, removed entries and empty inventory passed; user config unchanged"
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn check_fixture_writer(directory: &Path) -> &'static str {
    use scoplen_client_core::profiles::OpenSshExportProfile;
    use scoplen_client_platform::keystore::suppress_keychain_prompts;
    use zeroize::Zeroizing;

    let Ok(_policy) = suppress_keychain_prompts() else { return "unavailable" };
    let Ok(passphrase) = fs::read_to_string(directory.join("local-passphrase")).map(Zeroizing::new)
    else {
        return "unavailable";
    };
    match OpenSshExportProfile::open(directory, None, None, Some(&passphrase)) {
        Ok(_) => "reopened",
        Err(_) => "refused",
    }
}

async fn publish_generation(
    inventory: &Inventory,
    preview: &OpenSshGeneratedPreview,
    scratch: &Path,
    name: &str,
    helper: Option<&Path>,
    wrapper: &Path,
) -> Result<PathBuf> {
    if let Some(helper) = helper {
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            tokio::process::Command::new(helper)
                .args(["config", "generate", "--profile", "local", "--passphrase-file"])
                .arg(scratch.join("local-passphrase"))
                .arg("--yes")
                .env("SPL_DATA_DIR", scratch)
                .kill_on_drop(true)
                .output(),
        )
        .await??;
        let diagnostics = scratch.parent().ok_or("fixture diagnostics parent missing")?;
        fs::write(diagnostics.join(format!("{name}-helper.stdout")), &output.stdout)?;
        fs::write(diagnostics.join(format!("{name}-helper.stderr")), &output.stderr)?;
        if !output.status.success() {
            #[cfg(target_os = "macos")]
            if name == "packaged-helper" {
                eprintln!("packaged-helper: writer={}", check_fixture_writer(scratch));
            }
            return Err(
                "actual generated-Include helper failed; private process evidence required".into(),
            );
        }
        let report = String::from_utf8(output.stdout)?;
        assert!(report.contains(&generated_open_ssh_include_line(wrapper)?));
        assert!(!report.contains("disposable local export passphrase"));
        assert!(!report.contains("disposable-export-password"));
        let active = fs::read_to_string(wrapper)?;
        let generation = active
            .lines()
            .find_map(|line| line.strip_prefix("# Generation "))
            .ok_or("helper omitted native generation ownership")?;
        let generation = Uuid::parse_str(generation)?;
        let directory = wrapper
            .parent()
            .ok_or("wrapper parent missing")?
            .join("generations")
            .join(generation.to_string());
        assert!(directory.join(".scoplen-generation").is_file());
        Ok(directory)
    } else {
        let generated = inventory.write_generated_open_ssh(preview, &scratch.join(name))?;
        fs::write(
            wrapper,
            format!(
                "{}\n",
                generated_open_ssh_include_line(&Path::new(&generated.directory).join("config"))?
            ),
        )?;
        Ok(PathBuf::from(generated.directory))
    }
}

async fn effective_config(config: &Path, alias: &str) -> Result<String> {
    let output = tokio::process::Command::new("ssh")
        .args(["-G", "-F"])
        .arg(config)
        .arg(alias)
        .output()
        .await?;
    if !output.status.success() {
        return Err("generated Include could not be read by OpenSSH".into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

async fn start_agent(
    key: ssh_key::PrivateKey,
    decoy: ssh_key::PrivateKey,
    signs: Arc<AtomicUsize>,
) -> Result<tokio::task::JoinHandle<()>> {
    let public = key.public_key().to_bytes()?;
    let decoy = decoy.public_key().to_bytes()?;
    let key = Arc::new(Ed25519SigningKey::from_bytes(
        key.key_data().ed25519().unwrap().private.as_ref(),
    )?);
    let socket = env::var_os("SSH_AUTH_SOCK").ok_or("isolated agent socket required")?;
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ServerOptions;
        let mut listener = ServerOptions::new().first_pipe_instance(true).create(&socket)?;
        Ok(tokio::spawn(async move {
            loop {
                if listener.connect().await.is_err() {
                    break;
                }
                let stream = listener;
                listener = match ServerOptions::new().create(&socket) {
                    Ok(next) => next,
                    Err(_) => break,
                };
                let (key, public, decoy, signs) =
                    (key.clone(), public.clone(), decoy.clone(), signs.clone());
                tokio::spawn(async move {
                    let _ = serve_agent(stream, &public, &decoy, &key, &signs).await;
                });
            }
        }))
    }
    #[cfg(unix)]
    {
        let listener = tokio::net::UnixListener::bind(socket)?;
        Ok(tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (key, public, decoy, signs) =
                    (key.clone(), public.clone(), decoy.clone(), signs.clone());
                tokio::spawn(async move {
                    let _ = serve_agent(stream, &public, &decoy, &key, &signs).await;
                });
            }
        }))
    }
}

async fn serve_agent<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    public: &[u8],
    decoy: &[u8],
    key: &Ed25519SigningKey,
    signs: &AtomicUsize,
) -> io::Result<()> {
    loop {
        let length = match stream.read_u32().await {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if length > 262144 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut frame = length.to_be_bytes().to_vec();
        frame.resize(length as usize + 4, 0);
        stream.read_exact(&mut frame[4..]).await?;
        let reply = match AgentMessage::decode_frame(&frame).map_err(io::Error::other)? {
            AgentMessage::RequestIdentities => AgentMessage::IdentitiesAnswer {
                identities: vec![
                    AgentIdentity::new(decoy.to_vec(), b"decoy".to_vec())
                        .map_err(io::Error::other)?,
                    AgentIdentity::new(public.to_vec(), b"selected".to_vec())
                        .map_err(io::Error::other)?,
                ],
            },
            AgentMessage::SignRequest { key_blob, data, flags }
                if key_blob == public && flags == 0 =>
            {
                signs.fetch_add(1, Ordering::SeqCst);
                let mut signature = 11u32.to_be_bytes().to_vec();
                signature.extend_from_slice(b"ssh-ed25519");
                signature.extend_from_slice(&64u32.to_be_bytes());
                signature.extend_from_slice(&key.sign(&data));
                AgentMessage::SignResponse { signature }
            }
            _ => AgentMessage::Failure,
        };
        stream.write_all(&reply.encode_frame().map_err(io::Error::other)?).await?;
    }
}
