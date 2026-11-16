// SPDX-License-Identifier: Apache-2.0

//! OpenSSH migration and portable generated-key recovery against the same owned SSH/SFTP peer.

use std::{path::Path, process::Command, sync::Arc, time::Duration};

use scoplen_client_core::{
    connection::preparation::PreparationEvent,
    inventory::{Inventory, NewHost, OpenSshImportAction, OpenSshImportPreview, SignIn},
    portable_archive::{ArchiveSecretMode, ExportOptions, ImportConsent, PortableArchives},
    repository::{Edit, Provenance, Repository, TrustRecord, TrustRecordChange},
    session_files::{SessionDownloadStatus, SessionUploadStatus},
    session_manager::{SessionEvent, SessionManager},
    store::Store,
};
use scoplen_crypto::{LocalDatabaseKey, PortableExportPassphrase};
use scoplen_model::ObjectType;
use tokio::sync::mpsc;
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 5 {
        return Err("usage: openssh_import_smoke <port> <identity-file> <known-hosts-file> <fixture-directory>".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(run(&args)))
}

fn quote(path: &Path) -> String {
    format!("\"{}\"", path.to_string_lossy().replace('\\', "/"))
}

fn differential(preview: &OpenSshImportPreview) -> Result<(), Box<dyn std::error::Error>> {
    for row in &preview.entries {
        let output = Command::new("ssh").args(["-G", "-F", &preview.path, &row.alias]).output()?;
        if !output.status.success() {
            return Err("OpenSSH rejected the disposable import corpus".into());
        }
        let output = String::from_utf8(output.stdout)?;
        let value = |name: &str| {
            output.lines().find_map(|line| line.strip_prefix(&format!("{name} "))).unwrap_or("")
        };
        assert_eq!(value("hostname"), row.address);
        assert_eq!(value("user"), row.username);
        assert_eq!(value("port"), row.port.to_string());
    }
    Ok(())
}

async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let scratch = tempfile::tempdir_in(&args[4])?;
    let store = Arc::new(Store::open(
        &scratch.path().join("inventory.db"),
        &LocalDatabaseKey::new([7; 32]),
    )?);
    let inventory = Inventory::new(store.clone());
    inventory.add_host(NewHost {
        name: Some("Existing inventory".into()),
        address: "existing.example".into(),
        port: None,
        username: "existing".into(),
        sign_in: SignIn::Password { password: "disposable-unrelated-password".into() },
    })?;
    let parts = scratch.path().join("parts");
    std::fs::create_dir(&parts)?;
    let first = parts.join("10-hosts.conf");
    let first_text = format!("Host live\n HostName 127.0.0.1\n User smoke\n Port {}\n", args[1]);
    std::fs::write(&first, &first_text)?;
    std::fs::write(
        parts.join("20-defaults.conf"),
        "Host live\n HostName ignored.example\n User ignored\n",
    )?;
    let source = scratch.path().join("config");
    let source_text = format!(
        "IdentityFile {}\nUserKnownHostsFile {}\nInclude {}\nUser parent-default\nHost live\n HostName ignored-again.example\nHost *.example !excluded.example\n Port 2200\nHost matched.example excluded.example\n IdentityFile none\n",
        quote(Path::new(&args[2])),
        quote(Path::new(&args[3])),
        quote(&parts.join("*.conf"))
    );
    std::fs::write(&source, &source_text)?;
    let source_path = source.to_string_lossy().into_owned();
    let preview = inventory.preview_open_ssh_config(source_path.clone())?;
    assert_eq!(preview.entries.len(), 3);
    assert!(preview.unsupported.is_empty());
    assert!(preview.skipped_hosts.is_empty());
    assert!(preview.entries.iter().all(|row| !row.needs_credential));
    assert!(preview.entries.iter().find(|row| row.alias == "live").unwrap().trust_records > 0);
    differential(&preview)?;
    let imported = inventory.import_open_ssh_config(preview)?;
    assert_eq!(imported.created, 3);
    assert_eq!(std::fs::read_to_string(&source)?, source_text);
    assert_eq!(std::fs::read_to_string(&first)?, first_text);
    let live = imported.hosts.iter().find(|host| host.summary.name == "live").unwrap();
    let host_id = live.summary.id.clone();
    let profile_id = live.logins[0].id.clone();
    let types = [
        ObjectType::HOST,
        ObjectType::ACCESS_PROFILE,
        ObjectType::CREDENTIAL,
        ObjectType::TRUST_RECORD,
    ];
    let before = types.iter().map(|kind| store.list(*kind)).collect::<Result<Vec<_>, _>>()?;
    let repeated = inventory.preview_open_ssh_config(source_path.clone())?;
    assert!(repeated.entries.iter().all(|row| row.action == OpenSshImportAction::Unchanged));
    let result = inventory.import_open_ssh_config(repeated)?;
    assert_eq!((result.created, result.updated, result.unchanged), (0, 0, 3));
    assert_eq!(before, types.iter().map(|kind| store.list(*kind)).collect::<Result<Vec<_>, _>>()?);

    let manager = SessionManager::default();
    manager.reserve("imported-terminal", true)?;
    let (ready_tx, mut ready_rx) = mpsc::unbounded_channel();
    let (output_tx, mut output_rx) = mpsc::unbounded_channel();
    let terminal = Box::pin(manager.run(
        "imported-terminal",
        &profile_id,
        None,
        true,
        store,
        |event| {
            match event {
                SessionEvent::Ready { transport_id } => {
                    ready_tx.send(transport_id).map_err(|_| "ready receiver closed")?;
                }
                SessionEvent::Preparation { event, .. } => match *event {
                    PreparationEvent::Trust { .. } => {
                        return Err("imported ordinary host key was not trusted".into());
                    }
                    PreparationEvent::Passphrase { .. }
                    | PreparationEvent::KeyboardInteractive { .. }
                    | PreparationEvent::CommandExecution { .. } => {
                        return Err(
                            "imported fixture requested unexpected authentication input".into()
                        );
                    }
                    _ => (),
                },
                SessionEvent::Failed { error, .. } => return Err(error),
                _ => (),
            }
            Ok(())
        },
        |_, bytes| output_tx.send(bytes).map_err(|_| "output receiver closed".into()),
        |_, _| {},
    ));
    let exercise = Box::pin(async {
        let result =
            Box::pin(exercise(&manager, scratch.path(), "import", &mut ready_rx, &mut output_rx))
                .await;
        let _ = manager.close("imported-terminal");
        result
    });
    let (terminal, exercise) =
        tokio::time::timeout(Duration::from_secs(90), async { tokio::join!(terminal, exercise) })
            .await?;
    exercise?;
    terminal?;

    Box::pin(portable_generated_roundtrip(args, scratch.path(), &source)).await?;

    std::fs::write(&first, first_text.replace("User smoke", "User moved"))?;
    let changed = inventory.preview_open_ssh_config(source_path)?;
    let row = changed.entries.iter().find(|row| row.alias == "live").unwrap();
    assert_eq!(row.action, OpenSshImportAction::Update);
    assert_eq!(row.username, "moved");
    let updated = inventory.import_open_ssh_config(changed)?;
    let live = updated.hosts.iter().find(|host| host.summary.name == "live").unwrap();
    assert_eq!(live.summary.id, host_id);
    assert_eq!(live.logins[0].id, profile_id);
    assert_eq!(std::fs::read_to_string(&source)?, source_text);
    println!(
        "OpenSSH import and portable generated-key export/import/reopen, SSH, resize and binary SFTP passed"
    );
    Ok(())
}

async fn exercise(
    manager: &SessionManager,
    scratch: &Path,
    prefix: &str,
    ready: &mut mpsc::UnboundedReceiver<String>,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = ready.recv().await.ok_or("imported terminal did not become ready")?;
    manager.resize("imported-terminal", &transport, 100, 30)?;
    manager.input(
        "imported-terminal",
        &transport,
        b"printf '%s%s' SCOPLEN-IMPORT- GRID:; stty size\n".to_vec(),
    )?;
    let mut rendered = Vec::new();
    let marker = b"SCOPLEN-IMPORT-GRID:30 100\r\n";
    while !rendered.windows(marker.len()).any(|bytes| bytes == marker) {
        let bytes = output.recv().await.ok_or("imported shell closed before command output")?;
        if rendered.len() + bytes.len() > 65536 {
            return Err("fixture output exceeded its bound".into());
        }
        rendered.extend(bytes);
    }
    let bytes = (0..262149).map(|index| (index % 251) as u8).collect::<Vec<_>>();
    let filename = format!("{prefix}-binary.bin");
    let upload = scratch.join(&filename);
    std::fs::write(&upload, &bytes)?;
    let uploaded = manager
        .upload_file_with_picker(
            "imported-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            b".".to_vec(),
            || async { Ok(Some(upload.clone())) },
            |_| async { Err("new import fixture target unexpectedly exists".into()) },
            |_| {},
        )
        .await?;
    assert_eq!(uploaded.status, SessionUploadStatus::Saved);
    let directory = manager
        .list_files("imported-terminal", &transport, &Uuid::now_v7().to_string(), b".".to_vec())
        .await?;
    let remote = directory
        .entries
        .iter()
        .find(|entry| entry.name == filename)
        .ok_or("imported SFTP upload was not listed")?;
    assert_eq!(remote.size_bytes.as_deref(), Some("262149"));
    let destination = scratch.join("download.bin");
    let downloaded = manager
        .download_file_with_picker(
            "imported-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            remote.path.clone(),
            || async { Ok(Some(destination.clone())) },
            |_| {},
        )
        .await?;
    assert_eq!(downloaded.status, SessionDownloadStatus::Saved);
    assert_eq!(std::fs::read(&destination)?, bytes);
    Ok(())
}

async fn portable_generated_roundtrip(
    args: &[String],
    parent: &Path,
    fixture_config: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let scratch = tempfile::tempdir_in(parent)?;
    let source = Arc::new(Store::open(
        &scratch.path().join("portable-source.db"),
        &LocalDatabaseKey::new([21; 32]),
    )?);
    let details = Inventory::new(source.clone()).add_host(NewHost {
        name: Some("Portable generated key".into()),
        address: "127.0.0.1".into(),
        port: Some(args[1].parse()?),
        username: "smoke".into(),
        sign_in: SignIn::GenerateKey,
    })?;
    let public = details.logins[0]
        .credential
        .as_ref()
        .and_then(|credential| credential.public_key.as_ref())
        .ok_or("generated fixture key has no public identity")?;
    let mut parsed = ssh_key::PublicKey::from_openssh(public)?;
    parsed.set_comment("");
    let public = parsed.to_openssh()?;
    if !public.bytes().all(|byte| byte.is_ascii_alphanumeric() || b" -+/=".contains(&byte)) {
        return Err("generated fixture public key is not a literal OpenSSH key".into());
    }
    let output = Command::new("ssh")
        .arg("-F")
        .arg(fixture_config)
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "IdentitiesOnly=yes",
            "live",
        ])
        .arg(format!("umask 077; printf '%s\\n' '{public}' >> ~/.ssh/authorized_keys"))
        .output()?;
    if !output.status.success() {
        return Err("the owned OpenSSH fixture did not accept the generated public key".into());
    }
    let host = Uuid::parse_str(&details.summary.id)?;
    for line in std::fs::read_to_string(&args[3])?.lines() {
        let (_, key) = line.split_once(' ').ok_or("fixture host key is incomplete")?;
        let mut key = ssh_key::PublicKey::from_openssh(key)?;
        key.set_comment("");
        Repository::<TrustRecord>::new(&source).create(TrustRecordChange {
            host: Edit::Set(host),
            key: Edit::Set(key.to_openssh()?),
            fingerprint: Edit::Set(key.fingerprint(ssh_key::HashAlg::Sha256).to_string()),
            provenance: Some(Provenance::Manual),
            ..Default::default()
        })?;
    }
    let archives = PortableArchives::default();
    let passphrase = PortableExportPassphrase::new("disposable portable archive fixture".into())?;
    let archive = scratch.path().join("generated.age");
    archives.export(
        &source,
        std::fs::File::create_new(&archive)?,
        ExportOptions { secrets: ArchiveSecretMode::Included },
        Some(&passphrase),
    )?;
    let database = scratch.path().join("portable-destination.db");
    let destination = Arc::new(Store::open(&database, &LocalDatabaseKey::new([22; 32]))?);
    let preview =
        archives.preview(&destination, std::fs::File::open(&archive)?, Some(&passphrase))?;
    assert!(preview.can_import);
    assert!(!serde_json::to_string(&preview)?.contains("PRIVATE KEY"));
    let trust_source_ids = preview
        .entries
        .iter()
        .filter(|entry| entry.trust.as_ref().is_some_and(|trust| trust.requires_consent))
        .map(|entry| entry.source_id.clone())
        .collect();
    archives.import(
        &destination,
        std::fs::File::open(&archive)?,
        Some(&passphrase),
        &preview.id,
        ImportConsent { retain_secret_source_ids: vec![], trust_source_ids },
    )?;
    let login = destination.list(ObjectType::ACCESS_PROFILE)?.remove(0).id;
    assert_ne!(login.to_string(), details.logins[0].id);
    drop(destination);
    let reopened = Arc::new(Store::open(&database, &LocalDatabaseKey::new([22; 32]))?);
    let manager = SessionManager::default();
    manager.reserve("imported-terminal", true)?;
    let (ready_tx, mut ready_rx) = mpsc::unbounded_channel();
    let (output_tx, mut output_rx) = mpsc::unbounded_channel();
    let login = login.to_string();
    let terminal = Box::pin(manager.run(
        "imported-terminal",
        &login,
        None,
        true,
        reopened,
        |event| {
            match event {
                SessionEvent::Ready { transport_id } => {
                    ready_tx.send(transport_id).map_err(|_| "portable ready receiver closed")?;
                }
                SessionEvent::Preparation { event, .. } => match *event {
                    PreparationEvent::Trust { .. }
                    | PreparationEvent::Passphrase { .. }
                    | PreparationEvent::KeyboardInteractive { .. }
                    | PreparationEvent::CommandExecution { .. } => {
                        return Err(
                            "portable generated-key fixture unexpectedly requested input".into()
                        );
                    }
                    _ => (),
                },
                SessionEvent::Failed { error, .. } => return Err(error),
                _ => (),
            }
            Ok(())
        },
        |_, bytes| output_tx.send(bytes).map_err(|_| "portable output receiver closed".into()),
        |_, _| {},
    ));
    let exercise = Box::pin(async {
        let result =
            Box::pin(exercise(&manager, scratch.path(), "portable", &mut ready_rx, &mut output_rx))
                .await;
        let _ = manager.close("imported-terminal");
        result
    });
    let (terminal, exercise) =
        tokio::time::timeout(Duration::from_secs(90), async { tokio::join!(terminal, exercise) })
            .await?;
    exercise?;
    terminal?;
    Ok(())
}
