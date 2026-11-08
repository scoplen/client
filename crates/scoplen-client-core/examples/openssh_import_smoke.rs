// SPDX-License-Identifier: Apache-2.0

//! Read-only OpenSSH migration, differential evaluation, and an imported SSH/SFTP session.

use std::{path::Path, process::Command, sync::Arc, time::Duration};

use scoplen_client_core::{
    connection::preparation::PreparationEvent,
    inventory::{Inventory, NewHost, OpenSshImportAction, OpenSshImportPreview, SignIn},
    session_files::{SessionDownloadStatus, SessionUploadStatus},
    session_manager::{SessionEvent, SessionManager},
    store::Store,
};
use scoplen_crypto::LocalDatabaseKey;
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
            Box::pin(exercise(&manager, scratch.path(), &mut ready_rx, &mut output_rx)).await;
        let _ = manager.close("imported-terminal");
        result
    });
    let (terminal, exercise) =
        tokio::time::timeout(Duration::from_secs(90), async { tokio::join!(terminal, exercise) })
            .await?;
    exercise?;
    terminal?;

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
        "OpenSSH differential evaluation, repeatable import, imported-key SSH, resize and binary SFTP passed"
    );
    Ok(())
}

async fn exercise(
    manager: &SessionManager,
    scratch: &Path,
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
    let upload = scratch.join("import-binary.bin");
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
        .find(|entry| entry.name == "import-binary.bin")
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
