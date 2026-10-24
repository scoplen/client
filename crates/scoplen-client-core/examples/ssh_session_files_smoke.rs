// SPDX-License-Identifier: Apache-2.0

//! Exercise terminal-owned SFTP browsing, transfer, and file changes against disposable OpenSSH.

use std::env;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scoplen_client_core::connection::preparation::{PreparationEvent, PreparationResponse};
use scoplen_client_core::inventory::{Inventory, NewHost, SignIn};
use scoplen_client_core::session_files::{
    RemoteFileKind, SessionFileMutationStatus, SessionFileTransferPhase, SessionUploadStatus,
};
use scoplen_client_core::session_manager::{
    SessionEvent, SessionFileTransferProgress, SessionManager,
};
use scoplen_client_core::store::Store;
use scoplen_crypto::LocalDatabaseKey;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 4 {
        return Err("usage: ssh_session_files_smoke <host> <port> <password-file>".into());
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(run(&args))
}

async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let scratch = tempfile::tempdir()?;
    let store =
        Arc::new(Store::open(&scratch.path().join("local.db"), &LocalDatabaseKey::new([7; 32]))?);
    let host = Inventory::new(store.clone()).add_host(NewHost {
        name: Some("disposable file fixture".into()),
        address: args[1].clone(),
        port: Some(args[2].parse()?),
        username: "smoke".into(),
        sign_in: SignIn::Password { password: String::from_utf8(fs::read(&args[3])?)? },
    })?;
    let manager = SessionManager::default();
    manager.reserve("fixture-terminal", true)?;
    let (ready_tx, mut ready_rx) = mpsc::unbounded_channel::<String>();
    let (output_tx, mut output_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let terminal = manager.run(
        "fixture-terminal",
        &host.logins[0].id,
        None,
        true,
        store,
        |event| {
            match event {
                SessionEvent::Preparation { event, .. } => {
                    if let PreparationEvent::Trust { prompt_id, .. } = *event {
                        manager.respond(
                            "fixture-terminal",
                            &prompt_id,
                            PreparationResponse::AcceptHostKey,
                        )?;
                    }
                }
                SessionEvent::Ready { transport_id } => {
                    ready_tx.send(transport_id).map_err(|_| "ready receiver closed")?;
                }
                SessionEvent::Failed { error, .. } => return Err(error),
                _ => {}
            }
            Ok(())
        },
        |_, bytes| output_tx.send(bytes).map_err(|_| "output receiver closed".into()),
        |_, _| {},
    );
    let exercise = async {
        let result = exercise(&manager, scratch.path(), &mut ready_rx, &mut output_rx).await;
        let _ = manager.close("fixture-terminal");
        result
    };
    let (terminal, exercise) =
        tokio::time::timeout(Duration::from_secs(60), async { tokio::join!(terminal, exercise) })
            .await?;
    exercise?;
    terminal?;
    Ok(())
}

async fn exercise(
    manager: &SessionManager,
    local: &std::path::Path,
    ready: &mut mpsc::UnboundedReceiver<String>,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = ready.recv().await.ok_or("terminal did not become ready")?;
    manager.input(
        "fixture-terminal",
        &transport,
        b"mkdir -p .scoplen-files-smoke && { dd if=/dev/zero bs=32768 count=8 2>/dev/null; printf '\\377\\001END'; } > .scoplen-files-smoke/binary.bin && truncate -s 1099511627776 .scoplen-files-smoke/large.bin && printf '%s%s\\n' SCOPLEN- SHELL-READY\n"
            .to_vec(),
    )?;
    wait_for(output, b"SCOPLEN-SHELL-READY").await?;

    let operation = Uuid::now_v7().to_string();
    let browse = manager.list_files("fixture-terminal", &transport, &operation, b".".to_vec());
    let terminal_input = async {
        manager.input(
            "fixture-terminal",
            &transport,
            b"printf '%s%s\\n' SCOPLEN- TERMINAL-ALIVE\n".to_vec(),
        )?;
        manager.resize("fixture-terminal", &transport, 100, 30)
    };
    let (directory, sent) = tokio::join!(browse, terminal_input);
    sent?;
    let directory = directory?;
    let folder = directory
        .entries
        .iter()
        .find(|entry| entry.name == ".scoplen-files-smoke")
        .ok_or("remote fixture directory was not listed")?;
    assert_eq!(folder.kind, RemoteFileKind::Directory);
    wait_for(output, b"SCOPLEN-TERMINAL-ALIVE").await?;

    let remote_folder = manager
        .list_files(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
        )
        .await?;
    let file = remote_folder
        .entries
        .iter()
        .find(|entry| entry.name == "binary.bin")
        .ok_or("binary fixture was not listed")?;
    assert_eq!(file.kind, RemoteFileKind::File);
    assert_eq!(file.size_bytes.as_deref(), Some("262149"));

    let destination = local.join("downloaded.bin");
    fs::write(&destination, b"original")?;
    let download_id = Uuid::now_v7().to_string();
    let download_progress = Arc::new(Mutex::new(Vec::new()));
    let observed_download = download_progress.clone();
    let download = manager.download_file_with_picker(
        "fixture-terminal",
        &transport,
        &download_id,
        file.path.clone(),
        || async { Ok(Some(destination.clone())) },
        move |update| observed_download.lock().unwrap().push(update),
    );
    let terminal_during_download = async {
        manager.input(
            "fixture-terminal",
            &transport,
            b"printf '%s%s\\n' SCOPLEN- DOWNLOAD-ALIVE\n".to_vec(),
        )?;
        manager.resize("fixture-terminal", &transport, 110, 35)
    };
    let (downloaded, sent) = tokio::join!(download, terminal_during_download);
    sent?;
    assert!(downloaded?);
    assert_transfer_progress(&download_progress.lock().unwrap(), &transport, &download_id, 262149);
    wait_for(output, b"SCOPLEN-DOWNLOAD-ALIVE").await?;
    let downloaded = fs::read(&destination)?;
    assert_eq!(downloaded.len(), 262149);
    assert!(downloaded[..262144].iter().all(|byte| *byte == 0));
    assert_eq!(&downloaded[262144..], b"\xff\x01END");
    assert!(fs::read_dir(local)?.all(|entry| {
        !entry.unwrap().file_name().to_string_lossy().starts_with(".scoplen-download-")
    }));

    let upload_source = local.join("upload.bin");
    fs::write(&upload_source, b"first\0\xffupload")?;
    let upload_id = Uuid::now_v7().to_string();
    let upload_progress = Arc::new(Mutex::new(Vec::new()));
    let observed_upload = upload_progress.clone();
    let uploaded = manager
        .upload_file_with_picker(
            "fixture-terminal",
            &transport,
            &upload_id,
            folder.path.clone(),
            || async { Ok(Some(upload_source.clone())) },
            |_| async { Err("new target unexpectedly requested replacement".into()) },
            move |update| observed_upload.lock().unwrap().push(update),
        )
        .await?;
    assert_eq!(uploaded.status, SessionUploadStatus::Saved);
    assert_transfer_progress(&upload_progress.lock().unwrap(), &transport, &upload_id, 13);
    assert!(!uploaded.staging_may_remain);
    let remote_upload = manager
        .list_files(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
        )
        .await?
        .entries
        .into_iter()
        .find(|entry| entry.name == "upload.bin")
        .ok_or("uploaded file was not listed")?;
    let first_download = local.join("upload-first.bin");
    manager
        .download_file_with_picker(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            remote_upload.path.clone(),
            || async { Ok(Some(first_download.clone())) },
            |_| {},
        )
        .await?;
    assert_eq!(fs::read(&first_download)?, b"first\0\xffupload");

    fs::write(&upload_source, b"replacement\0\xfe")?;
    let confirmations = AtomicUsize::new(0);
    let declined = manager
        .upload_file_with_picker(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
            || async { Ok(Some(upload_source.clone())) },
            |name| {
                assert_eq!(name, "upload.bin");
                confirmations.fetch_add(1, Ordering::SeqCst);
                async { Ok(false) }
            },
            |_| {},
        )
        .await?;
    assert_eq!(declined.status, SessionUploadStatus::Cancelled);
    assert_eq!(confirmations.load(Ordering::SeqCst), 1);
    let declined_download = local.join("upload-declined.bin");
    manager
        .download_file_with_picker(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            remote_upload.path.clone(),
            || async { Ok(Some(declined_download.clone())) },
            |_| {},
        )
        .await?;
    assert_eq!(fs::read(&declined_download)?, b"first\0\xffupload");
    let replaced = manager
        .upload_file_with_picker(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
            || async { Ok(Some(upload_source.clone())) },
            |name| {
                assert_eq!(name, "upload.bin");
                confirmations.fetch_add(1, Ordering::SeqCst);
                async { Ok(true) }
            },
            |_| {},
        )
        .await?;
    assert_eq!(replaced.status, SessionUploadStatus::Saved);
    assert_eq!(confirmations.load(Ordering::SeqCst), 2);
    let replacement_download = local.join("upload-replaced.bin");
    manager
        .download_file_with_picker(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            remote_upload.path,
            || async { Ok(Some(replacement_download.clone())) },
            |_| {},
        )
        .await?;
    assert_eq!(fs::read(&replacement_download)?, b"replacement\0\xfe");
    let staged = manager
        .list_files(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
        )
        .await?;
    assert!(staged.entries.iter().all(|entry| !entry.name.starts_with(".scoplen-upload-")));

    let created = manager
        .create_remote_directory(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
            "new-directory",
        )
        .await?;
    assert_eq!(created.status, SessionFileMutationStatus::Saved);
    let collision = manager
        .create_remote_directory(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
            "new-directory",
        )
        .await?;
    assert_eq!(collision.status, SessionFileMutationStatus::Conflict);
    let entries = manager
        .list_files(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
        )
        .await?;
    let new_directory = entries
        .entries
        .iter()
        .find(|entry| entry.name == "new-directory")
        .ok_or("created directory was not listed")?;
    assert_eq!(new_directory.kind, RemoteFileKind::Directory);
    let uploaded_file = entries
        .entries
        .iter()
        .find(|entry| entry.name == "upload.bin")
        .ok_or("uploaded file was not listed before rename")?;
    let renamed = manager
        .rename_remote_entry(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
            uploaded_file.path.clone(),
            "renamed.bin",
        )
        .await?;
    assert_eq!(renamed.status, SessionFileMutationStatus::Saved);
    let renamed_entries = manager
        .list_files(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
        )
        .await?;
    assert!(renamed_entries.entries.iter().all(|entry| entry.name != "upload.bin"));
    let renamed_file = renamed_entries
        .entries
        .iter()
        .find(|entry| entry.name == "renamed.bin")
        .ok_or("renamed file was not listed")?;
    let rename_collision = manager
        .rename_remote_entry(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
            renamed_file.path.clone(),
            "binary.bin",
        )
        .await?;
    assert_eq!(rename_collision.status, SessionFileMutationStatus::Conflict);
    let declined_delete = manager
        .delete_remote_entry_with_confirmation(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
            renamed_file.path.clone(),
            |kind, name| {
                assert_eq!(kind, RemoteFileKind::File);
                assert_eq!(name, "renamed.bin");
                async { Ok(false) }
            },
        )
        .await?;
    assert_eq!(declined_delete.status, SessionFileMutationStatus::Cancelled);
    let deleted_file = manager
        .delete_remote_entry_with_confirmation(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
            renamed_file.path.clone(),
            |kind, _| {
                assert_eq!(kind, RemoteFileKind::File);
                async { Ok(true) }
            },
        )
        .await?;
    assert_eq!(deleted_file.status, SessionFileMutationStatus::Saved);
    let deleted_directory = manager
        .delete_remote_entry_with_confirmation(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
            new_directory.path.clone(),
            |kind, _| {
                assert_eq!(kind, RemoteFileKind::Directory);
                async { Ok(true) }
            },
        )
        .await?;
    assert_eq!(deleted_directory.status, SessionFileMutationStatus::Saved);
    let nonempty_directory = manager
        .delete_remote_entry_with_confirmation(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            b".".to_vec(),
            folder.path.clone(),
            |kind, _| {
                assert_eq!(kind, RemoteFileKind::Directory);
                async { Ok(true) }
            },
        )
        .await?;
    assert_eq!(nonempty_directory.status, SessionFileMutationStatus::Failed);
    manager.input(
        "fixture-terminal",
        &transport,
        b"ln -s binary.bin .scoplen-files-smoke/link.bin && printf '%s%s\\n' SCOPLEN- LINK-READY\n"
            .to_vec(),
    )?;
    wait_for(output, b"SCOPLEN-LINK-READY").await?;
    let linked = manager
        .list_files(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
        )
        .await?
        .entries
        .into_iter()
        .find(|entry| entry.name == "link.bin")
        .ok_or("link fixture was not listed")?;
    assert_eq!(linked.kind, RemoteFileKind::Other);
    let special = manager
        .delete_remote_entry_with_confirmation(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
            linked.path,
            |_, _| async { Err("special entry must not request confirmation".into()) },
        )
        .await?;
    assert_eq!(special.status, SessionFileMutationStatus::Unsupported);

    let cancelled_source = local.join("cancel-upload.bin");
    fs::File::create(&cancelled_source)?.set_len(1024 * 1024 * 1024)?;
    manager.input(
        "fixture-terminal",
        &transport,
        b"while :; do for staged in .scoplen-files-smoke/.scoplen-upload-*.part; do if [ -s \"$staged\" ] && [ ! -e .scoplen-files-smoke/cancel-upload.bin ]; then printf '%s%s\\n' SCOPLEN- UPLOAD-IN-FLIGHT; break 2; fi; done; sleep 0.02; done\n".to_vec(),
    )?;
    let cancel_upload_id = Uuid::now_v7().to_string();
    let upload = manager.upload_file_with_picker(
        "fixture-terminal",
        &transport,
        &cancel_upload_id,
        folder.path.clone(),
        || async { Ok(Some(cancelled_source.clone())) },
        |_| async { Err("new target unexpectedly requested replacement".into()) },
        |_| {},
    );
    let cancel_after_staging = async {
        tokio::time::timeout(
            Duration::from_secs(10),
            wait_for(output, b"SCOPLEN-UPLOAD-IN-FLIGHT"),
        )
        .await??;
        manager.cancel_file_operation("fixture-terminal", &transport, &cancel_upload_id)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let (cancelled, cancelled_after_staging) = tokio::join!(upload, cancel_after_staging);
    cancelled_after_staging?;
    let cancelled = cancelled?;
    assert_eq!(cancelled.status, SessionUploadStatus::Cancelled);
    assert!(!cancelled.staging_may_remain);
    let after_cancel = manager
        .list_files(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
        )
        .await?;
    assert!(after_cancel.entries.iter().all(|entry| {
        entry.name != "cancel-upload.bin" && !entry.name.starts_with(".scoplen-upload-")
    }));
    manager.input(
        "fixture-terminal",
        &transport,
        b"printf '%s%s\\n' SCOPLEN- UPLOAD-CANCEL-ALIVE\n".to_vec(),
    )?;
    wait_for(output, b"SCOPLEN-UPLOAD-CANCEL-ALIVE").await?;

    let blocked_destination = local.join("existing-directory");
    fs::create_dir(&blocked_destination)?;
    let failed_download_id = Uuid::now_v7().to_string();
    let failed_progress = Arc::new(Mutex::new(Vec::new()));
    let observed_failure = failed_progress.clone();
    assert!(
        manager
            .download_file_with_picker(
                "fixture-terminal",
                &transport,
                &failed_download_id,
                file.path.clone(),
                || async { Ok(Some(blocked_destination.clone())) },
                move |update| observed_failure.lock().unwrap().push(update),
            )
            .await
            .unwrap_err()
            .contains("local file could not be saved")
    );
    assert_transfer_progress(
        &failed_progress.lock().unwrap(),
        &transport,
        &failed_download_id,
        262149,
    );
    assert!(blocked_destination.is_dir());
    assert!(fs::read_dir(local)?.all(|entry| {
        !entry.unwrap().file_name().to_string_lossy().starts_with(".scoplen-download-")
    }));

    let large = remote_folder
        .entries
        .iter()
        .find(|entry| entry.name == "large.bin")
        .ok_or("large sparse fixture was not listed")?;
    assert_eq!(large.size_bytes.as_deref(), Some("1099511627776"));
    let cancel_transfer_id = Uuid::now_v7().to_string();
    let cancelled_destination = local.join("cancelled.bin");
    let transfer = manager.download_file_with_picker(
        "fixture-terminal",
        &transport,
        &cancel_transfer_id,
        large.path.clone(),
        || async { Ok(Some(cancelled_destination.clone())) },
        |_| {},
    );
    let cancel_transfer = async {
        let part = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(entry) = fs::read_dir(local)?.find(|entry| {
                    entry.as_ref().is_ok_and(|entry| {
                        entry.file_name().to_string_lossy().starts_with(".scoplen-download-")
                    })
                }) {
                    break Ok::<_, std::io::Error>(entry?.path());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;
        manager.input(
            "fixture-terminal",
            &transport,
            b"printf '%s%s\\n' SCOPLEN- TRANSFER-ALIVE\n".to_vec(),
        )?;
        manager.resize("fixture-terminal", &transport, 120, 40)?;
        manager.cancel_file_operation("fixture-terminal", &transport, &cancel_transfer_id)?;
        Ok::<_, Box<dyn std::error::Error>>(part)
    };
    let (transfer, cancelled_part) = tokio::join!(transfer, cancel_transfer);
    assert!(transfer.unwrap_err().contains("cancelled"));
    let cancelled_part = cancelled_part?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while cancelled_part.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert!(!cancelled_destination.exists());
    tokio::time::timeout(Duration::from_secs(10), wait_for(output, b"SCOPLEN-TRANSFER-ALIVE"))
        .await??;

    let missing = manager
        .list_files(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            b"./.scoplen-files-smoke/missing".to_vec(),
        )
        .await;
    assert!(missing.is_err(), "missing remote path should be refused");
    manager
        .list_files(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
        )
        .await?;

    let cancel_id = Uuid::now_v7().to_string();
    let (entered_tx, entered_rx) = oneshot::channel();
    let (_chosen_tx, chosen_rx) = oneshot::channel::<std::path::PathBuf>();
    let picker = manager.download_file_with_picker(
        "fixture-terminal",
        &transport,
        &cancel_id,
        file.path.clone(),
        || async move {
            let _ = entered_tx.send(());
            Ok(Some(chosen_rx.await.map_err(|_| "picker closed")?))
        },
        |_| {},
    );
    let cancel = async {
        entered_rx.await.map_err(|_| "picker did not start")?;
        manager.cancel_file_operation("fixture-terminal", &transport, &cancel_id)
    };
    let (picker, cancel) = tokio::join!(picker, cancel);
    cancel?;
    assert!(picker.unwrap_err().contains("cancelled"));
    manager
        .list_files(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
        )
        .await?;
    Ok(())
}

async fn wait_for(
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    marker: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut received = Vec::new();
    loop {
        let bytes = output.recv().await.ok_or("terminal output ended")?;
        received.extend(bytes);
        if received.windows(marker.len()).any(|part| part == marker) {
            return Ok(());
        }
        if received.len() > 1024 * 1024 {
            return Err("terminal fixture produced too much output".into());
        }
    }
}

fn assert_transfer_progress(
    updates: &[SessionFileTransferProgress],
    transport: &str,
    operation: &str,
    total: u64,
) {
    assert!(updates.len() >= 2, "transfer should report data and finalization");
    assert_eq!(updates[0].transferred_bytes, "0");
    assert_eq!(updates[0].phase, SessionFileTransferPhase::Transferring);
    let mut previous = 0;
    let expected_total = total.to_string();
    for update in updates {
        assert_eq!(update.session_id, "fixture-terminal");
        assert_eq!(update.transport_id, transport);
        assert_eq!(update.operation_id, operation);
        assert_eq!(update.total_bytes.as_deref(), Some(expected_total.as_str()));
        let transferred = update.transferred_bytes.parse::<u64>().unwrap();
        assert!(transferred >= previous && transferred <= total);
        previous = transferred;
    }
    let last = updates.last().unwrap();
    assert_eq!(last.phase, SessionFileTransferPhase::Finalizing);
    assert_eq!(last.transferred_bytes, total.to_string());
}
