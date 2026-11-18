// SPDX-License-Identifier: Apache-2.0

//! Exercise terminal-owned SFTP browsing, transfer, and file changes against disposable OpenSSH.

use std::env;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scoplen_client_core::connection::preparation::{PreparationEvent, PreparationResponse};
use scoplen_client_core::inventory::{Inventory, NewHost, SignIn};
use scoplen_client_core::session_directory_copy::{
    SessionDirectoryCopyIssue, SessionDirectoryCopyPhase, SessionDirectoryCopyPrepareResult,
};
use scoplen_client_core::session_directory_sync::{
    SessionDirectorySyncApplyResult, SessionDirectorySyncChange,
    SessionDirectorySyncDirectoryChange, SessionDirectorySyncEntry, SessionDirectorySyncIssue,
    SessionDirectorySyncPlan, SessionDirectorySyncPrepareResult, SessionDirectorySyncProgress,
};
use scoplen_client_core::session_editor::{
    SessionEditorIssue, SessionEditorSnapshot, SessionEditorStartResult, SessionEditorState,
};
use scoplen_client_core::session_files::{
    RemoteFileKind, RemoteTextPreviewIssue, SessionDownloadStatus, SessionFileMutationStatus,
    SessionFileTransferPhase, SessionUploadStatus,
};
use scoplen_client_core::session_manager::{
    SessionEvent, SessionFileTransferProgress, SessionManager,
};
use scoplen_client_core::session_transfers::{
    SessionTransferDirection, SessionTransferEnqueueResult, SessionTransferItem,
    SessionTransferState,
};
use scoplen_client_core::store::Store;
use scoplen_crypto::LocalDatabaseKey;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if !(args.len() == 4 || args.len() == 5 && args[4] == "--unknown") {
        return Err(
            "usage: ssh_session_files_smoke <host> <port> <password-file> [--unknown]".into()
        );
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(run(&args)))
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
    let terminal = Box::pin(manager.run(
        "fixture-terminal",
        &host.logins[0].id,
        None,
        true,
        store,
        |event| {
            match event {
                SessionEvent::Preparation { transport_id, event } => {
                    if let PreparationEvent::Trust { prompt_id, .. } = *event {
                        manager.respond(
                            "fixture-terminal",
                            &transport_id,
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
    ));
    let exercise = async {
        let result = if args.len() == 5 {
            exercise_sync_unknown(&manager, scratch.path(), &mut ready_rx, &mut output_rx).await
        } else {
            exercise(&manager, scratch.path(), &mut ready_rx, &mut output_rx).await
        };
        let _ = manager.close("fixture-terminal");
        result
    };
    let (terminal, exercise) =
        tokio::time::timeout(Duration::from_secs(600), async { tokio::join!(terminal, exercise) })
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

    exercise_preview(manager, &transport, local, output).await?;
    exercise_editor(manager, &transport, local, output).await?;
    exercise_directory_sync(manager, &transport, local, output).await?;
    exercise_directory_copy(manager, &transport, local, output).await?;

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
    assert_eq!(downloaded?.status, SessionDownloadStatus::Saved);
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
    let failed = manager
        .download_file_with_picker(
            "fixture-terminal",
            &transport,
            &failed_download_id,
            file.path.clone(),
            || async { Ok(Some(blocked_destination.clone())) },
            move |update| observed_failure.lock().unwrap().push(update),
        )
        .await?;
    assert_eq!(failed.status, SessionDownloadStatus::Failed);
    assert!(
        failed.message.as_deref().unwrap_or_default().contains("local file could not be saved")
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
    assert_eq!(transfer?.status, SessionDownloadStatus::Cancelled);
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
    assert_eq!(picker?.status, SessionDownloadStatus::Cancelled);
    manager
        .list_files(
            "fixture-terminal",
            &transport,
            &Uuid::now_v7().to_string(),
            folder.path.clone(),
        )
        .await?;
    exercise_queue(manager, local, &transport, folder.path.clone(), file.path.clone(), output)
        .await?;
    exercise_download_resume(manager, local, &transport, folder.path.clone(), output).await?;
    exercise_upload_resume(manager, local, &transport, folder.path.clone(), output).await?;
    Ok(())
}

async fn exercise_preview(
    manager: &SessionManager,
    transport: &str,
    local: &std::path::Path,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    manager.input("fixture-terminal", transport, b"printf 'Scoplen UTF-8 \\344\\270\\255\\346\\226\\207\\r\\n\\t<literal>\\n' > .scoplen-files-smoke/preview.txt && : > .scoplen-files-smoke/empty.txt && head -c 262144 /dev/zero | tr '\\000' x > .scoplen-files-smoke/cap.txt; printf '\\377' > .scoplen-files-smoke/invalid.txt; printf 'text\\000control' > .scoplen-files-smoke/control.txt; ln -s preview.txt .scoplen-files-smoke/preview-link; printf secret > .scoplen-files-smoke/denied.txt; chmod 000 .scoplen-files-smoke/denied.txt; printf '%s%s\\n' SCOPLEN- PREVIEW-READY\n".to_vec())?;
    wait_for(output, b"SCOPLEN-PREVIEW-READY").await?;
    let local_before = fs::read_dir(local)?.count();
    let operation = Uuid::now_v7().to_string();
    let preview = manager.preview_file(
        "fixture-terminal",
        transport,
        &operation,
        b"./.scoplen-files-smoke/preview.txt".to_vec(),
    );
    let terminal = async {
        manager.input(
            "fixture-terminal",
            transport,
            b"printf '%s%s\\n' SCOPLEN- PREVIEW-ALIVE\n".to_vec(),
        )?;
        manager.resize("fixture-terminal", transport, 115, 36)
    };
    let (preview, sent) = tokio::join!(preview, terminal);
    sent?;
    let preview = preview.map_err(|issue| format!("text preview failed: {issue:?}"))?;
    assert_eq!(preview.text, "Scoplen UTF-8 中文\r\n\t<literal>\n");
    assert_eq!(preview.size_bytes as usize, preview.text.len());
    wait_for(output, b"SCOPLEN-PREVIEW-ALIVE").await?;
    for name in ["empty.txt", "cap.txt"] {
        let path = format!("./.scoplen-files-smoke/{name}").into_bytes();
        let result = manager
            .preview_file("fixture-terminal", transport, &Uuid::now_v7().to_string(), path)
            .await
            .map_err(|issue| format!("bounded preview failed: {issue:?}"))?;
        if name == "empty.txt" {
            assert!(result.text.is_empty());
        } else {
            assert_eq!(result.text.len(), 262144);
            assert!(result.text.bytes().all(|byte| byte == b'x'));
        }
    }
    for (name, issue) in [
        ("binary.bin", RemoteTextPreviewIssue::TooLarge),
        ("invalid.txt", RemoteTextPreviewIssue::NotText),
        ("control.txt", RemoteTextPreviewIssue::NotText),
        ("preview-link", RemoteTextPreviewIssue::NotRegularFile),
        ("denied.txt", RemoteTextPreviewIssue::RemoteDenied),
    ] {
        assert_eq!(
            manager
                .preview_file(
                    "fixture-terminal",
                    transport,
                    &Uuid::now_v7().to_string(),
                    format!("./.scoplen-files-smoke/{name}").into_bytes()
                )
                .await
                .unwrap_err(),
            issue
        );
    }
    assert_eq!(
        manager
            .preview_file(
                "fixture-terminal",
                transport,
                &Uuid::now_v7().to_string(),
                b"./.scoplen-files-smoke".to_vec()
            )
            .await
            .unwrap_err(),
        RemoteTextPreviewIssue::NotRegularFile
    );
    let after_refusal = manager
        .preview_file(
            "fixture-terminal",
            transport,
            &Uuid::now_v7().to_string(),
            b"./.scoplen-files-smoke/preview.txt".to_vec(),
        )
        .await
        .map_err(|issue| format!("preview after refusal failed: {issue:?}"))?;
    assert_eq!(after_refusal.text, preview.text);
    assert_eq!(fs::read_dir(local)?.count(), local_before, "preview must not create local files");
    Ok(())
}

async fn exercise_editor(
    manager: &SessionManager,
    transport: &str,
    local: &std::path::Path,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    manager.input("fixture-terminal", transport, b"printf 'original editor text\\n' > .scoplen-files-smoke/editor.txt; printf '%s%s\\n' SCOPLEN- EDITOR-READY\n".to_vec())?;
    wait_for(output, b"SCOPLEN-EDITOR-READY").await?;
    let copy = local.join("different-editor-name.txt");
    let picked = copy.clone();
    let expected = copy.clone();
    let launches = Arc::new(AtomicUsize::new(0));
    let observed = launches.clone();
    let result = manager
        .edit_file_with_picker(
            "fixture-terminal",
            transport,
            b"./.scoplen-files-smoke/editor.txt".to_vec(),
            move || async { Ok(Some(picked)) },
            |_| async { panic!("new editor copy must not request replacement") },
            move |path| {
                assert_eq!(path, expected);
                let observed = observed.clone();
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        )
        .await?;
    let SessionEditorStartResult::Started { editor_id } = result else {
        return Err("editor selection cancelled".into());
    };
    let saved =
        wait_editor(manager, |snapshot| snapshot.state == SessionEditorState::Watching).await?;
    assert_eq!(saved.remote_name, "./.scoplen-files-smoke/editor.txt");
    assert_eq!(fs::read(&copy)?, b"original editor text\n");
    assert_eq!(launches.load(Ordering::SeqCst), 1);
    let replacement = local.join("editor-atomic-save.txt");
    fs::write(&replacement, b"explicit edited text\n")?;
    fs::rename(replacement, &copy)?;
    wait_editor(manager, |snapshot| snapshot.state == SessionEditorState::ChangesDetected).await?;
    assert_drop_bytes(
        manager,
        local,
        transport,
        b"./.scoplen-files-smoke",
        "editor.txt",
        b"original editor text\n",
    )
    .await?;
    let declined = manager
        .upload_editor("fixture-terminal", transport, &editor_id, |_| async { Ok(false) })
        .await?;
    assert_eq!(
        wait_queue_item(manager, &queue_identity(&declined).1).await?.state,
        SessionTransferState::Cancelled
    );
    wait_editor(manager, |snapshot| snapshot.state == SessionEditorState::ChangesDetected).await?;
    assert_drop_bytes(
        manager,
        local,
        transport,
        b"./.scoplen-files-smoke",
        "editor.txt",
        b"original editor text\n",
    )
    .await?;
    manager.input("fixture-terminal", transport, b"printf 'remote edit\\n' > .scoplen-files-smoke/editor.txt; printf '%s%s\\n' SCOPLEN- EDITOR-REMOTE-CHANGED\n".to_vec())?;
    wait_for(output, b"SCOPLEN-EDITOR-REMOTE-CHANGED").await?;
    let confirmations = Arc::new(AtomicUsize::new(0));
    let confirmed = confirmations.clone();
    let uploaded = manager
        .upload_editor("fixture-terminal", transport, &editor_id, move |review| {
            assert_eq!(review.name, "editor.txt");
            async move {
                confirmed.fetch_add(1, Ordering::SeqCst);
                Ok(true)
            }
        })
        .await?;
    assert_eq!(
        wait_queue_item(manager, &queue_identity(&uploaded).1).await?.state,
        SessionTransferState::Saved
    );
    wait_editor(manager, |snapshot| snapshot.state == SessionEditorState::Uploaded).await?;
    assert_eq!(confirmations.load(Ordering::SeqCst), 1);
    assert_drop_bytes(
        manager,
        local,
        transport,
        b"./.scoplen-files-smoke",
        "editor.txt",
        b"explicit edited text\n",
    )
    .await?;
    fs::write(&copy, [0])?;
    assert_eq!(
        manager
            .upload_editor("fixture-terminal", transport, &editor_id, |_| async {
                panic!("invalid text must not reach confirmation")
            })
            .await,
        Err(SessionEditorIssue::NotText)
    );
    assert_eq!(fs::read(&copy)?, [0]);
    manager.stop_editor("fixture-terminal", &editor_id)?;
    assert!(copy.exists());
    for (name, issue) in [
        ("invalid.txt", SessionEditorIssue::NotText),
        ("binary.bin", SessionEditorIssue::TooLarge),
        ("preview-link", SessionEditorIssue::InvalidSelection),
    ] {
        let destination = local.join(format!("refused-editor-{name}.txt"));
        fs::write(&destination, b"existing local copy")?;
        let picked = destination.clone();
        let result = manager
            .edit_file_with_picker(
                "fixture-terminal",
                transport,
                format!("./.scoplen-files-smoke/{name}").into_bytes(),
                move || async { Ok(Some(picked)) },
                |_| async { Ok(true) },
                |_| async { panic!("refused editor download must never launch") },
            )
            .await?;
        let SessionEditorStartResult::Started { editor_id } = result else { panic!() };
        wait_editor(manager, |snapshot| snapshot.issue == Some(issue)).await?;
        assert_eq!(fs::read(destination)?, b"existing local copy");
        manager.stop_editor("fixture-terminal", &editor_id)?;
    }
    println!(
        "local editor core: real OpenSSH text download, atomic local save detection, explicit original-target upload, refusal and retained copy passed; editor launch was injected"
    );
    Ok(())
}

async fn wait_editor(
    manager: &SessionManager,
    expected: impl Fn(&SessionEditorSnapshot) -> bool,
) -> Result<SessionEditorSnapshot, Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let snapshot =
                manager.editor_snapshot("fixture-terminal")?.ok_or("editor registration ended")?;
            if expected(&snapshot) {
                return Ok::<_, Box<dyn std::error::Error>>(snapshot);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?
}

async fn directory_plan(
    manager: &SessionManager,
    transport: &str,
    remote: &[u8],
    local: &std::path::Path,
    direction: SessionTransferDirection,
) -> Result<SessionDirectorySyncPlan, Box<dyn std::error::Error>> {
    let folder = local.to_path_buf();
    let result = manager
        .prepare_directory_sync_with_picker(
            "fixture-terminal",
            transport,
            &Uuid::now_v7().to_string(),
            remote.to_vec(),
            direction,
            move || async { Ok(Some(folder)) },
        )
        .await?;
    let SessionDirectorySyncPrepareResult::Prepared { plan } = result else {
        return Err("directory selection cancelled".into());
    };
    Ok(plan)
}

async fn apply_directory(
    manager: &SessionManager,
    transport: &str,
    plan: &SessionDirectorySyncPlan,
    decline: Option<usize>,
) -> Result<SessionTransferItem, Box<dyn std::error::Error>> {
    let direction = plan.direction;
    let confirmations = Arc::new(AtomicUsize::new(0));
    let confirmed = confirmations.clone();
    let result = manager
        .apply_directory_sync("fixture-terminal", transport, &plan.plan_id, move |review| {
            let confirmed = confirmed.clone();
            async move {
                assert_eq!(review.host, "disposable file fixture");
                assert_eq!(review.username, "smoke");
                assert_eq!(review.direction, direction);
                Ok(decline != Some(confirmed.fetch_add(1, Ordering::SeqCst) + 1))
            }
        })
        .await?;
    let SessionDirectorySyncApplyResult::Queued { queue_id, item_id, execution_id } = result else {
        return Err("changed recursive directory was not queued".into());
    };
    let settled = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
            assert_eq!(snapshot.queue_id, queue_id);
            if let Some(row) = snapshot.recent.into_iter().find(|row| row.item_id == item_id) {
                assert_eq!(row.execution_id, execution_id);
                assert_eq!(row.transport_id, transport);
                assert!(row.directory_copy.is_none());
                assert_eq!(snapshot.outstanding, 0);
                return Ok::<_, Box<dyn std::error::Error>>(row);
            }
            let row = snapshot
                .items
                .iter()
                .find(|row| row.item_id == item_id)
                .ok_or("recursive sync job disappeared")?;
            assert_eq!(row.execution_id, execution_id);
            assert_eq!(row.transport_id, transport);
            assert_eq!(snapshot.outstanding, 1, "one tree must occupy exactly one slot");
            assert!(!row.can_pause && !row.can_resume);
            assert!(row.directory_sync.is_some() && row.directory_copy.is_none());
            if row.state == SessionTransferState::Unknown {
                return Err("recursive sync publication was unknown; no replay attempted".into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    if let Some(count) = decline {
        assert_eq!(
            confirmations.load(Ordering::SeqCst),
            count,
            "a refusal must stop later confirmations"
        );
    }
    settled
}

fn sync_progress(row: &SessionTransferItem) -> &SessionDirectorySyncProgress {
    row.directory_sync.as_ref().expect("recursive synchronization progress")
}

fn assert_sync_file(
    plan: &SessionDirectorySyncPlan,
    name: &str,
    change: SessionDirectorySyncChange,
) {
    assert!(
        plan.entries.iter().any(|row| matches!(row,
            SessionDirectorySyncEntry::File { name: found, change: actual, .. }
                if found == name && *actual == change
        )),
        "missing expected file action for {name}"
    );
}

fn assert_sync_directory(
    plan: &SessionDirectorySyncPlan,
    name: &str,
    change: SessionDirectorySyncDirectoryChange,
) {
    assert!(
        plan.entries.iter().any(|row| matches!(row,
            SessionDirectorySyncEntry::Directory { name: found, change: actual }
                if found == name && *actual == change
        )),
        "missing expected directory action for {name}"
    );
}

async fn remote_sync_metadata(
    manager: &SessionManager,
    transport: &str,
    remote: &[u8],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::to_value(
        manager
            .list_files("fixture-terminal", transport, &Uuid::now_v7().to_string(), remote.to_vec())
            .await?,
    )?)
}

async fn sync_shell(
    manager: &SessionManager,
    transport: &str,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    command: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    manager.input(
        "fixture-terminal",
        transport,
        format!("(set -eu; {command}); status=$?; if test $status -eq 0; then printf '%s%s\\n' SCOPLEN- SYNC-SHELL-READY; else printf '%s%s\\n' SCOPLEN- SYNC-SHELL-FAILED; fi\n").into_bytes(),
    )?;
    tokio::time::timeout(Duration::from_secs(60), wait_for(output, b"SCOPLEN-SYNC-SHELL-READY"))
        .await?
}

fn create_sync_tree(root: &std::path::Path, source: bool) -> Result<(), std::io::Error> {
    fs::create_dir_all(root.join("nested"))?;
    for (name, bytes) in [
        ("b-size", if source { b"x".as_slice() } else { b"longer".as_slice() }),
        ("c-bytes", if source { b"new".as_slice() } else { b"old".as_slice() }),
        ("d-same", b"same"),
        ("e-empty", b""),
    ] {
        fs::write(root.join(name), bytes)?;
    }
    if source {
        fs::create_dir_all(root.join("nested/deeper"))?;
        fs::create_dir(root.join("empty"))?;
        fs::write(root.join("a-create"), [0, 255, 3])?;
        fs::write(root.join("nested/deeper/payload.bin"), [255, 0, 8, 7])?;
        for index in 0..20 {
            fs::write(root.join("nested").join(format!("child-{index:02}")), b"tree")?;
        }
    } else {
        fs::create_dir_all(root.join("kept"))?;
        fs::write(root.join("kept/leaf"), b"target directory preserved")?;
        fs::write(root.join("target-only"), b"target file preserved")?;
    }
    Ok(())
}

async fn assert_sync_unchanged(
    manager: &SessionManager,
    transport: &str,
    plan: &SessionDirectorySyncPlan,
) -> Result<(), Box<dyn std::error::Error>> {
    let before = manager.transfer_queue_snapshot("fixture-terminal")?;
    assert_eq!(
        manager
            .apply_directory_sync("fixture-terminal", transport, &plan.plan_id, |_| async {
                panic!("Same/Existing rows cannot ask for replacement")
            },)
            .await?,
        SessionDirectorySyncApplyResult::Unchanged
    );
    let after = manager.transfer_queue_snapshot("fixture-terminal")?;
    assert_eq!(before.outstanding, after.outstanding);
    assert_eq!(before.items, after.items);
    assert_eq!(before.recent, after.recent);
    Ok(())
}

async fn exercise_directory_sync(
    manager: &SessionManager,
    transport: &str,
    local: &std::path::Path,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    sync_shell(manager, transport, output,
        "mkdir -p .scoplen-files-smoke/sync-links; ln -s missing .scoplen-files-smoke/sync-links/link").await?;
    for direction in [SessionTransferDirection::Upload, SessionTransferDirection::Download] {
        let label = match direction {
            SessionTransferDirection::Upload => "upload",
            SessionTransferDirection::Download => "download",
        };
        let root = local.join(format!("directory-{label}"));
        create_sync_tree(&root, direction == SessionTransferDirection::Upload)?;
        let remote = format!("./.scoplen-files-smoke/sync-{label}");
        let contents = if direction == SessionTransferDirection::Upload {
            format!(
                "mkdir -p {remote}/kept; printf longer > {remote}/b-size; printf old > {remote}/c-bytes; printf 'target file preserved' > {remote}/target-only; printf 'target directory preserved' > {remote}/kept/leaf; ln -s missing {remote}/kept/link"
            )
        } else {
            format!(
                "mkdir -p {remote}/empty {remote}/nested/deeper; printf x > {remote}/b-size; printf new > {remote}/c-bytes; printf '\\000\\377\\003' > {remote}/a-create; printf '\\377\\000\\010\\007' > {remote}/nested/deeper/payload.bin; i=0; while test $i -lt 20; do name=$(printf child-%02d $i); printf tree > {remote}/nested/$name; i=$((i+1)); done"
            )
        };
        sync_shell(manager, transport, output, &format!(
            "mkdir -p {remote}/nested; {contents}; printf same > {remote}/d-same; : > {remote}/e-empty; touch -t 200001010000 {remote}/d-same {remote}/e-empty"
        )).await?;
        let before = remote_sync_metadata(manager, transport, remote.as_bytes()).await?;
        let nested_remote = format!("{remote}/nested");
        let before_nested =
            remote_sync_metadata(manager, transport, nested_remote.as_bytes()).await?;
        let same_modified = fs::metadata(root.join("d-same"))?.modified()?;
        let empty_modified = fs::metadata(root.join("e-empty"))?.modified()?;
        let plan = directory_plan(manager, transport, remote.as_bytes(), &root, direction).await?;
        assert_eq!(plan.direction, direction);
        assert_eq!(plan.entries.len(), 30);
        assert_eq!(
            (plan.summary.files_create, plan.summary.files_changed, plan.summary.files_same),
            (22, 2, 2)
        );
        assert_eq!((plan.summary.directories_create, plan.summary.directories_existing), (2, 2));
        assert_eq!(plan.summary.transfer_size_bytes, "91");
        for (name, change) in [
            ("a-create", SessionDirectorySyncChange::Create),
            ("b-size", SessionDirectorySyncChange::Changed),
            ("c-bytes", SessionDirectorySyncChange::Changed),
            ("d-same", SessionDirectorySyncChange::Same),
            ("e-empty", SessionDirectorySyncChange::Same),
            ("nested/deeper/payload.bin", SessionDirectorySyncChange::Create),
        ] {
            assert_sync_file(&plan, name, change);
        }
        for index in 0..20 {
            assert_sync_file(
                &plan,
                &format!("nested/child-{index:02}"),
                SessionDirectorySyncChange::Create,
            );
        }
        for (name, change) in [
            (".", SessionDirectorySyncDirectoryChange::Existing),
            ("nested", SessionDirectorySyncDirectoryChange::Existing),
            ("empty", SessionDirectorySyncDirectoryChange::Create),
            ("nested/deeper", SessionDirectorySyncDirectoryChange::Create),
        ] {
            assert_sync_directory(&plan, name, change);
        }
        assert_eq!(
            before,
            remote_sync_metadata(manager, transport, remote.as_bytes()).await?,
            "comparison must not write"
        );
        assert_eq!(
            before_nested,
            remote_sync_metadata(manager, transport, nested_remote.as_bytes()).await?
        );
        if direction == SessionTransferDirection::Download {
            assert!(!root.join("a-create").exists() && !root.join("empty").exists());
            assert_eq!(fs::read(root.join("b-size"))?, b"longer");
            assert_eq!(fs::read(root.join("c-bytes"))?, b"old");
        }
        let saved = apply_directory(manager, transport, &plan, None).await?;
        assert_eq!(saved.state, SessionTransferState::Saved);
        assert_eq!(
            (saved.transferred_bytes.as_str(), saved.total_bytes.as_deref()),
            ("91", Some("91"))
        );
        let progress = sync_progress(&saved);
        assert_eq!((progress.files_total, progress.directories_total), (24, 2));
        assert_eq!(
            (
                progress.files_created,
                progress.files_updated,
                progress.files_skipped,
                progress.directories_created
            ),
            (22, 2, 2, 2)
        );
        assert!(progress.failed_name.is_none() && progress.issue.is_none());
        assert_eq!(
            manager
                .apply_directory_sync("fixture-terminal", transport, &plan.plan_id, |_| async {
                    panic!("consumed plan cannot ask again")
                })
                .await,
            Err(SessionDirectorySyncIssue::Unavailable)
        );
        let after = remote_sync_metadata(manager, transport, remote.as_bytes()).await?;
        if direction == SessionTransferDirection::Upload {
            for name in ["d-same", "e-empty"] {
                let metadata = |snapshot: &serde_json::Value| {
                    snapshot["entries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|row| row["name"] == name)
                        .unwrap()
                        .clone()
                };
                assert_eq!(
                    metadata(&before),
                    metadata(&after),
                    "Same files must retain destination metadata"
                );
            }
            for (name, expected) in [
                ("a-create", &[0, 255, 3][..]),
                ("b-size", b"x"),
                ("c-bytes", b"new"),
                ("d-same", b"same"),
                ("e-empty", b""),
                ("target-only", b"target file preserved"),
            ] {
                assert_drop_bytes(manager, local, transport, remote.as_bytes(), name, expected)
                    .await?;
            }
            for index in 0..20 {
                assert_drop_bytes(
                    manager,
                    local,
                    transport,
                    nested_remote.as_bytes(),
                    &format!("child-{index:02}"),
                    b"tree",
                )
                .await?;
            }
            assert_drop_bytes(
                manager,
                local,
                transport,
                format!("{remote}/nested/deeper").as_bytes(),
                "payload.bin",
                &[255, 0, 8, 7],
            )
            .await?;
            assert_drop_bytes(
                manager,
                local,
                transport,
                format!("{remote}/kept").as_bytes(),
                "leaf",
                b"target directory preserved",
            )
            .await?;
            let empty =
                remote_sync_metadata(manager, transport, format!("{remote}/empty").as_bytes())
                    .await?;
            assert!(empty["entries"].as_array().unwrap().is_empty());
        } else {
            for (name, expected) in [
                ("a-create", &[0, 255, 3][..]),
                ("b-size", b"x"),
                ("c-bytes", b"new"),
                ("d-same", b"same"),
                ("e-empty", b""),
                ("target-only", b"target file preserved"),
                ("kept/leaf", b"target directory preserved"),
                ("nested/deeper/payload.bin", &[255, 0, 8, 7]),
            ] {
                assert_eq!(fs::read(root.join(name))?, expected);
            }
            for index in 0..20 {
                assert_eq!(fs::read(root.join(format!("nested/child-{index:02}")))?, b"tree");
            }
            assert_eq!(fs::read_dir(root.join("empty"))?.count(), 0);
            assert_eq!(fs::metadata(root.join("d-same"))?.modified()?, same_modified);
            assert_eq!(fs::metadata(root.join("e-empty"))?.modified()?, empty_modified);
        }
        let same = directory_plan(manager, transport, remote.as_bytes(), &root, direction).await?;
        assert_eq!((same.summary.files_same, same.summary.directories_existing), (26, 4));
        assert_eq!(
            (
                same.summary.files_create,
                same.summary.files_changed,
                same.summary.directories_create
            ),
            (0, 0, 0)
        );
        assert_sync_unchanged(manager, transport, &same).await?;
        for membership in [false, true] {
            let stale =
                directory_plan(manager, transport, remote.as_bytes(), &root, direction).await?;
            if direction == SessionTransferDirection::Upload {
                if membership {
                    fs::write(root.join("nested/new-member"), b"x")?;
                } else {
                    fs::write(root.join("d-same"), b"changed source metadata")?;
                }
            } else {
                let change = if membership {
                    format!("printf x > {remote}/nested/new-member")
                } else {
                    format!("printf 'changed source metadata' > {remote}/d-same")
                };
                sync_shell(manager, transport, output, &change).await?;
            }
            assert_eq!(
                manager
                    .apply_directory_sync(
                        "fixture-terminal",
                        transport,
                        &stale.plan_id,
                        |_| async { panic!("stale plan cannot ask for replacement") }
                    )
                    .await,
                Err(SessionDirectorySyncIssue::FileChanged)
            );
            assert_eq!(manager.transfer_queue_snapshot("fixture-terminal")?.outstanding, 0);
            if direction == SessionTransferDirection::Upload {
                if membership {
                    fs::remove_file(root.join("nested/new-member"))?;
                } else {
                    fs::write(root.join("d-same"), b"same")?;
                }
            } else {
                let restore = if membership {
                    format!("rm {remote}/nested/new-member")
                } else {
                    format!("printf same > {remote}/d-same")
                };
                sync_shell(manager, transport, output, &restore).await?;
            }
        }
        let stale_target =
            directory_plan(manager, transport, remote.as_bytes(), &root, direction).await?;
        if direction == SessionTransferDirection::Upload {
            sync_shell(
                manager,
                transport,
                output,
                &format!("printf 'changed target metadata' > {remote}/d-same"),
            )
            .await?;
        } else {
            fs::write(root.join("d-same"), b"changed target metadata")?;
        }
        assert_eq!(
            manager
                .apply_directory_sync(
                    "fixture-terminal",
                    transport,
                    &stale_target.plan_id,
                    |_| async { panic!("a changed Same target needs renewed comparison") },
                )
                .await,
            Err(SessionDirectorySyncIssue::FileChanged)
        );
        if direction == SessionTransferDirection::Upload {
            sync_shell(manager, transport, output, &format!("printf same > {remote}/d-same"))
                .await?;
        } else {
            fs::write(root.join("d-same"), b"same")?;
        }
        println!(
            "OpenSSH recursive {label}: complete 30-row read-only review, one stable job, 22 created/2 updated/2 skipped files, 2 created directories, exact bytes, target-only preservation and stale-plan refusal passed"
        );
    }
    exercise_sync_empty_and_wide(manager, transport, local, output).await?;
    exercise_sync_refusals(manager, transport, local, output).await?;
    exercise_sync_partial(manager, transport, local, output).await?;
    exercise_sync_large(manager, transport, local, output).await?;
    sync_shell(manager, transport, output, "true").await?;
    println!(
        "recursive directory sync public-core OpenSSH acceptance passed; native folder selection was injected"
    );
    Ok(())
}

async fn exercise_sync_empty_and_wide(
    manager: &SessionManager,
    transport: &str,
    local: &std::path::Path,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let empty = local.join("sync-empty");
    fs::create_dir(&empty)?;
    let remote = b"./.scoplen-files-smoke/sync-empty";
    sync_shell(manager, transport, output, "mkdir .scoplen-files-smoke/sync-empty").await?;
    for direction in [SessionTransferDirection::Upload, SessionTransferDirection::Download] {
        let plan = directory_plan(manager, transport, remote, &empty, direction).await?;
        assert_eq!(plan.entries.len(), 1);
        assert_sync_directory(&plan, ".", SessionDirectorySyncDirectoryChange::Existing);
        assert_sync_unchanged(manager, transport, &plan).await?;
    }
    fs::create_dir(empty.join("missing-empty"))?;
    let plan = directory_plan(manager, transport, remote, &empty, SessionTransferDirection::Upload)
        .await?;
    assert_eq!(plan.summary.directories_create, 1);
    let saved = apply_directory(manager, transport, &plan, None).await?;
    assert_eq!(saved.state, SessionTransferState::Saved);
    assert_eq!(saved.transferred_bytes, "0");
    assert_eq!(sync_progress(&saved).directories_created, 1);
    let existing = remote_sync_metadata(
        manager,
        transport,
        b"./.scoplen-files-smoke/sync-empty/missing-empty",
    )
    .await?;
    assert!(existing["entries"].as_array().unwrap().is_empty());
    let wide = local.join("sync-wide");
    fs::create_dir(&wide)?;
    sync_shell(manager, transport, output, "mkdir .scoplen-files-smoke/sync-wide; i=0; while test $i -lt 1025; do printf x > .scoplen-files-smoke/sync-wide/file-$i; i=$((i+1)); done").await?;
    let plan = directory_plan(
        manager,
        transport,
        b"./.scoplen-files-smoke/sync-wide",
        &wide,
        SessionTransferDirection::Download,
    )
    .await?;
    assert_eq!(plan.entries.len(), 1026);
    assert_eq!(plan.summary.files_create, 1025);
    let saved = apply_directory(manager, transport, &plan, None).await?;
    assert_eq!(saved.state, SessionTransferState::Saved);
    assert_eq!(saved.transferred_bytes, "1025");
    assert_eq!(sync_progress(&saved).files_created, 1025);
    assert_eq!(fs::read_dir(&wide)?.count(), 1025);
    for index in 0..1025 {
        assert_eq!(fs::read(wide.join(format!("file-{index}")))?, b"x");
    }
    println!(
        "OpenSSH recursive sync: empty roots consume no slot; missing empty child consumes one job; complete 1025-file shallow enumeration and exact destination bytes passed"
    );
    Ok(())
}

async fn exercise_sync_refusals(
    manager: &SessionManager,
    transport: &str,
    local: &std::path::Path,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let destination = local.join("sync-refusals");
    fs::create_dir(&destination)?;
    for (label, entries, expected) in [
        ("link", "ln -s missing {root}/entry", SessionDirectorySyncIssue::UnsupportedEntry),
        ("fifo", "mkfifo {root}/entry", SessionDirectorySyncIssue::UnsupportedEntry),
        (
            "invalid-utf8",
            "printf x > {root}/$(printf '\\377')",
            SessionDirectorySyncIssue::UnsupportedName,
        ),
        (
            "ascii",
            "printf a > {root}/A.txt; printf b > {root}/a.txt",
            SessionDirectorySyncIssue::UnsupportedName,
        ),
        (
            "unicode-case",
            "printf a > {root}/\u{00c4}.txt; printf b > {root}/\u{00e4}.txt",
            SessionDirectorySyncIssue::UnsupportedName,
        ),
        (
            "unicode-form",
            "printf a > {root}/\u{00e9}.txt; printf b > {root}/e\u{0301}.txt",
            SessionDirectorySyncIssue::UnsupportedName,
        ),
    ] {
        let remote = format!("./.scoplen-files-smoke/sync-refused-{label}");
        sync_shell(
            manager,
            transport,
            output,
            &format!("mkdir {remote}; {}", entries.replace("{root}", &remote)),
        )
        .await?;
        let selected = destination.clone();
        assert_eq!(
            manager
                .prepare_directory_sync_with_picker(
                    "fixture-terminal",
                    transport,
                    &Uuid::now_v7().to_string(),
                    remote.into_bytes(),
                    SessionTransferDirection::Download,
                    move || async { Ok(Some(selected)) }
                )
                .await,
            Err(expected)
        );
        assert_eq!(fs::read_dir(&destination)?.count(), 0);
        assert_eq!(manager.transfer_queue_snapshot("fixture-terminal")?.outstanding, 0);
    }
    fs::write(destination.join("entry"), b"source retained")?;
    for (label, entry) in
        [("type", "mkdir {root}/entry"), ("target-link", "ln -s missing {root}/entry")]
    {
        let remote = format!("./.scoplen-files-smoke/sync-refused-{label}");
        sync_shell(
            manager,
            transport,
            output,
            &format!("mkdir {remote}; {}", entry.replace("{root}", &remote)),
        )
        .await?;
        let selected = destination.clone();
        assert_eq!(
            manager
                .prepare_directory_sync_with_picker(
                    "fixture-terminal",
                    transport,
                    &Uuid::now_v7().to_string(),
                    remote.into_bytes(),
                    SessionTransferDirection::Upload,
                    move || async { Ok(Some(selected)) }
                )
                .await,
            Err(SessionDirectorySyncIssue::UnsupportedEntry)
        );
        assert_eq!(fs::read(destination.join("entry"))?, b"source retained");
    }
    fs::remove_file(destination.join("entry"))?;
    for (label, remote_name, native_name) in
        [("ascii-target", "A.txt", "a.txt"), ("unicode-target", "\u{00e9}.txt", "e\u{0301}.txt")]
    {
        let remote = format!("./.scoplen-files-smoke/sync-refused-{label}");
        sync_shell(
            manager,
            transport,
            output,
            &format!("mkdir {remote}; printf x > '{remote}/{remote_name}'"),
        )
        .await?;
        fs::write(destination.join(native_name), b"existing target retained")?;
        let selected = destination.clone();
        assert_eq!(
            manager
                .prepare_directory_sync_with_picker(
                    "fixture-terminal",
                    transport,
                    &Uuid::now_v7().to_string(),
                    remote.into_bytes(),
                    SessionTransferDirection::Download,
                    move || async { Ok(Some(selected)) }
                )
                .await,
            Err(SessionDirectorySyncIssue::UnsupportedName)
        );
        assert_eq!(fs::read(destination.join(native_name))?, b"existing target retained");
        fs::remove_file(destination.join(native_name))?;
    }
    println!(
        "OpenSSH recursive sync refusals: source link/FIFO/invalid UTF-8, ASCII/Unicode case/composition collision, existing-target name collision, type conflict and unsafe target; no partial plan, queue admission or destination mutation"
    );
    Ok(())
}

async fn exercise_sync_partial(
    manager: &SessionManager,
    transport: &str,
    local: &std::path::Path,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    for direction in [SessionTransferDirection::Upload, SessionTransferDirection::Download] {
        let label =
            if direction == SessionTransferDirection::Upload { "upload" } else { "download" };
        let root = local.join(format!("sync-partial-{label}"));
        fs::create_dir(&root)?;
        let remote = format!("./.scoplen-files-smoke/sync-partial-{label}");
        let local_bytes =
            if direction == SessionTransferDirection::Upload { b"new" } else { b"old" };
        for name in ["a-replace", "b-replace", "c-replace"] {
            fs::write(root.join(name), local_bytes)?;
        }
        fs::write(root.join("d-same"), b"same")?;
        let remote_bytes =
            if direction == SessionTransferDirection::Upload { "old" } else { "new" };
        sync_shell(manager, transport, output, &format!("mkdir {remote}; printf {remote_bytes} > {remote}/a-replace; printf {remote_bytes} > {remote}/b-replace; printf {remote_bytes} > {remote}/c-replace; printf same > {remote}/d-same")).await?;
        if direction == SessionTransferDirection::Upload {
            sync_shell(
                manager,
                transport,
                output,
                &format!("printf preserved > {remote}/target-only"),
            )
            .await?;
        } else {
            fs::write(root.join("target-only"), b"preserved")?;
        }
        let plan = directory_plan(manager, transport, remote.as_bytes(), &root, direction).await?;
        let cancelled = apply_directory(manager, transport, &plan, Some(2)).await?;
        assert_eq!(cancelled.state, SessionTransferState::Cancelled);
        assert_eq!(cancelled.transferred_bytes, "3");
        let progress = sync_progress(&cancelled);
        assert_eq!(
            (progress.files_created, progress.files_updated, progress.files_skipped),
            (0, 1, 1)
        );
        let failed =
            progress.failed_name.as_deref().ok_or("refusal must name its relative file")?;
        assert!(["a-replace", "b-replace", "c-replace"].contains(&failed));
        assert!(!cancelled.staging_may_remain);
        if direction == SessionTransferDirection::Upload {
            sync_shell(manager, transport, output, &format!("test $(grep -l '^new$' {remote}/a-replace {remote}/b-replace {remote}/c-replace | wc -l) -eq 1; test $(grep -l '^old$' {remote}/a-replace {remote}/b-replace {remote}/c-replace | wc -l) -eq 2")).await?;
            assert_drop_bytes(manager, local, transport, remote.as_bytes(), failed, b"old").await?;
            assert_drop_bytes(
                manager,
                local,
                transport,
                remote.as_bytes(),
                "target-only",
                b"preserved",
            )
            .await?;
            let entries = remote_sync_metadata(manager, transport, remote.as_bytes()).await?;
            assert!(
                entries["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|row| !row["name"].as_str().unwrap().starts_with(".scoplen-upload-"))
            );
        } else {
            let contents = ["a-replace", "b-replace", "c-replace"]
                .map(|name| fs::read(root.join(name)).unwrap());
            assert_eq!(contents.iter().filter(|bytes| bytes.as_slice() == b"new").count(), 1);
            assert_eq!(contents.iter().filter(|bytes| bytes.as_slice() == b"old").count(), 2);
            assert_eq!(fs::read(root.join(failed))?, b"old");
            assert_eq!(fs::read(root.join("target-only"))?, b"preserved");
            assert!(fs::read_dir(&root)?.all(|row| {
                !row.unwrap().file_name().to_string_lossy().starts_with(".scoplen-download-")
            }));
        }
        let renewed =
            directory_plan(manager, transport, remote.as_bytes(), &root, direction).await?;
        let saved = apply_directory(manager, transport, &renewed, None).await?;
        assert_eq!(saved.state, SessionTransferState::Saved);
        assert_eq!(
            (
                sync_progress(&saved).files_created,
                sync_progress(&saved).files_updated,
                sync_progress(&saved).files_skipped
            ),
            (0, 2, 2)
        );
        println!(
            "OpenSSH recursive {label} partial result: first confirmed replacement retained, next refusal cancels the whole job before later confirmation, target-only data preserved; renewed explicit review completes remaining changes"
        );
    }
    Ok(())
}

async fn exercise_sync_large(
    manager: &SessionManager,
    transport: &str,
    local: &std::path::Path,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read as _, Seek as _, Write as _};

    let source = local.join("sync-large-source");
    fs::create_dir(&source)?;
    let length = 64 * 1024 * 1024 + 1;
    let mut file = fs::File::create(source.join("large.bin"))?;
    file.set_len(length)?;
    file.seek(std::io::SeekFrom::End(-4))?;
    file.write_all(&[255, 0, 7, 3])?;
    drop(file);
    let remote = b"./.scoplen-files-smoke/sync-large";
    sync_shell(manager, transport, output,
        &format!("mkdir .scoplen-files-smoke/sync-large; truncate -s {length} .scoplen-files-smoke/sync-large/large.bin")).await?;
    for direction in [SessionTransferDirection::Upload, SessionTransferDirection::Download] {
        let selected = source.clone();
        assert_eq!(
            manager
                .prepare_directory_sync_with_picker(
                    "fixture-terminal",
                    transport,
                    &Uuid::now_v7().to_string(),
                    remote.to_vec(),
                    direction,
                    move || async { Ok(Some(selected)) },
                )
                .await,
            Err(SessionDirectorySyncIssue::TooLarge),
            "an equal-size file above the hash bound must refuse the complete plan",
        );
    }
    sync_shell(
        manager,
        transport,
        output,
        "printf old > .scoplen-files-smoke/sync-large/large.bin",
    )
    .await?;
    let plan =
        directory_plan(manager, transport, remote, &source, SessionTransferDirection::Upload)
            .await?;
    assert_sync_file(&plan, "large.bin", SessionDirectorySyncChange::Changed);
    assert_eq!(plan.summary.transfer_size_bytes, length.to_string());
    let saved = apply_directory(manager, transport, &plan, None).await?;
    assert_eq!(saved.state, SessionTransferState::Saved);
    assert_eq!(saved.transferred_bytes, length.to_string());
    assert_eq!(sync_progress(&saved).files_updated, 1);
    let destination = local.join("sync-large-destination");
    fs::create_dir(&destination)?;
    fs::write(destination.join("large.bin"), b"x")?;
    let plan = directory_plan(
        manager,
        transport,
        remote,
        &destination,
        SessionTransferDirection::Download,
    )
    .await?;
    assert_sync_file(&plan, "large.bin", SessionDirectorySyncChange::Changed);
    let saved = apply_directory(manager, transport, &plan, None).await?;
    assert_eq!(saved.state, SessionTransferState::Saved);
    assert_eq!(saved.transferred_bytes, length.to_string());
    assert_eq!(sync_progress(&saved).files_updated, 1);
    let mut expected = fs::File::open(source.join("large.bin"))?;
    let mut actual = fs::File::open(destination.join("large.bin"))?;
    assert_eq!(actual.metadata()?.len(), length);
    let mut expected_bytes = [0; 32 * 1024];
    let mut actual_bytes = [0; 32 * 1024];
    loop {
        let count = expected.read(&mut expected_bytes)?;
        actual.read_exact(&mut actual_bytes[..count])?;
        assert_eq!(expected_bytes[..count], actual_bytes[..count]);
        if count == 0 {
            break;
        }
    }
    println!(
        "OpenSSH recursive sync: equal-size 64 MiB + 1 byte hashing refused in both directions; different-size changes streamed in both directions with complete bounded-buffer byte equality"
    );
    Ok(())
}

async fn exercise_sync_unknown(
    manager: &SessionManager,
    local: &std::path::Path,
    ready: &mut mpsc::UnboundedReceiver<String>,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = ready.recv().await.ok_or("unknown fixture terminal did not become ready")?;
    let source = local.join("sync-unknown");
    fs::create_dir_all(source.join("parent/child"))?;
    let remote = b"./.scoplen-files-smoke/sync-unknown";
    sync_shell(manager, &transport, output,
        "mkdir -p .scoplen-files-smoke/sync-unknown; printf retained > .scoplen-files-smoke/sync-unknown/target-only").await?;
    let plan =
        directory_plan(manager, &transport, remote, &source, SessionTransferDirection::Upload)
            .await?;
    assert_eq!((plan.summary.directories_create, plan.summary.directories_existing), (2, 1));
    let SessionDirectorySyncApplyResult::Queued { queue_id, item_id, execution_id } = manager
        .apply_directory_sync("fixture-terminal", &transport, &plan.plan_id, |_| async {
            panic!("directory creation cannot request file replacement")
        })
        .await?
    else {
        return Err("unknown fixture directory job was not admitted".into());
    };
    let unknown = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
            assert_eq!(snapshot.queue_id, queue_id);
            assert_eq!(snapshot.outstanding, 1);
            let row = snapshot
                .items
                .into_iter()
                .find(|row| row.item_id == item_id)
                .ok_or("unknown fixture job left the outstanding queue")?;
            assert_eq!(row.execution_id, execution_id);
            if row.state == SessionTransferState::Unknown {
                return Ok::<_, Box<dyn std::error::Error>>(row);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    let progress = sync_progress(&unknown);
    assert_eq!((progress.directories_total, progress.directories_created), (2, 1));
    assert_eq!((progress.files_created, progress.files_updated, progress.files_skipped), (0, 0, 0));
    assert_eq!(progress.failed_name.as_deref(), Some("parent/child"));
    assert_eq!(progress.issue, Some(SessionDirectorySyncIssue::PublicationUnknown));
    assert_eq!(unknown.transferred_bytes, "0");
    assert!(unknown.can_acknowledge && !unknown.can_cancel);
    assert_eq!(
        manager
            .apply_directory_sync("fixture-terminal", &transport, &plan.plan_id, |_| async {
                panic!("lost acknowledgement cannot replay a consumed plan")
            })
            .await,
        Err(SessionDirectorySyncIssue::Unavailable)
    );
    sync_shell(manager, &transport, output,
        "test -d .scoplen-files-smoke/sync-unknown/parent; test -d .scoplen-files-smoke/sync-unknown/parent/child; test $(cat .scoplen-files-smoke/sync-unknown/target-only) = retained").await?;
    let current = manager.transfer_queue_snapshot("fixture-terminal")?;
    let retained = current.items.iter().find(|row| row.item_id == item_id).unwrap();
    assert_eq!(retained, &unknown, "unknown work must stay visible without automatic replay");
    manager.acknowledge_transfer("fixture-terminal", &queue_id, &item_id, &execution_id)?;
    assert_eq!(manager.transfer_queue_snapshot("fixture-terminal")?.outstanding, 0);
    println!(
        "OpenSSH recursive sync Unknown: one confirmed created directory, second mkdir genuinely created remotely with its success STATUS withheld, exact failed relative name, retained target-only bytes, stable reminder, no replay and explicit acknowledgement passed"
    );
    Ok(())
}

async fn exercise_upload_resume(
    manager: &SessionManager,
    local: &std::path::Path,
    transport: &str,
    directory: Vec<u8>,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = local.join("upload-resume-source.bin");
    let bytes = (0_u64..(16 * 1024 * 1024 + 17_u64).div_ceil(8))
        .flat_map(u64::to_le_bytes)
        .take(16 * 1024 * 1024 + 17)
        .collect::<Vec<_>>();
    fs::write(&source, &bytes)?;
    let upload = queue_upload(manager, transport, directory.clone(), source).await?;
    let (queue, item, execution) = queue_identity(&upload);
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
            if snapshot.items.iter().any(|row| row.item_id == item && row.can_pause) {
                manager.pause_transfer("fixture-terminal", &queue, &item, &execution)?;
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            if snapshot.recent.iter().any(|row| row.item_id == item) {
                return Err("upload ended before Pause was admitted".into());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await??;
    let paused = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
            if let Some(row) = snapshot
                .items
                .into_iter()
                .find(|row| row.item_id == item && row.state == SessionTransferState::Paused)
            {
                return Ok::<_, Box<dyn std::error::Error>>(row);
            }
            if snapshot.recent.iter().any(|row| row.item_id == item) {
                return Err("upload ended while settling Pause".into());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await??;
    let offset = paused.transferred_bytes.parse::<usize>()?;
    assert!(offset > 0 && offset < bytes.len());
    assert!(paused.can_resume);
    let follower = local.join("upload-resume-follower.bin");
    fs::write(&follower, b"later work runs while upload is paused")?;
    let follow = queue_upload(manager, transport, directory.clone(), follower).await?;
    assert_eq!(
        wait_queue_item(manager, &queue_identity(&follow).1).await?.state,
        SessionTransferState::Saved
    );
    let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
    assert_eq!(snapshot.outstanding, 1);
    assert!(!snapshot.blocks_file_operations);
    manager.input("fixture-terminal", transport, format!(
        "printf 'SCOPLEN-UPLOAD-RESUME {offset}\\n' >> /tmp/scoplen-files-sftp.log; printf '%s%s\\n' SCOPLEN- UPLOAD-RESUME-ALIVE\n"
    ).into_bytes())?;
    manager.resize("fixture-terminal", transport, 104, 32)?;
    wait_for(output, b"SCOPLEN-UPLOAD-RESUME-ALIVE").await?;
    manager.resume_transfer("fixture-terminal", &queue, &item, &execution)?;
    let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
    let resumed = snapshot
        .items
        .iter()
        .find(|row| row.item_id == item)
        .ok_or("resumed upload disappeared")?;
    assert_ne!(resumed.execution_id, execution);
    assert_eq!(resumed.transferred_bytes.parse::<usize>()?, offset);
    assert!(manager.pause_transfer("fixture-terminal", &queue, &item, &execution).is_err());
    let saved = wait_queue_item(manager, &item).await?;
    assert_eq!(saved.state, SessionTransferState::Saved);
    assert_eq!(saved.transferred_bytes.parse::<usize>()?, bytes.len());
    let mut remote = directory;
    remote.extend_from_slice(b"/upload-resume-source.bin");
    let destination = local.join("upload-resume-result.bin");
    let selected = destination.clone();
    let download = manager
        .enqueue_download_with_picker(
            "fixture-terminal",
            transport,
            remote,
            move || async move { Ok(Some(selected)) },
            |_| async { panic!("new verification destination cannot need replacement") },
        )
        .await?;
    assert_eq!(
        wait_queue_item(manager, &queue_identity(&download).1).await?.state,
        SessionTransferState::Saved
    );
    assert_eq!(fs::read(destination)?, bytes);
    println!(
        "upload continuation: live nonzero checkpoint, later FIFO work, terminal input/resize and exact bytes passed"
    );
    Ok(())
}

async fn exercise_download_resume(
    manager: &SessionManager,
    local: &std::path::Path,
    transport: &str,
    directory: Vec<u8>,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = local.join("resume-source.bin");
    let bytes = (0_u64..(16 * 1024 * 1024 + 17_u64).div_ceil(8))
        .flat_map(u64::to_le_bytes)
        .take(16 * 1024 * 1024 + 17)
        .collect::<Vec<_>>();
    fs::write(&source, &bytes)?;
    let uploaded = queue_upload(manager, transport, directory.clone(), source).await?;
    assert_eq!(
        wait_queue_item(manager, &queue_identity(&uploaded).1).await?.state,
        SessionTransferState::Saved
    );
    let mut remote = directory.clone();
    remote.extend_from_slice(b"/resume-source.bin");
    let destination = local.join("resume-result.bin");
    fs::write(&destination, b"destination remains until publication")?;
    let selected = destination.clone();
    let download = manager
        .enqueue_download_with_picker(
            "fixture-terminal",
            transport,
            remote.clone(),
            move || async move { Ok(Some(selected)) },
            |_| async { Ok(true) },
        )
        .await?;
    let (queue, item, execution) = queue_identity(&download);
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
            if snapshot.items.iter().any(|row| row.item_id == item && row.can_pause) {
                manager.pause_transfer("fixture-terminal", &queue, &item, &execution)?;
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            if let Some(row) = snapshot.recent.iter().find(|row| row.item_id == item) {
                return Err(format!(
                    "download ended before Pause: {:?}, {:?}",
                    row.state, row.issue
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await??;
    let paused = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
            if let Some(row) = snapshot
                .items
                .into_iter()
                .find(|row| row.item_id == item && row.state == SessionTransferState::Paused)
            {
                return Ok::<_, Box<dyn std::error::Error>>(row);
            }
            if let Some(row) = snapshot.recent.iter().find(|row| row.item_id == item) {
                return Err(format!(
                    "download ended while pausing: {:?}, {:?}",
                    row.state, row.issue
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await??;
    let offset = paused.transferred_bytes.parse::<usize>()?;
    assert!(offset > 0 && offset < bytes.len());
    assert!(paused.can_resume);
    assert_eq!(fs::read(&destination)?, b"destination remains until publication");
    let partials = fs::read_dir(local)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".scoplen-download-"))
        .collect::<Vec<_>>();
    assert_eq!(partials.len(), 1);
    let partial = partials[0].path();
    assert_eq!(fs::read(&partial)?, bytes[..offset]);

    let follower = local.join("resume-follower.bin");
    fs::write(&follower, b"following work runs while download is paused")?;
    let follow = queue_upload(manager, transport, directory, follower).await?;
    assert_eq!(
        wait_queue_item(manager, &queue_identity(&follow).1).await?.state,
        SessionTransferState::Saved
    );
    let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
    assert_eq!(snapshot.outstanding, 1);
    assert!(!snapshot.blocks_file_operations);
    assert!(
        snapshot
            .items
            .iter()
            .any(|row| row.item_id == item && row.state == SessionTransferState::Paused)
    );
    manager.input(
        "fixture-terminal",
        transport,
        b"printf '%s%s\\n' SCOPLEN- RESUME-ALIVE\n".to_vec(),
    )?;
    manager.resize("fixture-terminal", transport, 103, 31)?;
    wait_for(output, b"SCOPLEN-RESUME-ALIVE").await?;
    manager.resume_transfer("fixture-terminal", &queue, &item, &execution)?;
    let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
    let resumed =
        snapshot.items.iter().find(|row| row.item_id == item).ok_or("resumed item disappeared")?;
    assert_ne!(resumed.execution_id, execution);
    assert_eq!(resumed.transferred_bytes.parse::<usize>()?, offset);
    assert!(manager.resume_transfer("fixture-terminal", &queue, &item, &execution).is_err());
    let saved = wait_queue_item(manager, &item).await?;
    assert_eq!(saved.state, SessionTransferState::Saved);
    assert_eq!(saved.transferred_bytes.parse::<usize>()?, bytes.len());
    assert_eq!(fs::read(destination)?, bytes);
    assert!(!partial.exists());
    Ok(())
}

async fn exercise_queue(
    manager: &SessionManager,
    local: &std::path::Path,
    transport: &str,
    directory: Vec<u8>,
    binary_path: Vec<u8>,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let first = local.join("queue-first.bin");
    let second = local.join("queue-second.bin");
    let downloaded = local.join("queue-downloaded.bin");
    fs::write(&first, vec![0x91; 4 * 1024 * 1024])?;
    fs::write(&second, b"queued\0\xffbytes")?;
    let first_upload = queue_upload(manager, transport, directory.clone(), first.clone()).await?;
    let second_upload = queue_upload(manager, transport, directory.clone(), second.clone()).await?;
    let destination = downloaded.clone();
    let download = manager
        .enqueue_download_with_picker(
            "fixture-terminal",
            transport,
            binary_path.clone(),
            move || async move { Ok(Some(destination)) },
            |_| async { panic!("new queue destination cannot require replacement") },
        )
        .await?;
    let first_id = queue_identity(&first_upload);
    let second_id = queue_identity(&second_upload);
    let download_id = queue_identity(&download);
    assert_eq!(first_id.0, second_id.0);
    assert_eq!(first_id.0, download_id.0);
    assert_ne!(first_id.2, second_id.2);
    for identity in [&first_id, &second_id, &download_id] {
        let saved = wait_queue_item(manager, &identity.1).await?;
        assert_eq!(saved.state, SessionTransferState::Saved);
        assert!(!saved.staging_may_remain);
        assert_eq!(saved.transferred_bytes, saved.total_bytes.unwrap());
    }
    let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
    assert_eq!(
        snapshot
            .recent
            .iter()
            .rev()
            .take(3)
            .rev()
            .map(|row| row.item_id.as_str())
            .collect::<Vec<_>>(),
        [first_id.1.as_str(), second_id.1.as_str(), download_id.1.as_str(),]
    );
    assert_eq!(snapshot.outstanding, 0);
    assert!(!snapshot.blocks_file_operations);
    let bytes = fs::read(&downloaded)?;
    assert_eq!(bytes.len(), 262149);
    assert_eq!(&bytes[262144..], b"\xff\x01END");

    let entries = manager
        .list_files("fixture-terminal", transport, &Uuid::now_v7().to_string(), directory.clone())
        .await?;
    let remote = entries
        .entries
        .iter()
        .find(|entry| entry.name == "queue-second.bin")
        .ok_or("queued upload was not listed")?;
    let copy = local.join("queue-copy.bin");
    fs::write(&copy, b"reviewed local target")?;
    let chosen = copy.clone();
    let confirmations = Arc::new(AtomicUsize::new(0));
    let confirmed = confirmations.clone();
    let replacement = manager
        .enqueue_download_with_picker(
            "fixture-terminal",
            transport,
            remote.path.clone(),
            move || async move { Ok(Some(chosen)) },
            move |review| async move {
                assert_eq!(review.name, "queue-copy.bin");
                assert_eq!(review.host, "disposable file fixture");
                assert_eq!(review.username, "smoke");
                assert_eq!(review.address, "127.0.0.1");
                assert!(review.port > 0);
                assert_eq!(review.direction, SessionTransferDirection::Download);
                confirmed.fetch_add(1, Ordering::SeqCst);
                Ok(true)
            },
        )
        .await?;
    assert_eq!(
        wait_queue_item(manager, &queue_identity(&replacement).1).await?.state,
        SessionTransferState::Saved
    );
    assert_eq!(confirmations.load(Ordering::SeqCst), 1);
    assert_eq!(fs::read(copy)?, b"queued\0\xffbytes");

    let cancelled =
        queue_upload(manager, transport, directory.clone(), local.join("cancel-upload.bin"))
            .await?;
    let cancelled_id = queue_identity(&cancelled);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
            if snapshot.items.iter().any(|row| {
                row.item_id == cancelled_id.1 && row.transferred_bytes != "0" && row.can_cancel
            }) {
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
            if snapshot.recent.iter().any(|row| row.item_id == cancelled_id.1) {
                return Err("queue cancellation fixture ended before cancellation".into());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await??;
    manager.cancel_transfer(
        "fixture-terminal",
        &cancelled_id.0,
        &cancelled_id.1,
        &cancelled_id.2,
    )?;
    let cancelled = wait_queue_item(manager, &cancelled_id.1).await?;
    assert_eq!(cancelled.state, SessionTransferState::Cancelled);
    assert!(!cancelled.staging_may_remain);
    let entries = manager
        .list_files("fixture-terminal", transport, &Uuid::now_v7().to_string(), directory.clone())
        .await?;
    assert!(
        entries.entries.iter().all(|entry| entry.name != "cancel-upload.bin"
            && !entry.name.starts_with(".scoplen-upload-"))
    );
    assert!(fs::read_dir(local)?.all(|entry| {
        !entry.unwrap().file_name().to_string_lossy().starts_with(".scoplen-download-")
    }));
    manager.input(
        "fixture-terminal",
        transport,
        b"printf '%s%s\\n' SCOPLEN- QUEUE-ALIVE\n".to_vec(),
    )?;
    wait_for(output, b"SCOPLEN-QUEUE-ALIVE").await?;
    exercise_native_drops(manager, local, transport, directory, output).await?;
    Ok(())
}

async fn exercise_native_drops(
    manager: &SessionManager,
    local: &std::path::Path,
    transport: &str,
    directory: Vec<u8>,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let context = Uuid::now_v7().to_string();
    manager.arm_file_drop(
        "fixture-window",
        &context,
        "fixture-terminal",
        transport,
        &manager.transfer_queue_snapshot("fixture-terminal")?.queue_id,
        directory.clone(),
    )?;
    let first = local.join("drop-first.bin");
    let second = local.join("drop-second.bin");
    fs::write(&first, b"native first\0\xff")?;
    fs::write(&second, b"native second\0\xfe")?;
    let capture = |paths| {
        manager
            .capture_file_drop(
                &tokio::runtime::Handle::current(),
                "fixture-window",
                paths,
                Some((0.8, 0.5)),
            )
            .and_then(|event| event.ticket_id)
            .ok_or("native fixture did not produce a ticket")
    };
    let ticket = capture(vec![first.clone(), second])?;
    assert_eq!(
        manager
            .consume_file_drop("fixture-window", &context, &ticket, |_| async {
                panic!("new drop cannot require replacement")
            })
            .await?
            .accepted,
        2
    );
    let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
    let added = snapshot
        .recent
        .iter()
        .chain(&snapshot.items)
        .filter(|item| item.name.starts_with("drop-"))
        .map(|item| item.item_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(added.len(), 2);
    for id in &added {
        assert_eq!(wait_queue_item(manager, id).await?.state, SessionTransferState::Saved);
    }
    let recent = manager.transfer_queue_snapshot("fixture-terminal")?.recent;
    assert_eq!(
        recent
            .iter()
            .filter(|item| added.contains(&item.item_id))
            .map(|item| item.name.as_str())
            .collect::<Vec<_>>(),
        ["drop-first.bin", "drop-second.bin"]
    );
    assert_drop_bytes(
        manager,
        local,
        transport,
        &directory,
        "drop-first.bin",
        b"native first\0\xff",
    )
    .await?;
    assert_drop_bytes(
        manager,
        local,
        transport,
        &directory,
        "drop-second.bin",
        b"native second\0\xfe",
    )
    .await?;

    let refused = local.join("drop-refused.bin");
    fs::write(&refused, b"must never upload")?;
    let before = manager.transfer_queue_snapshot("fixture-terminal")?;
    let ticket = capture(vec![refused.clone(), local.join("missing-drop-source")])?;
    assert!(
        manager
            .consume_file_drop("fixture-window", &context, &ticket, |_| async { Ok(true) })
            .await
            .is_err()
    );
    let after = manager.transfer_queue_snapshot("fixture-terminal")?;
    assert_eq!(before.items, after.items);
    assert_eq!(before.recent, after.recent);
    assert_eq!(after.outstanding, 0);

    fs::write(&first, b"confirmed native replacement\0\xfd")?;
    let retained = local.join("drop-retained.bin");
    let cancelled = local.join("drop-cancelled.bin");
    fs::write(&retained, b"retained source\0\xfc")?;
    fs::write(&cancelled, b"cancel before dispatch")?;
    let release = Arc::new(tokio::sync::Notify::new());
    let review_gate = release.clone();
    let ticket = capture(vec![first.clone(), retained.clone(), cancelled])?;
    manager
        .consume_file_drop("fixture-window", &context, &ticket, move |review| {
            let release = review_gate.clone();
            async move {
                assert_eq!(review.host, "disposable file fixture");
                assert_eq!(review.username, "smoke");
                assert_eq!(review.name, "drop-first.bin");
                release.notified().await;
                Ok(false)
            }
        })
        .await?;
    let items = manager.transfer_queue_snapshot("fixture-terminal")?.items;
    assert_eq!(items.len(), 3);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if manager.transfer_queue_snapshot("fixture-terminal")?.items[0].state
                == SessionTransferState::AwaitingConfirmation
            {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await??;
    fs::rename(&retained, local.join("moved-drop-source.bin"))?;
    fs::write(&retained, b"replacement path must not redirect retained handle")?;
    let cancel = &items[2];
    manager.cancel_transfer(
        "fixture-terminal",
        &manager.transfer_queue_snapshot("fixture-terminal")?.queue_id,
        &cancel.item_id,
        &cancel.execution_id,
    )?;
    release.notify_one();
    for (item, state) in items.iter().zip([
        SessionTransferState::Cancelled,
        SessionTransferState::Saved,
        SessionTransferState::Cancelled,
    ]) {
        assert_eq!(wait_queue_item(manager, &item.item_id).await?.state, state);
    }
    assert_drop_bytes(
        manager,
        local,
        transport,
        &directory,
        "drop-first.bin",
        b"native first\0\xff",
    )
    .await?;
    assert_drop_bytes(
        manager,
        local,
        transport,
        &directory,
        "drop-retained.bin",
        b"retained source\0\xfc",
    )
    .await?;
    let ticket = capture(vec![first])?;
    let previous = manager
        .transfer_queue_snapshot("fixture-terminal")?
        .recent
        .into_iter()
        .map(|row| row.item_id)
        .collect::<Vec<_>>();
    manager.consume_file_drop("fixture-window", &context, &ticket, |_| async { Ok(true) }).await?;
    let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
    let item = snapshot
        .recent
        .iter()
        .chain(&snapshot.items)
        .find(|row| row.name == "drop-first.bin" && !previous.contains(&row.item_id))
        .ok_or("replacement drop missing")?;
    assert_eq!(wait_queue_item(manager, &item.item_id).await?.state, SessionTransferState::Saved);
    assert_drop_bytes(
        manager,
        local,
        transport,
        &directory,
        "drop-first.bin",
        b"confirmed native replacement\0\xfd",
    )
    .await?;
    manager.revoke_file_drop("fixture-window", &context);
    let entries = manager
        .list_files("fixture-terminal", transport, &Uuid::now_v7().to_string(), directory)
        .await?
        .entries;
    assert!(entries.iter().all(|entry| entry.name != "drop-refused.bin"
        && entry.name != "drop-cancelled.bin"
        && !entry.name.starts_with(".scoplen-upload-")));
    manager.input(
        "fixture-terminal",
        transport,
        b"printf '%s%s\\n' SCOPLEN- DROP-ALIVE\n".to_vec(),
    )?;
    manager.resize("fixture-terminal", transport, 108, 34)?;
    wait_for(output, b"SCOPLEN-DROP-ALIVE").await?;
    println!(
        "native drop queue: FIFO bytes, whole-batch refusal, retained handles, replacement refusal/acceptance, queued cancellation and cleanup passed"
    );
    Ok(())
}

async fn assert_drop_bytes(
    manager: &SessionManager,
    local: &std::path::Path,
    transport: &str,
    directory: &[u8],
    name: &str,
    expected: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut remote = directory.to_vec();
    remote.push(b'/');
    remote.extend(name.as_bytes());
    let destination = local.join(format!("readback-{}-{name}", Uuid::now_v7()));
    let result = manager
        .download_file_with_picker(
            "fixture-terminal",
            transport,
            &Uuid::now_v7().to_string(),
            remote,
            || async { Ok(Some(destination.clone())) },
            |_| {},
        )
        .await?;
    assert_eq!(result.status, SessionDownloadStatus::Saved);
    assert_eq!(fs::read(destination)?, expected);
    Ok(())
}

async fn directory_copy(
    manager: &SessionManager,
    transport: &str,
    local: std::path::PathBuf,
    remote: &[u8],
    direction: SessionTransferDirection,
    root_name: &str,
) -> Result<SessionTransferItem, Box<dyn std::error::Error>> {
    let SessionDirectoryCopyPrepareResult::Prepared { selection } = manager
        .prepare_directory_copy_with_picker(
            "fixture-terminal",
            transport,
            remote.to_vec(),
            direction,
            move || async move { Ok(Some(local)) },
        )
        .await?
    else {
        return Err("directory fixture selection was cancelled".into());
    };
    let admitted = manager.enqueue_directory_copy(
        "fixture-terminal",
        transport,
        &selection.selection_id,
        root_name,
    )?;
    let (_, item, execution) = queue_identity(&admitted);
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
            if let Some(row) = snapshot.recent.into_iter().find(|row| row.item_id == item) {
                assert_eq!(row.execution_id, execution);
                return Ok::<_, Box<dyn std::error::Error>>(row);
            }
            let row = snapshot
                .items
                .iter()
                .find(|row| row.item_id == item)
                .ok_or("directory item disappeared")?;
            assert_eq!(row.execution_id, execution);
            assert!(!row.can_pause && !row.can_resume);
            assert_eq!(snapshot.outstanding, 1);
            if row.state == SessionTransferState::Unknown {
                return Err("directory result unknown; no replay attempted".into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?
}

async fn exercise_directory_copy(
    manager: &SessionManager,
    transport: &str,
    local: &std::path::Path,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read as _, Seek as _, Write as _};

    let source = local.join("recursive-source");
    fs::create_dir_all(source.join("nested/empty"))?;
    fs::create_dir_all(source.join("empty"))?;
    for index in 0..24 {
        fs::write(source.join("nested").join(format!("file-{index:02}")), [0, 255, index])?;
    }
    fs::write(source.join("zero"), b"")?;
    let unicode_name = "\u{6587}\u{4ef6}-\u{e9}.bin";
    fs::write(source.join(unicode_name), [255, 0, 3, 7])?;
    let large_size = 64 * 1024 * 1024 + 1;
    let mut large = fs::File::create(source.join("large.bin"))?;
    large.set_len(large_size)?;
    large.seek(std::io::SeekFrom::End(-4))?;
    large.write_all(&[255, 0, 7, 3])?;
    drop(large);
    let total_bytes = (large_size + 76).to_string();
    let upload = directory_copy(
        manager,
        transport,
        source.clone(),
        b"./.scoplen-files-smoke",
        SessionTransferDirection::Upload,
        "recursive-upload",
    );
    let terminal = async {
        loop {
            let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
            if snapshot.items.iter().any(|row| {
                row.directory_copy
                    .as_ref()
                    .is_some_and(|progress| progress.phase == SessionDirectoryCopyPhase::Copying)
            }) {
                break;
            }
            if snapshot.recent.iter().any(|row| row.name == "recursive-upload") {
                return Err("folder settled before the terminal liveness probe".into());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        manager.input(
            "fixture-terminal",
            transport,
            b"printf '%s%s\\n' SCOPLEN- DIRECTORY-ALIVE\n".to_vec(),
        )?;
        manager.resize("fixture-terminal", transport, 112, 36)?;
        wait_for(output, b"SCOPLEN-DIRECTORY-ALIVE").await
    };
    let (saved, ()) = tokio::try_join!(upload, terminal)?;
    assert_eq!(saved.state, SessionTransferState::Saved);
    assert_eq!(saved.transferred_bytes, total_bytes);
    let progress = saved.directory_copy.as_ref().unwrap();
    assert_eq!((progress.files_completed, progress.directories_created), (27, 4));
    assert!(progress.root_created && !progress.root_creation_unknown);
    let download = local.join("recursive-download-parent");
    fs::create_dir(&download)?;
    let saved = directory_copy(
        manager,
        transport,
        download.clone(),
        b"./.scoplen-files-smoke/recursive-upload",
        SessionTransferDirection::Download,
        "recursive-download",
    )
    .await?;
    assert_eq!(saved.state, SessionTransferState::Saved);
    assert_eq!(saved.transferred_bytes, total_bytes);
    let destination = download.join("recursive-download");
    assert!(destination.join("nested/empty").is_dir() && destination.join("empty").is_dir());
    assert_eq!(fs::read(destination.join("zero"))?, b"");
    assert_eq!(fs::read(destination.join(unicode_name))?, [255, 0, 3, 7]);
    {
        let mut source_large = fs::File::open(source.join("large.bin"))?;
        let mut copied_large = fs::File::open(destination.join("large.bin"))?;
        assert_eq!(copied_large.metadata()?.len(), large_size);
        let mut expected = vec![0; 64 * 1024];
        let mut actual = vec![0; 64 * 1024];
        loop {
            let count = source_large.read(&mut expected)?;
            copied_large.read_exact(&mut actual[..count])?;
            assert_eq!(&actual[..count], &expected[..count]);
            if count == 0 {
                break;
            }
        }
    }
    for index in 0..24 {
        assert_eq!(
            fs::read(destination.join("nested").join(format!("file-{index:02}")))?,
            [0, 255, index]
        );
    }
    let empty = local.join("empty-source-tree");
    fs::create_dir(&empty)?;
    for direction in [SessionTransferDirection::Upload, SessionTransferDirection::Download] {
        let (selected, remote, name) = match direction {
            SessionTransferDirection::Upload => {
                (empty.clone(), b"./.scoplen-files-smoke".as_slice(), "empty-tree-upload")
            }
            SessionTransferDirection::Download => (
                download.clone(),
                b"./.scoplen-files-smoke/empty-tree-upload".as_slice(),
                "empty-tree-download",
            ),
        };
        let saved = directory_copy(manager, transport, selected, remote, direction, name).await?;
        assert_eq!(saved.state, SessionTransferState::Saved);
        assert_eq!(
            (saved.transferred_bytes.as_str(), saved.total_bytes.as_deref()),
            ("0", Some("0"))
        );
        let progress = saved.directory_copy.as_ref().unwrap();
        assert_eq!((progress.files_total, progress.files_completed), (Some(0), 0));
        assert_eq!((progress.directories_total, progress.directories_created), (Some(1), 1));
        assert!(progress.root_created && !progress.root_creation_unknown);
    }
    assert_eq!(fs::read_dir(download.join("empty-tree-download"))?.count(), 0);
    for direction in [SessionTransferDirection::Upload, SessionTransferDirection::Download] {
        let (selected, remote, name) = match direction {
            SessionTransferDirection::Upload => {
                (source.clone(), b"./.scoplen-files-smoke".as_slice(), "recursive-upload")
            }
            SessionTransferDirection::Download => (
                download.clone(),
                b"./.scoplen-files-smoke/recursive-upload".as_slice(),
                "recursive-download",
            ),
        };
        let refused = directory_copy(manager, transport, selected, remote, direction, name).await?;
        assert_eq!(refused.state, SessionTransferState::Conflict);
        let progress = refused.directory_copy.as_ref().unwrap();
        assert_eq!(progress.issue, Some(SessionDirectoryCopyIssue::DestinationExists));
        assert!(!progress.root_created && !progress.root_creation_unknown);
    }
    let refused = directory_copy(
        manager,
        transport,
        download.clone(),
        b"./.scoplen-files-smoke/sync-links",
        SessionTransferDirection::Download,
        "links-refused",
    )
    .await?;
    assert_eq!(
        refused.directory_copy.as_ref().unwrap().issue,
        Some(SessionDirectoryCopyIssue::UnsupportedEntry)
    );
    assert!(!download.join("links-refused").exists());
    manager.input("fixture-terminal", transport, b"mkdir .scoplen-files-smoke/recursive-flat; i=0; while test $i -lt 1025; do : > .scoplen-files-smoke/recursive-flat/file-$i; i=$((i+1)); done; printf '%s%s\\n' SCOPLEN- RECURSIVE-FLAT-READY\n".to_vec())?;
    wait_for(output, b"SCOPLEN-RECURSIVE-FLAT-READY").await?;
    let flat = directory_copy(
        manager,
        transport,
        download.clone(),
        b"./.scoplen-files-smoke/recursive-flat",
        SessionTransferDirection::Download,
        "flat",
    )
    .await?;
    assert_eq!(flat.state, SessionTransferState::Saved);
    assert_eq!(flat.transferred_bytes, "0");
    assert_eq!(flat.directory_copy.as_ref().unwrap().files_completed, 1025);
    assert_eq!(fs::read_dir(download.join("flat"))?.count(), 1025);
    println!(
        "OpenSSH recursive upload/download: binary/Unicode, >64MiB file, empty files/folders/root, >16 children, 1025 flat files, new-root refusal, link refusal"
    );
    Ok(())
}

async fn queue_upload(
    manager: &SessionManager,
    transport: &str,
    directory: Vec<u8>,
    source: std::path::PathBuf,
) -> Result<SessionTransferEnqueueResult, Box<dyn std::error::Error>> {
    Ok(manager
        .enqueue_upload_with_picker(
            "fixture-terminal",
            transport,
            directory,
            move || async move { Ok(Some(source)) },
            |_| async { panic!("new queued upload cannot require replacement") },
        )
        .await?)
}

fn queue_identity(result: &SessionTransferEnqueueResult) -> (String, String, String) {
    match result {
        SessionTransferEnqueueResult::Queued { queue_id, item_id, execution_id } => {
            (queue_id.clone(), item_id.clone(), execution_id.clone())
        }
        SessionTransferEnqueueResult::Cancelled => panic!("queue fixture selection was cancelled"),
    }
}

async fn wait_queue_item(
    manager: &SessionManager,
    item: &str,
) -> Result<SessionTransferItem, Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = manager.transfer_queue_snapshot("fixture-terminal")?;
            if let Some(row) = snapshot.recent.into_iter().find(|row| row.item_id == item) {
                return Ok::<SessionTransferItem, Box<dyn std::error::Error>>(row);
            }
            if snapshot
                .items
                .iter()
                .any(|row| row.item_id == item && row.state == SessionTransferState::Unknown)
            {
                return Err("queue fixture publication was unknown; no retry was attempted".into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?
}

async fn wait_for(
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    marker: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut received = Vec::new();
    loop {
        let bytes = output.recv().await.ok_or("terminal output ended")?;
        received.extend(bytes);
        if received
            .windows(b"SCOPLEN-SYNC-SHELL-FAILED".len())
            .any(|part| part == b"SCOPLEN-SYNC-SHELL-FAILED")
        {
            return Err("disposable synchronization shell assertion failed".into());
        }
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
