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
        tokio::time::timeout(Duration::from_secs(120), async { tokio::join!(terminal, exercise) })
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
        snapshot.recent.iter().map(|row| row.item_id.as_str()).collect::<Vec<_>>(),
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
