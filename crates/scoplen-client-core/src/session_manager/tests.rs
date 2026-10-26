// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::inventory::{NewHost, SignIn};
use scoplen_crypto::LocalDatabaseKey;
use std::sync::atomic::{AtomicUsize, Ordering};

fn store() -> (tempfile::TempDir, Arc<Store>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("local.db"), &LocalDatabaseKey::new([7; 32])).unwrap();
    (dir, Arc::new(store))
}

fn snapshot(data: &str) -> TerminalSnapshot {
    TerminalSnapshot { version: 1, columns: 80, rows: 24, data: data.into() }
}

fn ready_file_manager()
-> (Arc<SessionManager>, Uuid, mpsc::Receiver<TransportCommand>, mpsc::Receiver<FileCommand>) {
    let manager = Arc::new(SessionManager::default());
    manager.reserve("terminal", true).unwrap();
    let transport = Uuid::now_v7();
    let (sender, commands) = mpsc::channel(COMMAND_QUEUE);
    let (files, file_requests) = mpsc::channel(FILE_QUEUE);
    let mut sessions = manager.sessions.lock().unwrap();
    let entry = sessions.get_mut("terminal").unwrap();
    entry.phase = Phase::Running;
    entry.active = Some(ActiveAttempt {
        id: transport,
        control: PreparationControl::default(),
        sender,
        files,
        file: None,
        ready: true,
        context: None,
    });
    drop(sessions);
    (manager, transport, commands, file_requests)
}

#[tokio::test]
async fn prepared_snippet_and_one_enter_use_only_the_captured_ready_transport() {
    use crate::snippets::{SnippetInput, SnippetVariableInput, SnippetVariableKind, Snippets};
    use std::collections::BTreeMap;

    let (_dir, store) = store();
    let snippets = Snippets::new(store);
    let saved = snippets
        .create(SnippetInput {
            name: "Inspect".into(),
            template: "printf '%s' '{{label}}'".into(),
            variables: vec![SnippetVariableInput {
                name: "label".into(),
                kind: SnippetVariableKind::Text,
                default: Some("ready".into()),
                choices: Vec::new(),
            }],
            tags: Vec::new(),
            folder: None,
        })
        .unwrap();
    let preview = snippets.prepare(&saved.id, BTreeMap::new()).unwrap();
    let (manager, transport, mut commands, _files) = ready_file_manager();
    let exact_input = format!("{}\r", preview.command).into_bytes();
    manager.input("terminal", &transport.to_string(), exact_input.clone()).unwrap();
    let Some(TransportCommand::Input(received)) = commands.recv().await else {
        panic!("prepared command must reach the captured input queue")
    };
    assert_eq!(received, b"printf '%s' 'ready'\r");
    assert!(manager.input("terminal", &Uuid::now_v7().to_string(), exact_input.clone()).is_err());
    let replacement = Uuid::now_v7();
    manager.sessions.lock().unwrap().get_mut("terminal").unwrap().active.as_mut().unwrap().id =
        replacement;
    assert!(manager.input("terminal", &transport.to_string(), exact_input.clone()).is_err());
    assert!(commands.try_recv().is_err());
    manager.close_all().unwrap();
    assert!(manager.input("terminal", &replacement.to_string(), exact_input).is_err());
}

#[tokio::test]
async fn profile_switch_closes_live_and_reserved_sessions_without_reusing_their_transports() {
    let (manager, transport, _commands, _files) = ready_file_manager();
    manager.reserve("pending", true).unwrap();
    manager.close_all().unwrap();
    assert!(manager.input("terminal", &transport.to_string(), b"late".to_vec()).is_err());
    assert!(manager.sessions.lock().unwrap().is_empty());
    manager.close_all().unwrap();
    manager.reserve("terminal", true).unwrap();
    assert!(manager.input("terminal", &transport.to_string(), b"foreign".to_vec()).is_err());
}

#[tokio::test]
async fn preview_serializes_file_access_without_blocking_terminal_commands() {
    let (manager, transport, mut commands, mut files) = ready_file_manager();
    let operation = Uuid::now_v7();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .preview_file(
                    "terminal",
                    &transport.to_string(),
                    &operation.to_string(),
                    b"./text".to_vec(),
                )
                .await
        }
    });
    let FileCommand::Preview { path, reply } = files.recv().await.unwrap() else {
        panic!("preview request expected")
    };
    assert_eq!(path, b"./text");
    assert_eq!(
        manager
            .preview_file(
                "terminal",
                &transport.to_string(),
                &Uuid::now_v7().to_string(),
                b"./second".to_vec()
            )
            .await
            .unwrap_err(),
        RemoteTextPreviewIssue::Unavailable
    );
    manager.input("terminal", &transport.to_string(), b"echo alive\n".to_vec()).unwrap();
    manager.resize("terminal", &transport.to_string(), 100, 30).unwrap();
    assert!(matches!(commands.recv().await.unwrap(), TransportCommand::Input(_)));
    assert!(matches!(commands.recv().await.unwrap(), TransportCommand::Resize { .. }));
    reply.send(Ok(RemoteTextPreview { text: "complete".into(), size_bytes: 8 })).unwrap();
    assert_eq!(pending.await.unwrap().unwrap().text, "complete");
    assert!(manager.sessions.lock().unwrap()["terminal"].active.as_ref().unwrap().file.is_none());
}

#[tokio::test]
async fn preview_cancel_is_operation_fenced_and_closes_its_response_receiver() {
    let (manager, transport, _commands, mut files) = ready_file_manager();
    let operation = Uuid::now_v7();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .preview_file(
                    "terminal",
                    &transport.to_string(),
                    &operation.to_string(),
                    b"./text".to_vec(),
                )
                .await
        }
    });
    let FileCommand::Preview { mut reply, .. } = files.recv().await.unwrap() else {
        panic!("preview request expected")
    };
    assert!(
        manager
            .cancel_file_operation("terminal", &transport.to_string(), &Uuid::now_v7().to_string())
            .is_err()
    );
    assert!(!pending.is_finished());
    manager
        .cancel_file_operation("terminal", &transport.to_string(), &operation.to_string())
        .unwrap();
    assert_eq!(pending.await.unwrap().unwrap_err(), RemoteTextPreviewIssue::Cancelled);
    reply.closed().await;
}

#[tokio::test(start_paused = true)]
async fn preview_has_a_sixty_second_absolute_deadline_and_releases_admission() {
    let (manager, transport, _commands, mut files) = ready_file_manager();
    let operation = Uuid::now_v7();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .preview_file(
                    "terminal",
                    &transport.to_string(),
                    &operation.to_string(),
                    b"./text".to_vec(),
                )
                .await
        }
    });
    let FileCommand::Preview { mut reply, .. } = files.recv().await.unwrap() else {
        panic!("preview request expected")
    };
    tokio::time::advance(Duration::from_secs(59)).await;
    assert!(!pending.is_finished());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(pending.await.unwrap().unwrap_err(), RemoteTextPreviewIssue::Timeout);
    reply.closed().await;
    assert!(manager.sessions.lock().unwrap()["terminal"].active.as_ref().unwrap().file.is_none());
}

#[tokio::test]
async fn preview_cannot_disclose_a_reply_after_transport_replacement() {
    let (manager, transport, _commands, mut files) = ready_file_manager();
    let operation = Uuid::now_v7();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .preview_file(
                    "terminal",
                    &transport.to_string(),
                    &operation.to_string(),
                    b"./text".to_vec(),
                )
                .await
        }
    });
    let FileCommand::Preview { reply, .. } = files.recv().await.unwrap() else {
        panic!("preview request expected")
    };
    manager.sessions.lock().unwrap().get_mut("terminal").unwrap().active.as_mut().unwrap().id =
        Uuid::now_v7();
    reply.send(Ok(RemoteTextPreview { text: "old transport".into(), size_bytes: 13 })).unwrap();
    assert_eq!(pending.await.unwrap().unwrap_err(), RemoteTextPreviewIssue::Unavailable);
}

#[test]
fn file_progress_is_decimal_and_fenced_to_the_current_operation() {
    let (manager, transport, _commands, _files) = ready_file_manager();
    let operation = Uuid::now_v7();
    let (abort, _) = AbortHandle::new_pair();
    let _guard = manager
        .reserve_file_operation("terminal", &transport.to_string(), &operation.to_string(), abort)
        .unwrap();
    let mut updates = Vec::new();
    let mut report = |update| updates.push(update);
    let large = 9_007_199_254_740_993_u64;
    let transfer = FileTransferProgress {
        transferred: large,
        total: Some(large + 1),
        phase: SessionFileTransferPhase::Transferring,
    };
    SessionManager::report_file_progress(
        &manager.sessions,
        "terminal",
        Uuid::now_v7(),
        operation,
        &mut report,
        transfer,
    );
    SessionManager::report_file_progress(
        &manager.sessions,
        "terminal",
        transport,
        operation,
        &mut report,
        transfer,
    );
    manager
        .cancel_file_operation("terminal", &transport.to_string(), &operation.to_string())
        .unwrap();
    SessionManager::report_file_progress(
        &manager.sessions,
        "terminal",
        transport,
        operation,
        &mut report,
        transfer,
    );
    let next_operation = Uuid::now_v7();
    let (next_abort, _) = AbortHandle::new_pair();
    let _next_guard = manager
        .reserve_file_operation(
            "terminal",
            &transport.to_string(),
            &next_operation.to_string(),
            next_abort,
        )
        .unwrap();
    manager.finish_remote_effect("terminal", transport, next_operation);
    SessionManager::report_file_progress(
        &manager.sessions,
        "terminal",
        transport,
        next_operation,
        &mut report,
        transfer,
    );
    let expired_operation = Uuid::now_v7();
    let (expired_abort, _) = AbortHandle::new_pair();
    let _expired_guard = manager
        .reserve_file_operation(
            "terminal",
            &transport.to_string(),
            &expired_operation.to_string(),
            expired_abort,
        )
        .unwrap();
    manager.expire_ready_transport("terminal", transport).unwrap();
    SessionManager::report_file_progress(
        &manager.sessions,
        "terminal",
        transport,
        expired_operation,
        &mut report,
        transfer,
    );
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].session_id, "terminal");
    assert_eq!(updates[0].transport_id, transport.to_string());
    assert_eq!(updates[0].operation_id, operation.to_string());
    assert_eq!(updates[0].transferred_bytes, large.to_string());
    assert_eq!(updates[0].total_bytes, Some((large + 1).to_string()));
}

#[tokio::test]
async fn upload_refuses_existing_target_without_atomic_replace_extension() {
    let (manager, transport, _commands, mut files) = ready_file_manager();
    let local = tempfile::tempdir().unwrap();
    let source = local.path().join("keep.bin");
    std::fs::write(&source, b"new content").unwrap();
    let confirmed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let pending = tokio::spawn({
        let manager = manager.clone();
        let confirmed = confirmed.clone();
        async move {
            manager
                .upload_file_with_picker(
                    "terminal",
                    &transport.to_string(),
                    &Uuid::now_v7().to_string(),
                    b".".to_vec(),
                    || async { Ok(Some(source)) },
                    move |_| async move {
                        confirmed.store(true, Ordering::SeqCst);
                        Ok(true)
                    },
                    |_| {},
                )
                .await
        }
    });
    let FileCommand::PreflightUpload { target, reply } = files.recv().await.unwrap() else {
        panic!("expected upload preflight")
    };
    assert_eq!(target, b"./keep.bin");
    reply
        .send(Ok(UploadPreflight {
            target_attributes: Some(scoplen_ssh::SftpAttributes {
                permissions: Some(0o100600),
                size: Some(3),
                ..Default::default()
            }),
            replacement_supported: false,
        }))
        .unwrap();
    let result = pending.await.unwrap().unwrap();
    assert_eq!(result.status, SessionUploadStatus::Unsupported);
    assert!(!result.staging_may_remain);
    assert!(!confirmed.load(Ordering::SeqCst));
    assert!(files.try_recv().is_err());
    assert_eq!(std::fs::read(local.path().join("keep.bin")).unwrap(), b"new content");
}

#[tokio::test]
async fn upload_publication_rejects_cancel_and_lost_worker_is_unknown() {
    let (manager, transport, _commands, mut files) = ready_file_manager();
    let local = tempfile::tempdir().unwrap();
    let source = local.path().join("upload.bin");
    std::fs::write(&source, b"new content").unwrap();
    let operation = Uuid::now_v7();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .upload_file_with_picker(
                    "terminal",
                    &transport.to_string(),
                    &operation.to_string(),
                    b".".to_vec(),
                    || async { Ok(Some(source)) },
                    |_| async { Ok(true) },
                    |_| {},
                )
                .await
        }
    });
    let FileCommand::PreflightUpload { reply, .. } = files.recv().await.unwrap() else {
        panic!("expected upload preflight")
    };
    reply
        .send(Ok(UploadPreflight { target_attributes: None, replacement_supported: false }))
        .unwrap();
    let FileCommand::Upload { state, reply, .. } = files.recv().await.unwrap() else {
        panic!("expected upload worker")
    };
    state.staging_may_remain.store(true, Ordering::SeqCst);
    SessionManager::authorize_remote_effect(&manager.sessions, "terminal", transport, operation)
        .unwrap();
    assert!(
        manager
            .cancel_file_operation("terminal", &transport.to_string(), &operation.to_string())
            .unwrap_err()
            .contains("result must be checked")
    );
    manager.expire_ready_transport("terminal", transport).unwrap();
    drop(reply);
    let result = pending.await.unwrap().unwrap();
    assert_eq!(result.status, SessionUploadStatus::Unknown);
    assert!(result.staging_may_remain);
}

#[tokio::test]
async fn cancelled_upload_confirmation_cannot_queue_late_transfer() {
    let (manager, transport, _commands, mut files) = ready_file_manager();
    let local = tempfile::tempdir().unwrap();
    let source = local.path().join("existing.bin");
    std::fs::write(&source, b"new content").unwrap();
    let operation = Uuid::now_v7();
    let (entered, waiting) = oneshot::channel();
    let (confirm, decided) = oneshot::channel::<bool>();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .upload_file_with_picker(
                    "terminal",
                    &transport.to_string(),
                    &operation.to_string(),
                    b".".to_vec(),
                    || async { Ok(Some(source)) },
                    |_| async move {
                        entered.send(()).unwrap();
                        Ok(decided.await.unwrap())
                    },
                    |_| {},
                )
                .await
        }
    });
    let FileCommand::PreflightUpload { reply, .. } = files.recv().await.unwrap() else {
        panic!("expected upload preflight")
    };
    reply
        .send(Ok(UploadPreflight {
            target_attributes: Some(scoplen_ssh::SftpAttributes {
                permissions: Some(0o100600),
                ..Default::default()
            }),
            replacement_supported: true,
        }))
        .unwrap();
    waiting.await.unwrap();
    manager
        .cancel_file_operation("terminal", &transport.to_string(), &operation.to_string())
        .unwrap();
    let result = pending.await.unwrap().unwrap();
    assert_eq!(result.status, SessionUploadStatus::Cancelled);
    assert!(!result.staging_may_remain);
    assert!(confirm.send(true).is_err(), "late native answer must be ignored");
    assert!(files.try_recv().is_err());
}

#[tokio::test]
async fn cancel_before_upload_publication_waits_for_worker_cleanup() {
    let (manager, transport, _commands, mut files) = ready_file_manager();
    let local = tempfile::tempdir().unwrap();
    let source = local.path().join("upload.bin");
    std::fs::write(&source, b"new content").unwrap();
    let operation = Uuid::now_v7();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .upload_file_with_picker(
                    "terminal",
                    &transport.to_string(),
                    &operation.to_string(),
                    b".".to_vec(),
                    || async { Ok(Some(source)) },
                    |_| async { Ok(true) },
                    |_| {},
                )
                .await
        }
    });
    let FileCommand::PreflightUpload { reply, .. } = files.recv().await.unwrap() else {
        panic!("expected upload preflight")
    };
    reply
        .send(Ok(UploadPreflight { target_attributes: None, replacement_supported: false }))
        .unwrap();
    let FileCommand::Upload { cancel, reply, .. } = files.recv().await.unwrap() else {
        panic!("expected upload worker")
    };
    manager
        .cancel_file_operation("terminal", &transport.to_string(), &operation.to_string())
        .unwrap();
    assert!(*cancel.borrow());
    assert!(!pending.is_finished(), "caller must wait for cleanup result");
    manager.finish_remote_effect("terminal", transport, operation);
    reply.send(SessionUploadResult::new(SessionUploadStatus::Cancelled, None, false)).unwrap();
    let result = pending.await.unwrap().unwrap();
    assert_eq!(result.status, SessionUploadStatus::Cancelled);
}

#[tokio::test]
async fn remote_create_lost_acknowledgement_is_unknown_and_never_requeued() {
    let (manager, transport, _commands, mut files) = ready_file_manager();
    let operation = Uuid::now_v7();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .create_remote_directory(
                    "terminal",
                    &transport.to_string(),
                    &operation.to_string(),
                    b".".to_vec(),
                    "new-folder",
                )
                .await
        }
    });
    let FileCommand::PreflightMutation { mutation, reply } = files.recv().await.unwrap() else {
        panic!("expected mutation preflight")
    };
    assert!(
        matches!(mutation, RemoteMutation::CreateDirectory { target, .. } if target == b"./new-folder")
    );
    reply
        .send(Ok(MutationPreflight {
            directory_attributes: scoplen_ssh::SftpAttributes {
                permissions: Some(0o040700),
                ..Default::default()
            },
            source_attributes: None,
            source_kind: None,
        }))
        .ok();
    let FileCommand::Mutation { reply, .. } = files.recv().await.unwrap() else {
        panic!("expected mutation dispatch")
    };
    SessionManager::authorize_remote_effect(&manager.sessions, "terminal", transport, operation)
        .unwrap();
    assert!(
        manager
            .cancel_file_operation("terminal", &transport.to_string(), &operation.to_string())
            .unwrap_err()
            .contains("result must be checked")
    );
    manager.expire_ready_transport("terminal", transport).unwrap();
    drop(reply);
    let result = pending.await.unwrap().unwrap();
    assert_eq!(result.status, SessionFileMutationStatus::Unknown);
    assert!(files.try_recv().is_err(), "unknown result must not enqueue a retry");
}

#[tokio::test]
async fn cancelled_delete_confirmation_cannot_dispatch_a_late_removal() {
    let (manager, transport, _commands, mut files) = ready_file_manager();
    let operation = Uuid::now_v7();
    let (entered, waiting) = oneshot::channel();
    let (confirm, decided) = oneshot::channel::<bool>();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .delete_remote_entry_with_confirmation(
                    "terminal",
                    &transport.to_string(),
                    &operation.to_string(),
                    b".".to_vec(),
                    b"./empty".to_vec(),
                    |kind, name| async move {
                        assert_eq!(kind, session_files::RemoteFileKind::Directory);
                        assert_eq!(name, "empty");
                        entered.send(()).unwrap();
                        Ok(decided.await.unwrap())
                    },
                )
                .await
        }
    });
    let FileCommand::PreflightMutation { reply, .. } = files.recv().await.unwrap() else {
        panic!("expected mutation preflight")
    };
    reply
        .send(Ok(MutationPreflight {
            directory_attributes: scoplen_ssh::SftpAttributes {
                permissions: Some(0o040700),
                ..Default::default()
            },
            source_attributes: Some(scoplen_ssh::SftpAttributes {
                permissions: Some(0o040700),
                ..Default::default()
            }),
            source_kind: Some(session_files::RemoteFileKind::Directory),
        }))
        .ok();
    waiting.await.unwrap();
    manager
        .cancel_file_operation("terminal", &transport.to_string(), &operation.to_string())
        .unwrap();
    let result = pending.await.unwrap().unwrap();
    assert_eq!(result.status, SessionFileMutationStatus::Cancelled);
    assert!(confirm.send(true).is_err(), "late native answer must be ignored");
    assert!(files.try_recv().is_err());
}

#[tokio::test]
async fn remote_rename_conflict_stops_before_dispatch() {
    let (manager, transport, _commands, mut files) = ready_file_manager();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .rename_remote_entry(
                    "terminal",
                    &transport.to_string(),
                    &Uuid::now_v7().to_string(),
                    b".".to_vec(),
                    b"./source".to_vec(),
                    "existing",
                )
                .await
        }
    });
    let FileCommand::PreflightMutation { reply, .. } = files.recv().await.unwrap() else {
        panic!("expected mutation preflight")
    };
    reply.send(Err(session_files::FileAccessError::Conflict)).ok();
    let result = pending.await.unwrap().unwrap();
    assert_eq!(result.status, SessionFileMutationStatus::Conflict);
    assert!(files.try_recv().is_err());
}

#[tokio::test]
async fn file_cancellation_and_refusal_preserve_terminal_and_allow_a_new_request() {
    let (manager, transport, mut commands, mut files) = ready_file_manager();
    let first = Uuid::now_v7();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .list_files("terminal", &transport.to_string(), &first.to_string(), b".".to_vec())
                .await
        }
    });
    let FileCommand::List { reply, .. } = files.recv().await.unwrap() else {
        panic!("expected a directory request")
    };
    manager.input("terminal", &transport.to_string(), b"pwd\n".to_vec()).unwrap();
    manager.resize("terminal", &transport.to_string(), 100, 30).unwrap();
    assert_eq!(commands.recv().await, Some(TransportCommand::Input(b"pwd\n".to_vec())));
    assert_eq!(commands.recv().await, Some(TransportCommand::Resize { columns: 100, rows: 30 }));
    manager.cancel_file_operation("terminal", &transport.to_string(), &first.to_string()).unwrap();
    assert!(pending.await.unwrap().unwrap_err().contains("cancelled"));
    assert!(reply.is_closed());

    let second = Uuid::now_v7();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .list_files("terminal", &transport.to_string(), &second.to_string(), b".".to_vec())
                .await
        }
    });
    let FileCommand::List { reply, .. } = files.recv().await.unwrap() else {
        panic!("expected the replacement directory request")
    };
    reply.send(Err("remote SFTP was refused".into())).unwrap();
    assert!(pending.await.unwrap().unwrap_err().contains("refused"));
    manager.input("terminal", &transport.to_string(), b"still open\n".to_vec()).unwrap();
    assert_eq!(commands.recv().await, Some(TransportCommand::Input(b"still open\n".to_vec())));

    let third = Uuid::now_v7();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .list_files("terminal", &transport.to_string(), &third.to_string(), b".".to_vec())
                .await
        }
    });
    let FileCommand::List { reply, .. } = files.recv().await.unwrap() else {
        panic!("expected a fresh directory request")
    };
    reply.send(Ok(RemoteDirectory { entries: Vec::new() })).unwrap();
    assert_eq!(pending.await.unwrap().unwrap(), RemoteDirectory { entries: Vec::new() });
}

#[tokio::test]
async fn cancelled_picker_cannot_queue_a_late_download() {
    let (manager, transport, _commands, mut files) = ready_file_manager();
    let picker_opened = std::sync::atomic::AtomicBool::new(false);
    assert!(
        manager
            .download_file_with_picker(
                "terminal",
                &transport.to_string(),
                &Uuid::now_v7().to_string(),
                Vec::new(),
                || async {
                    picker_opened.store(true, Ordering::SeqCst);
                    Ok(None)
                },
                |_| {},
            )
            .await
            .is_err()
    );
    assert!(!picker_opened.load(Ordering::SeqCst));
    let operation = Uuid::now_v7();
    let (picker_started, started) = oneshot::channel();
    let (picker_result, chosen) = oneshot::channel();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .download_file_with_picker(
                    "terminal",
                    &transport.to_string(),
                    &operation.to_string(),
                    b"./document".to_vec(),
                    || async move {
                        picker_started.send(()).unwrap();
                        Ok(Some(chosen.await.unwrap()))
                    },
                    |_| {},
                )
                .await
        }
    });
    started.await.unwrap();
    manager
        .cancel_file_operation("terminal", &transport.to_string(), &operation.to_string())
        .unwrap();
    assert_eq!(pending.await.unwrap().unwrap().status, SessionDownloadStatus::Cancelled);
    assert!(picker_result.send(PathBuf::from("late-choice")).is_err());
    assert!(files.try_recv().is_err());
}

#[tokio::test]
async fn ended_transport_cancels_a_picker_before_its_late_result() {
    let (manager, transport, _commands, mut files) = ready_file_manager();
    let operation = Uuid::now_v7();
    let (picker_started, started) = oneshot::channel();
    let (_picker_result, chosen) = oneshot::channel::<PathBuf>();
    let pending = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .download_file_with_picker(
                    "terminal",
                    &transport.to_string(),
                    &operation.to_string(),
                    b"./document".to_vec(),
                    || async move {
                        picker_started.send(()).unwrap();
                        Ok(Some(chosen.await.unwrap()))
                    },
                    |_| {},
                )
                .await
        }
    });
    started.await.unwrap();
    manager.phase("terminal", Phase::Ended).unwrap();
    assert_eq!(pending.await.unwrap().unwrap().status, SessionDownloadStatus::Cancelled);
    assert!(files.try_recv().is_err());
}

#[test]
fn old_transport_cannot_commit_a_download() {
    let (manager, transport, _commands, _files) = ready_file_manager();
    let operation = Uuid::now_v7();
    let (abort, _) = AbortHandle::new_pair();
    let _guard = manager
        .reserve_file_operation("terminal", &transport.to_string(), &operation.to_string(), abort)
        .unwrap();
    let folder = tempfile::tempdir().unwrap();
    let temporary = folder.path().join("partial");
    let destination = folder.path().join("existing");
    std::fs::write(&temporary, b"new").unwrap();
    std::fs::write(&destination, b"original").unwrap();
    manager.sessions.lock().unwrap().get_mut("terminal").unwrap().active.as_mut().unwrap().id =
        Uuid::now_v7();
    assert_eq!(
        SessionManager::commit_download(
            &manager.sessions,
            "terminal",
            transport,
            operation,
            None,
            || std::fs::rename(&temporary, &destination)
                .map_err(session_files::FileAccessError::LocalIo),
        )
        .status,
        SessionDownloadStatus::Failed
    );
    assert_eq!(std::fs::read(destination).unwrap(), b"original");
}

#[test]
fn cancellation_before_local_commit_leaves_the_destination_untouched() {
    let (manager, transport, _commands, _files) = ready_file_manager();
    let operation = Uuid::now_v7();
    let (abort, _) = AbortHandle::new_pair();
    let _guard = manager
        .reserve_file_operation("terminal", &transport.to_string(), &operation.to_string(), abort)
        .unwrap();
    let folder = tempfile::tempdir().unwrap();
    let temporary = folder.path().join("partial");
    let destination = folder.path().join("existing");
    std::fs::write(&temporary, b"new").unwrap();
    std::fs::write(&destination, b"original").unwrap();
    manager
        .cancel_file_operation("terminal", &transport.to_string(), &operation.to_string())
        .unwrap();
    let result = SessionManager::commit_download(
        &manager.sessions,
        "terminal",
        transport,
        operation,
        None,
        || {
            std::fs::rename(&temporary, &destination)
                .map_err(session_files::FileAccessError::LocalIo)
        },
    );
    assert_eq!(result.status, SessionDownloadStatus::Failed);
    assert_eq!(std::fs::read(destination).unwrap(), b"original");
    assert_eq!(std::fs::read(temporary).unwrap(), b"new");
}

#[tokio::test]
async fn started_local_commit_rejects_cancel_and_keeps_its_result_after_disconnect_or_close() {
    for close in [false, true] {
        let (manager, transport, _commands, _files) = ready_file_manager();
        let operation = Uuid::now_v7();
        let (abort, _) = AbortHandle::new_pair();
        let _guard = manager
            .reserve_file_operation(
                "terminal",
                &transport.to_string(),
                &operation.to_string(),
                abort.clone(),
            )
            .unwrap();
        let folder = tempfile::tempdir().unwrap();
        let temporary = folder.path().join("partial");
        let destination = folder.path().join("existing");
        std::fs::write(&temporary, b"new").unwrap();
        std::fs::write(&destination, b"original").unwrap();
        let (commit_started, started) = oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let sessions = manager.sessions.clone();
        let commit = tokio::task::spawn_blocking(move || {
            SessionManager::commit_download(
                &sessions,
                "terminal",
                transport,
                operation,
                None,
                || {
                    commit_started.send(()).unwrap();
                    released.recv().unwrap();
                    std::fs::rename(&temporary, &destination)
                        .map_err(session_files::FileAccessError::LocalIo)
                },
            )
        });
        started.await.unwrap();
        assert!(
            manager
                .cancel_file_operation("terminal", &transport.to_string(), &operation.to_string())
                .unwrap_err()
                .contains("result must be checked")
        );
        if close {
            manager.phase("terminal", Phase::Ended).unwrap();
        } else {
            manager.expire_ready_transport("terminal", transport).unwrap();
        }
        assert!(!abort.is_aborted());
        release.send(()).unwrap();
        assert_eq!(commit.await.unwrap().status, SessionDownloadStatus::Saved);
        assert_eq!(std::fs::read(folder.path().join("existing")).unwrap(), b"new");
    }
}

#[tokio::test]
async fn claimed_download_delivers_saved_after_stop_fail_close_or_registration_drop() {
    for action in [Intent::Stop, Intent::Fail, Intent::Close, Intent::None] {
        let (manager, transport, _commands, mut files) = ready_file_manager();
        let operation = Uuid::now_v7();
        let folder = tempfile::tempdir().unwrap();
        let destination = folder.path().join("existing");
        let temporary = folder.path().join("partial");
        std::fs::write(&destination, b"original").unwrap();
        std::fs::write(&temporary, b"new").unwrap();
        let pending = tokio::spawn({
            let manager = manager.clone();
            let destination = destination.clone();
            async move {
                manager
                    .download_file_with_picker(
                        "terminal",
                        &transport.to_string(),
                        &operation.to_string(),
                        b"./document".to_vec(),
                        || async { Ok(Some(destination)) },
                        |_| {},
                    )
                    .await
            }
        });
        let FileCommand::Download { reply, .. } = files.recv().await.unwrap() else {
            panic!("expected download worker")
        };
        let (claimed, started) = oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let sessions = manager.sessions.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let result = SessionManager::commit_download(
                &sessions,
                "terminal",
                transport,
                operation,
                None,
                || {
                    claimed.send(()).unwrap();
                    released.recv().unwrap();
                    std::fs::rename(&temporary, &destination)
                        .map_err(session_files::FileAccessError::LocalIo)
                },
            );
            SessionManager::finish_file_effect(&sessions, "terminal", transport, operation);
            let _ = reply.send(result.clone());
            result
        });
        started.await.unwrap();
        match action {
            Intent::Stop => manager.stop("terminal").unwrap(),
            Intent::Fail => manager.fail("terminal").unwrap(),
            Intent::Close => manager.close("terminal").unwrap(),
            Intent::None => drop(Registration { manager: &manager, id: "terminal" }),
            Intent::Retry => unreachable!(),
        }
        release.send(()).unwrap();
        assert_eq!(worker.await.unwrap().status, SessionDownloadStatus::Saved);
        assert_eq!(pending.await.unwrap().unwrap().status, SessionDownloadStatus::Saved);
        assert_eq!(std::fs::read(folder.path().join("existing")).unwrap(), b"new");
    }
}

#[tokio::test]
async fn lost_download_worker_reply_is_unknown_after_commit_and_is_not_requeued() {
    let (manager, transport, _commands, mut files) = ready_file_manager();
    let operation = Uuid::now_v7();
    let folder = tempfile::tempdir().unwrap();
    let destination = folder.path().join("existing");
    let temporary = folder.path().join("partial");
    std::fs::write(&destination, b"original").unwrap();
    std::fs::write(&temporary, b"new").unwrap();
    let pending = tokio::spawn({
        let manager = manager.clone();
        let destination = destination.clone();
        async move {
            manager
                .download_file_with_picker(
                    "terminal",
                    &transport.to_string(),
                    &operation.to_string(),
                    b"./document".to_vec(),
                    || async { Ok(Some(destination)) },
                    |_| {},
                )
                .await
        }
    });
    let FileCommand::Download { reply, .. } = files.recv().await.unwrap() else {
        panic!("expected download worker")
    };
    let committed = SessionManager::commit_download(
        &manager.sessions,
        "terminal",
        transport,
        operation,
        None,
        || {
            std::fs::rename(&temporary, &destination)
                .map_err(session_files::FileAccessError::LocalIo)
        },
    );
    assert_eq!(committed.status, SessionDownloadStatus::Saved);
    drop(reply);
    assert_eq!(pending.await.unwrap().unwrap().status, SessionDownloadStatus::Unknown);
    assert_eq!(std::fs::read(destination).unwrap(), b"new");
    assert!(files.try_recv().is_err());
}

#[tokio::test]
async fn ended_ready_transport_fences_a_delayed_file_commit() {
    let (manager, transport, _commands, _files) = ready_file_manager();
    let operation = Uuid::now_v7();
    let (abort, _) = AbortHandle::new_pair();
    let _guard = manager
        .reserve_file_operation("terminal", &transport.to_string(), &operation.to_string(), abort)
        .unwrap();
    let folder = tempfile::tempdir().unwrap();
    let temporary = folder.path().join("partial");
    let destination = folder.path().join("existing");
    std::fs::write(&temporary, b"new").unwrap();
    std::fs::write(&destination, b"original").unwrap();
    let (worker_started, started) = oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let sessions = manager.sessions.clone();
    let commit = tokio::task::spawn_blocking({
        let temporary = temporary.clone();
        let destination = destination.clone();
        move || {
            worker_started.send(()).unwrap();
            released.recv().unwrap();
            SessionManager::commit_download(
                &sessions,
                "terminal",
                transport,
                operation,
                None,
                || {
                    std::fs::rename(&temporary, &destination)
                        .map_err(session_files::FileAccessError::LocalIo)
                },
            )
        }
    });
    started.await.unwrap();
    manager.expire_ready_transport("terminal", transport).unwrap();
    assert!(manager.input("terminal", &transport.to_string(), b"late\n".to_vec()).is_err());
    release.send(()).unwrap();
    assert_eq!(commit.await.unwrap().status, SessionDownloadStatus::Failed);
    assert_eq!(std::fs::read(destination).unwrap(), b"original");
    assert_eq!(std::fs::read(temporary).unwrap(), b"new");
}

#[tokio::test]
async fn file_permit_expires_before_select_drops_the_file_worker() {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct PendingFileWorker<'a> {
        manager: &'a SessionManager,
        transport: Uuid,
    }

    impl Future for PendingFileWorker<'_> {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingFileWorker<'_> {
        fn drop(&mut self) {
            let sessions = self.manager.sessions.lock().unwrap();
            let active = sessions.get("terminal").unwrap().active.as_ref().unwrap();
            assert_eq!(active.id, self.transport);
            assert!(!active.ready);
            assert!(active.file.is_none());
        }
    }

    let (manager, transport, _commands, _files) = ready_file_manager();
    let operation = Uuid::now_v7();
    let (abort, _) = AbortHandle::new_pair();
    let _guard = manager
        .reserve_file_operation("terminal", &transport.to_string(), &operation.to_string(), abort)
        .unwrap();
    tokio::select! { biased;
        result = manager.stream_with_file_expiry("terminal", transport, async { Ok(()) }) => {
            result.unwrap();
        }
        _ = PendingFileWorker { manager: &manager, transport } => unreachable!(),
    }
}

#[test]
fn checkpoint_ownership_rejects_cross_store_attempt_sequence_and_forgotten_history() {
    use crate::store::device::{SessionKind, SessionOutcome};
    let (_dir, local) = store();
    let (_other_dir, other) = store();
    let history = local.record_session_start(Uuid::now_v7(), SessionKind::Terminal).unwrap();
    let manager = SessionManager::default();
    manager.reserve("logical", true).unwrap();
    let transport = Uuid::now_v7();
    manager.sessions.lock().unwrap().get_mut("logical").unwrap().checkpoint =
        Some(CheckpointOwner { store: local.clone(), history, transport, sequence: 0 });
    let saved = snapshot("last valid rendered screen");
    manager.save_output(&local, "logical", &transport.to_string(), 1, &saved).unwrap();
    for result in [
        manager.save_output(&other, "logical", &transport.to_string(), 2, &saved),
        manager.save_output(&local, "other", &transport.to_string(), 2, &saved),
        manager.save_output(&local, "logical", &Uuid::now_v7().to_string(), 2, &saved),
        manager.save_output(&local, "logical", &transport.to_string(), 1, &saved),
    ] {
        assert_eq!(result, Err(SavedOutputError::StaleCheckpoint));
    }
    assert_eq!(local.scrollback(history).unwrap(), Some(saved.clone()));
    local.record_session_end(history, SessionOutcome::Closed).unwrap();
    local.forget_session(history).unwrap();
    assert_eq!(
        manager.save_output(&local, "logical", &transport.to_string(), 2, &saved),
        Err(SavedOutputError::Unavailable)
    );
    manager.close("logical").unwrap();
    assert_eq!(
        manager.save_output(&local, "logical", &transport.to_string(), 3, &saved),
        Err(SavedOutputError::StaleCheckpoint)
    );
}

#[tokio::test]
async fn interactive_answers_reject_wrong_and_previous_transports_without_consuming_the_current_prompt()
 {
    use crate::connection::preparation::{PreparationEvent, PreparationResponse};
    use crate::connection::test_peer::{Authentication, Peer};
    let peer = Peer::with_authentication(Authentication::Interactive).await;
    let (_dir, store) = store();
    let inventory = Inventory::new(store.clone());
    let host = inventory
        .add_host(NewHost {
            name: Some("interactive peer".into()),
            address: "127.0.0.1".into(),
            port: Some(peer.port),
            username: "trust-fixture".into(),
            sign_in: SignIn::KeyboardInteractive,
        })
        .unwrap();
    let manager = SessionManager::default();
    manager.reserve("terminal", true).unwrap();
    let transports = Mutex::new(Vec::new());
    let old_prompt = Mutex::new(None);
    let rounds = AtomicUsize::new(0);
    let ready = AtomicUsize::new(0);
    tokio::time::timeout(
        Duration::from_secs(20),
        manager.run(
            "terminal",
            &host.logins[0].id,
            None,
            true,
            store,
            |event| {
                match event {
                    SessionEvent::Starting { transport_id, .. } => {
                        transports.lock().unwrap().push(transport_id)
                    }
                    SessionEvent::Preparation { transport_id, event } => match *event {
                        PreparationEvent::Trust { prompt_id, .. } => {
                            manager.respond(
                                "terminal",
                                &transport_id,
                                &prompt_id,
                                PreparationResponse::AcceptHostKey,
                            )?;
                        }
                        PreparationEvent::KeyboardInteractive { prompt_id, .. } => {
                            let response = || {
                                PreparationResponse::keyboard_interactive(vec![
                                    b"visible".to_vec(),
                                    vec![],
                                ])
                                .unwrap()
                            };
                            assert!(
                                manager
                                    .respond(
                                        "terminal",
                                        &Uuid::now_v7().to_string(),
                                        &prompt_id,
                                        response()
                                    )
                                    .is_err()
                            );
                            assert!(
                                manager
                                    .respond("unknown", &transport_id, &prompt_id, response())
                                    .is_err()
                            );
                            let first = transports.lock().unwrap()[0].clone();
                            if first == transport_id {
                                *old_prompt.lock().unwrap() = Some(prompt_id);
                                manager.stop("terminal")?;
                            } else {
                                let old = old_prompt.lock().unwrap().clone().unwrap();
                                assert!(
                                    manager.respond("terminal", &first, &old, response()).is_err()
                                );
                                assert!(
                                    manager
                                        .respond("terminal", &first, &prompt_id, response())
                                        .is_err()
                                );
                                assert!(
                                    manager
                                        .respond("terminal", &transport_id, &old, response())
                                        .is_err()
                                );
                                let answer = match rounds.fetch_add(1, Ordering::SeqCst) {
                                    0 => vec![b"visible".to_vec(), vec![]],
                                    1 => vec![],
                                    2 => vec![b"123456".to_vec()],
                                    _ => panic!("unexpected authentication round"),
                                };
                                manager.respond(
                                    "terminal",
                                    &transport_id,
                                    &prompt_id,
                                    PreparationResponse::keyboard_interactive(answer).unwrap(),
                                )?;
                            }
                        }
                        _ => {}
                    },
                    SessionEvent::Closed => manager.retry("terminal")?,
                    SessionEvent::Ready { .. } => {
                        ready.fetch_add(1, Ordering::SeqCst);
                        manager.close("terminal")?;
                    }
                    SessionEvent::Failed { error, .. } => {
                        panic!("interactive session failed: {error}")
                    }
                    _ => {}
                }
                Ok(())
            },
            |_, _| Ok(()),
            |_, _| {},
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(transports.lock().unwrap().len(), 2);
    assert_eq!(rounds.load(Ordering::SeqCst), 3);
    assert_eq!(ready.load(Ordering::SeqCst), 1);
    assert!(manager.sessions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rejected_saved_password_fails_and_preserves_manual_retry_without_automatic_reconnect() {
    use crate::connection::preparation::{PreparationEvent, PreparationResponse};
    let peer = crate::connection::test_peer::Peer::start().await;
    let (_dir, store) = store();
    let inventory = Inventory::new(store.clone());
    let host = inventory
        .add_host(NewHost {
            name: Some("rejected-password peer".into()),
            address: "127.0.0.1".into(),
            port: Some(peer.port),
            username: "trust-fixture".into(),
            sign_in: SignIn::Password { password: "wrong-disposable-password".into() },
        })
        .unwrap();
    let manager = SessionManager::default();
    manager.reserve("terminal", true).unwrap();
    let transports = Mutex::new(Vec::new());
    let failures = AtomicUsize::new(0);
    tokio::time::timeout(
        Duration::from_secs(10),
        manager.run(
            "terminal",
            &host.logins[0].id,
            None,
            true,
            store.clone(),
            |event| {
                match event {
                    SessionEvent::Starting { transport_id, automatic } => {
                        assert!(!automatic);
                        transports.lock().unwrap().push(transport_id);
                    }
                    SessionEvent::Preparation { transport_id, event } => {
                        if let PreparationEvent::Trust { prompt_id, .. } = *event {
                            manager.respond(
                                "terminal",
                                &transport_id,
                                &prompt_id,
                                PreparationResponse::AcceptHostKey,
                            )?;
                        }
                    }
                    SessionEvent::Failed { exhausted, .. } => {
                        assert!(!exhausted);
                        if failures.fetch_add(1, Ordering::SeqCst) == 0 {
                            manager.retry("terminal")?;
                        } else {
                            manager.close("terminal")?;
                        }
                    }
                    _ => {
                        panic!("rejected authentication must fail without closing or reconnecting")
                    }
                }
                Ok(())
            },
            |_, _| panic!("rejected authentication must not open a shell"),
            |_, _| {},
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(failures.load(Ordering::SeqCst), 2);
    assert_eq!(peer.authentications.load(Ordering::SeqCst), 2);
    assert_eq!(peer.challenges.load(Ordering::SeqCst), 0);
    assert_eq!(peer.session_channels.load(Ordering::SeqCst), 0);
    let transports = transports.lock().unwrap();
    assert_eq!(transports.len(), 2);
    assert_ne!(transports[0], transports[1]);
    assert!(manager.sessions.lock().unwrap().is_empty());
    let recent = inventory.recent_sessions().unwrap();
    assert_eq!(recent.len(), 2);
    assert!(recent.iter().all(|entry| {
        entry.ended_at.is_some() && entry.outcome == Some(RecentSessionOutcome::Failed)
    }));
}

#[tokio::test]
async fn real_ssh_output_checkpoint_survives_encrypted_reopen_and_offline_read() {
    use crate::connection::preparation::{PreparationEvent, PreparationResponse};
    let peer = crate::connection::test_peer::Peer::start().await;
    let (dir, local) = store();
    let inventory = Inventory::new(local.clone());
    let host = inventory
        .add_host(NewHost {
            name: Some("saved-output peer".into()),
            address: "127.0.0.1".into(),
            port: Some(peer.port),
            username: "trust-fixture".into(),
            sign_in: SignIn::Password { password: "disposable-trust-password".into() },
        })
        .unwrap();
    let manager = SessionManager::default();
    manager.reserve("terminal", true).unwrap();
    let bytes = Mutex::new(Vec::new());
    let transport = Mutex::new(None);
    tokio::time::timeout(
        Duration::from_secs(10),
        manager.run(
            "terminal",
            &host.logins[0].id,
            None,
            true,
            local.clone(),
            |event| {
                match event {
                    SessionEvent::Starting { transport_id, .. } => {
                        *transport.lock().unwrap() = Some(transport_id)
                    }
                    SessionEvent::Preparation { event, .. } => {
                        if let PreparationEvent::Trust { prompt_id, .. } = *event {
                            assert_eq!(peer.authentications.load(Ordering::SeqCst), 0);
                            manager.respond(
                                "terminal",
                                transport.lock().unwrap().as_ref().unwrap(),
                                &prompt_id,
                                PreparationResponse::AcceptHostKey,
                            )?;
                        }
                    }
                    SessionEvent::Closed => {
                        let data = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
                        // The core accepts a rendered snapshot supplied by its renderer boundary.
                        manager
                            .save_output(
                                &local,
                                "terminal",
                                transport.lock().unwrap().as_ref().unwrap(),
                                1,
                                &snapshot(&data),
                            )
                            .unwrap();
                        manager.close("terminal")?;
                    }
                    _ => {}
                }
                Ok(())
            },
            |_, output| {
                bytes.lock().unwrap().extend(output);
                manager.stop("terminal")?;
                Ok(())
            },
            |_, _| {},
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(peer.authentications.load(Ordering::SeqCst), 1);
    let recents = inventory.recent_sessions().unwrap();
    assert_eq!(recents.len(), 1);
    assert!(recents[0].has_saved_output);
    let saved = inventory.saved_terminal_output(recents[0].id.clone()).unwrap();
    assert!(saved.snapshot.data.contains("actual SSH saved-output fixture"));
    drop(saved);
    drop(inventory);
    drop(local);
    drop(peer);
    let file = std::fs::read(dir.path().join("local.db")).unwrap();
    assert!(
        !file
            .windows(b"actual SSH saved-output fixture".len())
            .any(|window| window == b"actual SSH saved-output fixture")
    );
    let reopened = Arc::new(
        Store::open(&dir.path().join("local.db"), &LocalDatabaseKey::new([7; 32])).unwrap(),
    );
    let offline = Inventory::new(reopened);
    let restored = offline.saved_terminal_output(recents[0].id.clone()).unwrap();
    assert!(restored.snapshot.data.contains("actual SSH saved-output fixture"));
    assert_eq!(offline.recent_sessions().unwrap().len(), 1, "offline viewing creates no attempt");
}

#[test]
fn only_ready_sessions_receive_five_exponential_retries() {
    let mut budget = RetryBudget::default();
    assert_eq!(budget.next(), None, "initial failure must not loop");
    budget.ended(Some(Duration::ZERO));
    for delay in RETRY_DELAYS {
        assert_eq!(budget.next(), Some(delay));
        budget.ended(Some(Duration::ZERO));
    }
    assert_eq!(budget.next(), None, "brief readiness must not reset exhaustion");
    budget.ended(Some(Duration::from_secs(29)));
    assert_eq!(budget.next(), None);
    budget.ended(Some(Duration::from_secs(30)));
    assert_eq!(budget.next(), Some(1));
}

#[test]
fn only_typed_network_causes_qualify_for_automatic_reconnect() {
    use scoplen_ssh::{ProxyOperation, ProxyProtocol};
    assert!(retryable_connection(&SshConnectionError::Engine(ClientError::NetworkLost)));
    for kind in [ErrorKind::ConnectionReset, ErrorKind::ConnectionRefused, ErrorKind::TimedOut] {
        assert!(retryable_connection(&SshConnectionError::Engine(ClientError::Transport(
            std::io::Error::from(kind),
        ))));
    }
    for error in [
        SshConnectionError::InvalidPrivateKey,
        SshConnectionError::AgentCancelled,
        SshConnectionError::InvalidUsername,
        SshConnectionError::OutputTooLarge { limit: 1 },
        SshConnectionError::Engine(ClientError::Protocol),
        SshConnectionError::Engine(ClientError::Channel),
        SshConnectionError::Engine(ClientError::ConnectionClosed),
        SshConnectionError::Engine(ClientError::AuthenticationRejected {
            partial_success: false,
            remaining_methods: vec![],
        }),
        SshConnectionError::Engine(ClientError::Transport(std::io::Error::from(
            ErrorKind::InvalidData,
        ))),
    ] {
        assert!(!retryable_connection(&error), "{error}");
    }
    assert!(retryable_connection(&SshConnectionError::Engine(ClientError::Proxy(
        ProxyError::Io {
            protocol: ProxyProtocol::HttpConnect,
            operation: ProxyOperation::Read,
            kind: ErrorKind::TimedOut
        }
        .into(),
    ))));
    assert!(!retryable_connection(&SshConnectionError::Engine(ClientError::Proxy(
        ProxyError::AuthenticationRejected { protocol: ProxyProtocol::Socks5, code: 1 }.into(),
    ))));
}

#[test]
fn closing_an_unclaimed_reservation_prevents_any_attempt() {
    let manager = SessionManager::default();
    assert!(manager.reserve("", true).is_err());
    manager.reserve("logical", true).unwrap();
    assert!(manager.reserve("logical", true).is_err());
    manager.close("logical").unwrap();
    assert!(manager.sessions.lock().unwrap().is_empty());
    assert!(manager.retry("logical").is_err());
    manager.reserve("logical", true).unwrap();
}

#[test]
fn failed_send_keeps_output_and_half_close_before_confirmed_network_loss() {
    let mut terminal = false;
    let mut output = Vec::new();
    for event in [
        ChannelEvent::Data(b"before".to_vec()),
        ChannelEvent::Success,
        ChannelEvent::Eof,
        ChannelEvent::ExtendedData {
            data_type: scoplen_ssh::ExtendedDataType::Stderr,
            data: b"after".to_vec(),
        },
    ] {
        match send_failure_event(Ok(Some(event)), &mut terminal) {
            SendFailureEvent::Output(bytes) => output.extend(bytes),
            SendFailureEvent::Continue => {}
            other => panic!("must drain queued output before deciding: {other:?}"),
        }
    }
    assert_eq!(output, b"beforeafter");
    assert!(!terminal, "EOF only closes one direction");
    assert_eq!(
        send_failure_event(
            Err(SshConnectionError::Engine(ClientError::NetworkLost)),
            &mut terminal
        ),
        SendFailureEvent::NetworkLost
    );
}

#[test]
fn failed_send_keeps_terminal_priority_and_preserves_tail_output() {
    for event in [
        ChannelEvent::ExitStatus(0),
        ChannelEvent::ExitSignal {
            signal: "TERM".into(),
            core_dumped: false,
            error_message: String::new(),
            language_tag: String::new(),
        },
        ChannelEvent::OpenFailure { code: 1, reason: String::new() },
    ] {
        let mut terminal = false;
        assert_eq!(send_failure_event(Ok(Some(event)), &mut terminal), SendFailureEvent::Continue);
        assert!(terminal);
        assert_eq!(
            send_failure_event(Ok(Some(ChannelEvent::Data(b"tail".to_vec()))), &mut terminal),
            SendFailureEvent::Output(b"tail".to_vec())
        );
        assert_eq!(
            send_failure_event(
                Err(SshConnectionError::Engine(ClientError::NetworkLost)),
                &mut terminal
            ),
            SendFailureEvent::Complete
        );
        assert_eq!(send_failure_event(Ok(None), &mut terminal), SendFailureEvent::Complete);
    }
    assert_eq!(
        send_failure_event(Ok(Some(ChannelEvent::Close)), &mut false),
        SendFailureEvent::Complete
    );
}

#[test]
fn failed_send_keeps_unknown_none_and_other_errors_nonretryable() {
    for event in [
        Ok(None),
        Err(SshConnectionError::Engine(ClientError::Protocol)),
        Err(SshConnectionError::Engine(ClientError::Channel)),
        Err(SshConnectionError::OutputTooLarge { limit: 1 }),
    ] {
        assert_eq!(send_failure_event(event, &mut false), SendFailureEvent::Original);
    }
}
#[tokio::test]
async fn pending_stop_fail_and_close_win_before_automatic_or_manual_attempt_registration() {
    for previous in [Intent::None, Intent::Retry] {
        for pending in [Intent::Stop, Intent::Fail, Intent::Close] {
            let manager = Arc::new(SessionManager::default());
            manager.reserve("logical", true).unwrap();
            let mut intents = {
                let mut sessions = manager.sessions.lock().unwrap();
                let entry = sessions.get_mut("logical").unwrap();
                entry.phase =
                    if previous == Intent::Retry { Phase::Ended } else { Phase::Retrying };
                entry.receiver.take().unwrap()
            };
            if previous == Intent::Retry {
                manager.retry("logical").unwrap();
            }
            intents.borrow_and_update();
            let (reached, at_registration) = tokio::sync::oneshot::channel();
            let (resume, gate) = tokio::sync::oneshot::channel();
            let attempt = tokio::spawn({
                let manager = manager.clone();
                async move {
                    reached.send(()).unwrap();
                    gate.await.unwrap();
                    let (sender, _) = mpsc::channel(COMMAND_QUEUE);
                    let (files, _) = mpsc::channel(FILE_QUEUE);
                    manager.register_attempt(
                        "logical",
                        Uuid::now_v7(),
                        &PreparationControl::default(),
                        sender,
                        files,
                        &mut intents,
                    )
                }
            });
            at_registration.await.unwrap();
            manager.intent("logical", pending).unwrap();
            resume.send(()).unwrap();
            assert_eq!(attempt.await.unwrap().unwrap(), pending);
            let sessions = manager.sessions.lock().unwrap();
            let entry = sessions.get("logical").unwrap();
            assert!(entry.active.is_none(), "{pending:?} must prevent transport registration");
            assert_eq!(*entry.intent.borrow(), pending, "pending intent must not be cleared");
        }
    }
}

#[tokio::test]
async fn stop_before_the_reserved_owner_starts_waits_for_manual_retry_without_dialing() {
    let (_dir, store) = store();
    let manager = SessionManager::default();
    manager.reserve("logical", true).unwrap();
    manager.stop("logical").unwrap();
    let starts = AtomicUsize::new(0);
    let closed = AtomicUsize::new(0);
    manager
        .run(
            "logical",
            "invalid-profile",
            None,
            true,
            store,
            |event| {
                match event {
                    SessionEvent::Closed => {
                        assert_eq!(starts.load(Ordering::SeqCst), 0);
                        closed.fetch_add(1, Ordering::SeqCst);
                        manager.retry("logical").unwrap();
                    }
                    SessionEvent::Starting { automatic, .. } => {
                        assert!(!automatic);
                        starts.fetch_add(1, Ordering::SeqCst);
                    }
                    SessionEvent::Failed { .. } => manager.close("logical").unwrap(),
                    _ => panic!("stopped reservation must not connect automatically"),
                }
                Ok(())
            },
            |_, _| panic!("no transport"),
            |_, _| {},
        )
        .await
        .unwrap();
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(closed.load(Ordering::SeqCst), 1);
}

#[test]
fn input_is_bounded_and_old_transport_input_cannot_reach_the_replacement() {
    let manager = SessionManager::default();
    manager.reserve("logical", true).unwrap();
    let old = Uuid::now_v7();
    let (sender, mut receiver) = mpsc::channel(COMMAND_QUEUE);
    let (files, _) = mpsc::channel(FILE_QUEUE);
    manager.sessions.lock().unwrap().get_mut("logical").unwrap().active = Some(ActiveAttempt {
        id: old,
        control: PreparationControl::default(),
        sender,
        files,
        file: None,
        ready: false,
        context: None,
    });
    assert!(manager.input("logical", &old.to_string(), vec![1]).is_err());
    manager.sessions.lock().unwrap().get_mut("logical").unwrap().active.as_mut().unwrap().ready =
        true;
    manager.input("logical", &old.to_string(), vec![1]).unwrap();
    assert_eq!(receiver.try_recv(), Ok(TransportCommand::Input(vec![1])));
    assert!(manager.input("logical", &old.to_string(), vec![0; MAX_SSH_INPUT + 1]).is_err());
    for _ in 0..COMMAND_QUEUE {
        manager.input("logical", &old.to_string(), vec![1]).unwrap();
    }
    assert!(manager.input("logical", &old.to_string(), vec![1]).is_err());
    manager.phase("logical", Phase::Ended).unwrap();
    let replacement = Uuid::now_v7();
    let (sender, mut new_receiver) = mpsc::channel(COMMAND_QUEUE);
    let (files, _) = mpsc::channel(FILE_QUEUE);
    manager.sessions.lock().unwrap().get_mut("logical").unwrap().active = Some(ActiveAttempt {
        id: replacement,
        control: PreparationControl::default(),
        sender,
        files,
        file: None,
        ready: true,
        context: None,
    });
    assert!(manager.input("logical", &old.to_string(), vec![2]).is_err());
    assert!(new_receiver.try_recv().is_err());
    manager.input("logical", &replacement.to_string(), vec![3]).unwrap();
    assert_eq!(new_receiver.try_recv(), Ok(TransportCommand::Input(vec![3])));
}

#[tokio::test]
async fn failed_initial_attempt_waits_for_manual_intent_and_keeps_the_logical_id() {
    let (_dir, store) = store();
    let manager = SessionManager::default();
    manager.reserve("logical", true).unwrap();
    let starts = Mutex::new(Vec::new());
    let failures = AtomicUsize::new(0);
    manager
        .run(
            "logical",
            "invalid-profile",
            None,
            true,
            store,
            |event| {
                match event {
                    SessionEvent::Starting { transport_id, automatic } => {
                        assert!(!automatic);
                        starts.lock().unwrap().push(transport_id);
                    }
                    SessionEvent::Failed { exhausted, .. } => {
                        assert!(!exhausted);
                        if failures.fetch_add(1, Ordering::SeqCst) == 0 {
                            manager.retry("logical").unwrap();
                        } else {
                            manager.close("logical").unwrap();
                        }
                    }
                    _ => panic!("invalid initial attempt must not reconnect automatically"),
                }
                Ok(())
            },
            |_, _| panic!("no transport"),
            |_, _| {},
        )
        .await
        .unwrap();
    let starts = starts.lock().unwrap();
    assert_eq!(starts.len(), 2);
    assert_ne!(starts[0], starts[1]);
    assert!(manager.sessions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn repeated_stop_and_fail_keep_the_ended_session_available_for_manual_retry() {
    let (_dir, store) = store();
    let manager = SessionManager::default();
    manager.reserve("logical", true).unwrap();
    let starts = AtomicUsize::new(0);
    let failures = AtomicUsize::new(0);
    let closed = AtomicUsize::new(0);
    manager
        .run(
            "logical",
            "invalid-profile",
            None,
            true,
            store,
            |event| {
                match event {
                    SessionEvent::Starting { automatic, .. } => {
                        assert!(!automatic);
                        starts.fetch_add(1, Ordering::SeqCst);
                    }
                    SessionEvent::Failed { .. } => match failures.fetch_add(1, Ordering::SeqCst) {
                        0 => manager.fail("logical").unwrap(),
                        1 => manager.stop("logical").unwrap(),
                        2 => manager.close("logical").unwrap(),
                        _ => panic!("only the explicit manual intent may start a new attempt"),
                    },
                    SessionEvent::Closed => {
                        closed.fetch_add(1, Ordering::SeqCst);
                        manager.retry("logical").unwrap();
                    }
                    _ => panic!("no automatic or network activity expected"),
                }
                Ok(())
            },
            |_, _| panic!("invalid profile has no transport"),
            |_, _| {},
        )
        .await
        .unwrap();
    assert_eq!(starts.load(Ordering::SeqCst), 2);
    assert_eq!(failures.load(Ordering::SeqCst), 3);
    assert_eq!(closed.load(Ordering::SeqCst), 1);
    assert!(manager.sessions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn stop_during_initial_preparation_keeps_manual_retry_and_closes_each_recent() {
    let (_dir, store) = store();
    let inventory = Inventory::new(store.clone());
    let host = inventory
        .add_host(NewHost {
            name: None,
            address: "127.0.0.1".into(),
            port: Some(1),
            username: "fixture".into(),
            sign_in: SignIn::Password { password: "fixture-password".into() },
        })
        .unwrap();
    let manager = SessionManager::default();
    manager.reserve("logical", true).unwrap();
    let attempts = AtomicUsize::new(0);
    manager
        .run(
            "logical",
            &host.logins[0].id,
            None,
            true,
            store.clone(),
            |event| {
                match event {
                    SessionEvent::Preparation { .. } => {
                        if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                            manager.stop("logical").unwrap();
                        } else {
                            manager.close("logical").unwrap();
                        }
                    }
                    SessionEvent::Closed => manager.retry("logical").unwrap(),
                    SessionEvent::Starting { .. } => {}
                    _ => panic!("cancelled preparation must not dial or fail"),
                }
                Ok(())
            },
            |_, _| panic!("cancelled before network"),
            |_, _| {},
        )
        .await
        .unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    let recents = store.recent_sessions(10).unwrap();
    assert_eq!(recents.len(), 2);
    assert!(recents.iter().all(|entry| entry.ended_at.is_some()));
}

#[tokio::test]
async fn aborting_the_owner_removes_its_session_and_closes_pending_prompts() {
    let (_dir, store) = store();
    let manager = Arc::new(SessionManager::default());
    manager.reserve("logical", true).unwrap();
    let (failed, received) = tokio::sync::oneshot::channel();
    let failed = Mutex::new(Some(failed));
    let task = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .run(
                    "logical",
                    "invalid",
                    None,
                    true,
                    store,
                    |event| {
                        if matches!(event, SessionEvent::Failed { .. }) {
                            let _ = failed.lock().unwrap().take().unwrap().send(());
                        }
                        Ok(())
                    },
                    |_, _| Ok(()),
                    |_, _| {},
                )
                .await
        }
    });
    received.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(manager.sessions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn exec_mode_finishes_after_one_attempt_without_automatic_or_manual_wait() {
    let (_dir, store) = store();
    let manager = SessionManager::default();
    manager.reserve("exec", false).unwrap();
    let failures = AtomicUsize::new(0);
    let result = manager
        .run(
            "exec",
            "invalid",
            Some("true"),
            false,
            store,
            |event| {
                if let SessionEvent::Failed { exhausted, .. } = event {
                    assert!(!exhausted);
                    failures.fetch_add(1, Ordering::SeqCst);
                }
                Ok(())
            },
            |_, _| Ok(()),
            |_, _| {},
        )
        .await;
    assert!(result.is_err());
    assert_eq!(failures.load(Ordering::SeqCst), 1);
    assert!(manager.sessions.lock().unwrap().is_empty());
}
