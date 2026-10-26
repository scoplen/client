// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::connection::preparation::PreparationContext;
use crate::session_transfers::SessionTransferReview;

fn ready_manager() -> (SessionManager, Uuid, mpsc::Receiver<FileCommand>) {
    let manager = SessionManager::default();
    manager.reserve("terminal", true).unwrap();
    let transport = Uuid::now_v7();
    let (sender, _) = mpsc::channel(COMMAND_QUEUE);
    let (files, requests) = mpsc::channel(FILE_QUEUE);
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
        context: Some(PreparationContext {
            profile_id: Uuid::now_v7().to_string(),
            host_id: Uuid::now_v7().to_string(),
            login: "Saved login".into(),
            host: "Saved host".into(),
            username: "deploy".into(),
            address: "fixture.example".into(),
            port: 22,
            position: 1,
            total: 1,
            target: true,
        }),
    });
    drop(sessions);
    (manager, transport, requests)
}

async fn request(requests: &mut mpsc::Receiver<FileCommand>) -> FileCommand {
    tokio::time::timeout(Duration::from_secs(3), requests.recv()).await.unwrap().unwrap()
}

async fn editor_where(
    manager: &SessionManager,
    expected: impl Fn(&SessionEditorSnapshot) -> bool,
) -> SessionEditorSnapshot {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = manager.editor_snapshot("terminal").unwrap().unwrap();
            let id = Uuid::parse_str(&snapshot.editor_id).unwrap();
            manager.observe_editor("terminal", id).await;
            let snapshot = manager.editor_snapshot("terminal").unwrap().unwrap();
            if expected(&snapshot) {
                return snapshot;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("editor did not reach its expected state")
}

async fn saved_editor(
    manager: &SessionManager,
    transport: Uuid,
    requests: &mut mpsc::Receiver<FileCommand>,
    path: PathBuf,
    launches: Arc<AtomicUsize>,
) -> String {
    let expected = path.clone();
    let result = manager
        .edit_file_with_picker(
            "terminal",
            &transport.to_string(),
            b"./original/config.txt".to_vec(),
            move || async move { Ok(Some(path)) },
            |_| async { panic!("new local copy needs no replacement") },
            move |path| {
                assert_eq!(path, expected);
                let launches = launches.clone();
                async move {
                    launches.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
    let SessionEditorStartResult::Started { editor_id } = result else { panic!() };
    let FileCommand::TransferDownload {
        input: DownloadInput::New { remote_path, destination, text_only },
        reply,
        ..
    } = request(requests).await
    else {
        panic!("expected editor download")
    };
    assert_eq!(remote_path, b"./original/config.txt");
    assert!(text_only);
    tokio::fs::write(destination.path(), b"original text\n").await.unwrap();
    reply
        .send(Ok(DownloadExecution::Published {
            result: SessionDownloadResult::new(SessionDownloadStatus::Saved, None),
            staging_may_remain: false,
        }))
        .ok();
    editor_where(manager, |snapshot| snapshot.state == State::Watching).await;
    editor_id
}

#[tokio::test]
async fn atomic_editor_save_only_marks_changes_and_explicit_upload_keeps_original_target() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("different-local-name.txt");
    let (manager, transport, mut requests) = ready_manager();
    let launches = Arc::new(AtomicUsize::new(0));
    let id = saved_editor(&manager, transport, &mut requests, path.clone(), launches.clone()).await;
    let snapshot = manager.editor_snapshot("terminal").unwrap().unwrap();
    assert_eq!(snapshot.remote_name, "./original/config.txt");
    assert_eq!(snapshot.local_name.as_deref(), Some("different-local-name.txt"));
    assert!(snapshot.can_open);
    let replacement = directory.path().join("editor-save.txt");
    tokio::fs::write(&replacement, b"a new complete editor save\n").await.unwrap();
    tokio::fs::rename(replacement, &path).await.unwrap();
    editor_where(&manager, |snapshot| snapshot.state == State::ChangesDetected).await;
    assert!(requests.try_recv().is_err());
    assert_eq!(launches.load(Ordering::SeqCst), 1);
    manager
        .upload_editor(
            "terminal",
            &transport.to_string(),
            &id,
            |review: SessionTransferReview| async move {
                assert_eq!(review.name, "config.txt");
                Ok(true)
            },
        )
        .await
        .unwrap();
    let FileCommand::PreflightUpload { target, reply } = request(&mut requests).await else {
        panic!()
    };
    assert_eq!(target, b"./original/config.txt");
    reply
        .send(Ok(UploadPreflight {
            target_attributes: Some(scoplen_ssh::SftpAttributes {
                permissions: Some(0o100600),
                ..Default::default()
            }),
            replacement_supported: true,
        }))
        .ok();
    let FileCommand::TransferUpload {
        input: UploadInput::New { source, directory, target, .. },
        reply,
        ..
    } = request(&mut requests).await
    else {
        panic!()
    };
    assert_eq!(source.size(), 27);
    assert_eq!(directory, b"./original");
    assert_eq!(target, b"./original/config.txt");
    reply.send(UploadExecution::Published).ok();
    editor_where(&manager, |snapshot| snapshot.state == State::Uploaded).await;
    manager.stop_editor("terminal", &id).unwrap();
    assert!(manager.editor_snapshot("terminal").unwrap().is_none());
    assert_eq!(tokio::fs::read(path).await.unwrap(), b"a new complete editor save\n");
}

#[tokio::test]
async fn local_refusals_persist_without_deleting_the_working_copy_or_dispatching_uploads() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("working.txt");
    let (manager, transport, mut requests) = ready_manager();
    let id = saved_editor(
        &manager,
        transport,
        &mut requests,
        path.clone(),
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    for (bytes, issue) in [(vec![0], Issue::NotText), (vec![b'a'; 262_145], Issue::TooLarge)] {
        tokio::fs::write(&path, &bytes).await.unwrap();
        assert_eq!(
            manager
                .upload_editor("terminal", &transport.to_string(), &id, |_| async { Ok(true) })
                .await,
            Err(issue)
        );
        manager.observe_editor("terminal", Uuid::parse_str(&id).unwrap()).await;
        assert_eq!(manager.editor_snapshot("terminal").unwrap().unwrap().issue, Some(issue));
        assert_eq!(tokio::fs::read(&path).await.unwrap(), bytes);
        assert!(requests.try_recv().is_err());
    }
    manager.stop_editor("terminal", &id).unwrap();
}

#[tokio::test]
async fn native_selection_cancellation_releases_the_single_copy_and_queue_capacity() {
    let (manager, transport, _) = ready_manager();
    assert_eq!(
        manager
            .edit_file_with_picker(
                "terminal",
                &transport.to_string(),
                b"./file.txt".to_vec(),
                || async { Ok(None) },
                |_| async { Ok(true) },
                |_| async { panic!("cancelled selection cannot launch") },
            )
            .await
            .unwrap(),
        SessionEditorStartResult::Cancelled
    );
    assert!(manager.editor_snapshot("terminal").unwrap().is_none());
    let queue = manager.transfer_queue_snapshot("terminal").unwrap();
    assert_eq!(queue.outstanding, 0);
    assert!(!queue.picker_busy);
}

#[tokio::test]
async fn a_second_editor_and_foreign_ids_cannot_replace_the_existing_copy() {
    let directory = tempfile::tempdir().unwrap();
    let (manager, transport, mut requests) = ready_manager();
    let id = saved_editor(
        &manager,
        transport,
        &mut requests,
        directory.path().join("copy.txt"),
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    assert_eq!(
        manager
            .edit_file_with_picker(
                "terminal",
                &transport.to_string(),
                b"./other.txt".to_vec(),
                || async { panic!("second editor cannot open a picker") },
                |_| async { Ok(true) },
                |_| async { Ok(()) },
            )
            .await,
        Err(Issue::AlreadyEditing)
    );
    assert_eq!(
        manager.stop_editor("terminal", &Uuid::now_v7().to_string()),
        Err(Issue::Unavailable)
    );
    assert_eq!(manager.editor_snapshot("terminal").unwrap().unwrap().editor_id, id);
    manager.stop_editor("terminal", &id).unwrap();
}

#[tokio::test]
async fn transport_end_preserves_original_identity_and_local_copy_without_upload_authority() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("copy.txt");
    let (manager, transport, mut requests) = ready_manager();
    let id = saved_editor(
        &manager,
        transport,
        &mut requests,
        path.clone(),
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    {
        let mut sessions = manager.sessions.lock().unwrap();
        let entry = sessions.get_mut("terminal").unwrap();
        interrupt_transfers(entry, transport);
        entry.active.as_mut().unwrap().id = Uuid::now_v7();
    }
    let snapshot = manager.editor_snapshot("terminal").unwrap().unwrap();
    assert_eq!(snapshot.transport_id, transport.to_string());
    assert_eq!(snapshot.state, State::Unavailable);
    assert_eq!(
        manager
            .upload_editor("terminal", &transport.to_string(), &id, |_| async { panic!() })
            .await,
        Err(Issue::Unavailable)
    );
    manager.stop_editor("terminal", &id).unwrap();
    assert!(path.exists());
    assert!(requests.try_recv().is_err());
}

#[tokio::test]
async fn editor_launch_failure_keeps_the_saved_copy_for_an_explicit_retry() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("copy.txt");
    let (manager, transport, mut requests) = ready_manager();
    let attempts = Arc::new(AtomicUsize::new(0));
    let current = attempts.clone();
    let selected = path.clone();
    let result = manager
        .edit_file_with_picker(
            "terminal",
            &transport.to_string(),
            b"./file.txt".to_vec(),
            move || async { Ok(Some(selected)) },
            |_| async { Ok(true) },
            move |_| {
                let attempts = current.clone();
                async move {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(Issue::EditorLaunchFailed)
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .await
        .unwrap();
    let SessionEditorStartResult::Started { editor_id } = result else { panic!() };
    let FileCommand::TransferDownload { reply, .. } = request(&mut requests).await else {
        panic!()
    };
    tokio::fs::write(&path, b"saved text").await.unwrap();
    reply
        .send(Ok(DownloadExecution::Published {
            result: SessionDownloadResult::new(SessionDownloadStatus::Saved, None),
            staging_may_remain: false,
        }))
        .ok();
    editor_where(&manager, |snapshot| snapshot.issue == Some(Issue::EditorLaunchFailed)).await;
    assert!(path.exists());
    manager.open_editor("terminal", &editor_id).await.unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(manager.editor_snapshot("terminal").unwrap().unwrap().state, State::Watching);
    manager.stop_editor("terminal", &editor_id).unwrap();
}

#[tokio::test]
async fn unknown_upload_waits_for_existing_queue_acknowledgement_and_never_replays() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("copy.txt");
    let (manager, transport, mut requests) = ready_manager();
    let id = saved_editor(
        &manager,
        transport,
        &mut requests,
        path.clone(),
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    manager
        .upload_editor("terminal", &transport.to_string(), &id, |_| async { Ok(true) })
        .await
        .unwrap();
    let FileCommand::PreflightUpload { reply, .. } = request(&mut requests).await else { panic!() };
    reply.send(Ok(UploadPreflight { target_attributes: None, replacement_supported: true })).ok();
    let FileCommand::TransferUpload { reply, .. } = request(&mut requests).await else { panic!() };
    reply
        .send(UploadExecution::Failed {
            error: FileAccessError::PublicationUnknown,
            staging_may_remain: true,
        })
        .ok();
    let snapshot = editor_where(&manager, |snapshot| snapshot.state == State::Unknown).await;
    assert!(!snapshot.can_open);
    assert_eq!(
        manager
            .upload_editor("terminal", &transport.to_string(), &id, |_| async { panic!() })
            .await,
        Err(Issue::PublicationUnknown)
    );
    let transfer = snapshot.transfer.unwrap();
    manager
        .acknowledge_transfer(
            "terminal",
            &transfer.queue_id,
            &transfer.item_id,
            &transfer.execution_id,
        )
        .unwrap();
    editor_where(&manager, |snapshot| snapshot.state == State::ChangesDetected).await;
    assert!(requests.try_recv().is_err());
    manager.stop_editor("terminal", &id).unwrap();
    assert!(path.exists());
}

#[tokio::test]
async fn stopping_while_launch_is_pending_preserves_the_copy_and_discards_the_late_result() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("copy.txt");
    let (manager, transport, mut requests) = ready_manager();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let signal = started.clone();
    let wait = release.clone();
    let selected = path.clone();
    let result = manager
        .edit_file_with_picker(
            "terminal",
            &transport.to_string(),
            b"./file.txt".to_vec(),
            move || async { Ok(Some(selected)) },
            |_| async { Ok(true) },
            move |_| {
                let signal = signal.clone();
                let wait = wait.clone();
                async move {
                    signal.notify_one();
                    wait.notified().await;
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
    let SessionEditorStartResult::Started { editor_id } = result else { panic!() };
    let FileCommand::TransferDownload { reply, .. } = request(&mut requests).await else {
        panic!()
    };
    tokio::fs::write(&path, b"retained local copy").await.unwrap();
    reply
        .send(Ok(DownloadExecution::Published {
            result: SessionDownloadResult::new(SessionDownloadStatus::Saved, None),
            staging_may_remain: false,
        }))
        .ok();
    tokio::time::timeout(Duration::from_secs(3), started.notified()).await.unwrap();
    manager.stop_editor("terminal", &editor_id).unwrap();
    release.notify_one();
    tokio::task::yield_now().await;
    assert!(manager.editor_snapshot("terminal").unwrap().is_none());
    assert_eq!(tokio::fs::read(path).await.unwrap(), b"retained local copy");
}
