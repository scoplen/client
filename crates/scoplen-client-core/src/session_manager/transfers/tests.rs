// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicBool, AtomicUsize};

use super::*;

fn ready_manager() -> (SessionManager, Uuid, mpsc::Receiver<FileCommand>) {
    let manager = SessionManager::default();
    manager.reserve("terminal", true).unwrap();
    let transport = Uuid::now_v7();
    let (sender, _commands) = mpsc::channel(COMMAND_QUEUE);
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
            login: "Production login".into(),
            host: "Bound target".into(),
            username: "deploy".into(),
            address: "fixture.example".into(),
            port: 2222,
            position: 1,
            total: 1,
            target: true,
        }),
    });
    drop(sessions);
    (manager, transport, requests)
}

async fn snapshot_where(
    manager: &SessionManager,
    expected: impl Fn(&SessionTransferQueueSnapshot) -> bool,
) -> SessionTransferQueueSnapshot {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = manager.transfer_queue_snapshot("terminal").unwrap();
            if expected(&snapshot) {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("queue did not reach the expected state")
}

async fn enqueue_upload(
    manager: &SessionManager,
    transport: Uuid,
    path: PathBuf,
) -> SessionTransferEnqueueResult {
    manager
        .enqueue_upload_with_picker(
            "terminal",
            &transport.to_string(),
            b".".to_vec(),
            move || async move { Ok(Some(path)) },
            |_| async { panic!("unexpected replacement confirmation") },
        )
        .await
        .unwrap()
}

fn enqueue_ids(result: &SessionTransferEnqueueResult) -> (&str, &str, &str) {
    match result {
        SessionTransferEnqueueResult::Queued { queue_id, item_id, execution_id } => {
            (queue_id, item_id, execution_id)
        }
        SessionTransferEnqueueResult::Cancelled => panic!("expected a queued file"),
    }
}

async fn next_upload(
    requests: &mut mpsc::Receiver<FileCommand>,
    expected: &[u8],
) -> (oneshot::Sender<UploadExecution>, Arc<UploadState>, Uuid) {
    let FileCommand::PreflightUpload { target, reply } = next_request(requests).await else {
        panic!("expected upload preflight");
    };
    assert_eq!(target, expected);
    reply.send(Ok(UploadPreflight { target_attributes: None, replacement_supported: true })).ok();
    let FileCommand::TransferUpload {
        input: UploadInput::New { target, .. },
        reply,
        state,
        operation,
        ..
    } = next_request(requests).await
    else {
        panic!("expected the selected upload");
    };
    assert_eq!(target, expected);
    (reply, state, operation)
}

async fn next_request(requests: &mut mpsc::Receiver<FileCommand>) -> FileCommand {
    tokio::time::timeout(Duration::from_secs(3), requests.recv())
        .await
        .expect("queued file operation did not dispatch")
        .expect("file worker closed")
}

async fn drive_upload(
    manager: &SessionManager,
    peer: &crate::session_files::uploads::tests::Peer,
    request: FileCommand,
    pause: bool,
) {
    let FileCommand::TransferUpload {
        input,
        control,
        state,
        session_id,
        transport,
        operation,
        reply,
    } = request
    else {
        panic!("expected a queued upload")
    };
    let mut requested = false;
    let result = session_files::transfer_upload(
        &peer.connection,
        input,
        control,
        state,
        |update| {
            SessionManager::report_file_progress(
                &manager.sessions,
                &session_id,
                transport,
                operation,
                &mut |_| {},
                update,
            );
            if pause && !requested {
                let snapshot = manager.transfer_queue_snapshot(&session_id).unwrap();
                let row = snapshot
                    .items
                    .iter()
                    .find(|row| row.execution_id == operation.to_string())
                    .unwrap();
                manager
                    .pause_transfer(
                        &session_id,
                        &snapshot.queue_id,
                        &row.item_id,
                        &row.execution_id,
                    )
                    .unwrap();
                requested = true;
            }
        },
        || {
            SessionManager::report_upload_pause(
                &manager.sessions,
                &session_id,
                transport,
                operation,
            )
        },
        || {
            SessionManager::authorize_remote_effect(
                &manager.sessions,
                &session_id,
                transport,
                operation,
            )
        },
    )
    .await;
    manager.finish_remote_effect(&session_id, transport, operation);
    reply.send(result).ok();
}

#[tokio::test]
async fn public_upload_queue_releases_paused_execution_and_resumes_real_original_handle() {
    use crate::session_files::uploads::tests::{Peer, source};
    let peer = Peer::start().await;
    let (manager, transport, mut requests) = ready_manager();
    let folder = tempfile::tempdir().unwrap();
    let (path, bytes) = source(folder.path());
    let queued = enqueue_upload(&manager, transport, path).await;
    let (queue, item, execution) = enqueue_ids(&queued);
    let FileCommand::PreflightUpload { target, reply } = next_request(&mut requests).await else {
        panic!()
    };
    reply
        .send(
            session_files::preflight_upload(&peer.connection, &target)
                .await
                .map_err(|error| error.to_string()),
        )
        .ok();
    let request = next_request(&mut requests).await;
    drive_upload(&manager, &peer, request, true).await;
    let snapshot = snapshot_where(&manager, |snapshot| {
        snapshot.items[0].state == SessionTransferState::Paused
    })
    .await;
    let offset = snapshot.items[0].transferred_bytes.parse::<u64>().unwrap();
    assert!(offset > 0 && offset < bytes.len() as u64);
    assert_eq!(snapshot.outstanding, 1);
    assert!(!snapshot.blocks_file_operations);
    let follower = folder.path().join("later.bin");
    std::fs::write(&follower, b"later queued selection").unwrap();
    enqueue_upload(&manager, transport, follower).await;
    let (reply, _, operation) = next_upload(&mut requests, b"./later.bin").await;
    manager.resume_transfer("terminal", queue, item, execution).unwrap();
    assert!(manager.cancel_transfer("terminal", queue, item, execution).is_err());
    saved(&manager, transport, operation, reply);
    let request = next_request(&mut requests).await;
    let FileCommand::TransferUpload { operation, .. } = &request else { panic!() };
    assert_ne!(operation.to_string(), execution);
    let writes = peer.write_offsets().len();
    drive_upload(&manager, &peer, request, false).await;
    let snapshot = snapshot_where(&manager, |snapshot| snapshot.recent.len() == 2).await;
    assert!(snapshot.items.is_empty());
    assert_eq!(snapshot.recent[1].item_id, item);
    assert_eq!(snapshot.recent[1].state, SessionTransferState::Saved);
    assert_eq!(snapshot.recent[1].transferred_bytes, bytes.len().to_string());
    assert_eq!(peer.write_offsets()[writes], offset);
}

#[tokio::test]
async fn upload_resume_dispatch_loss_settles_the_checkpoint_before_finishing() {
    use crate::session_files::uploads::tests::{Peer, source};
    let peer = Peer::start().await;
    let (manager, transport, requests) = ready_manager();
    let folder = tempfile::tempdir().unwrap();
    let (path, _) = source(folder.path());
    let checkpoint = peer.paused(&path).await;
    let operation = Uuid::now_v7();
    let identity = TransferIdentity { item: Uuid::now_v7(), execution: operation, transport };
    let (abort, _) = AbortHandle::new_pair();
    let guard = manager
        .reserve_file_operation("terminal", &transport.to_string(), &operation.to_string(), abort)
        .unwrap();
    {
        let mut sessions = manager.sessions.lock().unwrap();
        sessions
            .get_mut("terminal")
            .unwrap()
            .active
            .as_mut()
            .unwrap()
            .file
            .as_mut()
            .unwrap()
            .transfer = Some(identity);
    }
    drop(requests);
    let TransferExecutionResult::Finished(result) = manager
        .execute_upload_transfer("terminal", identity, guard, UploadInput::Resume(checkpoint))
        .await
    else {
        panic!()
    };
    assert!(!result.staging_may_remain);
    assert!(matches!(
        result.state,
        SessionTransferState::Interrupted | SessionTransferState::Cancelled
    ));
}

#[tokio::test]
async fn accepted_upload_resume_dropped_before_poll_reports_unconfirmed_remote_staging() {
    use crate::session_files::uploads::tests::{Peer, source};
    let peer = Peer::start().await;
    let (manager, transport, mut requests) = ready_manager();
    let folder = tempfile::tempdir().unwrap();
    let (path, bytes) = source(folder.path());
    let queued = enqueue_upload(&manager, transport, path).await;
    let (queue, item, execution) = enqueue_ids(&queued);
    let FileCommand::PreflightUpload { target, reply } = next_request(&mut requests).await else {
        panic!()
    };
    reply
        .send(
            session_files::preflight_upload(&peer.connection, &target)
                .await
                .map_err(|error| error.to_string()),
        )
        .ok();
    let request = next_request(&mut requests).await;
    drive_upload(&manager, &peer, request, true).await;
    snapshot_where(&manager, |snapshot| snapshot.items[0].state == SessionTransferState::Paused)
        .await;
    manager.resume_transfer("terminal", queue, item, execution).unwrap();
    let request = next_request(&mut requests).await;
    let FileCommand::TransferUpload { input: UploadInput::Resume(_), state, .. } = &request else {
        panic!()
    };
    assert!(state.staging_may_remain.load(Ordering::SeqCst));
    let writes = peer.write_offsets().len();
    manager.expire_ready_transport("terminal", transport).unwrap();
    drop(request);
    drop(requests);
    let snapshot = snapshot_where(&manager, |snapshot| snapshot.recent.len() == 1).await;
    assert_eq!(snapshot.recent[0].state, SessionTransferState::Interrupted);
    assert!(snapshot.recent[0].staging_may_remain);
    assert_eq!(snapshot.recent[0].item_id, item);
    assert!(snapshot.recent[0].transferred_bytes.parse::<usize>().unwrap() < bytes.len());
    assert!(peer.staging_exists());
    assert_eq!(peer.write_offsets().len(), writes);
}

#[tokio::test]
async fn paused_upload_cancel_disconnect_and_close_settle_owned_resources() {
    use crate::session_files::uploads::tests::{Peer, source};
    for scenario in 0..4 {
        let peer = Peer::start().await;
        let (manager, transport, _requests) = ready_manager();
        let folder = tempfile::tempdir().unwrap();
        let (path, bytes) = source(folder.path());
        let checkpoint = peer.paused(&path).await;
        let (queue, identity) = {
            let mut sessions = manager.sessions.lock().unwrap();
            let entry = sessions.get_mut("terminal").unwrap();
            let selection = entry.transfers.reserve_selection(transport).unwrap();
            entry
                .transfers
                .enqueue_selected(
                    selection,
                    "source.bin",
                    SessionTransferDirection::Upload,
                    Some(bytes.len() as u64),
                    SelectedTransfer::ResumeUpload(checkpoint),
                )
                .unwrap();
            let selected = entry.transfers.take_next(transport).unwrap();
            entry.transfers.admit_upload_pause(selected.identity);
            entry.transfers.progress(
                selected.identity,
                FileTransferProgress {
                    transferred: 1024 * 1024,
                    total: Some(bytes.len() as u64),
                    phase: SessionFileTransferPhase::Transferring,
                },
            );
            entry
                .transfers
                .pause(entry.transfers.id(), selected.identity.item, selected.identity.execution)
                .unwrap();
            assert!(entry.transfers.retain_paused(selected.identity, selected.resources).is_ok());
            (entry.transfers.id(), selected.identity)
        };
        match scenario {
            1 => manager.expire_ready_transport("terminal", transport).unwrap(),
            2 => manager.close("terminal").unwrap(),
            _ => {
                if scenario == 3 {
                    peer.refuse_cleanup();
                }
                manager
                    .cancel_transfer(
                        "terminal",
                        &queue.to_string(),
                        &identity.item.to_string(),
                        &identity.execution.to_string(),
                    )
                    .unwrap();
            }
        }
        if scenario == 2 {
            tokio::time::timeout(Duration::from_secs(3), async {
                while manager.transfer_queue_snapshot("terminal")
                    != Err(SessionTransferIssue::SessionUnavailable)
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        } else {
            let snapshot = snapshot_where(&manager, |snapshot| snapshot.recent.len() == 1).await;
            assert_eq!(snapshot.outstanding, 0);
            assert_eq!(
                snapshot.recent[0].state,
                if scenario == 1 {
                    SessionTransferState::Interrupted
                } else {
                    SessionTransferState::Cancelled
                }
            );
            assert_eq!(snapshot.recent[0].staging_may_remain, scenario == 3);
            if scenario == 3 {
                assert_eq!(snapshot.recent[0].issue, Some(SessionTransferIssue::CleanupIncomplete));
            }
            assert!(
                manager
                    .resume_transfer(
                        "terminal",
                        &queue.to_string(),
                        &identity.item.to_string(),
                        &identity.execution.to_string()
                    )
                    .is_err()
            );
        }
        assert_eq!(peer.staging_exists(), scenario == 3);
    }
}

#[tokio::test]
async fn close_during_partial_creation_retains_capacity_until_the_owned_cleanup_finishes() {
    use crate::session_files::downloads::tests::{Peer, blocked_creation};

    let peer = Peer::start().await;
    let (manager, transport, mut requests) = ready_manager();
    let folder = tempfile::tempdir().unwrap();
    let destination = folder.path().join("saved.bin");
    let selected = destination.clone();
    manager
        .enqueue_download_with_picker(
            "terminal",
            &transport.to_string(),
            b"./source.bin".to_vec(),
            move || async move { Ok(Some(selected)) },
            |_| async { Ok(true) },
        )
        .await
        .unwrap();
    let FileCommand::TransferDownload { input, control, operation, reply, .. } =
        next_request(&mut requests).await
    else {
        panic!()
    };
    let prepared = peer.prepare(input).await;
    let (started, created) = oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let owner = tokio::spawn(complete_owned_download(
        manager.sessions.clone(),
        "terminal".into(),
        transport,
        operation,
        reply,
        blocked_creation(prepared, control, started, blocked),
    ));
    let partial = created.await.unwrap();
    assert!(partial.exists());
    drop(requests);
    manager.close("terminal").unwrap();
    drop(Registration { manager: &manager, id: "terminal" });
    let snapshot = manager.transfer_queue_snapshot("terminal").unwrap();
    assert_eq!(snapshot.outstanding, 1);
    assert_eq!(snapshot.items[0].state, SessionTransferState::Cancelling);
    assert!(partial.exists());
    assert!(!owner.is_finished());
    release.send(()).unwrap();
    owner.await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while manager.transfer_queue_snapshot("terminal")
            != Err(SessionTransferIssue::SessionUnavailable)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!partial.exists());
    assert!(!destination.exists());
}

#[tokio::test]
async fn resume_dispatch_failure_settles_the_retained_partial_including_identity_conflicts() {
    use crate::session_files::downloads::tests::Peer;
    let peer = Peer::start().await;
    for scenario in 0..4 {
        let (manager, transport, requests) = ready_manager();
        let folder = tempfile::tempdir().unwrap();
        let destination = folder.path().join("saved.bin");
        let checkpoint = peer.paused(destination.clone()).await;
        let partial = checkpoint.test_partial_path().to_path_buf();
        let operation = Uuid::now_v7();
        let identity = TransferIdentity { item: Uuid::now_v7(), execution: operation, transport };
        let (abort, _) = AbortHandle::new_pair();
        let guard = manager
            .reserve_file_operation(
                "terminal",
                &transport.to_string(),
                &operation.to_string(),
                abort.clone(),
            )
            .unwrap();
        let (queue, context) = {
            let mut sessions = manager.sessions.lock().unwrap();
            let entry = sessions.get_mut("terminal").unwrap();
            let active = entry.active.as_mut().unwrap();
            active.file.as_mut().unwrap().transfer = Some(identity);
            if scenario == 0 || scenario == 3 {
                active.ready = false;
            }
            (entry.transfers.id(), active.context.clone().unwrap())
        };
        if scenario == 1 {
            abort.abort();
        }
        if scenario == 3 {
            std::fs::rename(&partial, folder.path().join("old-partial")).unwrap();
            std::fs::write(&partial, b"replacement must survive").unwrap();
        }
        drop(requests);
        let result = manager
            .execute_download_transfer(
                "terminal",
                queue,
                identity,
                &context,
                guard,
                None,
                Some(checkpoint),
            )
            .await;
        let TransferExecutionResult::Finished(result) = result else {
            panic!("failed dispatch cannot pause")
        };
        assert_eq!(
            result.state,
            if scenario == 1 {
                SessionTransferState::Cancelled
            } else {
                SessionTransferState::Interrupted
            }
        );
        assert_eq!(result.staging_may_remain, scenario == 3);
        if scenario == 3 {
            assert_eq!(std::fs::read(&partial).unwrap(), b"replacement must survive");
        } else {
            assert!(!partial.exists());
        }
        assert!(!destination.exists());
    }
}

#[tokio::test]
async fn finalization_cleanup_uncertainty_survives_the_published_result_projection() {
    let (manager, transport, mut requests) = ready_manager();
    let folder = tempfile::tempdir().unwrap();
    let chosen = folder.path().join("saved.bin");
    manager
        .enqueue_download_with_picker(
            "terminal",
            &transport.to_string(),
            b"./source.bin".to_vec(),
            move || async move { Ok(Some(chosen)) },
            |_| async { Ok(true) },
        )
        .await
        .unwrap();
    let FileCommand::TransferDownload { reply, .. } = next_request(&mut requests).await else {
        panic!()
    };
    reply
        .send(Ok(DownloadExecution::Published {
            result: SessionDownloadResult::new(SessionDownloadStatus::Conflict, None),
            staging_may_remain: true,
        }))
        .ok();
    let snapshot = snapshot_where(&manager, |snapshot| snapshot.recent.len() == 1).await;
    assert_eq!(snapshot.recent[0].state, SessionTransferState::Conflict);
    assert!(snapshot.recent[0].staging_may_remain);
}

#[tokio::test]
async fn a_late_pause_result_after_close_settles_cleanup_and_releases_the_closed_owner() {
    use crate::session_files::downloads::tests::Peer;
    let peer = Peer::start().await;
    let (manager, transport, _requests) = ready_manager();
    let folder = tempfile::tempdir().unwrap();
    let checkpoint = peer.paused(folder.path().join("saved.bin")).await;
    let partial = checkpoint.test_partial_path().to_path_buf();
    let (queue, selected) = {
        let mut sessions = manager.sessions.lock().unwrap();
        let entry = sessions.get_mut("terminal").unwrap();
        let selection = entry.transfers.reserve_selection(transport).unwrap();
        entry
            .transfers
            .enqueue_selected(
                selection,
                "source.bin",
                SessionTransferDirection::Download,
                Some(3 * 1024 * 1024 + 17),
                SelectedTransfer::ResumeDownload(checkpoint),
            )
            .unwrap();
        let selected = entry.transfers.take_next(transport).unwrap();
        entry
            .transfers
            .pause(entry.transfers.id(), selected.identity.item, selected.identity.execution)
            .unwrap();
        entry.transfers.interrupt_transport(transport);
        entry.intent.send_replace(Intent::Close);
        entry.active = None;
        (entry.transfers.id(), selected)
    };
    assert!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding > 0);
    manager
        .settle_rejected_checkpoint("terminal", queue, selected.identity, selected.resources)
        .await;
    assert!(!partial.exists());
    assert_eq!(
        manager.transfer_queue_snapshot("terminal"),
        Err(SessionTransferIssue::SessionUnavailable)
    );
}

fn saved(
    manager: &SessionManager,
    transport: Uuid,
    operation: Uuid,
    reply: oneshot::Sender<UploadExecution>,
) {
    manager.finish_remote_effect("terminal", transport, operation);
    reply.send(UploadExecution::Published).ok();
}

#[tokio::test]
async fn dropping_the_enqueue_waiter_does_not_drop_the_picker_or_selected_transfer() {
    let (manager, transport, mut requests) = ready_manager();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("detached.bin");
    std::fs::write(&path, b"selected bytes").unwrap();
    let (opened, did_open) = oneshot::channel();
    let (selected, selection) = oneshot::channel();
    let request = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .enqueue_upload_with_picker(
                    "terminal",
                    &transport.to_string(),
                    b".".to_vec(),
                    move || async move {
                        opened.send(()).unwrap();
                        selection.await.unwrap();
                        Ok(Some(path))
                    },
                    |_| async { Ok(true) },
                )
                .await
        }
    });
    did_open.await.unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    let snapshot = manager.transfer_queue_snapshot("terminal").unwrap();
    assert!(snapshot.picker_busy);
    assert_eq!(snapshot.outstanding, 1);
    selected.send(()).unwrap();
    let (reply, _, operation) = next_upload(&mut requests, b"./detached.bin").await;
    saved(&manager, transport, operation, reply);
    let snapshot = snapshot_where(&manager, |snapshot| snapshot.recent.len() == 1).await;
    assert_eq!(snapshot.recent[0].state, SessionTransferState::Saved);
    assert_eq!(snapshot.outstanding, 0);
}

#[tokio::test]
async fn execution_is_fifo_and_cancelling_a_queued_item_never_dispatches_it() {
    let (manager, transport, mut requests) = ready_manager();
    let directory = tempfile::tempdir().unwrap();
    let mut paths = Vec::new();
    for name in ["first.bin", "cancelled.bin", "last.bin"] {
        let path = directory.path().join(name);
        std::fs::write(&path, b"queued bytes").unwrap();
        paths.push(path);
    }
    let _first = enqueue_upload(&manager, transport, paths.remove(0)).await;
    let (first_reply, _, first_operation) = next_upload(&mut requests, b"./first.bin").await;
    assert!(
        manager
            .list_files(
                "terminal",
                &transport.to_string(),
                &Uuid::now_v7().to_string(),
                b".".to_vec()
            )
            .await
            .is_err()
    );
    assert!(
        manager
            .create_remote_directory(
                "terminal",
                &transport.to_string(),
                &Uuid::now_v7().to_string(),
                b".".to_vec(),
                "blocked-directory"
            )
            .await
            .is_err()
    );
    let second = enqueue_upload(&manager, transport, paths.remove(0)).await;
    let _third = enqueue_upload(&manager, transport, paths.remove(0)).await;
    assert!(requests.try_recv().is_err());
    let (queue, item, execution) = enqueue_ids(&second);
    manager.cancel_transfer("terminal", queue, item, execution).unwrap();
    saved(&manager, transport, first_operation, first_reply);
    let (last_reply, _, last_operation) = next_upload(&mut requests, b"./last.bin").await;
    saved(&manager, transport, last_operation, last_reply);
    let snapshot = snapshot_where(&manager, |snapshot| snapshot.recent.len() == 3).await;
    assert_eq!(
        snapshot.recent.iter().map(|row| row.state).collect::<Vec<_>>(),
        [SessionTransferState::Cancelled, SessionTransferState::Saved, SessionTransferState::Saved,]
    );
    assert_eq!(snapshot.outstanding, 0);
}

#[tokio::test]
async fn full_queue_rejects_before_opening_another_native_picker() {
    let (manager, transport, mut requests) = ready_manager();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bounded.bin");
    std::fs::write(&path, b"bounded bytes").unwrap();
    enqueue_upload(&manager, transport, path.clone()).await;
    let (reply, _, _) = next_upload(&mut requests, b"./bounded.bin").await;
    for _ in 1..16 {
        enqueue_upload(&manager, transport, path.clone()).await;
    }
    let invoked = Arc::new(AtomicBool::new(false));
    let choosing = invoked.clone();
    let error = manager
        .enqueue_upload_with_picker(
            "terminal",
            &transport.to_string(),
            b".".to_vec(),
            move || async move {
                choosing.store(true, Ordering::SeqCst);
                Ok(Some(path))
            },
            |_| async { Ok(true) },
        )
        .await
        .unwrap_err();
    assert_eq!(error, SessionTransferIssue::QueueFull);
    assert!(!invoked.load(Ordering::SeqCst));
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 16);
    manager.expire_ready_transport("terminal", transport).unwrap();
    drop(reply);
    let snapshot = snapshot_where(&manager, |snapshot| snapshot.outstanding == 0).await;
    assert_eq!(snapshot.recent.len(), 16);
    assert!(snapshot.recent.iter().all(|row| row.state == SessionTransferState::Interrupted));
}

#[tokio::test]
async fn cancellation_waits_for_the_real_native_confirmation_callback() {
    let (manager, transport, mut requests) = ready_manager();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("reviewed.bin");
    std::fs::write(&path, b"reviewed bytes").unwrap();
    let (opened, did_open) = oneshot::channel();
    let (finish, finished) = oneshot::channel();
    let queued = manager
        .enqueue_upload_with_picker(
            "terminal",
            &transport.to_string(),
            b".".to_vec(),
            move || async move { Ok(Some(path)) },
            move |review| async move {
                opened.send(review).unwrap();
                finished.await.unwrap();
                Ok(true)
            },
        )
        .await
        .unwrap();
    let FileCommand::PreflightUpload { reply, .. } = next_request(&mut requests).await else {
        panic!()
    };
    reply
        .send(Ok(UploadPreflight {
            target_attributes: Some(scoplen_ssh::SftpAttributes {
                permissions: Some(0o100600),
                ..Default::default()
            }),
            replacement_supported: true,
        }))
        .ok();
    let review = did_open.await.unwrap();
    assert_eq!(review.name, "reviewed.bin");
    assert_eq!(review.host, "Bound target");
    assert_eq!(review.username, "deploy");
    assert_eq!(review.address, "fixture.example");
    assert_eq!(review.port, 2222);
    assert_eq!(review.direction, SessionTransferDirection::Upload);
    let (queue, item, execution) = enqueue_ids(&queued);
    manager.cancel_transfer("terminal", queue, item, execution).unwrap();
    let snapshot = snapshot_where(&manager, |snapshot| {
        snapshot.items[0].state == SessionTransferState::Cancelling
    })
    .await;
    assert!(snapshot.picker_busy);
    assert_eq!(snapshot.outstanding, 1);
    assert!(snapshot.recent.is_empty());
    let error = manager
        .enqueue_download_with_picker(
            "terminal",
            &transport.to_string(),
            b"./another.bin".to_vec(),
            || async { panic!("must not open a second picker") },
            |_| async { Ok(true) },
        )
        .await
        .unwrap_err();
    assert_eq!(error, SessionTransferIssue::NativeDialogBusy);
    finish.send(()).unwrap();
    let snapshot = snapshot_where(&manager, |snapshot| snapshot.recent.len() == 1).await;
    assert!(!snapshot.picker_busy);
    assert_eq!(snapshot.recent[0].state, SessionTransferState::Cancelled);
    assert!(requests.try_recv().is_err());
}

#[tokio::test]
async fn changing_a_download_destination_while_queued_is_a_conflict_before_network_io() {
    let (manager, transport, mut requests) = ready_manager();
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("first.bin");
    let target = directory.path().join("download.bin");
    std::fs::write(&source, b"first bytes").unwrap();
    std::fs::write(&target, b"original target").unwrap();
    enqueue_upload(&manager, transport, source).await;
    let (reply, _, operation) = next_upload(&mut requests, b"./first.bin").await;
    let chosen = target.clone();
    manager
        .enqueue_download_with_picker(
            "terminal",
            &transport.to_string(),
            b"./remote.bin".to_vec(),
            move || async move { Ok(Some(chosen)) },
            |_| async { panic!("a changed target must conflict before confirmation") },
        )
        .await
        .unwrap();
    std::fs::write(&target, b"new local content must survive").unwrap();
    saved(&manager, transport, operation, reply);
    let snapshot = snapshot_where(&manager, |snapshot| snapshot.recent.len() == 2).await;
    assert_eq!(snapshot.recent[1].state, SessionTransferState::Conflict);
    assert_eq!(snapshot.recent[1].issue, Some(SessionTransferIssue::TargetChanged));
    assert!(!snapshot.recent[1].staging_may_remain);
    assert!(requests.try_recv().is_err());
    assert_eq!(std::fs::read(target).unwrap(), b"new local content must survive");
}

#[tokio::test]
async fn changing_a_selected_upload_while_queued_conflicts_without_reopening_it() {
    let (manager, transport, mut requests) = ready_manager();
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("selected.bin");
    std::fs::write(&source, b"original bytes").unwrap();
    enqueue_upload(&manager, transport, source.clone()).await;
    let (reply, _, operation) = next_upload(&mut requests, b"./selected.bin").await;
    enqueue_upload(&manager, transport, source.clone()).await;
    std::fs::write(&source, b"changed selected bytes").unwrap();
    saved(&manager, transport, operation, reply);
    let snapshot = snapshot_where(&manager, |snapshot| snapshot.recent.len() == 2).await;
    assert_eq!(snapshot.recent[1].state, SessionTransferState::Conflict);
    assert_eq!(snapshot.recent[1].issue, Some(SessionTransferIssue::SourceChanged));
    assert!(requests.try_recv().is_err());
}

#[tokio::test]
async fn publication_claim_fences_cancellation_and_unknown_reminders_allow_browsing() {
    let (manager, transport, mut requests) = ready_manager();
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("unknown.bin");
    std::fs::write(&source, b"publication bytes").unwrap();
    let queued = enqueue_upload(&manager, transport, source).await;
    let (reply, state, operation) = next_upload(&mut requests, b"./unknown.bin").await;
    SessionManager::authorize_remote_effect(&manager.sessions, "terminal", transport, operation)
        .unwrap();
    let (queue, item, execution) = enqueue_ids(&queued);
    assert!(state.effect_started.load(Ordering::SeqCst));
    assert_eq!(
        manager.cancel_transfer("terminal", queue, item, execution),
        Err(SessionTransferIssue::PublicationStarted)
    );
    manager.finish_remote_effect("terminal", transport, operation);
    reply
        .send(UploadExecution::Failed {
            error: FileAccessError::PublicationUnknown,
            staging_may_remain: true,
        })
        .ok();
    let snapshot = snapshot_where(&manager, |snapshot| {
        snapshot.items[0].state == SessionTransferState::Unknown
    })
    .await;
    assert_eq!(snapshot.outstanding, 1);
    assert!(!snapshot.blocks_file_operations);
    let (abort, _) = AbortHandle::new_pair();
    let browsing = manager
        .reserve_file_operation(
            "terminal",
            &transport.to_string(),
            &Uuid::now_v7().to_string(),
            abort,
        )
        .unwrap();
    drop(browsing);
    manager.acknowledge_transfer("terminal", queue, item, execution).unwrap();
    let snapshot = manager.transfer_queue_snapshot("terminal").unwrap();
    assert_eq!(snapshot.outstanding, 0);
    assert!(snapshot.recent.is_empty());
    assert!(requests.try_recv().is_err());
}

#[tokio::test]
async fn declining_download_replacement_is_cancelled_without_network_or_cleanup_claims() {
    let (manager, transport, mut requests) = ready_manager();
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("keep.bin");
    std::fs::write(&target, b"keep local content").unwrap();
    let chosen = target.clone();
    let confirmations = Arc::new(AtomicUsize::new(0));
    let confirmed = confirmations.clone();
    manager
        .enqueue_download_with_picker(
            "terminal",
            &transport.to_string(),
            b"./remote.bin".to_vec(),
            move || async move { Ok(Some(chosen)) },
            move |review| async move {
                assert_eq!(review.direction, SessionTransferDirection::Download);
                assert_eq!(review.name, "keep.bin");
                confirmed.fetch_add(1, Ordering::SeqCst);
                Ok(false)
            },
        )
        .await
        .unwrap();
    let snapshot = snapshot_where(&manager, |snapshot| snapshot.recent.len() == 1).await;
    assert_eq!(confirmations.load(Ordering::SeqCst), 1);
    assert_eq!(snapshot.recent[0].state, SessionTransferState::Cancelled);
    assert_eq!(snapshot.recent[0].issue, None);
    assert!(!snapshot.recent[0].staging_may_remain);
    assert!(requests.try_recv().is_err());
    assert_eq!(std::fs::read(target).unwrap(), b"keep local content");
}

#[tokio::test]
async fn final_destination_recheck_conflicts_before_the_publication_claim() {
    let (manager, transport, mut requests) = ready_manager();
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("selected.bin");
    let chosen = target.clone();
    manager
        .enqueue_download_with_picker(
            "terminal",
            &transport.to_string(),
            b"./remote.bin".to_vec(),
            move || async move { Ok(Some(chosen)) },
            |_| async { Ok(true) },
        )
        .await
        .unwrap();
    let FileCommand::TransferDownload { input, operation, reply, .. } =
        next_request(&mut requests).await
    else {
        panic!()
    };
    let DownloadInput::New { destination: baseline, .. } = input else { panic!() };
    std::fs::write(&target, b"created after download started").unwrap();
    let published = AtomicBool::new(false);
    let result = SessionManager::commit_download(
        &manager.sessions,
        "terminal",
        transport,
        operation,
        Some(&baseline),
        || {
            published.store(true, Ordering::SeqCst);
            Ok(())
        },
    );
    assert_eq!(result.status, SessionDownloadStatus::Conflict);
    assert!(!published.load(Ordering::SeqCst));
    assert!(
        !manager
            .sessions
            .lock()
            .unwrap()
            .get("terminal")
            .unwrap()
            .active
            .as_ref()
            .unwrap()
            .file
            .as_ref()
            .unwrap()
            .upload_state
            .effect_started
            .load(Ordering::SeqCst)
    );
    manager.finish_remote_effect("terminal", transport, operation);
    reply.send(Ok(DownloadExecution::Published { result, staging_may_remain: false })).ok();
    let snapshot = snapshot_where(&manager, |snapshot| snapshot.recent.len() == 1).await;
    assert_eq!(snapshot.recent[0].state, SessionTransferState::Conflict);
    assert_eq!(snapshot.recent[0].issue, Some(SessionTransferIssue::TargetChanged));
    assert!(!snapshot.recent[0].staging_may_remain);
    assert_eq!(std::fs::read(target).unwrap(), b"created after download started");
}

#[tokio::test]
async fn cancellation_of_a_dispatched_download_waits_for_owned_cleanup_settlement() {
    let (manager, transport, mut requests) = ready_manager();
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("cancelled.bin");
    let queued = manager
        .enqueue_download_with_picker(
            "terminal",
            &transport.to_string(),
            b"./remote.bin".to_vec(),
            move || async move { Ok(Some(target)) },
            |_| async { Ok(true) },
        )
        .await
        .unwrap();
    let FileCommand::TransferDownload { mut control, reply, .. } =
        next_request(&mut requests).await
    else {
        panic!()
    };
    let (queue, item, execution) = enqueue_ids(&queued);
    manager.cancel_transfer("terminal", queue, item, execution).unwrap();
    control.changed().await.unwrap();
    assert!(*control.borrow() == TransferControl::Cancel);
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 1);
    reply
        .send(Ok(DownloadExecution::Failed {
            error: FileAccessError::Cancelled,
            staging_may_remain: false,
        }))
        .ok();
    let snapshot = snapshot_where(&manager, |snapshot| snapshot.recent.len() == 1).await;
    assert_eq!(snapshot.recent[0].state, SessionTransferState::Cancelled);
    assert!(!snapshot.recent[0].staging_may_remain);
}

#[tokio::test]
async fn ended_runtime_retains_unknown_for_offline_review_and_same_session_reopening() {
    let (manager, transport, mut requests) = ready_manager();
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("unknown.bin");
    std::fs::write(&source, b"publication bytes").unwrap();
    let queued = enqueue_upload(&manager, transport, source).await;
    let (reply, _, operation) = next_upload(&mut requests, b"./unknown.bin").await;
    SessionManager::authorize_remote_effect(&manager.sessions, "terminal", transport, operation)
        .unwrap();
    manager.finish_remote_effect("terminal", transport, operation);
    reply
        .send(UploadExecution::Failed {
            error: FileAccessError::PublicationUnknown,
            staging_may_remain: true,
        })
        .ok();
    snapshot_where(&manager, |snapshot| snapshot.items[0].state == SessionTransferState::Unknown)
        .await;
    drop(Registration { manager: &manager, id: "terminal" });
    let (queue, item, execution) = enqueue_ids(&queued);
    let snapshot = manager.transfer_queue_snapshot("terminal").unwrap();
    assert_eq!(snapshot.queue_id, queue);
    assert_eq!(snapshot.items[0].state, SessionTransferState::Unknown);
    assert!(manager.reserve("terminal", false).is_err());
    manager.reserve("terminal", true).unwrap();
    assert!(manager.reserve("terminal", true).is_err());
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().queue_id, queue);
    manager.acknowledge_transfer("terminal", queue, item, execution).unwrap();
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 0);
    manager.close("terminal").unwrap();
    assert_eq!(
        manager.transfer_queue_snapshot("terminal"),
        Err(SessionTransferIssue::SessionUnavailable)
    );
    assert!(requests.try_recv().is_err());
}

#[tokio::test]
async fn expired_native_selection_keeps_its_permit_until_the_old_callback_returns() {
    let (manager, transport, _requests) = ready_manager();
    let (opened, did_open) = oneshot::channel();
    let (finish, finished) = oneshot::channel();
    let selection = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .enqueue_download_with_picker(
                    "terminal",
                    &transport.to_string(),
                    b"./remote.bin".to_vec(),
                    move || async move {
                        opened.send(()).unwrap();
                        finished.await.unwrap();
                        Ok(None)
                    },
                    |_| async { Ok(true) },
                )
                .await
        }
    });
    did_open.await.unwrap();
    manager.expire_ready_transport("terminal", transport).unwrap();
    let replacement = Uuid::now_v7();
    {
        let mut sessions = manager.sessions.lock().unwrap();
        let active = sessions.get_mut("terminal").unwrap().active.as_mut().unwrap();
        active.id = replacement;
        active.ready = true;
    }
    let error = manager
        .enqueue_download_with_picker(
            "terminal",
            &replacement.to_string(),
            b"./second.bin".to_vec(),
            || async { panic!("old OS dialog still holds its permit") },
            |_| async { Ok(true) },
        )
        .await
        .unwrap_err();
    assert_eq!(error, SessionTransferIssue::NativeDialogBusy);
    finish.send(()).unwrap();
    assert_eq!(selection.await.unwrap().unwrap(), SessionTransferEnqueueResult::Cancelled);
    let snapshot = manager.transfer_queue_snapshot("terminal").unwrap();
    assert!(!snapshot.picker_busy);
    assert_eq!(snapshot.outstanding, 0);
    assert!(snapshot.items.is_empty());
}

#[test]
fn dropping_a_file_guard_cannot_abort_a_claim_decided_under_the_same_owner_lock() {
    let (manager, transport, _requests) = ready_manager();
    let (abort, _) = AbortHandle::new_pair();
    let guard = manager
        .reserve_file_operation(
            "terminal",
            &transport.to_string(),
            &Uuid::now_v7().to_string(),
            abort.clone(),
        )
        .unwrap();
    std::thread::scope(|scope| {
        let sessions = manager.sessions.lock().unwrap();
        let state = sessions
            .get("terminal")
            .unwrap()
            .active
            .as_ref()
            .unwrap()
            .file
            .as_ref()
            .unwrap()
            .upload_state
            .clone();
        let (entered, entering) = std::sync::mpsc::channel();
        let dropped = scope.spawn(move || {
            entered.send(()).unwrap();
            drop(guard);
        });
        entering.recv().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let aborted_before_claim_finished = abort.is_aborted();
        state.effect_started.store(true, Ordering::SeqCst);
        drop(sessions);
        dropped.join().unwrap();
        assert!(!aborted_before_claim_finished);
        assert!(!abort.is_aborted());
    });
}
