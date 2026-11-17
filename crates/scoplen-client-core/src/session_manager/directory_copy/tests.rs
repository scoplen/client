// SPDX-License-Identifier: Apache-2.0

use super::*;

fn ready_manager() -> (SessionManager, Uuid, mpsc::Receiver<FileCommand>) {
    let manager = SessionManager::default();
    manager.reserve("terminal", true).unwrap();
    let transport = Uuid::now_v7();
    let (sender, _) = mpsc::channel(COMMAND_QUEUE);
    let (files, requests) = mpsc::channel(FILE_QUEUE);
    {
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
                terminal_profile: None,
                source: None,
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
    }
    (manager, transport, requests)
}

async fn prepare(
    manager: &SessionManager,
    transport: Uuid,
    path: PathBuf,
) -> SessionDirectoryCopySelection {
    let PrepareResult::Prepared { selection } = manager
        .prepare_directory_copy_with_picker(
            "terminal",
            &transport.to_string(),
            b"./remote".to_vec(),
            Direction::Upload,
            move || async move { Ok(Some(path)) },
        )
        .await
        .unwrap()
    else {
        panic!()
    };
    selection
}

#[tokio::test]
async fn preparation_reserves_one_slot_without_remote_work_and_discard_releases_it() {
    let root = tempfile::tempdir().unwrap();
    let (manager, transport, mut requests) = ready_manager();
    let selection = prepare(&manager, transport, root.path().to_path_buf()).await;
    let snapshot = manager.transfer_queue_snapshot("terminal").unwrap();
    assert_eq!(snapshot.outstanding, 1);
    assert!(snapshot.picker_busy);
    assert!(requests.try_recv().is_err());
    manager.discard_directory_copy("terminal", &selection.selection_id).unwrap();
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 0);
}

#[tokio::test]
async fn invalid_name_retains_original_selection_and_expiry_then_admission_consumes_it_once() {
    let root = tempfile::tempdir().unwrap();
    let (manager, transport, mut requests) = ready_manager();
    let selection = prepare(&manager, transport, root.path().to_path_buf()).await;
    let expiry = manager
        .sessions
        .lock()
        .unwrap()
        .get("terminal")
        .unwrap()
        .directory_copy
        .as_ref()
        .unwrap()
        .expires;
    assert_eq!(
        manager.enqueue_directory_copy(
            "terminal",
            &transport.to_string(),
            &selection.selection_id,
            "../bad"
        ),
        Err(Issue::UnsupportedName)
    );
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 1);
    assert_eq!(
        manager
            .sessions
            .lock()
            .unwrap()
            .get("terminal")
            .unwrap()
            .directory_copy
            .as_ref()
            .unwrap()
            .expires,
        expiry
    );
    let result = manager
        .enqueue_directory_copy(
            "terminal",
            &transport.to_string(),
            &selection.selection_id,
            "new-root",
        )
        .unwrap();
    assert!(matches!(result, SessionTransferEnqueueResult::Queued { .. }));
    assert_eq!(
        manager.enqueue_directory_copy(
            "terminal",
            &transport.to_string(),
            &selection.selection_id,
            "another-root"
        ),
        Err(Issue::Unavailable)
    );
    let FileCommand::TransferDirectory { input, identity, reply, .. } =
        requests.recv().await.unwrap()
    else {
        panic!()
    };
    assert_eq!(input.root_name, b"new-root");
    let snapshot = manager.transfer_queue_snapshot("terminal").unwrap();
    assert_eq!(snapshot.outstanding, 1);
    assert_eq!(snapshot.items[0].execution_id, identity.execution.to_string());
    assert!(!snapshot.items[0].can_pause);
    reply
        .send(session_files::directory_copy::DirectoryCopyResult {
            issue: None,
            staging_may_remain: false,
        })
        .ok();
}

#[tokio::test]
async fn cancelled_picker_and_abandoned_ipc_release_selection_without_any_writes() {
    let (manager, transport, mut requests) = ready_manager();
    assert_eq!(
        manager
            .prepare_directory_copy_with_picker(
                "terminal",
                &transport.to_string(),
                b"./remote".to_vec(),
                Direction::Upload,
                || async { Ok(None) }
            )
            .await
            .unwrap(),
        PrepareResult::Cancelled
    );
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 0);
    let (entered, received) = oneshot::channel();
    let (finish, finished) = oneshot::channel();
    let task_manager = manager.clone();
    let task = tokio::spawn(async move {
        task_manager
            .prepare_directory_copy_with_picker(
                "terminal",
                &transport.to_string(),
                b"./remote".to_vec(),
                Direction::Upload,
                || async {
                    let _ = entered.send(());
                    finished.await.unwrap();
                    Ok(None)
                },
            )
            .await
    });
    received.await.unwrap();
    task.abort();
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 1);
    finish.send(()).unwrap();
    for _ in 0..50 {
        if manager.transfer_queue_snapshot("terminal").unwrap().outstanding == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 0);
    assert!(requests.try_recv().is_err());
}

#[tokio::test]
async fn transport_replacement_invalidates_prepared_selection_and_releases_capacity() {
    let root = tempfile::tempdir().unwrap();
    let (manager, transport, mut requests) = ready_manager();
    let selection = prepare(&manager, transport, root.path().to_path_buf()).await;
    {
        let mut sessions = manager.sessions.lock().unwrap();
        let entry = sessions.get_mut("terminal").unwrap();
        interrupt_transfers(entry, transport);
        entry.active.as_mut().unwrap().id = Uuid::now_v7();
    }
    assert_eq!(
        manager.enqueue_directory_copy(
            "terminal",
            &transport.to_string(),
            &selection.selection_id,
            "root"
        ),
        Err(Issue::Unavailable)
    );
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 0);
    assert!(requests.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn prepared_selection_expires_without_renewal_or_admission() {
    let root = tempfile::tempdir().unwrap();
    let (manager, transport, mut requests) = ready_manager();
    let selection = prepare(&manager, transport, root.path().to_path_buf()).await;
    tokio::time::advance(SELECTION_LIFETIME + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(
        manager
            .enqueue_directory_copy(
                "terminal",
                &transport.to_string(),
                &selection.selection_id,
                "new-root"
            )
            .is_err()
    );
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 0);
    assert!(requests.try_recv().is_err());
}

#[tokio::test]
async fn lost_effect_reply_retains_unknown_root_or_partial_tree_without_replay() {
    for root_unknown in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let (manager, transport, mut requests) = ready_manager();
        let selection = prepare(&manager, transport, root.path().to_path_buf()).await;
        manager
            .enqueue_directory_copy(
                "terminal",
                &transport.to_string(),
                &selection.selection_id,
                "new-root",
            )
            .unwrap();
        let FileCommand::TransferDirectory { identity, state, reply, .. } =
            requests.recv().await.unwrap()
        else {
            panic!()
        };
        let callbacks = manager.directory_copy_callbacks("terminal", identity, state.clone());
        (callbacks.authorize)().unwrap();
        let progress = crate::session_directory_copy::SessionDirectoryCopyProgress {
            root_created: !root_unknown,
            root_creation_unknown: root_unknown,
            directories_created: u32::from(!root_unknown),
            files_completed: u32::from(!root_unknown),
            ..Default::default()
        };
        (callbacks.progress)(0, None, progress);
        drop(reply);
        for _ in 0..50 {
            if manager.transfer_queue_snapshot("terminal").unwrap().items[0].state
                == SessionTransferState::Unknown
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        let snapshot = manager.transfer_queue_snapshot("terminal").unwrap();
        assert_eq!(snapshot.outstanding, 1);
        assert_eq!(snapshot.items[0].state, SessionTransferState::Unknown);
        assert!(snapshot.items[0].can_acknowledge && !snapshot.items[0].can_cancel);
        let progress = snapshot.items[0].directory_copy.as_ref().unwrap();
        assert_eq!(progress.root_creation_unknown, root_unknown);
        assert_eq!(progress.root_created, !root_unknown);
        assert_eq!(progress.issue, Some(Issue::PublicationUnknown));
        assert!(requests.try_recv().is_err());
    }
}
