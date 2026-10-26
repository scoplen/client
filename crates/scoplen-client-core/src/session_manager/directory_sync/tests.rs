// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::connection::preparation::PreparationContext;
use crate::session_files::directory_sync::tests::upload_plan;
use crate::session_transfers::{SessionTransferState, TransferCompletion};
use std::path::Path;

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
    requests: &mut mpsc::Receiver<FileCommand>,
    root: &Path,
) -> String {
    let plan = upload_plan(root).await;
    let operation = Uuid::now_v7().to_string();
    let folder = root.to_path_buf();
    let transport_text = transport.to_string();
    let prepare = manager.prepare_directory_sync_with_picker(
        "terminal",
        &transport_text,
        &operation,
        b"./root".to_vec(),
        SessionTransferDirection::Upload,
        || async { Ok(Some(folder)) },
    );
    let peer = async {
        let FileCommand::CompareDirectory { reply, remote, direction, .. } =
            requests.recv().await.unwrap()
        else {
            panic!()
        };
        assert_eq!(remote, b"./root");
        assert_eq!(direction, SessionTransferDirection::Upload);
        reply.send(Ok(plan)).ok();
    };
    let (result, ()) = tokio::join!(prepare, peer);
    let PrepareResult::Prepared { plan } = result.unwrap() else { panic!() };
    plan.plan_id
}

#[tokio::test]
async fn cancelled_picker_owns_no_plan_capacity_or_remote_request() {
    let (manager, transport, mut requests) = ready_manager();
    assert_eq!(
        manager
            .prepare_directory_sync_with_picker(
                "terminal",
                &transport.to_string(),
                &Uuid::now_v7().to_string(),
                b"./root".to_vec(),
                SessionTransferDirection::Download,
                || async { Ok(None) }
            )
            .await
            .unwrap(),
        PrepareResult::Cancelled
    );
    assert!(requests.try_recv().is_err());
    assert!(manager.sessions.lock().unwrap().get("terminal").unwrap().directory_sync.is_none());
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 0);
}

#[tokio::test]
async fn unchanged_apply_consumes_no_slots_and_discard_and_double_apply_have_no_authority() {
    let root = tempfile::tempdir().unwrap();
    let (manager, transport, mut requests) = ready_manager();
    let id = prepare(&manager, transport, &mut requests, root.path()).await;
    let transport_text = transport.to_string();
    let apply = manager.apply_directory_sync("terminal", &transport_text, &id, |_| async {
        panic!("empty plan has no confirmation")
    });
    let peer = async {
        let FileCommand::ValidateDirectory { plan, reply } = requests.recv().await.unwrap() else {
            panic!()
        };
        reply.send(Ok(plan)).ok();
    };
    let (result, ()) = tokio::join!(apply, peer);
    assert_eq!(result.unwrap(), ApplyResult::Unchanged);
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 0);
    assert_eq!(
        manager
            .apply_directory_sync("terminal", &transport_text, &id, |_| async { Ok(true) })
            .await,
        Err(Issue::Unavailable)
    );
    let id = prepare(&manager, transport, &mut requests, root.path()).await;
    manager.discard_directory_sync("terminal", &id).unwrap();
    assert_eq!(
        manager
            .apply_directory_sync("terminal", &transport_text, &id, |_| async { Ok(true) })
            .await,
        Err(Issue::Unavailable)
    );
    assert!(requests.try_recv().is_err());
}

#[tokio::test]
async fn cancellation_and_transport_loss_suppress_late_prepared_authority() {
    for transport_loss in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let plan = upload_plan(root.path()).await;
        let (manager, transport, mut requests) = ready_manager();
        let operation = Uuid::now_v7().to_string();
        let transport_text = transport.to_string();
        let prepare = manager.prepare_directory_sync_with_picker(
            "terminal",
            &transport_text,
            &operation,
            b"./root".to_vec(),
            SessionTransferDirection::Upload,
            || async { Ok(Some(root.path().to_path_buf())) },
        );
        let cancel = async {
            let FileCommand::CompareDirectory { reply, .. } = requests.recv().await.unwrap() else {
                panic!()
            };
            if transport_loss {
                let mut sessions = manager.sessions.lock().unwrap();
                let entry = sessions.get_mut("terminal").unwrap();
                interrupt_transfers(entry, transport);
                entry.active.as_mut().unwrap().id = Uuid::now_v7();
            } else {
                manager.cancel_file_operation("terminal", &transport_text, &operation).unwrap();
            }
            reply.send(Ok(plan)).ok();
        };
        let (result, ()) = tokio::join!(prepare, cancel);
        assert!(result.is_err());
        assert!(manager.sessions.lock().unwrap().get("terminal").unwrap().directory_sync.is_none());
        assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 0);
    }
}

#[tokio::test]
async fn failed_validation_discards_the_plan_without_admitting_any_files() {
    let root = tempfile::tempdir().unwrap();
    tokio::fs::write(root.path().join("file"), b"x").await.unwrap();
    let (manager, transport, mut requests) = ready_manager();
    let id = prepare(&manager, transport, &mut requests, root.path()).await;
    let transport_text = transport.to_string();
    let apply =
        manager.apply_directory_sync("terminal", &transport_text, &id, |_| async { Ok(true) });
    let peer = async {
        let FileCommand::ValidateDirectory { reply, .. } = requests.recv().await.unwrap() else {
            panic!()
        };
        reply.send(Err(Issue::FileChanged)).ok();
    };
    let (result, ()) = tokio::join!(apply, peer);
    assert_eq!(result, Err(Issue::FileChanged));
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 0);
    assert!(manager.sessions.lock().unwrap().get("terminal").unwrap().directory_sync.is_none());
}

#[tokio::test(start_paused = true)]
async fn absolute_deadline_starts_after_folder_selection_and_clears_unfinished_comparison() {
    let (manager, transport, mut requests) = ready_manager();
    let operation = Uuid::now_v7().to_string();
    let transport_text = transport.to_string();
    let root = tempfile::tempdir().unwrap();
    let prepare = manager.prepare_directory_sync_with_picker(
        "terminal",
        &transport_text,
        &operation,
        b"./root".to_vec(),
        SessionTransferDirection::Upload,
        || async {
            tokio::time::sleep(COMPARISON_TIMEOUT + Duration::from_secs(1)).await;
            Ok(Some(root.path().to_path_buf()))
        },
    );
    let pending = async {
        let FileCommand::CompareDirectory { mut reply, .. } = requests.recv().await.unwrap() else {
            panic!("folder selection must finish before the comparison deadline starts")
        };
        reply.closed().await;
    };
    let (result, ()) = tokio::join!(prepare, pending);
    assert_eq!(result, Err(Issue::Timeout));
    assert!(manager.sessions.lock().unwrap().get("terminal").unwrap().directory_sync.is_none());
}

#[tokio::test]
async fn whole_batch_capacity_failure_keeps_the_plan_for_one_explicit_retry() {
    let root = tempfile::tempdir().unwrap();
    tokio::fs::write(root.path().join("a"), b"a").await.unwrap();
    tokio::fs::write(root.path().join("b"), b"b").await.unwrap();
    let (manager, transport, mut requests) = ready_manager();
    let id = prepare(&manager, transport, &mut requests, root.path()).await;
    let mut unknown = Vec::new();
    for _ in 0..15 {
        let source = session_files::open_upload_source(&root.path().join("a")).await.unwrap();
        let mut sessions = manager.sessions.lock().unwrap();
        let queue = &mut sessions.get_mut("terminal").unwrap().transfers;
        let reservation = queue.reserve_selection(transport).unwrap();
        queue
            .enqueue_selected(
                reservation,
                "existing",
                SessionTransferDirection::Upload,
                Some(1),
                SelectedTransfer::Upload {
                    source,
                    directory: b"./root".to_vec(),
                    target: b"./root/existing".to_vec(),
                    confirm: Box::new(|_| Box::pin(async { Ok(true) })),
                    editor: None,
                },
            )
            .unwrap();
        let selected = queue.take_next(transport).unwrap();
        queue.finish(
            selected.identity,
            TransferCompletion {
                state: SessionTransferState::Unknown,
                issue: None,
                staging_may_remain: false,
            },
        );
        unknown.push(selected.identity);
    }
    let transport_text = transport.to_string();
    let apply =
        manager.apply_directory_sync("terminal", &transport_text, &id, |_| async { Ok(true) });
    let validate = async {
        let FileCommand::ValidateDirectory { plan, reply } = requests.recv().await.unwrap() else {
            panic!()
        };
        reply.send(Ok(plan)).ok();
    };
    let (result, ()) = tokio::join!(apply, validate);
    assert_eq!(result, Err(Issue::QueueFull));
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 15);
    assert!(
        manager
            .sessions
            .lock()
            .unwrap()
            .get("terminal")
            .unwrap()
            .directory_sync
            .as_ref()
            .unwrap()
            .plan
            .is_some()
    );
    {
        let mut sessions = manager.sessions.lock().unwrap();
        let queue = &mut sessions.get_mut("terminal").unwrap().transfers;
        let identity = unknown[0];
        queue.acknowledge(queue.id(), identity.item, identity.execution).unwrap();
    }
    let apply = manager.apply_directory_sync("terminal", &transport_text, &id, |_| async {
        panic!("missing targets need no confirmation")
    });
    let validate = async {
        let FileCommand::ValidateDirectory { plan, reply } = requests.recv().await.unwrap() else {
            panic!()
        };
        reply.send(Ok(plan)).ok();
    };
    let (result, ()) = tokio::join!(apply, validate);
    let ApplyResult::Queued { items, .. } = result.unwrap() else { panic!() };
    assert_eq!(items.len(), 2);
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 16);
    let transfer = async {
        for name in [b"./root/a", b"./root/b"] {
            let FileCommand::PreflightUpload { target, reply } = requests.recv().await.unwrap()
            else {
                panic!()
            };
            assert_eq!(target, name);
            reply
                .send(Ok(UploadPreflight { target_attributes: None, replacement_supported: true }))
                .ok();
            let FileCommand::TransferUpload { reply, .. } = requests.recv().await.unwrap() else {
                panic!()
            };
            reply.send(UploadExecution::Published).ok();
        }
    };
    tokio::time::timeout(Duration::from_secs(3), transfer).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = manager.transfer_queue_snapshot("terminal").unwrap();
            if snapshot.recent.len() == 2 {
                assert_eq!(
                    snapshot.recent.iter().map(|row| row.name.as_str()).collect::<Vec<_>>(),
                    ["a", "b"]
                );
                assert!(snapshot.recent.iter().all(|row| row.state == SessionTransferState::Saved));
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(manager.sessions.lock().unwrap().get("terminal").unwrap().directory_sync.is_none());
}
