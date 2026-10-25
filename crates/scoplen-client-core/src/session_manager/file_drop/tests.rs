// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::session_files::FileAccessError;

fn ready() -> (SessionManager, String, mpsc::Receiver<FileCommand>) {
    let manager = SessionManager::default();
    manager.reserve("terminal", true).unwrap();
    let transport = Uuid::now_v7();
    let (sender, _) = mpsc::channel(COMMAND_QUEUE);
    let (files, requests) = mpsc::channel(FILE_QUEUE);
    let mut sessions = manager.sessions.lock().unwrap();
    let entry = sessions.get_mut("terminal").unwrap();
    entry.active = Some(ActiveAttempt {
        id: transport,
        control: PreparationControl::default(),
        sender,
        files,
        file: None,
        ready: true,
        context: None,
    });
    // Hold the executor so assertions inspect admission independently of remote execution.
    entry.transfer_worker_running = true;
    drop(sessions);
    (manager, transport.to_string(), requests)
}

fn arm(manager: &SessionManager, transport: &str) -> String {
    let id = Uuid::now_v7().to_string();
    manager
        .arm_file_drop(
            "main",
            &id,
            "terminal",
            transport,
            &manager.transfer_queue_snapshot("terminal").unwrap().queue_id,
            b"./original".to_vec(),
        )
        .unwrap();
    id
}

fn sources(folder: &std::path::Path, count: usize) -> Vec<PathBuf> {
    (0..count)
        .map(|number| {
            let path = folder.join(format!("{number}.bin"));
            std::fs::write(&path, format!("selected {number}")).unwrap();
            path
        })
        .collect()
}

async fn consume(
    manager: &SessionManager,
    context: &str,
    ticket: &str,
) -> Result<FileDropAccepted, SessionTransferIssue> {
    manager
        .consume_file_drop("main", context, ticket, |_| async {
            panic!("admission cannot open replacement review")
        })
        .await
}

#[test]
fn synchronous_native_callback_needs_no_ambient_tokio_runtime() {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let (manager, transport, _) = ready();
    let folder = tempfile::tempdir().unwrap();
    let context = arm(&manager, &transport);
    assert!(tokio::runtime::Handle::try_current().is_err());
    let ticket = manager
        .capture_file_drop(runtime.handle(), "main", sources(folder.path(), 1), Some((0.5, 0.5)))
        .unwrap()
        .ticket_id
        .unwrap();
    assert_eq!(runtime.block_on(consume(&manager, &context, &ticket)).unwrap().accepted, 1);
}

#[tokio::test]
async fn native_enter_count_survives_over_and_leave_does_not_cancel_drop() {
    let (manager, transport, _) = ready();
    let context = arm(&manager, &transport);
    let entered = manager.begin_file_drag("main", 2, Some((0.8, 0.5))).unwrap();
    assert_eq!((entered.phase, entered.count), (FileDragPhase::Over, 2));
    let over = manager.file_drag("main", FileDragPhase::Over, Some((0.9, 0.5))).unwrap();
    assert_eq!((over.phase, over.count), (FileDragPhase::Over, 2));
    let folder = tempfile::tempdir().unwrap();
    let ticket = manager
        .capture_file_drop(
            &tokio::runtime::Handle::current(),
            "main",
            sources(folder.path(), 2),
            Some((0.9, 0.5)),
        )
        .unwrap()
        .ticket_id
        .unwrap();
    assert_eq!(manager.file_drag("main", FileDragPhase::Leave, None).unwrap().count, 0);
    assert_eq!(consume(&manager, &context, &ticket).await.unwrap().accepted, 2);
    assert_eq!(
        manager.file_drag("main", FileDragPhase::Over, Some((0.9, 0.5))).unwrap().phase,
        FileDragPhase::Refused
    );
    assert_eq!(manager.begin_file_drag("main", usize::MAX, Some((0.8, 0.5))).unwrap().count, 17);
}

#[tokio::test]
async fn one_and_sixteen_file_batches_keep_order_and_frozen_destination_after_view_revoke() {
    for count in [1, 16] {
        let (manager, transport, mut requests) = ready();
        let folder = tempfile::tempdir().unwrap();
        let context = arm(&manager, &transport);
        let event = manager
            .capture_file_drop(
                &tokio::runtime::Handle::current(),
                "main",
                sources(folder.path(), count),
                Some((0.8, 0.5)),
            )
            .unwrap();
        assert_eq!(event.phase, FileDragPhase::Drop);
        assert_eq!(event.count, count as u32);
        assert_eq!(
            consume(&manager, &context, event.ticket_id.as_ref().unwrap()).await.unwrap().accepted,
            count as u32
        );
        manager.revoke_file_drop("main", &context);
        let snapshot = manager.transfer_queue_snapshot("terminal").unwrap();
        assert_eq!(snapshot.outstanding, count as u32);
        assert_eq!(
            snapshot.items.iter().map(|item| item.name.clone()).collect::<Vec<_>>(),
            (0..count).map(|n| format!("{n}.bin")).collect::<Vec<_>>()
        );
        let mut sessions = manager.sessions.lock().unwrap();
        let entry = sessions.get_mut("terminal").unwrap();
        for n in 0..count {
            let selected = entry.transfers.take_next(Uuid::parse_str(&transport).unwrap()).unwrap();
            let SelectedTransfer::Upload { source, directory, .. } = selected.resources else {
                panic!()
            };
            assert_eq!(directory, b"./original");
            assert_eq!(
                source.target(&directory).unwrap(),
                format!("./original/{n}.bin").as_bytes()
            );
            entry.transfers.finish(
                selected.identity,
                crate::session_transfers::TransferCompletion {
                    state: crate::session_transfers::SessionTransferState::Saved,
                    issue: None,
                    staging_may_remain: false,
                },
            );
        }
        assert!(requests.try_recv().is_err());
    }
}

#[tokio::test]
async fn rejected_later_source_duplicate_directory_and_link_leave_no_partial_batch() {
    let folder = tempfile::tempdir().unwrap();
    let ordinary = sources(folder.path(), 1).remove(0);
    let same = folder.path().join("nested");
    std::fs::create_dir(&same).unwrap();
    std::fs::write(same.join("0.bin"), b"duplicate target").unwrap();
    let mut cases = vec![
        vec![ordinary.clone(), folder.path().join("missing")],
        vec![ordinary.clone(), same.clone()],
        vec![ordinary.clone(), same.join("0.bin")],
    ];
    #[cfg(windows)]
    {
        let link = folder.path().join("link.bin");
        std::os::windows::fs::symlink_file(&ordinary, &link).unwrap();
        cases.push(vec![ordinary.clone(), link]);
    }
    #[cfg(unix)]
    {
        let link = folder.path().join("link.bin");
        std::os::unix::fs::symlink(&ordinary, &link).unwrap();
        cases.push(vec![ordinary.clone(), link]);
        let fifo = folder.path().join("special");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        cases.push(vec![ordinary.clone(), fifo]);
    }
    for paths in cases {
        let (manager, transport, mut requests) = ready();
        let context = arm(&manager, &transport);
        let ticket = manager
            .capture_file_drop(&tokio::runtime::Handle::current(), "main", paths, Some((0.9, 0.5)))
            .unwrap()
            .ticket_id
            .unwrap();
        assert!(consume(&manager, &context, &ticket).await.is_err());
        assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 0);
        assert!(manager.transfer_queue_snapshot("terminal").unwrap().items.is_empty());
        assert!(requests.try_recv().is_err());
        // No native selection permit or retained file prevents a following valid admission.
        let ticket = manager
            .capture_file_drop(
                &tokio::runtime::Handle::current(),
                "main",
                vec![ordinary.clone()],
                Some((0.9, 0.5)),
            )
            .unwrap()
            .ticket_id
            .unwrap();
        assert_eq!(consume(&manager, &context, &ticket).await.unwrap().accepted, 1);
    }
}

#[tokio::test(start_paused = true)]
async fn tickets_expire_at_thirty_seconds_are_single_use_and_bound_to_window_and_context() {
    let (manager, transport, _) = ready();
    let folder = tempfile::tempdir().unwrap();
    let paths = sources(folder.path(), 1);
    let context = arm(&manager, &transport);
    let first = manager
        .capture_file_drop(
            &tokio::runtime::Handle::current(),
            "main",
            paths.clone(),
            Some((0.5, 0.5)),
        )
        .unwrap()
        .ticket_id
        .unwrap();
    assert!(
        manager.consume_file_drop("other", &context, &first, |_| async { Ok(true) }).await.is_err()
    );
    assert!(consume(&manager, &Uuid::now_v7().to_string(), &first).await.is_err());
    tokio::time::advance(Duration::from_secs(30)).await;
    tokio::task::yield_now().await;
    assert_eq!(consume(&manager, &context, &first).await, Err(SessionTransferIssue::StaleItem));
    assert!(manager.drops.lock().unwrap().get("main").unwrap().ticket.is_none());
    tokio::time::resume();
    let ticket = manager
        .capture_file_drop(&tokio::runtime::Handle::current(), "main", paths, Some((0.5, 0.5)))
        .unwrap()
        .ticket_id
        .unwrap();
    // Leave following Drop preserves the ticket.
    manager.file_drag("main", FileDragPhase::Leave, None).unwrap();
    assert_eq!(consume(&manager, &context, &ticket).await.unwrap().accepted, 1);
    assert_eq!(consume(&manager, &context, &ticket).await, Err(SessionTransferIssue::StaleItem));
}

#[test]
fn asynchronous_admission_releases_the_whole_batch_after_context_expiry_or_cancellation() {
    for scenario in 0..6 {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let (manager, transport, mut requests) = ready();
            let folder = tempfile::tempdir().unwrap();
            let paths = sources(folder.path(), 2);
            let context = arm(&manager, &transport);
            let ticket = manager
                .capture_file_drop(
                    &tokio::runtime::Handle::current(),
                    "main",
                    paths.clone(),
                    Some((0.5, 0.5)),
                )
                .unwrap()
                .ticket_id
                .unwrap();
            let (entered, started) = oneshot::channel();
            let (release, waiting) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                waiting.recv().unwrap();
            });
            started.await.unwrap();
            let owner = manager.clone();
            let view = context.clone();
            let selection = ticket.clone();
            let admission = tokio::spawn(async move { consume(&owner, &view, &selection).await });
            tokio::time::timeout(Duration::from_secs(2), async {
                while manager.transfer_queue_snapshot("terminal").unwrap().outstanding != 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            match scenario {
                0 => manager.revoke_file_drop("main", &context),
                1 => manager.invalidate_file_drop("main"),
                2 => manager.cancel_file_drop("main", &context, &ticket),
                3 => {
                    manager.capture_file_drop(
                        &tokio::runtime::Handle::current(),
                        "main",
                        paths,
                        Some((0.5, 0.5)),
                    );
                }
                4 => {
                    manager
                        .sessions
                        .lock()
                        .unwrap()
                        .get_mut("terminal")
                        .unwrap()
                        .active
                        .as_mut()
                        .unwrap()
                        .ready = false;
                }
                _ => {
                    tokio::time::pause();
                    tokio::time::advance(Duration::from_secs(30)).await;
                    tokio::task::yield_now().await;
                    tokio::time::resume();
                }
            }
            release.send(()).unwrap();
            blocker.await.unwrap();
            assert!(admission.await.unwrap().is_err());
            let snapshot = manager.transfer_queue_snapshot("terminal").unwrap();
            assert_eq!(snapshot.outstanding, 0);
            assert!(snapshot.items.is_empty());
            assert!(!snapshot.picker_busy);
            assert!(requests.try_recv().is_err());
        });
    }
}

#[test]
fn absolute_ticket_expiry_releases_all_slots_while_source_open_is_still_blocked() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (manager, transport, mut requests) = ready();
        let folder = tempfile::tempdir().unwrap();
        let paths = sources(folder.path(), TRANSFER_CAPACITY);
        let context = arm(&manager, &transport);
        let (entered, started) = oneshot::channel();
        let (release, waiting) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            entered.send(()).unwrap();
            let _ = waiting.recv();
        });
        started.await.unwrap();
        tokio::time::pause();
        let ticket = manager
            .capture_file_drop(&tokio::runtime::Handle::current(), "main", paths, Some((0.5, 0.5)))
            .unwrap()
            .ticket_id
            .unwrap();
        tokio::time::advance(Duration::from_secs(29)).await;
        let owner = manager.clone();
        let admission = tokio::spawn(async move { consume(&owner, &context, &ticket).await });
        for _ in 0..128 {
            if manager.transfer_queue_snapshot("terminal").unwrap().outstanding
                == TRANSFER_CAPACITY as u32
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        let reserved = manager.transfer_queue_snapshot("terminal").unwrap().outstanding;
        tokio::task::yield_now().await;
        // Tokio rounds sleep deadlines up to its next millisecond timer tick.
        tokio::time::advance(Duration::from_millis(1001)).await;
        for _ in 0..128 {
            if admission.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let completed_before_release = admission.is_finished();
        let snapshot = manager.transfer_queue_snapshot("terminal").unwrap();
        let next_reservation = {
            let mut sessions = manager.sessions.lock().unwrap();
            let transfers = &mut sessions.get_mut("terminal").unwrap().transfers;
            let reservation = transfers
                .reserve_selections(Uuid::parse_str(&transport).unwrap(), TRANSFER_CAPACITY);
            if let Ok(reservation) = reservation {
                transfers.release_selection(reservation);
            }
            reservation
        };
        // Reclaim the blocking worker even when the deadline assertion would fail.
        release.send(()).unwrap();
        tokio::time::resume();
        blocker.await.unwrap();
        let outcome = admission.await.unwrap();
        assert_eq!(reserved, TRANSFER_CAPACITY as u32);
        assert!(completed_before_release);
        assert_eq!(outcome, Err(SessionTransferIssue::StaleItem));
        assert_eq!(snapshot.outstanding, 0);
        assert!(!snapshot.picker_busy);
        assert!(snapshot.items.is_empty());
        assert!(next_reservation.is_ok());
        assert!(requests.try_recv().is_err());
    });
}

#[tokio::test(start_paused = true)]
async fn expiry_of_obsolete_ticket_cannot_erase_a_superseding_drop() {
    let (manager, transport, _) = ready();
    let folder = tempfile::tempdir().unwrap();
    let paths = sources(folder.path(), 1);
    let context = arm(&manager, &transport);
    let first = manager
        .capture_file_drop(
            &tokio::runtime::Handle::current(),
            "main",
            paths.clone(),
            Some((0.5, 0.5)),
        )
        .unwrap()
        .ticket_id
        .unwrap();
    tokio::time::advance(Duration::from_secs(15)).await;
    let second = manager
        .capture_file_drop(&tokio::runtime::Handle::current(), "main", paths, Some((0.5, 0.5)))
        .unwrap()
        .ticket_id
        .unwrap();
    tokio::time::advance(Duration::from_secs(15)).await;
    tokio::task::yield_now().await;
    assert_eq!(consume(&manager, &context, &first).await, Err(SessionTransferIssue::StaleItem));
    tokio::time::resume();
    assert_eq!(consume(&manager, &context, &second).await.unwrap().accepted, 1);
}

#[tokio::test]
async fn superseding_drop_context_cleanup_cancellation_and_transport_change_fence_old_tickets() {
    let (manager, transport, _) = ready();
    let folder = tempfile::tempdir().unwrap();
    let paths = sources(folder.path(), 1);
    let old_context = arm(&manager, &transport);
    let old = manager
        .capture_file_drop(
            &tokio::runtime::Handle::current(),
            "main",
            paths.clone(),
            Some((0.2, 0.3)),
        )
        .unwrap()
        .ticket_id
        .unwrap();
    let new_context = arm(&manager, &transport);
    manager.revoke_file_drop("main", &old_context);
    assert!(consume(&manager, &old_context, &old).await.is_err());
    let first = manager
        .capture_file_drop(
            &tokio::runtime::Handle::current(),
            "main",
            paths.clone(),
            Some((0.2, 0.3)),
        )
        .unwrap()
        .ticket_id
        .unwrap();
    let second = manager
        .capture_file_drop(
            &tokio::runtime::Handle::current(),
            "main",
            paths.clone(),
            Some((0.2, 0.3)),
        )
        .unwrap()
        .ticket_id
        .unwrap();
    manager.cancel_file_drop("main", &old_context, &second);
    assert!(consume(&manager, &new_context, &first).await.is_err());
    manager.cancel_file_drop("main", &new_context, &second);
    assert!(consume(&manager, &new_context, &second).await.is_err());
    let next = manager
        .capture_file_drop(&tokio::runtime::Handle::current(), "main", paths, Some((0.2, 0.3)))
        .unwrap()
        .ticket_id
        .unwrap();
    manager.sessions.lock().unwrap().get_mut("terminal").unwrap().active.as_mut().unwrap().id =
        Uuid::now_v7();
    assert_eq!(
        consume(&manager, &new_context, &next).await,
        Err(SessionTransferIssue::TransportEnded)
    );
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 0);
}

#[tokio::test]
async fn full_queue_rejects_before_source_open_and_invalid_count_or_position_retains_no_ticket() {
    let (manager, transport, mut requests) = ready();
    let folder = tempfile::tempdir().unwrap();
    let context = arm(&manager, &transport);
    let paths = sources(folder.path(), 16);
    let ticket = manager
        .capture_file_drop(&tokio::runtime::Handle::current(), "main", paths, Some((0.2, 0.3)))
        .unwrap()
        .ticket_id
        .unwrap();
    consume(&manager, &context, &ticket).await.unwrap();
    // This source does not exist: capacity, rather than an open failure, must reject first.
    let ticket = manager
        .capture_file_drop(
            &tokio::runtime::Handle::current(),
            "main",
            vec![folder.path().join("missing")],
            Some((0.2, 0.3)),
        )
        .unwrap()
        .ticket_id
        .unwrap();
    assert_eq!(consume(&manager, &context, &ticket).await, Err(SessionTransferIssue::QueueFull));
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 16);
    assert!(requests.try_recv().is_err());
    for (paths, position) in [
        (vec![], Some((0.5, 0.5))),
        (vec![folder.path().to_path_buf(); 17], Some((0.5, 0.5))),
        (vec![folder.path().to_path_buf()], Some((f64::NAN, 0.5))),
        (vec![folder.path().to_path_buf()], Some((1.0, 0.5))),
    ] {
        let event = manager
            .capture_file_drop(&tokio::runtime::Handle::current(), "main", paths, position)
            .unwrap();
        assert_eq!(event.phase, FileDragPhase::Refused);
        assert!(event.ticket_id.is_none());
        assert!(event.count <= 17);
    }
}

#[tokio::test]
async fn invalid_combined_remote_target_rejects_every_source_before_dispatch() {
    let (manager, transport, mut requests) = ready();
    let folder = tempfile::tempdir().unwrap();
    let context = Uuid::now_v7().to_string();
    manager
        .arm_file_drop(
            "main",
            &context,
            "terminal",
            &transport,
            &manager.transfer_queue_snapshot("terminal").unwrap().queue_id,
            vec![b'x'; 4096],
        )
        .unwrap();
    let ticket = manager
        .capture_file_drop(
            &tokio::runtime::Handle::current(),
            "main",
            sources(folder.path(), 2),
            Some((0.5, 0.5)),
        )
        .unwrap()
        .ticket_id
        .unwrap();
    assert_eq!(consume(&manager, &context, &ticket).await, Err(SessionTransferIssue::InvalidPath));
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 0);
    assert!(requests.try_recv().is_err());
}

#[tokio::test]
async fn admitted_drop_uses_the_existing_worker_and_unknown_results_are_never_replayed() {
    use crate::session_transfers::SessionTransferState;
    let (manager, transport, mut requests) = ready();
    {
        let mut sessions = manager.sessions.lock().unwrap();
        let entry = sessions.get_mut("terminal").unwrap();
        entry.transfer_worker_running = false;
        entry.active.as_mut().unwrap().context = Some(PreparationContext {
            profile_id: Uuid::now_v7().to_string(),
            host_id: Uuid::now_v7().to_string(),
            login: "fixture".into(),
            host: "bound fixture".into(),
            username: "operator".into(),
            address: "fixture.example".into(),
            port: 22,
            position: 1,
            total: 1,
            target: true,
        });
    }
    let context = arm(&manager, &transport);
    let folder = tempfile::tempdir().unwrap();
    let ticket = manager
        .capture_file_drop(
            &tokio::runtime::Handle::current(),
            "main",
            sources(folder.path(), 1),
            Some((0.5, 0.5)),
        )
        .unwrap()
        .ticket_id
        .unwrap();
    consume(&manager, &context, &ticket).await.unwrap();
    let FileCommand::PreflightUpload { reply, .. } = requests.recv().await.unwrap() else {
        panic!()
    };
    reply.send(Ok(UploadPreflight { target_attributes: None, replacement_supported: true })).ok();
    let FileCommand::TransferUpload { reply, .. } = requests.recv().await.unwrap() else {
        panic!()
    };
    reply
        .send(UploadExecution::Failed {
            error: FileAccessError::PublicationUnknown,
            staging_may_remain: false,
        })
        .ok();
    let snapshot = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = manager.transfer_queue_snapshot("terminal").unwrap();
            if snapshot
                .items
                .first()
                .is_some_and(|item| item.state == SessionTransferState::Unknown)
            {
                break snapshot;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(snapshot.outstanding, 1);
    let item = &snapshot.items[0];
    manager
        .acknowledge_transfer("terminal", &snapshot.queue_id, &item.item_id, &item.execution_id)
        .unwrap();
    assert_eq!(manager.transfer_queue_snapshot("terminal").unwrap().outstanding, 0);
    assert!(consume(&manager, &context, &ticket).await.is_err());
    assert!(requests.try_recv().is_err());
}
