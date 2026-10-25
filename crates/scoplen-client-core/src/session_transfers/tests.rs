// SPDX-License-Identifier: Apache-2.0

use super::*;

fn queued(queue: &mut TransferQueue<usize>, transport: Uuid, value: usize) -> TransferIdentity {
    let selected = queue.reserve_selection(transport).unwrap();
    let SessionTransferEnqueueResult::Queued { item_id, execution_id, .. } = queue
        .enqueue_selected(selected, "file.bin", SessionTransferDirection::Upload, Some(64), value)
        .unwrap()
    else {
        panic!("selection should have queued a transfer");
    };
    TransferIdentity {
        item: Uuid::parse_str(&item_id).unwrap(),
        execution: Uuid::parse_str(&execution_id).unwrap(),
        transport,
    }
}

fn complete(state: SessionTransferState) -> TransferCompletion {
    TransferCompletion { state, issue: None, staging_may_remain: false }
}

#[test]
fn upload_pause_requires_admitted_read_capability_and_keeps_fifo_and_execution_fences() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let original = queued(&mut queue, transport, 10);
    queue.take_next(transport).unwrap();
    assert!(!queue.snapshot("session").items[0].can_pause);
    assert!(queue.pause(queue.id(), original.item, original.execution).is_err());
    queue.admit_upload_pause(original);
    assert!(queue.snapshot("session").items[0].can_pause);
    queue.progress(
        original,
        FileTransferProgress {
            transferred: 32,
            total: Some(64),
            phase: SessionFileTransferPhase::Transferring,
        },
    );
    queue.pause(queue.id(), original.item, original.execution).unwrap();
    queue.retain_paused(original, 10).unwrap();
    let later = queued(&mut queue, transport, 20);
    queue.resume(queue.id(), original.item, original.execution, transport).unwrap();
    assert_eq!(queue.snapshot("session").outstanding, 2);
    assert_eq!(queue.take_next(transport).unwrap().identity, later);
    queue.finish(later, complete(SessionTransferState::Saved));
    let resumed = queue.take_next(transport).unwrap();
    assert_eq!(resumed.identity.item, original.item);
    assert_ne!(resumed.identity.execution, original.execution);
    queue.progress(
        original,
        FileTransferProgress {
            transferred: 64,
            total: Some(64),
            phase: SessionFileTransferPhase::Finalizing,
        },
    );
    queue.admit_upload_pause(original);
    let row = &queue.snapshot("session").items[0];
    assert_eq!(row.state, SessionTransferState::Validating);
    assert_eq!(row.transferred_bytes, "32");
    assert!(!row.can_pause);
    assert!(!queue.finish(original, complete(SessionTransferState::Saved)));
}

#[test]
fn paused_uploads_keep_all_capacity_until_cleanup_settlement() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let mut first = None;
    for value in 0..TRANSFER_CAPACITY {
        let identity = queued(&mut queue, transport, value);
        queue.take_next(transport).unwrap();
        queue.admit_upload_pause(identity);
        queue.pause(queue.id(), identity.item, identity.execution).unwrap();
        queue.retain_paused(identity, value).unwrap();
        first.get_or_insert(identity);
    }
    assert_eq!(queue.reserve_selection(transport), Err(SessionTransferIssue::QueueFull));
    let first = first.unwrap();
    let CancelTransfer::Cleanup(identity, _) =
        queue.cancel(queue.id(), first.item, first.execution).unwrap()
    else {
        panic!()
    };
    assert_eq!(queue.snapshot("session").outstanding, TRANSFER_CAPACITY as u32);
    queue.finish_cleanup(identity, complete(SessionTransferState::Cancelled));
    assert!(queue.reserve_selection(transport).is_ok());
}

#[test]
fn batch_reservation_holds_every_slot_and_appends_contiguously_in_order() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    queued(&mut queue, transport, 0);
    let selection = queue.reserve_selections(transport, 15).unwrap();
    assert_eq!(queue.snapshot("session").outstanding, 16);
    assert_eq!(queue.reserve_selection(transport), Err(SessionTransferIssue::QueueFull));
    queue
        .enqueue_upload_batch(
            selection,
            (1..16).map(|value| (format!("{value}.bin"), 64, value)).collect(),
        )
        .unwrap();
    assert_eq!(queue.snapshot("session").outstanding, 16);
    for value in 0..16 {
        let selected = queue.take_next(transport).unwrap();
        assert_eq!(selected.resources, value);
        queue.finish(selected.identity, complete(SessionTransferState::Saved));
    }
    assert!(queue.take_next(transport).is_none());
}

#[test]
fn failed_or_obsolete_batch_reservations_add_nothing_and_release_every_slot() {
    let mut queue = TransferQueue::<usize>::default();
    let transport = Uuid::now_v7();
    assert_eq!(queue.reserve_selections(transport, 0), Err(SessionTransferIssue::InvalidSelection));
    assert_eq!(
        queue.reserve_selections(transport, 17),
        Err(SessionTransferIssue::InvalidSelection)
    );
    let reservation = queue.reserve_selections(transport, 16).unwrap();
    assert_eq!(
        queue.enqueue_upload_batch(reservation, vec![("short".into(), 1, 0)]),
        Err(SessionTransferIssue::InvalidSelection)
    );
    assert!(queue.snapshot("session").items.is_empty());
    queue.release_selection(reservation);
    assert_eq!(queue.snapshot("session").outstanding, 0);
    let reservation = queue.reserve_selections(transport, 16).unwrap();
    queue.interrupt_transport(transport);
    assert_eq!(
        queue.enqueue_upload_batch(
            reservation,
            (0..16).map(|value| ("file".into(), 1, value)).collect()
        ),
        Err(SessionTransferIssue::TransportEnded)
    );
    assert_eq!(queue.snapshot("session").outstanding, 0);
}

fn paused(queue: &mut TransferQueue<usize>, transport: Uuid, resource: usize) -> TransferIdentity {
    let selection = queue.reserve_selection(transport).unwrap();
    queue
        .enqueue_selected(
            selection,
            "source.bin",
            SessionTransferDirection::Download,
            Some(64),
            resource,
        )
        .unwrap();
    let selected = queue.take_next(transport).unwrap();
    queue.progress(
        selected.identity,
        FileTransferProgress {
            transferred: 32,
            total: Some(64),
            phase: SessionFileTransferPhase::Transferring,
        },
    );
    queue.pause(queue.id(), selected.identity.item, selected.identity.execution).unwrap();
    queue.retain_paused(selected.identity, selected.resources).unwrap();
    selected.identity
}

#[test]
fn paused_download_releases_execution_and_explicit_resume_enters_fifo_with_a_fresh_execution() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let checkpoint = paused(&mut queue, transport, 10);
    assert!(!queue.blocks_file_operations());
    assert_eq!(queue.snapshot("session").outstanding, 1);
    assert!(queue.snapshot("session").items[0].can_resume);
    let second = queued(&mut queue, transport, 20);
    let third = queued(&mut queue, transport, 30);
    assert_eq!(queue.take_next(transport).unwrap().identity, second);
    queue.resume(queue.id(), checkpoint.item, checkpoint.execution, transport).unwrap();
    assert!(queue.finish(second, complete(SessionTransferState::Saved)));
    assert_eq!(queue.take_next(transport).unwrap().identity, third);
    assert!(queue.finish(third, complete(SessionTransferState::Saved)));
    let resumed = queue.take_next(transport).unwrap();
    assert_eq!(resumed.identity.item, checkpoint.item);
    assert_ne!(resumed.identity.execution, checkpoint.execution);
    assert_eq!(resumed.resources, 10);
    assert_eq!(queue.snapshot("session").items[0].state, SessionTransferState::Validating);
    assert!(!queue.finish(checkpoint, complete(SessionTransferState::Saved)));
    assert!(matches!(
        queue.cancel(queue.id(), checkpoint.item, checkpoint.execution),
        Err(SessionTransferIssue::StaleItem)
    ));
    assert!(queue.resume(queue.id(), checkpoint.item, checkpoint.execution, transport).is_err());
}

#[test]
fn paused_download_capacity_is_not_released_until_owned_cleanup_settles() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let first = paused(&mut queue, transport, 0);
    for value in 1..TRANSFER_CAPACITY {
        paused(&mut queue, transport, value);
    }
    assert_eq!(queue.reserve_selection(transport), Err(SessionTransferIssue::QueueFull));
    let CancelTransfer::Cleanup(identity, resources) =
        queue.cancel(queue.id(), first.item, first.execution).unwrap()
    else {
        panic!()
    };
    assert_eq!(identity, first);
    assert_eq!(resources, 0);
    assert_eq!(queue.snapshot("session").outstanding, 16);
    queue.finish_cleanup(identity, complete(SessionTransferState::Cancelled));
    assert_eq!(queue.snapshot("session").outstanding, 15);
    queue.reserve_selection(transport).unwrap();
}

#[test]
fn transport_expiry_collects_paused_checkpoints_for_cleanup_without_replay() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let first = paused(&mut queue, transport, 41);
    queue.interrupt_transport(transport);
    assert_eq!(queue.snapshot("session").outstanding, 1);
    assert!(!queue.snapshot("session").items[0].can_resume);
    assert!(queue.resume(queue.id(), first.item, first.execution, Uuid::now_v7()).is_err());
    let (cleanup, interrupted) = queue.take_cleanup().unwrap();
    assert!(interrupted);
    assert_eq!(cleanup.resources, 41);
    queue.finish_cleanup(cleanup.identity, complete(SessionTransferState::Interrupted));
    assert_eq!(queue.snapshot("session").outstanding, 0);
    assert!(queue.take_next(Uuid::now_v7()).is_none());
}

#[test]
fn an_accepted_pause_survives_replacement_confirmation_before_dispatch() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let selection = queue.reserve_selection(transport).unwrap();
    queue
        .enqueue_selected(selection, "source.bin", SessionTransferDirection::Download, Some(64), 1)
        .unwrap();
    let selected = queue.take_next(transport).unwrap();
    let identity = selected.identity;
    queue.pause(queue.id(), identity.item, identity.execution).unwrap();
    queue.begin_confirmation(identity).unwrap();
    assert!(queue.snapshot("session").picker_busy);
    assert_eq!(queue.snapshot("session").items[0].state, SessionTransferState::Pausing);
    queue.end_confirmation(identity);
    assert!(queue.is_pausing(identity));
    assert!(!queue.snapshot("session").picker_busy);
    queue.retain_paused(identity, selected.resources).unwrap();
    assert!(queue.snapshot("session").items[0].can_resume);
}

#[test]
fn a_late_pause_request_does_not_hide_finalization_or_cross_publication() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let selection = queue.reserve_selection(transport).unwrap();
    queue
        .enqueue_selected(selection, "source.bin", SessionTransferDirection::Download, Some(64), 1)
        .unwrap();
    let identity = queue.take_next(transport).unwrap().identity;
    queue.pause(queue.id(), identity.item, identity.execution).unwrap();
    queue.progress(
        identity,
        FileTransferProgress {
            transferred: 64,
            total: Some(64),
            phase: SessionFileTransferPhase::Finalizing,
        },
    );
    let row = &queue.snapshot("session").items[0];
    assert_eq!(row.state, SessionTransferState::Finalizing);
    assert!(!row.can_pause);
    assert!(row.can_cancel);
    queue.begin_publication(identity).unwrap();
    assert!(!queue.snapshot("session").items[0].can_cancel);
    assert_eq!(
        queue.pause(queue.id(), identity.item, identity.execution),
        Err(SessionTransferIssue::PublicationStarted)
    );
}

#[test]
fn selection_reserves_capacity_and_uses_one_native_dialog() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    for value in 0..TRANSFER_CAPACITY - 1 {
        queued(&mut queue, transport, value);
    }
    let selection = queue.reserve_selection(transport).unwrap();
    let snapshot = queue.snapshot("session");
    assert_eq!(snapshot.outstanding, 16);
    assert!(snapshot.picker_busy);
    assert!(snapshot.blocks_file_operations);
    assert_eq!(queue.reserve_selection(transport), Err(SessionTransferIssue::QueueFull));
    queue.release_selection(selection);
    assert_eq!(queue.snapshot("session").outstanding, 15);
    let selection = queue.reserve_selection(transport).unwrap();
    queue.release_selection(selection);

    let mut empty = TransferQueue::<usize>::default();
    empty.reserve_selection(transport).unwrap();
    assert_eq!(empty.reserve_selection(transport), Err(SessionTransferIssue::NativeDialogBusy));
}

#[test]
fn dispatch_is_fifo_with_exactly_one_owned_execution() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let first = queued(&mut queue, transport, 11);
    let second = queued(&mut queue, transport, 22);
    let first_run = queue.take_next(transport).unwrap();
    assert_eq!(first_run.identity, first);
    assert_eq!(first_run.resources, 11);
    assert!(queue.take_next(transport).is_none());
    assert!(queue.finish(first, complete(SessionTransferState::Saved)));
    let second_run = queue.take_next(transport).unwrap();
    assert_eq!(second_run.identity, second);
    assert_eq!(second_run.resources, 22);
    assert!(!queue.finish(first, complete(SessionTransferState::Failed)));
}

#[test]
fn unknown_results_occupy_capacity_until_explicit_acknowledgement() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let identity = queued(&mut queue, transport, 0);
    queue.take_next(transport).unwrap();
    assert!(queue.finish(identity, complete(SessionTransferState::Unknown)));
    for value in 1..TRANSFER_CAPACITY {
        queued(&mut queue, transport, value);
    }
    assert_eq!(queue.reserve_selection(transport), Err(SessionTransferIssue::QueueFull));
    let snapshot = queue.snapshot("session");
    assert_eq!(snapshot.items[0].state, SessionTransferState::Unknown);
    assert!(snapshot.items[0].can_acknowledge);
    assert!(!snapshot.items[0].can_cancel);
    let id = Uuid::parse_str(&snapshot.queue_id).unwrap();
    assert!(matches!(
        queue.cancel(id, identity.item, identity.execution),
        Err(SessionTransferIssue::PublicationUnknown)
    ));
    queue.acknowledge(id, identity.item, identity.execution).unwrap();
    assert_eq!(queue.snapshot("session").outstanding, 15);
    assert!(queue.snapshot("session").recent.is_empty());
    assert_eq!(queue.take_next(transport).unwrap().resources, 1);
}

#[test]
fn confirmed_history_is_bounded_without_evicting_unknown_items() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let unknown = queued(&mut queue, transport, 99);
    queue.take_next(transport).unwrap();
    queue.finish(unknown, complete(SessionTransferState::Unknown));
    for value in 0..50 {
        let identity = queued(&mut queue, transport, value);
        queue.take_next(transport).unwrap();
        queue.finish(identity, complete(SessionTransferState::Saved));
    }
    let snapshot = queue.snapshot("session");
    assert_eq!(snapshot.items.len(), 1);
    assert_eq!(snapshot.items[0].item_id, unknown.item.to_string());
    assert_eq!(snapshot.recent.len(), 32);
    assert!(snapshot.recent.iter().all(|row| row.state == SessionTransferState::Saved));
}

#[test]
fn cancelling_a_queued_item_releases_resources_without_dispatch() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let first = queued(&mut queue, transport, 1);
    let second = queued(&mut queue, transport, 2);
    let queue_id = Uuid::parse_str(&queue.snapshot("session").queue_id).unwrap();
    assert!(matches!(
        queue.cancel(queue_id, first.item, first.execution).unwrap(),
        CancelTransfer::Queued(1)
    ));
    assert_eq!(queue.take_next(transport).unwrap().identity, second);
    assert_eq!(queue.snapshot("session").recent[0].state, SessionTransferState::Cancelled);
    assert!(matches!(
        queue.cancel(queue_id, first.item, first.execution).unwrap(),
        CancelTransfer::Settled
    ));
}

#[test]
fn cancellation_cannot_cross_publication_or_another_execution() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let identity = queued(&mut queue, transport, 1);
    queue.take_next(transport).unwrap();
    let queue_id = Uuid::parse_str(&queue.snapshot("session").queue_id).unwrap();
    assert!(matches!(
        queue.cancel(queue_id, identity.item, Uuid::now_v7()),
        Err(SessionTransferIssue::StaleItem)
    ));
    queue.begin_publication(identity).unwrap();
    assert!(matches!(
        queue.cancel(queue_id, identity.item, identity.execution),
        Err(SessionTransferIssue::PublicationStarted)
    ));
    assert!(!queue.snapshot("session").items[0].can_cancel);
}

#[test]
fn native_confirmation_and_selection_share_the_same_permit() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let identity = queued(&mut queue, transport, 1);
    queue.take_next(transport).unwrap();
    let selection = queue.reserve_selection(transport).unwrap();
    assert_eq!(queue.begin_confirmation(identity), Err(SessionTransferIssue::NativeDialogBusy));
    queue.release_selection(selection);
    queue.begin_confirmation(identity).unwrap();
    assert_eq!(queue.reserve_selection(transport), Err(SessionTransferIssue::NativeDialogBusy));
    assert!(queue.snapshot("session").picker_busy);
    assert_eq!(queue.snapshot("session").outstanding, 1);
    queue.end_confirmation(TransferIdentity { execution: Uuid::now_v7(), ..identity });
    assert!(queue.snapshot("session").picker_busy);
    queue.end_confirmation(identity);
    assert!(!queue.snapshot("session").picker_busy);
}

#[test]
fn interrupted_selection_does_not_release_an_open_os_dialog_early() {
    let mut queue = TransferQueue::<usize>::default();
    let transport = Uuid::now_v7();
    let selection = queue.reserve_selection(transport).unwrap();
    queue.interrupt_transport(transport);
    assert!(queue.snapshot("session").picker_busy);
    assert_eq!(
        queue.reserve_selection(Uuid::now_v7()),
        Err(SessionTransferIssue::NativeDialogBusy)
    );
    assert_eq!(
        queue.enqueue_selected(selection, "late.bin", SessionTransferDirection::Upload, Some(1), 7),
        Err(SessionTransferIssue::TransportEnded)
    );
    assert!(!queue.snapshot("session").picker_busy);
    assert_eq!(queue.snapshot("session").outstanding, 0);
}

#[test]
fn transport_loss_interrupts_unstarted_items_without_moving_them_to_a_new_connection() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let first = queued(&mut queue, transport, 1);
    let second = queued(&mut queue, transport, 2);
    queue.take_next(transport).unwrap();
    let interrupted = queue.interrupt_transport(transport);
    assert_eq!(interrupted.running, Some(first));
    assert_eq!(interrupted.selected, [2]);
    assert!(queue.take_next(Uuid::now_v7()).is_none());
    let snapshot = queue.snapshot("session");
    assert_eq!(snapshot.recent[0].item_id, second.item.to_string());
    assert_eq!(snapshot.recent[0].state, SessionTransferState::Interrupted);
    assert_eq!(snapshot.items[0].state, SessionTransferState::Cancelling);
}

#[test]
fn progress_is_decimal_and_ignores_old_cancelled_and_regressing_frames() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let identity = queued(&mut queue, transport, 1);
    queue.take_next(transport).unwrap();
    let large = 9_007_199_254_740_993;
    let update = FileTransferProgress {
        transferred: large,
        total: Some(large + 1),
        phase: SessionFileTransferPhase::Transferring,
    };
    queue.progress(TransferIdentity { execution: Uuid::now_v7(), ..identity }, update);
    assert_eq!(queue.snapshot("session").items[0].transferred_bytes, "0");
    queue.progress(identity, update);
    assert_eq!(queue.snapshot("session").items[0].transferred_bytes, large.to_string());
    queue.progress(identity, FileTransferProgress { transferred: 1, ..update });
    assert_eq!(queue.snapshot("session").items[0].transferred_bytes, large.to_string());
    let queue_id = Uuid::parse_str(&queue.snapshot("session").queue_id).unwrap();
    assert!(matches!(
        queue.cancel(queue_id, identity.item, identity.execution).unwrap(),
        CancelTransfer::Running(current) if current == identity
    ));
    queue.progress(identity, FileTransferProgress { transferred: large + 1, ..update });
    assert_eq!(queue.snapshot("session").items[0].transferred_bytes, large.to_string());
    assert_eq!(queue.begin_publication(identity), Err(SessionTransferIssue::StaleItem));
}

#[test]
fn snapshots_are_bounded_and_never_serialize_private_resources() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let selection = queue.reserve_selection(transport).unwrap();
    queue
        .enqueue_selected(
            selection,
            &format!("file\n\u{202e}{}", "a".repeat(500)),
            SessionTransferDirection::Download,
            None,
            "private-native-location-and-open-handle",
        )
        .unwrap();
    let snapshot = queue.snapshot("session");
    assert!(snapshot.items[0].name.chars().count() <= MAX_NAME_CHARACTERS);
    assert!(!snapshot.items[0].name.contains(['\n', '\u{202e}']));
    let encoded = serde_json::to_string(&snapshot).unwrap();
    assert!(!encoded.contains("private-native-location-and-open-handle"));
    assert!(snapshot.revision.parse::<u64>().unwrap() > 0);
}

#[test]
fn an_unknown_publication_does_not_free_a_still_open_native_dialog() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let identity = queued(&mut queue, transport, 1);
    queue.take_next(transport).unwrap();
    queue.begin_confirmation(identity).unwrap();
    queue.interrupt_transport(transport);
    queue.finish(identity, complete(SessionTransferState::Unknown));
    assert!(queue.snapshot("session").picker_busy);
    assert!(queue.snapshot("session").blocks_file_operations);
    assert_eq!(
        queue.reserve_selection(Uuid::now_v7()),
        Err(SessionTransferIssue::NativeDialogBusy)
    );
    queue.end_confirmation(identity);
    let snapshot = queue.snapshot("session");
    assert!(!snapshot.picker_busy);
    assert!(!snapshot.blocks_file_operations);
    assert_eq!(snapshot.outstanding, 1);
    assert_eq!(snapshot.items[0].state, SessionTransferState::Unknown);
}

#[test]
fn finalizing_all_bytes_never_fabricates_a_successful_save() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let identity = queued(&mut queue, transport, 1);
    queue.take_next(transport).unwrap();
    queue.progress(
        identity,
        FileTransferProgress {
            transferred: 64,
            total: Some(64),
            phase: SessionFileTransferPhase::Finalizing,
        },
    );
    let snapshot = queue.snapshot("session");
    assert_eq!(snapshot.items[0].state, SessionTransferState::Finalizing);
    assert!(snapshot.recent.is_empty());
    queue.begin_publication(identity).unwrap();
    queue.finish(
        identity,
        TransferCompletion {
            state: SessionTransferState::Failed,
            issue: Some(SessionTransferIssue::LocalIo),
            staging_may_remain: false,
        },
    );
    let snapshot = queue.snapshot("session");
    assert!(snapshot.items.is_empty());
    assert_eq!(snapshot.recent[0].state, SessionTransferState::Failed);
    assert_eq!(snapshot.recent[0].issue, Some(SessionTransferIssue::LocalIo));
}

#[test]
fn a_replaced_queue_or_wrong_item_cannot_cancel_or_acknowledge_work() {
    let mut queue = TransferQueue::default();
    let transport = Uuid::now_v7();
    let identity = queued(&mut queue, transport, 1);
    let before = queue.snapshot("session");
    assert!(matches!(
        queue.cancel(Uuid::now_v7(), identity.item, identity.execution),
        Err(SessionTransferIssue::StaleItem)
    ));
    assert_eq!(
        queue.acknowledge(Uuid::now_v7(), identity.item, identity.execution),
        Err(SessionTransferIssue::StaleItem)
    );
    assert_eq!(queue.snapshot("session"), before);
}
