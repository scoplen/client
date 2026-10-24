// SPDX-License-Identifier: Apache-2.0

use futures_util::future::AbortRegistration;
use tokio::sync::Notify;

use crate::connection::preparation::PreparationContext;
use crate::session_files::{FileAccessError, SessionDownloadStatus};
use crate::session_transfers::{
    CancelTransfer, DispatchedTransfer, DownloadDestination, ReplaceConfirmation, SelectedTransfer,
    SelectionReservation, SessionTransferDirection, SessionTransferEnqueueResult,
    SessionTransferIssue, SessionTransferQueueSnapshot, SessionTransferReview,
    SessionTransferState, TransferCompletion, TransferIdentity,
};

use super::*;

pub(super) struct SelectionLease {
    pub(super) manager: SessionManager,
    pub(super) session: String,
    pub(super) reservation: SelectionReservation,
}

impl Drop for SelectionLease {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.manager.sessions.lock()
            && let Some(entry) = sessions.get_mut(&self.session)
        {
            entry.transfers.release_selection(self.reservation);
            entry.transfer_notify.notify_one();
        }
    }
}

struct ConfirmationLease {
    manager: SessionManager,
    session: String,
    queue: Uuid,
    identity: TransferIdentity,
}

impl Drop for ConfirmationLease {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.manager.sessions.lock()
            && let Some(entry) = sessions.get_mut(&self.session)
            && entry.transfers.id() == self.queue
        {
            entry.transfers.end_confirmation(self.identity);
            entry.transfer_notify.notify_one();
        }
    }
}

struct TransferExecution {
    selected: DispatchedTransfer<SelectedTransfer>,
    context: PreparationContext,
    abort: AbortHandle,
    cancellation: AbortRegistration,
    state: Arc<UploadState>,
}

enum TransferExecutionResult {
    Finished(TransferCompletion),
    Paused(SelectedTransfer),
}

impl SessionManager {
    /// Request normal settlement of the running download's bounded segment.
    pub fn pause_transfer(
        &self,
        session_id: &str,
        queue_id: &str,
        item_id: &str,
        execution_id: &str,
    ) -> Result<(), SessionTransferIssue> {
        let (queue, item, execution) = transfer_ids(queue_id, item_id, execution_id)?;
        let mut sessions =
            self.sessions.lock().map_err(|_| SessionTransferIssue::SessionUnavailable)?;
        let entry = sessions.get_mut(session_id).ok_or(SessionTransferIssue::SessionUnavailable)?;
        let active = entry
            .active
            .as_ref()
            .filter(|active| active.ready && *entry.intent.borrow() == Intent::None)
            .ok_or(SessionTransferIssue::TransportEnded)?;
        let identity = entry.transfers.pause(queue, item, execution)?;
        if active.id != identity.transport {
            return Err(SessionTransferIssue::TransportEnded);
        }
        if let Some(control) = active.file.as_ref().and_then(|file| file.download_control.as_ref())
        {
            control.send_replace(DownloadControl::Pause);
        }
        Ok(())
    }

    /// Queue explicit validated continuation of one retained checkpoint at the FIFO tail.
    pub fn resume_transfer(
        &self,
        session_id: &str,
        queue_id: &str,
        item_id: &str,
        execution_id: &str,
    ) -> Result<(), SessionTransferIssue> {
        let (queue, item, execution) = transfer_ids(queue_id, item_id, execution_id)?;
        let mut sessions =
            self.sessions.lock().map_err(|_| SessionTransferIssue::SessionUnavailable)?;
        let entry = sessions.get_mut(session_id).ok_or(SessionTransferIssue::SessionUnavailable)?;
        let active = entry
            .active
            .as_ref()
            .filter(|active| active.ready && *entry.intent.borrow() == Intent::None)
            .ok_or(SessionTransferIssue::TransportEnded)?;
        entry.transfers.resume(queue, item, execution, active.id)?;
        entry.transfer_notify.notify_one();
        drop(sessions);
        self.start_transfer_worker(session_id);
        Ok(())
    }
    /// Read the bounded state retained by one live logical terminal.
    pub fn transfer_queue_snapshot(
        &self,
        session_id: &str,
    ) -> Result<SessionTransferQueueSnapshot, SessionTransferIssue> {
        let sessions =
            self.sessions.lock().map_err(|_| SessionTransferIssue::SessionUnavailable)?;
        let entry = sessions.get(session_id).ok_or(SessionTransferIssue::SessionUnavailable)?;
        Ok(entry.transfers.snapshot(session_id))
    }

    /// Reserve capacity before native selection; the selected handle then belongs to Rust.
    pub async fn enqueue_upload_with_picker<F, Fut, C, ConfirmFut>(
        &self,
        session_id: &str,
        transport_id: &str,
        directory: Vec<u8>,
        choose_source: F,
        confirm_replace: C,
    ) -> Result<SessionTransferEnqueueResult, SessionTransferIssue>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Option<PathBuf>, SessionTransferIssue>> + Send + 'static,
        C: FnOnce(SessionTransferReview) -> ConfirmFut + Send + 'static,
        ConfirmFut: Future<Output = Result<bool, SessionTransferIssue>> + Send + 'static,
    {
        session_files::validate_path(&directory).map_err(file_issue)?;
        let (transport, reservation) = self.reserve_transfer_selection(session_id, transport_id)?;
        let manager = self.clone();
        let session = session_id.to_owned();
        // The task owns the actual picker completion even if its IPC waiter disappears.
        tokio::spawn(async move {
            let _selection =
                SelectionLease { manager: manager.clone(), session: session.clone(), reservation };
            let Some(path) = choose_source().await? else {
                return Ok(SessionTransferEnqueueResult::Cancelled);
            };
            let source = session_files::open_upload_source(&path).await.map_err(file_issue)?;
            source.target(&directory).map_err(file_issue)?;
            let name = source.display_name();
            let total = source.size();
            let resources = SelectedTransfer::Upload {
                source,
                directory,
                confirm: Box::new(move |review| Box::pin(confirm_replace(review))),
            };
            manager.enqueue_selected_transfer(
                &session,
                transport,
                reservation,
                &name,
                SessionTransferDirection::Upload,
                Some(total),
                resources,
            )
        })
        .await
        .map_err(|_| SessionTransferIssue::SelectionFailed)?
    }

    /// Retain a native-selected destination and its baseline without exposing its path.
    pub async fn enqueue_download_with_picker<F, Fut, C, ConfirmFut>(
        &self,
        session_id: &str,
        transport_id: &str,
        remote_path: Vec<u8>,
        choose_destination: F,
        confirm_replace: C,
    ) -> Result<SessionTransferEnqueueResult, SessionTransferIssue>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Option<PathBuf>, SessionTransferIssue>> + Send + 'static,
        C: FnOnce(SessionTransferReview) -> ConfirmFut + Send + 'static,
        ConfirmFut: Future<Output = Result<bool, SessionTransferIssue>> + Send + 'static,
    {
        session_files::validate_path(&remote_path).map_err(file_issue)?;
        let name = remote_path.rsplit(|byte| *byte == b'/').next().unwrap_or_default();
        if name.is_empty() || name == b"." || name == b".." {
            return Err(SessionTransferIssue::InvalidPath);
        }
        let name = String::from_utf8_lossy(name).into_owned();
        let (transport, reservation) = self.reserve_transfer_selection(session_id, transport_id)?;
        let manager = self.clone();
        let session = session_id.to_owned();
        tokio::spawn(async move {
            let _selection =
                SelectionLease { manager: manager.clone(), session: session.clone(), reservation };
            let Some(path) = choose_destination().await? else {
                return Ok(SessionTransferEnqueueResult::Cancelled);
            };
            let destination = DownloadDestination::capture(path).await?;
            let resources = SelectedTransfer::Download {
                remote_path,
                destination,
                confirm: Box::new(move |review| Box::pin(confirm_replace(review))),
            };
            manager.enqueue_selected_transfer(
                &session,
                transport,
                reservation,
                &name,
                SessionTransferDirection::Download,
                None,
                resources,
            )
        })
        .await
        .map_err(|_| SessionTransferIssue::SelectionFailed)?
    }

    /// Cancel only the item and execution named by the current snapshot.
    pub fn cancel_transfer(
        &self,
        session_id: &str,
        queue_id: &str,
        item_id: &str,
        execution_id: &str,
    ) -> Result<(), SessionTransferIssue> {
        let (queue, item, execution) = transfer_ids(queue_id, item_id, execution_id)?;
        let mut sessions =
            self.sessions.lock().map_err(|_| SessionTransferIssue::SessionUnavailable)?;
        let entry = sessions.get_mut(session_id).ok_or(SessionTransferIssue::SessionUnavailable)?;
        match entry.transfers.cancel(queue, item, execution)? {
            CancelTransfer::Queued(selected) => drop(selected),
            CancelTransfer::Cleanup(identity, resources) => {
                let manager = self.clone();
                let session = session_id.to_owned();
                drop(tokio::spawn(async move {
                    manager.settle_checkpoint(&session, queue, identity, resources, false).await;
                }));
            }
            CancelTransfer::Running(identity) => {
                if let Some(active) = &entry.active
                    && active.id == identity.transport
                    && let Some(file) = &active.file
                    && file.transfer == Some(identity)
                {
                    if let Some(control) = &file.download_control {
                        control.send_replace(DownloadControl::Cancel);
                    } else if let Some(cancel) = &file.effect_cancel {
                        cancel.send_replace(true);
                    } else {
                        file.abort.abort();
                    }
                }
            }
            CancelTransfer::Settled => {}
        }
        entry.transfer_notify.notify_one();
        Ok(())
    }

    /// Clear an unknown reminder without retrying or asserting a publication outcome.
    pub fn acknowledge_transfer(
        &self,
        session_id: &str,
        queue_id: &str,
        item_id: &str,
        execution_id: &str,
    ) -> Result<(), SessionTransferIssue> {
        let (queue, item, execution) = transfer_ids(queue_id, item_id, execution_id)?;
        let mut sessions =
            self.sessions.lock().map_err(|_| SessionTransferIssue::SessionUnavailable)?;
        let entry = sessions.get_mut(session_id).ok_or(SessionTransferIssue::SessionUnavailable)?;
        entry.transfers.acknowledge(queue, item, execution)
    }

    fn reserve_transfer_selection(
        &self,
        session_id: &str,
        transport_id: &str,
    ) -> Result<(Uuid, SelectionReservation), SessionTransferIssue> {
        let transport =
            Uuid::parse_str(transport_id).map_err(|_| SessionTransferIssue::InvalidIdentifier)?;
        let mut sessions =
            self.sessions.lock().map_err(|_| SessionTransferIssue::SessionUnavailable)?;
        let entry = sessions.get_mut(session_id).ok_or(SessionTransferIssue::SessionUnavailable)?;
        let active = entry.active.as_ref().ok_or(SessionTransferIssue::TransportEnded)?;
        if !active.ready || active.id != transport || *entry.intent.borrow() != Intent::None {
            return Err(SessionTransferIssue::TransportEnded);
        }
        Ok((transport, entry.transfers.reserve_selection(transport)?))
    }

    #[allow(clippy::too_many_arguments)]
    fn enqueue_selected_transfer(
        &self,
        session: &str,
        transport: Uuid,
        reservation: SelectionReservation,
        name: &str,
        direction: SessionTransferDirection,
        total: Option<u64>,
        resources: SelectedTransfer,
    ) -> Result<SessionTransferEnqueueResult, SessionTransferIssue> {
        let result = {
            let mut sessions =
                self.sessions.lock().map_err(|_| SessionTransferIssue::SessionUnavailable)?;
            let entry =
                sessions.get_mut(session).ok_or(SessionTransferIssue::SessionUnavailable)?;
            if entry.active.as_ref().is_none_or(|active| active.id != transport || !active.ready)
                || *entry.intent.borrow() != Intent::None
            {
                return Err(SessionTransferIssue::TransportEnded);
            }
            let result =
                entry.transfers.enqueue_selected(reservation, name, direction, total, resources)?;
            entry.transfer_notify.notify_one();
            result
        };
        self.start_transfer_worker(session);
        Ok(result)
    }

    pub(super) fn start_transfer_worker(&self, session: &str) {
        let start = {
            let Ok(mut sessions) = self.sessions.lock() else { return };
            let Some(entry) = sessions.get_mut(session) else { return };
            if entry.transfer_worker_running || !entry.transfers.has_pending() {
                return;
            }
            entry.transfer_worker_running = true;
            (entry.transfers.id(), entry.transfer_notify.clone())
        };
        let manager = self.clone();
        let session = session.to_owned();
        drop(tokio::spawn(async move {
            manager.run_transfer_queue(&session, start.0, start.1).await;
        }));
    }

    async fn run_transfer_queue(&self, session: &str, queue: Uuid, notify: Arc<Notify>) {
        loop {
            let cleanup = self.sessions.lock().ok().and_then(|mut sessions| {
                sessions
                    .get_mut(session)
                    .filter(|entry| entry.transfers.id() == queue)
                    .and_then(|entry| entry.transfers.take_cleanup())
            });
            if let Some((selected, interrupted)) = cleanup {
                self.settle_checkpoint(
                    session,
                    queue,
                    selected.identity,
                    selected.resources,
                    interrupted,
                )
                .await;
                continue;
            }
            let next = {
                let Ok(mut sessions) = self.sessions.lock() else { return };
                let Some(entry) = sessions.get_mut(session) else { return };
                if entry.transfers.id() != queue {
                    return;
                }
                if !entry.transfers.has_pending() {
                    entry.transfer_worker_running = false;
                    if *entry.intent.borrow() == Intent::Close
                        && !entry.transfers.is_settling()
                        && (entry.active.is_none() || entry.receiver.is_some())
                    {
                        sessions.remove(session);
                    }
                    return;
                }
                let active = entry.active.as_mut().filter(|active| {
                    active.ready && active.file.is_none() && *entry.intent.borrow() == Intent::None
                });
                match active {
                    Some(active) if active.context.is_some() => {
                        let context = active.context.clone().expect("verified target context");
                        entry.transfers.take_next(active.id).map(|selected| {
                            let (abort, cancellation) = AbortHandle::new_pair();
                            let state = Arc::new(UploadState::default());
                            active.file = Some(ActiveFile {
                                id: selected.identity.execution,
                                abort: abort.clone(),
                                upload_state: state.clone(),
                                effect_cancel: None,
                                transfer: Some(selected.identity),
                                download_control: None,
                            });
                            TransferExecution { selected, context, abort, cancellation, state }
                        })
                    }
                    _ => None,
                }
            };
            let Some(execution) = next else {
                notify.notified().await;
                continue;
            };
            let identity = execution.selected.identity;
            let completion = self.execute_transfer(session, queue, execution).await;
            // Cancelling an IPC future cannot close an OS dialog. Its real callback
            // completion releases the permit before the outstanding slot settles.
            loop {
                let open = self.sessions.lock().is_ok_and(|sessions| {
                    sessions.get(session).is_some_and(|entry| {
                        entry.transfers.id() == queue && entry.transfers.confirmation_open(identity)
                    })
                });
                if !open {
                    break;
                }
                notify.notified().await;
            }
            if let Ok(mut sessions) = self.sessions.lock()
                && let Some(entry) = sessions.get_mut(session)
                && entry.transfers.id() == queue
            {
                match completion {
                    TransferExecutionResult::Finished(completion) => {
                        entry.transfers.finish(identity, completion);
                    }
                    TransferExecutionResult::Paused(resources) => {
                        if let Err(resources) = entry.transfers.retain_paused(identity, resources) {
                            let manager = self.clone();
                            let session = session.to_owned();
                            drop(tokio::spawn(async move {
                                manager
                                    .settle_rejected_checkpoint(
                                        &session, queue, identity, resources,
                                    )
                                    .await;
                            }));
                        }
                    }
                }
            }
        }
    }

    async fn execute_transfer(
        &self,
        session: &str,
        queue: Uuid,
        execution: TransferExecution,
    ) -> TransferExecutionResult {
        let TransferExecution { selected, context, abort, cancellation, state } = execution;
        let identity = selected.identity;
        let guard = FileRequestGuard {
            manager: self,
            session_id: session,
            transport: identity.transport,
            operation: identity.execution,
            abort,
            upload_state: state,
        };
        let completion = match selected.resources {
            SelectedTransfer::Upload { source, directory, confirm } => {
                let preparation = Abortable::new(
                    async {
                        source.check_current().await.map_err(file_issue)?;
                        let target = source.target(&directory).map_err(file_issue)?;
                        let (reply, received) = oneshot::channel();
                        self.queue_file_request(
                            &guard,
                            FileCommand::PreflightUpload { target: target.clone(), reply },
                        )
                        .map_err(|_| SessionTransferIssue::TransportEnded)?;
                        let preflight = tokio::time::timeout(FILE_LIST_TIMEOUT, received)
                            .await
                            .map_err(|_| SessionTransferIssue::TransferFailed)?
                            .map_err(|_| SessionTransferIssue::TransportEnded)?
                            .map_err(|_| SessionTransferIssue::TransferFailed)?;
                        if preflight.target_attributes.is_some() {
                            if !preflight.replacement_supported
                                || !preflight
                                    .target_attributes
                                    .as_ref()
                                    .is_some_and(session_files::is_regular_upload_target)
                            {
                                return Err(SessionTransferIssue::Unsupported);
                            }
                            let review = SessionTransferReview::new(
                                &context,
                                &source.display_name(),
                                SessionTransferDirection::Upload,
                            );
                            if !self
                                .confirm_transfer(session, queue, identity, review, confirm)
                                .await?
                            {
                                return Ok(None);
                            }
                        }
                        Ok(Some((source, target, preflight)))
                    },
                    cancellation,
                )
                .await;
                match preparation {
                    Err(_) => self.stopped_completion(session, identity, false),
                    Ok(Err(issue)) => issue_completion(issue, false),
                    Ok(Ok(None)) => known_completion(SessionTransferState::Cancelled),
                    Ok(Ok(Some((source, target, preflight)))) => {
                        let (cancel_sender, cancel) = watch::channel(false);
                        let (reply, received) = oneshot::channel();
                        let request = FileCommand::Upload {
                            source: Box::new(source),
                            directory,
                            target,
                            preflight,
                            cancel,
                            state: guard.upload_state.clone(),
                            session_id: session.to_owned(),
                            transport: identity.transport,
                            operation: identity.execution,
                            progress: Box::new(|_| {}),
                            reply,
                        };
                        if self.queue_effect_request(&guard, cancel_sender, request).is_err() {
                            self.stopped_completion(session, identity, false)
                        } else {
                            match received.await {
                                Ok(result) if result.status == SessionUploadStatus::Cancelled => {
                                    self.stopped_completion(
                                        session,
                                        identity,
                                        result.staging_may_remain,
                                    )
                                }
                                Ok(result) => upload_completion(result),
                                Err(_)
                                    if guard.upload_state.effect_started.load(Ordering::SeqCst) =>
                                {
                                    issue_completion(
                                        SessionTransferIssue::PublicationUnknown,
                                        guard
                                            .upload_state
                                            .staging_may_remain
                                            .load(Ordering::SeqCst),
                                    )
                                }
                                Err(_) => self.stopped_completion(
                                    session,
                                    identity,
                                    guard.upload_state.staging_may_remain.load(Ordering::SeqCst),
                                ),
                            }
                        }
                    }
                }
            }
            SelectedTransfer::Download { remote_path, destination, confirm } => {
                return self
                    .execute_download_transfer(
                        session,
                        queue,
                        identity,
                        &context,
                        guard,
                        Some((remote_path, destination, confirm)),
                        None,
                    )
                    .await;
            }
            SelectedTransfer::ResumeDownload(checkpoint) => {
                return self
                    .execute_download_transfer(
                        session,
                        queue,
                        identity,
                        &context,
                        guard,
                        None,
                        Some(checkpoint),
                    )
                    .await;
            }
        };
        drop(guard);
        TransferExecutionResult::Finished(completion)
    }

    async fn settle_checkpoint(
        &self,
        session: &str,
        queue: Uuid,
        identity: TransferIdentity,
        resources: SelectedTransfer,
        interrupted: bool,
    ) {
        let clean = match resources {
            SelectedTransfer::ResumeDownload(checkpoint) => checkpoint.discard().await,
            _ => true,
        };
        if let Ok(mut sessions) = self.sessions.lock()
            && let Some(entry) = sessions.get_mut(session)
            && entry.transfers.id() == queue
        {
            entry.transfers.finish_cleanup(
                identity,
                TransferCompletion {
                    state: if interrupted {
                        SessionTransferState::Interrupted
                    } else {
                        SessionTransferState::Cancelled
                    },
                    issue: if !clean {
                        Some(SessionTransferIssue::CleanupIncomplete)
                    } else if interrupted {
                        Some(SessionTransferIssue::TransportEnded)
                    } else {
                        None
                    },
                    staging_may_remain: !clean,
                },
            );
            entry.transfer_notify.notify_one();
            if *entry.intent.borrow() == Intent::Close
                && !entry.transfers.has_pending()
                && !entry.transfers.is_settling()
                && entry.active.is_none()
            {
                sessions.remove(session);
            }
        }
    }

    async fn settle_rejected_checkpoint(
        &self,
        session: &str,
        queue: Uuid,
        identity: TransferIdentity,
        resources: SelectedTransfer,
    ) {
        let clean = match resources {
            SelectedTransfer::ResumeDownload(checkpoint) => checkpoint.discard().await,
            _ => true,
        };
        let completion = self.stopped_completion(session, identity, !clean);
        if let Ok(mut sessions) = self.sessions.lock()
            && let Some(entry) = sessions.get_mut(session)
            && entry.transfers.id() == queue
        {
            entry.transfers.finish(identity, completion);
            entry.transfer_notify.notify_one();
            if *entry.intent.borrow() == Intent::Close
                && !entry.transfers.has_pending()
                && !entry.transfers.is_settling()
                && entry.active.is_none()
            {
                sessions.remove(session);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_download_transfer(
        &self,
        session: &str,
        queue: Uuid,
        identity: TransferIdentity,
        context: &PreparationContext,
        guard: FileRequestGuard<'_>,
        selected: Option<(Vec<u8>, DownloadDestination, ReplaceConfirmation)>,
        checkpoint: Option<Box<DownloadCheckpoint>>,
    ) -> TransferExecutionResult {
        let result = async {
            let input = if let Some(checkpoint) = checkpoint {
                DownloadInput::Resume(checkpoint)
            } else {
                let (remote_path, destination, confirm) =
                    selected.expect("download selection or checkpoint");
                destination.check().await?;
                if destination.exists()
                    && !self
                        .confirm_transfer(
                            session,
                            queue,
                            identity,
                            SessionTransferReview::new(
                                context,
                                &destination.display_name(),
                                SessionTransferDirection::Download,
                            ),
                            confirm,
                        )
                        .await?
                {
                    return Ok(None);
                }
                destination.check().await?;
                DownloadInput::New { remote_path, destination }
            };
            let (reply, received) = oneshot::channel();
            if let Err(failed) = self.dispatch_download(&guard, identity, input, reply) {
                let (error, input) = *failed;
                let clean = match input {
                    DownloadInput::Resume(checkpoint) => checkpoint.discard().await,
                    DownloadInput::New { .. } => true,
                };
                return Ok(Some(DownloadExecution::Failed { error, staging_may_remain: !clean }));
            }
            match received.await.map_err(|_| {
                if guard.upload_state.effect_started.load(Ordering::SeqCst) {
                    SessionTransferIssue::PublicationUnknown
                } else {
                    SessionTransferIssue::TransportEnded
                }
            })? {
                Ok(result) => Ok(Some(result)),
                Err(FileAccessError::Cancelled) => Ok(None),
                Err(error) => Err(file_issue(error)),
            }
        }
        .await;
        drop(guard);
        match result {
            Ok(Some(DownloadExecution::Paused(checkpoint))) => {
                TransferExecutionResult::Paused(SelectedTransfer::ResumeDownload(checkpoint))
            }
            Ok(Some(DownloadExecution::Ready { .. })) => {
                unreachable!("file owner publishes prepared downloads")
            }
            Ok(Some(DownloadExecution::Failed { error, staging_may_remain })) => {
                TransferExecutionResult::Finished(if matches!(error, FileAccessError::Cancelled) {
                    self.stopped_completion(session, identity, staging_may_remain)
                } else {
                    issue_completion(file_issue(error), staging_may_remain)
                })
            }
            Ok(Some(DownloadExecution::Published { result, staging_may_remain })) => {
                TransferExecutionResult::Finished(match result.status {
                    SessionDownloadStatus::Saved => known_completion(SessionTransferState::Saved),
                    SessionDownloadStatus::Cancelled => {
                        self.stopped_completion(session, identity, staging_may_remain)
                    }
                    SessionDownloadStatus::Conflict => {
                        issue_completion(SessionTransferIssue::TargetChanged, staging_may_remain)
                    }
                    SessionDownloadStatus::Unknown => issue_completion(
                        SessionTransferIssue::PublicationUnknown,
                        staging_may_remain,
                    ),
                    SessionDownloadStatus::Failed => {
                        issue_completion(SessionTransferIssue::LocalIo, staging_may_remain)
                    }
                })
            }
            Ok(None) => {
                TransferExecutionResult::Finished(self.stopped_completion(session, identity, false))
            }
            Err(issue) => TransferExecutionResult::Finished(
                if issue == SessionTransferIssue::TransportEnded {
                    self.stopped_completion(session, identity, false)
                } else {
                    issue_completion(issue, false)
                },
            ),
        }
    }

    fn dispatch_download(
        &self,
        guard: &FileRequestGuard<'_>,
        identity: TransferIdentity,
        input: DownloadInput,
        reply: oneshot::Sender<Result<DownloadExecution, FileAccessError>>,
    ) -> Result<(), Box<(FileAccessError, DownloadInput)>> {
        let (sender, control) = watch::channel(DownloadControl::Run);
        let mut request = Some(FileCommand::TransferDownload {
            input,
            control,
            session_id: guard.session_id.to_owned(),
            transport: identity.transport,
            operation: identity.execution,
            reply,
        });
        let result = (|| {
            let mut sessions =
                self.sessions.lock().map_err(|_| FileAccessError::ConnectionEnded)?;
            let entry =
                sessions.get_mut(guard.session_id).ok_or(FileAccessError::ConnectionEnded)?;
            if *entry.intent.borrow() != Intent::None {
                return Err(FileAccessError::ConnectionEnded);
            }
            if guard.abort.is_aborted() {
                return Err(FileAccessError::Cancelled);
            }
            if entry.transfers.is_pausing(identity) {
                sender.send_replace(DownloadControl::Pause);
            }
            let active = entry
                .active
                .as_mut()
                .filter(|active| active.ready && active.id == identity.transport)
                .ok_or(FileAccessError::ConnectionEnded)?;
            let file = active
                .file
                .as_mut()
                .filter(|file| file.transfer == Some(identity))
                .ok_or(FileAccessError::ConnectionEnded)?;
            file.download_control = Some(sender);
            active.files.try_send(request.take().expect("owned request")).map_err(|error| {
                request = Some(error.into_inner());
                FileAccessError::ConnectionEnded
            })
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                let Some(FileCommand::TransferDownload { input, .. }) = request else {
                    unreachable!("failed dispatch retains ownership")
                };
                Err(Box::new((error, input)))
            }
        }
    }

    async fn confirm_transfer(
        &self,
        session: &str,
        queue: Uuid,
        identity: TransferIdentity,
        review: SessionTransferReview,
        confirm: ReplaceConfirmation,
    ) -> Result<bool, SessionTransferIssue> {
        loop {
            let waiting = {
                let mut sessions =
                    self.sessions.lock().map_err(|_| SessionTransferIssue::SessionUnavailable)?;
                let entry =
                    sessions.get_mut(session).ok_or(SessionTransferIssue::SessionUnavailable)?;
                if entry.transfers.id() != queue {
                    return Err(SessionTransferIssue::StaleItem);
                }
                match entry.transfers.begin_confirmation(identity) {
                    Ok(()) => None,
                    Err(SessionTransferIssue::NativeDialogBusy) => {
                        Some(entry.transfer_notify.clone())
                    }
                    Err(issue) => return Err(issue),
                }
            };
            let Some(notify) = waiting else { break };
            notify.notified().await;
        }
        let lease = ConfirmationLease {
            manager: self.clone(),
            session: session.to_owned(),
            queue,
            identity,
        };
        tokio::spawn(async move {
            let _lease = lease;
            confirm(review).await
        })
        .await
        .map_err(|_| SessionTransferIssue::SelectionFailed)?
    }

    fn stopped_completion(
        &self,
        session: &str,
        identity: TransferIdentity,
        staging_may_remain: bool,
    ) -> TransferCompletion {
        let connected = self.sessions.lock().is_ok_and(|sessions| {
            sessions.get(session).is_some_and(|entry| {
                *entry.intent.borrow() == Intent::None
                    && entry
                        .active
                        .as_ref()
                        .is_some_and(|active| active.ready && active.id == identity.transport)
            })
        });
        TransferCompletion {
            state: if connected {
                SessionTransferState::Cancelled
            } else {
                SessionTransferState::Interrupted
            },
            issue: (!connected).then_some(SessionTransferIssue::TransportEnded),
            staging_may_remain,
        }
    }
}

fn transfer_ids(
    queue: &str,
    item: &str,
    execution: &str,
) -> Result<(Uuid, Uuid, Uuid), SessionTransferIssue> {
    Ok((
        Uuid::parse_str(queue).map_err(|_| SessionTransferIssue::InvalidIdentifier)?,
        Uuid::parse_str(item).map_err(|_| SessionTransferIssue::InvalidIdentifier)?,
        Uuid::parse_str(execution).map_err(|_| SessionTransferIssue::InvalidIdentifier)?,
    ))
}

pub(super) fn file_issue(error: FileAccessError) -> SessionTransferIssue {
    match error {
        FileAccessError::InvalidPath => SessionTransferIssue::InvalidPath,
        FileAccessError::InvalidSource | FileAccessError::InvalidDestination => {
            SessionTransferIssue::InvalidSelection
        }
        FileAccessError::SourceChanged | FileAccessError::FileChanged => {
            SessionTransferIssue::SourceChanged
        }
        FileAccessError::Conflict => SessionTransferIssue::TargetChanged,
        FileAccessError::ConnectionEnded => SessionTransferIssue::TransportEnded,
        FileAccessError::ReplacementUnsupported
        | FileAccessError::UnsupportedEntry
        | FileAccessError::NotRegularFile => SessionTransferIssue::Unsupported,
        FileAccessError::LocalIo(_) | FileAccessError::LocalSourceIo(_) => {
            SessionTransferIssue::LocalIo
        }
        FileAccessError::RemoteStatus(_) => SessionTransferIssue::RemoteRefused,
        _ => SessionTransferIssue::TransferFailed,
    }
}

fn known_completion(state: SessionTransferState) -> TransferCompletion {
    TransferCompletion { state, issue: None, staging_may_remain: false }
}

fn issue_completion(issue: SessionTransferIssue, staging_may_remain: bool) -> TransferCompletion {
    TransferCompletion {
        state: match issue {
            SessionTransferIssue::SourceChanged | SessionTransferIssue::TargetChanged => {
                SessionTransferState::Conflict
            }
            SessionTransferIssue::PublicationUnknown => SessionTransferState::Unknown,
            SessionTransferIssue::TransportEnded | SessionTransferIssue::SessionUnavailable => {
                SessionTransferState::Interrupted
            }
            _ => SessionTransferState::Failed,
        },
        issue: Some(issue),
        staging_may_remain,
    }
}

fn upload_completion(result: SessionUploadResult) -> TransferCompletion {
    match result.status {
        SessionUploadStatus::Saved => known_completion(SessionTransferState::Saved),
        SessionUploadStatus::Cancelled => TransferCompletion {
            state: SessionTransferState::Cancelled,
            issue: None,
            staging_may_remain: result.staging_may_remain,
        },
        SessionUploadStatus::Conflict => {
            issue_completion(SessionTransferIssue::TargetChanged, result.staging_may_remain)
        }
        SessionUploadStatus::Unsupported => {
            issue_completion(SessionTransferIssue::Unsupported, result.staging_may_remain)
        }
        SessionUploadStatus::Unknown => {
            issue_completion(SessionTransferIssue::PublicationUnknown, result.staging_may_remain)
        }
        SessionUploadStatus::Failed => {
            issue_completion(SessionTransferIssue::TransferFailed, result.staging_may_remain)
        }
    }
}

#[cfg(test)]
mod tests;
