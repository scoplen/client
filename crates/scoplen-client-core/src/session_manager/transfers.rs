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

struct SelectionLease {
    manager: SessionManager,
    session: String,
    reservation: SelectionReservation,
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

impl SessionManager {
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
            CancelTransfer::Running(identity) => {
                if let Some(active) = &entry.active
                    && active.id == identity.transport
                    && let Some(file) = &active.file
                    && file.transfer == Some(identity)
                {
                    if let Some(cancel) = &file.effect_cancel {
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

    fn start_transfer_worker(&self, session: &str) {
        let start = {
            let Ok(mut sessions) = self.sessions.lock() else { return };
            let Some(entry) = sessions.get_mut(session) else { return };
            if entry.transfer_worker_running {
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
            let next = {
                let Ok(mut sessions) = self.sessions.lock() else { return };
                let Some(entry) = sessions.get_mut(session) else { return };
                if entry.transfers.id() != queue {
                    return;
                }
                if !entry.transfers.has_pending() {
                    entry.transfer_worker_running = false;
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
                entry.transfers.finish(identity, completion);
            }
        }
    }

    async fn execute_transfer(
        &self,
        session: &str,
        queue: Uuid,
        execution: TransferExecution,
    ) -> TransferCompletion {
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
                let mut dispatched = false;
                let result = Abortable::new(
                    async {
                        destination.check().await?;
                        if destination.exists() {
                            let review = SessionTransferReview::new(
                                &context,
                                &destination.display_name(),
                                SessionTransferDirection::Download,
                            );
                            if !self
                                .confirm_transfer(session, queue, identity, review, confirm)
                                .await?
                            {
                                return Ok(None);
                            }
                        }
                        destination.check().await?;
                        let path = destination.path().to_path_buf();
                        let (reply, received) = oneshot::channel();
                        self.queue_file_request(
                            &guard,
                            FileCommand::Download {
                                remote_path,
                                destination: path,
                                baseline: Some(destination),
                                session_id: session.to_owned(),
                                transport: identity.transport,
                                operation: identity.execution,
                                progress: Box::new(|_| {}),
                                reply,
                            },
                        )
                        .map_err(|_| SessionTransferIssue::TransportEnded)?;
                        dispatched = true;
                        received.await.map(Some).map_err(|_| {
                            if guard.upload_state.effect_started.load(Ordering::SeqCst) {
                                SessionTransferIssue::PublicationUnknown
                            } else {
                                SessionTransferIssue::TransportEnded
                            }
                        })
                    },
                    cancellation,
                )
                .await;
                match result {
                    Err(_) => self.stopped_completion(session, identity, dispatched),
                    Ok(Err(issue)) => issue_completion(issue, dispatched),
                    Ok(Ok(None)) => known_completion(SessionTransferState::Cancelled),
                    Ok(Ok(Some(result))) => match result.status {
                        SessionDownloadStatus::Saved => {
                            known_completion(SessionTransferState::Saved)
                        }
                        SessionDownloadStatus::Cancelled => {
                            self.stopped_completion(session, identity, dispatched)
                        }
                        SessionDownloadStatus::Conflict => {
                            issue_completion(SessionTransferIssue::TargetChanged, dispatched)
                        }
                        SessionDownloadStatus::Unknown => {
                            issue_completion(SessionTransferIssue::PublicationUnknown, dispatched)
                        }
                        SessionDownloadStatus::Failed => {
                            issue_completion(SessionTransferIssue::TransferFailed, dispatched)
                        }
                    },
                }
            }
        };
        drop(guard);
        completion
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

fn file_issue(error: FileAccessError) -> SessionTransferIssue {
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
