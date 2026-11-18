// SPDX-License-Identifier: Apache-2.0

use crate::session_directory_sync::{
    SessionDirectorySyncApplyResult as ApplyResult, SessionDirectorySyncIssue as Issue,
    SessionDirectorySyncPrepareResult as PrepareResult,
};
use crate::session_files::directory_sync::ComparedDirectory;
use crate::session_transfers::{
    SessionTransferDirection, SessionTransferEnqueueResult, SessionTransferIssue,
    SessionTransferReview, SessionTransferState,
};

use super::*;

const COMPARISON_TIMEOUT: Duration = Duration::from_secs(120);

pub(super) struct DirectoryRecord {
    id: Uuid,
    pub(super) transport: Uuid,
    pub(super) operation: Uuid,
    plan: Option<ComparedDirectory>,
}

fn current(entry: &SessionEntry, guard: &FileRequestGuard<'_>, id: Uuid) -> bool {
    *entry.intent.borrow() == Intent::None
        && !guard.abort.is_aborted()
        && entry.active.as_ref().is_some_and(|active| {
            active.ready
                && active.id == guard.transport
                && active.file.as_ref().is_some_and(|file| file.id == guard.operation)
        })
        && entry.directory_sync.as_ref().is_some_and(|record| {
            record.id == id
                && record.transport == guard.transport
                && record.operation == guard.operation
        })
}

impl SessionManager {
    /// Select a local folder and compare complete current-directory file contents without writes.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_directory_sync_with_picker<F, Fut>(
        &self,
        session_id: &str,
        transport_id: &str,
        operation_id: &str,
        remote_path: Vec<u8>,
        direction: SessionTransferDirection,
        choose_folder: F,
    ) -> Result<PrepareResult, Issue>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<PathBuf>, SessionTransferIssue>>,
    {
        let (abort, cancellation) = AbortHandle::new_pair();
        let guard = self
            .reserve_file_operation(session_id, transport_id, operation_id, abort)
            .map_err(|_| Issue::Unavailable)?;
        let id = Uuid::now_v7();
        {
            let mut sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
            let entry = sessions.get_mut(session_id).ok_or(Issue::Unavailable)?;
            if !entry.pty {
                return Err(Issue::Unavailable);
            }
            entry.directory_sync = Some(DirectoryRecord {
                id,
                transport: guard.transport,
                operation: guard.operation,
                plan: None,
            });
        }
        let result = Abortable::new(
            async {
                let Some(local) = choose_folder().await? else {
                    return Ok(PrepareResult::Cancelled);
                };
                let (reply, received) = oneshot::channel();
                self.queue_file_request(
                    &guard,
                    FileCommand::CompareDirectory { remote: remote_path, local, direction, reply },
                )
                .map_err(|_| Issue::Unavailable)?;
                let plan = tokio::time::timeout(COMPARISON_TIMEOUT, received)
                    .await
                    .map_err(|_| Issue::Timeout)?
                    .map_err(|_| Issue::Unavailable)??;
                let snapshot = plan.snapshot(session_id, guard.transport, id);
                let mut sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
                let entry = sessions.get_mut(session_id).ok_or(Issue::Unavailable)?;
                if !current(entry, &guard, id) {
                    return Err(Issue::Unavailable);
                }
                entry.directory_sync.as_mut().expect("current plan owner").plan = Some(plan);
                Ok(PrepareResult::Prepared { plan: snapshot })
            },
            cancellation,
        )
        .await
        .map_err(|_| Issue::Cancelled)
        .and_then(|result| result);
        if !matches!(result, Ok(PrepareResult::Prepared { .. })) {
            self.remove_directory_plan(session_id, id);
        }
        drop(guard);
        result
    }

    /// Explicitly recheck a reviewed plan and atomically admit its changes to the existing FIFO.
    pub async fn apply_directory_sync<C, Fut>(
        &self,
        session_id: &str,
        transport_id: &str,
        plan_id: &str,
        confirm_replace: C,
    ) -> Result<ApplyResult, Issue>
    where
        C: Fn(SessionTransferReview) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, SessionTransferIssue>> + Send + 'static,
    {
        let id = Uuid::parse_str(plan_id).map_err(|_| Issue::Unavailable)?;
        let (abort, cancellation) = AbortHandle::new_pair();
        let guard = self
            .reserve_file_operation(session_id, transport_id, plan_id, abort)
            .map_err(|_| Issue::Unavailable)?;
        let plan = {
            let mut sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
            let record = sessions
                .get_mut(session_id)
                .and_then(|entry| entry.directory_sync.as_mut())
                .filter(|record| record.id == id && record.transport == guard.transport)
                .ok_or(Issue::Unavailable)?;
            let plan = record.plan.take().ok_or(Issue::Unavailable)?;
            record.operation = guard.operation;
            plan
        };
        let result = Abortable::new(
            async {
                let (reply, received) = oneshot::channel();
                self.queue_file_request(
                    &guard,
                    FileCommand::ValidateDirectory { plan: Box::new(plan), reply },
                )
                .map_err(|_| Issue::Unavailable)?;
                let plan = tokio::time::timeout(COMPARISON_TIMEOUT, received)
                    .await
                    .map_err(|_| Issue::Timeout)?
                    .map_err(|_| Issue::Unavailable)??;
                let mut sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
                let entry = sessions.get_mut(session_id).ok_or(Issue::Unavailable)?;
                if !current(entry, &guard, id) {
                    return Err(Issue::Unavailable);
                }
                let count = plan.changes();
                if count == 0 {
                    entry.directory_sync = None;
                    return Ok(ApplyResult::Unchanged);
                }
                let reservation = match entry.transfers.reserve_selection(guard.transport) {
                    Ok(reservation) => reservation,
                    Err(issue) => {
                        entry.directory_sync.as_mut().expect("current plan owner").plan =
                            Some(*plan);
                        return Err(issue.into());
                    }
                };
                let direction = plan.direction;
                let progress = session_files::directory_sync::execute::initial_progress(&plan);
                let total =
                    plan.summary.transfer_size_bytes.parse().expect("computed unsigned total");
                let name = session_files::display_remote_path(&plan.remote_root);
                let resource = SelectedTransfer::DirectorySync {
                    plan,
                    confirm: Arc::new(move |review| Box::pin(confirm_replace(review))),
                };
                let admitted = entry.transfers.enqueue_directory_sync(
                    reservation,
                    &name,
                    direction,
                    total,
                    progress,
                    resource,
                )?;
                let SessionTransferEnqueueResult::Queued { queue_id, item_id, execution_id } =
                    admitted
                else {
                    unreachable!("synchronization always queues")
                };
                entry.directory_sync = None;
                entry.transfer_notify.notify_one();
                Ok(ApplyResult::Queued { queue_id, item_id, execution_id })
            },
            cancellation,
        )
        .await
        .map_err(|_| Issue::Cancelled)
        .and_then(|result| result);
        if !matches!(result, Err(Issue::QueueFull)) {
            self.remove_directory_plan(session_id, id);
        }
        drop(guard);
        if matches!(result, Ok(ApplyResult::Queued { .. })) {
            self.start_transfer_worker(session_id);
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute_directory_sync(
        &self,
        session: &str,
        queue: Uuid,
        identity: TransferIdentity,
        context: PreparationContext,
        guard: FileRequestGuard<'_>,
        plan: Box<ComparedDirectory>,
        confirm: crate::session_transfers::RepeatedConfirmation,
    ) -> super::transfers::TransferExecutionResult {
        use super::transfers::{TransferExecutionResult, issue_completion, known_completion};
        let direction = plan.direction;
        let progress_sessions = self.sessions.clone();
        let progress_session = session.to_owned();
        let authorize_sessions = self.sessions.clone();
        let authorize_session = session.to_owned();
        let settled_sessions = self.sessions.clone();
        let settled_session = session.to_owned();
        let state = guard.upload_state.clone();
        let settled_state = state.clone();
        let confirm_manager = self.clone();
        let confirm_session = session.to_owned();
        let callbacks = session_files::directory_sync::execute::Callbacks {
            progress: Arc::new(move |transferred, total, progress| {
                if let Ok(mut sessions) = progress_sessions.lock()
                    && let Some(entry) = sessions.get_mut(&progress_session)
                {
                    entry.transfers.synchronization_progress(
                        identity,
                        transferred,
                        total,
                        progress,
                    );
                }
            }),
            authorize: Arc::new(move || {
                Self::authorize_remote_effect(
                    &authorize_sessions,
                    &authorize_session,
                    identity.transport,
                    identity.execution,
                )
            }),
            settled: Arc::new(move || {
                if let Ok(mut sessions) = settled_sessions.lock()
                    && let Some(entry) = sessions.get_mut(&settled_session)
                {
                    entry.transfers.finish_directory_effect(identity);
                    settled_state.effect_started.store(false, Ordering::SeqCst);
                }
            }),
            confirm: Arc::new(move |name| {
                let manager = confirm_manager.clone();
                let session = confirm_session.clone();
                let review = SessionTransferReview::new(&context, &name, direction);
                let confirm = confirm.clone();
                Box::pin(async move {
                    manager
                        .confirm_transfer(
                            &session,
                            queue,
                            identity,
                            review,
                            Box::new(move |review| confirm(review)),
                        )
                        .await
                })
            }),
            state,
        };
        let (sender, control) = watch::channel(session_files::TransferControl::Run);
        let (reply, received) = oneshot::channel();
        let dispatched = (|| {
            let mut sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
            let entry = sessions.get_mut(session).ok_or(Issue::Unavailable)?;
            if *entry.intent.borrow() != Intent::None || guard.abort.is_aborted() {
                return Err(Issue::Unavailable);
            }
            let active = entry
                .active
                .as_mut()
                .filter(|active| active.ready && active.id == identity.transport)
                .ok_or(Issue::Unavailable)?;
            let file = active
                .file
                .as_mut()
                .filter(|file| file.transfer == Some(identity))
                .ok_or(Issue::Unavailable)?;
            file.transfer_control = Some(sender);
            active
                .files
                .try_send(FileCommand::SynchronizeDirectory { plan, control, callbacks, reply })
                .map_err(|_| Issue::Unavailable)
        })();
        let completion = if dispatched.is_err() {
            self.stopped_completion(session, identity, false)
        } else {
            match received.await {
                Ok(result) => match result.issue {
                    None => known_completion(SessionTransferState::Saved),
                    Some(Issue::Cancelled) => {
                        self.stopped_completion(session, identity, result.staging_may_remain)
                    }
                    Some(issue) => issue_completion(
                        match issue {
                            Issue::PublicationUnknown => SessionTransferIssue::PublicationUnknown,
                            Issue::FileChanged => SessionTransferIssue::TargetChanged,
                            Issue::Unavailable => SessionTransferIssue::TransportEnded,
                            Issue::CleanupIncomplete => SessionTransferIssue::CleanupIncomplete,
                            _ => SessionTransferIssue::TransferFailed,
                        },
                        result.staging_may_remain,
                    ),
                },
                Err(_) => {
                    let remains = guard.upload_state.staging_may_remain.load(Ordering::SeqCst);
                    if guard.upload_state.effect_started.load(Ordering::SeqCst) {
                        issue_completion(SessionTransferIssue::PublicationUnknown, remains)
                    } else {
                        self.stopped_completion(session, identity, remains)
                    }
                }
            }
        };
        drop(guard);
        TransferExecutionResult::Finished(completion)
    }

    /// Discard exactly one unapplied plan and cancel its pending comparison or validation.
    pub fn discard_directory_sync(&self, session_id: &str, plan_id: &str) -> Result<(), Issue> {
        let id = Uuid::parse_str(plan_id).map_err(|_| Issue::Unavailable)?;
        let record = {
            let mut sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
            let entry = sessions.get_mut(session_id).ok_or(Issue::Unavailable)?;
            if entry.directory_sync.as_ref().is_none_or(|record| record.id != id) {
                return Err(Issue::Unavailable);
            }
            entry.directory_sync.take().expect("matching plan")
        };
        let _ = self.cancel_file_operation(
            session_id,
            &record.transport.to_string(),
            &record.operation.to_string(),
        );
        Ok(())
    }

    fn remove_directory_plan(&self, session_id: &str, id: Uuid) {
        if let Ok(mut sessions) = self.sessions.lock()
            && let Some(entry) = sessions.get_mut(session_id)
            && entry.directory_sync.as_ref().is_some_and(|record| record.id == id)
        {
            entry.directory_sync = None;
        }
    }
}

#[cfg(test)]
mod tests;
