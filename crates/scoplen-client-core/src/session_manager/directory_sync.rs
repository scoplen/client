// SPDX-License-Identifier: Apache-2.0

use crate::session_directory_sync::{
    SessionDirectorySyncApplyResult as ApplyResult, SessionDirectorySyncChange as Change,
    SessionDirectorySyncIssue as Issue, SessionDirectorySyncItem,
    SessionDirectorySyncPrepareResult as PrepareResult,
};
use crate::session_files::directory_sync::ComparedDirectory;
use crate::session_transfers::{
    SessionTransferDirection, SessionTransferEnqueueResult, SessionTransferIssue,
    SessionTransferReview,
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
        C: Fn(SessionTransferReview) -> Fut + Clone + Send + 'static,
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
                let reservation = match entry.transfers.reserve_selections(guard.transport, count) {
                    Ok(reservation) => reservation,
                    Err(issue) => {
                        entry.directory_sync.as_mut().expect("current plan owner").plan =
                            Some(*plan);
                        return Err(issue.into());
                    }
                };
                let direction = plan.direction;
                let mut selected = Vec::with_capacity(count);
                for row in plan.rows {
                    if row.change == Change::Same {
                        continue;
                    }
                    let callback = confirm_replace.clone();
                    let confirm: crate::session_transfers::ReplaceConfirmation =
                        Box::new(move |review| Box::pin(callback(review)));
                    let resource = match direction {
                        SessionTransferDirection::Upload => SelectedTransfer::Upload {
                            source: row.source.expect("admitted upload source"),
                            directory: plan.remote_root.clone(),
                            target: row.remote_path,
                            confirm,
                            editor: None,
                        },
                        SessionTransferDirection::Download => SelectedTransfer::Download {
                            remote_path: row.remote_path,
                            destination: Box::new(row.local),
                            confirm,
                            editor: None,
                        },
                    };
                    selected.push((session_files::display_name(&row.name), row.size, resource));
                }
                let admitted = match entry.transfers.enqueue_batch(reservation, direction, selected)
                {
                    Ok(admitted) => admitted,
                    Err(issue) => {
                        entry.transfers.release_selection(reservation);
                        return Err(issue.into());
                    }
                };
                let queue_id = entry.transfers.id().to_string();
                let items = admitted
                    .into_iter()
                    .map(|result| {
                        let SessionTransferEnqueueResult::Queued { item_id, execution_id, .. } =
                            result
                        else {
                            unreachable!("batch always queues")
                        };
                        SessionDirectorySyncItem { item_id, execution_id }
                    })
                    .collect();
                entry.directory_sync = None;
                entry.transfer_notify.notify_one();
                Ok(ApplyResult::Queued { queue_id, items })
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
