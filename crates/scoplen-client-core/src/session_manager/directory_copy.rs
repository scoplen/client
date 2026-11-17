// SPDX-License-Identifier: Apache-2.0

use crate::session_directory_copy::{
    SessionDirectoryCopyIssue as Issue, SessionDirectoryCopyPrepareResult as PrepareResult,
    SessionDirectoryCopySelection,
};
use crate::session_files::directory_copy::{Callbacks, DirectoryCopy};
use crate::session_transfers::{
    SelectionReservation, SessionTransferDirection as Direction, SessionTransferEnqueueResult,
    SessionTransferIssue, SessionTransferState,
};

use super::transfers::{TransferExecutionResult, issue_completion, known_completion};
use super::*;

const SELECTION_LIFETIME: Duration = Duration::from_secs(300);

pub(super) struct PreparedSelection {
    id: Uuid,
    pub(super) transport: Uuid,
    pub(super) reservation: SelectionReservation,
    expires: Instant,
    local: PathBuf,
    remote: Vec<u8>,
    direction: Direction,
}

struct SelectionOwner {
    manager: SessionManager,
    session: String,
    reservation: SelectionReservation,
    retained: bool,
}

impl Drop for SelectionOwner {
    fn drop(&mut self) {
        if !self.retained
            && let Ok(mut sessions) = self.manager.sessions.lock()
            && let Some(entry) = sessions.get_mut(&self.session)
        {
            entry.transfers.release_selection(self.reservation);
            entry.transfer_notify.notify_one();
        }
    }
}

impl From<SessionTransferIssue> for Issue {
    fn from(issue: SessionTransferIssue) -> Self {
        match issue {
            SessionTransferIssue::QueueFull => Self::QueueFull,
            SessionTransferIssue::NativeDialogBusy => Self::NativeDialogBusy,
            SessionTransferIssue::InvalidSelection | SessionTransferIssue::InvalidPath => {
                Self::InvalidSelection
            }
            SessionTransferIssue::LocalIo => Self::LocalIo,
            SessionTransferIssue::SelectionFailed => Self::Failed,
            _ => Self::Unavailable,
        }
    }
}

fn basename(path: &[u8]) -> &[u8] {
    let path = path.strip_suffix(b"/").unwrap_or(path);
    path.rsplit(|byte| *byte == b'/').next().filter(|name| !name.is_empty()).unwrap_or(b"/")
}

impl SessionManager {
    /// Reserve one queue slot before selecting a source folder or destination parent.
    pub async fn prepare_directory_copy_with_picker<F, Fut>(
        &self,
        session_id: &str,
        transport_id: &str,
        remote_path: Vec<u8>,
        direction: Direction,
        choose_folder: F,
    ) -> Result<PrepareResult, Issue>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Option<PathBuf>, SessionTransferIssue>> + Send + 'static,
    {
        session_files::validate_path(&remote_path)?;
        let (transport, reservation) = self.reserve_transfer_selection(session_id, transport_id)?;
        let manager = self.clone();
        let session = session_id.to_owned();
        let (reply, received) = oneshot::channel();
        drop(tokio::spawn(async move {
            let mut owner = SelectionOwner {
                manager: manager.clone(),
                session: session.clone(),
                reservation,
                retained: false,
            };
            let id = Uuid::now_v7();
            let result = async {
                let Some(local) = choose_folder().await? else {
                    return Ok(PrepareResult::Cancelled);
                };
                session_files::directory_copy::local_directory(&local).await?;
                let native_name =
                    local.file_name().unwrap_or(std::ffi::OsStr::new("Selected folder"));
                let local_name =
                    session_files::display_name(native_name.to_string_lossy().as_bytes());
                let remote_name = session_files::display_name(basename(&remote_path));
                let (source_name, destination_parent_name, default_name) = match direction {
                    Direction::Upload => (local_name, remote_name, native_name.to_str()),
                    Direction::Download => {
                        (remote_name, local_name, std::str::from_utf8(basename(&remote_path)).ok())
                    }
                };
                let default_root_name = default_name.and_then(|name| {
                    if session_files::display_name(name.as_bytes()) != name {
                        return None;
                    }
                    session_files::directory_copy::root_name(name, direction)
                        .ok()
                        .map(|_| name.to_owned())
                });
                let snapshot = SessionDirectoryCopySelection {
                    selection_id: id.to_string(),
                    session_id: session.clone(),
                    transport_id: transport.to_string(),
                    direction,
                    source_name,
                    destination_parent_name,
                    default_root_name,
                };
                let expires = Instant::now() + SELECTION_LIFETIME;
                {
                    let mut sessions = manager.sessions.lock().map_err(|_| Issue::Unavailable)?;
                    let entry = sessions.get_mut(&session).ok_or(Issue::Unavailable)?;
                    if !entry.pty
                        || *entry.intent.borrow() != Intent::None
                        || entry
                            .active
                            .as_ref()
                            .is_none_or(|active| !active.ready || active.id != transport)
                    {
                        return Err(Issue::Unavailable);
                    }
                    entry.directory_copy = Some(PreparedSelection {
                        id,
                        transport,
                        reservation,
                        expires,
                        local,
                        remote: remote_path,
                        direction,
                    });
                }
                owner.retained = true;
                let expiring_manager = manager.clone();
                let expiring_session = session.clone();
                drop(tokio::spawn(async move {
                    tokio::time::sleep_until(expires).await;
                    let _ =
                        expiring_manager.discard_directory_copy(&expiring_session, &id.to_string());
                }));
                Ok(PrepareResult::Prepared { selection: snapshot })
            }
            .await;
            if reply.send(result).is_err() && owner.retained {
                let _ = manager.discard_directory_copy(&session, &id.to_string());
            }
        }));
        received.await.map_err(|_| Issue::Failed)?
    }

    /// Admit a valid reviewed selection once; root-name input refusals retain its expiry.
    pub fn enqueue_directory_copy(
        &self,
        session_id: &str,
        transport_id: &str,
        selection_id: &str,
        root_name: &str,
    ) -> Result<SessionTransferEnqueueResult, Issue> {
        let id = Uuid::parse_str(selection_id).map_err(|_| Issue::Unavailable)?;
        let transport = Uuid::parse_str(transport_id).map_err(|_| Issue::Unavailable)?;
        let result = {
            let mut sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
            let entry = sessions.get_mut(session_id).ok_or(Issue::Unavailable)?;
            let selection = entry
                .directory_copy
                .as_ref()
                .filter(|record| record.id == id && record.transport == transport)
                .ok_or(Issue::Unavailable)?;
            if Instant::now() >= selection.expires {
                let selection = entry.directory_copy.take().expect("matching selection");
                entry.transfers.release_selection(selection.reservation);
                entry.transfer_notify.notify_one();
                return Err(Issue::SelectionExpired);
            }
            let root = session_files::directory_copy::root_name(root_name, selection.direction)?;
            if *entry.intent.borrow() != Intent::None
                || entry
                    .active
                    .as_ref()
                    .is_none_or(|active| !active.ready || active.id != transport)
            {
                return Err(Issue::Unavailable);
            }
            let selection = entry.directory_copy.take().expect("matching selection");
            let direction = selection.direction;
            let result = entry.transfers.enqueue_directory_copy(
                selection.reservation,
                root_name,
                direction,
                SelectedTransfer::Directory(DirectoryCopy {
                    local: selection.local,
                    remote: selection.remote,
                    root_name: root,
                    direction,
                }),
            )?;
            entry.transfer_notify.notify_one();
            result
        };
        self.start_transfer_worker(session_id);
        Ok(result)
    }

    /// Release an unapplied prepared selection without changing admitted queue work.
    pub fn discard_directory_copy(
        &self,
        session_id: &str,
        selection_id: &str,
    ) -> Result<(), Issue> {
        let id = Uuid::parse_str(selection_id).map_err(|_| Issue::Unavailable)?;
        let mut sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
        let entry = sessions.get_mut(session_id).ok_or(Issue::Unavailable)?;
        if entry.directory_copy.as_ref().is_some_and(|selection| selection.id == id)
            && let Some(selection) = entry.directory_copy.take()
        {
            entry.transfers.release_selection(selection.reservation);
            entry.transfer_notify.notify_one();
        }
        Ok(())
    }

    pub(super) fn directory_copy_callbacks(
        &self,
        session: &str,
        identity: TransferIdentity,
        state: Arc<UploadState>,
    ) -> Callbacks {
        let progress_sessions = self.sessions.clone();
        let progress_session = session.to_owned();
        let authorize_sessions = self.sessions.clone();
        let authorize_session = session.to_owned();
        let settled_sessions = self.sessions.clone();
        let settled_session = session.to_owned();
        let settled_state = state.clone();
        Callbacks {
            state,
            progress: Arc::new(move |transferred, total, progress| {
                if let Ok(mut sessions) = progress_sessions.lock()
                    && let Some(entry) = sessions.get_mut(&progress_session)
                {
                    entry.transfers.directory_progress(identity, transferred, total, progress);
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
        }
    }

    pub(super) async fn execute_directory_copy(
        &self,
        session: &str,
        identity: TransferIdentity,
        guard: FileRequestGuard<'_>,
        input: DirectoryCopy,
    ) -> TransferExecutionResult {
        let (reply, received) = oneshot::channel();
        let (sender, control) = watch::channel(TransferControl::Run);
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
                .try_send(FileCommand::TransferDirectory {
                    input,
                    control,
                    state: guard.upload_state.clone(),
                    session_id: session.to_owned(),
                    identity,
                    reply,
                })
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
                    Some(Issue::Unavailable) => issue_completion(
                        SessionTransferIssue::TransportEnded,
                        result.staging_may_remain,
                    ),
                    Some(issue) => issue_completion(
                        match issue {
                            Issue::PublicationUnknown => SessionTransferIssue::PublicationUnknown,
                            Issue::SourceChanged => SessionTransferIssue::SourceChanged,
                            Issue::TargetChanged | Issue::DestinationExists => {
                                SessionTransferIssue::TargetChanged
                            }
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
}

#[cfg(test)]
mod tests;
