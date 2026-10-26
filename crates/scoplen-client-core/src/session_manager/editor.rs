// SPDX-License-Identifier: Apache-2.0

use std::pin::Pin;

use crate::session_editor::{
    SessionEditorIssue as Issue, SessionEditorSnapshot, SessionEditorStartResult,
    SessionEditorState as State, SessionEditorTransfer,
};
use crate::session_files::FileAccessError;
use crate::session_transfers::{
    SessionTransferDirection, SessionTransferEnqueueResult, SessionTransferIssue,
    SessionTransferState,
};

use super::*;

type Launcher =
    Arc<dyn Fn(PathBuf) -> Pin<Box<dyn Future<Output = Result<(), Issue>> + Send>> + Send + Sync>;

pub(super) struct EditorRecord {
    pub(super) id: Uuid,
    pub(super) transport: Uuid,
    target: Vec<u8>,
    path: Option<PathBuf>,
    baseline: Option<DownloadDestination>,
    upload_baseline: Option<DownloadDestination>,
    state: State,
    issue: Option<Issue>,
    transfer: Option<SessionEditorTransfer>,
    direction: SessionTransferDirection,
    transfer_complete: bool,
    saved: bool,
    pub(super) ended: bool,
    launcher: Launcher,
}

impl EditorRecord {
    pub(super) fn end_transport(&mut self) {
        self.ended = true;
        self.state = State::Unavailable;
        self.issue = Some(Issue::Unavailable);
    }

    fn snapshot(&self, session: &str) -> SessionEditorSnapshot {
        let remote_name = session_files::display_remote_path(&self.target);
        SessionEditorSnapshot {
            session_id: session.to_owned(),
            editor_id: self.id.to_string(),
            transport_id: self.transport.to_string(),
            remote_name,
            local_name: self.path.as_ref().map(|path| {
                session_files::display_name(
                    path.file_name().unwrap_or_default().to_string_lossy().as_bytes(),
                )
            }),
            state: self.state,
            issue: self.issue,
            can_open: self.saved && self.transfer_complete && self.state != State::Opening,
            transfer: self.transfer.clone(),
        }
    }
}

fn active(entry: &SessionEntry, transport: Uuid) -> bool {
    *entry.intent.borrow() == Intent::None
        && entry.active.as_ref().is_some_and(|current| current.ready && current.id == transport)
}

fn transfer_issue(issue: SessionTransferIssue) -> Issue {
    match issue {
        SessionTransferIssue::QueueFull | SessionTransferIssue::NativeDialogBusy => {
            Issue::QueueFull
        }
        SessionTransferIssue::InvalidSelection | SessionTransferIssue::InvalidPath => {
            Issue::InvalidSelection
        }
        SessionTransferIssue::LocalIo => Issue::LocalIo,
        SessionTransferIssue::TargetChanged => Issue::TargetChanged,
        SessionTransferIssue::PublicationUnknown => Issue::PublicationUnknown,
        SessionTransferIssue::TransportEnded
        | SessionTransferIssue::SessionUnavailable
        | SessionTransferIssue::StaleItem
        | SessionTransferIssue::InvalidIdentifier => Issue::Unavailable,
        _ => Issue::TransferFailed,
    }
}

fn file_issue(error: &FileAccessError) -> Issue {
    match error {
        FileAccessError::PreviewTooLarge => Issue::TooLarge,
        FileAccessError::PreviewNotText => Issue::NotText,
        FileAccessError::InvalidSource
        | FileAccessError::InvalidDestination
        | FileAccessError::NotRegularFile => Issue::InvalidSelection,
        FileAccessError::LocalIo(_) | FileAccessError::LocalSourceIo(_) => Issue::LocalIo,
        FileAccessError::Conflict => Issue::TargetChanged,
        FileAccessError::ConnectionEnded => Issue::Unavailable,
        FileAccessError::PublicationUnknown => Issue::PublicationUnknown,
        _ => Issue::TransferFailed,
    }
}

pub(super) fn attach_transfer(
    entry: &mut SessionEntry,
    id: Uuid,
    direction: SessionTransferDirection,
    result: &SessionTransferEnqueueResult,
) {
    let Some(editor) = entry.editor.as_mut().filter(|editor| editor.id == id) else { return };
    let SessionTransferEnqueueResult::Queued { queue_id, item_id, execution_id } = result else {
        return;
    };
    editor.transfer = Some(SessionEditorTransfer {
        queue_id: queue_id.clone(),
        item_id: item_id.clone(),
        execution_id: execution_id.clone(),
    });
    editor.direction = direction;
    editor.transfer_complete = false;
    editor.issue = None;
    editor.state = if direction == SessionTransferDirection::Download {
        State::Preparing
    } else {
        State::Queued
    };
}

impl SessionManager {
    /// Observe the local-editor registration without launching or transferring anything.
    pub fn editor_snapshot(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionEditorSnapshot>, Issue> {
        let sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
        let entry = sessions.get(session_id).ok_or(Issue::Unavailable)?;
        Ok(entry.editor.as_ref().map(|editor| editor.snapshot(session_id)))
    }

    /// Select a retained working-copy destination and queue a complete text download.
    #[allow(clippy::too_many_arguments)]
    pub async fn edit_file_with_picker<F, Fut, C, ConfirmFut, L, LaunchFut>(
        &self,
        session_id: &str,
        transport_id: &str,
        remote_path: Vec<u8>,
        choose_destination: F,
        confirm_replace: C,
        launch: L,
    ) -> Result<SessionEditorStartResult, Issue>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Option<PathBuf>, SessionTransferIssue>> + Send + 'static,
        C: FnOnce(crate::session_transfers::SessionTransferReview) -> ConfirmFut + Send + 'static,
        ConfirmFut: Future<Output = Result<bool, SessionTransferIssue>> + Send + 'static,
        L: Fn(PathBuf) -> LaunchFut + Send + Sync + 'static,
        LaunchFut: Future<Output = Result<(), Issue>> + Send + 'static,
    {
        session_files::validate_path(&remote_path).map_err(|_| Issue::InvalidSelection)?;
        let name = remote_path.rsplit(|byte| *byte == b'/').next().unwrap_or_default();
        if name.is_empty() || name == b"." || name == b".." {
            return Err(Issue::InvalidSelection);
        }
        {
            let sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
            let entry = sessions.get(session_id).ok_or(Issue::Unavailable)?;
            if !entry.pty {
                return Err(Issue::Unavailable);
            }
            if entry.editor.is_some() {
                return Err(Issue::AlreadyEditing);
            }
        }
        let (transport, reservation) =
            self.reserve_transfer_selection(session_id, transport_id).map_err(transfer_issue)?;
        let selection = transfers::SelectionLease {
            manager: self.clone(),
            session: session_id.to_owned(),
            reservation,
        };
        let id = Uuid::now_v7();
        {
            let mut sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
            let entry = sessions.get_mut(session_id).ok_or(Issue::Unavailable)?;
            if entry.editor.is_some() {
                return Err(Issue::AlreadyEditing);
            }
            if !active(entry, transport) {
                return Err(Issue::Unavailable);
            }
            entry.editor = Some(EditorRecord {
                id,
                transport,
                target: remote_path.clone(),
                path: None,
                baseline: None,
                upload_baseline: None,
                state: State::Preparing,
                issue: None,
                transfer: None,
                direction: SessionTransferDirection::Download,
                transfer_complete: false,
                saved: false,
                ended: false,
                launcher: Arc::new(move |path| Box::pin(launch(path))),
            });
        }
        self.start_editor_observer(session_id, id);
        let manager = self.clone();
        let session = session_id.to_owned();
        tokio::spawn(async move {
            let _selection = selection;
            let result = async {
                let Some(path) = choose_destination().await.map_err(transfer_issue)? else {
                    manager.remove_editor(&session, id);
                    return Ok(SessionEditorStartResult::Cancelled);
                };
                let destination =
                    DownloadDestination::capture(path.clone()).await.map_err(transfer_issue)?;
                {
                    let mut sessions = manager.sessions.lock().map_err(|_| Issue::Unavailable)?;
                    let entry = sessions.get_mut(&session).ok_or(Issue::Unavailable)?;
                    if !active(entry, transport) {
                        return Err(Issue::Unavailable);
                    }
                    let editor = entry
                        .editor
                        .as_mut()
                        .filter(|editor| editor.id == id && !editor.ended)
                        .ok_or(Issue::Unavailable)?;
                    editor.path = Some(path);
                }
                let name = session_files::display_name(
                    remote_path.rsplit(|byte| *byte == b'/').next().unwrap_or_default(),
                );
                manager
                    .enqueue_selected_transfer(
                        &session,
                        transport,
                        reservation,
                        &name,
                        SessionTransferDirection::Download,
                        None,
                        SelectedTransfer::Download {
                            remote_path,
                            destination,
                            confirm: Box::new(move |review| Box::pin(confirm_replace(review))),
                            editor: Some(id),
                        },
                    )
                    .map_err(transfer_issue)?;
                Ok(SessionEditorStartResult::Started { editor_id: id.to_string() })
            }
            .await;
            if let Err(issue) = result {
                manager.set_editor_issue(&session, id, issue);
            }
            result
        })
        .await
        .map_err(|_| Issue::Unavailable)?
    }

    /// Explicitly open the retained local copy in the fixed platform text editor.
    pub async fn open_editor(&self, session_id: &str, editor_id: &str) -> Result<(), Issue> {
        let id = Uuid::parse_str(editor_id).map_err(|_| Issue::Unavailable)?;
        let (path, launcher, previous) = {
            let mut sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
            let editor = sessions
                .get_mut(session_id)
                .and_then(|entry| entry.editor.as_mut())
                .filter(|editor| editor.id == id && editor.saved)
                .ok_or(Issue::Unavailable)?;
            if editor.state == State::Opening || !editor.transfer_complete {
                return Err(Issue::Unavailable);
            }
            let path = editor.path.clone().ok_or(Issue::Unavailable)?;
            let previous = editor.state;
            editor.state = State::Opening;
            editor.issue = None;
            (path, editor.launcher.clone(), previous)
        };
        let result = launcher(path).await;
        if let Ok(mut sessions) = self.sessions.lock()
            && let Some(editor) = sessions
                .get_mut(session_id)
                .and_then(|entry| entry.editor.as_mut())
                .filter(|editor| editor.id == id)
        {
            if editor.ended {
                editor.end_transport();
            } else if let Err(issue) = result {
                editor.state = State::Unavailable;
                editor.issue = Some(issue);
            } else {
                editor.state = if matches!(
                    previous,
                    State::ChangesDetected | State::Uploaded | State::Unknown
                ) {
                    previous
                } else {
                    State::Watching
                };
                editor.issue = None;
            }
        }
        result
    }

    /// Reopen the latest local save and queue an explicit upload to the original target.
    pub async fn upload_editor<C, ConfirmFut>(
        &self,
        session_id: &str,
        transport_id: &str,
        editor_id: &str,
        confirm_replace: C,
    ) -> Result<SessionTransferEnqueueResult, Issue>
    where
        C: FnOnce(crate::session_transfers::SessionTransferReview) -> ConfirmFut + Send + 'static,
        ConfirmFut: Future<Output = Result<bool, SessionTransferIssue>> + Send + 'static,
    {
        let id = Uuid::parse_str(editor_id).map_err(|_| Issue::Unavailable)?;
        let (path, target) = {
            let sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
            let entry = sessions.get(session_id).ok_or(Issue::Unavailable)?;
            let editor = entry
                .editor
                .as_ref()
                .filter(|editor| editor.id == id && editor.saved && !editor.ended)
                .ok_or(Issue::Unavailable)?;
            if editor.transport.to_string() != transport_id || !active(entry, editor.transport) {
                return Err(Issue::Unavailable);
            }
            if editor.state == State::Unknown {
                return Err(Issue::PublicationUnknown);
            }
            if !editor.transfer_complete || editor.state == State::Opening {
                return Err(Issue::Unavailable);
            }
            (editor.path.clone().ok_or(Issue::Unavailable)?, editor.target.clone())
        };
        let result = async {
            let (transport, reservation) = self
                .reserve_transfer_selection(session_id, transport_id)
                .map_err(transfer_issue)?;
            let _selection = transfers::SelectionLease {
                manager: self.clone(),
                session: session_id.to_owned(),
                reservation,
            };
            let baseline =
                DownloadDestination::capture(path.clone()).await.map_err(transfer_issue)?;
            let source = session_files::open_editor_upload_source(&path)
                .await
                .map_err(|error| file_issue(&error))?;
            let directory = match target.iter().rposition(|byte| *byte == b'/') {
                Some(0) => b"/".to_vec(),
                Some(index) => target[..index].to_vec(),
                None => b".".to_vec(),
            };
            {
                let mut sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
                let entry = sessions.get_mut(session_id).ok_or(Issue::Unavailable)?;
                if !active(entry, transport) {
                    return Err(Issue::Unavailable);
                }
                let editor = entry
                    .editor
                    .as_mut()
                    .filter(|editor| editor.id == id && !editor.ended)
                    .ok_or(Issue::Unavailable)?;
                editor.upload_baseline = Some(baseline);
            }
            let name = session_files::display_name(
                target.rsplit(|byte| *byte == b'/').next().unwrap_or_default(),
            );
            let size = source.size();
            self.enqueue_selected_transfer(
                session_id,
                transport,
                reservation,
                &name,
                SessionTransferDirection::Upload,
                Some(size),
                SelectedTransfer::Upload {
                    source,
                    directory,
                    target,
                    confirm: Box::new(move |review| Box::pin(confirm_replace(review))),
                    editor: Some(id),
                },
            )
            .map_err(transfer_issue)
        }
        .await;
        if let Err(issue) = result {
            self.set_editor_issue(session_id, id, issue);
        }
        result
    }

    /// Stop observing and uploading; the user's copy and external editor remain untouched.
    pub fn stop_editor(&self, session_id: &str, editor_id: &str) -> Result<(), Issue> {
        let id = Uuid::parse_str(editor_id).map_err(|_| Issue::Unavailable)?;
        let transfer = {
            let mut sessions = self.sessions.lock().map_err(|_| Issue::Unavailable)?;
            let entry = sessions.get_mut(session_id).ok_or(Issue::Unavailable)?;
            if entry.editor.as_ref().is_none_or(|editor| editor.id != id) {
                return Err(Issue::Unavailable);
            }
            entry
                .editor
                .take()
                .and_then(|editor| (!editor.transfer_complete).then_some(editor.transfer).flatten())
        };
        if let Some(transfer) = transfer {
            let _ = self.cancel_transfer(
                session_id,
                &transfer.queue_id,
                &transfer.item_id,
                &transfer.execution_id,
            );
        }
        Ok(())
    }

    fn remove_editor(&self, session: &str, id: Uuid) {
        if let Ok(mut sessions) = self.sessions.lock()
            && let Some(entry) = sessions.get_mut(session)
            && entry.editor.as_ref().is_some_and(|editor| editor.id == id)
        {
            entry.editor.take();
        }
    }

    fn set_editor_issue(&self, session: &str, id: Uuid, issue: Issue) {
        if let Ok(mut sessions) = self.sessions.lock()
            && let Some(editor) = sessions
                .get_mut(session)
                .and_then(|entry| entry.editor.as_mut())
                .filter(|editor| editor.id == id)
        {
            editor.issue = Some(issue);
            if !editor.saved {
                editor.state = State::Unavailable;
            }
        }
    }

    pub(super) fn editor_transfer_error(
        &self,
        session: &str,
        identity: TransferIdentity,
        error: &FileAccessError,
    ) {
        if let Ok(mut sessions) = self.sessions.lock()
            && let Some(editor) = sessions.get_mut(session).and_then(|entry| entry.editor.as_mut())
            && editor.transfer.as_ref().is_some_and(|transfer| {
                transfer.item_id == identity.item.to_string()
                    && transfer.execution_id == identity.execution.to_string()
            })
        {
            editor.issue = Some(file_issue(error));
        }
    }

    fn start_editor_observer(&self, session: &str, id: Uuid) {
        let manager = self.clone();
        let session = session.to_owned();
        drop(tokio::spawn(async move {
            while manager.observe_editor(&session, id).await {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }));
    }

    async fn observe_editor(&self, session: &str, id: Uuid) -> bool {
        let (path, baseline, launch) = {
            let Ok(mut sessions) = self.sessions.lock() else { return false };
            let Some(entry) = sessions.get_mut(session) else { return false };
            let current = entry.editor.as_ref().is_some_and(|editor| {
                editor.id == id && !editor.ended && active(entry, editor.transport)
            });
            if !current {
                if let Some(editor) = entry.editor.as_mut().filter(|editor| editor.id == id) {
                    editor.end_transport();
                }
                return false;
            }
            let queue = entry.transfers.snapshot(session);
            let editor = entry.editor.as_mut().expect("current editor exists");
            let mut launch = false;
            if let Some(transfer) = &editor.transfer
                && !editor.transfer_complete
            {
                let item = queue.items.iter().chain(&queue.recent).find(|item| {
                    item.item_id == transfer.item_id && item.execution_id == transfer.execution_id
                });
                match item.map(|item| item.state) {
                    Some(SessionTransferState::Saved) => {
                        editor.transfer_complete = true;
                        editor.issue = None;
                        if editor.direction == SessionTransferDirection::Download {
                            editor.saved = true;
                            launch = true;
                        } else {
                            editor.baseline = editor.upload_baseline.take();
                            editor.state = State::Uploaded;
                        }
                    }
                    Some(SessionTransferState::Unknown) => {
                        editor.state = State::Unknown;
                        editor.issue = Some(Issue::PublicationUnknown);
                    }
                    None if editor.state == State::Unknown => {
                        editor.transfer_complete = true;
                        editor.state = State::ChangesDetected;
                        editor.issue = None;
                    }
                    Some(SessionTransferState::Queued) => {
                        editor.state = if editor.direction == SessionTransferDirection::Upload {
                            State::Queued
                        } else {
                            State::Preparing
                        };
                    }
                    Some(
                        SessionTransferState::Cancelled
                        | SessionTransferState::Conflict
                        | SessionTransferState::Failed
                        | SessionTransferState::Interrupted,
                    ) => {
                        editor.transfer_complete = true;
                        editor.state =
                            if editor.saved { State::ChangesDetected } else { State::Unavailable };
                        editor.issue = editor
                            .issue
                            .or_else(|| item.and_then(|item| item.issue).map(transfer_issue));
                    }
                    Some(_) if editor.direction == SessionTransferDirection::Upload => {
                        editor.state = State::Uploading
                    }
                    _ => {}
                }
            }
            (editor.path.clone().filter(|_| editor.saved), editor.baseline.clone(), launch)
        };
        let Some(path) = path else { return true };
        if launch {
            match DownloadDestination::capture(path).await {
                Ok(baseline) => {
                    if let Ok(mut sessions) = self.sessions.lock()
                        && let Some(editor) = sessions
                            .get_mut(session)
                            .and_then(|entry| entry.editor.as_mut())
                            .filter(|editor| editor.id == id && !editor.ended)
                    {
                        editor.baseline = Some(baseline);
                    }
                    let _ = self.open_editor(session, &id.to_string()).await;
                }
                Err(issue) => {
                    if let Ok(mut sessions) = self.sessions.lock()
                        && let Some(editor) = sessions
                            .get_mut(session)
                            .and_then(|entry| entry.editor.as_mut())
                            .filter(|editor| editor.id == id)
                    {
                        editor.state = State::Unavailable;
                        editor.issue = Some(transfer_issue(issue));
                    }
                }
            }
        } else if let Some(baseline) = baseline {
            let changed = baseline.check().await.is_err();
            if changed
                && let Ok(mut sessions) = self.sessions.lock()
                && let Some(editor) = sessions
                    .get_mut(session)
                    .and_then(|entry| entry.editor.as_mut())
                    .filter(|editor| editor.id == id && !editor.ended)
                && matches!(
                    editor.state,
                    State::Watching | State::Uploaded | State::ChangesDetected
                )
            {
                editor.state = State::ChangesDetected;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests;
