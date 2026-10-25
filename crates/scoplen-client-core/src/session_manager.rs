// SPDX-License-Identifier: Apache-2.0

//! Rust-owned terminal sessions, bounded transport attempts, and reconnect policy.

use std::collections::HashMap;
use std::future::Future;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::future::{AbortHandle, Abortable};
use scoplen_ssh::{ChannelEvent, ClientError, ProxyError, ProxyTransportError, TransportError};
use serde::Serialize;
use specta::Type;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::time::Instant;
use uuid::Uuid;

use crate::connection::preparation::{
    PreparationContext, PreparationControl, PreparationError, PreparationEvent,
    PreparationResponse, prepare_connection,
};
use crate::connection::{MAX_SSH_INPUT, SshConnectionError, SshSession, terminal_size};
use crate::inventory::{DeletionStore, Inventory, RecentSessionKind, RecentSessionOutcome};
use crate::session_files::{
    self, DownloadCheckpoint, DownloadExecution, DownloadInput, FileTransferProgress,
    MutationPreflight, RemoteDirectory, RemoteMutation, RemoteTextPreview, RemoteTextPreviewIssue,
    SessionDownloadResult, SessionDownloadStatus, SessionFileMutationResult,
    SessionFileMutationStatus, SessionFileTransferPhase, SessionUploadResult, SessionUploadStatus,
    TransferControl, UploadExecution, UploadInput, UploadPreflight, UploadSource, UploadState,
};
use crate::session_lifecycle::SessionHistoryLease;
use crate::session_transfers::{
    DownloadDestination, SelectedTransfer, TransferIdentity, TransferQueue,
};
use crate::store::Store;
use crate::terminal_output::{SavedOutputError, TerminalSnapshot};

const COMMAND_QUEUE: usize = 64;
const FILE_QUEUE: usize = 1;
const FILE_LIST_TIMEOUT: Duration = Duration::from_secs(20);
const FILE_PREVIEW_TIMEOUT: Duration = Duration::from_secs(60);
const STABLE_READY: Duration = Duration::from_secs(30);
const RETRY_DELAYS: [u8; 5] = [1, 2, 4, 8, 16];

pub mod file_drop;
mod transfers;

/// Display-safe state of one logical terminal. Output is delivered as binary frames.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SessionEvent {
    /// A fresh transport is about to resolve the current saved Login.
    Starting {
        /// Opaque attempt identity used to fence input and output.
        transport_id: String,
        /// Whether this attempt follows the automatic reconnect policy.
        automatic: bool,
    },
    /// Progress or a one-time prompt for this transport.
    Preparation {
        /// Current transport identity.
        transport_id: String,
        /// Current hop's progress or prompt.
        event: Box<PreparationEvent>,
    },
    /// Shell setup completed independently of receiving output.
    Ready {
        /// Only this transport may receive subsequent terminal input.
        transport_id: String,
    },
    /// A typed network failure qualified for the next bounded retry.
    Retrying {
        /// One-based automatic attempt number, at most five.
        attempt: u8,
        /// Fixed delay before the next attempt.
        delay_seconds: u8,
        /// Display-safe reason for the preceding failure.
        error: String,
    },
    /// The remote shell exited or the person stopped reconnecting.
    Closed,
    /// The session remains available for an explicit manual reconnect.
    Failed {
        /// Actionable error, without credential or helper output.
        error: String,
        /// All five automatic attempts have been consumed.
        exhausted: bool,
    },
}

/// Transfer progress for one file operation on one authenticated transport.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionFileTransferProgress {
    /// Logical terminal session owning the transfer.
    pub session_id: String,
    /// Exact authenticated connection attempt.
    pub transport_id: String,
    /// Exact file operation within that connection.
    pub operation_id: String,
    /// Decimal text preserves the full 64-bit byte count in JavaScript.
    pub transferred_bytes: String,
    /// Expected total as decimal text, when available.
    pub total_bytes: Option<String>,
    /// Data transfer or final save stage; neither implies success.
    pub phase: SessionFileTransferPhase,
}

/// A Recent record opened or ended by one transport attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryChange {
    /// An attempt opened a Recent record.
    Opened,
    /// An attempt recorded its final outcome.
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Intent {
    None,
    Retry,
    Stop,
    Fail,
    Close,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Reserved,
    Running,
    Retrying,
    Ended,
}

#[derive(Debug, Eq, PartialEq)]
enum TransportCommand {
    Input(Vec<u8>),
    Resize { columns: u32, rows: u32 },
}

enum FileCommand {
    TransferUpload {
        input: UploadInput,
        control: watch::Receiver<TransferControl>,
        state: Arc<UploadState>,
        session_id: String,
        transport: Uuid,
        operation: Uuid,
        reply: oneshot::Sender<UploadExecution>,
    },
    TransferDownload {
        input: DownloadInput,
        control: watch::Receiver<TransferControl>,
        session_id: String,
        transport: Uuid,
        operation: Uuid,
        reply: oneshot::Sender<Result<DownloadExecution, session_files::FileAccessError>>,
    },
    List {
        path: Vec<u8>,
        reply: oneshot::Sender<Result<RemoteDirectory, String>>,
    },
    Preview {
        path: Vec<u8>,
        reply: oneshot::Sender<Result<RemoteTextPreview, RemoteTextPreviewIssue>>,
    },
    Download {
        remote_path: Vec<u8>,
        destination: PathBuf,
        baseline: Option<DownloadDestination>,
        session_id: String,
        transport: Uuid,
        operation: Uuid,
        progress: FileProgressSink,
        reply: oneshot::Sender<SessionDownloadResult>,
    },
    PreflightUpload {
        target: Vec<u8>,
        reply: oneshot::Sender<Result<UploadPreflight, String>>,
    },
    Upload {
        source: Box<UploadSource>,
        directory: Vec<u8>,
        target: Vec<u8>,
        preflight: UploadPreflight,
        cancel: watch::Receiver<bool>,
        state: Arc<UploadState>,
        session_id: String,
        transport: Uuid,
        operation: Uuid,
        progress: FileProgressSink,
        reply: oneshot::Sender<SessionUploadResult>,
    },
    PreflightMutation {
        mutation: RemoteMutation,
        reply: oneshot::Sender<Result<MutationPreflight, session_files::FileAccessError>>,
    },
    Mutation {
        mutation: RemoteMutation,
        preflight: MutationPreflight,
        cancel: watch::Receiver<bool>,
        session_id: String,
        transport: Uuid,
        operation: Uuid,
        reply: oneshot::Sender<SessionFileMutationResult>,
    },
}

type FileProgressSink = Box<dyn FnMut(SessionFileTransferProgress) + Send>;

enum PreparedUpload {
    Done(SessionUploadResult),
    Ready { source: Box<UploadSource>, target: Vec<u8>, preflight: UploadPreflight },
}

struct ActiveFile {
    id: Uuid,
    abort: AbortHandle,
    upload_state: Arc<UploadState>,
    effect_cancel: Option<watch::Sender<bool>>,
    transfer: Option<TransferIdentity>,
    transfer_control: Option<watch::Sender<TransferControl>>,
}

struct ActiveAttempt {
    id: Uuid,
    control: PreparationControl,
    sender: mpsc::Sender<TransportCommand>,
    files: mpsc::Sender<FileCommand>,
    file: Option<ActiveFile>,
    ready: bool,
    context: Option<PreparationContext>,
}

struct FileRequestGuard<'a> {
    manager: &'a SessionManager,
    session_id: &'a str,
    transport: Uuid,
    operation: Uuid,
    abort: AbortHandle,
    upload_state: Arc<UploadState>,
}

impl Drop for FileRequestGuard<'_> {
    fn drop(&mut self) {
        let Ok(mut sessions) = self.manager.sessions.lock() else { return };
        if self.upload_state.effect_started.load(Ordering::SeqCst) {
            return;
        }
        // Publication claims use this same lock, including the decision to abort.
        self.abort.abort();
        if let Some(entry) = sessions.get_mut(self.session_id)
            && let Some(active) = entry.active.as_mut()
            && active.id == self.transport
            && active.file.as_ref().is_some_and(|file| file.id == self.operation)
        {
            if let Some(cancel) = active.file.as_ref().and_then(|file| file.effect_cancel.as_ref())
            {
                cancel.send_replace(true);
            } else {
                active.file.take();
            }
            entry.transfer_notify.notify_one();
        }
    }
}

struct SessionEntry {
    pty: bool,
    phase: Phase,
    intent: watch::Sender<Intent>,
    receiver: Option<watch::Receiver<Intent>>,
    active: Option<ActiveAttempt>,
    checkpoint: Option<CheckpointOwner>,
    transfers: TransferQueue<SelectedTransfer>,
    transfer_notify: Arc<Notify>,
    transfer_worker_running: bool,
}

struct CheckpointOwner {
    store: Arc<Store>,
    history: Uuid,
    transport: Uuid,
    sequence: u32,
}

fn interrupt_transfers(entry: &mut SessionEntry, transport: Uuid) {
    let interrupted = entry.transfers.interrupt_transport(transport);
    if let Some(identity) = interrupted.running
        && let Some(file) = entry.active.as_ref().and_then(|active| active.file.as_ref())
        && file.transfer == Some(identity)
        && !file.upload_state.effect_started.load(Ordering::SeqCst)
    {
        if let Some(control) = &file.transfer_control {
            control.send_replace(TransferControl::Cancel);
        } else if let Some(cancel) = &file.effect_cancel {
            cancel.send_replace(true);
        } else {
            file.abort.abort();
        }
    }
    drop(interrupted.selected);
    entry.transfer_notify.notify_one();
}

/// Owns logical terminal lifetimes independently of renderer visibility.
///
/// Each active transport has a separate bounded queue and preparation control.
/// Replacing it drops old queued input rather than replaying it into a new shell.
#[derive(Clone, Default)]
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
    drops: Arc<Mutex<HashMap<String, file_drop::DropContext>>>,
}

struct Registration<'a> {
    manager: &'a SessionManager,
    id: &'a str,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.manager.sessions.lock()
            && let Some(mut entry) = sessions.remove(self.id)
        {
            let closing = *entry.intent.borrow() == Intent::Close;
            if let Some(transport) = entry.active.as_ref().map(|active| active.id) {
                interrupt_transfers(&mut entry, transport);
            }
            entry.transfer_notify.notify_one();
            if let Some(active) = entry.active.take() {
                active.control.cancel();
                if let Some(file) = active.file
                    && !file.upload_state.effect_started.load(Ordering::SeqCst)
                {
                    file.abort.abort();
                }
            }
            if entry.transfers.has_state()
                && (!closing || entry.transfers.has_pending() || entry.transfers.is_settling())
            {
                entry.phase = Phase::Ended;
                let (intent, receiver) =
                    watch::channel(if closing { Intent::Close } else { Intent::None });
                entry.intent = intent;
                entry.receiver = Some(receiver);
                sessions.insert(self.id.to_owned(), entry);
            }
        }
        self.manager.start_transfer_worker(self.id);
    }
}

#[derive(Default)]
struct RetryBudget {
    ever_ready: bool,
    attempts: usize,
}

impl RetryBudget {
    fn ended(&mut self, ready_for: Option<Duration>) {
        if let Some(ready_for) = ready_for {
            self.ever_ready = true;
            if ready_for >= STABLE_READY {
                self.attempts = 0;
            }
        }
    }

    fn next(&mut self) -> Option<u8> {
        if !self.ever_ready {
            return None;
        }
        let delay = *RETRY_DELAYS.get(self.attempts)?;
        self.attempts += 1;
        Some(delay)
    }
}

#[derive(Debug, thiserror::Error)]
enum AttemptError {
    #[error(transparent)]
    Preparation(#[from] PreparationError),
    #[error(transparent)]
    Connection(#[from] SshConnectionError),
    #[error("{0}")]
    Local(String),
}

impl AttemptError {
    fn retryable(&self) -> bool {
        match self {
            Self::Connection(error) => retryable_connection(error),
            Self::Preparation(PreparationError::Connection(error)) => retryable_connection(error),
            _ => false,
        }
    }
}

fn retryable_io(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::NotConnected
            | ErrorKind::BrokenPipe
            | ErrorKind::TimedOut
            | ErrorKind::UnexpectedEof
            | ErrorKind::NetworkDown
            | ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
    )
}

fn retryable_transport(error: &TransportError) -> bool {
    match error {
        TransportError::Resolution { kind }
        | TransportError::Connect { kind, .. }
        | TransportError::Io { kind, .. } => retryable_io(*kind),
        TransportError::ConnectTimeout { .. } => true,
        TransportError::Proxy { error: ProxyError::Io { kind, .. }, .. } => retryable_io(*kind),
        _ => false,
    }
}

fn retryable_connection(error: &SshConnectionError) -> bool {
    match error {
        SshConnectionError::Engine(ClientError::NetworkLost) => true,
        SshConnectionError::Engine(ClientError::Transport(error)) => retryable_io(error.kind()),
        SshConnectionError::Engine(ClientError::DirectTcp(error)) => retryable_transport(error),
        SshConnectionError::Engine(ClientError::Proxy(ProxyTransportError::Transport(error))) => {
            retryable_transport(error)
        }
        SshConnectionError::Engine(ClientError::Proxy(ProxyTransportError::Proxy(
            ProxyError::Io { kind, .. },
        ))) => retryable_io(*kind),
        SshConnectionError::Engine(
            ClientError::DirectSshHandshakeTimeout { .. }
            | ClientError::ProxySshHandshakeTimeout { .. }
            | ClientError::ProxyCommandHandshakeTimeout { .. },
        )
        | SshConnectionError::JumpSetupTimeout => true,
        _ => false,
    }
}

impl SessionManager {
    /// Reserve a logical session before acknowledging it to the renderer.
    pub fn reserve(&self, session_id: &str, pty: bool) -> Result<(), String> {
        if session_id.trim().is_empty() || session_id.len() > 128 {
            return Err("session identifier must contain 1-128 bytes".into());
        }
        let mut sessions = self.sessions.lock().map_err(|_| "session manager is unavailable")?;
        if let Some(entry) = sessions.get_mut(session_id) {
            if entry.phase == Phase::Ended && entry.receiver.is_some() && entry.pty == pty {
                entry.phase = Phase::Reserved;
                return Ok(());
            }
            return Err("session is already connected".into());
        }
        let (intent, receiver) = watch::channel(Intent::None);
        sessions.insert(
            session_id.into(),
            SessionEntry {
                pty,
                phase: Phase::Reserved,
                intent,
                receiver: Some(receiver),
                active: None,
                checkpoint: None,
                transfers: TransferQueue::default(),
                transfer_notify: Arc::new(Notify::new()),
                transfer_worker_running: false,
            },
        );
        Ok(())
    }

    /// Cancel the complete logical session, including timers and prompts.
    pub fn close(&self, session_id: &str) -> Result<(), String> {
        self.intent(session_id, Intent::Close)
    }

    /// Cancel every logical session before replacing its owning profile.
    pub fn close_all(&self) -> Result<(), String> {
        let ids: Vec<_> = self
            .sessions
            .lock()
            .map_err(|_| "session manager is unavailable")?
            .keys()
            .cloned()
            .collect();
        for id in ids {
            let mut sessions =
                self.sessions.lock().map_err(|_| "session manager is unavailable")?;
            let Some(entry) = sessions.get_mut(&id) else {
                continue;
            };
            if *entry.intent.borrow() == Intent::Close {
                continue;
            }
            drop(sessions);
            // An owner may finish between the snapshot and cancellation.
            let _ = self.close(&id);
        }
        Ok(())
    }

    /// Save only a rendered checkpoint belonging to the exact current local owner.
    pub fn save_output(
        &self,
        store: &Arc<Store>,
        session_id: &str,
        transport_id: &str,
        sequence: u32,
        snapshot: &TerminalSnapshot,
    ) -> Result<(), SavedOutputError> {
        let transport =
            Uuid::parse_str(transport_id).map_err(|_| SavedOutputError::StaleCheckpoint)?;
        let mut sessions = self.sessions.lock().map_err(|_| SavedOutputError::Storage)?;
        let entry = sessions.get_mut(session_id).ok_or(SavedOutputError::StaleCheckpoint)?;
        let owner = entry.checkpoint.as_mut().ok_or(SavedOutputError::StaleCheckpoint)?;
        if !Arc::ptr_eq(&owner.store, store)
            || owner.transport != transport
            || sequence <= owner.sequence
            || *entry.intent.borrow() == Intent::Close
        {
            return Err(SavedOutputError::StaleCheckpoint);
        }
        store.save_scrollback(owner.history, snapshot)?;
        owner.sequence = sequence;
        Ok(())
    }

    /// Start a fresh manual budget after the preceding attempt has ended.
    pub fn retry(&self, session_id: &str) -> Result<(), String> {
        self.intent(session_id, Intent::Retry)
    }

    /// Stop reconnecting while preserving the logical session and terminal output.
    pub fn stop(&self, session_id: &str) -> Result<(), String> {
        self.intent(session_id, Intent::Stop)
    }

    /// A terminal capability or input failure must not trigger automatic retries.
    pub fn fail(&self, session_id: &str) -> Result<(), String> {
        self.intent(session_id, Intent::Fail)
    }

    fn intent(&self, session_id: &str, intent: Intent) -> Result<(), String> {
        let mut sessions = self.sessions.lock().map_err(|_| "session manager is unavailable")?;
        let entry = sessions.get_mut(session_id).ok_or("session is not connected")?;
        if intent == Intent::Retry && entry.phase != Phase::Ended {
            return Err("wait for the current connection attempt to end".into());
        }
        if *entry.intent.borrow() == Intent::Close {
            return Err("session is closed".into());
        }
        if intent != Intent::Retry
            && let Some(transport) = entry.active.as_ref().map(|active| active.id)
        {
            interrupt_transfers(entry, transport);
        }
        if intent != Intent::Retry
            && let Some(active) = &entry.active
        {
            active.control.cancel();
            if let Some(file) = &active.file
                && !file.upload_state.effect_started.load(Ordering::SeqCst)
            {
                file.abort.abort();
            }
        }
        entry.intent.send_replace(intent);
        if intent == Intent::Close
            && entry.receiver.is_some()
            && !entry.transfers.has_pending()
            && !entry.transfers.is_settling()
        {
            sessions.remove(session_id);
        }
        drop(sessions);
        self.start_transfer_worker(session_id);
        Ok(())
    }

    /// Reply only to the active attempt's one-use preparation prompt.
    pub fn respond(
        &self,
        session_id: &str,
        transport_id: &str,
        prompt_id: &str,
        response: PreparationResponse,
    ) -> Result<(), String> {
        let sessions = self.sessions.lock().map_err(|_| "session manager is unavailable")?;
        let control = &sessions
            .get(session_id)
            .and_then(|entry| entry.active.as_ref())
            .filter(|active| active.id.to_string() == transport_id)
            .ok_or("this connection prompt has expired")?
            .control;
        control.respond(prompt_id, response)
    }

    /// Send bounded input to the exact ready transport, never its replacement.
    pub fn input(&self, session_id: &str, transport_id: &str, data: Vec<u8>) -> Result<(), String> {
        if data.len() > MAX_SSH_INPUT {
            return Err("session input exceeds the 64 KiB limit".into());
        }
        self.send(session_id, transport_id, TransportCommand::Input(data))
    }

    /// Resize the exact ready transport after validating its cell dimensions.
    pub fn resize(
        &self,
        session_id: &str,
        transport_id: &str,
        columns: u32,
        rows: u32,
    ) -> Result<(), String> {
        terminal_size(columns, rows).map_err(|error| error.to_string())?;
        self.send(session_id, transport_id, TransportCommand::Resize { columns, rows })
    }

    /// Browse one remote directory on the current terminal's authenticated connection.
    pub async fn list_files(
        &self,
        session_id: &str,
        transport_id: &str,
        operation_id: &str,
        path: Vec<u8>,
    ) -> Result<RemoteDirectory, String> {
        let (abort, cancellation) = AbortHandle::new_pair();
        let guard = self.reserve_file_operation(session_id, transport_id, operation_id, abort)?;
        let (reply, received) = oneshot::channel();
        self.queue_file_request(&guard, FileCommand::List { path, reply })?;
        let result =
            Abortable::new(tokio::time::timeout(FILE_LIST_TIMEOUT, received), cancellation)
                .await
                .map_err(|_| "file operation was cancelled".to_owned())?
                .map_err(|_| "the remote directory did not respond; try again".to_owned())?
                .map_err(|_| "the file operation ended with this connection".to_owned())?;
        drop(guard);
        result
    }

    /// Disclose one complete bounded text file only to its current requesting transport.
    pub async fn preview_file(
        &self,
        session_id: &str,
        transport_id: &str,
        operation_id: &str,
        path: Vec<u8>,
    ) -> Result<RemoteTextPreview, RemoteTextPreviewIssue> {
        let (abort, cancellation) = AbortHandle::new_pair();
        let guard = self
            .reserve_file_operation(session_id, transport_id, operation_id, abort)
            .map_err(|_| RemoteTextPreviewIssue::Unavailable)?;
        let (reply, received) = oneshot::channel();
        self.queue_file_request(&guard, FileCommand::Preview { path, reply })
            .map_err(|_| RemoteTextPreviewIssue::Unavailable)?;
        let result =
            Abortable::new(tokio::time::timeout(FILE_PREVIEW_TIMEOUT, received), cancellation)
                .await
                .map_err(|_| RemoteTextPreviewIssue::Cancelled)?
                .map_err(|_| RemoteTextPreviewIssue::Timeout)?
                .map_err(|_| RemoteTextPreviewIssue::Unavailable)?;
        {
            let sessions = self.sessions.lock().map_err(|_| RemoteTextPreviewIssue::Unavailable)?;
            let current = sessions.get(session_id).is_some_and(|entry| {
                *entry.intent.borrow() == Intent::None
                    && entry.active.as_ref().is_some_and(|active| {
                        active.ready
                            && active.id == guard.transport
                            && active.file.as_ref().is_some_and(|file| file.id == guard.operation)
                    })
            });
            if !current || guard.abort.is_aborted() {
                return Err(RemoteTextPreviewIssue::Unavailable);
            }
        }
        drop(guard);
        result
    }

    /// Stream one selected regular remote file to a native-picker destination.
    pub async fn download_file_with_picker<F, Fut, P>(
        &self,
        session_id: &str,
        transport_id: &str,
        operation_id: &str,
        remote_path: Vec<u8>,
        choose_destination: F,
        progress: P,
    ) -> Result<SessionDownloadResult, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<PathBuf>, String>>,
        P: FnMut(SessionFileTransferProgress) + Send + 'static,
    {
        session_files::validate_path(&remote_path).map_err(|error| error.to_string())?;
        let (abort, cancellation) = AbortHandle::new_pair();
        let guard = self.reserve_file_operation(session_id, transport_id, operation_id, abort)?;
        let result = Abortable::new(
            async {
                let destination = match choose_destination().await {
                    Ok(Some(destination)) => destination,
                    Ok(None) => {
                        return SessionDownloadResult::new(SessionDownloadStatus::Cancelled, None);
                    }
                    Err(message) => {
                        return SessionDownloadResult::new(
                            SessionDownloadStatus::Failed,
                            Some(message),
                        );
                    }
                };
                let (reply, received) = oneshot::channel();
                if let Err(message) = self.queue_file_request(
                    &guard,
                    FileCommand::Download {
                        remote_path,
                        destination,
                        baseline: None,
                        session_id: session_id.to_owned(),
                        transport: guard.transport,
                        operation: guard.operation,
                        progress: Box::new(progress),
                        reply,
                    },
                ) {
                    return SessionDownloadResult::new(
                        SessionDownloadStatus::Failed,
                        Some(message),
                    );
                }
                match received.await {
                    Ok(result) => result,
                    Err(_) if guard.upload_state.effect_started.load(Ordering::SeqCst) => {
                        SessionDownloadResult::new(SessionDownloadStatus::Unknown, None)
                    }
                    Err(_) => SessionDownloadResult::new(
                        SessionDownloadStatus::Failed,
                        Some("the file operation ended with this connection".into()),
                    ),
                }
            },
            cancellation,
        )
        .await
        .unwrap_or_else(|_| SessionDownloadResult::new(SessionDownloadStatus::Cancelled, None));
        drop(guard);
        Ok(result)
    }

    /// Select one local file and upload it only after Rust-owned conflict review.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_file_with_picker<F, Fut, C, ConfirmFut, P>(
        &self,
        session_id: &str,
        transport_id: &str,
        operation_id: &str,
        directory: Vec<u8>,
        choose_source: F,
        confirm_replace: C,
        progress: P,
    ) -> Result<SessionUploadResult, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<PathBuf>, String>>,
        C: FnOnce(String) -> ConfirmFut,
        ConfirmFut: Future<Output = Result<bool, String>>,
        P: FnMut(SessionFileTransferProgress) + Send + 'static,
    {
        session_files::validate_path(&directory).map_err(|error| error.to_string())?;
        let (abort, cancellation) = AbortHandle::new_pair();
        let guard = self.reserve_file_operation(session_id, transport_id, operation_id, abort)?;
        let preparation = Abortable::new(
            async {
                let Some(path) = choose_source().await? else {
                    return Ok(PreparedUpload::Done(SessionUploadResult::new(
                        SessionUploadStatus::Cancelled,
                        None,
                        false,
                    )));
                };
                let source = session_files::open_upload_source(&path)
                    .await
                    .map_err(|error| error.to_string())?;
                let target = source.target(&directory).map_err(|error| error.to_string())?;
                let (reply, received) = oneshot::channel();
                self.queue_file_request(
                    &guard,
                    FileCommand::PreflightUpload { target: target.clone(), reply },
                )?;
                let preflight = tokio::time::timeout(FILE_LIST_TIMEOUT, received)
                    .await
                    .map_err(|_| "the remote upload target did not respond".to_owned())?
                    .map_err(|_| "the file operation ended with this connection".to_owned())??;
                if preflight.target_attributes.is_some() {
                    if !preflight.replacement_supported
                        || !preflight
                            .target_attributes
                            .as_ref()
                            .is_some_and(session_files::is_regular_upload_target)
                    {
                        return Ok(PreparedUpload::Done(SessionUploadResult::new(
                            SessionUploadStatus::Unsupported,
                            None,
                            false,
                        )));
                    }
                    if !confirm_replace(source.display_name()).await? {
                        return Ok(PreparedUpload::Done(SessionUploadResult::new(
                            SessionUploadStatus::Cancelled,
                            None,
                            false,
                        )));
                    }
                }
                Ok::<PreparedUpload, String>(PreparedUpload::Ready {
                    source: Box::new(source),
                    target,
                    preflight,
                })
            },
            cancellation,
        )
        .await;
        let prepared = match preparation {
            Ok(Ok(prepared)) => prepared,
            Ok(Err(error)) => {
                return Ok(SessionUploadResult::new(
                    SessionUploadStatus::Failed,
                    Some(error),
                    false,
                ));
            }
            Err(_) => {
                return Ok(SessionUploadResult::new(SessionUploadStatus::Cancelled, None, false));
            }
        };
        let (source, target, preflight) = match prepared {
            PreparedUpload::Ready { source, target, preflight } => (source, target, preflight),
            PreparedUpload::Done(result) => return Ok(result),
        };
        let (cancel_sender, cancel) = watch::channel(false);
        let (reply, received) = oneshot::channel();
        self.queue_effect_request(
            &guard,
            cancel_sender,
            FileCommand::Upload {
                source,
                directory,
                target,
                preflight,
                cancel,
                state: guard.upload_state.clone(),
                session_id: session_id.to_owned(),
                transport: guard.transport,
                operation: guard.operation,
                progress: Box::new(progress),
                reply,
            },
        )?;
        let result = match received.await {
            Ok(result) => result,
            Err(_) if guard.upload_state.effect_started.load(Ordering::SeqCst) => {
                SessionUploadResult::new(
                    SessionUploadStatus::Unknown,
                    None,
                    guard.upload_state.staging_may_remain.load(Ordering::SeqCst),
                )
            }
            Err(_) => SessionUploadResult::new(
                SessionUploadStatus::Failed,
                Some("the file operation ended with this connection".into()),
                guard.upload_state.staging_may_remain.load(Ordering::SeqCst),
            ),
        };
        drop(guard);
        Ok(result)
    }

    /// Create one directory in the current terminal-owned remote directory.
    pub async fn create_remote_directory(
        &self,
        session_id: &str,
        transport_id: &str,
        operation_id: &str,
        directory: Vec<u8>,
        name: &str,
    ) -> Result<SessionFileMutationResult, String> {
        let mutation =
            RemoteMutation::create_directory(directory, name).map_err(|error| error.to_string())?;
        self.mutate_remote_entry(session_id, transport_id, operation_id, mutation, |_, _| async {
            Ok(true)
        })
        .await
    }

    /// Rename one immediate ordinary child without replacing an existing destination.
    pub async fn rename_remote_entry(
        &self,
        session_id: &str,
        transport_id: &str,
        operation_id: &str,
        directory: Vec<u8>,
        entry: Vec<u8>,
        new_name: &str,
    ) -> Result<SessionFileMutationResult, String> {
        let mutation = RemoteMutation::rename_entry(directory, entry, new_name)
            .map_err(|error| error.to_string())?;
        self.mutate_remote_entry(session_id, transport_id, operation_id, mutation, |_, _| async {
            Ok(true)
        })
        .await
    }

    /// Delete one immediate ordinary child only after native confirmation.
    #[allow(clippy::too_many_arguments)]
    pub async fn delete_remote_entry_with_confirmation<C, Fut>(
        &self,
        session_id: &str,
        transport_id: &str,
        operation_id: &str,
        directory: Vec<u8>,
        entry: Vec<u8>,
        confirm: C,
    ) -> Result<SessionFileMutationResult, String>
    where
        C: FnOnce(session_files::RemoteFileKind, String) -> Fut,
        Fut: Future<Output = Result<bool, String>>,
    {
        let mutation =
            RemoteMutation::delete_entry(directory, entry).map_err(|error| error.to_string())?;
        self.mutate_remote_entry(session_id, transport_id, operation_id, mutation, confirm).await
    }

    async fn mutate_remote_entry<C, Fut>(
        &self,
        session_id: &str,
        transport_id: &str,
        operation_id: &str,
        mutation: RemoteMutation,
        confirm: C,
    ) -> Result<SessionFileMutationResult, String>
    where
        C: FnOnce(session_files::RemoteFileKind, String) -> Fut,
        Fut: Future<Output = Result<bool, String>>,
    {
        let (abort, cancellation) = AbortHandle::new_pair();
        let guard = self.reserve_file_operation(session_id, transport_id, operation_id, abort)?;
        let preparation = Abortable::new(
            async {
                let (reply, received) = oneshot::channel();
                self.queue_file_request(
                    &guard,
                    FileCommand::PreflightMutation { mutation: mutation.clone(), reply },
                )
                .map_err(|message| {
                    SessionFileMutationResult::new(SessionFileMutationStatus::Failed, Some(message))
                })?;
                let preflight = tokio::time::timeout(FILE_LIST_TIMEOUT, received)
                    .await
                    .map_err(|_| {
                        SessionFileMutationResult::new(
                            SessionFileMutationStatus::Failed,
                            Some("the remote file did not respond".into()),
                        )
                    })?
                    .map_err(|_| {
                        SessionFileMutationResult::new(
                            SessionFileMutationStatus::Failed,
                            Some("the file operation ended with this connection".into()),
                        )
                    })?
                    .map_err(SessionFileMutationResult::from_error)?;
                if matches!(mutation, RemoteMutation::DeleteEntry { .. }) {
                    let kind = preflight.source_kind.expect("delete preflight checked source kind");
                    let name = mutation.display_name().expect("delete mutation has a source");
                    let confirmed = confirm(kind, name).await.map_err(|message| {
                        SessionFileMutationResult::new(
                            SessionFileMutationStatus::Failed,
                            Some(message),
                        )
                    })?;
                    if !confirmed {
                        return Ok(None);
                    }
                }
                Ok::<Option<MutationPreflight>, SessionFileMutationResult>(Some(preflight))
            },
            cancellation,
        )
        .await;
        let preflight = match preparation {
            Ok(Ok(Some(preflight))) => preflight,
            Ok(Ok(None)) | Err(_) => {
                return Ok(SessionFileMutationResult::new(
                    SessionFileMutationStatus::Cancelled,
                    None,
                ));
            }
            Ok(Err(result)) => return Ok(result),
        };
        let (cancel_sender, cancel) = watch::channel(false);
        let (reply, received) = oneshot::channel();
        self.queue_effect_request(
            &guard,
            cancel_sender,
            FileCommand::Mutation {
                mutation,
                preflight,
                cancel,
                session_id: session_id.to_owned(),
                transport: guard.transport,
                operation: guard.operation,
                reply,
            },
        )?;
        let result = match received.await {
            Ok(result) => result,
            Err(_) if guard.upload_state.effect_started.load(Ordering::SeqCst) => {
                SessionFileMutationResult::new(SessionFileMutationStatus::Unknown, None)
            }
            Err(_) => SessionFileMutationResult::new(
                SessionFileMutationStatus::Failed,
                Some("the file operation ended with this connection".into()),
            ),
        };
        drop(guard);
        Ok(result)
    }

    /// Cancel only the matching in-flight SFTP operation.
    pub fn cancel_file_operation(
        &self,
        session_id: &str,
        transport_id: &str,
        operation_id: &str,
    ) -> Result<(), String> {
        let transport =
            Uuid::parse_str(transport_id).map_err(|_| "transport identifier is invalid")?;
        let operation =
            Uuid::parse_str(operation_id).map_err(|_| "file operation identifier is invalid")?;
        let mut sessions = self.sessions.lock().map_err(|_| "session manager is unavailable")?;
        let entry = sessions.get_mut(session_id).ok_or("session is not connected")?;
        let active = entry.active.as_mut().ok_or("session is not ready")?;
        if active.id != transport || *entry.intent.borrow() != Intent::None {
            return Err("this session transport is no longer ready".into());
        }
        let file = active.file.as_mut().ok_or("file operation has ended")?;
        if file.id != operation {
            return Err("file operation has ended".into());
        }
        if file.transfer.is_some() {
            return Err("cancel this file through its transfer-queue action".into());
        }
        if file.upload_state.effect_started.load(Ordering::SeqCst) {
            return Err("the final file save has started; its result must be checked".into());
        }
        file.abort.abort();
        if let Some(cancel) = &file.effect_cancel {
            cancel.send_replace(true);
        } else {
            active.file.take();
        }
        Ok(())
    }

    fn reserve_file_operation<'a>(
        &'a self,
        session_id: &'a str,
        transport_id: &str,
        operation_id: &str,
        abort: AbortHandle,
    ) -> Result<FileRequestGuard<'a>, String> {
        let transport =
            Uuid::parse_str(transport_id).map_err(|_| "transport identifier is invalid")?;
        let operation =
            Uuid::parse_str(operation_id).map_err(|_| "file operation identifier is invalid")?;
        let mut sessions = self.sessions.lock().map_err(|_| "session manager is unavailable")?;
        let entry = sessions.get_mut(session_id).ok_or("session is not connected")?;
        if entry.transfers.blocks_file_operations() {
            return Err("wait for the file-transfer queue to settle".into());
        }
        let active = entry.active.as_mut().ok_or("session is not ready")?;
        if !active.ready || active.id != transport || *entry.intent.borrow() != Intent::None {
            return Err("this session transport is no longer ready".into());
        }
        if active.file.is_some() {
            return Err("another file operation is already running".into());
        }
        let upload_state = Arc::new(UploadState::default());
        active.file = Some(ActiveFile {
            id: operation,
            abort: abort.clone(),
            upload_state: upload_state.clone(),
            effect_cancel: None,
            transfer: None,
            transfer_control: None,
        });
        Ok(FileRequestGuard {
            manager: self,
            session_id,
            transport,
            operation,
            abort,
            upload_state,
        })
    }

    fn queue_file_request(
        &self,
        guard: &FileRequestGuard<'_>,
        request: FileCommand,
    ) -> Result<(), String> {
        let sessions = self.sessions.lock().map_err(|_| "session manager is unavailable")?;
        let entry = sessions.get(guard.session_id).ok_or("session is not connected")?;
        let active = entry.active.as_ref().ok_or("session is not ready")?;
        if active.id != guard.transport
            || *entry.intent.borrow() != Intent::None
            || guard.abort.is_aborted()
            || active.file.as_ref().is_none_or(|file| file.id != guard.operation)
        {
            return Err("this file operation is no longer current".into());
        }
        active.files.try_send(request).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => "file operation queue is full".to_owned(),
            mpsc::error::TrySendError::Closed(_) => "session is no longer connected".to_owned(),
        })
    }

    fn queue_effect_request(
        &self,
        guard: &FileRequestGuard<'_>,
        cancel: watch::Sender<bool>,
        request: FileCommand,
    ) -> Result<(), String> {
        let mut sessions = self.sessions.lock().map_err(|_| "session manager is unavailable")?;
        let entry = sessions.get_mut(guard.session_id).ok_or("session is not connected")?;
        let active = entry.active.as_mut().ok_or("session is not ready")?;
        if active.id != guard.transport
            || *entry.intent.borrow() != Intent::None
            || guard.abort.is_aborted()
            || active.file.as_ref().is_none_or(|file| file.id != guard.operation)
        {
            return Err("this file operation is no longer current".into());
        }
        active.file.as_mut().expect("matching file operation exists").effect_cancel = Some(cancel);
        match active.files.try_send(request) {
            Ok(()) => Ok(()),
            Err(error) => {
                active.file.as_mut().expect("matching file operation exists").effect_cancel = None;
                Err(match error {
                    mpsc::error::TrySendError::Full(_) => "file operation queue is full".to_owned(),
                    mpsc::error::TrySendError::Closed(_) => {
                        "session is no longer connected".to_owned()
                    }
                })
            }
        }
    }

    fn authorize_remote_effect(
        sessions: &Mutex<HashMap<String, SessionEntry>>,
        session_id: &str,
        transport: Uuid,
        operation: Uuid,
    ) -> Result<(), session_files::FileAccessError> {
        let mut sessions =
            sessions.lock().map_err(|_| session_files::FileAccessError::ConnectionEnded)?;
        let entry =
            sessions.get_mut(session_id).ok_or(session_files::FileAccessError::ConnectionEnded)?;
        let active =
            entry.active.as_ref().ok_or(session_files::FileAccessError::ConnectionEnded)?;
        let file = active.file.as_ref().ok_or(session_files::FileAccessError::ConnectionEnded)?;
        if file.abort.is_aborted() {
            return Err(session_files::FileAccessError::Cancelled);
        }
        if !active.ready
            || active.id != transport
            || *entry.intent.borrow() != Intent::None
            || file.id != operation
        {
            return Err(session_files::FileAccessError::ConnectionEnded);
        }
        let transfer = file.transfer;
        let state = file.upload_state.clone();
        if let Some(identity) = transfer {
            entry
                .transfers
                .begin_publication(identity)
                .map_err(|_| session_files::FileAccessError::Cancelled)?;
        }
        state.effect_started.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn finish_remote_effect(&self, session_id: &str, transport: Uuid, operation: Uuid) {
        Self::finish_file_effect(&self.sessions, session_id, transport, operation);
    }

    fn finish_file_effect(
        sessions: &Mutex<HashMap<String, SessionEntry>>,
        session_id: &str,
        transport: Uuid,
        operation: Uuid,
    ) {
        if let Ok(mut sessions) = sessions.lock()
            && let Some(entry) = sessions.get_mut(session_id)
            && let Some(active) = entry.active.as_mut()
            && active.id == transport
            && active.file.as_ref().is_some_and(|file| file.id == operation)
        {
            active.file.take();
            entry.transfer_notify.notify_one();
        }
    }

    fn report_upload_pause(
        sessions: &Mutex<HashMap<String, SessionEntry>>,
        session_id: &str,
        transport: Uuid,
        operation: Uuid,
    ) {
        if let Ok(mut sessions) = sessions.lock()
            && let Some(entry) = sessions.get_mut(session_id)
            && let Some(active) = &entry.active
            && active.ready
            && active.id == transport
            && *entry.intent.borrow() == Intent::None
            && let Some(file) = &active.file
            && file.id == operation
            && !file.abort.is_aborted()
            && let Some(identity) = file.transfer
        {
            entry.transfers.admit_upload_pause(identity);
        }
    }

    fn report_file_progress(
        sessions: &Mutex<HashMap<String, SessionEntry>>,
        session_id: &str,
        transport: Uuid,
        operation: Uuid,
        progress: &mut dyn FnMut(SessionFileTransferProgress),
        update: FileTransferProgress,
    ) {
        let current = sessions.lock().is_ok_and(|mut sessions| {
            let Some(entry) = sessions.get_mut(session_id) else { return false };
            let Some(active) = &entry.active else { return false };
            let Some(file) = &active.file else { return false };
            if !active.ready
                || active.id != transport
                || *entry.intent.borrow() != Intent::None
                || file.id != operation
                || file.abort.is_aborted()
            {
                return false;
            }
            if let Some(identity) = file.transfer {
                entry.transfers.progress(identity, update);
            }
            true
        });
        if current {
            progress(SessionFileTransferProgress {
                session_id: session_id.to_owned(),
                transport_id: transport.to_string(),
                operation_id: operation.to_string(),
                transferred_bytes: update.transferred.to_string(),
                total_bytes: update.total.map(|total| total.to_string()),
                phase: update.phase,
            });
        }
    }

    fn commit_download<F>(
        sessions: &Mutex<HashMap<String, SessionEntry>>,
        session_id: &str,
        transport: Uuid,
        operation: Uuid,
        baseline: Option<&DownloadDestination>,
        commit: F,
    ) -> SessionDownloadResult
    where
        F: FnOnce() -> Result<(), session_files::FileAccessError>,
    {
        if let Some(baseline) = baseline
            && let Err(issue) = baseline.check_before_publication()
        {
            return SessionDownloadResult::new(
                if issue == crate::session_transfers::SessionTransferIssue::TargetChanged {
                    SessionDownloadStatus::Conflict
                } else {
                    SessionDownloadStatus::Failed
                },
                None,
            );
        }
        let authorized = Self::authorize_remote_effect(sessions, session_id, transport, operation);
        match authorized.and_then(|()| commit()) {
            Ok(()) => SessionDownloadResult::new(SessionDownloadStatus::Saved, None),
            Err(session_files::FileAccessError::Cancelled) => {
                SessionDownloadResult::new(SessionDownloadStatus::Cancelled, None)
            }
            Err(error) => {
                SessionDownloadResult::new(SessionDownloadStatus::Failed, Some(error.to_string()))
            }
        }
    }

    fn send(
        &self,
        session_id: &str,
        transport_id: &str,
        command: TransportCommand,
    ) -> Result<(), String> {
        let id = Uuid::parse_str(transport_id).map_err(|_| "transport identifier is invalid")?;
        let sessions = self.sessions.lock().map_err(|_| "session manager is unavailable")?;
        let entry = sessions.get(session_id).ok_or("session is not connected")?;
        if matches!(command, TransportCommand::Resize { .. }) && !entry.pty {
            return Err("session has no PTY to resize".into());
        }
        let active = entry.active.as_ref().ok_or("session is not ready")?;
        if !active.ready || active.id != id || *entry.intent.borrow() != Intent::None {
            return Err("this session transport is no longer ready".into());
        }
        active.sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => "session command queue is full".into(),
            mpsc::error::TrySendError::Closed(_) => "session is no longer connected".into(),
        })
    }

    fn phase(&self, session_id: &str, phase: Phase) -> Result<(), String> {
        let mut sessions = self.sessions.lock().map_err(|_| "session manager is unavailable")?;
        let entry = sessions.get_mut(session_id).ok_or("session is closed")?;
        entry.phase = phase;
        if let Some(transport) = entry.active.as_ref().map(|active| active.id) {
            interrupt_transfers(entry, transport);
        }
        if let Some(active) = entry.active.take()
            && let Some(file) = active.file
            && !file.upload_state.effect_started.load(Ordering::SeqCst)
        {
            file.abort.abort();
        }
        Ok(())
    }

    fn expire_ready_transport(&self, session_id: &str, transport: Uuid) -> Result<(), String> {
        let mut sessions = self.sessions.lock().map_err(|_| "session manager is unavailable")?;
        if let Some(entry) = sessions.get_mut(session_id)
            && entry.active.as_ref().is_some_and(|active| active.id == transport)
        {
            interrupt_transfers(entry, transport);
            let active = entry.active.as_mut().expect("matching transport exists");
            active.ready = false;
            if let Some(file) = active.file.take()
                && !file.upload_state.effect_started.load(Ordering::SeqCst)
            {
                file.abort.abort();
            }
        }
        drop(sessions);
        self.start_transfer_worker(session_id);
        Ok(())
    }

    async fn stream_with_file_expiry(
        &self,
        session_id: &str,
        transport: Uuid,
        stream: impl Future<Output = Result<(), AttemptError>>,
    ) -> Result<(), AttemptError> {
        let result = stream.await;
        self.expire_ready_transport(session_id, transport).map_err(AttemptError::Local)?;
        result
    }

    fn register_attempt(
        &self,
        session_id: &str,
        transport: Uuid,
        control: &PreparationControl,
        sender: mpsc::Sender<TransportCommand>,
        files: mpsc::Sender<FileCommand>,
        intents: &mut watch::Receiver<Intent>,
    ) -> Result<Intent, String> {
        let mut sessions = self.sessions.lock().map_err(|_| "session manager is unavailable")?;
        let entry = sessions.get_mut(session_id).ok_or("session is closed")?;
        let requested = *entry.intent.borrow();
        if matches!(requested, Intent::None | Intent::Retry) {
            if let Some(old) = entry.active.as_ref().map(|active| active.id) {
                interrupt_transfers(entry, old);
            }
            entry.intent.send_replace(Intent::None);
            entry.phase = Phase::Running;
            entry.checkpoint = None;
            entry.active = Some(ActiveAttempt {
                id: transport,
                control: control.clone(),
                sender,
                files,
                file: None,
                ready: false,
                context: None,
            });
        }
        intents.borrow_and_update();
        Ok(requested)
    }

    /// Run one logical terminal until tab closure. Closed and failed terminals
    /// remain owned here so manual reconnect does not replace the terminal.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        &self,
        session_id: &str,
        profile_id: &str,
        command: Option<&str>,
        pty: bool,
        store: Arc<Store>,
        emit: impl Fn(SessionEvent) -> Result<(), String> + Sync,
        output: impl Fn(Uuid, Vec<u8>) -> Result<(), String>,
        history_changed: impl Fn(&str, HistoryChange) + Clone + Send + Sync + 'static,
    ) -> Result<(), String> {
        let mut intents = {
            let mut sessions =
                self.sessions.lock().map_err(|_| "session manager is unavailable")?;
            let entry = sessions.get_mut(session_id).ok_or("session reservation is closed")?;
            if entry.pty != pty {
                return Err("session reservation has different PTY settings".into());
            }
            entry.receiver.take().ok_or("session is already connected")?
        };
        let _registration = Registration { manager: self, id: session_id };
        let mut budget = RetryBudget::default();
        let mut automatic = false;
        loop {
            let transport = Uuid::now_v7();
            let control = PreparationControl::default();
            let (sender, mut commands) = mpsc::channel(COMMAND_QUEUE);
            let (file_sender, mut files) = mpsc::channel(FILE_QUEUE);
            let requested = self.register_attempt(
                session_id,
                transport,
                &control,
                sender,
                file_sender,
                &mut intents,
            )?;
            match requested {
                Intent::Close => return Ok(()),
                Intent::Stop | Intent::Fail => {
                    match self.wait_after_stop(session_id, requested, &mut intents, &emit).await? {
                        Intent::Close => return Ok(()),
                        Intent::Retry => {
                            budget = RetryBudget::default();
                            automatic = false;
                            continue;
                        }
                        _ => return Err("unexpected session intent".into()),
                    }
                }
                Intent::Retry => {
                    budget = RetryBudget::default();
                    automatic = false;
                }
                Intent::None => {}
            }
            emit(SessionEvent::Starting { transport_id: transport.to_string(), automatic })?;
            let mut ready_for = None;
            let result = self
                .attempt(
                    session_id,
                    profile_id,
                    command,
                    pty,
                    &store,
                    transport,
                    &control,
                    &mut commands,
                    &mut files,
                    &mut ready_for,
                    &emit,
                    &output,
                    history_changed.clone(),
                )
                .await;
            let requested = *intents.borrow_and_update();
            let completed = if requested == Intent::None { Some(result) } else { None };
            control.cancel();
            self.phase(session_id, Phase::Ended)?;
            budget.ended(ready_for);
            let next = match completed {
                None => requested,
                Some(Ok(())) => {
                    emit(SessionEvent::Closed)?;
                    if command.is_some() {
                        return Ok(());
                    }
                    self.wait_manual(&mut intents).await
                }
                Some(Err(error)) => {
                    if command.is_some() {
                        emit(SessionEvent::Failed { error: error.to_string(), exhausted: false })?;
                        return Err(error.to_string());
                    }
                    let delay =
                        if command.is_none() && error.retryable() { budget.next() } else { None };
                    if let Some(delay) = delay {
                        self.phase(session_id, Phase::Retrying)?;
                        emit(SessionEvent::Retrying {
                            attempt: budget.attempts as u8,
                            delay_seconds: delay,
                            error: error.to_string(),
                        })?;
                        tokio::select! { biased;
                            _ = intents.changed() => *intents.borrow_and_update(),
                            _ = tokio::time::sleep(Duration::from_secs(u64::from(delay))) => Intent::None,
                        }
                    } else {
                        emit(SessionEvent::Failed {
                            error: error.to_string(),
                            exhausted: error.retryable()
                                && budget.ever_ready
                                && budget.attempts == RETRY_DELAYS.len(),
                        })?;
                        self.wait_manual(&mut intents).await
                    }
                }
            };
            let next = self.wait_after_stop(session_id, next, &mut intents, &emit).await?;
            match next {
                Intent::Close => return Ok(()),
                Intent::Retry => {
                    budget = RetryBudget::default();
                    automatic = false;
                }
                Intent::None => automatic = true,
                Intent::Stop | Intent::Fail => return Err("unexpected session intent".into()),
            }
        }
    }

    async fn wait_after_stop(
        &self,
        session_id: &str,
        mut next: Intent,
        intents: &mut watch::Receiver<Intent>,
        emit: &(impl Fn(SessionEvent) -> Result<(), String> + Sync),
    ) -> Result<Intent, String> {
        while matches!(next, Intent::Stop | Intent::Fail) {
            self.phase(session_id, Phase::Ended)?;
            if next == Intent::Fail {
                emit(SessionEvent::Failed {
                    error: "The terminal could not continue. Reconnect to start a new shell."
                        .into(),
                    exhausted: false,
                })?;
            } else {
                emit(SessionEvent::Closed)?;
            }
            next = self.wait_manual(intents).await;
        }
        Ok(next)
    }

    async fn wait_manual(&self, intents: &mut watch::Receiver<Intent>) -> Intent {
        loop {
            if intents.changed().await.is_err() {
                return Intent::Close;
            }
            let intent = *intents.borrow_and_update();
            if intent != Intent::None {
                return intent;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn attempt(
        &self,
        session_id: &str,
        profile_id: &str,
        command: Option<&str>,
        pty: bool,
        store: &Arc<Store>,
        transport: Uuid,
        control: &PreparationControl,
        commands: &mut mpsc::Receiver<TransportCommand>,
        files: &mut mpsc::Receiver<FileCommand>,
        ready_for: &mut Option<Duration>,
        emit: &(impl Fn(SessionEvent) -> Result<(), String> + Sync),
        output: &impl Fn(Uuid, Vec<u8>) -> Result<(), String>,
        history_changed: impl Fn(&str, HistoryChange) + Clone + Send + Sync + 'static,
    ) -> Result<(), AttemptError> {
        let id = Uuid::parse_str(profile_id)
            .map_err(|_| AttemptError::Local("the Login identifier is invalid".into()))?;
        let closed = history_changed.clone();
        let history = SessionHistoryLease::start(
            Inventory::with_deletions(store.clone(), DeletionStore::default()),
            profile_id.to_owned(),
            RecentSessionKind::Terminal,
            move |id| closed(id, HistoryChange::Closed),
        )
        .map_err(|error| AttemptError::Local(error.to_string()))?;
        {
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| AttemptError::Local("session manager is unavailable".into()))?;
            let entry = sessions
                .get_mut(session_id)
                .ok_or_else(|| AttemptError::Local("session is closed".into()))?;
            if entry.active.as_ref().is_some_and(|active| active.id == transport) {
                entry.checkpoint = Some(CheckpointOwner {
                    store: store.clone(),
                    history: Uuid::parse_str(history.id()).expect("store UUID"),
                    transport,
                    sequence: 0,
                });
            }
        }
        history_changed(history.id(), HistoryChange::Opened);
        let connection = prepare_connection(store, id, control, |event| {
            if let PreparationEvent::Verified { context, .. } = &event
                && context.target
                && let Ok(mut sessions) = self.sessions.lock()
                && let Some(active) =
                    sessions.get_mut(session_id).and_then(|entry| entry.active.as_mut())
                && active.id == transport
            {
                active.context = Some(context.clone());
            }
            emit(SessionEvent::Preparation {
                transport_id: transport.to_string(),
                event: Box::new(event),
            })
        })
        .await;
        let connection = match connection {
            Ok(connection) => connection,
            Err(_) if control.is_cancelled() => {
                return history
                    .finish(RecentSessionOutcome::Closed)
                    .map_err(|error| AttemptError::Local(error.to_string()));
            }
            Err(error) => return Err(error.into()),
        };
        let mut ready_at = None;
        let operation = async {
            let mut session = connection.open_session().await?;
            let pty_request = pty.then(default_pty);
            if let Some(command) = command {
                let result = session.exec(command.as_bytes(), pty_request.as_ref()).await?;
                for bytes in [result.stdout, result.stderr] {
                    if !bytes.is_empty() {
                        output(transport, bytes).map_err(AttemptError::Local)?;
                    }
                }
            } else {
                if let Some(request) = pty_request.as_ref() {
                    session.request_pty(request).await?;
                }
                session.request_shell().await?;
                {
                    let mut sessions = self.sessions.lock().map_err(|_| {
                        AttemptError::Local("session manager is unavailable".into())
                    })?;
                    let entry = sessions
                        .get_mut(session_id)
                        .ok_or_else(|| AttemptError::Local("session is closed".into()))?;
                    if *entry.intent.borrow() != Intent::None {
                        return Ok(());
                    }
                    let active = entry
                        .active
                        .as_mut()
                        .ok_or_else(|| AttemptError::Local("session is closed".into()))?;
                    active.ready = true;
                }
                ready_at = Some(Instant::now());
                emit(SessionEvent::Ready { transport_id: transport.to_string() })
                    .map_err(AttemptError::Local)?;
                tokio::select! { biased;
                    result = self.stream_with_file_expiry(
                        session_id,
                        transport,
                        stream_channel(&mut session, transport, commands, output),
                    ) => result?,
                    _ = serve_files(self, &connection, files) => {
                        return Err(AttemptError::Local("the file request channel closed unexpectedly".into()));
                    }
                }
            }
            Ok::<(), AttemptError>(())
        };
        let result = tokio::select! { biased;
            _ = control.cancelled() => Ok(()),
            result = operation => result,
        };
        self.expire_ready_transport(session_id, transport).map_err(AttemptError::Local)?;
        *ready_for = ready_at.map(|started| started.elapsed());
        let _ = connection.close().await;
        result?;
        history
            .finish(RecentSessionOutcome::Closed)
            .map_err(|error| AttemptError::Local(error.to_string()))
    }
}

async fn complete_owned_download(
    sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
    session_id: String,
    transport: Uuid,
    operation: Uuid,
    reply: oneshot::Sender<Result<DownloadExecution, session_files::FileAccessError>>,
    download: impl Future<Output = DownloadExecution>,
) {
    match download.await {
        DownloadExecution::Ready { prepared, destination } => {
            drop(tokio::task::spawn_blocking(move || {
                let mut prepared = prepared;
                let result = SessionManager::commit_download(
                    &sessions,
                    &session_id,
                    transport,
                    operation,
                    Some(&destination),
                    || prepared.commit_retained(),
                );
                let clean = result.status == SessionDownloadStatus::Saved || prepared.discard();
                SessionManager::finish_file_effect(&sessions, &session_id, transport, operation);
                let _ = reply
                    .send(Ok(DownloadExecution::Published { result, staging_may_remain: !clean }));
            }));
        }
        result => {
            let _ = reply.send(Ok(result));
        }
    }
}

async fn serve_files(
    manager: &SessionManager,
    connection: &crate::connection::SshConnection,
    files: &mut mpsc::Receiver<FileCommand>,
) {
    while let Some(request) = files.recv().await {
        match request {
            FileCommand::TransferUpload {
                input,
                control,
                state,
                session_id,
                transport,
                operation,
                reply,
            } => {
                let sessions = manager.sessions.clone();
                let progress_sessions = sessions.clone();
                let capability_sessions = sessions.clone();
                let progress_session = session_id.clone();
                let capability_session = session_id.clone();
                let authorized_session = session_id.clone();
                let result = session_files::transfer_upload(
                    connection,
                    input,
                    control,
                    state,
                    move |update| {
                        SessionManager::report_file_progress(
                            &progress_sessions,
                            &progress_session,
                            transport,
                            operation,
                            &mut |_| {},
                            update,
                        );
                    },
                    move || {
                        SessionManager::report_upload_pause(
                            &capability_sessions,
                            &capability_session,
                            transport,
                            operation,
                        );
                    },
                    move || {
                        SessionManager::authorize_remote_effect(
                            &sessions,
                            &authorized_session,
                            transport,
                            operation,
                        )
                    },
                )
                .await;
                manager.finish_remote_effect(&session_id, transport, operation);
                if let Err(UploadExecution::Paused(checkpoint)) = reply.send(result) {
                    let _ = checkpoint.discard().await;
                }
            }
            FileCommand::TransferDownload {
                input,
                control,
                session_id,
                transport,
                operation,
                reply,
            } => {
                let sessions = manager.sessions.clone();
                let progress_sessions = sessions.clone();
                let progress_session = session_id.clone();
                let prepared = match session_files::prepare_download(connection, input).await {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        let _ = reply.send(Err(error));
                        continue;
                    }
                };
                drop(tokio::spawn(complete_owned_download(
                    sessions,
                    session_id,
                    transport,
                    operation,
                    reply,
                    session_files::continue_download(prepared, control, move |update| {
                        SessionManager::report_file_progress(
                            &progress_sessions,
                            &progress_session,
                            transport,
                            operation,
                            &mut |_| {},
                            update,
                        );
                    }),
                )));
            }
            FileCommand::List { path, mut reply } => {
                tokio::select! { biased;
                    _ = reply.closed() => {},
                    result = session_files::list_directory(connection, path) => {
                        let _ = reply.send(result.map_err(|error| error.to_string()));
                    }
                }
            }
            FileCommand::Preview { path, mut reply } => {
                tokio::select! { biased;
                    _ = reply.closed() => {},
                    result = session_files::preview_file(connection, path) => {
                        let _ = reply.send(result.map_err(RemoteTextPreviewIssue::from));
                    }
                }
            }
            FileCommand::Download {
                remote_path,
                destination,
                baseline,
                session_id,
                transport,
                operation,
                mut progress,
                mut reply,
            } => {
                let sessions = manager.sessions.clone();
                let progress_sessions = sessions.clone();
                let progress_session = session_id.clone();
                let result = tokio::select! { biased;
                    _ = reply.closed() => None,
                    result = session_files::download_file(connection, remote_path, &destination, move |update| {
                        SessionManager::report_file_progress(
                            &progress_sessions,
                            &progress_session,
                            transport,
                            operation,
                            progress.as_mut(),
                            update,
                        );
                    }) => Some(result),
                };
                match result {
                    Some(Ok(prepared)) => {
                        // The worker owns both the synchronized file and reply past transport expiry.
                        drop(tokio::task::spawn_blocking(move || {
                            let result = SessionManager::commit_download(
                                &sessions,
                                &session_id,
                                transport,
                                operation,
                                baseline.as_ref(),
                                || prepared.commit(),
                            );
                            SessionManager::finish_file_effect(
                                &sessions,
                                &session_id,
                                transport,
                                operation,
                            );
                            let _ = reply.send(result);
                        }));
                    }
                    Some(Err(error)) => {
                        let _ = reply.send(SessionDownloadResult::new(
                            SessionDownloadStatus::Failed,
                            Some(error.to_string()),
                        ));
                    }
                    None => {}
                }
            }
            FileCommand::PreflightUpload { target, mut reply } => {
                tokio::select! { biased;
                    _ = reply.closed() => {},
                    result = session_files::preflight_upload(connection, &target) => {
                        let _ = reply.send(result.map_err(|error| error.to_string()));
                    }
                }
            }
            FileCommand::Upload {
                source,
                directory,
                target,
                preflight,
                cancel,
                state,
                session_id,
                transport,
                operation,
                mut progress,
                reply,
            } => {
                let sessions = manager.sessions.clone();
                let progress_sessions = sessions.clone();
                let authorized_session = session_id.clone();
                let progress_session = session_id.clone();
                let result = session_files::upload_file(
                    connection,
                    *source,
                    directory,
                    target,
                    preflight,
                    cancel,
                    state,
                    move |update| {
                        SessionManager::report_file_progress(
                            &progress_sessions,
                            &progress_session,
                            transport,
                            operation,
                            progress.as_mut(),
                            update,
                        );
                    },
                    move || {
                        SessionManager::authorize_remote_effect(
                            &sessions,
                            &authorized_session,
                            transport,
                            operation,
                        )
                    },
                )
                .await;
                manager.finish_remote_effect(&session_id, transport, operation);
                let _ = reply.send(result);
            }
            FileCommand::PreflightMutation { mutation, mut reply } => {
                tokio::select! { biased;
                    _ = reply.closed() => {},
                    result = session_files::preflight_mutation(connection, &mutation) => {
                        let _ = reply.send(result);
                    }
                }
            }
            FileCommand::Mutation {
                mutation,
                preflight,
                cancel,
                session_id,
                transport,
                operation,
                reply,
            } => {
                let sessions = manager.sessions.clone();
                let authorized_session = session_id.clone();
                let result = session_files::mutate_entry(
                    connection,
                    mutation,
                    preflight,
                    cancel,
                    move || {
                        SessionManager::authorize_remote_effect(
                            &sessions,
                            &authorized_session,
                            transport,
                            operation,
                        )
                    },
                )
                .await;
                manager.finish_remote_effect(&session_id, transport, operation);
                let _ = reply.send(result);
            }
        }
    }
}

fn default_pty() -> scoplen_ssh::PtyRequest {
    scoplen_ssh::PtyRequest {
        term: b"xterm-256color".to_vec(),
        columns: 80,
        rows: 24,
        pixel_width: 0,
        pixel_height: 0,
        modes: vec![0],
    }
}

async fn stream_channel(
    session: &mut SshSession,
    transport: Uuid,
    commands: &mut mpsc::Receiver<TransportCommand>,
    output: &impl Fn(Uuid, Vec<u8>) -> Result<(), String>,
) -> Result<(), AttemptError> {
    let mut terminal = false;
    loop {
        tokio::select! { biased;
            command = commands.recv() => match command {
                Some(TransportCommand::Input(data)) => {
                    if let Err(error) = session.send_data(&data).await {
                        return confirm_send_failure(session, transport, error, terminal, output).await;
                    }
                },
                Some(TransportCommand::Resize { columns, rows }) => {
                    if let Err(error) = session.resize(columns, rows).await {
                        return confirm_send_failure(session, transport, error, terminal, output).await;
                    }
                },
                None => return Ok(()),
            },
            event = session.next_event() => match event? {
                Some(ChannelEvent::Data(data) | ChannelEvent::ExtendedData { data, .. }) => output(transport, data).map_err(AttemptError::Local)?,
                Some(ChannelEvent::Close) | None => return Ok(()),
                Some(ChannelEvent::ExitStatus(_) | ChannelEvent::ExitSignal { .. } | ChannelEvent::OpenFailure { .. }) => terminal = true,
                Some(_) => {},
            },
        }
    }
}

async fn confirm_send_failure(
    session: &mut SshSession,
    transport: Uuid,
    original: SshConnectionError,
    mut terminal: bool,
    output: &impl Fn(Uuid, Vec<u8>) -> Result<(), String>,
) -> Result<(), AttemptError> {
    if !matches!(
        original,
        SshConnectionError::Engine(ClientError::Channel | ClientError::ConnectionClosed)
    ) {
        return Err(original.into());
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let event = tokio::time::timeout_at(deadline, session.next_event())
            .await
            .unwrap_or(Err(SshConnectionError::Engine(ClientError::Channel)));
        match send_failure_event(event, &mut terminal) {
            SendFailureEvent::Output(data) => {
                output(transport, data).map_err(AttemptError::Local)?;
            }
            SendFailureEvent::Complete => return Ok(()),
            SendFailureEvent::Continue => {}
            SendFailureEvent::NetworkLost => {
                return Err(SshConnectionError::Engine(ClientError::NetworkLost).into());
            }
            SendFailureEvent::Original => return Err(original.into()),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum SendFailureEvent {
    Output(Vec<u8>),
    Continue,
    Complete,
    NetworkLost,
    Original,
}

fn send_failure_event(
    event: Result<Option<ChannelEvent>, SshConnectionError>,
    terminal: &mut bool,
) -> SendFailureEvent {
    match event {
        Ok(Some(ChannelEvent::Data(data) | ChannelEvent::ExtendedData { data, .. })) => {
            SendFailureEvent::Output(data)
        }
        Ok(Some(ChannelEvent::Close)) => SendFailureEvent::Complete,
        Ok(Some(
            ChannelEvent::ExitStatus(_)
            | ChannelEvent::ExitSignal { .. }
            | ChannelEvent::OpenFailure { .. },
        )) => {
            *terminal = true;
            SendFailureEvent::Continue
        }
        Ok(Some(_)) => SendFailureEvent::Continue,
        Err(SshConnectionError::Engine(ClientError::NetworkLost)) if !*terminal => {
            SendFailureEvent::NetworkLost
        }
        _ if *terminal => SendFailureEvent::Complete,
        _ => SendFailureEvent::Original,
    }
}

#[cfg(test)]
mod tests;
