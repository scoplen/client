// SPDX-License-Identifier: Apache-2.0

//! The smallest live SSH IPC path: resolve one local profile, connect through
//! the shared engine, and stream channel bytes as binary Tauri frames.

use crate::events::{SessionChangeKind, SessionChanged};
use crate::frames::{FrameSender, RawFrame};
use crate::local_data::LocalDataState;
use scoplen_client_core::connection::{
    HostKeyPresentation, HostKeyStatus, HostKeyTrust, MAX_PRIVATE_KEY_PASSPHRASE, SshConnection,
    SshConnectionError, SshExecOutput, SshSession, StoredHostKeyVerifier, evaluate_host_key,
    private_key_passphrase_required, probe_host_key, terminal_size,
};
use scoplen_client_core::inventory::{
    DeletionStore, Inventory, RecentSessionKind, RecentSessionOutcome,
};
use scoplen_client_core::repository::{
    Edit, Provenance, Repository, TrustRecord, TrustRecordChange,
};
use scoplen_client_core::session_lifecycle::SessionHistoryLease;
use scoplen_crypto::SecretVec;
use scoplen_ssh::ChannelEvent;
use serde::Serialize;
use specta::Type;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::ipc::Channel;
use tauri_specta::Event as _;
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    watch,
};

const SESSION_COMMAND_QUEUE: usize = 64;

/// A command sent from the frontend to one live SSH session.
#[derive(Debug, Eq, PartialEq)]
enum SessionCommand {
    Input(Vec<u8>),
    Resize { columns: u32, rows: u32 },
}

struct SessionEntry {
    sender: Sender<SessionCommand>,
    close: watch::Sender<bool>,
    pty: bool,
}

struct SessionRegistration<'a> {
    registry: &'a SessionRegistry,
    session_id: String,
}

impl Drop for SessionRegistration<'_> {
    fn drop(&mut self) {
        self.registry.remove(&self.session_id);
    }
}

/// Routes frontend session commands to their owning SSH connection task.
///
/// The registry is process-local and holds no credentials or channel bytes after
/// a session has ended. Each session has a bounded command queue so an
/// untrusted renderer cannot grow memory without limit.
#[derive(Default)]
pub struct SessionRegistry {
    sessions: Mutex<HashMap<String, SessionEntry>>,
}

impl SessionRegistry {
    fn register(
        &self,
        session_id: &str,
        pty: bool,
    ) -> Result<(SessionRegistration<'_>, Receiver<SessionCommand>, watch::Receiver<bool>), String>
    {
        if session_id.trim().is_empty() {
            return Err("session id must not be empty".to_owned());
        }
        let (sender, receiver) = mpsc::channel(SESSION_COMMAND_QUEUE);
        let (close_sender, close_receiver) = watch::channel(false);
        let mut sessions =
            self.sessions.lock().map_err(|_| "session registry is unavailable".to_owned())?;
        if sessions.contains_key(session_id) {
            return Err("session is already connected".to_owned());
        }
        sessions.insert(session_id.to_owned(), SessionEntry { sender, close: close_sender, pty });
        Ok((
            SessionRegistration { registry: self, session_id: session_id.to_owned() },
            receiver,
            close_receiver,
        ))
    }

    fn remove(&self, session_id: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(session_id);
        }
    }

    fn send(&self, session_id: &str, command: SessionCommand) -> Result<(), String> {
        let sessions =
            self.sessions.lock().map_err(|_| "session registry is unavailable".to_owned())?;
        let entry =
            sessions.get(session_id).ok_or_else(|| "session is not connected".to_owned())?;
        if matches!(command, SessionCommand::Resize { .. }) && !entry.pty {
            return Err("session has no PTY to resize".to_owned());
        }
        let sender = entry.sender.clone();
        drop(sessions);
        sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => "session command queue is full".to_owned(),
            mpsc::error::TrySendError::Closed(_) => "session is no longer connected".to_owned(),
        })
    }

    fn close(&self, session_id: &str) -> Result<(), String> {
        let sessions =
            self.sessions.lock().map_err(|_| "session registry is unavailable".to_owned())?;
        let entry =
            sessions.get(session_id).ok_or_else(|| "session is not connected".to_owned())?;
        entry.close.send_replace(true);
        Ok(())
    }
}

/// The result of comparing the probed key with this Host's active trust records.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum HostKeyTrustStatus {
    /// The key already matches an active host-specific trust record.
    Trusted,
    /// No active host-specific key exists yet.
    New,
    /// An active host-specific key exists, but it does not match.
    Changed,
}

/// A validated host key suitable for a confirmation dialog.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyDetails {
    /// The SSH algorithm identifier.
    pub algorithm: String,
    /// The complete OpenSSH public-key text.
    pub key: String,
    /// The OpenSSH SHA-256 fingerprint.
    pub fingerprint: String,
    /// How the key relates to the local Host trust records.
    pub status: HostKeyTrustStatus,
    /// Whether the selected saved OpenSSH key requires a one-time passphrase.
    pub passphrase_required: bool,
}

fn host_key_details(
    presentation: HostKeyPresentation,
    status: HostKeyStatus,
    passphrase_required: bool,
) -> HostKeyDetails {
    HostKeyDetails {
        algorithm: presentation.algorithm,
        key: presentation.key,
        fingerprint: presentation.fingerprint,
        status: match status {
            HostKeyStatus::Trusted => HostKeyTrustStatus::Trusted,
            HostKeyStatus::New => HostKeyTrustStatus::New,
            HostKeyStatus::Changed => HostKeyTrustStatus::Changed,
        },
        passphrase_required,
    }
}

/// An SSH connection error safe to return over the desktop IPC boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SessionConnectError {
    /// An encrypted saved key needs its passphrase.
    PassphraseRequired,
    /// The passphrase did not open the encrypted key.
    InvalidPrivateKeyPassphrase,
    /// Another connection error; the message contains no credential material.
    Failed {
        /// Safe error detail for the session UI.
        message: String,
    },
}

impl From<String> for SessionConnectError {
    fn from(message: String) -> Self {
        Self::Failed { message }
    }
}

impl SessionConnectError {
    fn from_ssh(error: SshConnectionError) -> Self {
        match error {
            SshConnectionError::EncryptedPrivateKey => Self::PassphraseRequired,
            SshConnectionError::InvalidPrivateKeyPassphrase => Self::InvalidPrivateKeyPassphrase,
            other => Self::Failed { message: display_connection_error(other) },
        }
    }
}

/// Probe and classify the SSH host key before opening an authenticated session.
///
/// New and changed keys are returned to the frontend for explicit confirmation;
/// this command never writes a trust record and never accepts a key for a later
/// connection by itself.
#[tauri::command]
#[specta::specta]
pub async fn session_host_key(
    local: tauri::State<'_, LocalDataState>,
    profile_id: String,
) -> Result<HostKeyDetails, String> {
    let store = local.store().ok_or_else(|| "local data is locked".to_owned())?;
    let inventory = Inventory::with_deletions(store.clone(), DeletionStore::default());
    let plan = inventory.connection_plan(profile_id).map_err(|error| error.to_string())?;
    let records =
        Repository::<TrustRecord>::new(&store).list().map_err(|error| error.to_string())?;
    let presentation = probe_host_key(&plan).await.map_err(display_connection_error)?;
    let status =
        evaluate_host_key(plan.host_id, &presentation.key, &presentation.fingerprint, &records);
    let passphrase_required =
        private_key_passphrase_required(&plan.credential).map_err(display_connection_error)?;
    Ok(host_key_details(presentation, status, passphrase_required))
}

/// Trust a previously displayed host key after probing it again.
///
/// The expected values bind the confirmation to the exact probe shown to the
/// user. A changed value aborts without writing anything. Older active direct
/// key records for the Host are revoked before the new manual record is
/// created, so a key rotation cannot leave two different keys trusted at once.
#[tauri::command]
#[specta::specta]
pub async fn session_trust_host_key(
    local: tauri::State<'_, LocalDataState>,
    profile_id: String,
    algorithm: String,
    key: String,
    fingerprint: String,
) -> Result<(), String> {
    let store = local.store().ok_or_else(|| "local data is locked".to_owned())?;
    let inventory = Inventory::with_deletions(store.clone(), DeletionStore::default());
    let plan = inventory.connection_plan(profile_id).map_err(|error| error.to_string())?;
    let current = probe_host_key(&plan).await.map_err(display_connection_error)?;
    if current.algorithm != algorithm || current.key != key || current.fingerprint != fingerprint {
        return Err("host key changed while waiting for confirmation; try again".to_owned());
    }

    let repository = Repository::<TrustRecord>::new(&store);
    let records = repository.list().map_err(|error| error.to_string())?;
    let status = evaluate_host_key(plan.host_id, &current.key, &current.fingerprint, &records);
    if status == HostKeyStatus::Trusted {
        return Ok(());
    }

    for record in records
        .iter()
        .filter(|record| record.host == Some(plan.host_id) && !record.revoked && !record.ca)
    {
        repository
            .update(record.meta.id, TrustRecordChange { revoked: Some(true), ..Default::default() })
            .map_err(|error| error.to_string())?;
    }
    repository
        .create(TrustRecordChange {
            host: Edit::Set(plan.host_id),
            key: Edit::Set(current.key),
            fingerprint: Edit::Set(current.fingerprint),
            provenance: Some(Provenance::Manual),
            accepted_at: Edit::Set(now_millis()),
            ..Default::default()
        })
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// Connects one direct profile and streams its exec or shell output.
/// Interactive shells notify `ready` after authentication, PTY, and shell setup.
///
/// Host-key verification uses active, host-specific trust records and remains
/// fail-closed for new, changed, revoked, wildcard-only, or CA records.
#[tauri::command]
#[specta::specta]
#[allow(clippy::too_many_arguments)] // Tauri injects both state arguments.
pub async fn session_connect(
    app: tauri::AppHandle,
    local: tauri::State<'_, LocalDataState>,
    registry: tauri::State<'_, SessionRegistry>,
    profile_id: String,
    command: Option<String>,
    pty: bool,
    session_id: String,
    passphrase: Option<String>,
    frames: Channel<RawFrame>,
    ready: Channel<()>,
) -> Result<(), SessionConnectError> {
    let passphrase = passphrase.map(|value| SecretVec::new(value.into_bytes()));
    if passphrase.as_ref().is_some_and(|value| value.len() > MAX_PRIVATE_KEY_PASSPHRASE) {
        return Err(SessionConnectError::Failed {
            message: format!(
                "SSH private-key passphrase exceeds the {MAX_PRIVATE_KEY_PASSPHRASE}-byte limit"
            ),
        });
    }
    let (_registration, mut commands, mut close) = if command.is_none() {
        let (registration, receiver, close) = registry.register(&session_id, pty)?;
        (Some(registration), Some(receiver), Some(close))
    } else {
        (None, None, None)
    };
    session_connect_inner(
        &app,
        &local,
        profile_id,
        command,
        pty,
        passphrase,
        frames,
        ready,
        commands.as_mut(),
        close.as_mut(),
    )
    .await
}

/// Sends one bounded input chunk to a live shell session.
#[tauri::command]
#[specta::specta]
pub fn session_input(
    registry: tauri::State<'_, SessionRegistry>,
    session_id: String,
    data: Vec<u8>,
) -> Result<(), String> {
    if data.len() > scoplen_client_core::connection::MAX_SSH_INPUT {
        return Err("session input exceeds the 64 KiB limit".to_owned());
    }
    registry.send(&session_id, SessionCommand::Input(data))
}

/// Notifies a live SSH PTY of a new character-cell size.
#[tauri::command]
#[specta::specta]
pub fn session_resize(
    registry: tauri::State<'_, SessionRegistry>,
    session_id: String,
    columns: u32,
    rows: u32,
) -> Result<(), String> {
    terminal_size(columns, rows).map_err(display_connection_error)?;
    registry.send(&session_id, SessionCommand::Resize { columns, rows })
}

/// Closes the transport for a live shell session.
#[tauri::command]
#[specta::specta]
pub fn session_close_transport(
    registry: tauri::State<'_, SessionRegistry>,
    session_id: String,
) -> Result<(), String> {
    registry.close(&session_id)
}

#[allow(clippy::too_many_arguments)] // Forwards the IPC request and both channels into the connection task.
async fn session_connect_inner(
    app: &tauri::AppHandle,
    local: &LocalDataState,
    profile_id: String,
    command: Option<String>,
    pty: bool,
    passphrase: Option<SecretVec>,
    frames: Channel<RawFrame>,
    ready: Channel<()>,
    commands: Option<&mut Receiver<SessionCommand>>,
    mut close: Option<&mut watch::Receiver<bool>>,
) -> Result<(), SessionConnectError> {
    let store = local.store().ok_or_else(|| "local data is locked".to_owned())?;
    let inventory = Inventory::with_deletions(store.clone(), DeletionStore::default());
    let plan = inventory.connection_plan(profile_id.clone()).map_err(|error| error.to_string())?;
    let records =
        Repository::<TrustRecord>::new(&store).list().map_err(|error| error.to_string())?;
    let trust: HostKeyTrust = Arc::new(StoredHostKeyVerifier::new(plan.host_id, records));
    let closed_app = app.clone();
    let history =
        SessionHistoryLease::start(inventory, profile_id, RecentSessionKind::Terminal, move |id| {
            let _ = SessionChanged { session_id: id.to_owned(), change: SessionChangeKind::Closed }
                .emit(&closed_app);
        })
        .map_err(|error| error.to_string())?;
    let _ =
        SessionChanged { session_id: history.id().to_owned(), change: SessionChangeKind::Opened }
            .emit(app);
    let interactive = command.is_none();
    let pty_request = pty.then(default_pty);
    let prepare = async {
        let mut connection =
            SshConnection::connect(&plan, Some(trust)).await.map_err(display_connection_error)?;
        connection
            .authenticate_with_passphrase(passphrase)
            .await
            .map_err(SessionConnectError::from_ssh)?;
        let session = connection.open_session().await.map_err(display_connection_error)?;
        if interactive {
            if let Some(request) = pty_request.as_ref() {
                session.request_pty(request).await.map_err(display_connection_error)?;
            }
            session.request_shell().await.map_err(display_connection_error)?;
        }
        Ok::<_, SessionConnectError>((connection, session))
    };
    let Some(prepared) = prepare_session_or_close(prepare, close.as_deref_mut()).await else {
        return history
            .finish(RecentSessionOutcome::Closed)
            .map_err(|error| error.to_string().into());
    };
    let (connection, mut session) = prepared?;
    let sender = FrameSender::new(frames);
    if let Some(command) = command {
        let output = session
            .exec(command.as_bytes(), pty_request.as_ref())
            .await
            .map_err(display_connection_error)?;
        send_exec_output(&sender, output)?;
    } else {
        let commands =
            commands.ok_or_else(|| "session command channel is unavailable".to_owned())?;
        ready.send(()).map_err(|_| "session readiness channel is closed".to_owned())?;
        let close = close.ok_or_else(|| "session close signal is unavailable".to_owned())?;
        stream_channel(&mut session, &sender, commands, close).await?;
    }
    connection.close().await.map_err(display_connection_error)?;
    history.finish(RecentSessionOutcome::Closed).map_err(|error| error.to_string().into())
}

async fn prepare_session_or_close<T>(
    prepare: impl Future<Output = T>,
    close: Option<&mut watch::Receiver<bool>>,
) -> Option<T> {
    let Some(close) = close else { return Some(prepare.await) };
    tokio::select! {
        biased;
        _ = wait_for_close(close) => None,
        result = prepare => Some(result),
    }
}

async fn wait_for_close(close: &mut watch::Receiver<bool>) {
    let _ = close.wait_for(|requested| *requested).await;
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

fn send_exec_output(sender: &FrameSender, output: SshExecOutput) -> Result<(), String> {
    if !output.stdout.is_empty() {
        sender.send(output.stdout).map_err(|error| error.to_string())?;
    }
    if !output.stderr.is_empty() {
        sender.send(output.stderr).map_err(|error| error.to_string())?;
    }
    Ok(())
}

async fn stream_channel(
    session: &mut SshSession,
    sender: &FrameSender,
    commands: &mut Receiver<SessionCommand>,
    close: &mut watch::Receiver<bool>,
) -> Result<(), String> {
    loop {
        tokio::select! {
            biased;
            _ = wait_for_close(close) => {
                session.close().await.map_err(display_connection_error)?;
                break;
            },
            command = commands.recv() => match command {
                Some(SessionCommand::Input(data)) => {
                    session.send_data(&data).await.map_err(display_connection_error)?;
                }
                Some(SessionCommand::Resize { columns, rows }) => {
                    session.resize(columns, rows).await.map_err(display_connection_error)?;
                }
                None => {
                    session.close().await.map_err(display_connection_error)?;
                    break;
                }
            },
            event = session.next_event() => match event.map_err(display_connection_error)? {
                Some(ChannelEvent::Data(data) | ChannelEvent::ExtendedData { data, .. }) => {
                    sender.send(data).map_err(|error| error.to_string())?;
                }
                Some(ChannelEvent::Close) | None => break,
                Some(_) => {}
            },
        }
    }
    Ok(())
}

fn display_connection_error(error: SshConnectionError) -> String {
    error.to_string()
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis().try_into().unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::{SessionCommand, SessionRegistry, prepare_session_or_close};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn registry_routes_commands_and_rejects_duplicate_sessions() {
        let registry = SessionRegistry::default();
        assert_eq!(
            registry.register(" ", true).err().expect("empty id rejected"),
            "session id must not be empty"
        );

        let (registration, mut receiver, close) =
            registry.register("session-1", true).expect("register session");
        assert_eq!(
            registry.register("session-1", true).err().expect("duplicate rejected"),
            "session is already connected"
        );
        registry.send("session-1", SessionCommand::Input(vec![1, 2, 3])).expect("route input");
        registry
            .send("session-1", SessionCommand::Resize { columns: 120, rows: 40 })
            .expect("route resize");
        registry.close("session-1").expect("route close");
        assert_eq!(
            receiver.try_recv().expect("input command"),
            SessionCommand::Input(vec![1, 2, 3])
        );
        assert_eq!(
            receiver.try_recv().expect("resize command"),
            SessionCommand::Resize { columns: 120, rows: 40 }
        );
        assert!(*close.borrow());

        drop(registration);
        assert_eq!(registry.close("session-1").unwrap_err(), "session is not connected");
    }

    #[test]
    fn registry_rejects_resize_without_pty() {
        let registry = SessionRegistry::default();
        let (_registration, mut receiver, _close) =
            registry.register("session-2", false).expect("register session");
        assert_eq!(
            registry
                .send("session-2", SessionCommand::Resize { columns: 120, rows: 40 })
                .unwrap_err(),
            "session has no PTY to resize"
        );
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn cancelled_connection_future_releases_transport_id() {
        let registry = Arc::new(SessionRegistry::default());
        let runtime =
            tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        runtime.block_on(async {
            let (started, ready) = tokio::sync::oneshot::channel();
            let task = tokio::spawn({
                let registry = registry.clone();
                async move {
                    let (_registration, _receiver, _close) =
                        registry.register("transport-1", true).expect("register");
                    let _ = started.send(());
                    std::future::pending::<()>().await;
                }
            });
            ready.await.expect("registered");
            task.abort();
            assert!(task.await.expect_err("cancelled").is_cancelled());
        });
        assert_eq!(registry.close("transport-1").unwrap_err(), "session is not connected");
        let (_registration, _receiver, _close) =
            registry.register("transport-1", true).expect("reusable");
    }

    #[test]
    fn close_during_key_unlock_cancels_pre_ready_connection_attempt() {
        let registry = Arc::new(SessionRegistry::default());
        let runtime =
            tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        runtime.block_on(async {
            let (_registration, mut commands, mut close) =
                registry.register("unlocking", true).expect("register");
            let dropped = Arc::new(AtomicBool::new(false));
            let authenticated = Arc::new(AtomicBool::new(false));
            let shell_opened = Arc::new(AtomicBool::new(false));
            let (started, ready) = tokio::sync::oneshot::channel();
            let (unlock, unlocked) = tokio::sync::oneshot::channel::<()>();
            let attempt = {
                let dropped = dropped.clone();
                let authenticated = authenticated.clone();
                let shell_opened = shell_opened.clone();
                async move {
                    let _transport = DropSignal(dropped);
                    let _ = started.send(());
                    let _ = unlocked.await;
                    authenticated.store(true, Ordering::SeqCst);
                    shell_opened.store(true, Ordering::SeqCst);
                }
            };
            let task =
                tokio::spawn(
                    async move { prepare_session_or_close(attempt, Some(&mut close)).await },
                );
            ready.await.expect("unlock started");
            registry.send("unlocking", SessionCommand::Input(vec![1])).expect("early input");
            registry.close("unlocking").expect("close transport");
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), task)
                .await
                .expect("close interrupts pending unlock")
                .expect("task completes");
            assert!(outcome.is_none());
            assert!(dropped.load(Ordering::SeqCst));
            assert!(!authenticated.load(Ordering::SeqCst));
            assert!(!shell_opened.load(Ordering::SeqCst));
            assert_eq!(
                commands.try_recv().expect("early input retained"),
                SessionCommand::Input(vec![1])
            );
            assert!(unlock.send(()).is_err(), "cancelled unlock cannot resume authentication");
        });
    }

    #[test]
    fn input_queued_during_preparation_is_available_after_ready() {
        let registry = SessionRegistry::default();
        let runtime =
            tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        runtime.block_on(async {
            let (_registration, mut commands, mut close) =
                registry.register("pre-ready", true).expect("register");
            let (started, ready) = tokio::sync::oneshot::channel();
            let (release, released) = tokio::sync::oneshot::channel::<()>();
            let prepare = async {
                let _ = started.send(());
                released.await.expect("release preparation");
                "ready"
            };
            let task = tokio::spawn(async move {
                let result = prepare_session_or_close(prepare, Some(&mut close)).await;
                (result, commands.recv().await, commands.recv().await)
            });
            ready.await.expect("preparation started");
            registry
                .send("pre-ready", SessionCommand::Input(b"ls\n".to_vec()))
                .expect("queue input");
            registry
                .send("pre-ready", SessionCommand::Resize { columns: 120, rows: 40 })
                .expect("queue resize");
            release.send(()).expect("finish preparation");
            let (result, first, second) = task.await.expect("task completes");
            assert_eq!(result, Some("ready"));
            assert_eq!(first, Some(SessionCommand::Input(b"ls\n".to_vec())));
            assert_eq!(second, Some(SessionCommand::Resize { columns: 120, rows: 40 }));
        });
    }
}
