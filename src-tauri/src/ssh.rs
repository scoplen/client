// SPDX-License-Identifier: Apache-2.0

//! The smallest live SSH IPC path: resolve one local profile, connect through
//! the shared engine, and stream channel bytes as binary Tauri frames.

use crate::events::{SessionChangeKind, SessionChanged};
use crate::frames::{FrameSender, RawFrame};
use crate::local_data::LocalDataState;
use scoplen_client_core::connection::{
    HostKeyPresentation, HostKeyStatus, HostKeyTrust, SshConnection, SshConnectionError,
    SshExecOutput, SshSession, StoredHostKeyVerifier, evaluate_host_key, probe_host_key,
    terminal_size,
};
use scoplen_client_core::inventory::{
    DeletionStore, Inventory, RecentSessionKind, RecentSessionOutcome,
};
use scoplen_client_core::repository::{
    Edit, Provenance, Repository, TrustRecord, TrustRecordChange,
};
use scoplen_client_core::session_lifecycle::SessionHistoryLease;
use scoplen_ssh::ChannelEvent;
use serde::Serialize;
use specta::Type;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::ipc::Channel;
use tauri_specta::Event as _;
use tokio::sync::mpsc::{self, Receiver, Sender};

const SESSION_COMMAND_QUEUE: usize = 64;

/// A command sent from the frontend to one live SSH session.
#[derive(Debug, Eq, PartialEq)]
enum SessionCommand {
    Input(Vec<u8>),
    Resize { columns: u32, rows: u32 },
    Close,
}

struct SessionEntry {
    sender: Sender<SessionCommand>,
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
    ) -> Result<(SessionRegistration<'_>, Receiver<SessionCommand>), String> {
        if session_id.trim().is_empty() {
            return Err("session id must not be empty".to_owned());
        }
        let (sender, receiver) = mpsc::channel(SESSION_COMMAND_QUEUE);
        let mut sessions =
            self.sessions.lock().map_err(|_| "session registry is unavailable".to_owned())?;
        if sessions.contains_key(session_id) {
            return Err("session is already connected".to_owned());
        }
        sessions.insert(session_id.to_owned(), SessionEntry { sender, pty });
        Ok((SessionRegistration { registry: self, session_id: session_id.to_owned() }, receiver))
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
}

fn host_key_details(presentation: HostKeyPresentation, status: HostKeyStatus) -> HostKeyDetails {
    HostKeyDetails {
        algorithm: presentation.algorithm,
        key: presentation.key,
        fingerprint: presentation.fingerprint,
        status: match status {
            HostKeyStatus::Trusted => HostKeyTrustStatus::Trusted,
            HostKeyStatus::New => HostKeyTrustStatus::New,
            HostKeyStatus::Changed => HostKeyTrustStatus::Changed,
        },
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
    Ok(host_key_details(presentation, status))
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
    frames: Channel<RawFrame>,
    ready: Channel<()>,
) -> Result<(), String> {
    let (_registration, mut commands) = if command.is_none() {
        let (registration, receiver) = registry.register(&session_id, pty)?;
        (Some(registration), Some(receiver))
    } else {
        (None, None)
    };
    session_connect_inner(&app, &local, profile_id, command, pty, frames, ready, commands.as_mut())
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
    registry.send(&session_id, SessionCommand::Close)
}

#[allow(clippy::too_many_arguments)] // Forwards the IPC request and both channels into the connection task.
async fn session_connect_inner(
    app: &tauri::AppHandle,
    local: &LocalDataState,
    profile_id: String,
    command: Option<String>,
    pty: bool,
    frames: Channel<RawFrame>,
    ready: Channel<()>,
    commands: Option<&mut Receiver<SessionCommand>>,
) -> Result<(), String> {
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
    let mut connection =
        SshConnection::connect(&plan, Some(trust)).await.map_err(display_connection_error)?;
    drop(plan);
    connection.authenticate().await.map_err(display_connection_error)?;
    let mut session = connection.open_session().await.map_err(display_connection_error)?;
    let sender = FrameSender::new(frames);
    let pty_request = pty.then(default_pty);
    if let Some(command) = command {
        let output = session
            .exec(command.as_bytes(), pty_request.as_ref())
            .await
            .map_err(display_connection_error)?;
        send_exec_output(&sender, output)?;
    } else {
        if let Some(request) = pty_request.as_ref() {
            session.request_pty(request).await.map_err(display_connection_error)?;
        }
        session.request_shell().await.map_err(display_connection_error)?;
        let commands =
            commands.ok_or_else(|| "session command channel is unavailable".to_owned())?;
        ready.send(()).map_err(|_| "session readiness channel is closed".to_owned())?;
        stream_channel(&mut session, &sender, commands).await?;
    }
    connection.close().await.map_err(display_connection_error)?;
    history.finish(RecentSessionOutcome::Closed).map_err(|error| error.to_string())
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
) -> Result<(), String> {
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(SessionCommand::Input(data)) => {
                    session.send_data(&data).await.map_err(display_connection_error)?;
                }
                Some(SessionCommand::Resize { columns, rows }) => {
                    session.resize(columns, rows).await.map_err(display_connection_error)?;
                }
                Some(SessionCommand::Close) | None => {
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
    use super::{SessionCommand, SessionRegistry};
    use std::sync::Arc;

    #[test]
    fn registry_routes_commands_and_rejects_duplicate_sessions() {
        let registry = SessionRegistry::default();
        assert_eq!(
            registry.register(" ", true).err().expect("empty id rejected"),
            "session id must not be empty"
        );

        let (registration, mut receiver) =
            registry.register("session-1", true).expect("register session");
        assert_eq!(
            registry.register("session-1", true).err().expect("duplicate rejected"),
            "session is already connected"
        );
        registry.send("session-1", SessionCommand::Input(vec![1, 2, 3])).expect("route input");
        registry
            .send("session-1", SessionCommand::Resize { columns: 120, rows: 40 })
            .expect("route resize");
        registry.send("session-1", SessionCommand::Close).expect("route close");
        assert_eq!(
            receiver.try_recv().expect("input command"),
            SessionCommand::Input(vec![1, 2, 3])
        );
        assert_eq!(
            receiver.try_recv().expect("resize command"),
            SessionCommand::Resize { columns: 120, rows: 40 }
        );
        assert_eq!(receiver.try_recv().expect("close command"), SessionCommand::Close);

        drop(registration);
        assert_eq!(
            registry.send("session-1", SessionCommand::Close).unwrap_err(),
            "session is not connected"
        );
    }

    #[test]
    fn registry_rejects_resize_without_pty() {
        let registry = SessionRegistry::default();
        let (_registration, mut receiver) =
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
                    let (_registration, _receiver) =
                        registry.register("transport-1", true).expect("register");
                    let _ = started.send(());
                    std::future::pending::<()>().await;
                }
            });
            ready.await.expect("registered");
            task.abort();
            assert!(task.await.expect_err("cancelled").is_cancelled());
        });
        assert_eq!(
            registry.send("transport-1", SessionCommand::Close).unwrap_err(),
            "session is not connected"
        );
        let (_registration, _receiver) = registry.register("transport-1", true).expect("reusable");
    }
}
