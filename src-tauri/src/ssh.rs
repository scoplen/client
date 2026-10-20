// SPDX-License-Identifier: Apache-2.0

//! Session-owned SSH preparation, per-hop user intents, and binary channel frames.

use crate::events::{SessionChangeKind, SessionChanged};
use crate::frames::{FrameSender, RawFrame};
use crate::local_data::LocalDataState;
use scoplen_client_core::connection::preparation::{
    PreparationControl, PreparationEvent, PreparationResponse, prepare_connection,
};
use scoplen_client_core::connection::{
    SshConnectionError, SshExecOutput, SshSession, terminal_size,
};
use scoplen_client_core::inventory::{
    DeletionStore, Inventory, RecentSessionKind, RecentSessionOutcome,
};
use scoplen_client_core::session_lifecycle::SessionHistoryLease;
use scoplen_crypto::SecretVec;
use scoplen_ssh::ChannelEvent;
use serde::Deserialize;
use specta::Type;
use std::collections::HashMap;
#[cfg(test)]
use std::future::Future;
use std::sync::Mutex;
use tauri::ipc::Channel;
use tauri_specta::Event as _;
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    watch,
};
use uuid::Uuid;

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
    preparation: PreparationControl,
    commands: Option<Receiver<SessionCommand>>,
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
    #[cfg(test)]
    fn register(
        &self,
        session_id: &str,
        pty: bool,
    ) -> Result<(SessionRegistration<'_>, Receiver<SessionCommand>, watch::Receiver<bool>), String>
    {
        self.reserve(session_id, pty)?;
        self.claim(session_id, pty)
    }

    fn reserve(&self, session_id: &str, pty: bool) -> Result<(), String> {
        if session_id.trim().is_empty() {
            return Err("session id must not be empty".to_owned());
        }
        let (sender, receiver) = mpsc::channel(SESSION_COMMAND_QUEUE);
        let (close_sender, _) = watch::channel(false);
        let mut sessions =
            self.sessions.lock().map_err(|_| "session registry is unavailable".to_owned())?;
        if sessions.contains_key(session_id) {
            return Err("session is already connected".to_owned());
        }
        sessions.insert(
            session_id.to_owned(),
            SessionEntry {
                sender,
                close: close_sender,
                pty,
                preparation: PreparationControl::default(),
                commands: Some(receiver),
            },
        );
        Ok(())
    }

    fn claim(
        &self,
        session_id: &str,
        pty: bool,
    ) -> Result<(SessionRegistration<'_>, Receiver<SessionCommand>, watch::Receiver<bool>), String>
    {
        let mut sessions = self.sessions.lock().map_err(|_| "session registry is unavailable")?;
        let entry = sessions.get_mut(session_id).ok_or("session reservation is closed")?;
        if entry.pty != pty {
            return Err("session reservation has different PTY settings".into());
        }
        let receiver = entry.commands.take().ok_or("session is already connected")?;
        let close = entry.close.subscribe();
        Ok((
            SessionRegistration { registry: self, session_id: session_id.to_owned() },
            receiver,
            close,
        ))
    }

    fn preparation(&self, session_id: &str) -> Result<PreparationControl, String> {
        self.sessions
            .lock()
            .map_err(|_| "session registry is unavailable")?
            .get(session_id)
            .map(|entry| entry.preparation.clone())
            .ok_or_else(|| "session is not connected".into())
    }

    fn remove(&self, session_id: &str) {
        if let Ok(mut sessions) = self.sessions.lock()
            && let Some(entry) = sessions.remove(session_id)
        {
            entry.preparation.cancel();
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
        let mut sessions =
            self.sessions.lock().map_err(|_| "session registry is unavailable".to_owned())?;
        let entry =
            sessions.get(session_id).ok_or_else(|| "session is not connected".to_owned())?;
        entry.preparation.cancel();
        entry.close.send_replace(true);
        if entry.commands.is_some() {
            sessions.remove(session_id);
        }
        Ok(())
    }
}

/// Reserve a cancelable transport before the renderer starts preparation.
/// A disposed renderer closes the acknowledged reservation without connecting.
#[tauri::command]
#[specta::specta]
pub fn session_reserve_transport(
    registry: tauri::State<'_, SessionRegistry>,
    session_id: String,
    pty: bool,
) -> Result<(), String> {
    registry.reserve(&session_id, pty)
}

/// A user intent for the one current preparation prompt.
#[derive(Deserialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SessionPreparationIntent {
    /// Accept only the exact host key retained by Rust.
    AcceptHostKey,
    /// Supply a one-time key passphrase, never returned to the renderer.
    Passphrase {
        /// Write-only secret input.
        value: String,
    },
}

/// Respond to one session-owned, one-use preparation prompt.
#[tauri::command]
#[specta::specta]
pub fn session_respond(
    registry: tauri::State<'_, SessionRegistry>,
    session_id: String,
    prompt_id: String,
    intent: SessionPreparationIntent,
) -> Result<(), String> {
    let response = match intent {
        SessionPreparationIntent::AcceptHostKey => PreparationResponse::AcceptHostKey,
        SessionPreparationIntent::Passphrase { value } => {
            PreparationResponse::Passphrase(SecretVec::new(value.into_bytes()))
        }
    };
    registry.preparation(&session_id)?.respond(&prompt_id, response)
}

/// Prepare every hop and stream the target's shell or exec output.
#[tauri::command]
#[specta::specta]
#[allow(clippy::too_many_arguments)]
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
    preparation: Channel<PreparationEvent>,
) -> Result<(), String> {
    let (_registration, mut commands, mut close) = registry.claim(&session_id, pty)?;
    let control = registry.preparation(&session_id)?;
    session_connect_inner(
        &app,
        &local,
        profile_id,
        command,
        pty,
        frames,
        ready,
        preparation,
        &control,
        &mut commands,
        &mut close,
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

#[allow(clippy::too_many_arguments)]
async fn session_connect_inner(
    app: &tauri::AppHandle,
    local: &LocalDataState,
    profile_id: String,
    command: Option<String>,
    pty: bool,
    frames: Channel<RawFrame>,
    ready: Channel<()>,
    preparation: Channel<PreparationEvent>,
    control: &PreparationControl,
    commands: &mut Receiver<SessionCommand>,
    close: &mut watch::Receiver<bool>,
) -> Result<(), String> {
    let store = local.store().ok_or_else(|| "local data is locked".to_owned())?;
    let id = Uuid::parse_str(&profile_id).map_err(|_| "the Login identifier is invalid")?;
    let inventory = Inventory::with_deletions(store.clone(), DeletionStore::default());
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
    let connection = match prepare_connection(&store, id, control, |event| {
        preparation.send(event).map_err(|_| "connection progress channel is closed".into())
    })
    .await
    {
        Ok(connection) => connection,
        Err(error) => {
            if *close.borrow() {
                return history.finish(RecentSessionOutcome::Closed).map_err(|e| e.to_string());
            }
            return Err(error);
        }
    };
    let interactive = command.is_none();
    let pty_request = pty.then(default_pty);
    let operation = async {
        let mut session = connection.open_session().await.map_err(display_connection_error)?;
        let sender = FrameSender::new(frames);
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
            if interactive {
                ready.send(()).map_err(|_| "session readiness channel is closed")?;
            }
            stream_channel(&mut session, &sender, commands, close).await?;
        }
        Ok::<(), String>(())
    };
    let outcome = tokio::select! { biased;
        _ = control.cancelled() => Ok(()),
        result = operation => result,
    };
    let cleanup = connection.close().await.map_err(display_connection_error);
    outcome?;
    cleanup?;
    history.finish(RecentSessionOutcome::Closed).map_err(|error| error.to_string())
}

#[cfg(test)]
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
    fn closed_reservation_cannot_be_claimed_or_replied_to() {
        let registry = SessionRegistry::default();
        registry.reserve("closed-before-start", true).expect("reserve");
        let control = registry.preparation("closed-before-start").expect("control");
        registry.close("closed-before-start").expect("close unclaimed reservation");
        assert_eq!(
            registry.claim("closed-before-start", true).err().expect("claim rejected"),
            "session reservation is closed"
        );
        assert!(registry.preparation("closed-before-start").is_err());
        assert!(control.respond("late", scoplen_client_core::connection::preparation::PreparationResponse::AcceptHostKey).is_err());
        assert!(registry.sessions.lock().expect("registry").is_empty());
        registry.reserve("fresh-session", true).expect("fresh reserve");
        let (_registration, _commands, _close) =
            registry.claim("fresh-session", true).expect("fresh claim");
    }

    #[test]
    fn reservation_is_claimed_once_with_matching_settings() {
        let registry = SessionRegistry::default();
        registry.reserve("reserved", true).expect("reserve");
        assert!(registry.reserve("reserved", true).is_err());
        assert_eq!(
            registry.claim("reserved", false).err().expect("mismatch"),
            "session reservation has different PTY settings"
        );
        let (_registration, _commands, _close) = registry.claim("reserved", true).expect("claim");
        assert_eq!(
            registry.claim("reserved", true).err().expect("duplicate claim"),
            "session is already connected"
        );
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
