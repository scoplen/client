// SPDX-License-Identifier: Apache-2.0

//! Rust-owned terminal sessions, bounded transport attempts, and reconnect policy.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scoplen_ssh::{ChannelEvent, ClientError, TransportError};
use serde::Serialize;
use specta::Type;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use uuid::Uuid;

use crate::connection::preparation::{
    PreparationControl, PreparationError, PreparationEvent, PreparationResponse, prepare_connection,
};
use crate::connection::{MAX_SSH_INPUT, SshConnectionError, SshSession, terminal_size};
use crate::inventory::{DeletionStore, Inventory, RecentSessionKind, RecentSessionOutcome};
use crate::session_lifecycle::SessionHistoryLease;
use crate::store::Store;

const COMMAND_QUEUE: usize = 64;
const STABLE_READY: Duration = Duration::from_secs(30);
const RETRY_DELAYS: [u8; 5] = [1, 2, 4, 8, 16];

/// Display-safe state of one logical terminal. Output uses a separate binary stream.
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

struct ActiveAttempt {
    id: Uuid,
    control: PreparationControl,
    sender: mpsc::Sender<TransportCommand>,
    ready: bool,
}

struct SessionEntry {
    pty: bool,
    phase: Phase,
    intent: watch::Sender<Intent>,
    receiver: Option<watch::Receiver<Intent>>,
    active: Option<ActiveAttempt>,
}

/// Owns logical terminal lifetimes independently of renderer visibility.
///
/// Each active transport has a separate bounded queue and preparation control.
/// Replacing it drops old queued input rather than replaying it into a new shell.
#[derive(Default)]
pub struct SessionManager {
    sessions: Mutex<HashMap<String, SessionEntry>>,
}

struct Registration<'a> {
    manager: &'a SessionManager,
    id: &'a str,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.manager.sessions.lock()
            && let Some(entry) = sessions.remove(self.id)
            && let Some(active) = entry.active
        {
            active.control.cancel();
        }
    }
}

#[derive(Default)]
struct RetryBudget {
    ever_ready: bool,
    attempts: usize,
}

impl RetryBudget {
    fn ended(&mut self, ready_at: Option<Instant>) {
        if let Some(ready_at) = ready_at {
            self.ever_ready = true;
            if ready_at.elapsed() >= STABLE_READY {
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
        _ => false,
    }
}

fn retryable_connection(error: &SshConnectionError) -> bool {
    match error {
        SshConnectionError::Engine(ClientError::Transport(error)) => retryable_io(error.kind()),
        SshConnectionError::Engine(ClientError::DirectTcp(error)) => retryable_transport(error),
        SshConnectionError::Engine(
            ClientError::DirectSshHandshakeTimeout { .. }
            | ClientError::ProxySshHandshakeTimeout { .. }
            | ClientError::ProxyCommandHandshakeTimeout { .. },
        ) => true,
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
        if sessions.contains_key(session_id) {
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
            },
        );
        Ok(())
    }

    /// Cancel the complete logical session, including timers and prompts.
    pub fn close(&self, session_id: &str) -> Result<(), String> {
        self.intent(session_id, Intent::Close)
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
            && let Some(active) = &entry.active
        {
            active.control.cancel();
        }
        entry.intent.send_replace(intent);
        if intent == Intent::Close && entry.receiver.is_some() {
            sessions.remove(session_id);
        }
        Ok(())
    }

    /// Reply only to the active attempt's one-use preparation prompt.
    pub fn respond(
        &self,
        session_id: &str,
        prompt_id: &str,
        response: PreparationResponse,
    ) -> Result<(), String> {
        let sessions = self.sessions.lock().map_err(|_| "session manager is unavailable")?;
        let control = &sessions
            .get(session_id)
            .and_then(|entry| entry.active.as_ref())
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
        entry.active.take();
        Ok(())
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
        emit: impl Fn(SessionEvent) -> Result<(), String>,
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
            {
                let mut sessions =
                    self.sessions.lock().map_err(|_| "session manager is unavailable")?;
                let entry = sessions.get_mut(session_id).ok_or("session is closed")?;
                if *entry.intent.borrow() == Intent::Close {
                    return Ok(());
                }
                entry.intent.send_replace(Intent::None);
                intents.borrow_and_update();
                entry.phase = Phase::Running;
                entry.active = Some(ActiveAttempt {
                    id: transport,
                    control: control.clone(),
                    sender,
                    ready: false,
                });
            }
            emit(SessionEvent::Starting { transport_id: transport.to_string(), automatic })?;
            let mut ready_at = None;
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
                    &mut ready_at,
                    &emit,
                    &output,
                    history_changed.clone(),
                )
                .await;
            let requested = *intents.borrow_and_update();
            let completed = if requested == Intent::None { Some(result) } else { None };
            control.cancel();
            self.phase(session_id, Phase::Ended)?;
            budget.ended(ready_at);
            let mut next = match completed {
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
                next = self.wait_manual(&mut intents).await;
            }
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
        ready_at: &mut Option<Instant>,
        emit: &impl Fn(SessionEvent) -> Result<(), String>,
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
        history_changed(history.id(), HistoryChange::Opened);
        let connection = prepare_connection(store, id, control, |event| {
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
                        .and_then(|entry| entry.active.as_mut())
                        .ok_or_else(|| AttemptError::Local("session is closed".into()))?;
                    entry.ready = true;
                }
                *ready_at = Some(Instant::now());
                emit(SessionEvent::Ready { transport_id: transport.to_string() })
                    .map_err(AttemptError::Local)?;
                stream_channel(&mut session, transport, commands, output).await?;
            }
            Ok::<(), AttemptError>(())
        };
        let result = tokio::select! { biased;
            _ = control.cancelled() => Ok(()),
            result = operation => result,
        };
        let _ = connection.close().await;
        result?;
        history
            .finish(RecentSessionOutcome::Closed)
            .map_err(|error| AttemptError::Local(error.to_string()))
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
    loop {
        tokio::select! { biased;
            command = commands.recv() => match command {
                Some(TransportCommand::Input(data)) => session.send_data(&data).await?,
                Some(TransportCommand::Resize { columns, rows }) => session.resize(columns, rows).await?,
                None => return Ok(()),
            },
            event = session.next_event() => match event? {
                Some(ChannelEvent::Data(data) | ChannelEvent::ExtendedData { data, .. }) => output(transport, data).map_err(AttemptError::Local)?,
                Some(ChannelEvent::Close) | None => return Ok(()),
                Some(_) => {},
            },
        }
    }
}

#[cfg(test)]
mod tests;
