// SPDX-License-Identifier: Apache-2.0

//! Explicit local TCP tunnels with Rust-owned preparation, listeners and peer lifetimes.

use std::{
    collections::BTreeMap,
    future::pending,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

use scoplen_ssh::ClientError;
use serde::Serialize;
use specta::Type;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinSet,
};
use uuid::Uuid;

use crate::{
    connection::{
        SshConnection,
        preparation::{
            PreparationContext, PreparationControl, PreparationEvent, PreparationPlan,
            PreparationResponse, prepare_resolved_connection, resolve_preparation_plan,
        },
    },
    repository::{AccessProfile, Forward, ForwardKind, Repository},
    store::Store,
};

/// Maximum live tunnels, including preparation and shutdown.
pub const MAX_RUNNING_FORWARDS: usize = 16;
/// Maximum accepted peers, including pending SSH channel opens, in each tunnel.
pub const MAX_FORWARD_PEERS: usize = 32;
/// Maximum retained completed tunnel snapshots.
pub const MAX_COMPLETED_FORWARDS: usize = 32;
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(35);
const PUBLISH_INTERVAL: Duration = Duration::from_millis(250);
const COPY_BUFFER: usize = 32 * 1024;

/// Immutable saved endpoints selected for one explicit execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct LocalForwardConfiguration {
    /// Saved Forward identity, never a renderer-selected destination override.
    pub forward_id: String,
    /// Saved display label.
    pub name: String,
    /// Explicitly selected existing Login.
    pub profile_id: String,
    /// Target Login and Host identity from the same immutable preparation plan.
    pub login: PreparationContext,
    /// Exact saved IPv4 or IPv6 listening address.
    pub bind_address: String,
    /// Exact nonzero saved local port.
    pub bind_port: u16,
    /// Exact remote target, resolved by the authenticated SSH server.
    pub target_host: String,
    /// Exact nonzero remote target port.
    pub target_port: u16,
}

/// State of an independent tunnel, never inferred from an open terminal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum ForwardPhase {
    /// Resolving the saved Login and completing trust and authentication.
    Preparing,
    /// The selected local socket is accepting connections.
    Listening,
    /// New peers and prompt replies are fenced while owned resources settle.
    Stopping,
    /// Explicitly stopped and all owned resources released.
    Stopped,
    /// Execution failed and all owned resources released.
    Failed,
}

impl ForwardPhase {
    fn live(self) -> bool {
        matches!(self, Self::Preparing | Self::Listening | Self::Stopping)
    }
}

/// Fixed failure categories; native errors and connection secrets are never exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub enum ForwardIssue {
    /// Saved fields or identifiers are invalid for this local TCP outcome.
    #[error("save valid local tunnel endpoints and select a Login")]
    InvalidConfiguration,
    /// The saved tunnel or selected Login no longer exists.
    #[error("the saved tunnel or Login is no longer available")]
    NotFound,
    /// Remote and dynamic definitions cannot execute as local TCP forwards.
    #[error("select a local TCP tunnel")]
    NotLocal,
    /// That saved definition already owns a live execution.
    #[error("this tunnel is already running or stopping")]
    AlreadyRunning,
    /// Live execution capacity is reserved before any network operation.
    #[error("stop another tunnel before starting this one")]
    CapacityReached,
    /// Local storage, manager state or the asynchronous runtime is unavailable.
    #[error("tunnel management is unavailable")]
    Unavailable,
    /// A run, prompt or store identity has been replaced or completed.
    #[error("this tunnel action has expired")]
    Expired,
    /// Existing SSH preparation rejected the configuration, trust or authentication.
    #[error("SSH preparation failed; check the selected Login and connect again")]
    PreparationFailed,
    /// The saved local socket cannot be bound or its listener failed.
    #[error("the local listening address is unavailable")]
    ListenFailed,
    /// The SSH event loop or transport ended.
    #[error("the SSH connection ended; start the tunnel again")]
    ConnectionLost,
    /// One accepted peer's target channel was refused.
    #[error("the SSH server refused a target connection")]
    TargetRejected,
    /// One accepted peer's target channel did not open within its budget.
    #[error("a target connection timed out")]
    TargetTimedOut,
    /// An excess accepted socket was closed without opening an SSH channel.
    #[error("the tunnel has reached its connection limit")]
    PeerLimitReached,
    /// One peer failed while copying bytes; other peers remain independent.
    #[error("a tunnel connection ended before copying completed")]
    PeerIo,
    /// Owned shutdown could not be confirmed within its complete-chain budget.
    #[error("tunnel shutdown could not be confirmed")]
    ShutdownFailed,
}

/// Display-safe execution state. Full-width counters are decimal strings for JavaScript.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct ForwardSnapshot {
    /// Fresh execution identity; an earlier run can never control a later one.
    pub run_id: String,
    /// Immutable saved forwarding configuration.
    pub configuration: LocalForwardConfiguration,
    /// Current Rust-owned phase.
    pub phase: ForwardPhase,
    /// Latest preparation state, including any current one-use prompt.
    pub preparation: Option<PreparationEvent>,
    /// Actual bound socket, present only after successful listener admission.
    pub bound_address: Option<String>,
    /// Accepted and opening peers, bounded by `MAX_FORWARD_PEERS`.
    pub active_connections: u32,
    /// Bytes successfully written toward the SSH target.
    pub uploaded_bytes: String,
    /// Bytes successfully written toward the local peer.
    pub downloaded_bytes: String,
    /// Peers refused by target admission, capacity or I/O failure.
    pub rejected_connections: String,
    /// Latest fixed issue category; no remote payload or native error text.
    pub last_issue: Option<ForwardIssue>,
    /// Strictly increasing per-run snapshot revision.
    pub revision: String,
}

type Observer = Arc<dyn Fn(ForwardSnapshot) + Send + Sync>;

struct State {
    snapshot: ForwardSnapshot,
    revision: u64,
}

struct Run {
    store: Weak<Store>,
    configuration: LocalForwardConfiguration,
    state: Mutex<State>,
    control: PreparationControl,
    stop: watch::Sender<bool>,
    finished: watch::Sender<bool>,
    active: AtomicU32,
    uploaded: AtomicU64,
    downloaded: AtomicU64,
    rejected: AtomicU64,
    peer_issue: Mutex<Option<ForwardIssue>>,
    observer: Mutex<Option<Observer>>,
}

impl Run {
    fn snapshot(&self) -> Result<ForwardSnapshot, ForwardIssue> {
        let state = self.state.lock().map_err(|_| ForwardIssue::Unavailable)?;
        Ok(state.snapshot.clone())
    }

    fn update(&self, change: impl FnOnce(&mut ForwardSnapshot)) {
        let snapshot = {
            let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let previous = state.snapshot.clone();
            if let Some(issue) =
                self.peer_issue.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
            {
                state.snapshot.last_issue = Some(issue);
            }
            change(&mut state.snapshot);
            state.snapshot.active_connections = self.active.load(Ordering::Acquire);
            state.snapshot.uploaded_bytes = self.uploaded.load(Ordering::Acquire).to_string();
            state.snapshot.downloaded_bytes = self.downloaded.load(Ordering::Acquire).to_string();
            state.snapshot.rejected_connections = self.rejected.load(Ordering::Acquire).to_string();
            if state.snapshot == previous {
                return;
            }
            state.revision = state.revision.saturating_add(1);
            state.snapshot.revision = state.revision.to_string();
            state.snapshot.clone()
        };
        let observer = {
            let mut observer =
                self.observer.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if snapshot.phase.live() { observer.clone() } else { observer.take() }
        };
        if let Some(observer) = observer {
            observer(snapshot);
        }
    }

    fn prepare(&self, event: PreparationEvent) {
        self.update(|snapshot| {
            if snapshot.phase == ForwardPhase::Preparing {
                snapshot.preparation = Some(event);
            }
        });
    }

    fn stop(&self) {
        self.update(|snapshot| {
            if snapshot.phase.live() {
                self.control.cancel();
                self.stop.send_replace(true);
                snapshot.phase = ForwardPhase::Stopping;
                snapshot.preparation = None;
            }
        });
    }

    fn peer_failed(&self, issue: ForwardIssue) {
        self.rejected.fetch_add(1, Ordering::AcqRel);
        *self.peer_issue.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(issue);
    }
}

/// Owns independent local TCP executions even when the observing interface detaches.
#[derive(Clone, Default)]
pub struct ForwardManager {
    registry: Arc<Mutex<Registry>>,
}

#[derive(Default)]
struct Registry {
    closed: bool,
    runs: BTreeMap<Uuid, Arc<Run>>,
}

impl ForwardManager {
    /// Validate and snapshot a saved local Forward, then spawn its independent owner.
    ///
    /// The observer is optional notification only: losing a renderer never stops a tunnel.
    /// `list` and `snapshot` retain pending preparation prompts for a new observer.
    pub fn start(
        &self,
        store: Arc<Store>,
        forward_id: &str,
        profile_id: &str,
        emit: impl Fn(ForwardSnapshot) + Send + Sync + 'static,
    ) -> Result<ForwardSnapshot, ForwardIssue> {
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| ForwardIssue::Unavailable)?;
        let (configuration, plan) = saved_configuration(&store, forward_id, profile_id)?;
        let mut registry = self.registry.lock().map_err(|_| ForwardIssue::Unavailable)?;
        if registry.closed {
            return Err(ForwardIssue::Unavailable);
        }
        for run in registry.runs.values() {
            let snapshot = run.snapshot()?;
            if snapshot.phase.live()
                && snapshot.configuration.forward_id == configuration.forward_id
            {
                return Err(ForwardIssue::AlreadyRunning);
            }
        }
        if registry.runs.values().filter(|run| run.snapshot().is_ok_and(|s| s.phase.live())).count()
            >= MAX_RUNNING_FORWARDS
        {
            return Err(ForwardIssue::CapacityReached);
        }
        let id = Uuid::now_v7();
        let snapshot = ForwardSnapshot {
            run_id: id.to_string(),
            configuration: configuration.clone(),
            phase: ForwardPhase::Preparing,
            preparation: None,
            bound_address: None,
            active_connections: 0,
            uploaded_bytes: "0".into(),
            downloaded_bytes: "0".into(),
            rejected_connections: "0".into(),
            last_issue: None,
            revision: "1".into(),
        };
        let (stop, _) = watch::channel(false);
        let (finished, _) = watch::channel(false);
        let run = Arc::new(Run {
            store: Arc::downgrade(&store),
            configuration,
            state: Mutex::new(State { snapshot: snapshot.clone(), revision: 1 }),
            control: PreparationControl::default(),
            stop,
            finished,
            active: AtomicU32::new(0),
            uploaded: AtomicU64::new(0),
            downloaded: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            peer_issue: Mutex::new(None),
            observer: Mutex::new(Some(Arc::new(emit))),
        });
        registry.runs.insert(id, run.clone());
        drop(registry);
        let manager = self.clone();
        runtime.spawn(async move {
            let result = execute(&run, store, plan).await;
            run.update(|snapshot| {
                snapshot.preparation = None;
                snapshot.bound_address = None;
                match result {
                    Ok(()) => snapshot.phase = ForwardPhase::Stopped,
                    Err(issue) => {
                        snapshot.phase = ForwardPhase::Failed;
                        snapshot.last_issue = Some(issue);
                    }
                }
            });
            manager.prune_completed();
            run.finished.send_replace(true);
        });
        Ok(snapshot)
    }

    /// Read retained snapshots belonging to this exact open store.
    pub fn list(&self, store: &Arc<Store>) -> Result<Vec<ForwardSnapshot>, ForwardIssue> {
        self.registry
            .lock()
            .map_err(|_| ForwardIssue::Unavailable)?
            .runs
            .values()
            .filter(|run| run.store.ptr_eq(&Arc::downgrade(store)))
            .map(|run| run.snapshot())
            .collect()
    }

    /// Read one exact execution without exposing state from another open store.
    pub fn snapshot(
        &self,
        store: &Arc<Store>,
        run_id: &str,
    ) -> Result<ForwardSnapshot, ForwardIssue> {
        self.run(store, run_id)?.snapshot()
    }

    /// Reply to the existing trust, key-passphrase or Interactive preparation protocol.
    pub fn respond(
        &self,
        store: &Arc<Store>,
        run_id: &str,
        prompt_id: &str,
        response: PreparationResponse,
    ) -> Result<(), ForwardIssue> {
        let run = self.run(store, run_id)?;
        let state = run.state.lock().map_err(|_| ForwardIssue::Unavailable)?;
        if state.snapshot.phase != ForwardPhase::Preparing || *run.stop.borrow() {
            return Err(ForwardIssue::Expired);
        }
        run.control.respond(prompt_id, response).map_err(|_| ForwardIssue::Expired)
    }

    /// Fence new peers and replies, then settle owned sockets and the SSH chain.
    /// Completion is reported by the retained `Stopped` or `Failed` snapshot.
    pub fn stop(&self, store: &Arc<Store>, run_id: &str) -> Result<(), ForwardIssue> {
        self.run(store, run_id)?.stop();
        Ok(())
    }

    /// Permanently fence registration before application exit, even if state is poisoned.
    /// Returns an error after cancellation when the registry was already unavailable.
    pub fn shutdown(&self) -> Result<(), ForwardIssue> {
        let (mut registry, poisoned) = match self.registry.lock() {
            Ok(registry) => (registry, false),
            Err(error) => (error.into_inner(), true),
        };
        registry.closed = true;
        if poisoned {
            for run in registry.runs.values() {
                run.control.cancel();
                run.stop.send_replace(true);
            }
            return Err(ForwardIssue::Unavailable);
        }
        Ok(())
    }

    /// Cancel every current owner before awaiting their cleanup under one 35-second budget.
    /// Store replacement may use this without permanently closing future admission.
    pub async fn stop_all(&self) -> Result<(), ForwardIssue> {
        let (runs, poisoned): (Vec<_>, _) = {
            let (registry, poisoned) = match self.registry.lock() {
                Ok(registry) => (registry, false),
                Err(error) => (error.into_inner(), true),
            };
            (registry.runs.values().cloned().collect(), poisoned)
        };
        for run in &runs {
            run.stop();
        }
        tokio::time::timeout(CLOSE_TIMEOUT, async {
            for run in runs {
                let mut finished = run.finished.subscribe();
                finished
                    .wait_for(|finished| *finished)
                    .await
                    .map_err(|_| ForwardIssue::ShutdownFailed)?;
                if run.snapshot()?.last_issue == Some(ForwardIssue::ShutdownFailed) {
                    return Err(ForwardIssue::ShutdownFailed);
                }
            }
            Ok(())
        })
        .await
        .map_err(|_| ForwardIssue::ShutdownFailed)??;
        if poisoned {
            return Err(ForwardIssue::Unavailable);
        }
        Ok(())
    }

    fn run(&self, store: &Arc<Store>, id: &str) -> Result<Arc<Run>, ForwardIssue> {
        let id = Uuid::parse_str(id).map_err(|_| ForwardIssue::Expired)?;
        let registry = self.registry.lock().map_err(|_| ForwardIssue::Unavailable)?;
        registry
            .runs
            .get(&id)
            .filter(|run| run.store.ptr_eq(&Arc::downgrade(store)))
            .cloned()
            .ok_or(ForwardIssue::Expired)
    }

    fn prune_completed(&self) {
        let Ok(mut registry) = self.registry.lock() else { return };
        let completed: Vec<_> = registry
            .runs
            .iter()
            .filter(|(_, run)| run.snapshot().is_ok_and(|s| !s.phase.live()))
            .map(|(id, _)| *id)
            .collect();
        let excess = completed.len().saturating_sub(MAX_COMPLETED_FORWARDS);
        for id in completed.into_iter().take(excess) {
            registry.runs.remove(&id);
        }
    }
}

fn saved_configuration(
    store: &Store,
    forward_id: &str,
    profile_id: &str,
) -> Result<(LocalForwardConfiguration, PreparationPlan), ForwardIssue> {
    let forward = Uuid::parse_str(forward_id).map_err(|_| ForwardIssue::InvalidConfiguration)?;
    let profile = Uuid::parse_str(profile_id).map_err(|_| ForwardIssue::InvalidConfiguration)?;
    let forward = Repository::<Forward>::new(store)
        .get(forward)
        .map_err(|_| ForwardIssue::Unavailable)?
        .ok_or(ForwardIssue::NotFound)?;
    if forward.kind != ForwardKind::Local {
        return Err(ForwardIssue::NotLocal);
    }
    if Repository::<AccessProfile>::new(store)
        .get(profile)
        .map_err(|_| ForwardIssue::Unavailable)?
        .is_none()
    {
        return Err(ForwardIssue::NotFound);
    }
    let plan =
        resolve_preparation_plan(store, profile).map_err(|_| ForwardIssue::PreparationFailed)?;
    let configuration = LocalForwardConfiguration {
        forward_id: forward.meta.id.to_string(),
        name: forward.name,
        profile_id: profile.to_string(),
        login: plan.target_context().clone(),
        bind_address: forward.bind_address.ok_or(ForwardIssue::InvalidConfiguration)?,
        bind_port: forward.bind_port.ok_or(ForwardIssue::InvalidConfiguration)?,
        target_host: forward.target_host.ok_or(ForwardIssue::InvalidConfiguration)?,
        target_port: forward.target_port.ok_or(ForwardIssue::InvalidConfiguration)?,
    };
    validate_configuration(&configuration)?;
    Ok((configuration, plan))
}

fn validate_configuration(configuration: &LocalForwardConfiguration) -> Result<(), ForwardIssue> {
    if configuration.name.trim().is_empty()
        || configuration.name.len() > scoplen_model::MAX_TEXT_BYTES
        || configuration.bind_address.parse::<IpAddr>().is_err()
        || configuration.bind_port == 0
        || configuration.target_port == 0
        || configuration.target_host.is_empty()
        || configuration.target_host.len() > 1024
        || configuration.target_host.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(ForwardIssue::InvalidConfiguration);
    }
    Ok(())
}

async fn execute(
    run: &Arc<Run>,
    store: Arc<Store>,
    plan: PreparationPlan,
) -> Result<(), ForwardIssue> {
    let mut stop = run.stop.subscribe();
    if *stop.borrow() {
        return Ok(());
    }
    let preparation = prepare_resolved_connection(&store, plan, &run.control, |event| {
        run.prepare(event);
        Ok(())
    });
    tokio::pin!(preparation);
    let connection = tokio::select! {
        biased;
        _ = async { let _ = stop.wait_for(|stopped| *stopped).await; } => {
            return settle_preparation(run, &mut preparation).await;
        },
        result = &mut preparation => {
            match result {
                Ok(connection) => connection,
                Err(_) if *run.stop.borrow() => return Ok(()),
                Err(_) => return Err(ForwardIssue::PreparationFailed),
            }
        }
    };
    let mut connection = Arc::new(connection);
    let result = serve(run, &mut connection, &mut stop).await;
    let connection = Arc::try_unwrap(connection).map_err(|_| ForwardIssue::ShutdownFailed)?;
    let closed = tokio::time::timeout(CLOSE_TIMEOUT, connection.close()).await;
    match closed {
        Ok(Ok(())) => result,
        // A dead event loop may refuse the disconnect send; close still exhausts the chain.
        Ok(Err(_)) if result == Err(ForwardIssue::ConnectionLost) => result,
        _ => Err(ForwardIssue::ShutdownFailed),
    }
}

async fn settle_preparation(
    run: &Run,
    preparation: impl std::future::Future<
        Output = Result<SshConnection, crate::connection::preparation::PreparationError>,
    >,
) -> Result<(), ForwardIssue> {
    run.control.cancel();
    let cleanup = async {
        if let Ok(connection) = preparation.await {
            connection.close().await.map_err(|_| ForwardIssue::ShutdownFailed)?;
        }
        Ok(())
    };
    tokio::time::timeout(CLOSE_TIMEOUT, cleanup)
        .await
        .map_err(|_| ForwardIssue::ShutdownFailed)??;
    Ok(())
}

enum Activity {
    Stop,
    Accepted(std::io::Result<(TcpStream, SocketAddr)>),
    Peer(Option<Result<Result<(), ForwardIssue>, tokio::task::JoinError>>),
    Disconnected,
    UnexpectedChannel(scoplen_ssh::ForwardedChannel),
    Publish,
}

async fn serve(
    run: &Arc<Run>,
    connection: &mut Arc<SshConnection>,
    stop: &mut watch::Receiver<bool>,
) -> Result<(), ForwardIssue> {
    if *stop.borrow() {
        return Ok(());
    }
    let address = SocketAddr::new(
        run.configuration.bind_address.parse().map_err(|_| ForwardIssue::InvalidConfiguration)?,
        run.configuration.bind_port,
    );
    let listener = TcpListener::bind(address).await.map_err(|_| ForwardIssue::ListenFailed)?;
    if *stop.borrow() {
        return Ok(());
    }
    let bound = listener.local_addr().map_err(|_| ForwardIssue::ListenFailed)?.to_string();
    run.update(|snapshot| {
        if snapshot.phase == ForwardPhase::Preparing {
            snapshot.phase = ForwardPhase::Listening;
            snapshot.preparation = None;
            snapshot.bound_address = Some(bound);
        }
    });
    let mut peers = JoinSet::new();
    let publish = tokio::time::sleep(PUBLISH_INTERVAL);
    tokio::pin!(publish);
    let result = loop {
        let activity = tokio::select! {
            biased;
            _ = stop.wait_for(|stopped| *stopped) => Activity::Stop,
            result = peers.join_next(), if !peers.is_empty() => Activity::Peer(result),
            result = observe_connection(connection) => match result {
                Some(channel) => Activity::UnexpectedChannel(channel),
                None => Activity::Disconnected,
            },
            _ = &mut publish => Activity::Publish,
            result = listener.accept() => Activity::Accepted(result),
        };
        match activity {
            Activity::Stop => break Ok(()),
            Activity::Disconnected => break Err(ForwardIssue::ConnectionLost),
            Activity::UnexpectedChannel(channel) => {
                // Local forwarding never authorizes a server-initiated reverse channel.
                drop(channel);
                break Err(ForwardIssue::ConnectionLost);
            }
            Activity::Peer(Some(Ok(Err(ForwardIssue::ConnectionLost)))) => {
                break Err(ForwardIssue::ConnectionLost);
            }
            Activity::Peer(Some(Ok(Err(issue)))) => run.peer_failed(issue),
            Activity::Peer(Some(Err(_))) => break Err(ForwardIssue::PeerIo),
            Activity::Peer(_) => {}
            Activity::Publish => {
                run.update(|_| {});
                publish.as_mut().reset(tokio::time::Instant::now() + PUBLISH_INTERVAL);
            }
            Activity::Accepted(Err(_)) => break Err(ForwardIssue::ListenFailed),
            Activity::Accepted(Ok((socket, origin))) => {
                if *stop.borrow() {
                    drop(socket);
                    break Ok(());
                }
                if run.active.load(Ordering::Acquire) as usize >= MAX_FORWARD_PEERS {
                    drop(socket);
                    run.peer_failed(ForwardIssue::PeerLimitReached);
                    continue;
                }
                run.active.fetch_add(1, Ordering::AcqRel);
                peers.spawn(peer(PeerLease(run.clone()), connection.clone(), socket, origin));
            }
        }
    };
    drop(listener);
    peers.abort_all();
    while peers.join_next().await.is_some() {}
    run.update(|snapshot| {
        snapshot.phase = ForwardPhase::Stopping;
        snapshot.preparation = None;
        snapshot.bound_address = None;
    });
    result
}

async fn observe_connection(
    connection: &mut Arc<SshConnection>,
) -> Option<scoplen_ssh::ForwardedChannel> {
    // Openers share the connection only until they own a channel. They never queue behind a
    // mutable event-loop observer; the coalescing tick revisits observation after they finish.
    let Some(connection) = Arc::get_mut(connection) else { return pending().await };
    let connection = match connection.authenticated_connection_mut() {
        Ok(connection) => connection,
        Err(_) => return None,
    };
    connection.next_forwarded_channel().await
}

struct PeerLease(Arc<Run>);

impl Drop for PeerLease {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

async fn peer(
    lease: PeerLease,
    connection: Arc<SshConnection>,
    socket: TcpStream,
    origin: SocketAddr,
) -> Result<(), ForwardIssue> {
    let run = &lease.0;
    let client = connection.authenticated_connection().map_err(|_| ForwardIssue::ConnectionLost)?;
    let channel = match tokio::time::timeout(
        OPEN_TIMEOUT,
        client.open_direct_tcpip(
            &run.configuration.target_host,
            u32::from(run.configuration.target_port),
            &origin.ip().to_string(),
            u32::from(origin.port()),
        ),
    )
    .await
    {
        Ok(Ok(channel)) => channel,
        Ok(Err(ClientError::ConnectionClosed | ClientError::NetworkLost)) => {
            return Err(ForwardIssue::ConnectionLost);
        }
        Ok(Err(_)) => return Err(ForwardIssue::TargetRejected),
        Err(_) => return Err(ForwardIssue::TargetTimedOut),
    };
    drop(connection);
    let stream = channel.into_stream();
    let (socket_read, socket_write) = tokio::io::split(socket);
    let (remote_read, remote_write) = tokio::io::split(stream);
    tokio::try_join!(
        copy(socket_read, remote_write, &run.uploaded),
        copy(remote_read, socket_write, &run.downloaded),
    )
    .map(|_| ())
    .map_err(|_| ForwardIssue::PeerIo)
}

async fn copy(
    mut source: impl AsyncRead + Unpin,
    mut destination: impl AsyncWrite + Unpin,
    count: &AtomicU64,
) -> std::io::Result<()> {
    let mut buffer = vec![0; COPY_BUFFER];
    loop {
        let read = source.read(&mut buffer).await?;
        if read == 0 {
            destination.shutdown().await?;
            return Ok(());
        }
        let mut written = 0;
        while written < read {
            let bytes = destination.write(&buffer[written..read]).await?;
            if bytes == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            count.fetch_add(bytes as u64, Ordering::AcqRel);
            written += bytes;
        }
    }
}

#[cfg(test)]
mod tests;
