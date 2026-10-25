// SPDX-License-Identifier: Apache-2.0

use super::*;
use scoplen_ssh::{ForwardedChannel, ForwardedChannelKind, MAX_TCP_ADDRESSES};
use tokio::time::{Instant, timeout_at};

const CANCEL_TIMEOUT: Duration = Duration::from_secs(1);
const PEER_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) async fn execute(
    run: &Arc<Run>,
    mut connection: SshConnection,
    stop: &mut watch::Receiver<bool>,
) -> Result<(), ForwardIssue> {
    let (address, port) = run.configuration.bind();
    let mut peers = JoinSet::new();
    let mut registered = false;
    let mut uncertain = false;
    let result = if *stop.borrow() {
        Ok(())
    } else {
        let request = async {
            connection
                .authenticated_connection()
                .map_err(|_| ClientError::ConnectionClosed)?
                .request_tcpip_forward(address, u32::from(port))
                .await
        };
        let deadline = Instant::now() + OPEN_TIMEOUT;
        let acknowledgement = tokio::select! {
            biased;
            _ = stop.wait_for(|stopped| *stopped) => None,
            result = timeout_at(deadline, request) => Some(result),
        };
        match acknowledgement {
            // Fixed-port SSH success has an empty payload and the adapter returns zero.
            Some(Ok(Ok(actual))) if actual == 0 || actual == u32::from(port) => {
                registered = true;
                serve(run, &mut connection, stop, &mut peers).await
            }
            Some(Err(_)) => {
                uncertain = true;
                Err(ForwardIssue::ListenTimedOut)
            }
            Some(Ok(_)) => {
                // The shared error erases request-denied versus an interrupted reply.
                uncertain = true;
                Err(ForwardIssue::ListenFailed)
            }
            None => {
                uncertain = true;
                Ok(())
            }
        }
    };

    let deadline = Instant::now() + CLOSE_TIMEOUT;
    run.stop();
    run.update(|snapshot| {
        snapshot.preparation = None;
        snapshot.bound_address = None;
        if let Err(issue) = result {
            snapshot.last_issue = Some(issue);
        }
    });
    let cleanup = async {
        peers.abort_all();
        while peers.join_next().await.is_some() {}
        if registered {
            let cancel_deadline = deadline.min(Instant::now() + CANCEL_TIMEOUT);
            let cancelled = async {
                connection
                    .authenticated_connection()
                    .map_err(|_| ClientError::ConnectionClosed)?
                    .cancel_tcpip_forward(address, u32::from(port))
                    .await
            };
            if !matches!(timeout_at(cancel_deadline, cancelled).await, Ok(Ok(()))) {
                uncertain = true;
            }
        }
        let closed = connection.close().await;
        if uncertain || closed.is_err() { Err(ForwardIssue::ShutdownFailed) } else { result }
    };
    timeout_at(deadline, cleanup).await.map_err(|_| ForwardIssue::ShutdownFailed)?
}

async fn serve(
    run: &Arc<Run>,
    connection: &mut SshConnection,
    stop: &mut watch::Receiver<bool>,
    peers: &mut JoinSet<Result<(), ForwardIssue>>,
) -> Result<(), ForwardIssue> {
    let ForwardConfiguration::Remote { bind_address, bind_port, target_host, target_port, .. } =
        &run.configuration
    else {
        return Err(ForwardIssue::InvalidConfiguration);
    };
    if *stop.borrow() {
        return Ok(());
    }
    run.update(|snapshot| {
        if snapshot.phase == ForwardPhase::Preparing {
            snapshot.phase = ForwardPhase::Listening;
            snapshot.preparation = None;
        }
    });
    let publish = tokio::time::sleep(PUBLISH_INTERVAL);
    tokio::pin!(publish);
    loop {
        let client =
            connection.authenticated_connection_mut().map_err(|_| ForwardIssue::ConnectionLost)?;
        tokio::select! {
            biased;
            _ = async { let _ = stop.wait_for(|stopped| *stopped).await; } => return Ok(()),
            result = peers.join_next(), if !peers.is_empty() => match result {
                Some(Ok(Err(ForwardIssue::ConnectionLost))) => {
                    run.peer_failed(ForwardIssue::PeerIo);
                    return Err(ForwardIssue::ConnectionLost);
                },
                Some(Ok(Err(issue))) => run.peer_failed(issue),
                Some(Err(_)) => return Err(ForwardIssue::PeerIo),
                _ => {}
            },
            _ = &mut publish => {
                run.update(|_| {});
                publish.as_mut().reset(Instant::now() + PUBLISH_INTERVAL);
            },
            channel = client.next_forwarded_channel() => {
                let Some(channel) = channel else {
                    return Err(ForwardIssue::ConnectionLost);
                };
                if *stop.borrow() {
                    close_peer(channel.into_channel()).await?;
                    return Ok(());
                }
                if !matches_endpoint(&channel, bind_address, *bind_port) {
                    run.peer_failed(ForwardIssue::PeerRejected);
                    close_peer(channel.into_channel()).await?;
                    continue;
                }
                if run.active.load(Ordering::Acquire) as usize >= MAX_FORWARD_PEERS {
                    run.peer_failed(ForwardIssue::PeerLimitReached);
                    close_peer(channel.into_channel()).await?;
                    continue;
                }
                run.active.fetch_add(1, Ordering::AcqRel);
                let lease = PeerLease(run.clone());
                let target_host = target_host.clone();
                let target_port = *target_port;
                let deadline = Instant::now() + OPEN_TIMEOUT;
                peers.spawn(async move {
                    let channel = channel.into_channel();
                    let socket = match connect_target(&target_host, target_port, deadline, &lease.0.stop).await {
                        Ok(Some(socket)) => socket,
                        result => {
                            close_peer(channel).await?;
                            return result.map(|_| ());
                        }
                    };
                    copy_peer(&lease.0, socket, channel, Vec::new()).await
                });
            },
        }
    }
}

async fn close_peer(channel: ClientChannel) -> Result<(), ForwardIssue> {
    tokio::time::timeout(PEER_CLOSE_TIMEOUT, channel.close())
        .await
        .map_err(|_| ForwardIssue::ConnectionLost)?
        .map_err(|_| ForwardIssue::ConnectionLost)
}

fn matches_endpoint(channel: &ForwardedChannel, address: &str, port: u16) -> bool {
    matches!(channel.kind(), ForwardedChannelKind::Tcp {
        connected_address, connected_port, ..
    } if connected_address == address && *connected_port == u32::from(port))
}

pub(super) async fn connect_target(
    host: &str,
    port: u16,
    deadline: Instant,
    stop: &watch::Sender<bool>,
) -> Result<Option<TcpStream>, ForwardIssue> {
    let mut cancelled = stop.subscribe();
    if *stop.borrow() {
        return Ok(None);
    }
    if Instant::now() >= deadline {
        return Err(ForwardIssue::TargetTimedOut);
    }
    let setup = timeout_at(deadline, async {
        let addresses = resolve_target(host, port).await?;
        for address in addresses {
            // A resolver completing after cancellation or expiry must not initiate a dial.
            if *stop.borrow() {
                return Ok(None);
            }
            if Instant::now() >= deadline {
                return Err(ForwardIssue::TargetTimedOut);
            }
            if let Ok(socket) = TcpStream::connect(address).await {
                return Ok(Some(socket));
            }
        }
        Err(ForwardIssue::TargetRejected)
    });
    tokio::select! {
        biased;
        _ = cancelled.wait_for(|stopped| *stopped) => Ok(None),
        result = setup => result.map_err(|_| ForwardIssue::TargetTimedOut)?,
    }
}

async fn resolve_target(host: &str, port: u16) -> Result<Vec<SocketAddr>, ForwardIssue> {
    #[cfg(test)]
    let pending = resolution_gates().lock().unwrap().remove(host);
    #[cfg(test)]
    if let Some(pending) = pending {
        let _ = pending.entered.send(());
        let addresses = pending.resolution.await.map_err(|_| ForwardIssue::TargetRejected)?;
        return target_addresses(addresses.into_iter());
    }
    let raw =
        tokio::net::lookup_host((host, port)).await.map_err(|_| ForwardIssue::TargetRejected)?;
    target_addresses(raw)
}

pub(super) fn target_addresses(
    raw: impl Iterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, ForwardIssue> {
    let mut addresses = Vec::new();
    for (index, address) in raw.enumerate() {
        if index >= MAX_TCP_ADDRESSES {
            return Err(ForwardIssue::TargetRejected);
        }
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    Ok(addresses)
}

#[cfg(test)]
struct PendingResolution {
    entered: tokio::sync::oneshot::Sender<()>,
    resolution: tokio::sync::oneshot::Receiver<Vec<SocketAddr>>,
}

#[cfg(test)]
fn resolution_gates() -> &'static Mutex<BTreeMap<String, PendingResolution>> {
    static GATES: std::sync::OnceLock<Mutex<BTreeMap<String, PendingResolution>>> =
        std::sync::OnceLock::new();
    GATES.get_or_init(Mutex::default)
}

#[cfg(test)]
pub(super) struct ResolutionGate(String);

#[cfg(test)]
impl Drop for ResolutionGate {
    fn drop(&mut self) {
        resolution_gates().lock().unwrap().remove(&self.0);
    }
}

#[cfg(test)]
pub(super) fn hold_resolution(
    host: String,
) -> (
    ResolutionGate,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<Vec<SocketAddr>>,
) {
    let (entered, started) = tokio::sync::oneshot::channel();
    let (complete, resolution) = tokio::sync::oneshot::channel();
    let previous = resolution_gates()
        .lock()
        .unwrap()
        .insert(host.clone(), PendingResolution { entered, resolution });
    assert!(previous.is_none());
    (ResolutionGate(host), started, complete)
}
