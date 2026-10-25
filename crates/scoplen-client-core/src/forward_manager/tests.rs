// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    connection::test_peer::{Authentication, Peer},
    inventory::{Inventory, NewHost, SignIn},
    repository::{
        AccessProfileChange, Credential, CredentialBinding, CredentialChange, CredentialKind, Edit,
        ForwardChange, Host, HostChange, RouteChoice,
    },
};
use scoplen_crypto::{LocalDatabaseKey, SecretVec};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{Notify, mpsc};

mod dynamic;
mod remote;

struct Fixture {
    _directory: tempfile::TempDir,
    store: Arc<Store>,
    profile: String,
    forward: String,
    port: u16,
}

impl Fixture {
    async fn new(ssh_port: u16) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            Store::open(&directory.path().join("fixture.db"), &LocalDatabaseKey::new([41; 32]))
                .unwrap(),
        );
        let inventory = Inventory::new(store.clone());
        let host = inventory
            .add_host(NewHost {
                name: Some("SSH fixture".into()),
                address: "127.0.0.1".into(),
                port: Some(ssh_port),
                username: "trust-fixture".into(),
                sign_in: SignIn::Password { password: "disposable-trust-password".into() },
            })
            .unwrap();
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = local.local_addr().unwrap().port();
        drop(local);
        let profile = host.logins[0].id.clone();
        let forward = Repository::<Forward>::new(&store)
            .create(ForwardChange {
                name: Some("Saved local fixture".into()),
                kind: Some(ForwardKind::Local),
                bind_address: Edit::Set("127.0.0.1".into()),
                bind_port: Edit::Set(port),
                target_host: Edit::Set("target.example".into()),
                target_port: Edit::Set(4242),
                profile: Edit::Set(Uuid::parse_str(&profile).unwrap()),
            })
            .unwrap()
            .meta
            .id
            .to_string();
        Self { _directory: directory, store, profile, forward, port }
    }

    fn start(&self, manager: &ForwardManager) -> ForwardSnapshot {
        let owner = manager.clone();
        let store = self.store.clone();
        manager
            .start(self.store.clone(), &self.forward, &self.profile, move |snapshot| {
                if let Some(PreparationEvent::Trust { prompt_id, .. }) = snapshot.preparation {
                    owner
                        .respond(
                            &store,
                            &snapshot.run_id,
                            &prompt_id,
                            PreparationResponse::AcceptHostKey,
                        )
                        .unwrap();
                }
            })
            .unwrap()
    }
}

async fn phase(
    manager: &ForwardManager,
    fixture: &Fixture,
    id: &str,
    expected: ForwardPhase,
) -> ForwardSnapshot {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = manager.snapshot(&fixture.store, id).unwrap();
            if snapshot.phase == expected {
                return snapshot;
            }
            assert!(
                snapshot.phase.live(),
                "expected {expected:?}, received {:?}: {:?}",
                snapshot.phase,
                snapshot.last_issue,
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("tunnel reached the expected phase")
}

async fn stop(manager: &ForwardManager, fixture: &Fixture, id: &str) {
    manager.stop(&fixture.store, id).unwrap();
    let stopped = phase(manager, fixture, id, ForwardPhase::Stopped).await;
    assert_eq!(stopped.active_connections, 0);
    assert!(stopped.preparation.is_none());
    assert!(stopped.bound_address.is_none());
    let listener = TcpListener::bind(("127.0.0.1", fixture.port)).await.unwrap();
    drop(listener);
}

#[derive(Clone, Copy)]
enum PeerMode {
    Echo,
    Trailer,
    RemoteEofFirst,
    RefuseFirst,
    HoldFirst,
    HoldAll,
}

struct ForwardPeer {
    port: u16,
    opened: Arc<AtomicUsize>,
    sessions: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<(String, u32)>>>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    release: Arc<Notify>,
    control: mpsc::Receiver<russh::server::Handle>,
    workers: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
    task: tokio::task::JoinHandle<()>,
}

struct Handler {
    mode: PeerMode,
    opened: Arc<AtomicUsize>,
    sessions: Arc<AtomicUsize>,
    targets: Arc<Mutex<Vec<(String, u32)>>>,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    release: Arc<Notify>,
    workers: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
}

impl russh::server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        Ok(if username == "trust-fixture" && password == "disposable-trust-password" {
            russh::server::Auth::Accept
        } else {
            russh::server::Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        self.sessions.fetch_add(1, Ordering::SeqCst);
        reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        host: &str,
        port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        let index = self.opened.fetch_add(1, Ordering::SeqCst);
        self.targets.lock().unwrap().push((host.to_owned(), port));
        if matches!(self.mode, PeerMode::RefuseFirst) && index == 0 {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        }
        let held = matches!(self.mode, PeerMode::HoldAll)
            || matches!(self.mode, PeerMode::HoldFirst) && index == 0;
        let release = self.release.clone();
        let mode = self.mode;
        let received = self.received.clone();
        let worker = tokio::spawn(async move {
            if held {
                release.notified().await;
            }
            reply.accept().await;
            let mut stream = channel.into_stream();
            let mut payload = Vec::new();
            let _ = async {
                if matches!(mode, PeerMode::RemoteEofFirst) {
                    stream.write_all(b"remote EOF first").await?;
                    stream.shutdown().await?;
                }
                stream.read_to_end(&mut payload).await?;
                received.lock().unwrap().push(payload.clone());
                if !matches!(mode, PeerMode::RemoteEofFirst) {
                    if matches!(mode, PeerMode::Trailer) {
                        payload.extend_from_slice(b"EOF-only trailer");
                    }
                    stream.write_all(&payload).await?;
                    stream.shutdown().await?;
                }
                Ok::<_, std::io::Error>(())
            }
            .await;
        });
        self.workers.lock().unwrap().push(worker.abort_handle());
        Ok(())
    }
}

impl ForwardPeer {
    async fn new(mode: PeerMode) -> Self {
        let mut config =
            russh::server::Config { auth_rejection_time: Duration::ZERO, ..Default::default() };
        config.keys.push(
            ssh_key::PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                ssh_key::Algorithm::Ed25519,
            )
            .unwrap(),
        );
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let opened = Arc::new(AtomicUsize::new(0));
        let sessions = Arc::new(AtomicUsize::new(0));
        let targets = Arc::new(Mutex::new(Vec::new()));
        let received = Arc::new(Mutex::new(Vec::new()));
        let release = Arc::new(Notify::new());
        let workers: Arc<Mutex<Vec<tokio::task::AbortHandle>>> = Arc::default();
        let (control, receiver) = mpsc::channel(16);
        let handler = Handler {
            mode,
            opened: opened.clone(),
            sessions: sessions.clone(),
            targets: targets.clone(),
            received: received.clone(),
            release: release.clone(),
            workers: workers.clone(),
        };
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let connection = russh::server::run_stream(config, socket, handler).await.unwrap();
            control.send(connection.handle()).await.unwrap();
            let _ = connection.await;
        });
        Self {
            port,
            opened,
            sessions,
            targets,
            received,
            release,
            control: receiver,
            workers,
            task,
        }
    }

    async fn wait_opened(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.opened.load(Ordering::SeqCst) < count {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn disconnect(&mut self) {
        self.control
            .recv()
            .await
            .unwrap()
            .disconnect(russh::Disconnect::ByApplication, String::new(), String::new())
            .await
            .unwrap();
    }
}

impl Drop for ForwardPeer {
    fn drop(&mut self) {
        self.task.abort();
        for worker in self.workers.lock().unwrap().drain(..) {
            worker.abort();
        }
    }
}

async fn exchange(port: u16, payload: &[u8]) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        socket.write_all(payload).await.unwrap();
        // The target responds only after EOF, so this verifies independent half-close handling.
        socket.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        socket.read_to_end(&mut echoed).await.unwrap();
        echoed
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn forward_manager_transfers_parallel_peers_counts_bytes_and_freezes_saved_endpoints() {
    let peer = ForwardPeer::new(PeerMode::Echo).await;
    let fixture = Fixture::new(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    Repository::<Forward>::new(&fixture.store)
        .update(
            Uuid::parse_str(&fixture.forward).unwrap(),
            ForwardChange {
                name: Some("Changed after start".into()),
                target_host: Edit::Set("changed.example".into()),
                target_port: Edit::Set(5252),
                ..Default::default()
            },
        )
        .unwrap();
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let first = vec![17; COPY_BUFFER * 3 + 19];
    let second = vec![43; COPY_BUFFER * 2 + 29];
    let (one, two) = tokio::join!(exchange(fixture.port, &first), exchange(fixture.port, &second));
    assert_eq!(one, first);
    assert_eq!(two, second);
    assert_eq!(peer.sessions.load(Ordering::SeqCst), 0);
    assert_eq!(
        peer.targets.lock().unwrap().as_slice(),
        &[("target.example".into(), 4242), ("target.example".into(), 4242),]
    );
    tokio::time::sleep(PUBLISH_INTERVAL * 2).await;
    let current = manager.snapshot(&fixture.store, &initial.run_id).unwrap();
    assert_eq!(current.configuration, initial.configuration);
    assert_eq!(current.uploaded_bytes, (first.len() + second.len()).to_string());
    assert_eq!(current.downloaded_bytes, current.uploaded_bytes);
    assert_eq!(current.active_connections, 0);
    assert!(current.revision.parse::<u64>().unwrap() > initial.revision.parse::<u64>().unwrap());
    stop(&manager, &fixture, &initial.run_id).await;
}

#[tokio::test]
async fn forward_manager_freezes_login_host_route_and_credential_before_first_owner_poll() {
    let peer = ForwardPeer::new(PeerMode::Echo).await;
    let fixture = Fixture::new(peer.port).await;
    let profile_id = Uuid::parse_str(&fixture.profile).unwrap();
    let profile =
        Repository::<AccessProfile>::new(&fixture.store).get(profile_id).unwrap().unwrap();
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    // This current-thread test does not yield until every saved input has changed.
    Repository::<Host>::new(&fixture.store)
        .update(
            profile.host,
            HostChange {
                name: Some("Changed Host after start".into()),
                address: Some("127.0.0.2".into()),
                port: Edit::Set(9),
                ..Default::default()
            },
        )
        .unwrap();
    Repository::<AccessProfile>::new(&fixture.store)
        .update(
            profile_id,
            AccessProfileChange {
                name: Edit::Set("Changed Login after start".into()),
                username: Some("changed-after-start".into()),
                route: Some(RouteChoice::Route(Uuid::now_v7())),
                ..Default::default()
            },
        )
        .unwrap();
    Repository::<Credential>::new(&fixture.store)
        .update(
            profile.credential.unwrap(),
            CredentialChange {
                secret: Edit::Set(SecretVec::new(b"changed-after-start".to_vec())),
                ..Default::default()
            },
        )
        .unwrap();
    let listening = phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    assert_eq!(listening.configuration.login(), initial.configuration.login());
    assert_eq!(listening.configuration.login().profile_id, fixture.profile);
    assert_eq!(listening.configuration.login().host_id, profile.host.to_string());
    assert_eq!(listening.configuration.login().login, "trust-fixture");
    assert_eq!(listening.configuration.login().host, "SSH fixture");
    assert_eq!(listening.configuration.login().username, "trust-fixture");
    assert_eq!(listening.configuration.login().address, "127.0.0.1");
    assert_eq!(listening.configuration.login().port, peer.port);
    assert_eq!(exchange(fixture.port, b"fixed login").await, b"fixed login");
    assert_eq!(peer.sessions.load(Ordering::SeqCst), 0);
    stop(&manager, &fixture, &initial.run_id).await;
    assert_eq!(
        manager.start(fixture.store.clone(), &fixture.forward, &fixture.profile, |_| {}).err(),
        Some(ForwardIssue::PreparationFailed)
    );
}

#[tokio::test]
async fn forward_manager_coalesces_short_peer_traffic_and_retains_final_counts_without_observer() {
    let peer = ForwardPeer::new(PeerMode::Echo).await;
    let fixture = Fixture::new(peer.port).await;
    let manager = ForwardManager::default();
    let owner = manager.clone();
    let store = fixture.store.clone();
    let events = Arc::new(Mutex::new(Some(Vec::new())));
    let observed = events.clone();
    let initial = manager
        .start(fixture.store.clone(), &fixture.forward, &fixture.profile, move |snapshot| {
            if let Some(events) = observed.lock().unwrap().as_mut() {
                events.push((tokio::time::Instant::now(), snapshot.clone()));
            }
            if let Some(PreparationEvent::Trust { prompt_id, .. }) = snapshot.preparation {
                owner
                    .respond(
                        &store,
                        &snapshot.run_id,
                        &prompt_id,
                        PreparationResponse::AcceptHostKey,
                    )
                    .unwrap();
            }
        })
        .unwrap();
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    for _ in 0..12 {
        assert_eq!(exchange(fixture.port, b"short peer").await, b"short peer");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    tokio::time::sleep(PUBLISH_INTERVAL * 2).await;
    let recorded = events.lock().unwrap().take().unwrap();
    let traffic: Vec<_> = recorded
        .iter()
        .filter(|(_, snapshot)| {
            snapshot.phase == ForwardPhase::Listening && snapshot.uploaded_bytes != "0"
        })
        .collect();
    assert!(!traffic.is_empty());
    for pair in traffic.windows(2) {
        assert!(pair[1].0.duration_since(pair[0].0) >= PUBLISH_INTERVAL);
    }
    // Detaching the display does not affect the independent listener or retained state.
    assert_eq!(exchange(fixture.port, b"detached").await, b"detached");
    stop(&manager, &fixture, &initial.run_id).await;
    let final_snapshot = manager.snapshot(&fixture.store, &initial.run_id).unwrap();
    assert_eq!(
        final_snapshot.uploaded_bytes,
        (12 * b"short peer".len() + b"detached".len()).to_string()
    );
    assert_eq!(final_snapshot.downloaded_bytes, final_snapshot.uploaded_bytes);
}

#[tokio::test]
async fn forward_manager_terminal_snapshot_releases_an_observer_that_captured_its_owner() {
    let peer = ForwardPeer::new(PeerMode::Echo).await;
    let fixture = Fixture::new(peer.port).await;
    let retained = Arc::downgrade(&fixture.store);
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    stop(&manager, &fixture, &initial.run_id).await;
    assert_eq!(manager.list(&fixture.store).unwrap().len(), 1);
    drop(manager);
    drop(fixture);
    assert!(retained.upgrade().is_none());
}

#[tokio::test]
async fn forward_manager_stop_all_releases_store_while_retaining_terminal_identity() {
    let peer = ForwardPeer::new(PeerMode::Echo).await;
    let fixture = Fixture::new(peer.port).await;
    let retained = Arc::downgrade(&fixture.store);
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    manager.stop_all().await.unwrap();
    assert_eq!(manager.list(&fixture.store).unwrap().len(), 1);
    assert_eq!(
        manager.snapshot(&fixture.store, &initial.run_id).unwrap().phase,
        ForwardPhase::Stopped
    );
    drop(fixture);
    assert!(retained.upgrade().is_none());
    let replacement = Fixture::new(9).await;
    assert!(manager.list(&replacement.store).unwrap().is_empty());
    let newer = manager
        .start(replacement.store.clone(), &replacement.forward, &replacement.profile, |_| {})
        .unwrap();
    manager.stop_all().await.unwrap();
    assert_eq!(
        manager.snapshot(&replacement.store, &newer.run_id).unwrap().phase,
        ForwardPhase::Stopped
    );
    assert_eq!(manager.snapshot(&replacement.store, &initial.run_id), Err(ForwardIssue::Expired));
}

#[tokio::test]
async fn forward_manager_pending_opener_does_not_serialize_other_peers() {
    let peer = ForwardPeer::new(PeerMode::HoldFirst).await;
    let fixture = Fixture::new(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let mut held = TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap();
    held.write_all(b"held").await.unwrap();
    held.shutdown().await.unwrap();
    peer.wait_opened(1).await;
    assert_eq!(exchange(fixture.port, b"independent").await, b"independent");
    peer.release.notify_one();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), held.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, b"held");
    stop(&manager, &fixture, &initial.run_id).await;
}

#[tokio::test]
async fn forward_manager_target_refusal_preserves_listener_and_later_peer() {
    let peer = ForwardPeer::new(PeerMode::RefuseFirst).await;
    let fixture = Fixture::new(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let mut socket = TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), socket.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(exchange(fixture.port, b"after refusal").await, b"after refusal");
    tokio::time::sleep(PUBLISH_INTERVAL * 2).await;
    let snapshot = manager.snapshot(&fixture.store, &initial.run_id).unwrap();
    assert_eq!(snapshot.phase, ForwardPhase::Listening);
    assert_eq!(snapshot.rejected_connections, "1");
    assert_eq!(snapshot.last_issue, Some(ForwardIssue::TargetRejected));
    stop(&manager, &fixture, &initial.run_id).await;
}

#[tokio::test]
async fn forward_manager_capacity_includes_openers_and_stop_releases_every_peer() {
    let peer = ForwardPeer::new(PeerMode::HoldAll).await;
    let fixture = Fixture::new(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let mut sockets = Vec::new();
    for _ in 0..MAX_FORWARD_PEERS {
        sockets.push(TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap());
    }
    peer.wait_opened(MAX_FORWARD_PEERS).await;
    let mut excess = TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), excess.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(peer.opened.load(Ordering::SeqCst), MAX_FORWARD_PEERS);
    stop(&manager, &fixture, &initial.run_id).await;
    for mut socket in sockets {
        assert_eq!(socket.read(&mut [0]).await.unwrap(), 0);
    }
    let snapshot = manager.snapshot(&fixture.store, &initial.run_id).unwrap();
    assert_eq!(snapshot.rejected_connections, "1");
    assert_eq!(snapshot.active_connections, 0);
}

#[tokio::test]
async fn forward_manager_idle_ssh_disconnect_releases_listener_without_shell_or_reconnect() {
    let mut peer = ForwardPeer::new(PeerMode::Echo).await;
    let fixture = Fixture::new(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    peer.disconnect().await;
    let failed = phase(&manager, &fixture, &initial.run_id, ForwardPhase::Failed).await;
    assert_eq!(failed.last_issue, Some(ForwardIssue::ConnectionLost));
    assert_eq!(failed.active_connections, 0);
    assert_eq!(peer.opened.load(Ordering::SeqCst), 0);
    assert_eq!(peer.sessions.load(Ordering::SeqCst), 0);
    TcpListener::bind(("127.0.0.1", fixture.port)).await.unwrap();
}

#[tokio::test]
async fn forward_manager_ssh_disconnect_closes_active_local_peers() {
    let mut peer = ForwardPeer::new(PeerMode::Echo).await;
    let fixture = Fixture::new(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let mut socket = TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap();
    peer.wait_opened(1).await;
    peer.disconnect().await;
    let failed = phase(&manager, &fixture, &initial.run_id, ForwardPhase::Failed).await;
    assert_eq!(failed.last_issue, Some(ForwardIssue::ConnectionLost));
    assert_eq!(failed.active_connections, 0);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), socket.read(&mut [0])).await.unwrap().unwrap(),
        0
    );
}

#[tokio::test]
async fn forward_manager_channel_open_timeout_releases_slot_and_does_not_retry() {
    let peer = ForwardPeer::new(PeerMode::HoldFirst).await;
    let fixture = Fixture::new(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let mut socket = TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap();
    peer.wait_opened(1).await;
    assert_eq!(
        tokio::time::timeout(OPEN_TIMEOUT + Duration::from_secs(2), socket.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(exchange(fixture.port, b"after open timeout").await, b"after open timeout");
    tokio::time::sleep(PUBLISH_INTERVAL * 2).await;
    let snapshot = manager.snapshot(&fixture.store, &initial.run_id).unwrap();
    assert_eq!(snapshot.phase, ForwardPhase::Listening);
    assert_eq!(snapshot.active_connections, 0);
    assert_eq!(snapshot.rejected_connections, "1");
    assert_eq!(snapshot.last_issue, Some(ForwardIssue::TargetTimedOut));
    assert_eq!(peer.opened.load(Ordering::SeqCst), 2);
    stop(&manager, &fixture, &initial.run_id).await;
}

#[tokio::test]
async fn forward_manager_trust_cancel_fences_store_run_and_late_prompt() {
    let peer = Peer::start().await;
    let fixture = Fixture::new(peer.port).await;
    let other = Fixture::new(peer.port).await;
    let manager = ForwardManager::default();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let initial = manager
        .start(fixture.store.clone(), &fixture.forward, &fixture.profile, move |s| {
            tx.send(s).unwrap();
        })
        .unwrap();
    let prompt = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let snapshot = rx.recv().await.unwrap();
            if let Some(PreparationEvent::Trust { prompt_id, .. }) = snapshot.preparation {
                break prompt_id;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(peer.authentications.load(Ordering::SeqCst), 0);
    assert!(manager.list(&other.store).unwrap().is_empty());
    assert_eq!(manager.stop(&other.store, &initial.run_id), Err(ForwardIssue::Expired));
    assert_eq!(
        manager.respond(
            &fixture.store,
            &initial.run_id,
            "wrong",
            PreparationResponse::AcceptHostKey
        ),
        Err(ForwardIssue::Expired)
    );
    stop(&manager, &fixture, &initial.run_id).await;
    assert_eq!(
        manager.respond(
            &fixture.store,
            &initial.run_id,
            &prompt,
            PreparationResponse::AcceptHostKey
        ),
        Err(ForwardIssue::Expired)
    );
    assert_eq!(peer.authentications.load(Ordering::SeqCst), 0);
    assert_eq!(peer.session_channels.load(Ordering::SeqCst), 0);
    let newer = fixture.start(&manager);
    assert_ne!(initial.run_id, newer.run_id);
    phase(&manager, &fixture, &newer.run_id, ForwardPhase::Listening).await;
    assert_eq!(
        manager.respond(
            &fixture.store,
            &initial.run_id,
            &prompt,
            PreparationResponse::AcceptHostKey
        ),
        Err(ForwardIssue::Expired)
    );
    stop(&manager, &fixture, &newer.run_id).await;
}

#[tokio::test]
async fn forward_manager_reuses_private_key_passphrase_and_interactive_prompts() {
    let peer = Peer::with_authentication(Authentication::KeyThenInteractive).await;
    let fixture = Fixture::new(peer.port).await;
    let profile = Repository::<AccessProfile>::new(&fixture.store)
        .get(Uuid::parse_str(&fixture.profile).unwrap())
        .unwrap()
        .unwrap();
    let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
    let private = ssh_key::PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519)
        .unwrap()
        .encrypt(&mut rng, b"disposable-passphrase")
        .unwrap();
    Repository::<Credential>::new(&fixture.store)
        .update(
            profile.credential.unwrap(),
            CredentialChange {
                kind: Some(CredentialKind::PrivateKey),
                binding: Some(CredentialBinding::Shared),
                secret: Edit::Set(SecretVec::new(
                    private.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes().to_vec(),
                )),
                ..Default::default()
            },
        )
        .unwrap();
    let manager = ForwardManager::default();
    let owner = manager.clone();
    let store = fixture.store.clone();
    let rounds = Arc::new(AtomicUsize::new(0));
    let answers = rounds.clone();
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = events.clone();
    let initial = manager
        .start(fixture.store.clone(), &fixture.forward, &fixture.profile, move |snapshot| {
            observed.lock().unwrap().push(snapshot.clone());
            let response = match snapshot.preparation {
                Some(PreparationEvent::Trust { prompt_id, .. }) => {
                    Some((prompt_id, PreparationResponse::AcceptHostKey))
                }
                Some(PreparationEvent::Passphrase { prompt_id, .. }) => Some((
                    prompt_id,
                    PreparationResponse::Passphrase(SecretVec::new(
                        b"disposable-passphrase".to_vec(),
                    )),
                )),
                Some(PreparationEvent::KeyboardInteractive { prompt_id, prompts, .. }) => {
                    let values = match answers.fetch_add(1, Ordering::SeqCst) {
                        0 => vec![b"visible".to_vec(), vec![]],
                        1 => vec![],
                        _ => vec![b"123456".to_vec()],
                    };
                    assert_eq!(prompts.len(), values.len());
                    Some((prompt_id, PreparationResponse::keyboard_interactive(values).unwrap()))
                }
                _ => None,
            };
            if let Some((prompt, response)) = response {
                owner.respond(&store, &snapshot.run_id, &prompt, response).unwrap();
            }
        })
        .unwrap();
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    assert_eq!(rounds.load(Ordering::SeqCst), 3);
    assert_eq!(peer.session_channels.load(Ordering::SeqCst), 0);
    let serialized = serde_json::to_string(&*events.lock().unwrap()).unwrap();
    assert!(!serialized.contains("disposable-passphrase"));
    assert!(!serialized.contains("123456"));
    stop(&manager, &fixture, &initial.run_id).await;
}

#[tokio::test]
async fn forward_manager_validates_before_network_and_admits_only_one_run_per_definition() {
    let fixture = Fixture::new(9).await;
    let manager = ForwardManager::default();
    let id = Uuid::parse_str(&fixture.forward).unwrap();
    let base = Repository::<Forward>::new(&fixture.store).get(id).unwrap().unwrap();
    for invalid in ["localhost", "127.0.0.1 ", "", "[::1]"] {
        Repository::<Forward>::new(&fixture.store)
            .update(
                id,
                ForwardChange { bind_address: Edit::Set(invalid.into()), ..Default::default() },
            )
            .unwrap();
        assert_eq!(
            manager.start(fixture.store.clone(), &fixture.forward, &fixture.profile, |_| {}).err(),
            Some(ForwardIssue::InvalidConfiguration)
        );
    }
    Repository::<Forward>::new(&fixture.store)
        .update(
            id,
            ForwardChange {
                bind_address: Edit::Set(base.bind_address.unwrap()),
                bind_port: Edit::Set(0),
                kind: Some(ForwardKind::Remote),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        manager.start(fixture.store.clone(), &fixture.forward, &fixture.profile, |_| {}).err(),
        Some(ForwardIssue::InvalidConfiguration)
    );
    Repository::<Forward>::new(&fixture.store)
        .update(
            id,
            ForwardChange {
                kind: Some(ForwardKind::Local),
                bind_port: Edit::Set(fixture.port),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        manager
            .start(fixture.store.clone(), &fixture.forward, &Uuid::now_v7().to_string(), |_| {})
            .err(),
        Some(ForwardIssue::NotFound)
    );
    let initial = fixture.start(&manager);
    assert_eq!(
        manager.start(fixture.store.clone(), &fixture.forward, &fixture.profile, |_| {}).err(),
        Some(ForwardIssue::AlreadyRunning)
    );
    manager.stop_all().await.unwrap();
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Stopped).await;
    assert_eq!(manager.snapshot(&fixture.store, &initial.run_id).unwrap().active_connections, 0);
}

#[tokio::test]
async fn forward_manager_limits_live_and_completed_records_without_starting_cancelled_preparations()
{
    let fixture = Fixture::new(9).await;
    let manager = ForwardManager::default();
    let mut ids = Vec::new();
    for n in 0..=MAX_RUNNING_FORWARDS {
        let forward = Repository::<Forward>::new(&fixture.store)
            .create(ForwardChange {
                name: Some(format!("fixture {n}")),
                kind: Some(if n % 2 == 0 { ForwardKind::Local } else { ForwardKind::Dynamic }),
                bind_address: Edit::Set("127.0.0.1".into()),
                bind_port: Edit::Set(fixture.port),
                target_host: Edit::Set("target.example".into()),
                target_port: Edit::Set(4242),
                ..Default::default()
            })
            .unwrap()
            .meta
            .id
            .to_string();
        let result = manager.start(fixture.store.clone(), &forward, &fixture.profile, |_| {});
        if n == MAX_RUNNING_FORWARDS {
            assert_eq!(result.err(), Some(ForwardIssue::CapacityReached));
        } else {
            ids.push(result.unwrap().run_id);
        }
    }
    manager.stop_all().await.unwrap();
    for id in ids {
        phase(&manager, &fixture, &id, ForwardPhase::Stopped).await;
    }
    for _ in 0..MAX_COMPLETED_FORWARDS {
        let initial = fixture.start(&manager);
        manager.stop(&fixture.store, &initial.run_id).unwrap();
        phase(&manager, &fixture, &initial.run_id, ForwardPhase::Stopped).await;
    }
    let retained = manager.list(&fixture.store).unwrap();
    assert_eq!(retained.len(), MAX_COMPLETED_FORWARDS);
    assert!(retained.iter().all(|s| s.phase == ForwardPhase::Stopped));
}

#[tokio::test]
async fn forward_manager_occupied_bind_fails_and_preserves_the_other_listener() {
    let peer = Peer::start().await;
    let fixture = Fixture::new(peer.port).await;
    let existing = TcpListener::bind(("127.0.0.1", fixture.port)).await.unwrap();
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    let failed = phase(&manager, &fixture, &initial.run_id, ForwardPhase::Failed).await;
    assert_eq!(failed.last_issue, Some(ForwardIssue::ListenFailed));
    assert_eq!(failed.active_connections, 0);
    assert_eq!(existing.local_addr().unwrap().port(), fixture.port);
    assert_eq!(peer.session_channels.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn forward_manager_shutdown_permanently_fences_new_registration_before_drain() {
    let fixture = Fixture::new(9).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    manager.shutdown().unwrap();
    assert_eq!(
        manager.start(fixture.store.clone(), &fixture.forward, &fixture.profile, |_| {}).err(),
        Some(ForwardIssue::Unavailable)
    );
    manager.stop_all().await.unwrap();
    assert_eq!(
        manager.snapshot(&fixture.store, &initial.run_id).unwrap().phase,
        ForwardPhase::Stopped
    );
    assert_eq!(
        manager.start(fixture.store.clone(), &fixture.forward, &fixture.profile, |_| {}).err(),
        Some(ForwardIssue::Unavailable)
    );
}

#[tokio::test]
async fn forward_manager_poisoned_shutdown_still_fences_and_cancels_every_owner() {
    let fixture = Fixture::new(9).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    let run = manager.run(&fixture.store, &initial.run_id).unwrap();
    let registry = manager.registry.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = registry.lock().unwrap();
            panic!("injected unavailable registry");
        })
        .join()
        .is_err()
    );
    assert_eq!(manager.shutdown(), Err(ForwardIssue::Unavailable));
    assert!(*run.stop.borrow());
    assert!(run.control.is_cancelled());
    assert_eq!(
        manager.start(fixture.store.clone(), &fixture.forward, &fixture.profile, |_| {}).err(),
        Some(ForwardIssue::Unavailable)
    );
    assert_eq!(manager.stop_all().await, Err(ForwardIssue::Unavailable));
    assert!(*run.finished.borrow());
    assert_eq!(run.snapshot().unwrap().phase, ForwardPhase::Stopped);
}
