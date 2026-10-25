// SPDX-License-Identifier: Apache-2.0

use super::*;
use tokio::sync::Barrier;

#[derive(Clone, Copy)]
enum Decision {
    Accept,
    Deny,
    Hold,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Request {
    Listen(String, u32),
    Cancel(String, u32),
}

struct RemotePeer {
    port: u16,
    requests: mpsc::UnboundedReceiver<Request>,
    controls: mpsc::UnboundedReceiver<russh::server::Handle>,
    release: Arc<Notify>,
    sessions: Arc<AtomicUsize>,
    closed: watch::Receiver<bool>,
    task: tokio::task::JoinHandle<()>,
}

struct RemoteHandler {
    listen: Decision,
    cancel: Decision,
    requests: mpsc::UnboundedSender<Request>,
    release: Arc<Notify>,
    sessions: Arc<AtomicUsize>,
}

impl russh::server::Handler for RemoteHandler {
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

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        self.requests.send(Request::Listen(address.into(), *port)).unwrap();
        if matches!(self.listen, Decision::Hold) {
            self.release.notified().await;
        }
        Ok(!matches!(self.listen, Decision::Deny))
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        self.requests.send(Request::Cancel(address.into(), port)).unwrap();
        if matches!(self.cancel, Decision::Hold) {
            self.release.notified().await;
        }
        Ok(!matches!(self.cancel, Decision::Deny))
    }
}

impl RemotePeer {
    async fn new(listen: Decision, cancel: Decision) -> Self {
        let mut config =
            russh::server::Config { auth_rejection_time: Duration::ZERO, ..Default::default() };
        config.keys.push(
            ssh_key::PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                ssh_key::Algorithm::Ed25519,
            )
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (requests, receiver) = mpsc::unbounded_channel();
        let (controls, controls_receiver) = mpsc::unbounded_channel();
        let release = Arc::new(Notify::new());
        let sessions = Arc::new(AtomicUsize::new(0));
        let handler = RemoteHandler {
            listen,
            cancel,
            requests,
            release: release.clone(),
            sessions: sessions.clone(),
        };
        let (closed, closed_receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let connection =
                russh::server::run_stream(Arc::new(config), socket, handler).await.unwrap();
            controls.send(connection.handle()).unwrap();
            let _ = connection.await;
            closed.send_replace(true);
        });
        Self {
            port,
            requests: receiver,
            controls: controls_receiver,
            release,
            sessions,
            closed: closed_receiver,
            task,
        }
    }

    async fn request(&mut self) -> Request {
        tokio::time::timeout(Duration::from_secs(10), self.requests.recv()).await.unwrap().unwrap()
    }

    async fn control(&mut self) -> russh::server::Handle {
        tokio::time::timeout(Duration::from_secs(10), self.controls.recv()).await.unwrap().unwrap()
    }

    async fn wait_closed(&mut self) {
        tokio::time::timeout(Duration::from_secs(5), self.closed.wait_for(|closed| *closed))
            .await
            .unwrap()
            .unwrap();
    }
}

impl Drop for RemotePeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn fixture(ssh_port: u16, target: SocketAddr) -> Fixture {
    let fixture = Fixture::new(ssh_port).await;
    Repository::<Forward>::new(&fixture.store)
        .update(
            Uuid::parse_str(&fixture.forward).unwrap(),
            ForwardChange {
                name: Some("Saved remote fixture".into()),
                kind: Some(ForwardKind::Remote),
                target_host: Edit::Set(target.ip().to_string()),
                target_port: Edit::Set(target.port()),
                ..Default::default()
            },
        )
        .unwrap();
    fixture
}

async fn snapshot_when(
    manager: &ForwardManager,
    fixture: &Fixture,
    id: &str,
    condition: impl Fn(&ForwardSnapshot) -> bool,
) -> ForwardSnapshot {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let snapshot = manager.snapshot(&fixture.store, id).unwrap();
            if condition(&snapshot) {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("remote tunnel reached the expected state")
}

async fn forwarded(
    control: &russh::server::Handle,
    fixture: &Fixture,
) -> russh::Channel<russh::server::Msg> {
    tokio::time::timeout(
        Duration::from_secs(5),
        control.channel_open_forwarded_tcpip(
            "127.0.0.1",
            u32::from(fixture.port),
            "untrusted-origin.invalid",
            65535,
        ),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn closed(channel: russh::Channel<russh::server::Msg>) {
    let mut stream = channel.into_stream();
    let result = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut [0])).await.unwrap();
    assert!(matches!(result, Ok(0) | Err(_)), "rejected channel produced data");
}

#[tokio::test]
async fn remote_fixed_port_ack_preserves_snapshot_and_parallel_binary_half_close_counts() {
    let mut peer = RemotePeer::new(Decision::Accept, Decision::Accept).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = fixture(peer.port, target.local_addr().unwrap()).await;
    Repository::<Forward>::new(&fixture.store)
        .update(
            Uuid::parse_str(&fixture.forward).unwrap(),
            ForwardChange { target_host: Edit::Set("localhost".into()), ..Default::default() },
        )
        .unwrap();
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    let listening = phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    assert!(listening.bound_address.is_none());
    assert!(matches!(listening.configuration, ForwardConfiguration::Remote { bind_port, .. }
        if bind_port == fixture.port));
    assert_eq!(peer.request().await, Request::Listen("127.0.0.1".into(), fixture.port.into()));
    let local_guard = TcpListener::bind(("127.0.0.1", fixture.port)).await.unwrap();
    let control = peer.control().await;
    Repository::<Forward>::new(&fixture.store)
        .update(
            Uuid::parse_str(&fixture.forward).unwrap(),
            ForwardChange {
                name: Some("edited".into()),
                kind: Some(ForwardKind::Dynamic),
                target_host: Edit::Set("wrong.invalid".into()),
                target_port: Edit::Set(9),
                ..Default::default()
            },
        )
        .unwrap();
    Inventory::new(fixture.store.clone()).delete_forward(fixture.forward.clone()).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let (prefixes, mut received) = mpsc::unbounded_channel();
    let mut targets = JoinSet::new();
    let listener_task = tokio::spawn({
        let barrier = barrier.clone();
        async move {
            for _ in 0..2 {
                let (mut socket, _) = target.accept().await.unwrap();
                let barrier = barrier.clone();
                let prefixes = prefixes.clone();
                targets.spawn(async move {
                    let mut prefix = [0; 4];
                    socket.read_exact(&mut prefix).await.unwrap();
                    prefixes.send(prefix).unwrap();
                    barrier.wait().await;
                    let mut payload = prefix.to_vec();
                    socket.read_to_end(&mut payload).await.unwrap();
                    let mut response = payload.clone();
                    response.reverse();
                    response.extend_from_slice(b"EOF-only trailer");
                    socket.write_all(&response).await.unwrap();
                    socket.shutdown().await.unwrap();
                });
            }
            while let Some(result) = targets.join_next().await {
                result.unwrap();
            }
        }
    });
    let payloads = [vec![0, 255, 1, 128, 42, 0, 90], (0..=255).cycle().take(65539).collect()];
    let mut remotes = JoinSet::new();
    for payload in payloads.clone() {
        let channel = forwarded(&control, &fixture).await;
        remotes.spawn(async move {
            let mut stream = channel.into_stream();
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            let mut expected = payload;
            expected.reverse();
            expected.extend_from_slice(b"EOF-only trailer");
            assert_eq!(response, expected);
        });
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        received.recv().await.unwrap();
        received.recv().await.unwrap();
        barrier.wait().await;
        while let Some(result) = remotes.join_next().await {
            result.unwrap();
        }
        listener_task.await.unwrap();
    })
    .await
    .unwrap();
    let downloaded: usize = payloads.iter().map(Vec::len).sum();
    let uploaded = downloaded + 2 * b"EOF-only trailer".len();
    let snapshot = snapshot_when(&manager, &fixture, &initial.run_id, |snapshot| {
        snapshot.active_connections == 0 && snapshot.uploaded_bytes == uploaded.to_string()
    })
    .await;
    assert_eq!(snapshot.configuration, initial.configuration);
    assert_eq!(snapshot.downloaded_bytes, downloaded.to_string());
    assert_eq!(snapshot.rejected_connections, "0");
    assert_eq!(peer.sessions.load(Ordering::SeqCst), 0);
    drop(local_guard);
    stop(&manager, &fixture, &initial.run_id).await;
    assert_eq!(peer.request().await, Request::Cancel("127.0.0.1".into(), fixture.port.into()));
    peer.wait_closed().await;
    let stopped = manager.snapshot(&fixture.store, &initial.run_id).unwrap();
    assert_eq!(stopped.uploaded_bytes, uploaded.to_string());
    assert_eq!(stopped.downloaded_bytes, downloaded.to_string());
}

#[tokio::test]
async fn remote_local_target_half_close_does_not_discard_later_ssh_input() {
    let mut peer = RemotePeer::new(Decision::Accept, Decision::Accept).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = fixture(peer.port, target.local_addr().unwrap()).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let control = peer.control().await;
    let service = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        socket.write_all(b"local EOF first\0\xff").await.unwrap();
        socket.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        socket.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"SSH input after local EOF\0\x80");
    });
    let mut stream = forwarded(&control, &fixture).await.into_stream();
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"local EOF first\0\xff");
        stream.write_all(b"SSH input after local EOF\0\x80").await.unwrap();
        stream.shutdown().await.unwrap();
        service.await.unwrap();
    })
    .await
    .unwrap();
    snapshot_when(&manager, &fixture, &initial.run_id, |snapshot| {
        snapshot.active_connections == 0
            && snapshot.downloaded_bytes == b"SSH input after local EOF\0\x80".len().to_string()
    })
    .await;
    stop(&manager, &fixture, &initial.run_id).await;
}

#[tokio::test]
async fn remote_exact_metadata_fences_local_dials_and_later_valid_peer_remains_usable() {
    let mut peer = RemotePeer::new(Decision::Accept, Decision::Accept).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let trap = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = fixture(peer.port, target.local_addr().unwrap()).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let control = peer.control().await;
    for (address, port) in [
        ("localhost", u32::from(fixture.port)),
        ("0.0.0.0", u32::from(fixture.port)),
        ("127.0.0.1", u32::from(fixture.port) + 1),
    ] {
        let channel = control
            .channel_open_forwarded_tcpip(
                address,
                port,
                "127.0.0.1",
                trap.local_addr().unwrap().port().into(),
            )
            .await
            .unwrap();
        closed(channel).await;
    }
    closed(control.channel_open_forwarded_streamlocal("/fixture/unsupported.sock").await.unwrap())
        .await;
    assert!(control.channel_open_agent().await.is_err());
    assert!(tokio::time::timeout(Duration::from_millis(100), target.accept()).await.is_err());
    assert!(tokio::time::timeout(Duration::from_millis(100), trap.accept()).await.is_err());
    let snapshot = snapshot_when(&manager, &fixture, &initial.run_id, |snapshot| {
        snapshot.rejected_connections == "4"
    })
    .await;
    assert_eq!(snapshot.active_connections, 0);
    assert_eq!(snapshot.last_issue, Some(ForwardIssue::PeerRejected));
    let mut channel = control
        .channel_open_forwarded_tcpip(
            "127.0.0.1",
            fixture.port.into(),
            "127.0.0.1",
            trap.local_addr().unwrap().port().into(),
        )
        .await
        .unwrap()
        .into_stream();
    let (mut socket, _) =
        tokio::time::timeout(Duration::from_secs(5), target.accept()).await.unwrap().unwrap();
    channel.write_all(b"fixed target").await.unwrap();
    let mut bytes = [0; 12];
    tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"fixed target");
    assert!(tokio::time::timeout(Duration::from_millis(100), trap.accept()).await.is_err());
    stop(&manager, &fixture, &initial.run_id).await;
    assert_eq!(
        manager.snapshot(&fixture.store, &initial.run_id).unwrap().rejected_connections,
        "4"
    );
}

#[tokio::test]
async fn remote_refused_local_target_releases_peer_and_later_connection_recovers() {
    let mut peer = RemotePeer::new(Decision::Accept, Decision::Accept).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let fixture = fixture(peer.port, address).await;
    drop(target);
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let control = peer.control().await;
    closed(forwarded(&control, &fixture).await).await;
    let failed = snapshot_when(&manager, &fixture, &initial.run_id, |snapshot| {
        snapshot.active_connections == 0 && snapshot.rejected_connections == "1"
    })
    .await;
    assert_eq!(failed.phase, ForwardPhase::Listening);
    assert_eq!(failed.last_issue, Some(ForwardIssue::TargetRejected));
    let target = TcpListener::bind(address).await.unwrap();
    let mut stream = forwarded(&control, &fixture).await.into_stream();
    let (mut socket, _) = target.accept().await.unwrap();
    socket.write_all(b"recovered").await.unwrap();
    let mut bytes = [0; 9];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"recovered");
    stop(&manager, &fixture, &initial.run_id).await;
    assert_eq!(
        manager.snapshot(&fixture.store, &initial.run_id).unwrap().rejected_connections,
        "1"
    );
}

#[tokio::test]
async fn remote_capacity_closes_only_excess_delivered_peer_and_stop_does_not_reject() {
    let mut peer = RemotePeer::new(Decision::Accept, Decision::Accept).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = fixture(peer.port, target.local_addr().unwrap()).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let control = peer.control().await;
    let mut channels = Vec::new();
    let mut sockets = Vec::new();
    for _ in 0..MAX_FORWARD_PEERS {
        channels.push(forwarded(&control, &fixture).await);
        sockets.push(target.accept().await.unwrap().0);
    }
    snapshot_when(&manager, &fixture, &initial.run_id, |snapshot| {
        snapshot.active_connections == MAX_FORWARD_PEERS as u32
    })
    .await;
    closed(forwarded(&control, &fixture).await).await;
    assert!(tokio::time::timeout(Duration::from_millis(100), target.accept()).await.is_err());
    manager.stop_all().await.unwrap();
    let stopped = manager.snapshot(&fixture.store, &initial.run_id).unwrap();
    assert_eq!(stopped.phase, ForwardPhase::Stopped);
    assert_eq!(stopped.active_connections, 0);
    assert_eq!(stopped.rejected_connections, "1");
    assert_eq!(stopped.last_issue, Some(ForwardIssue::PeerLimitReached));
    assert_eq!(stopped.uploaded_bytes, "0");
    assert_eq!(stopped.downloaded_bytes, "0");
    for channel in channels {
        closed(channel).await;
    }
    for mut socket in sockets {
        assert_eq!(socket.read(&mut [0]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn remote_denied_registration_closes_transport_without_retry_or_cancel() {
    let mut peer = RemotePeer::new(Decision::Deny, Decision::Accept).await;
    let fixture = fixture(peer.port, "127.0.0.1:9".parse().unwrap()).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    assert_eq!(peer.request().await, Request::Listen("127.0.0.1".into(), fixture.port.into()));
    let failed = phase(&manager, &fixture, &initial.run_id, ForwardPhase::Failed).await;
    assert_eq!(failed.last_issue, Some(ForwardIssue::ShutdownFailed));
    assert!(failed.bound_address.is_none());
    assert_eq!(failed.rejected_connections, "0");
    peer.wait_closed().await;
    assert!(peer.requests.try_recv().is_err());
    assert_eq!(peer.sessions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn remote_stop_during_unknown_registration_fences_and_closes_without_retry() {
    let mut peer = RemotePeer::new(Decision::Hold, Decision::Accept).await;
    let fixture = fixture(peer.port, "127.0.0.1:9".parse().unwrap()).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    let _ = peer.request().await;
    manager.stop(&fixture.store, &initial.run_id).unwrap();
    let failed = phase(&manager, &fixture, &initial.run_id, ForwardPhase::Failed).await;
    assert_eq!(failed.last_issue, Some(ForwardIssue::ShutdownFailed));
    assert_eq!(failed.active_connections, 0);
    assert_eq!(failed.rejected_connections, "0");
    peer.release.notify_one();
    peer.wait_closed().await;
    assert!(peer.requests.try_recv().is_err());
}

#[tokio::test]
async fn remote_registration_absolute_timeout_never_claims_listener_or_cleanup_confirmation() {
    let mut peer = RemotePeer::new(Decision::Hold, Decision::Accept).await;
    let fixture = fixture(peer.port, "127.0.0.1:9".parse().unwrap()).await;
    let manager = ForwardManager::default();
    let (events, mut receiver) = mpsc::unbounded_channel();
    let owner = manager.clone();
    let store = fixture.store.clone();
    let initial = manager
        .start(store.clone(), &fixture.forward, &fixture.profile, move |snapshot| {
            if let Some(PreparationEvent::Trust { prompt_id, .. }) = &snapshot.preparation {
                owner
                    .respond(
                        &store,
                        &snapshot.run_id,
                        prompt_id,
                        PreparationResponse::AcceptHostKey,
                    )
                    .unwrap();
            }
            events.send(snapshot).unwrap();
        })
        .unwrap();
    let _ = peer.request().await;
    let started = tokio::time::Instant::now();
    let failed = phase(&manager, &fixture, &initial.run_id, ForwardPhase::Failed).await;
    assert!(started.elapsed() >= OPEN_TIMEOUT - Duration::from_millis(250));
    assert_eq!(failed.last_issue, Some(ForwardIssue::ShutdownFailed));
    let events: Vec<_> = std::iter::from_fn(|| receiver.try_recv().ok()).collect();
    assert!(events.iter().all(|snapshot| snapshot.phase != ForwardPhase::Listening));
    assert!(
        events.iter().any(|snapshot| snapshot.last_issue == Some(ForwardIssue::ListenTimedOut))
    );
    peer.release.notify_one();
    peer.wait_closed().await;
    assert!(peer.requests.try_recv().is_err());
}

#[tokio::test]
async fn remote_denied_and_withheld_cancel_always_close_transport_and_report_unknown_cleanup() {
    for cancel in [Decision::Deny, Decision::Hold] {
        let mut peer = RemotePeer::new(Decision::Accept, cancel).await;
        let fixture = fixture(peer.port, "127.0.0.1:9".parse().unwrap()).await;
        let manager = ForwardManager::default();
        let initial = fixture.start(&manager);
        phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
        let _ = peer.request().await;
        let started = tokio::time::Instant::now();
        assert_eq!(manager.stop_all().await, Err(ForwardIssue::ShutdownFailed));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(peer.request().await, Request::Cancel("127.0.0.1".into(), fixture.port.into()));
        let failed = manager.snapshot(&fixture.store, &initial.run_id).unwrap();
        assert_eq!(failed.phase, ForwardPhase::Failed);
        assert_eq!(failed.last_issue, Some(ForwardIssue::ShutdownFailed));
        assert_eq!(failed.rejected_connections, "0");
        peer.release.notify_one();
        peer.wait_closed().await;
        assert!(peer.requests.try_recv().is_err());
    }
}

#[tokio::test]
async fn remote_previous_shutdown_failure_does_not_skip_waiting_for_other_owners() {
    let mut first = RemotePeer::new(Decision::Deny, Decision::Accept).await;
    let first_fixture = fixture(first.port, "127.0.0.1:9".parse().unwrap()).await;
    let manager = ForwardManager::default();
    let failed = first_fixture.start(&manager);
    let _ = first.request().await;
    phase(&manager, &first_fixture, &failed.run_id, ForwardPhase::Failed).await;
    first.wait_closed().await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let mut second = RemotePeer::new(Decision::Accept, Decision::Hold).await;
    let second_fixture = fixture(second.port, "127.0.0.1:9".parse().unwrap()).await;
    let live = second_fixture.start(&manager);
    assert!(failed.run_id < live.run_id);
    let _ = second.request().await;
    phase(&manager, &second_fixture, &live.run_id, ForwardPhase::Listening).await;
    assert_eq!(manager.stop_all().await, Err(ForwardIssue::ShutdownFailed));
    let settled = manager.snapshot(&second_fixture.store, &live.run_id).unwrap();
    assert_eq!(settled.phase, ForwardPhase::Failed);
    assert_eq!(settled.last_issue, Some(ForwardIssue::ShutdownFailed));
    assert_eq!(
        second.request().await,
        Request::Cancel("127.0.0.1".into(), second_fixture.port.into())
    );
    second.release.notify_one();
    second.wait_closed().await;
}

#[tokio::test]
async fn remote_ssh_loss_remains_observable_while_local_peers_wait_and_does_not_reconnect() {
    let mut peer = RemotePeer::new(Decision::Accept, Decision::Accept).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fixture = fixture(peer.port, target.local_addr().unwrap()).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let control = peer.control().await;
    let mut channels = Vec::new();
    let mut sockets = Vec::new();
    for _ in 0..3 {
        channels.push(forwarded(&control, &fixture).await);
        sockets.push(target.accept().await.unwrap().0);
    }
    snapshot_when(&manager, &fixture, &initial.run_id, |snapshot| snapshot.active_connections == 3)
        .await;
    control
        .disconnect(russh::Disconnect::ByApplication, String::new(), String::new())
        .await
        .unwrap();
    let failed = phase(&manager, &fixture, &initial.run_id, ForwardPhase::Failed).await;
    assert_eq!(failed.last_issue, Some(ForwardIssue::ShutdownFailed));
    assert_eq!(failed.active_connections, 0);
    assert_eq!(failed.rejected_connections, "0");
    for mut socket in sockets {
        assert_eq!(socket.read(&mut [0]).await.unwrap(), 0);
    }
    for channel in channels {
        closed(channel).await;
    }
}

#[tokio::test]
async fn remote_stop_during_trust_fences_prompt_before_any_listener_request() {
    let mut peer = RemotePeer::new(Decision::Accept, Decision::Accept).await;
    let fixture = fixture(peer.port, "127.0.0.1:9".parse().unwrap()).await;
    let manager = ForwardManager::default();
    let (events, mut receiver) = mpsc::unbounded_channel();
    let initial = manager
        .start(fixture.store.clone(), &fixture.forward, &fixture.profile, move |snapshot| {
            events.send(snapshot).unwrap();
        })
        .unwrap();
    let prompt = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(PreparationEvent::Trust { prompt_id, .. }) =
                receiver.recv().await.unwrap().preparation
            {
                break prompt_id;
            }
        }
    })
    .await
    .unwrap();
    manager.stop_all().await.unwrap();
    assert_eq!(
        manager.respond(
            &fixture.store,
            &initial.run_id,
            &prompt,
            PreparationResponse::AcceptHostKey
        ),
        Err(ForwardIssue::Expired)
    );
    let stopped = manager.snapshot(&fixture.store, &initial.run_id).unwrap();
    assert_eq!(stopped.phase, ForwardPhase::Stopped);
    assert_eq!(stopped.rejected_connections, "0");
    assert!(peer.requests.try_recv().is_err());
    peer.wait_closed().await;
}

#[test]
fn remote_resolution_limits_raw_candidates_before_deduplication() {
    use super::super::remote::target_addresses;
    let address: SocketAddr = "127.0.0.1:4242".parse().unwrap();
    assert_eq!(target_addresses(std::iter::repeat_n(address, 16)).unwrap(), vec![address]);
    assert_eq!(
        target_addresses(std::iter::repeat_n(address, 17)),
        Err(ForwardIssue::TargetRejected)
    );
    let addresses = [address, "[::1]:4242".parse().unwrap(), address];
    assert_eq!(target_addresses(addresses.into_iter()).unwrap(), addresses[..2]);
}

#[tokio::test]
async fn remote_expired_local_setup_budget_cannot_start_a_late_connection() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let (stop, _) = watch::channel(false);
    assert!(matches!(
        super::super::remote::connect_target(
            "localhost",
            address.port(),
            tokio::time::Instant::now() - Duration::from_secs(1),
            &stop,
        )
        .await,
        Err(ForwardIssue::TargetTimedOut)
    ));
    assert!(tokio::time::timeout(Duration::from_millis(100), target.accept()).await.is_err());
}

#[tokio::test]
async fn remote_already_stopped_setup_does_not_resolve_or_dial() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = format!("{}.invalid", Uuid::now_v7());
    let (_gate, mut entered, _complete) = super::super::remote::hold_resolution(host.clone());
    let (stop, _) = watch::channel(true);
    assert!(
        super::super::remote::connect_target(
            &host,
            target.local_addr().unwrap().port(),
            tokio::time::Instant::now() + OPEN_TIMEOUT,
            &stop,
        )
        .await
        .unwrap()
        .is_none()
    );
    assert!(matches!(entered.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty)));
    assert!(tokio::time::timeout(Duration::from_millis(100), target.accept()).await.is_err());
}

#[tokio::test]
async fn remote_owner_stop_and_ssh_loss_during_resolution_fence_late_local_dials() {
    for disconnect in [false, true] {
        let mut peer = RemotePeer::new(Decision::Accept, Decision::Accept).await;
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let fixture = fixture(peer.port, address).await;
        let host = format!("{}.invalid", Uuid::now_v7());
        let (_gate, entered, complete) = super::super::remote::hold_resolution(host.clone());
        Repository::<Forward>::new(&fixture.store)
            .update(
                Uuid::parse_str(&fixture.forward).unwrap(),
                ForwardChange { target_host: Edit::Set(host), ..Default::default() },
            )
            .unwrap();
        let manager = ForwardManager::default();
        let initial = fixture.start(&manager);
        phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
        let control = peer.control().await;
        let channel = forwarded(&control, &fixture).await;
        tokio::time::timeout(Duration::from_secs(5), entered).await.unwrap().unwrap();
        snapshot_when(&manager, &fixture, &initial.run_id, |snapshot| {
            snapshot.active_connections == 1
        })
        .await;
        let expected = if disconnect {
            control
                .disconnect(russh::Disconnect::ByApplication, String::new(), String::new())
                .await
                .unwrap();
            ForwardPhase::Failed
        } else {
            manager.stop(&fixture.store, &initial.run_id).unwrap();
            ForwardPhase::Stopped
        };
        let final_state = phase(&manager, &fixture, &initial.run_id, expected).await;
        assert_eq!(final_state.active_connections, 0);
        assert_eq!(final_state.rejected_connections, "0");
        if disconnect {
            assert_eq!(final_state.last_issue, Some(ForwardIssue::ShutdownFailed));
        }
        assert!(complete.send(vec![address]).is_err(), "cancelled setup retained its resolver");
        assert!(tokio::time::timeout(Duration::from_millis(100), target.accept()).await.is_err());
        closed(channel).await;
        peer.wait_closed().await;
    }
}
