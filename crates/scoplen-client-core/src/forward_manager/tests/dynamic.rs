// SPDX-License-Identifier: Apache-2.0

use super::*;

async fn fixture(ssh_port: u16) -> Fixture {
    let fixture = Fixture::new(ssh_port).await;
    Repository::<Forward>::new(&fixture.store)
        .update(
            Uuid::parse_str(&fixture.forward).unwrap(),
            ForwardChange { kind: Some(ForwardKind::Dynamic), ..Default::default() },
        )
        .unwrap();
    fixture
}

fn domain_request(domain: &[u8], port: u16) -> Vec<u8> {
    let mut request = vec![5, 1, 0, 3, u8::try_from(domain.len()).unwrap()];
    request.extend_from_slice(domain);
    request.extend_from_slice(&port.to_be_bytes());
    request
}

fn socks4_request(domain: Option<&[u8]>) -> Vec<u8> {
    let address = if domain.is_some() { [0, 0, 0, 1] } else { [203, 0, 113, 7] };
    let mut request = vec![4, 1, 0x10, 0x93];
    request.extend_from_slice(&address);
    request.extend_from_slice(b"untrusted-user-id\0");
    if let Some(domain) = domain {
        request.extend_from_slice(domain);
        request.push(0);
    }
    request
}

async fn read_exact<const N: usize>(socket: &mut TcpStream) -> [u8; N] {
    let mut response = [0; N];
    tokio::time::timeout(Duration::from_secs(10), socket.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

async fn socks5_socket(port: u16) -> TcpStream {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket.write_all(&[5]).await.unwrap();
    tokio::task::yield_now().await;
    socket.write_all(&[1, 0]).await.unwrap();
    assert_eq!(read_exact::<2>(&mut socket).await, [5, 0]);
    socket
}

async fn socks5_open(port: u16, request: &[u8]) -> TcpStream {
    let mut socket = socks5_socket(port).await;
    socket.write_all(request).await.unwrap();
    assert_eq!(read_exact::<10>(&mut socket).await, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    socket
}

async fn exchange_socket(mut socket: TcpStream, payload: &[u8]) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(10), async {
        socket.write_all(payload).await.unwrap();
        socket.shutdown().await.unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.unwrap();
        response
    })
    .await
    .unwrap()
}

async fn closed(socket: &mut TcpStream) {
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), socket.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

async fn snapshot_when(
    manager: &ForwardManager,
    fixture: &Fixture,
    id: &str,
    predicate: impl Fn(&ForwardSnapshot) -> bool,
) -> ForwardSnapshot {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let snapshot = manager.snapshot(&fixture.store, id).unwrap();
            if predicate(&snapshot) {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn dynamic_socks_versions_targets_trailing_and_application_counters() {
    let peer = ForwardPeer::new(PeerMode::Trailer).await;
    let fixture = fixture(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    let serialized = serde_json::to_value(&initial.configuration).unwrap();
    assert_eq!(serialized["kind"], "dynamic");
    assert_eq!(serialized["bindAddress"], "127.0.0.1");
    assert!(serialized.get("targetHost").is_none());
    assert!(serialized.get("targetPort").is_none());
    assert_eq!(initial.configuration.login().profile_id, fixture.profile);
    Repository::<Forward>::new(&fixture.store)
        .update(
            Uuid::parse_str(&fixture.forward).unwrap(),
            ForwardChange {
                name: Some("edited after Start".into()),
                kind: Some(ForwardKind::Local),
                target_host: Edit::Set("must-not-be-used.example".into()),
                target_port: Edit::Set(1),
                ..Default::default()
            },
        )
        .unwrap();
    Repository::<Forward>::new(&fixture.store)
        .delete(Uuid::parse_str(&fixture.forward).unwrap())
        .unwrap();
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let first: Vec<_> = (0..COPY_BUFFER * 3 + 19).map(|i| (i % 256) as u8).collect();
    let second = vec![0xff; COPY_BUFFER * 2 + 29];
    let first_exchange = async {
        let mut socket = TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap();
        let mut coalesced = vec![5, 1, 0];
        coalesced.extend_from_slice(&domain_request(b"remote-only.invalid", 4242));
        coalesced.extend_from_slice(&first);
        socket.write_all(&coalesced).await.unwrap();
        assert_eq!(read_exact::<12>(&mut socket).await, [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        exchange_socket(socket, &[]).await
    };
    let second_exchange = async {
        let mut socket = TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap();
        let request = socks4_request(Some(b"second-remote.invalid"));
        for fragment in request.chunks(3) {
            socket.write_all(fragment).await.unwrap();
            tokio::task::yield_now().await;
        }
        assert_eq!(read_exact::<8>(&mut socket).await, [0, 90, 0, 0, 0, 0, 0, 0]);
        exchange_socket(socket, &second).await
    };
    let (one, two) = tokio::join!(first_exchange, second_exchange);
    let trailer = b"EOF-only trailer";
    assert_eq!(one, [first.as_slice(), trailer].concat());
    assert_eq!(two, [second.as_slice(), trailer].concat());
    let mut ipv6 = vec![5, 1, 0, 4];
    ipv6.extend_from_slice(&"2001:db8::7".parse::<std::net::Ipv6Addr>().unwrap().octets());
    ipv6.extend_from_slice(&4244u16.to_be_bytes());
    let ipv6 = socks5_open(fixture.port, &ipv6).await;
    assert_eq!(exchange_socket(ipv6, b"IPv6").await, b"IPv6EOF-only trailer");
    let mut ipv4 = TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap();
    ipv4.write_all(&socks4_request(None)).await.unwrap();
    assert_eq!(read_exact::<8>(&mut ipv4).await, [0, 90, 0, 0, 0, 0, 0, 0]);
    assert_eq!(exchange_socket(ipv4, b"IPv4").await, b"IPv4EOF-only trailer");
    let ipv4_v5 = socks5_open(fixture.port, &[5, 1, 0, 1, 198, 51, 100, 9, 0x10, 0x95]).await;
    assert_eq!(exchange_socket(ipv4_v5, b"v5").await, b"v5EOF-only trailer");
    stop(&manager, &fixture, &initial.run_id).await;
    let final_snapshot = manager.snapshot(&fixture.store, &initial.run_id).unwrap();
    let uploaded = first.len() + second.len() + 4 + 4 + 2;
    assert_eq!(final_snapshot.configuration, initial.configuration);
    assert_eq!(final_snapshot.uploaded_bytes, uploaded.to_string());
    assert_eq!(final_snapshot.downloaded_bytes, (uploaded + 5 * trailer.len()).to_string());
    assert_eq!(final_snapshot.rejected_connections, "0");
    assert_eq!(peer.sessions.load(Ordering::SeqCst), 0);
    let targets = peer.targets.lock().unwrap();
    for target in [
        ("remote-only.invalid".into(), 4242),
        ("second-remote.invalid".into(), 4243),
        ("2001:db8::7".into(), 4244),
        ("203.0.113.7".into(), 4243),
        ("198.51.100.9".into(), 4245),
    ] {
        assert!(targets.contains(&target));
    }
}

#[tokio::test]
async fn dynamic_remote_eof_preserves_later_upload() {
    let peer = ForwardPeer::new(PeerMode::RemoteEofFirst).await;
    let fixture = fixture(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let mut socket = socks5_open(fixture.port, &domain_request(b"half-close.invalid", 80)).await;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, b"remote EOF first");
    let payload = b"uploaded after remote EOF\0\xff";
    socket.write_all(payload).await.unwrap();
    socket.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while peer.received.lock().unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(peer.received.lock().unwrap().as_slice(), &[payload.to_vec()]);
    stop(&manager, &fixture, &initial.run_id).await;
    let final_snapshot = manager.snapshot(&fixture.store, &initial.run_id).unwrap();
    assert_eq!(final_snapshot.uploaded_bytes, payload.len().to_string());
    assert_eq!(final_snapshot.downloaded_bytes, response.len().to_string());
}

#[tokio::test]
async fn dynamic_rejects_protocol_failures_once_without_opening_channels_or_losing_listener() {
    let peer = ForwardPeer::new(PeerMode::Echo).await;
    let fixture = fixture(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let mut rejected = 0;
    let mut no_auth = TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap();
    no_auth.write_all(&[5, 1, 2]).await.unwrap();
    assert_eq!(read_exact::<2>(&mut no_auth).await, [5, 255]);
    closed(&mut no_auth).await;
    rejected += 1;
    for (request, reply) in [
        (vec![5, 2, 0, 1, 127, 0, 0, 1, 0, 80], Some(7)),
        (vec![5, 3, 0, 1, 127, 0, 0, 1, 0, 80], Some(7)),
        (vec![5, 1, 0, 9], Some(8)),
        (vec![5, 1, 1, 1, 127, 0, 0, 1, 0, 80], None),
        (domain_request(&[0xff], 80), Some(2)),
        (domain_request(b"valid.invalid", 0), Some(2)),
        (domain_request(b"bad\0domain", 80), None),
        (vec![5, 1, 0, 3, 0], None),
    ] {
        let mut socket = socks5_socket(fixture.port).await;
        socket.write_all(&request).await.unwrap();
        if let Some(code) = reply {
            assert_eq!(read_exact::<10>(&mut socket).await, [5, code, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
        closed(&mut socket).await;
        rejected += 1;
    }
    let mut oversized = vec![4, 1, 0, 80, 127, 0, 0, 1];
    oversized.extend_from_slice(&[b'u'; 256]);
    for request in [vec![6], oversized] {
        let mut socket = TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap();
        socket.write_all(&request).await.unwrap();
        closed(&mut socket).await;
        rejected += 1;
    }
    let mut truncated = socks5_socket(fixture.port).await;
    truncated.write_all(&[5, 1, 0, 1, 127]).await.unwrap();
    truncated.shutdown().await.unwrap();
    closed(&mut truncated).await;
    rejected += 1;
    let failed = snapshot_when(&manager, &fixture, &initial.run_id, |snapshot| {
        snapshot.rejected_connections == rejected.to_string()
    })
    .await;
    assert_eq!(failed.phase, ForwardPhase::Listening);
    assert_eq!(failed.active_connections, 0);
    assert_eq!(failed.last_issue, Some(ForwardIssue::HandshakeRejected));
    assert_eq!(failed.uploaded_bytes, "0");
    assert_eq!(failed.downloaded_bytes, "0");
    assert_eq!(peer.opened.load(Ordering::SeqCst), 0);
    let socket = socks5_open(fixture.port, &domain_request(b"later.invalid", 80)).await;
    assert_eq!(exchange_socket(socket, b"later").await, b"later");
    stop(&manager, &fixture, &initial.run_id).await;
    assert_eq!(
        manager.snapshot(&fixture.store, &initial.run_id).unwrap().rejected_connections,
        rejected.to_string()
    );
}

#[tokio::test]
async fn dynamic_target_refusal_maps_reply_and_allows_later_peer() {
    let peer = ForwardPeer::new(PeerMode::RefuseFirst).await;
    let fixture = fixture(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let mut refused = socks5_socket(fixture.port).await;
    refused.write_all(&domain_request(b"refused.invalid", 80)).await.unwrap();
    assert_eq!(read_exact::<10>(&mut refused).await, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
    closed(&mut refused).await;
    let socket = socks5_open(fixture.port, &domain_request(b"later.invalid", 81)).await;
    assert_eq!(exchange_socket(socket, b"later").await, b"later");
    let snapshot = snapshot_when(&manager, &fixture, &initial.run_id, |snapshot| {
        snapshot.active_connections == 0 && snapshot.rejected_connections == "1"
    })
    .await;
    assert_eq!(snapshot.last_issue, Some(ForwardIssue::TargetRejected));
    assert_eq!(snapshot.phase, ForwardPhase::Listening);
    stop(&manager, &fixture, &initial.run_id).await;
}

#[tokio::test]
async fn dynamic_capacity_counts_negotiation_open_and_copy_and_stop_is_not_rejection() {
    let peer = ForwardPeer::new(PeerMode::HoldFirst).await;
    let fixture = fixture(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let mut opening = socks5_socket(fixture.port).await;
    opening.write_all(&domain_request(b"held.invalid", 80)).await.unwrap();
    peer.wait_opened(1).await;
    let mut copying = socks5_open(fixture.port, &domain_request(b"copy.invalid", 81)).await;
    let mut negotiating = Vec::new();
    for _ in 2..MAX_FORWARD_PEERS {
        let mut socket = TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap();
        socket.write_all(&[5]).await.unwrap();
        negotiating.push(socket);
    }
    snapshot_when(&manager, &fixture, &initial.run_id, |snapshot| {
        snapshot.active_connections == MAX_FORWARD_PEERS as u32
    })
    .await;
    let mut excess = TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap();
    closed(&mut excess).await;
    assert_eq!(peer.opened.load(Ordering::SeqCst), 2);
    stop(&manager, &fixture, &initial.run_id).await;
    closed(&mut opening).await;
    closed(&mut copying).await;
    for mut socket in negotiating {
        closed(&mut socket).await;
    }
    let final_snapshot = manager.snapshot(&fixture.store, &initial.run_id).unwrap();
    assert_eq!(final_snapshot.rejected_connections, "1");
    assert_eq!(final_snapshot.last_issue, Some(ForwardIssue::PeerLimitReached));
    assert_eq!(final_snapshot.active_connections, 0);
    assert_eq!(final_snapshot.uploaded_bytes, "0");
    assert_eq!(final_snapshot.downloaded_bytes, "0");
}

#[tokio::test]
async fn dynamic_negotiation_has_absolute_deadline_despite_slow_fragments() {
    let peer = ForwardPeer::new(PeerMode::Echo).await;
    let fixture = fixture(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let started = tokio::time::Instant::now();
    let socket = TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap();
    let (mut read, mut write) = socket.into_split();
    write.write_all(&[4, 1, 0, 80, 127, 0, 0, 1]).await.unwrap();
    let drip = tokio::spawn(async move {
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_secs(4)).await;
            if write.write_all(b"u").await.is_err() {
                break;
            }
        }
    });
    assert_eq!(
        tokio::time::timeout(
            socks::HANDSHAKE_TIMEOUT + Duration::from_secs(2),
            read.read(&mut [0])
        )
        .await
        .unwrap()
        .unwrap(),
        0
    );
    assert!(started.elapsed() >= socks::HANDSHAKE_TIMEOUT);
    drip.abort();
    let _ = drip.await;
    let snapshot = snapshot_when(&manager, &fixture, &initial.run_id, |snapshot| {
        snapshot.rejected_connections == "1" && snapshot.active_connections == 0
    })
    .await;
    assert_eq!(snapshot.last_issue, Some(ForwardIssue::HandshakeTimedOut));
    assert_eq!(peer.opened.load(Ordering::SeqCst), 0);
    let socket = socks5_open(fixture.port, &domain_request(b"fresh.invalid", 80)).await;
    assert_eq!(exchange_socket(socket, b"fresh").await, b"fresh");
    stop(&manager, &fixture, &initial.run_id).await;
    assert_eq!(
        manager.snapshot(&fixture.store, &initial.run_id).unwrap().rejected_connections,
        "1"
    );
}

#[tokio::test]
async fn dynamic_pending_open_is_independent_times_out_and_releases_capacity() {
    let peer = ForwardPeer::new(PeerMode::HoldFirst).await;
    let fixture = fixture(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let mut pending = socks5_socket(fixture.port).await;
    pending.write_all(&domain_request(b"pending.invalid", 80)).await.unwrap();
    peer.wait_opened(1).await;
    let socket = socks5_open(fixture.port, &domain_request(b"parallel.invalid", 81)).await;
    assert_eq!(exchange_socket(socket, b"parallel").await, b"parallel");
    let mut response = [0; 10];
    tokio::time::timeout(OPEN_TIMEOUT + Duration::from_secs(2), pending.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
    closed(&mut pending).await;
    let snapshot = snapshot_when(&manager, &fixture, &initial.run_id, |snapshot| {
        snapshot.rejected_connections == "1" && snapshot.active_connections == 0
    })
    .await;
    assert_eq!(snapshot.last_issue, Some(ForwardIssue::TargetTimedOut));
    assert_eq!(snapshot.phase, ForwardPhase::Listening);
    stop(&manager, &fixture, &initial.run_id).await;
    assert_eq!(
        manager.snapshot(&fixture.store, &initial.run_id).unwrap().rejected_connections,
        "1"
    );
}

#[tokio::test]
async fn dynamic_ssh_loss_with_only_negotiating_peers_releases_listener_without_reconnect() {
    let mut peer = ForwardPeer::new(PeerMode::Echo).await;
    let fixture = fixture(peer.port).await;
    let manager = ForwardManager::default();
    let initial = fixture.start(&manager);
    phase(&manager, &fixture, &initial.run_id, ForwardPhase::Listening).await;
    let mut sockets = Vec::new();
    for _ in 0..3 {
        let mut socket = TcpStream::connect(("127.0.0.1", fixture.port)).await.unwrap();
        socket.write_all(&[5]).await.unwrap();
        sockets.push(socket);
    }
    snapshot_when(&manager, &fixture, &initial.run_id, |snapshot| snapshot.active_connections == 3)
        .await;
    peer.disconnect().await;
    let failed = phase(&manager, &fixture, &initial.run_id, ForwardPhase::Failed).await;
    assert_eq!(failed.last_issue, Some(ForwardIssue::ConnectionLost));
    assert_eq!(failed.active_connections, 0);
    assert_eq!(failed.rejected_connections, "0");
    assert_eq!(peer.opened.load(Ordering::SeqCst), 0);
    for mut socket in sockets {
        closed(&mut socket).await;
    }
    TcpListener::bind(("127.0.0.1", fixture.port)).await.unwrap();
}

#[tokio::test]
async fn dynamic_stop_during_trust_fences_prompt_and_releases_store_owner() {
    let peer = Peer::start().await;
    let fixture = fixture(peer.port).await;
    let manager = ForwardManager::default();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let initial = manager
        .start(fixture.store.clone(), &fixture.forward, &fixture.profile, move |snapshot| {
            tx.send(snapshot).unwrap();
        })
        .unwrap();
    let prompt = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(PreparationEvent::Trust { prompt_id, .. }) =
                rx.recv().await.unwrap().preparation
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
    let snapshot = manager.snapshot(&fixture.store, &initial.run_id).unwrap();
    assert_eq!(snapshot.phase, ForwardPhase::Stopped);
    assert_eq!(snapshot.rejected_connections, "0");
    assert_eq!(peer.authentications.load(Ordering::SeqCst), 0);
    let weak = Arc::downgrade(&fixture.store);
    drop(fixture);
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn counted_copy_retains_partial_success_when_later_write_fails() {
    struct PartialWriter(usize);
    impl AsyncWrite for PartialWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.0 == 7 {
                return std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            let written = bytes.len().min(3).min(7 - self.0);
            self.0 += written;
            std::task::Poll::Ready(Ok(written))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
    let count = AtomicU64::new(0);
    let error = copy(std::io::Cursor::new([0; 20]), PartialWriter(0), &count).await.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    assert_eq!(count.load(Ordering::Acquire), 7);
}
