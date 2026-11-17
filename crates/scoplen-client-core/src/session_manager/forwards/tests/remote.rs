// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::connection::test_peer::{ForwardReply, RemoteRequest};
use crate::forward_manager::ForwardSnapshot;
use crate::forward_manager::MAX_FORWARD_PEERS;

fn profile(store: &Arc<Store>, peer: &Peer, ids: &[Uuid]) -> Uuid {
    let host = Inventory::new(store.clone())
        .add_host(NewHost {
            name: Some("Attached Remote peer".into()),
            address: "127.0.0.1".into(),
            port: Some(peer.port),
            username: "trust-fixture".into(),
            sign_in: SignIn::Password { password: "disposable-trust-password".into() },
        })
        .unwrap();
    let profile = Uuid::parse_str(&host.logins[0].id).unwrap();
    Repository::<AccessProfile>::new(store)
        .update(
            profile,
            AccessProfileChange {
                forwards: ids.iter().map(|id| (*id, true)).collect(),
                ..Default::default()
            },
        )
        .unwrap();
    profile
}

fn remote(store: &Store, port: u16, target: &TcpListener) -> Uuid {
    let id = definition(store, ForwardKind::Remote, port, "127.0.0.1");
    Repository::<Forward>::new(store)
        .update(
            id,
            ForwardChange {
                target_port: Edit::Set(target.local_addr().unwrap().port()),
                ..Default::default()
            },
        )
        .unwrap();
    id
}

async fn request(peer: &mut Peer) -> RemoteRequest {
    tokio::time::timeout(Duration::from_secs(15), peer.remote.as_mut().unwrap().requests.recv())
        .await
        .unwrap()
        .unwrap()
}

async fn control(peer: &mut Peer) -> russh::server::Handle {
    tokio::time::timeout(Duration::from_secs(10), peer.remote.as_mut().unwrap().connections.recv())
        .await
        .unwrap()
        .unwrap()
}

async fn delivered(
    control: &russh::server::Handle,
    address: &str,
    port: u32,
) -> russh::Channel<russh::server::Msg> {
    tokio::time::timeout(
        Duration::from_secs(5),
        control.channel_open_forwarded_tcpip(address, port, "untrusted-origin.invalid", 65535),
    )
    .await
    .unwrap()
    .unwrap()
}

async fn closed(channel: russh::Channel<russh::server::Msg>) {
    let mut stream = channel.into_stream();
    let result = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut [0])).await.unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
}

fn run(entries: &[SessionForwardSnapshot], id: Uuid) -> &ForwardSnapshot {
    entries.iter().find(|entry| entry.forward_id == id.to_string()).unwrap().run.as_ref().unwrap()
}

async fn ended(
    manager: &SessionManager,
    store: &Arc<Store>,
    transport: &str,
    id: Uuid,
) -> Vec<SessionForwardSnapshot> {
    entries(manager, store, transport, |entries| {
        matches!(run(entries, id).phase, ForwardPhase::Stopped | ForwardPhase::Failed)
    })
    .await
}

#[tokio::test]
async fn exact_remote_dispatch_shares_shell_and_local_tunnels_and_rejects_duplicate_tuple() {
    let mut peer = Peer::with_remote_forwarding(ForwardReply::Accept, ForwardReply::Accept).await;
    let (_directory, store) = store();
    let targets = [
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
    ];
    let ports = [unused_port().await, unused_port().await];
    let first = remote(&store, ports[0], &targets[0]);
    let duplicate = remote(&store, ports[0], &targets[0]);
    let second = remote(&store, ports[1], &targets[1]);
    let local_port = unused_port().await;
    let dynamic_port = unused_port().await;
    let local = definition(&store, ForwardKind::Local, local_port, "target.example");
    let dynamic = definition(&store, ForwardKind::Dynamic, dynamic_port, "unused.example");
    let profile = profile(&store, &peer, &[first, duplicate, second, local, dynamic]);
    let forwards = ForwardManager::default();
    let manager = SessionManager::with_forward_manager(forwards.clone());
    let (task, mut events, mut output) = connect(&manager, store.clone(), profile.to_string());
    let transport = ready(&mut events).await;
    let initial = entries(&manager, &store, &transport, |entries| {
        entries.len() == 5
            && entries.iter().all(|entry| {
                entry.run.as_ref().is_some_and(|run| run.phase != ForwardPhase::Preparing)
            })
    })
    .await;
    let first_id =
        if run(&initial, first).phase == ForwardPhase::Listening { first } else { duplicate };
    let duplicate_id = if first_id == first { duplicate } else { first };
    assert_eq!(run(&initial, duplicate_id).last_issue, Some(ForwardIssue::ListenFailed));
    assert_eq!(run(&initial, second).phase, ForwardPhase::Listening);
    let mut requested = vec![request(&mut peer).await, request(&mut peer).await];
    requested.sort_by_key(|request| match request {
        RemoteRequest::Listen(_, port) => *port,
        _ => 0,
    });
    let mut expected = ports.to_vec();
    expected.sort_unstable();
    assert_eq!(
        requested,
        expected
            .into_iter()
            .map(|port| RemoteRequest::Listen("127.0.0.1".into(), port.into()))
            .collect::<Vec<_>>()
    );
    manager.forward_stop(&store, "terminal", &transport, &duplicate_id.to_string()).unwrap();
    let control = control(&mut peer).await;
    for (address, port) in
        [("localhost", u32::from(ports[0])), ("0.0.0.0", u32::from(ports[0])), ("127.0.0.1", 65536)]
    {
        closed(delivered(&control, address, port).await).await;
    }
    closed(control.channel_open_forwarded_streamlocal("/fixture/unsupported.sock").await.unwrap())
        .await;
    assert!(control.channel_open_agent().await.is_err());
    for target in &targets {
        assert!(tokio::time::timeout(Duration::from_millis(50), target.accept()).await.is_err());
    }
    // Saved edits do not retarget either live endpoint.
    Repository::<Forward>::new(&store)
        .update(
            first_id,
            ForwardChange { target_host: Edit::Set("wrong.invalid".into()), ..Default::default() },
        )
        .unwrap();
    let mut services = tokio::task::JoinSet::new();
    for target in targets {
        services.spawn(async move {
            let (mut socket, _) = target.accept().await.unwrap();
            let mut bytes = Vec::new();
            socket.read_to_end(&mut bytes).await.unwrap();
            bytes.extend_from_slice(b"EOF trailer");
            socket.write_all(&bytes).await.unwrap();
            socket.shutdown().await.unwrap();
            target
        });
    }
    let payload: Vec<u8> = (0u8..=255).cycle().take(65555).collect();
    let mut channels = Vec::new();
    for port in ports {
        channels.push(delivered(&control, "127.0.0.1", port.into()).await.into_stream());
    }
    // Unfinished Remote peers do not block local channels or terminal input.
    exchange(local_port, false).await;
    exchange(dynamic_port, true).await;
    shell(&manager, &transport, &mut output).await;
    for mut channel in channels {
        channel.write_all(&payload).await.unwrap();
        channel.shutdown().await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), channel.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let mut expected = payload.clone();
        expected.extend_from_slice(b"EOF trailer");
        assert_eq!(response, expected);
    }
    let completed = entries(&manager, &store, &transport, |entries| {
        [first_id, second].into_iter().all(|id| {
            run(entries, id).active_connections == 0
                && run(entries, id).downloaded_bytes == payload.len().to_string()
        })
    })
    .await;
    for id in [first_id, second] {
        assert_eq!(
            run(&completed, id).uploaded_bytes,
            (payload.len() + b"EOF trailer".len()).to_string()
        );
    }
    manager.forward_stop(&store, "terminal", &transport, &first_id.to_string()).unwrap();
    assert_eq!(
        run(&ended(&manager, &store, &transport, first_id).await, first_id).phase,
        ForwardPhase::Stopped
    );
    assert_eq!(
        request(&mut peer).await,
        RemoteRequest::Cancel("127.0.0.1".into(), ports[0].into())
    );
    closed(delivered(&control, "127.0.0.1", ports[0].into()).await).await;
    forwards.stop(&store, &run(&initial, second).run_id).unwrap();
    assert_eq!(
        run(&ended(&manager, &store, &transport, second).await, second).phase,
        ForwardPhase::Stopped
    );
    assert_eq!(
        request(&mut peer).await,
        RemoteRequest::Cancel("127.0.0.1".into(), ports[1].into())
    );
    while let Some(service) = services.join_next().await {
        assert!(
            tokio::time::timeout(Duration::from_millis(50), service.unwrap().accept())
                .await
                .is_err()
        );
    }
    assert!(peer.remote.as_mut().unwrap().requests.try_recv().is_err());
    shell(&manager, &transport, &mut output).await;
    assert_eq!(peer.authentications.load(Ordering::SeqCst), 1);
    assert_eq!(peer.closed_connections.load(Ordering::SeqCst), 0);
    manager.close_all().unwrap();
    tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn unknown_remote_registration_never_admits_or_cancels_or_closes_the_terminal() {
    for (reply, stop) in
        [(ForwardReply::Deny, false), (ForwardReply::Hold, true), (ForwardReply::Hold, false)]
    {
        let mut peer = Peer::with_remote_forwarding(reply, ForwardReply::Accept).await;
        let (_directory, store) = store();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = unused_port().await;
        let id = remote(&store, port, &target);
        let profile = profile(&store, &peer, &[id]);
        let manager = SessionManager::default();
        let (task, mut events, mut output) = connect(&manager, store.clone(), profile.to_string());
        let transport = ready(&mut events).await;
        assert_eq!(
            request(&mut peer).await,
            RemoteRequest::Listen("127.0.0.1".into(), port.into())
        );
        if stop {
            manager.forward_stop(&store, "terminal", &transport, &id.to_string()).unwrap();
        }
        let result = ended(&manager, &store, &transport, id).await;
        assert_eq!(run(&result, id).phase, ForwardPhase::Failed);
        assert_eq!(run(&result, id).last_issue, Some(ForwardIssue::ShutdownFailed));
        assert_eq!(run(&result, id).active_connections, 0);
        peer.remote.as_ref().unwrap().release.notify_one();
        let control = control(&mut peer).await;
        closed(delivered(&control, "127.0.0.1", port.into()).await).await;
        assert!(tokio::time::timeout(Duration::from_millis(50), target.accept()).await.is_err());
        shell(&manager, &transport, &mut output).await;
        assert_eq!(peer.closed_connections.load(Ordering::SeqCst), 0);
        assert!(peer.remote.as_mut().unwrap().requests.try_recv().is_err());
        manager.close_all().unwrap();
        tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap().unwrap();
    }
}

#[tokio::test]
async fn uncertain_remote_cancellation_bounds_stop_and_preserves_other_services() {
    for reply in [ForwardReply::Deny, ForwardReply::Hold] {
        let mut peer = Peer::with_remote_forwarding(ForwardReply::Accept, reply).await;
        let (_directory, store) = store();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = unused_port().await;
        let id = remote(&store, port, &target);
        let local_port = unused_port().await;
        let local = definition(&store, ForwardKind::Local, local_port, "target.example");
        let profile = profile(&store, &peer, &[id, local]);
        let manager = SessionManager::default();
        let (task, mut events, mut output) = connect(&manager, store.clone(), profile.to_string());
        let transport = ready(&mut events).await;
        entries(&manager, &store, &transport, |entries| {
            run(entries, id).phase == ForwardPhase::Listening
        })
        .await;
        let _ = request(&mut peer).await;
        let control = control(&mut peer).await;
        let channel = delivered(&control, "127.0.0.1", port.into()).await;
        let (mut socket, _) = target.accept().await.unwrap();
        manager.forward_stop(&store, "terminal", &transport, &id.to_string()).unwrap();
        let result =
            tokio::time::timeout(Duration::from_secs(3), ended(&manager, &store, &transport, id))
                .await
                .unwrap();
        assert_eq!(run(&result, id).last_issue, Some(ForwardIssue::ShutdownFailed));
        assert_eq!(run(&result, id).active_connections, 0);
        assert_eq!(
            request(&mut peer).await,
            RemoteRequest::Cancel("127.0.0.1".into(), port.into())
        );
        peer.remote.as_ref().unwrap().release.notify_one();
        closed(channel).await;
        assert!(matches!(socket.read(&mut [0]).await, Ok(0) | Err(_)));
        closed(delivered(&control, "127.0.0.1", port.into()).await).await;
        assert!(tokio::time::timeout(Duration::from_millis(50), target.accept()).await.is_err());
        exchange(local_port, false).await;
        shell(&manager, &transport, &mut output).await;
        assert_eq!(peer.closed_connections.load(Ordering::SeqCst), 0);
        assert!(peer.remote.as_mut().unwrap().requests.try_recv().is_err());
        manager.close_all().unwrap();
        tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap().unwrap();
    }
}

#[tokio::test]
async fn remote_peer_capacity_and_local_refusal_do_not_block_another_route() {
    let mut peer = Peer::with_remote_forwarding(ForwardReply::Accept, ForwardReply::Accept).await;
    let (_directory, store) = store();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let other = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let other_address = other.local_addr().unwrap();
    let ports = [unused_port().await, unused_port().await];
    let ids = [remote(&store, ports[0], &target), remote(&store, ports[1], &other)];
    drop(other);
    let profile = profile(&store, &peer, &ids);
    let manager = SessionManager::default();
    let (task, mut events, mut output) = connect(&manager, store.clone(), profile.to_string());
    let transport = ready(&mut events).await;
    entries(&manager, &store, &transport, |entries| {
        ids.into_iter().all(|id| run(entries, id).phase == ForwardPhase::Listening)
    })
    .await;
    let _ = request(&mut peer).await;
    let _ = request(&mut peer).await;
    let control = control(&mut peer).await;
    let mut channels = Vec::new();
    let mut sockets = Vec::new();
    for _ in 0..MAX_FORWARD_PEERS {
        channels.push(delivered(&control, "127.0.0.1", ports[0].into()).await);
        sockets.push(
            tokio::time::timeout(Duration::from_secs(5), target.accept()).await.unwrap().unwrap().0,
        );
    }
    closed(delivered(&control, "127.0.0.1", ports[0].into()).await).await;
    let full = entries(&manager, &store, &transport, |entries| {
        run(entries, ids[0]).last_issue == Some(ForwardIssue::PeerLimitReached)
    })
    .await;
    assert_eq!(run(&full, ids[0]).active_connections, MAX_FORWARD_PEERS as u32);
    assert_eq!(run(&full, ids[0]).rejected_connections, "1");
    assert!(tokio::time::timeout(Duration::from_millis(50), target.accept()).await.is_err());
    closed(delivered(&control, "127.0.0.1", ports[1].into()).await).await;
    entries(&manager, &store, &transport, |entries| {
        run(entries, ids[1]).active_connections == 0
            && run(entries, ids[1]).last_issue == Some(ForwardIssue::TargetRejected)
    })
    .await;
    let other = TcpListener::bind(other_address).await.unwrap();
    let mut channel = delivered(&control, "127.0.0.1", ports[1].into()).await.into_stream();
    let (mut socket, _) =
        tokio::time::timeout(Duration::from_secs(5), other.accept()).await.unwrap().unwrap();
    socket.write_all(b"independent route").await.unwrap();
    let mut reply = [0; 17];
    tokio::time::timeout(Duration::from_secs(5), channel.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"independent route");
    shell(&manager, &transport, &mut output).await;
    manager.forward_stop(&store, "terminal", &transport, &ids[0].to_string()).unwrap();
    let stopped = ended(&manager, &store, &transport, ids[0]).await;
    assert_eq!(run(&stopped, ids[0]).phase, ForwardPhase::Stopped);
    assert_eq!(run(&stopped, ids[0]).active_connections, 0);
    assert_eq!(run(&stopped, ids[1]).phase, ForwardPhase::Listening);
    for channel in channels {
        closed(channel).await;
    }
    for mut socket in sockets {
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(5), socket.read(&mut [0])).await.unwrap(),
            Ok(0) | Err(_)
        ));
    }
    manager.close_all().unwrap();
    tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn remote_stop_during_resolution_closes_peer_before_late_results_without_blocking_shell() {
    let mut peer = Peer::with_remote_forwarding(ForwardReply::Accept, ForwardReply::Accept).await;
    let (_directory, store) = store();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = unused_port().await;
    let id = remote(&store, port, &target);
    let host = format!("pending-{}.invalid", Uuid::now_v7());
    let (_gate, started, complete) = crate::forward_manager::hold_resolution(host.clone());
    Repository::<Forward>::new(&store)
        .update(id, ForwardChange { target_host: Edit::Set(host), ..Default::default() })
        .unwrap();
    let profile = profile(&store, &peer, &[id]);
    let manager = SessionManager::default();
    let (task, mut events, mut output) = connect(&manager, store.clone(), profile.to_string());
    let transport = ready(&mut events).await;
    entries(&manager, &store, &transport, |entries| {
        run(entries, id).phase == ForwardPhase::Listening
    })
    .await;
    let control = control(&mut peer).await;
    let channel = delivered(&control, "127.0.0.1", port.into()).await;
    tokio::time::timeout(Duration::from_secs(5), started).await.unwrap().unwrap();
    shell(&manager, &transport, &mut output).await;
    manager.forward_stop(&store, "terminal", &transport, &id.to_string()).unwrap();
    let stopped =
        tokio::time::timeout(Duration::from_secs(3), ended(&manager, &store, &transport, id))
            .await
            .unwrap();
    assert_eq!(run(&stopped, id).phase, ForwardPhase::Stopped);
    assert_eq!(run(&stopped, id).active_connections, 0);
    closed(channel).await;
    assert!(complete.send(vec![target.local_addr().unwrap()]).is_err());
    assert!(tokio::time::timeout(Duration::from_millis(50), target.accept()).await.is_err());
    shell(&manager, &transport, &mut output).await;
    manager.close_all().unwrap();
    tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap().unwrap();
}
