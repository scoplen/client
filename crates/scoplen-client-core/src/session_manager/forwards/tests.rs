// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    connection::test_peer::{Authentication, Peer},
    forward_manager::{ForwardPhase, ForwardStartIntent},
    inventory::{NewHost, SignIn},
    repository::{
        AccessProfile, AccessProfileChange, Edit, Forward, ForwardChange, ForwardKind, Repository,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

mod remote;

fn store() -> (tempfile::TempDir, Arc<Store>) {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(
        &directory.path().join("attached.db"),
        &scoplen_crypto::LocalDatabaseKey::new([37; 32]),
    )
    .unwrap();
    (directory, Arc::new(store))
}

async fn unused_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}

fn definition(store: &Store, kind: ForwardKind, port: u16, target: &str) -> Uuid {
    Repository::<Forward>::new(store)
        .create(ForwardChange {
            name: Some(format!("Attached {kind:?} {port}")),
            kind: Some(kind),
            bind_address: Edit::Set("127.0.0.1".into()),
            bind_port: Edit::Set(port),
            target_host: Edit::Set(target.into()),
            target_port: Edit::Set(4242),
            // Attachment must use the terminal Login, never this absent default.
            profile: Edit::Set(Uuid::now_v7()),
        })
        .unwrap()
        .meta
        .id
}

type Connected = (
    tokio::task::JoinHandle<Result<(), String>>,
    mpsc::UnboundedReceiver<SessionEvent>,
    mpsc::UnboundedReceiver<Vec<u8>>,
);

fn connect(manager: &SessionManager, store: Arc<Store>, profile: String) -> Connected {
    manager.reserve("terminal", true).unwrap();
    let manager = manager.clone();
    let (events, receiver) = mpsc::unbounded_channel();
    let (output, bytes) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        manager
            .run_target(
                "terminal",
                &SessionTarget::Personal { profile_id: profile },
                &PersonalServer::default(),
                None,
                true,
                store,
                |event| {
                    if let SessionEvent::Preparation { transport_id, event } = &event
                        && let PreparationEvent::Trust { prompt_id, .. } = event.as_ref()
                    {
                        manager.respond(
                            "terminal",
                            transport_id,
                            prompt_id,
                            PreparationResponse::AcceptHostKey,
                        )?;
                    }
                    events.send(event).map_err(|_| "event receiver closed".to_owned())
                },
                |_, data| output.send(data).map_err(|_| "output receiver closed".to_owned()),
                |_, _| {},
            )
            .await
    });
    (task, receiver, bytes)
}

async fn ready(events: &mut mpsc::UnboundedReceiver<SessionEvent>) -> String {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match events.recv().await.unwrap() {
                SessionEvent::Ready { transport_id } => return transport_id,
                SessionEvent::Failed { error, .. } => panic!("terminal failed: {error}"),
                _ => {}
            }
        }
    })
    .await
    .unwrap()
}

async fn entries(
    manager: &SessionManager,
    store: &Arc<Store>,
    transport: &str,
    condition: impl Fn(&[SessionForwardSnapshot]) -> bool,
) -> Vec<SessionForwardSnapshot> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let entries = manager.forward_list(store, "terminal", transport).unwrap();
            if condition(&entries) {
                return entries;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("attached state reached its expected result")
}

async fn exchange(port: u16, socks: bool) {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    if socks {
        socket.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0; 2];
        socket.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        let mut request = vec![5, 1, 0, 3, 14];
        request.extend_from_slice(b"target.example");
        request.extend_from_slice(&4242u16.to_be_bytes());
        socket.write_all(&request).await.unwrap();
        let mut reply = [0; 10];
        socket.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    }
    let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    socket.write_all(&payload).await.unwrap();
    let mut received = vec![0; payload.len()];
    socket.read_exact(&mut received).await.unwrap();
    assert_eq!(received, payload);
    socket.shutdown().await.unwrap();
}

async fn shell(
    manager: &SessionManager,
    transport: &str,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) {
    manager.input("terminal", transport, b"terminal remains usable\n".to_vec()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut all = Vec::new();
        loop {
            all.extend(output.recv().await.unwrap());
            if all
                .windows(b"terminal remains usable".len())
                .any(|window| window == b"terminal remains usable")
            {
                break;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn attached_tunnels_share_authentication_report_failures_and_stop_without_closing_shell() {
    let peer = Peer::with_authentication(Authentication::Forwarding).await;
    let (_directory, store) = store();
    let host = Inventory::new(store.clone())
        .add_host(NewHost {
            name: Some("Attached peer".into()),
            address: "127.0.0.1".into(),
            port: Some(peer.port),
            username: "trust-fixture".into(),
            sign_in: SignIn::Password { password: "disposable-trust-password".into() },
        })
        .unwrap();
    let profile = Uuid::parse_str(&host.logins[0].id).unwrap();
    let local_port = unused_port().await;
    let dynamic_port = unused_port().await;
    let busy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = definition(&store, ForwardKind::Local, local_port, "target.example");
    let dynamic = definition(&store, ForwardKind::Dynamic, dynamic_port, "unused.example");
    let occupied =
        definition(&store, ForwardKind::Local, busy.local_addr().unwrap().port(), "target.example");
    let unsupported = definition(&store, ForwardKind::Remote, 0, "target.example");
    let denied_port = unused_port().await;
    let denied = definition(&store, ForwardKind::Local, denied_port, "refused.example");
    let missing = Uuid::now_v7();
    let independent_port = unused_port().await;
    let independent = definition(&store, ForwardKind::Local, independent_port, "target.example");
    Repository::<AccessProfile>::new(&store)
        .update(
            profile,
            AccessProfileChange {
                forwards: [local, dynamic, occupied, unsupported, denied, missing, independent]
                    .into_iter()
                    .map(|id| (id, true))
                    .collect(),
                ..Default::default()
            },
        )
        .unwrap();
    let forwards = ForwardManager::default();
    let independent_owner = forwards.clone();
    let independent_store = store.clone();
    let standalone = forwards
        .start(
            store.clone(),
            ForwardStartIntent::Saved {
                forward_id: independent.to_string(),
                profile_id: profile.to_string(),
            },
            move |snapshot| {
                if let Some(PreparationEvent::Trust { prompt_id, .. }) = snapshot.preparation {
                    independent_owner
                        .respond(
                            &independent_store,
                            &snapshot.run_id,
                            &prompt_id,
                            PreparationResponse::AcceptHostKey,
                        )
                        .unwrap();
                }
            },
        )
        .unwrap();
    let manager = SessionManager::with_forward_manager(forwards.clone());
    let (task, mut events, mut output) = connect(&manager, store.clone(), profile.to_string());
    let transport = ready(&mut events).await;
    let results = entries(&manager, &store, &transport, |entries| {
        entries.len() == 7
            && entries.iter().all(|entry| {
                entry.run.as_ref().is_none_or(|run| run.phase != ForwardPhase::Preparing)
            })
    })
    .await;
    let get = |id: Uuid| results.iter().find(|entry| entry.forward_id == id.to_string()).unwrap();
    assert_eq!(get(missing).issue, Some(ForwardIssue::NotFound));
    assert_eq!(get(unsupported).issue, Some(ForwardIssue::InvalidConfiguration));
    assert_eq!(get(independent).issue, Some(ForwardIssue::AlreadyRunning));
    assert_eq!(get(occupied).run.as_ref().unwrap().last_issue, Some(ForwardIssue::ListenFailed));
    for id in [local, dynamic, denied] {
        let run = get(id).run.as_ref().unwrap();
        assert_eq!(run.phase, ForwardPhase::Listening);
        let attachment = run.attachment.as_ref().unwrap();
        assert_eq!(attachment.session_id, "terminal");
        assert_eq!(attachment.transport_id, transport);
        assert_eq!(run.configuration.login().profile_id, profile.to_string());
    }
    tokio::time::timeout(Duration::from_secs(15), async {
        exchange(local_port, false).await;
        exchange(dynamic_port, true).await;
        exchange(independent_port, false).await;
        let mut socket = TcpStream::connect(("127.0.0.1", denied_port)).await.unwrap();
        socket.write_all(b"refused channel").await.unwrap();
        assert!(socket.read_u8().await.is_err());
    })
    .await
    .unwrap();
    assert_eq!(
        peer.authentications.load(Ordering::SeqCst),
        2,
        "one independent and one shared terminal authentication"
    );
    manager.forward_stop(&store, "terminal", &transport, &missing.to_string()).unwrap();
    forwards.stop(&store, &get(local).run.as_ref().unwrap().run_id).unwrap();
    entries(&manager, &store, &transport, |entries| {
        entries.iter().any(|entry| {
            entry.forward_id == local.to_string()
                && entry.stopped
                && entry.run.as_ref().unwrap().phase == ForwardPhase::Stopped
        }) && entries.iter().any(|entry| entry.forward_id == missing.to_string() && entry.stopped)
    })
    .await;
    assert!(TcpListener::bind(("127.0.0.1", local_port)).await.is_ok());
    assert_eq!(
        manager.forward_stop(&store, "terminal", &Uuid::now_v7().to_string(), &dynamic.to_string()),
        Err(ForwardIssue::Expired)
    );
    let (_other_directory, other_store) = self::store();
    assert_eq!(
        manager.forward_list(&other_store, "terminal", &transport),
        Err(ForwardIssue::Expired)
    );
    shell(&manager, &transport, &mut output).await;
    manager.close_all().unwrap();
    tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap().unwrap();
    assert!(TcpListener::bind(("127.0.0.1", dynamic_port)).await.is_ok());
    exchange(independent_port, false).await;
    assert_eq!(
        forwards.snapshot(&store, &standalone.run_id).unwrap().phase,
        ForwardPhase::Listening
    );
    forwards.stop_all().await.unwrap();
}

#[tokio::test]
async fn reconnect_releases_old_peers_rebuilds_eligible_runs_and_preserves_both_stop_paths() {
    let peer = Peer::with_authentication(Authentication::Forwarding).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let target_port = peer.port;
    let (cut, generation) = watch::channel(0u8);
    let relay = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (mut local, _) = listener.accept().await.unwrap();
            let mut cut = generation.clone();
            cut.borrow_and_update();
            connections.spawn(async move {
                let mut remote = TcpStream::connect(("127.0.0.1", target_port)).await.unwrap();
                tokio::select! {
                    _ = cut.changed() => {},
                    _ = tokio::io::copy_bidirectional(&mut local, &mut remote) => {},
                }
            });
        }
    });
    let (_directory, store) = store();
    let host = Inventory::new(store.clone())
        .add_host(NewHost {
            name: Some("Reconnect peer".into()),
            address: "127.0.0.1".into(),
            port: Some(port),
            username: "trust-fixture".into(),
            sign_in: SignIn::Password { password: "disposable-trust-password".into() },
        })
        .unwrap();
    let profile = Uuid::parse_str(&host.logins[0].id).unwrap();
    let ports = [unused_port().await, unused_port().await, unused_port().await];
    let ids = [
        definition(&store, ForwardKind::Local, ports[0], "target.example"),
        definition(&store, ForwardKind::Dynamic, ports[1], "unused.example"),
        definition(&store, ForwardKind::Local, ports[2], "target.example"),
    ];
    Repository::<AccessProfile>::new(&store)
        .update(
            profile,
            AccessProfileChange {
                forwards: ids.into_iter().map(|id| (id, true)).collect(),
                ..Default::default()
            },
        )
        .unwrap();
    let forwards = ForwardManager::default();
    let manager = SessionManager::with_forward_manager(forwards.clone());
    let (task, mut events, mut output) = connect(&manager, store.clone(), profile.to_string());
    let first = ready(&mut events).await;
    let initial = entries(&manager, &store, &first, |entries| {
        entries.len() == 3
            && entries.iter().all(|entry| {
                entry.run.as_ref().is_some_and(|run| run.phase == ForwardPhase::Listening)
            })
    })
    .await;
    let run = |id: Uuid| {
        initial
            .iter()
            .find(|entry| entry.forward_id == id.to_string())
            .unwrap()
            .run
            .as_ref()
            .unwrap()
    };
    let old_run = run(ids[2]).run_id.clone();
    let mut held = TcpStream::connect(("127.0.0.1", ports[2])).await.unwrap();
    held.write_all(b"held peer").await.unwrap();
    let mut reply = [0; 9];
    held.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"held peer");
    forwards.stop(&store, &run(ids[0]).run_id).unwrap();
    manager.forward_stop(&store, "terminal", &first, &ids[1].to_string()).unwrap();
    shell(&manager, &first, &mut output).await;
    cut.send_replace(1);
    let second = ready(&mut events).await;
    assert_ne!(first, second);
    let rebuilt = entries(&manager, &store, &second, |entries| {
        entries.iter().any(|entry| {
            entry.forward_id == ids[2].to_string()
                && entry.run.as_ref().is_some_and(|run| run.phase == ForwardPhase::Listening)
        })
    })
    .await;
    assert_eq!(rebuilt.len(), 3);
    for id in &ids[..2] {
        let entry = rebuilt.iter().find(|entry| entry.forward_id == id.to_string()).unwrap();
        assert!(entry.stopped);
        assert!(entry.run.is_none());
    }
    let replacement = rebuilt.iter().find(|entry| entry.forward_id == ids[2].to_string()).unwrap();
    assert_ne!(replacement.run.as_ref().unwrap().run_id, old_run);
    assert_eq!(forwards.snapshot(&store, &old_run).unwrap().phase, ForwardPhase::Stopped);
    assert_eq!(forwards.stop(&store, &old_run), Err(ForwardIssue::Expired));
    assert_eq!(
        manager.forward_stop(&store, "terminal", &first, &ids[2].to_string()),
        Err(ForwardIssue::Expired)
    );
    assert!(
        manager
            .forward_list(&store, "terminal", &second)
            .unwrap()
            .iter()
            .any(|entry| { entry.forward_id == ids[2].to_string() && !entry.stopped })
    );
    assert!(tokio::time::timeout(Duration::from_secs(5), held.read_u8()).await.unwrap().is_err());
    for port in &ports[..2] {
        assert!(TcpListener::bind(("127.0.0.1", *port)).await.is_ok());
    }
    exchange(ports[2], false).await;
    shell(&manager, &second, &mut output).await;
    assert_eq!(peer.authentications.load(Ordering::SeqCst), 2);
    manager.close_all().unwrap();
    tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap().unwrap();

    let (task, mut events, _output) = connect(&manager, store.clone(), profile.to_string());
    let third = ready(&mut events).await;
    entries(&manager, &store, &third, |entries| {
        entries.len() == 3
            && entries.iter().all(|entry| {
                !entry.stopped
                    && entry.run.as_ref().is_some_and(|run| run.phase == ForwardPhase::Listening)
            })
    })
    .await;
    manager.close_all().unwrap();
    tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap().unwrap();
    relay.abort();
    let _ = relay.await;
}
