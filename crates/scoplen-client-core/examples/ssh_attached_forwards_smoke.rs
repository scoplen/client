// SPDX-License-Identifier: Apache-2.0

//! Share one real target transport between shell, SFTP and Login-attached tunnels.

use std::sync::Arc;
use std::time::Duration;

use scoplen_client_core::connection::SessionTarget;
use scoplen_client_core::connection::preparation::{PreparationEvent, PreparationResponse};
use scoplen_client_core::forward_manager::{
    ForwardIssue, ForwardManager, ForwardPhase, ForwardStartIntent, SessionForwardSnapshot,
};
use scoplen_client_core::inventory::{Inventory, NewHost, SignIn};
use scoplen_client_core::personal_server::PersonalServer;
use scoplen_client_core::repository::{
    AccessProfile, AccessProfileChange, Edit, Forward, ForwardChange, ForwardKind, Repository,
    Route, RouteChange, RouteChoice, RouteKind,
};
use scoplen_client_core::session_files::{SessionDownloadStatus, SessionUploadStatus};
use scoplen_client_core::session_manager::{SessionEvent, SessionManager};
use scoplen_client_core::store::Store;
use scoplen_crypto::LocalDatabaseKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 || !matches!(args[1].as_str(), "direct" | "jump") {
        return Err(
            "usage: ssh_attached_forwards_smoke <direct|jump> <host> <ssh-port> <password-file>"
                .into(),
        );
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(run(&args)))
}

async fn unused_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0").await?.local_addr()?.port())
}

fn definition(store: &Store, kind: ForwardKind, port: u16, target: u16) -> Result<Uuid> {
    Ok(Repository::<Forward>::new(store)
        .create(ForwardChange {
            name: Some(format!("Attached {kind:?} {port}")),
            kind: Some(kind),
            bind_address: Edit::Set("127.0.0.1".into()),
            bind_port: Edit::Set(port),
            target_host: Edit::Set("127.0.0.1".into()),
            target_port: Edit::Set(target),
            profile: Edit::Set(Uuid::now_v7()),
        })?
        .meta
        .id)
}

async fn ready(events: &mut mpsc::UnboundedReceiver<SessionEvent>) -> Result<String> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match events.recv().await.ok_or("terminal event channel ended")? {
                SessionEvent::Ready { transport_id } => return Ok(transport_id),
                SessionEvent::Failed { error, .. } => return Err(error.into()),
                SessionEvent::Closed => return Err("terminal closed before ready".into()),
                _ => {}
            }
        }
    })
    .await?
}

async fn settled(
    manager: &SessionManager,
    store: &Arc<Store>,
    transport: &str,
) -> Result<Vec<SessionForwardSnapshot>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let entries = manager.forward_list(store, "terminal", transport)?;
            if entries.len() == 8
                && entries.iter().all(|entry| {
                    entry.run.as_ref().is_none_or(|run| run.phase != ForwardPhase::Preparing)
                })
            {
                return Ok(entries);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?
}

async fn traffic(port: u16, socks: bool) -> Result<()> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    if socks {
        stream.write_all(&[5, 1, 0]).await?;
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).await?;
        assert_eq!(reply, [5, 0]);
        let mut request = vec![5, 1, 0, 3, 9];
        request.extend_from_slice(b"localhost");
        request.extend_from_slice(&2300u16.to_be_bytes());
        stream.write_all(&request).await?;
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await?;
        assert_eq!(&reply[..3], &[5, 0, 0]);
        let length = match reply[3] {
            1 => 4,
            4 => 16,
            _ => return Err("unexpected SOCKS response address".into()),
        };
        stream.read_exact(&mut vec![0; length + 2]).await?;
    }
    let bytes: Vec<u8> = (0..=255).cycle().take(8192).collect();
    stream.write_all(&bytes).await?;
    let mut echoed = vec![0; bytes.len()];
    stream.read_exact(&mut echoed).await?;
    assert_eq!(echoed, bytes);
    stream.shutdown().await?;
    Ok(())
}

async fn shell(
    manager: &SessionManager,
    transport: &str,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    marker: &str,
) -> Result<()> {
    manager.input(
        "terminal",
        transport,
        format!("printf '%s%s\\n' SCOPLEN- {marker}\n").into_bytes(),
    )?;
    let marker = format!("SCOPLEN-{marker}");
    let mut received = Vec::new();
    loop {
        received.extend(output.recv().await.ok_or("shell output ended")?);
        if received.windows(marker.len()).any(|bytes| bytes == marker.as_bytes()) {
            return Ok(());
        }
        assert!(received.len() <= 65_536);
    }
}

async fn files(manager: &SessionManager, transport: &str, local: &std::path::Path) -> Result<()> {
    let source = local.join(format!("binary-{}.bin", Uuid::now_v7()));
    let expected: Vec<u8> = (0..=255).cycle().take(8192).collect();
    std::fs::write(&source, &expected)?;
    manager.list_files("terminal", transport, &Uuid::now_v7().to_string(), b".".to_vec()).await?;
    let upload = manager
        .upload_file_with_picker(
            "terminal",
            transport,
            &Uuid::now_v7().to_string(),
            b".".to_vec(),
            || async { Ok(Some(source.clone())) },
            |_| async { Err("new fixture target must not require replacement".into()) },
            |_| {},
        )
        .await?;
    assert_eq!(upload.status, SessionUploadStatus::Saved);
    let name = source.file_name().unwrap().to_str().unwrap();
    let listed = manager
        .list_files("terminal", transport, &Uuid::now_v7().to_string(), b".".to_vec())
        .await?;
    let path = listed
        .entries
        .into_iter()
        .find(|entry| entry.name == name)
        .ok_or("uploaded fixture was not listed")?
        .path;
    let destination = local.join(format!("download-{}.bin", Uuid::now_v7()));
    let download = manager
        .download_file_with_picker(
            "terminal",
            transport,
            &Uuid::now_v7().to_string(),
            path,
            || async { Ok(Some(destination.clone())) },
            |_| {},
        )
        .await?;
    assert_eq!(download.status, SessionDownloadStatus::Saved);
    assert_eq!(std::fs::read(destination)?, expected);
    Ok(())
}

async fn run(args: &[String]) -> Result<()> {
    let jump_route = args[1] == "jump";
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let target = format!("{}:{}", args[2], args[3]);
    let (cut, generation) = watch::channel(0u8);
    let relay = tokio::spawn(async move {
        let mut peers = tokio::task::JoinSet::new();
        let mut accepted = 0u32;
        while let Ok((mut local, _)) = listener.accept().await {
            accepted += 1;
            // The first connection belongs to the already-started independent run.
            let terminal = accepted > 1;
            let target = target.clone();
            let mut cut = generation.clone();
            cut.borrow_and_update();
            peers.spawn(async move {
                let mut remote = TcpStream::connect(target).await?;
                tokio::select! {
                    _ = cut.changed(), if terminal => {},
                    _ = tokio::io::copy_bidirectional(&mut local, &mut remote) => {},
                }
                Ok::<(), std::io::Error>(())
            });
        }
    });
    let scratch = tempfile::tempdir()?;
    let store = Arc::new(Store::open(
        &scratch.path().join("attached.db"),
        &LocalDatabaseKey::new([7; 32]),
    )?);
    let inventory = Inventory::new(store.clone());
    let password = std::fs::read_to_string(&args[4])?;
    let jump = inventory.add_host(NewHost {
        name: Some("Attachment Jump".into()),
        address: "127.0.0.1".into(),
        port: Some(port),
        username: "smoke".into(),
        sign_in: SignIn::Password { password: password.clone() },
    })?;
    let target = inventory.add_host(NewHost {
        name: Some("Attachment target".into()),
        address: "127.0.0.1".into(),
        port: Some(if jump_route { 2223 } else { port }),
        username: "smoke".into(),
        sign_in: SignIn::Password { password },
    })?;
    let route = Repository::<Route>::new(&store).create(RouteChange {
        name: Some("Attachment Jump route".into()),
        kind: Some(RouteKind::Jump { hops: vec![Uuid::parse_str(&jump.logins[0].id)?] }),
    })?;
    let ports =
        [unused_port().await?, unused_port().await?, unused_port().await?, unused_port().await?];
    let ids = [
        definition(&store, ForwardKind::Local, ports[0], 2300)?,
        definition(&store, ForwardKind::Dynamic, ports[1], 2300)?,
        definition(&store, ForwardKind::Local, ports[2], 2300)?,
        definition(&store, ForwardKind::Local, ports[3], 2300)?,
    ];
    let occupied = TcpListener::bind("127.0.0.1:0").await?;
    let busy = definition(&store, ForwardKind::Local, occupied.local_addr()?.port(), 2300)?;
    let unsupported = definition(&store, ForwardKind::Remote, unused_port().await?, 2300)?;
    let refused_port = unused_port().await?;
    let refused = definition(&store, ForwardKind::Local, refused_port, 2301)?;
    let missing = Uuid::now_v7();
    let hop_port = unused_port().await?;
    let hop_forward = definition(&store, ForwardKind::Local, hop_port, 2300)?;
    Repository::<AccessProfile>::new(&store).update(
        Uuid::parse_str(&jump.logins[0].id)?,
        AccessProfileChange { forwards: [(hop_forward, true)].into(), ..Default::default() },
    )?;
    Repository::<AccessProfile>::new(&store).update(
        Uuid::parse_str(&target.logins[0].id)?,
        AccessProfileChange {
            route: jump_route.then_some(RouteChoice::Route(route.meta.id)),
            forwards: ids
                .into_iter()
                .chain([busy, unsupported, refused, missing])
                .map(|id| (id, true))
                .collect(),
            ..Default::default()
        },
    )?;
    let forwards = ForwardManager::default();
    let (send, mut events) = mpsc::unbounded_channel();
    let independent = forwards.start(
        store.clone(),
        ForwardStartIntent::Saved {
            forward_id: ids[3].to_string(),
            profile_id: target.logins[0].id.clone(),
        },
        move |snapshot| {
            let _ = send.send(snapshot);
        },
    )?;
    loop {
        let state = events.recv().await.ok_or("independent tunnel ended")?;
        if let Some(PreparationEvent::Trust { prompt_id, .. }) = state.preparation {
            forwards.respond(
                &store,
                &independent.run_id,
                &prompt_id,
                PreparationResponse::AcceptHostKey,
            )?;
        }
        match state.phase {
            ForwardPhase::Listening => break,
            ForwardPhase::Failed | ForwardPhase::Stopped => {
                return Err(format!("independent fixture failed: {:?}", state.last_issue).into());
            }
            _ => {}
        }
    }
    let manager = SessionManager::with_forward_manager(forwards.clone());
    manager.reserve("terminal", true)?;
    let (send, mut events) = mpsc::unbounded_channel();
    let (bytes, mut output) = mpsc::unbounded_channel();
    let target = SessionTarget::Personal { profile_id: target.logins[0].id.clone() };
    let personal = PersonalServer::default();
    let terminal = Box::pin(manager.run_target(
        "terminal",
        &target,
        &personal,
        None,
        true,
        store.clone(),
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
            send.send(event).map_err(|_| "terminal event receiver closed".into())
        },
        |_, data| bytes.send(data).map_err(|_| "terminal output receiver closed".into()),
        |_, _| {},
    ));
    let exercise = Box::pin(async {
        let result = async {
            let first = ready(&mut events).await?;
            let initial = settled(&manager, &store, &first).await?;
            let entry =
                |id: Uuid| initial.iter().find(|entry| entry.forward_id == id.to_string()).unwrap();
            assert_eq!(
                entry(busy).run.as_ref().unwrap().last_issue,
                Some(ForwardIssue::ListenFailed)
            );
            assert_eq!(entry(unsupported).issue, Some(ForwardIssue::UnsupportedDefinition));
            assert_eq!(entry(missing).issue, Some(ForwardIssue::NotFound));
            assert_eq!(entry(ids[3]).issue, Some(ForwardIssue::AlreadyRunning));
            assert!(TcpListener::bind(("127.0.0.1", hop_port)).await.is_ok());
            traffic(ports[0], false).await?;
            traffic(ports[1], true).await?;
            traffic(ports[3], false).await?;
            let mut denied = TcpStream::connect(("127.0.0.1", refused_port)).await?;
            denied.write_all(b"channel denied").await?;
            assert!(denied.read_u8().await.is_err());
            Box::pin(files(&manager, &first, scratch.path())).await?;
            shell(&manager, &first, &mut output, "SHARED").await?;
            let old = entry(ids[2]).run.as_ref().unwrap().run_id.clone();
            let mut held = TcpStream::connect(("127.0.0.1", ports[2])).await?;
            held.write_all(b"held peer").await?;
            let mut reply = [0; 9];
            held.read_exact(&mut reply).await?;
            assert_eq!(&reply, b"held peer");
            forwards.stop(&store, &entry(ids[0]).run.as_ref().unwrap().run_id)?;
            manager.forward_stop(&store, "terminal", &first, &ids[1].to_string())?;
            Box::pin(files(&manager, &first, scratch.path())).await?;
            shell(&manager, &first, &mut output, "AFTER-STOP").await?;
            if !jump_route {
                cut.send_replace(1);
                let second = ready(&mut events).await?;
                assert_ne!(first, second);
                let rebuilt = settled(&manager, &store, &second).await?;
                for id in &ids[..2] {
                    let entry =
                        rebuilt.iter().find(|entry| entry.forward_id == id.to_string()).unwrap();
                    assert!(entry.stopped && entry.run.is_none());
                }
                let replacement =
                    rebuilt.iter().find(|entry| entry.forward_id == ids[2].to_string()).unwrap();
                assert_eq!(replacement.run.as_ref().unwrap().phase, ForwardPhase::Listening);
                assert_ne!(replacement.run.as_ref().unwrap().run_id, old);
                assert_eq!(forwards.snapshot(&store, &old)?.phase, ForwardPhase::Stopped);
                assert!(held.read_u8().await.is_err());
                for port in &ports[..2] {
                    assert!(TcpListener::bind(("127.0.0.1", *port)).await.is_ok());
                }
                traffic(ports[2], false).await?;
                traffic(ports[3], false).await?;
                Box::pin(files(&manager, &second, scratch.path())).await?;
                shell(&manager, &second, &mut output, "RECONNECTED").await?;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let _ = manager.close("terminal");
        result
    });
    let result =
        tokio::time::timeout(Duration::from_secs(90), async { tokio::join!(terminal, exercise) })
            .await;
    if result.is_err() {
        let _ = manager.close("terminal");
    }
    let independent = if matches!(&result, Ok((Ok(()), Ok(())))) {
        traffic(ports[3], false).await
    } else {
        Ok(())
    };
    let cleanup = forwards.stop_all().await;
    relay.abort();
    let _ = relay.await;
    let (terminal, exercise) = result?;
    exercise?;
    terminal?;
    independent?;
    cleanup?;
    for port in ports {
        assert!(TcpListener::bind(("127.0.0.1", port)).await.is_ok());
    }
    println!(
        "{}: real shell/SFTP/Local/SOCKS bytes, per-entry failures, both Stop paths and independent survival passed",
        args[1]
    );
    if !jump_route {
        println!(
            "Direct reconnect: old listener/peer release, eligible recreation and Stop preservation passed"
        );
    }
    Ok(())
}
