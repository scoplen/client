// SPDX-License-Identifier: Apache-2.0

//! Saved standalone SOCKS tunnels against disposable OpenSSH with MaxSessions 0.

use std::{
    collections::BTreeSet,
    env, fs,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use scoplen_client_core::{
    connection::preparation::{PreparationEvent, PreparationResponse},
    forward_manager::{ForwardIssue, ForwardManager, ForwardPhase, ForwardSnapshot},
    inventory::{Inventory, NewHost, SignIn},
    repository::{
        AccessProfile, AccessProfileChange, Edit, Forward, ForwardChange, ForwardKind, Repository,
        Route, RouteChange, RouteChoice, RouteKind,
    },
    session_manager::{SessionEvent, SessionManager},
    store::Store,
};
use scoplen_crypto::{LocalDatabaseKey, SecretVec};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch},
    task::JoinSet,
};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const DEADLINE: Duration = Duration::from_secs(38);
const TRAILER: &[u8] = b"SCOPLEN-FORWARD-EOF";
const TARGET: &str = "scoplen-dynamic-target.invalid";

struct Fixture {
    store: Arc<Store>,
    manager: ForwardManager,
    password: Vec<u8>,
    key: String,
    passphrase: Vec<u8>,
    direct_port: u16,
    interactive_port: u16,
}

struct Running {
    id: String,
    forward: Uuid,
    port: u16,
    updates: mpsc::UnboundedReceiver<ForwardSnapshot>,
}

#[derive(Default)]
struct Prompts {
    ids: BTreeSet<String>,
    trust: Vec<u32>,
    passphrases: usize,
    interactive: Vec<u32>,
    revision: u64,
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 7 {
        return Err("usage: ssh_dynamic_forward_smoke <terminal-port> <no-session-port> <interactive-port> <password-file> <encrypted-key-file> <passphrase-file>".into());
    }
    let directory = tempfile::tempdir()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(Box::pin(run(&args, directory.path())))
}

async fn run(args: &[String], directory: &Path) -> Result<()> {
    let fixture = Fixture {
        store: Arc::new(Store::open(&directory.join("local.db"), &LocalDatabaseKey::new([7; 32]))?),
        manager: ForwardManager::default(),
        password: fs::read(&args[4])?,
        key: fs::read_to_string(&args[5])?,
        passphrase: fs::read(&args[6])?,
        direct_port: args[2].parse()?,
        interactive_port: args[3].parse()?,
    };
    let terminal_profile = fixture.profile("127.0.0.1", args[1].parse()?, fixture.password())?;
    let terminal = SessionManager::default();
    terminal.reserve("independent-terminal", true)?;
    let (ready_tx, mut ready_rx) = mpsc::unbounded_channel();
    let (output_tx, mut output_rx) = mpsc::unbounded_channel();
    let session = Box::pin(terminal.run(
        "independent-terminal",
        &terminal_profile,
        None,
        true,
        fixture.store.clone(),
        |event| {
            match event {
                SessionEvent::Preparation { transport_id, event } => {
                    if let PreparationEvent::Trust { prompt_id, .. } = *event {
                        terminal.respond(
                            "independent-terminal",
                            &transport_id,
                            &prompt_id,
                            PreparationResponse::AcceptHostKey,
                        )?;
                    }
                }
                SessionEvent::Ready { transport_id } => {
                    ready_tx.send(transport_id).map_err(|_| "terminal ready receiver closed")?;
                }
                SessionEvent::Failed { error, .. } => return Err(error),
                _ => {}
            }
            Ok(())
        },
        |_, bytes| output_tx.send(bytes).map_err(|_| "terminal output receiver closed".into()),
        |_, _| {},
    ));
    let exercise = Box::pin(async {
        let result = async {
            let transport = ready_rx.recv().await.ok_or("independent terminal did not start")?;
            Box::pin(exercise(&fixture, &terminal, &transport, &mut output_rx)).await
        }
        .await;
        let cleanup = fixture.manager.stop_all().await;
        let closed = terminal.close("independent-terminal");
        result?;
        cleanup?;
        closed?;
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    let (session, exercise) =
        tokio::time::timeout(Duration::from_secs(240), async { tokio::join!(session, exercise) })
            .await?;
    exercise?;
    session?;
    println!(
        "standalone OpenSSH SOCKS: Direct/key/Interactive/Jump, remote domains, concurrent binary half-close/application counters, refusal, handshake/open/copy Stop, independent terminal and no reconnect passed"
    );
    Ok(())
}

impl Fixture {
    fn password(&self) -> SignIn {
        SignIn::Password { password: String::from_utf8(self.password.clone()).unwrap() }
    }

    fn profile(&self, address: &str, port: u16, sign_in: SignIn) -> Result<String> {
        let host = Inventory::new(self.store.clone()).add_host(NewHost {
            name: Some("disposable standalone tunnel fixture".into()),
            address: address.into(),
            port: Some(port),
            username: "smoke".into(),
            sign_in,
        })?;
        Ok(host.logins[0].id.clone())
    }

    async fn start(&self, profile: &str) -> Result<Running> {
        let available = TcpListener::bind("127.0.0.1:0").await?;
        let port = available.local_addr()?.port();
        drop(available);
        let forward = self.save_forward(profile, port)?;
        self.begin(profile, forward, port)
    }

    fn save_forward(&self, profile: &str, port: u16) -> Result<Uuid> {
        Ok(Repository::<Forward>::new(&self.store)
            .create(ForwardChange {
                name: Some("disposable saved SOCKS tunnel".into()),
                kind: Some(ForwardKind::Dynamic),
                bind_address: Edit::Set("127.0.0.1".into()),
                bind_port: Edit::Set(port),
                target_host: Edit::Clear,
                target_port: Edit::Clear,
                profile: Edit::Set(Uuid::parse_str(profile)?),
            })?
            .meta
            .id)
    }

    fn begin(&self, profile: &str, forward: Uuid, port: u16) -> Result<Running> {
        let (send, updates) = mpsc::unbounded_channel();
        let initial = self.manager.start(
            self.store.clone(),
            &forward.to_string(),
            profile,
            move |snapshot| {
                let _ = send.send(snapshot);
            },
        )?;
        assert_eq!(initial.phase, ForwardPhase::Preparing);
        assert!(initial.bound_address.is_none());
        assert_dynamic(&initial)?;
        Ok(Running { id: initial.run_id, forward, port, updates })
    }

    async fn prepare(&self, run: &mut Running, expected: ForwardPhase) -> Result<Prompts> {
        let mut prompts = Prompts::default();
        tokio::time::timeout(DEADLINE, async {
            loop {
                let snapshot = run.updates.recv().await.ok_or("forward observer closed")?;
                let revision = snapshot.revision.parse::<u64>()?;
                assert!(revision > prompts.revision);
                prompts.revision = revision;
                if snapshot.phase == expected {
                    return Ok::<(), Box<dyn std::error::Error>>(());
                }
                if snapshot.phase == ForwardPhase::Failed {
                    return Err(format!("forward failed: {:?}", snapshot.last_issue).into());
                }
                if snapshot.phase == ForwardPhase::Preparing {
                    assert!(snapshot.bound_address.is_none());
                }
                match snapshot.preparation {
                    Some(PreparationEvent::Trust { context, prompt_id, host_key })
                        if prompts.ids.insert(prompt_id.clone()) =>
                    {
                        assert!(!host_key.changed);
                        assert!(TcpStream::connect(("127.0.0.1", run.port)).await.is_err());
                        prompts.trust.push(context.position);
                        self.manager.respond(
                            &self.store,
                            &run.id,
                            &prompt_id,
                            PreparationResponse::AcceptHostKey,
                        )?;
                    }
                    Some(PreparationEvent::Passphrase { context, prompt_id, incorrect })
                        if prompts.ids.insert(prompt_id.clone()) =>
                    {
                        assert!(prompts.trust.contains(&context.position));
                        prompts.passphrases += 1;
                        self.manager.respond(
                            &self.store,
                            &run.id,
                            &prompt_id,
                            PreparationResponse::Passphrase(SecretVec::new(if incorrect {
                                self.passphrase.clone()
                            } else {
                                b"wrong-disposable-passphrase".to_vec()
                            })),
                        )?;
                    }
                    Some(PreparationEvent::KeyboardInteractive {
                        context,
                        prompt_id,
                        prompts: questions,
                        ..
                    }) if prompts.ids.insert(prompt_id.clone()) => {
                        assert!(prompts.trust.contains(&context.position));
                        let answers = if questions.is_empty() {
                            Vec::new()
                        } else {
                            assert_eq!(questions.len(), 1);
                            assert!(!questions[0].echo);
                            prompts.interactive.push(context.position);
                            vec![self.password.clone()]
                        };
                        self.manager.respond(
                            &self.store,
                            &run.id,
                            &prompt_id,
                            PreparationResponse::keyboard_interactive(answers)?,
                        )?;
                    }
                    _ => {}
                }
            }
        })
        .await??;
        Ok(prompts)
    }

    async fn wait(
        &self,
        run: &Running,
        predicate: impl Fn(&ForwardSnapshot) -> bool,
    ) -> Result<ForwardSnapshot> {
        tokio::time::timeout(DEADLINE, async {
            loop {
                let snapshot = self.manager.snapshot(&self.store, &run.id)?;
                if predicate(&snapshot) {
                    return Ok::<_, Box<dyn std::error::Error>>(snapshot);
                }
                if matches!(snapshot.phase, ForwardPhase::Stopped | ForwardPhase::Failed) {
                    return Err(format!("unexpected terminal snapshot: {snapshot:?}").into());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?
    }

    async fn stop(&self, run: &Running) -> Result<ForwardSnapshot> {
        self.manager.stop(&self.store, &run.id)?;
        let snapshot = self.wait(run, |s| s.phase == ForwardPhase::Stopped).await?;
        assert_eq!(snapshot.active_connections, 0);
        assert!(snapshot.bound_address.is_none());
        let available = TcpListener::bind(("127.0.0.1", run.port)).await?;
        drop(available);
        Ok(snapshot)
    }
}

fn assert_dynamic(snapshot: &ForwardSnapshot) -> Result<()> {
    let configuration = serde_json::to_value(&snapshot.configuration)?;
    assert_eq!(configuration["kind"], "dynamic");
    assert_eq!(configuration["bindAddress"], "127.0.0.1");
    assert!(configuration.get("targetHost").is_none());
    assert!(configuration.get("targetPort").is_none());
    Ok(())
}

async fn exercise(
    fixture: &Fixture,
    terminal: &SessionManager,
    transport: &str,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<()> {
    if let Ok(addresses) =
        tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((TARGET, 2300)))
            .await?
    {
        assert!(
            addresses.into_iter().all(|address| !address.ip().is_loopback()),
            "fixture target unexpectedly maps to client loopback",
        );
    }
    let direct = fixture.profile("127.0.0.1", fixture.direct_port, fixture.password())?;
    let mut run = fixture.start(&direct).await?;
    let prompts = fixture.prepare(&mut run, ForwardPhase::Listening).await?;
    assert_eq!(prompts.trust, vec![1]);
    assert_eq!(prompts.passphrases, 0);
    assert!(prompts.interactive.is_empty());
    assert_eq!(
        fixture.manager.start(fixture.store.clone(), &run.forward.to_string(), &direct, |_| {}),
        Err(ForwardIssue::AlreadyRunning),
    );
    let first = binary_payload(0, 262_149);
    let second = binary_payload(71, 393_223);
    let first_peer = socks4(run.port, true, 2300, &first[..127]).await?;
    let second_peer = socks5(run.port, TARGET, 2300, &second[..113]).await?;
    fixture.wait(&run, |s| s.active_connections == 2).await?;
    let (data, alive) = tokio::join!(
        echo_pair(first_peer, &first, 127, second_peer, &second, 113),
        terminal_probe(terminal, transport, output, "CONCURRENT"),
    );
    data?;
    alive?;
    let uploaded = first.len() + second.len();
    let downloaded = uploaded + 2 * TRAILER.len();
    let counts = fixture
        .wait(&run, |s| {
            s.active_connections == 0
                && s.uploaded_bytes == uploaded.to_string()
                && s.downloaded_bytes == downloaded.to_string()
        })
        .await?;
    assert_eq!(counts.rejected_connections, "0");
    assert_dynamic(&counts)?;

    Repository::<Forward>::new(&fixture.store).update(
        run.forward,
        ForwardChange {
            name: Some("edited saved definition".into()),
            kind: Some(ForwardKind::Local),
            target_host: Edit::Set("irrelevant.example".into()),
            target_port: Edit::Set(1),
            ..Default::default()
        },
    )?;
    Repository::<Forward>::new(&fixture.store).delete(run.forward)?;
    assert_eq!(
        fixture.manager.snapshot(&fixture.store, &run.id)?.configuration,
        counts.configuration,
    );
    let after_delete = b"saved snapshot remains live\0\xff";
    echo(run.port, after_delete).await?;
    let empty = socks4(run.port, false, 2300, &[]).await?;
    echo_stream(empty, &[], 0).await?;
    fixture
        .wait(&run, |s| {
            s.active_connections == 0
                && s.uploaded_bytes == (uploaded + after_delete.len()).to_string()
                && s.downloaded_bytes
                    == (downloaded + after_delete.len() + 2 * TRAILER.len()).to_string()
        })
        .await?;
    let final_counts = fixture.stop(&run).await?;
    assert_eq!(final_counts.rejected_connections, "0");
    assert_eq!(final_counts.uploaded_bytes, (uploaded + after_delete.len()).to_string());
    assert_eq!(
        final_counts.downloaded_bytes,
        (downloaded + after_delete.len() + 2 * TRAILER.len()).to_string()
    );
    terminal_probe(terminal, transport, output, "AFTER-STOP").await?;

    for (sign_in, port, keys, interactive) in [
        (SignIn::KeyText { key: fixture.key.clone() }, fixture.direct_port, 2, vec![]),
        (SignIn::KeyboardInteractive, fixture.interactive_port, 0, vec![1]),
    ] {
        let profile = fixture.profile("127.0.0.1", port, sign_in)?;
        let mut run = fixture.start(&profile).await?;
        let prompts = fixture.prepare(&mut run, ForwardPhase::Listening).await?;
        assert_eq!(prompts.trust, vec![1]);
        assert_eq!(prompts.passphrases, keys);
        assert_eq!(prompts.interactive, interactive);
        echo(run.port, b"key or Interactive\0\xff").await?;
        fixture.stop(&run).await?;
    }

    let jump_relay = Relay::start(fixture.interactive_port).await?;
    let hop = fixture.profile("127.0.0.1", jump_relay.port, SignIn::KeyboardInteractive)?;
    let target =
        fixture.profile("localhost", 2223, SignIn::KeyText { key: fixture.key.clone() })?;
    let route = Repository::<Route>::new(&fixture.store).create(RouteChange {
        name: Some("disposable Interactive jump".into()),
        kind: Some(RouteKind::Jump { hops: vec![Uuid::parse_str(&hop)?] }),
    })?;
    Repository::<AccessProfile>::new(&fixture.store).update(
        Uuid::parse_str(&target)?,
        AccessProfileChange {
            route: Some(RouteChoice::Route(route.meta.id)),
            ..Default::default()
        },
    )?;
    let mut jumped = fixture.start(&target).await?;
    let prompts = fixture.prepare(&mut jumped, ForwardPhase::Listening).await?;
    assert_eq!(prompts.trust, vec![1, 2]);
    assert_eq!(prompts.interactive, vec![1]);
    assert_eq!(prompts.passphrases, 2);
    let a = binary_payload(83, 131_079);
    let b = binary_payload(151, 196_613);
    let (first, second) = tokio::join!(
        socks4(jumped.port, true, 2300, &a[..17]),
        socks5(jumped.port, TARGET, 2300, &b[..31]),
    );
    let (first, second) = (first?, second?);
    fixture.wait(&jumped, |s| s.active_connections == 2).await?;
    echo_pair(first, &a, 17, second, &b, 31).await?;
    let counts = fixture
        .wait(&jumped, |s| {
            s.active_connections == 0
                && s.uploaded_bytes == (a.len() + b.len()).to_string()
                && s.downloaded_bytes == (a.len() + b.len() + 2 * TRAILER.len()).to_string()
        })
        .await?;
    assert_eq!(counts.rejected_connections, "0");
    let mut pending = TcpStream::connect(("127.0.0.1", jumped.port)).await?;
    pending.write_all(&[5]).await?;
    fixture.wait(&jumped, |s| s.active_connections == 1).await?;
    let stopped = fixture.stop(&jumped).await?;
    assert_eq!(stopped.rejected_connections, "0");
    closed_peer(&mut pending).await?;
    jump_relay.wait_closed().await?;

    refusal_and_stop(fixture, &direct).await?;
    stop_pending_open(fixture).await?;
    disconnected(fixture).await?;
    terminal_probe(terminal, transport, output, "AFTER-DISCONNECT").await?;
    Ok(())
}

async fn next_trust(run: &mut Running) -> Result<String> {
    tokio::time::timeout(DEADLINE, async {
        loop {
            let update = run.updates.recv().await.ok_or("trust event missing")?;
            if let Some(PreparationEvent::Trust { prompt_id, .. }) = update.preparation {
                return Ok::<_, Box<dyn std::error::Error>>(prompt_id);
            }
            assert_eq!(update.phase, ForwardPhase::Preparing);
        }
    })
    .await?
}

async fn refusal_and_stop(fixture: &Fixture, direct: &str) -> Result<()> {
    let occupied = TcpListener::bind("127.0.0.1:0").await?;
    let port = occupied.local_addr()?.port();
    let forward = fixture.save_forward(direct, port)?;
    let mut busy = fixture.begin(direct, forward, port)?;
    fixture.prepare(&mut busy, ForwardPhase::Failed).await?;
    assert_eq!(
        fixture.manager.snapshot(&fixture.store, &busy.id)?.last_issue,
        Some(ForwardIssue::ListenFailed)
    );
    drop(occupied);

    let untrusted = fixture.profile("127.0.0.1", fixture.direct_port, fixture.password())?;
    let mut cancelled = fixture.start(&untrusted).await?;
    let prompt = next_trust(&mut cancelled).await?;
    assert!(TcpStream::connect(("127.0.0.1", cancelled.port)).await.is_err());
    fixture.stop(&cancelled).await?;
    assert_eq!(
        fixture.manager.respond(
            &fixture.store,
            &cancelled.id,
            &prompt,
            PreparationResponse::AcceptHostKey
        ),
        Err(ForwardIssue::Expired)
    );

    let wrong = fixture.profile(
        "127.0.0.1",
        fixture.direct_port,
        SignIn::Password { password: "wrong-disposable-password".into() },
    )?;
    let mut rejected = fixture.start(&wrong).await?;
    fixture.prepare(&mut rejected, ForwardPhase::Failed).await?;
    assert_eq!(
        fixture.manager.snapshot(&fixture.store, &rejected.id)?.last_issue,
        Some(ForwardIssue::PreparationFailed)
    );
    assert!(TcpStream::connect(("127.0.0.1", rejected.port)).await.is_err());

    let mut run = fixture.start(direct).await?;
    fixture.prepare(&mut run, ForwardPhase::Listening).await?;
    let mut peer = TcpStream::connect(("127.0.0.1", run.port)).await?;
    socks5_greeting(&mut peer).await?;
    peer.write_all(&socks5_request(TARGET, 2301)?).await?;
    assert_ne!(socks5_reply(&mut peer).await?, 0);
    closed_peer(&mut peer).await?;
    let state =
        fixture.wait(&run, |s| s.rejected_connections == "1" && s.active_connections == 0).await?;
    assert_eq!(state.phase, ForwardPhase::Listening);
    assert_eq!(state.last_issue, Some(ForwardIssue::TargetRejected));
    assert_eq!(state.uploaded_bytes, "0");
    assert_eq!(state.downloaded_bytes, "0");

    for request in [
        vec![5, 1, 2],
        vec![5, 1, 0, 5, 2, 0, 1, 127, 0, 0, 1, 8, 252],
        vec![5, 1, 0, 5, 3, 0, 1, 127, 0, 0, 1, 8, 252],
    ] {
        let mut peer = TcpStream::connect(("127.0.0.1", run.port)).await?;
        peer.write_all(&request).await?;
        let mut replies = Vec::new();
        tokio::time::timeout(DEADLINE, (&mut peer).take(64).read_to_end(&mut replies)).await??;
        if request[2] == 2 {
            assert_eq!(replies, [5, 255]);
        } else {
            assert_eq!(&replies[..2], &[5, 0]);
            assert_eq!(replies.len(), 12);
            assert_ne!(replies[3], 0);
        }
    }
    let state =
        fixture.wait(&run, |s| s.rejected_connections == "4" && s.active_connections == 0).await?;
    assert_eq!(state.last_issue, Some(ForwardIssue::HandshakeRejected));
    assert_eq!(state.uploaded_bytes, "0");
    assert_eq!(state.downloaded_bytes, "0");
    let mut slow = TcpStream::connect(("127.0.0.1", run.port)).await?;
    let accepted = tokio::time::Instant::now();
    slow.write_all(&[5, 20]).await?;
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_secs(3)).await;
        slow.write_all(&[2]).await?;
    }
    tokio::time::timeout(Duration::from_secs(6), closed_peer(&mut slow)).await??;
    assert!(accepted.elapsed() >= Duration::from_secs(14));
    assert!(accepted.elapsed() < Duration::from_secs(18));
    let state =
        fixture.wait(&run, |s| s.rejected_connections == "5" && s.active_connections == 0).await?;
    assert_eq!(state.last_issue, Some(ForwardIssue::HandshakeTimedOut));
    assert_eq!(state.uploaded_bytes, "0");
    assert_eq!(state.downloaded_bytes, "0");
    echo(run.port, b"valid peer after rejections\0\xff").await?;
    fixture.wait(&run, |s| s.active_connections == 0).await?;
    let before_stop = fixture.manager.snapshot(&fixture.store, &run.id)?;
    let mut negotiating = TcpStream::connect(("127.0.0.1", run.port)).await?;
    negotiating.write_all(&[5, 2, 0]).await?;
    let mut copying = socks5(run.port, TARGET, 2300, b"copy-in-flight").await?;
    let mut echoed = [0; 14];
    copying.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"copy-in-flight");
    fixture.wait(&run, |s| s.active_connections == 2).await?;
    let stopped = fixture.stop(&run).await?;
    assert_eq!(stopped.rejected_connections, before_stop.rejected_connections);
    closed_peer(&mut negotiating).await?;
    closed_peer(&mut copying).await?;
    Ok(())
}

async fn stop_pending_open(fixture: &Fixture) -> Result<()> {
    let relay = Relay::start(fixture.direct_port).await?;
    let profile = fixture.profile("127.0.0.1", relay.port, fixture.password())?;
    let mut run = fixture.start(&profile).await?;
    fixture.prepare(&mut run, ForwardPhase::Listening).await?;
    relay.hold.send_replace(true);
    let mut peer = TcpStream::connect(("127.0.0.1", run.port)).await?;
    socks5_greeting(&mut peer).await?;
    peer.write_all(&socks5_request(TARGET, 2300)?).await?;
    fixture.wait(&run, |s| s.active_connections == 1).await?;
    tokio::time::timeout(DEADLINE, async {
        while relay.held.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    let mut byte = [0];
    assert!(tokio::time::timeout(Duration::from_millis(100), peer.read(&mut byte)).await.is_err());
    let stopped = fixture.stop(&run).await?;
    assert_eq!(stopped.rejected_connections, "0");
    assert_eq!(stopped.uploaded_bytes, "0");
    assert_eq!(stopped.downloaded_bytes, "0");
    closed_peer(&mut peer).await?;
    relay.wait_closed().await?;
    Ok(())
}

async fn disconnected(fixture: &Fixture) -> Result<()> {
    let relay = Relay::start(fixture.direct_port).await?;
    let profile = fixture.profile("127.0.0.1", relay.port, fixture.password())?;
    let mut run = fixture.start(&profile).await?;
    fixture.prepare(&mut run, ForwardPhase::Listening).await?;
    let mut first = TcpStream::connect(("127.0.0.1", run.port)).await?;
    first.write_all(&[4, 1, 8]).await?;
    let mut second = TcpStream::connect(("127.0.0.1", run.port)).await?;
    second.write_all(&[5]).await?;
    fixture.wait(&run, |s| s.active_connections == 2).await?;
    assert_eq!(relay.connections.load(Ordering::SeqCst), 1);
    relay.cut.send_replace(true);
    let stopped = fixture.wait(&run, |s| s.phase == ForwardPhase::Failed).await?;
    assert_eq!(stopped.last_issue, Some(ForwardIssue::ConnectionLost));
    assert_eq!(stopped.active_connections, 0);
    assert!(stopped.bound_address.is_none());
    closed_peer(&mut first).await?;
    closed_peer(&mut second).await?;
    relay.wait_closed().await?;
    let available = TcpListener::bind(("127.0.0.1", run.port)).await?;
    drop(available);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(fixture.manager.snapshot(&fixture.store, &run.id)?, stopped);
    assert_eq!(relay.connections.load(Ordering::SeqCst), 1, "tunnel automatically reconnected");
    Ok(())
}

fn binary_payload(seed: u8, length: usize) -> Vec<u8> {
    (0..length).map(|index| seed.wrapping_add(index as u8)).collect()
}

async fn socks4(port: u16, domain: bool, target: u16, prefix: &[u8]) -> Result<TcpStream> {
    tokio::time::timeout(DEADLINE, async {
        let mut peer = TcpStream::connect(("127.0.0.1", port)).await?;
        let mut request = vec![4, 1];
        request.extend_from_slice(&target.to_be_bytes());
        request.extend_from_slice(if domain { &[0, 0, 0, 1] } else { &[127, 0, 0, 1] });
        request.extend_from_slice(b"fixture-user\0");
        if domain {
            request.extend_from_slice(TARGET.as_bytes());
            request.push(0);
        }
        peer.write_all(&request[..3]).await?;
        tokio::task::yield_now().await;
        request.extend_from_slice(prefix);
        peer.write_all(&request[3..]).await?;
        let mut reply = [0; 8];
        peer.read_exact(&mut reply).await?;
        assert_eq!(&reply[..2], &[0, 90]);
        Ok::<_, Box<dyn std::error::Error>>(peer)
    })
    .await?
}

async fn socks5_greeting(peer: &mut TcpStream) -> Result<()> {
    peer.write_all(&[5]).await?;
    tokio::task::yield_now().await;
    peer.write_all(&[1, 0]).await?;
    let mut selected = [0; 2];
    peer.read_exact(&mut selected).await?;
    assert_eq!(selected, [5, 0]);
    Ok(())
}

fn socks5_request(target: &str, port: u16) -> Result<Vec<u8>> {
    let mut request = vec![5, 1, 0];
    match target.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            request.extend_from_slice(&[3, u8::try_from(target.len())?]);
            request.extend_from_slice(target.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

async fn socks5_reply(peer: &mut TcpStream) -> Result<u8> {
    let mut header = [0; 4];
    peer.read_exact(&mut header).await?;
    assert_eq!(header[0], 5);
    assert_eq!(header[2], 0);
    let length = match header[3] {
        1 => 4,
        4 => 16,
        3 => usize::from(peer.read_u8().await?),
        _ => return Err("invalid SOCKS5 response address".into()),
    };
    let mut address = vec![0; length + 2];
    peer.read_exact(&mut address).await?;
    Ok(header[1])
}

async fn socks5(port: u16, target: &str, target_port: u16, prefix: &[u8]) -> Result<TcpStream> {
    tokio::time::timeout(DEADLINE, async {
        let mut peer = TcpStream::connect(("127.0.0.1", port)).await?;
        socks5_greeting(&mut peer).await?;
        let mut request = socks5_request(target, target_port)?;
        request.extend_from_slice(prefix);
        peer.write_all(&request).await?;
        assert_eq!(socks5_reply(&mut peer).await?, 0);
        Ok::<_, Box<dyn std::error::Error>>(peer)
    })
    .await?
}

async fn echo(port: u16, payload: &[u8]) -> Result<()> {
    let sent = payload.len().min(127);
    echo_stream(socks5(port, TARGET, 2300, &payload[..sent]).await?, payload, sent).await
}

async fn echo_pair(
    mut first: TcpStream,
    first_payload: &[u8],
    first_prefix: usize,
    mut second: TcpStream,
    second_payload: &[u8],
    second_prefix: usize,
) -> Result<()> {
    tokio::time::timeout(DEADLINE, async {
        assert!(first_prefix > 0);
        assert!(second_prefix > 0);
        let mut first_echo = vec![0; first_prefix];
        let mut second_echo = vec![0; second_prefix];
        let (a, b) =
            tokio::join!(first.read_exact(&mut first_echo), second.read_exact(&mut second_echo),);
        a?;
        b?;
        assert_eq!(first_echo, first_payload[..first_prefix]);
        assert_eq!(second_echo, second_payload[..second_prefix]);
        // Neither peer sends its remaining payload or EOF until both prefixes arrive.
        let (a, b) = tokio::join!(
            echo_stream(first, &first_payload[first_prefix..], 0),
            echo_stream(second, &second_payload[second_prefix..], 0),
        );
        a?;
        b?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await?
}

async fn echo_stream(mut stream: TcpStream, payload: &[u8], already_sent: usize) -> Result<()> {
    tokio::time::timeout(DEADLINE, async {
        let (read, mut write) = stream.split();
        let send = async {
            write.write_all(&payload[already_sent..]).await?;
            write.shutdown().await
        };
        let mut received = Vec::new();
        let mut limited = read.take((payload.len() + TRAILER.len() + 1) as u64);
        let receive = limited.read_to_end(&mut received);
        let (sent, read) = tokio::join!(send, receive);
        sent?;
        read?;
        assert_eq!(received.len(), payload.len() + TRAILER.len());
        assert_eq!(&received[..payload.len()], payload);
        assert_eq!(&received[payload.len()..], TRAILER);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await?
}
async fn closed_peer(peer: &mut TcpStream) -> Result<()> {
    let mut byte = [0; 1];
    match tokio::time::timeout(DEADLINE, peer.read(&mut byte)).await? {
        Ok(0) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok(())
        }
        result => Err(format!("peer was not closed: {result:?}").into()),
    }
}

async fn terminal_probe(
    manager: &SessionManager,
    transport: &str,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    label: &str,
) -> Result<()> {
    let marker = format!("SCOPLEN-FORWARD-{label}");
    manager.input(
        "independent-terminal",
        transport,
        format!("printf '%s%s\\n' SCOPLEN-FORWARD- {label}\n").into_bytes(),
    )?;
    tokio::time::timeout(DEADLINE, async {
        let mut bytes = Vec::new();
        loop {
            bytes.extend(output.recv().await.ok_or("independent terminal ended")?);
            if bytes.windows(marker.len()).any(|part| part == marker.as_bytes()) {
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
            if bytes.len() > 64 * 1024 {
                return Err("independent terminal produced too much output".into());
            }
        }
    })
    .await?
}

struct Relay {
    port: u16,
    cut: watch::Sender<bool>,
    hold: watch::Sender<bool>,
    held: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Relay {
    async fn start(target: u16) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let (cut, generation) = watch::channel(false);
        let (hold, holding) = watch::channel(false);
        let held = Arc::new(AtomicUsize::new(0));
        let observed_held = held.clone();
        let connections = Arc::new(AtomicUsize::new(0));
        let observed = connections.clone();
        let active = Arc::new(AtomicUsize::new(0));
        let observed_active = active.clone();
        let task = tokio::spawn(async move {
            let mut peers = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut local, _) = accepted?;
                        observed.fetch_add(1, Ordering::SeqCst);
                        observed_active.fetch_add(1, Ordering::SeqCst);
                        let active = RelayPeer(observed_active.clone());
                        let mut cut = generation.clone();
                        let mut hold = holding.clone();
                        let held = observed_held.clone();
                        peers.spawn(async move {
                            let _active = active;
                            let remote = TcpStream::connect(("127.0.0.1", target)).await?;
                            let (mut local_read, mut local_write) = local.split();
                            let (mut remote_read, mut remote_write) = remote.into_split();
                            let downstream = async {
                                let mut buffer = [0; 32 * 1024];
                                loop {
                                    let count = remote_read.read(&mut buffer).await?;
                                    if count == 0 { return Ok::<(), std::io::Error>(()); }
                                    if *hold.borrow() {
                                        held.fetch_add(count, Ordering::SeqCst);
                                        while *hold.borrow() {
                                            hold.changed().await.map_err(|_| std::io::ErrorKind::BrokenPipe)?;
                                        }
                                    }
                                    local_write.write_all(&buffer[..count]).await?;
                                }
                            };
                            tokio::select! {
                                _ = cut.changed() => {},
                                result = tokio::io::copy(&mut local_read, &mut remote_write) => { result?; },
                                result = downstream => { result?; },
                            }
                            Ok::<(), std::io::Error>(())
                        });
                    }
                    Some(result) = peers.join_next(), if !peers.is_empty() => { result??; },
                }
            }
        });
        Ok(Self { port, cut, hold, held, connections, active, task })
    }

    async fn wait_closed(&self) -> Result<()> {
        tokio::time::timeout(DEADLINE, async {
            while self.active.load(Ordering::SeqCst) != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        Ok(())
    }
}

struct RelayPeer(Arc<AtomicUsize>);

impl Drop for RelayPeer {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}
