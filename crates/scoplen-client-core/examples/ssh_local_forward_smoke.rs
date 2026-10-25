// SPDX-License-Identifier: Apache-2.0

//! Saved standalone local TCP tunnels against disposable OpenSSH with MaxSessions 0.

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
    forward_manager::{
        ForwardConfiguration, ForwardIssue, ForwardManager, ForwardPhase, ForwardSnapshot,
    },
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
        return Err("usage: ssh_local_forward_smoke <terminal-port> <no-session-port> <interactive-port> <password-file> <encrypted-key-file> <passphrase-file>".into());
    }
    let directory = tempfile::tempdir()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(run(&args, directory.path()))
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
    let session = terminal.run(
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
    );
    let exercise = async {
        let result = async {
            let transport = ready_rx.recv().await.ok_or("independent terminal did not start")?;
            exercise(&fixture, &terminal, &transport, &mut output_rx).await
        }
        .await;
        let cleanup = fixture.manager.stop_all().await;
        let closed = terminal.close("independent-terminal");
        result?;
        cleanup?;
        closed?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let (session, exercise) =
        tokio::time::timeout(Duration::from_secs(180), async { tokio::join!(session, exercise) })
            .await?;
    exercise?;
    session?;
    println!(
        "standalone OpenSSH forwarding: password/key/Interactive/Jump, concurrent binary half-close/counters, independent terminal, refusal, stop and disconnect passed"
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

    async fn start(&self, profile: &str, target_port: u16) -> Result<Running> {
        let available = TcpListener::bind("127.0.0.1:0").await?;
        let port = available.local_addr()?.port();
        drop(available);
        let forward = self.save_forward(profile, port, target_port)?;
        self.begin(profile, forward, port)
    }

    fn save_forward(&self, profile: &str, port: u16, target_port: u16) -> Result<Uuid> {
        Ok(Repository::<Forward>::new(&self.store)
            .create(ForwardChange {
                name: Some("disposable saved local TCP tunnel".into()),
                kind: Some(ForwardKind::Local),
                bind_address: Edit::Set("127.0.0.1".into()),
                bind_port: Edit::Set(port),
                target_host: Edit::Set("scoplen-forward-target.invalid".into()),
                target_port: Edit::Set(target_port),
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
        assert!(matches!(
            &initial.configuration,
            ForwardConfiguration::Local { target_host, .. }
                if target_host == "scoplen-forward-target.invalid"
        ));
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

async fn exercise(
    fixture: &Fixture,
    terminal: &SessionManager,
    transport: &str,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<()> {
    let direct = fixture.profile("127.0.0.1", fixture.direct_port, fixture.password())?;
    let mut run = fixture.start(&direct, 2300).await?;
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
    let first_peer = TcpStream::connect(("127.0.0.1", run.port)).await?;
    let second_peer = TcpStream::connect(("127.0.0.1", run.port)).await?;
    fixture.wait(&run, |s| s.active_connections == 2).await?;
    let (a, b, alive) = tokio::join!(
        echo_stream(first_peer, &first),
        echo_stream(second_peer, &second),
        terminal_probe(terminal, transport, output, "CONCURRENT"),
    );
    a?;
    b?;
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

    Repository::<Forward>::new(&fixture.store)
        .update(run.forward, ForwardChange { target_port: Edit::Set(1), ..Default::default() })?;
    Repository::<Forward>::new(&fixture.store).delete(run.forward)?;
    assert!(matches!(
        fixture.manager.snapshot(&fixture.store, &run.id)?.configuration,
        ForwardConfiguration::Local { target_port: 2300, .. }
    ));
    let after_delete = b"saved snapshot remains live\0\xff";
    echo(run.port, after_delete).await?;
    let final_counts = fixture.stop(&run).await?;
    assert_eq!(final_counts.uploaded_bytes, (uploaded + after_delete.len()).to_string());
    assert_eq!(
        final_counts.downloaded_bytes,
        (downloaded + after_delete.len() + TRAILER.len()).to_string()
    );
    terminal_probe(terminal, transport, output, "AFTER-STOP").await?;

    for (sign_in, port, keys, interactive) in [
        (SignIn::KeyText { key: fixture.key.clone() }, fixture.direct_port, 2, vec![]),
        (SignIn::KeyboardInteractive, fixture.interactive_port, 0, vec![1]),
    ] {
        let profile = fixture.profile("127.0.0.1", port, sign_in)?;
        let mut run = fixture.start(&profile, 2300).await?;
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
    let mut jumped = fixture.start(&target, 2300).await?;
    let prompts = fixture.prepare(&mut jumped, ForwardPhase::Listening).await?;
    assert_eq!(prompts.trust, vec![1, 2]);
    assert_eq!(prompts.interactive, vec![1]);
    assert_eq!(prompts.passphrases, 2);
    echo(jumped.port, b"independently prepared jump target\0\xff").await?;
    fixture.stop(&jumped).await?;
    jump_relay.wait_closed().await?;

    refusal_and_stop(fixture, &direct).await?;
    disconnected(fixture).await?;
    terminal_probe(terminal, transport, output, "AFTER-DISCONNECT").await?;
    Ok(())
}

async fn refusal_and_stop(fixture: &Fixture, direct: &str) -> Result<()> {
    let occupied = TcpListener::bind("127.0.0.1:0").await?;
    let port = occupied.local_addr()?.port();
    let forward = fixture.save_forward(direct, port, 2300)?;
    let mut busy = fixture.begin(direct, forward, port)?;
    fixture.prepare(&mut busy, ForwardPhase::Failed).await?;
    assert_eq!(
        fixture.manager.snapshot(&fixture.store, &busy.id)?.last_issue,
        Some(ForwardIssue::ListenFailed)
    );
    drop(occupied);

    let untrusted = fixture.profile("127.0.0.1", fixture.direct_port, fixture.password())?;
    let mut cancelled = fixture.start(&untrusted, 2300).await?;
    let prompt = tokio::time::timeout(DEADLINE, async {
        loop {
            let update = cancelled.updates.recv().await.ok_or("trust event missing")?;
            if let Some(PreparationEvent::Trust { prompt_id, .. }) = update.preparation {
                return Ok::<_, Box<dyn std::error::Error>>(prompt_id);
            }
        }
    })
    .await??;
    assert!(TcpStream::connect(("127.0.0.1", cancelled.port)).await.is_err());
    fixture.manager.stop(&fixture.store, &cancelled.id)?;
    assert_eq!(
        fixture.manager.respond(
            &fixture.store,
            &cancelled.id,
            &prompt,
            PreparationResponse::AcceptHostKey
        ),
        Err(ForwardIssue::Expired)
    );
    fixture.stop(&cancelled).await?;

    let wrong = fixture.profile(
        "127.0.0.1",
        fixture.direct_port,
        SignIn::Password { password: "wrong-disposable-password".into() },
    )?;
    let mut rejected = fixture.start(&wrong, 2300).await?;
    fixture.prepare(&mut rejected, ForwardPhase::Failed).await?;
    assert_eq!(
        fixture.manager.snapshot(&fixture.store, &rejected.id)?.last_issue,
        Some(ForwardIssue::PreparationFailed)
    );
    assert!(TcpStream::connect(("127.0.0.1", rejected.port)).await.is_err());

    let mut rejected = fixture.start(direct, 2301).await?;
    fixture.prepare(&mut rejected, ForwardPhase::Listening).await?;
    let mut peer = TcpStream::connect(("127.0.0.1", rejected.port)).await?;
    let _ = peer.write_all(b"refused target").await;
    closed_peer(&mut peer).await?;
    let state = fixture
        .wait(&rejected, |s| s.rejected_connections == "1" && s.active_connections == 0)
        .await?;
    assert_eq!(state.phase, ForwardPhase::Listening);
    assert_eq!(state.last_issue, Some(ForwardIssue::TargetRejected));
    fixture.stop(&rejected).await?;

    let mut copying = fixture.start(direct, 2300).await?;
    fixture.prepare(&mut copying, ForwardPhase::Listening).await?;
    let mut peer = TcpStream::connect(("127.0.0.1", copying.port)).await?;
    peer.write_all(b"copy-in-flight").await?;
    let mut echoed = [0; 14];
    peer.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"copy-in-flight");
    fixture.wait(&copying, |s| s.active_connections == 1).await?;
    fixture.stop(&copying).await?;
    closed_peer(&mut peer).await?;
    Ok(())
}

async fn disconnected(fixture: &Fixture) -> Result<()> {
    let relay = Relay::start(fixture.direct_port).await?;
    let profile = fixture.profile("127.0.0.1", relay.port, fixture.password())?;
    let mut run = fixture.start(&profile, 2300).await?;
    fixture.prepare(&mut run, ForwardPhase::Listening).await?;
    let mut peer = TcpStream::connect(("127.0.0.1", run.port)).await?;
    peer.write_all(b"live").await?;
    let mut echoed = [0; 4];
    peer.read_exact(&mut echoed).await?;
    assert_eq!(&echoed, b"live");
    assert_eq!(relay.connections.load(Ordering::SeqCst), 1);
    relay.cut.send_replace(true);
    let stopped = fixture.wait(&run, |s| s.phase == ForwardPhase::Failed).await?;
    assert_eq!(stopped.last_issue, Some(ForwardIssue::ConnectionLost));
    assert_eq!(stopped.active_connections, 0);
    assert!(stopped.bound_address.is_none());
    closed_peer(&mut peer).await?;
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

async fn echo(port: u16, payload: &[u8]) -> Result<()> {
    echo_stream(TcpStream::connect(("127.0.0.1", port)).await?, payload).await
}

async fn echo_stream(mut stream: TcpStream, payload: &[u8]) -> Result<()> {
    tokio::time::timeout(DEADLINE, async {
        let (read, mut write) = stream.split();
        let send = async {
            write.write_all(payload).await?;
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
    connections: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Relay {
    async fn start(target: u16) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let (cut, generation) = watch::channel(false);
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
                        peers.spawn(async move {
                            let _active = active;
                            let mut remote = TcpStream::connect(("127.0.0.1", target)).await?;
                            tokio::select! {
                                _ = cut.changed() => {},
                                result = tokio::io::copy_bidirectional(&mut local, &mut remote) => { result?; },
                            }
                            Ok::<(), std::io::Error>(())
                        });
                    }
                    Some(result) = peers.join_next(), if !peers.is_empty() => { result??; },
                }
            }
        });
        Ok(Self { port, cut, connections, active, task })
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
