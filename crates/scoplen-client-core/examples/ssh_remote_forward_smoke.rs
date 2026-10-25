// SPDX-License-Identifier: Apache-2.0

//! Saved Remote tunnels against disposable OpenSSH, without session channels.

use std::{
    collections::BTreeSet,
    env, fs,
    net::SocketAddr,
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
    inventory::{ForwardInput, ForwardKindInput, Inventory, NewHost, SignIn},
    repository::{
        AccessProfile, AccessProfileChange, Repository, Route, RouteChange, RouteChoice, RouteKind,
    },
    session_manager::{SessionEvent, SessionManager},
    store::Store,
};
use scoplen_crypto::{LocalDatabaseKey, SecretVec};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::Command,
    sync::{Barrier, mpsc, watch},
    task::JoinSet,
};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const DEADLINE: Duration = Duration::from_secs(38);
const TRAILER: &[u8] = b"SCOPLEN-REMOTE-EOF";
const REMOTE_PORT: u16 = 2300;

struct Fixture {
    store: Arc<Store>,
    manager: ForwardManager,
    password: Vec<u8>,
    key: String,
    passphrase: Vec<u8>,
    direct_port: u16,
    interactive_port: u16,
    forced_scope_port: u16,
    denied_port: u16,
    published_port: u16,
    container: String,
}

struct Running {
    id: String,
    forward: String,
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
    if args.len() != 11 {
        return Err("usage: ssh_remote_forward_smoke <terminal-port> <no-session-port> <interactive-port> <forced-scope-port> <denied-port> <remote-published-port> <password-file> <encrypted-key-file> <passphrase-file> <owned-container>".into());
    }
    if !args[10].starts_with("scoplen-remote-forward-")
        || !args[10].bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("expected the owned disposable remote-forward container".into());
    }
    let directory = tempfile::tempdir()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(run(&args, directory.path())))
}

async fn run(args: &[String], directory: &Path) -> Result<()> {
    let fixture = Fixture {
        store: Arc::new(Store::open(&directory.join("local.db"), &LocalDatabaseKey::new([7; 32]))?),
        manager: ForwardManager::default(),
        password: fs::read(&args[7])?,
        key: fs::read_to_string(&args[8])?,
        passphrase: fs::read(&args[9])?,
        direct_port: args[2].parse()?,
        interactive_port: args[3].parse()?,
        forced_scope_port: args[4].parse()?,
        denied_port: args[5].parse()?,
        published_port: args[6].parse()?,
        container: args[10].clone(),
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
            exercise(&fixture, &terminal, &transport, &mut output_rx).await
        }
        .await;
        let _ = fixture.manager.stop_all().await;
        let closed = terminal.close("independent-terminal");
        result?;
        closed?;
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    let (session, exercise) =
        tokio::time::timeout(Duration::from_secs(240), async { tokio::join!(session, exercise) })
            .await?;
    exercise?;
    session?;
    println!(
        "standalone OpenSSH Remote: Direct/key/Interactive/Jump, fixed local targets, concurrent binary half-close/counters, GatewayPorts scope, refusal/recovery, Stop, SSH loss, owned cleanup and independent terminal passed"
    );
    Ok(())
}

impl Fixture {
    fn password(&self) -> SignIn {
        SignIn::Password { password: String::from_utf8(self.password.clone()).unwrap() }
    }

    fn profile(&self, address: &str, port: u16, sign_in: SignIn) -> Result<String> {
        let host = Inventory::new(self.store.clone()).add_host(NewHost {
            name: Some("disposable Remote tunnel fixture".into()),
            address: address.into(),
            port: Some(port),
            username: "smoke".into(),
            sign_in,
        })?;
        Ok(host.logins[0].id.clone())
    }

    fn start(&self, profile: &str, bind: &str, port: u16, target: SocketAddr) -> Result<Running> {
        let forward = Inventory::new(self.store.clone()).create_forward(ForwardInput {
            name: "disposable saved Remote tunnel".into(),
            kind: ForwardKindInput::Remote,
            bind_address: bind.into(),
            bind_port: u32::from(port),
            target_host: Some("localhost".into()),
            target_port: Some(u32::from(target.port())),
            profile: Some(profile.into()),
        })?;
        let (send, updates) = mpsc::unbounded_channel();
        let initial =
            self.manager.start(self.store.clone(), &forward.id, profile, move |snapshot| {
                let _ = send.send(snapshot);
            })?;
        assert_eq!(initial.phase, ForwardPhase::Preparing);
        assert!(initial.bound_address.is_none());
        assert!(
            matches!(initial.configuration, ForwardConfiguration::Remote { bind_port, .. } if bind_port == port)
        );
        Ok(Running { id: initial.run_id, forward: forward.id, updates })
    }

    async fn prepare(&self, run: &mut Running, expected: ForwardPhase) -> Result<Prompts> {
        let mut prompts = Prompts::default();
        tokio::time::timeout(DEADLINE, async {
            loop {
                let snapshot = run.updates.recv().await.ok_or("forward observer closed")?;
                let revision = snapshot.revision.parse::<u64>()?;
                assert!(revision > prompts.revision);
                prompts.revision = revision;
                assert!(snapshot.bound_address.is_none());
                if snapshot.phase == expected {
                    return Ok::<(), Box<dyn std::error::Error>>(());
                }
                if snapshot.phase == ForwardPhase::Failed {
                    return Err(format!("Remote failed: {:?}", snapshot.last_issue).into());
                }
                match snapshot.preparation {
                    Some(PreparationEvent::Trust { context, prompt_id, host_key })
                        if prompts.ids.insert(prompt_id.clone()) =>
                    {
                        assert!(!host_key.changed);
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
                    return Err(format!("unexpected terminal Remote snapshot: {snapshot:?}").into());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?
    }

    async fn stop(&self, run: &Running) -> Result<ForwardSnapshot> {
        self.manager.stop(&self.store, &run.id)?;
        let snapshot = self.wait(run, |state| state.phase == ForwardPhase::Stopped).await?;
        assert_eq!(snapshot.active_connections, 0);
        self.no_listener(REMOTE_PORT).await?;
        Ok(snapshot)
    }

    async fn listeners(&self) -> Result<String> {
        let result = Command::new("docker")
            .args(["exec", &self.container, "/bin/busybox", "netstat", "-ltn"])
            .output()
            .await?;
        if !result.status.success() || result.stdout.len() > 32 * 1024 {
            return Err("could not inspect owned OpenSSH listeners".into());
        }
        Ok(String::from_utf8(result.stdout)?)
    }

    async fn no_listener(&self, port: u16) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let ending = format!(":{port}");
                if !self.listeners().await?.split_whitespace().any(|field| field.ends_with(&ending))
                {
                    return Ok::<(), Box<dyn std::error::Error>>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?
    }
}

async fn exercise(
    fixture: &Fixture,
    terminal: &SessionManager,
    transport: &str,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<()> {
    let direct = fixture.profile("127.0.0.1", fixture.direct_port, fixture.password())?;
    let echo = Echo::start(true).await?;
    let mut run = fixture.start(&direct, "0.0.0.0", REMOTE_PORT, echo.address)?;
    let prompts = fixture.prepare(&mut run, ForwardPhase::Listening).await?;
    assert_eq!(prompts.trust, vec![1]);
    let first = binary_payload(11, 262_149);
    let second = binary_payload(71, 393_223);
    let (data, alive) = tokio::join!(
        async {
            tokio::try_join!(
                roundtrip(fixture.published_port, &first),
                roundtrip(fixture.published_port, &second)
            )
        },
        terminal_probe(terminal, transport, output, "CONCURRENT"),
    );
    data?;
    alive?;
    let payload = first.len() + second.len();
    let counts = fixture
        .wait(&run, |state| {
            state.active_connections == 0
                && state.downloaded_bytes == payload.to_string()
                && state.uploaded_bytes == (payload + 2 * TRAILER.len()).to_string()
        })
        .await?;
    assert_eq!(counts.rejected_connections, "0");
    assert_eq!(echo.connections.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture.manager.start(fixture.store.clone(), &run.forward, &direct, |_| {}),
        Err(ForwardIssue::AlreadyRunning)
    );
    Inventory::new(fixture.store.clone()).update_forward(
        run.forward.clone(),
        ForwardInput {
            name: "changed saved definition".into(),
            kind: ForwardKindInput::Local,
            bind_address: "127.0.0.1".into(),
            bind_port: 8080,
            target_host: Some("irrelevant.example".into()),
            target_port: Some(1),
            profile: None,
        },
    )?;
    Inventory::new(fixture.store.clone()).delete_forward(run.forward.clone())?;
    assert_eq!(
        fixture.manager.snapshot(&fixture.store, &run.id)?.configuration,
        counts.configuration
    );
    let (a, b) = tokio::join!(
        roundtrip(fixture.published_port, &[]),
        roundtrip(fixture.published_port, &[])
    );
    a?;
    b?;
    let stopped = fixture.stop(&run).await?;
    assert_eq!(stopped.downloaded_bytes, counts.downloaded_bytes);
    assert_eq!(stopped.uploaded_bytes, (payload + 4 * TRAILER.len()).to_string());

    for (sign_in, port, key_prompts, interactive) in [
        (SignIn::KeyText { key: fixture.key.clone() }, fixture.direct_port, 2, vec![]),
        (SignIn::KeyboardInteractive, fixture.interactive_port, 0, vec![1]),
    ] {
        let profile = fixture.profile("127.0.0.1", port, sign_in)?;
        let echo = Echo::start(false).await?;
        let mut run = fixture.start(&profile, "0.0.0.0", REMOTE_PORT, echo.address)?;
        let prompts = fixture.prepare(&mut run, ForwardPhase::Listening).await?;
        assert_eq!(prompts.trust, vec![1]);
        assert_eq!(prompts.passphrases, key_prompts);
        assert_eq!(prompts.interactive, interactive);
        roundtrip(fixture.published_port, b"authenticated Remote\0\xff").await?;
        fixture.stop(&run).await?;
    }

    let relay = Relay::start(fixture.direct_port).await?;
    let hop = fixture.profile("127.0.0.1", relay.port, fixture.password())?;
    let jumped =
        fixture.profile("localhost", 2223, SignIn::KeyText { key: fixture.key.clone() })?;
    let route = Repository::<Route>::new(&fixture.store).create(RouteChange {
        name: Some("disposable Remote jump".into()),
        kind: Some(RouteKind::Jump { hops: vec![Uuid::parse_str(&hop)?] }),
    })?;
    Repository::<AccessProfile>::new(&fixture.store).update(
        Uuid::parse_str(&jumped)?,
        AccessProfileChange {
            route: Some(RouteChoice::Route(route.meta.id)),
            ..Default::default()
        },
    )?;
    let echo = Echo::start(true).await?;
    let mut run = fixture.start(&jumped, "0.0.0.0", REMOTE_PORT, echo.address)?;
    let prompts = fixture.prepare(&mut run, ForwardPhase::Listening).await?;
    assert_eq!(prompts.trust, vec![1, 2]);
    assert_eq!(prompts.passphrases, 2);
    let a = binary_payload(83, 131_079);
    let b = binary_payload(151, 196_613);
    tokio::try_join!(roundtrip(fixture.published_port, &a), roundtrip(fixture.published_port, &b))?;
    fixture
        .wait(&run, |state| {
            state.active_connections == 0
                && state.downloaded_bytes == (a.len() + b.len()).to_string()
        })
        .await?;
    fixture.stop(&run).await?;
    relay.wait_closed().await?;
    assert_eq!(relay.connections.load(Ordering::SeqCst), 1);

    scope_and_refusal(fixture, &direct).await?;
    stop_and_loss(fixture, &direct).await?;
    local_half_close(fixture, &direct).await?;
    terminal_probe(terminal, transport, output, "AFTER-STOP-AND-LOSS").await?;
    let echo = Echo::start(false).await?;
    let mut first = fixture.start(&direct, "0.0.0.0", REMOTE_PORT, echo.address)?;
    let mut second = fixture.start(&direct, "0.0.0.0", 2302, echo.address)?;
    fixture.prepare(&mut first, ForwardPhase::Listening).await?;
    fixture.prepare(&mut second, ForwardPhase::Listening).await?;
    let began = tokio::time::Instant::now();
    assert_eq!(fixture.manager.stop_all().await, Err(ForwardIssue::ShutdownFailed));
    assert_eq!(fixture.manager.snapshot(&fixture.store, &first.id)?.phase, ForwardPhase::Stopped);
    assert_eq!(fixture.manager.snapshot(&fixture.store, &second.id)?.phase, ForwardPhase::Stopped);
    assert!(began.elapsed() < Duration::from_secs(35));
    fixture.no_listener(REMOTE_PORT).await?;
    fixture.no_listener(2302).await?;
    fixture.manager.shutdown()?;
    assert_eq!(
        fixture.manager.start(fixture.store.clone(), &first.forward, &direct, |_| {}),
        Err(ForwardIssue::Unavailable)
    );
    Ok(())
}

async fn scope_and_refusal(fixture: &Fixture, direct: &str) -> Result<()> {
    let echo = Echo::start(false).await?;
    let mut loopback = fixture.start(direct, "127.0.0.1", REMOTE_PORT, echo.address)?;
    fixture.prepare(&mut loopback, ForwardPhase::Listening).await?;
    assert!(fixture.listeners().await?.contains("127.0.0.1:2300"));
    fixture.stop(&loopback).await?;
    let forced = fixture.profile("127.0.0.1", fixture.forced_scope_port, fixture.password())?;
    let mut overridden = fixture.start(&forced, "127.0.0.1", REMOTE_PORT, echo.address)?;
    fixture.prepare(&mut overridden, ForwardPhase::Listening).await?;
    assert!(fixture.listeners().await?.contains("0.0.0.0:2300"));
    let snapshot = fixture.manager.snapshot(&fixture.store, &overridden.id)?;
    assert!(snapshot.bound_address.is_none());
    assert!(
        matches!(snapshot.configuration, ForwardConfiguration::Remote { bind_address, .. } if bind_address == "127.0.0.1")
    );
    roundtrip(fixture.published_port, b"server scope override\0\xff").await?;
    fixture.stop(&overridden).await?;

    let denied = fixture.profile("127.0.0.1", fixture.denied_port, fixture.password())?;
    for (profile, port) in [(direct, 2301), (&denied, REMOTE_PORT)] {
        let mut run = fixture.start(profile, "0.0.0.0", port, echo.address)?;
        fixture.prepare(&mut run, ForwardPhase::Failed).await?;
        let failed = fixture.manager.snapshot(&fixture.store, &run.id)?;
        assert_eq!(failed.active_connections, 0);
        assert_eq!(failed.last_issue, Some(ForwardIssue::ShutdownFailed));
        assert_eq!(echo.connections.load(Ordering::SeqCst), 1);
    }
    let missing = TcpListener::bind("127.0.0.1:0").await?;
    let target = missing.local_addr()?;
    drop(missing);
    let mut run = fixture.start(direct, "0.0.0.0", REMOTE_PORT, target)?;
    fixture.prepare(&mut run, ForwardPhase::Listening).await?;
    let mut refused = TcpStream::connect(("127.0.0.1", fixture.published_port)).await?;
    closed_peer(&mut refused).await?;
    let failed = fixture
        .wait(&run, |state| state.rejected_connections == "1" && state.active_connections == 0)
        .await?;
    assert_eq!(failed.last_issue, Some(ForwardIssue::TargetRejected));
    let recovered = Echo::bind(target, false).await?;
    roundtrip(fixture.published_port, b"recovered local target\0\xff").await?;
    assert_eq!(recovered.connections.load(Ordering::SeqCst), 1);
    fixture.stop(&run).await?;
    Ok(())
}

async fn stop_and_loss(fixture: &Fixture, direct: &str) -> Result<()> {
    let echo = Echo::start(false).await?;
    let untrusted = fixture.profile("127.0.0.1", fixture.direct_port, fixture.password())?;
    let mut pending = fixture.start(&untrusted, "0.0.0.0", REMOTE_PORT, echo.address)?;
    let prompt = tokio::time::timeout(DEADLINE, async {
        loop {
            let update = pending.updates.recv().await.ok_or("trust event missing")?;
            if let Some(PreparationEvent::Trust { prompt_id, .. }) = update.preparation {
                return Ok::<_, Box<dyn std::error::Error>>(prompt_id);
            }
        }
    })
    .await??;
    fixture.stop(&pending).await?;
    assert_eq!(
        fixture.manager.respond(
            &fixture.store,
            &pending.id,
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
    let mut failed = fixture.start(&wrong, "0.0.0.0", REMOTE_PORT, echo.address)?;
    fixture.prepare(&mut failed, ForwardPhase::Failed).await?;
    assert_eq!(
        fixture.manager.snapshot(&fixture.store, &failed.id)?.last_issue,
        Some(ForwardIssue::PreparationFailed)
    );
    fixture.no_listener(REMOTE_PORT).await?;

    let mut copying = fixture.start(direct, "0.0.0.0", REMOTE_PORT, echo.address)?;
    fixture.prepare(&mut copying, ForwardPhase::Listening).await?;
    let mut peer = TcpStream::connect(("127.0.0.1", fixture.published_port)).await?;
    peer.write_all(b"copy-in-flight").await?;
    let mut reflected = [0; 14];
    peer.read_exact(&mut reflected).await?;
    assert_eq!(&reflected, b"copy-in-flight");
    fixture.wait(&copying, |state| state.active_connections == 1).await?;
    let stopped = fixture.stop(&copying).await?;
    assert_eq!(stopped.rejected_connections, "0");
    closed_peer(&mut peer).await?;

    let relay = Relay::start(fixture.direct_port).await?;
    let profile = fixture.profile("127.0.0.1", relay.port, fixture.password())?;
    let mut run = fixture.start(&profile, "0.0.0.0", REMOTE_PORT, echo.address)?;
    fixture.prepare(&mut run, ForwardPhase::Listening).await?;
    let mut peer = TcpStream::connect(("127.0.0.1", fixture.published_port)).await?;
    fixture.wait(&run, |state| state.active_connections == 1).await?;
    relay.cut.send_replace(true);
    fixture.wait(&run, |state| state.phase == ForwardPhase::Failed).await?;
    closed_peer(&mut peer).await?;
    fixture.no_listener(REMOTE_PORT).await?;
    relay.wait_closed().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(relay.connections.load(Ordering::SeqCst), 1);
    Ok(())
}

async fn local_half_close(fixture: &Fixture, direct: &str) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut run = fixture.start(direct, "0.0.0.0", REMOTE_PORT, listener.local_addr()?)?;
    fixture.prepare(&mut run, ForwardPhase::Listening).await?;
    let mut peer = TcpStream::connect(("127.0.0.1", fixture.published_port)).await?;
    let (mut local, _) = listener.accept().await?;
    local.write_all(b"local EOF").await?;
    local.shutdown().await?;
    let mut greeting = Vec::new();
    tokio::time::timeout(DEADLINE, peer.read_to_end(&mut greeting)).await??;
    assert_eq!(greeting, b"local EOF");
    peer.write_all(b"after local EOF\0\xff").await?;
    peer.shutdown().await?;
    let mut later = Vec::new();
    tokio::time::timeout(DEADLINE, local.read_to_end(&mut later)).await??;
    assert_eq!(later, b"after local EOF\0\xff");
    fixture
        .wait(&run, |state| {
            state.active_connections == 0
                && state.uploaded_bytes == greeting.len().to_string()
                && state.downloaded_bytes == later.len().to_string()
        })
        .await?;
    fixture.stop(&run).await?;
    Ok(())
}

fn binary_payload(seed: u8, length: usize) -> Vec<u8> {
    (0..length).map(|index| seed.wrapping_add((index % 256) as u8)).collect()
}

async fn roundtrip(port: u16, payload: &[u8]) -> Result<()> {
    tokio::time::timeout(DEADLINE, async {
        let mut peer = TcpStream::connect(("127.0.0.1", port)).await?;
        let prefix = payload.len().min(64);
        peer.write_all(&payload[..prefix]).await?;
        let mut reflected = vec![0; prefix];
        peer.read_exact(&mut reflected).await?;
        assert_eq!(reflected, payload[..prefix]);
        peer.write_all(&payload[prefix..]).await?;
        peer.shutdown().await?;
        let mut rest = Vec::new();
        (&mut peer).take((payload.len() + TRAILER.len() + 1) as u64).read_to_end(&mut rest).await?;
        let expected = [&payload[prefix..], TRAILER].concat();
        assert_eq!(rest, expected);
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
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok(())
        }
        _ => Err("Remote peer remained usable after cleanup/refusal".into()),
    }
}

async fn terminal_probe(
    manager: &SessionManager,
    transport: &str,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    label: &str,
) -> Result<()> {
    let marker = format!("SCOPLEN-REMOTE-{label}");
    manager.input(
        "independent-terminal",
        transport,
        format!("printf '%s%s\\n' SCOPLEN-REMOTE- {label}\n").into_bytes(),
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

struct Echo {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Echo {
    async fn start(paired: bool) -> Result<Self> {
        Self::bind("127.0.0.1:0".parse()?, paired).await
    }

    async fn bind(address: SocketAddr, paired: bool) -> Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let connections = Arc::new(AtomicUsize::new(0));
        let observed = connections.clone();
        let barrier = paired.then(|| Arc::new(Barrier::new(2)));
        let task = tokio::spawn(async move {
            let mut peers = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut peer, _) = accepted?;
                        observed.fetch_add(1, Ordering::SeqCst);
                        let barrier = barrier.clone();
                        peers.spawn(async move {
                            if let Some(barrier) = barrier {
                                let mut prefix = [0; 64];
                                match peer.read_exact(&mut prefix).await {
                                    Ok(_) => { barrier.wait().await; peer.write_all(&prefix).await?; }
                                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
                                    Err(error) => return Err(error),
                                }
                            }
                            let mut bytes = [0; 32 * 1024];
                            loop {
                                let count = peer.read(&mut bytes).await?;
                                if count == 0 { peer.write_all(TRAILER).await?; peer.shutdown().await?; return Ok::<(), std::io::Error>(()); }
                                peer.write_all(&bytes[..count]).await?;
                            }
                        });
                    }
                    Some(_result) = peers.join_next(), if !peers.is_empty() => {}
                }
            }
        });
        Ok(Self { address, connections, task })
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.task.abort();
    }
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
                        let (mut peer, _) = accepted?;
                        observed.fetch_add(1, Ordering::SeqCst);
                        observed_active.fetch_add(1, Ordering::SeqCst);
                        let lease = RelayPeer(observed_active.clone());
                        let mut cut = generation.clone();
                        peers.spawn(async move {
                            let _lease = lease;
                            let mut remote = TcpStream::connect(("127.0.0.1", target)).await?;
                            tokio::select! { _ = cut.changed() => {}, result = tokio::io::copy_bidirectional(&mut peer, &mut remote) => { result?; } }
                            Ok::<(), std::io::Error>(())
                        });
                    }
                    Some(result) = peers.join_next(), if !peers.is_empty() => { result??; }
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
