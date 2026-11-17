// SPDX-License-Identifier: Apache-2.0

//! Saved external-password Logins against disposable real OpenSSH.

use scoplen_client_core::{
    connection::{
        ConnectionRoute,
        preparation::{
            PreparationControl, PreparationEvent, PreparationResponse, prepare_connection,
        },
        probe_host_key, resolve_connection_plan,
    },
    inventory::Inventory,
    repository::{
        AccessProfile, AccessProfileChange, Credential, CredentialBinding, CredentialChange,
        CredentialKind, Edit, Host, HostChange, Repository, Route, RouteChange, RouteChoice,
        RouteKind,
    },
    session_files::{SessionDownloadStatus, SessionUploadStatus},
    session_manager::{SessionEvent, SessionManager},
    store::Store,
};
use scoplen_crypto::LocalDatabaseKey;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::TcpStream as BlockingStream,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use uuid::Uuid;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const LITERALS: [&str; 8] = ["%h", "%p", "%r", "%%", "$HOME", "|", ">", ""];

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("helper") {
        return helper(&args);
    }
    if args.len() != 5 {
        return Err("usage: ssh_command_password_smoke <target-port> <jump-port> <internal-target-port> <password-file>".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(run(&args)))
}

fn helper(args: &[String]) -> Result<()> {
    if args.len() != 15 || args[7..] != LITERALS {
        return Err("literal helper arguments changed".into());
    }
    let mut lease = BlockingStream::connect(("127.0.0.1", args[4].parse()?))?;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args[5])?
        .write_all(format!("{}\n", args[6]).as_bytes())?;
    lease.write_all(format!("{}\n", args[6]).as_bytes())?;
    if std::io::stdin().read(&mut [0])? != 0 {
        return Err("provider stdin was not null".into());
    }
    let password = Zeroizing::new(fs::read(&args[3])?);
    let mut stdout = std::io::stdout().lock();
    match args[2].as_str() {
        "empty" => {}
        "oversize" => stdout.write_all(&vec![b'x'; 17000])?,
        "wrong" => stdout.write_all(b"wrong-disposable-password")?,
        "stall" => std::thread::sleep(Duration::from_secs(60)),
        mode => {
            stdout.write_all(&password)?;
            if mode == "lf" {
                stdout.write_all(b"\n")?;
            }
            if mode == "crlf" {
                stdout.write_all(b"\r\n")?;
            }
            stdout.flush()?;
            if mode == "exit" {
                std::process::exit(7);
            }
            if mode == "no-exit" {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
    }
    stdout.flush()?;
    std::io::stderr().write_all(&vec![b'x'; 65536])?;
    drop(lease);
    Ok(())
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn provider(
    executable: &Path,
    mode: &str,
    password: &Path,
    lease: u16,
    marker: &Path,
    label: &str,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut arguments = vec![
        "helper".into(),
        mode.into(),
        password.to_str().unwrap().into(),
        lease.to_string(),
        marker.to_str().unwrap().into(),
        label.into(),
    ];
    arguments.extend(LITERALS.map(str::to_owned));
    let path = std::iter::once(quote(executable.to_str().unwrap()))
        .chain(arguments.iter().map(|value| quote(value)))
        .collect::<Vec<_>>()
        .join(" ");
    (
        BTreeMap::from([
            ("type".into(), "command".into()),
            ("path".into(), path),
            ("field".into(), "password".into()),
        ]),
        arguments,
    )
}

fn login(
    store: &Store,
    port: u16,
    provider: BTreeMap<String, String>,
    label: &str,
) -> Result<(Uuid, Uuid)> {
    let host = Repository::<Host>::new(store).create(HostChange {
        name: Some(label.into()),
        address: Some("127.0.0.1".into()),
        port: Edit::Set(port),
        ..Default::default()
    })?;
    let credential = Repository::<Credential>::new(store).create(CredentialChange {
        kind: Some(CredentialKind::ExternalProvider),
        binding: Some(CredentialBinding::None),
        provider: provider.into_iter().map(|(key, value)| (key, Some(value))).collect(),
        ..Default::default()
    })?;
    let profile = Repository::<AccessProfile>::new(store).create(AccessProfileChange {
        host: Some(host.meta.id),
        username: Some("smoke".into()),
        credential: Edit::Set(credential.meta.id),
        ..Default::default()
    })?;
    Ok((profile.meta.id, credential.meta.id))
}

struct Relay {
    task: JoinHandle<()>,
    open: Arc<AtomicUsize>,
    port: u16,
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Relay {
    async fn start(destination: u16) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let open = Arc::new(AtomicUsize::new(0));
        let count = open.clone();
        let task = tokio::spawn(async move {
            let mut peers = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut client, _)) = accepted else { break; };
                        let count = count.clone();
                        peers.spawn(async move {
                            let Ok(mut upstream) = TcpStream::connect(("127.0.0.1", destination)).await else { return; };
                            count.fetch_add(1, Ordering::SeqCst);
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                            count.fetch_sub(1, Ordering::SeqCst);
                        });
                    },
                    _ = peers.join_next(), if !peers.is_empty() => {},
                }
            }
        });
        Ok(Self { task, open, port })
    }
    async fn idle(&self) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.open.load(Ordering::SeqCst) != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "retained SSH chain was not released".into())
    }
}

async fn leases(listener: &TcpListener, labels: &[&str]) -> Result<Vec<TcpStream>> {
    let mut result = Vec::new();
    for label in labels {
        let (mut stream, _) =
            tokio::time::timeout(Duration::from_secs(10), listener.accept()).await??;
        let mut actual = vec![0; label.len() + 1];
        stream.read_exact(&mut actual).await?;
        assert_eq!(actual, format!("{label}\n").as_bytes());
        result.push(stream);
    }
    Ok(result)
}

async fn released(mut streams: Vec<TcpStream>) -> Result<()> {
    for stream in &mut streams {
        let result = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut [0])).await?;
        assert!(
            matches!(result, Ok(0))
                || result.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset),
            "owned helper retained its independent lease"
        );
    }
    Ok(())
}

async fn run(args: &[String]) -> Result<()> {
    let scratch = tempfile::tempdir()?;
    let executable =
        scratch.path().join(if cfg!(windows) { "password helper.exe" } else { "password helper" });
    fs::copy(std::env::current_exe()?, &executable)?;
    let target: u16 = args[1].parse()?;
    let jump: u16 = args[2].parse()?;
    let internal: u16 = args[3].parse()?;
    let password = Path::new(&args[4]);
    for mode in [
        "raw",
        "lf",
        "crlf",
        "jump",
        "trust-refused",
        "command-refused",
        "invalid",
        "missing",
        "wrong",
        "exit",
        "empty",
        "oversize",
        "no-exit",
        "cancel",
        "drop",
        "jump-cancel",
    ] {
        Box::pin(prepare_case(&executable, password, target, jump, internal, mode)).await?;
        println!("command password {mode}: passed");
    }
    for route in [false, true] {
        Box::pin(session_case(&executable, password, target, jump, internal, route)).await?;
    }
    Box::pin(cancelled_session(&executable, password, target)).await?;
    println!("command password real SSH acceptance passed");
    Ok(())
}

async fn prepare_case(
    executable: &Path,
    password: &Path,
    target: u16,
    jump: u16,
    internal: u16,
    mode: &str,
) -> Result<()> {
    let scratch = tempfile::tempdir()?;
    let store = Store::open(&scratch.path().join("local.db"), &LocalDatabaseKey::new([7; 32]))?;
    let marker = scratch.path().join("invocations");
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let is_jump = mode.starts_with("jump");
    let relay = Relay::start(if is_jump { jump } else { target }).await?;
    let behavior = match mode {
        "cancel" | "drop" | "jump-cancel" => "stall",
        "jump" => "raw",
        other => other,
    };
    let (mut descriptor, target_args) =
        provider(executable, behavior, password, listener.local_addr()?.port(), &marker, "target");
    if mode == "invalid" {
        descriptor.insert("unknown".into(), "value".into());
    }
    if mode == "missing" {
        descriptor.insert("path".into(), "scoplen-fixture-missing-password-helper".into());
    }
    let (profile, _) =
        login(&store, if is_jump { internal } else { relay.port }, descriptor, "Password target")?;
    let (hop_descriptor, hop_args) =
        provider(executable, "raw", password, listener.local_addr()?.port(), &marker, "hop");
    if is_jump {
        let (hop, _) = login(&store, relay.port, hop_descriptor, "Password Jump")?;
        let route = Repository::<Route>::new(&store).create(RouteChange {
            name: Some("Password Jump route".into()),
            kind: Some(RouteKind::Jump { hops: vec![hop] }),
        })?;
        Repository::<AccessProfile>::new(&store).update(
            profile,
            AccessProfileChange {
                route: Some(RouteChoice::Route(route.meta.id)),
                ..Default::default()
            },
        )?;
    }
    if mode == "raw" {
        let plan = resolve_connection_plan(&store, profile)?;
        assert!(matches!(plan.route, ConnectionRoute::Direct));
        probe_host_key(&plan).await?;
        assert!(!marker.exists(), "resolve/probe executed the helper");
    }
    let control = PreparationControl::default();
    let verified = Mutex::new(Vec::new());
    let commands = AtomicUsize::new(0);
    let events = Mutex::new(Vec::new());
    let mut preparation = Box::pin(prepare_connection(&store, profile, &control, |event| {
        events.lock().unwrap().push(format!("{event:?}"));
        match event {
            PreparationEvent::Trust { prompt_id, .. } => {
                if mode == "trust-refused" {
                    control.cancel();
                } else {
                    control.respond(&prompt_id, PreparationResponse::AcceptHostKey)?;
                }
            }
            PreparationEvent::Verified { context, .. } => {
                verified.lock().unwrap().push(context.profile_id)
            }
            PreparationEvent::CommandExecution { prompt_id, program, arguments, context } => {
                assert!(verified.lock().unwrap().contains(&context.profile_id));
                if mode != "missing" {
                    assert_eq!(program, executable.to_str().unwrap());
                    assert_eq!(
                        arguments,
                        if context.target { &target_args } else { &hop_args }.clone()
                    );
                }
                commands.fetch_add(1, Ordering::SeqCst);
                if mode == "command-refused" {
                    control.cancel();
                } else {
                    control.respond(&prompt_id, PreparationResponse::AcceptCommand)?;
                }
            }
            PreparationEvent::Progress { .. } => {}
            _ => return Err("unexpected command-password prompt".into()),
        }
        Ok(())
    }));
    let expected = if ["invalid", "missing", "trust-refused", "command-refused"].contains(&mode) {
        vec![]
    } else if is_jump {
        vec!["hop", "target"]
    } else {
        vec!["target"]
    };
    let (drop_signal, mut dropped) = watch::channel(false);
    let monitor = async {
        let streams = leases(&listener, &expected).await?;
        if ["cancel", "jump-cancel"].contains(&mode) {
            control.cancel();
        }
        if mode == "drop" {
            drop_signal.send_replace(true);
        }
        Ok::<_, Box<dyn std::error::Error>>(streams)
    };
    let execute = async {
        if mode == "drop" {
            tokio::select! { biased;
                _ = dropped.changed() => { drop(preparation); None },
                result = &mut preparation => Some(result),
            }
        } else {
            Some(preparation.await)
        }
    };
    let (result, streams) =
        tokio::time::timeout(Duration::from_secs(40), async { tokio::join!(execute, monitor) })
            .await?;
    released(streams?).await?;
    if ["raw", "lf", "crlf", "jump"].contains(&mode) {
        let connection = result.unwrap()?;
        let output =
            connection.open_session().await?.exec(b"printf '\\000\\377provider-ok'", None).await?;
        assert_eq!(output.stdout, b"\0\xffprovider-ok");
        assert_eq!(output.exit_status, Some(0));
        connection.close().await?;
    } else if mode != "drop" {
        let error = result.unwrap().err().ok_or("expected password-provider failure")?.to_string();
        let expected = match mode {
            "invalid" => "external credential is invalid",
            "missing" => "could not start",
            "wrong" => {
                "SSH authentication with the password command was rejected. Check the Login, helper and any additional factors, then reconnect."
            }
            "exit" => "password command failed",
            "empty" => "empty password",
            "oversize" => "too much output",
            "no-exit" => "timed out",
            _ => "connection was cancelled",
        };
        assert!(error.contains(expected), "{mode}: unexpected fixed failure: {error}");
        assert!(!error.contains(executable.to_str().unwrap()));
    }
    relay.idle().await?;
    if expected.is_empty() {
        assert!(!marker.exists());
        assert!(tokio::time::timeout(Duration::from_millis(100), listener.accept()).await.is_err());
    } else {
        assert_eq!(fs::read_to_string(marker)?.lines().collect::<Vec<_>>(), expected);
    }
    let password = Zeroizing::new(fs::read(password)?);
    assert!(
        !events
            .lock()
            .unwrap()
            .join("\n")
            .as_bytes()
            .windows(password.len())
            .any(|window| window == password.as_slice())
    );
    for credential in Repository::<Credential>::new(&store).list()? {
        assert!(!credential.has_secret);
        assert!(
            scoplen_client_core::repository::credential_secret(&store, credential.meta.id)?
                .is_none()
        );
        assert!(store.device_credential(credential.meta.id)?.is_none());
    }
    assert_eq!(
        commands.load(Ordering::SeqCst),
        if mode == "invalid" || mode == "trust-refused" {
            0
        } else if is_jump {
            2
        } else {
            1
        }
    );
    Ok(())
}

async fn ready(events: &mut mpsc::UnboundedReceiver<SessionEvent>) -> Result<String> {
    loop {
        match events.recv().await.ok_or("session events ended")? {
            SessionEvent::Ready { transport_id } => return Ok(transport_id),
            SessionEvent::Failed { error, .. } => return Err(error.into()),
            _ => {}
        }
    }
}

async fn files(manager: &SessionManager, transport: &str, directory: &Path) -> Result<()> {
    let source = directory.join(format!("provider-{}.bin", Uuid::now_v7()));
    let expected: Vec<u8> = (0..=255).cycle().take(8192).collect();
    fs::write(&source, &expected)?;
    manager.list_files("terminal", transport, &Uuid::now_v7().to_string(), b".".to_vec()).await?;
    let upload = manager
        .upload_file_with_picker(
            "terminal",
            transport,
            &Uuid::now_v7().to_string(),
            b".".to_vec(),
            || async { Ok(Some(source.clone())) },
            |_| async { Err("fresh fixture must not overwrite".into()) },
            |_| {},
        )
        .await?;
    assert_eq!(upload.status, SessionUploadStatus::Saved);
    let remote = manager
        .list_files("terminal", transport, &Uuid::now_v7().to_string(), b".".to_vec())
        .await?
        .entries
        .into_iter()
        .find(|entry| entry.name == source.file_name().unwrap().to_str().unwrap())
        .ok_or("uploaded file missing")?
        .path;
    let destination = directory.join("download.bin");
    let download = manager
        .download_file_with_picker(
            "terminal",
            transport,
            &Uuid::now_v7().to_string(),
            remote,
            || async { Ok(Some(destination.clone())) },
            |_| {},
        )
        .await?;
    assert_eq!(download.status, SessionDownloadStatus::Saved);
    assert_eq!(fs::read(destination)?, expected);
    Ok(())
}

async fn session_case(
    executable: &Path,
    password: &Path,
    target: u16,
    jump: u16,
    internal: u16,
    is_jump: bool,
) -> Result<()> {
    let scratch = tempfile::tempdir()?;
    let store =
        Arc::new(Store::open(&scratch.path().join("local.db"), &LocalDatabaseKey::new([7; 32]))?);
    let marker = scratch.path().join("invocations");
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay = Relay::start(if is_jump { jump } else { target }).await?;
    let (descriptor, target_args) =
        provider(executable, "raw", password, listener.local_addr()?.port(), &marker, "target");
    let (profile, _) = login(
        &store,
        if is_jump { internal } else { relay.port },
        descriptor,
        "Session password target",
    )?;
    let (descriptor, hop_args) =
        provider(executable, "crlf", password, listener.local_addr()?.port(), &marker, "hop");
    if is_jump {
        let (hop, _) = login(&store, relay.port, descriptor, "Session password Jump")?;
        let route = Repository::<Route>::new(&store).create(RouteChange {
            name: Some("Session Jump route".into()),
            kind: Some(RouteKind::Jump { hops: vec![hop] }),
        })?;
        Repository::<AccessProfile>::new(&store).update(
            profile,
            AccessProfileChange {
                route: Some(RouteChoice::Route(route.meta.id)),
                ..Default::default()
            },
        )?;
    }
    let manager = SessionManager::default();
    manager.reserve("terminal", true)?;
    let (send, mut events) = mpsc::unbounded_channel();
    let approvals = AtomicUsize::new(0);
    let serialized = Mutex::new(Vec::new());
    let profile_id = profile.to_string();
    let terminal = Box::pin(manager.run(
        "terminal",
        &profile_id,
        None,
        true,
        store.clone(),
        |event| {
            serialized.lock().unwrap().push(format!("{event:?}"));
            if let SessionEvent::Preparation { transport_id, event } = &event {
                let answer = match event.as_ref() {
                    PreparationEvent::Trust { prompt_id, .. } => {
                        Some((prompt_id, PreparationResponse::AcceptHostKey))
                    }
                    PreparationEvent::CommandExecution {
                        prompt_id,
                        program,
                        arguments,
                        context,
                    } => {
                        assert_eq!(program, executable.to_str().unwrap());
                        assert_eq!(
                            arguments,
                            if context.target { &target_args } else { &hop_args }
                        );
                        approvals.fetch_add(1, Ordering::SeqCst);
                        Some((prompt_id, PreparationResponse::AcceptCommand))
                    }
                    _ => None,
                };
                if let Some((prompt, answer)) = answer {
                    manager.respond("terminal", transport_id, prompt, answer)?;
                }
            }
            send.send(event).map_err(|_| "session event receiver ended".into())
        },
        |_, _| Ok(()),
        |_, _| {},
    ));
    let exercise = async {
        let first = ready(&mut events).await?;
        files(&manager, &first, scratch.path()).await?;
        manager.stop("terminal")?;
        loop {
            if matches!(events.recv().await.ok_or("session events ended")?, SessionEvent::Closed) {
                break;
            }
        }
        assert!(manager.input("terminal", &first, b"stale".to_vec()).is_err());
        manager.retry("terminal")?;
        let next = ready(&mut events).await?;
        assert_ne!(first, next);
        manager.close_all()?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let labels =
        if is_jump { vec!["hop", "target", "hop", "target"] } else { vec!["target", "target"] };
    let (terminal, exercise, streams) = tokio::time::timeout(Duration::from_secs(40), async {
        tokio::join!(terminal, exercise, leases(&listener, &labels))
    })
    .await?;
    exercise?;
    terminal?;
    released(streams?).await?;
    relay.idle().await?;
    assert_eq!(approvals.load(Ordering::SeqCst), labels.len());
    assert_eq!(fs::read_to_string(marker)?.lines().collect::<Vec<_>>(), labels);
    let password = Zeroizing::new(fs::read(password)?);
    let recent = serde_json::to_string(&Inventory::new(store.clone()).recent_sessions()?)?;
    for output in [serialized.lock().unwrap().join("\n"), recent] {
        assert!(
            !output.as_bytes().windows(password.len()).any(|value| value == password.as_slice())
        );
    }
    for credential in Repository::<Credential>::new(&store).list()? {
        assert!(!credential.has_secret);
    }
    println!(
        "command password {} SessionManager: binary SFTP and fresh reconnect approval/fetch passed",
        if is_jump { "Jump" } else { "Direct" }
    );
    Ok(())
}

async fn cancelled_session(executable: &Path, password: &Path, port: u16) -> Result<()> {
    for all in [false, true] {
        let scratch = tempfile::tempdir()?;
        let store = Arc::new(Store::open(
            &scratch.path().join("local.db"),
            &LocalDatabaseKey::new([7; 32]),
        )?);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let marker = scratch.path().join("called");
        let relay = Relay::start(port).await?;
        let (descriptor, _) = provider(
            executable,
            "stall",
            password,
            listener.local_addr()?.port(),
            &marker,
            "target",
        );
        let (profile, _) = login(&store, relay.port, descriptor, "Pending session")?;
        let manager = SessionManager::default();
        manager.reserve("terminal", true)?;
        let (send, mut events) = mpsc::unbounded_channel();
        let profile_id = profile.to_string();
        let terminal = Box::pin(manager.run(
            "terminal",
            &profile_id,
            None,
            true,
            store,
            |event| {
                if let SessionEvent::Preparation { transport_id, event } = &event {
                    let answer = match event.as_ref() {
                        PreparationEvent::Trust { prompt_id, .. } => {
                            Some((prompt_id, PreparationResponse::AcceptHostKey))
                        }
                        PreparationEvent::CommandExecution { prompt_id, .. } => {
                            Some((prompt_id, PreparationResponse::AcceptCommand))
                        }
                        _ => None,
                    };
                    if let Some((prompt, answer)) = answer {
                        manager.respond("terminal", transport_id, prompt, answer)?;
                    }
                }
                send.send(event).map_err(|_| "session event receiver ended".into())
            },
            |_, _| Err("pending helper must not produce terminal output".into()),
            |_, _| {},
        ));
        let cancel = async {
            let streams = leases(&listener, &["target"]).await?;
            if all {
                manager.close_all()?;
            } else {
                manager.stop("terminal")?;
                loop {
                    if matches!(
                        events.recv().await.ok_or("session events ended")?,
                        SessionEvent::Closed
                    ) {
                        break;
                    }
                }
                manager.close("terminal")?;
            }
            released(streams).await
        };
        let (terminal, cancel) =
            tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(terminal, cancel) })
                .await?;
        cancel?;
        terminal?;
        relay.idle().await?;
    }
    println!(
        "command password SessionManager Stop/store replacement: independent helper exit observed"
    );
    Ok(())
}
