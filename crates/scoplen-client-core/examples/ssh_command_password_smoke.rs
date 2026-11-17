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
        AccessProfile, AccessProfileChange, Credential, Repository, Route, RouteChange,
        RouteChoice, RouteKind,
    },
    session_manager::{SessionEvent, SessionManager},
    store::Store,
};
use scoplen_crypto::LocalDatabaseKey;
use std::{
    fs,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, watch},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[path = "support/command_credentials.rs"]
mod fixture;
use fixture::{Relay, files, helper, leases, login, provider, ready, released};

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
    let (mut descriptor, target_args) = provider(
        executable,
        behavior,
        password,
        listener.local_addr()?.port(),
        &marker,
        "target",
        "password",
    );
    if mode == "invalid" {
        descriptor.insert("unknown".into(), "value".into());
    }
    if mode == "missing" {
        descriptor.insert("path".into(), "scoplen-fixture-missing-password-helper".into());
    }
    let (profile, _) =
        login(&store, if is_jump { internal } else { relay.port }, descriptor, "Password target")?;
    let (hop_descriptor, hop_args) = provider(
        executable,
        "raw",
        password,
        listener.local_addr()?.port(),
        &marker,
        "hop",
        "password",
    );
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
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(streams)
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
                "SSH authentication with the credential command was rejected. Check the Login, helper and any additional factors, then reconnect."
            }
            "exit" => "credential command failed",
            "empty" => "empty output",
            "oversize" => "too much output",
            "no-exit" => "timed out",
            _ => "connection was cancelled",
        };
        assert!(error.contains(expected), "{mode}: unexpected fixed failure: {error}");
        assert!(!error.contains(executable.to_str().unwrap()));
    }
    relay.idle().await?;
    assert_eq!(
        relay.accepted.load(Ordering::SeqCst),
        if mode == "raw" { 2 } else { usize::from(mode != "invalid") }
    );
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
    let (descriptor, target_args) = provider(
        executable,
        "raw",
        password,
        listener.local_addr()?.port(),
        &marker,
        "target",
        "password",
    );
    let (profile, _) = login(
        &store,
        if is_jump { internal } else { relay.port },
        descriptor,
        "Session password target",
    )?;
    let (descriptor, hop_args) = provider(
        executable,
        "crlf",
        password,
        listener.local_addr()?.port(),
        &marker,
        "hop",
        "password",
    );
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
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
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
            "password",
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
