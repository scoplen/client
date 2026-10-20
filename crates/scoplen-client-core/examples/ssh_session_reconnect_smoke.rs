// SPDX-License-Identifier: Apache-2.0

//! Exercise the public Rust session manager against disposable, real OpenSSH.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scoplen_client_core::connection::preparation::{PreparationEvent, PreparationResponse};
use scoplen_client_core::inventory::{Inventory, NewHost, SignIn};
use scoplen_client_core::repository::{
    AccessProfile, AccessProfileChange, Credential, CredentialChange, Edit, Repository,
};
use scoplen_client_core::session_manager::{SessionEvent, SessionManager};
use scoplen_client_core::store::Store;
use scoplen_crypto::{LocalDatabaseKey, SecretVec};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use uuid::Uuid;

const MODES: [&str; 9] = [
    "reconnect",
    "reconnect-input",
    "reconnect-resize",
    "normal-exit",
    "stop-backoff",
    "stop-preparation",
    "exhaustion",
    "config-change",
    "auth-change",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 5 || !MODES.contains(&args[1].as_str()) {
        return Err("usage: ssh_session_reconnect_smoke <reconnect|reconnect-input|reconnect-resize|normal-exit|stop-backoff|stop-preparation|exhaustion|config-change|auth-change> <host> <port> <password-file>".into());
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(run(&args))
}

async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mode = args[1].as_str();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let target = format!("{}:{}", args[2], args[3]);
    let (cut, generation) = watch::channel(0u64);
    let (stop_listener, mut stopped) = watch::channel(false);
    let relay = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! { biased;
                _ = stopped.changed() => break,
                connection = listener.accept() => {
                    let (mut local, _) = connection?;
                    let target = target.clone();
                    let mut cut = generation.clone();
                    cut.borrow_and_update();
                    connections.spawn(async move {
                        let mut remote = TcpStream::connect(target).await?;
                        tokio::select! { biased;
                            _ = cut.changed() => {},
                            _ = tokio::io::copy_bidirectional(&mut local, &mut remote) => {},
                        }
                        Ok::<(), std::io::Error>(())
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => { result??; },
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });

    let scratch = tempfile::tempdir()?;
    let store =
        Arc::new(Store::open(&scratch.path().join("local.db"), &LocalDatabaseKey::new([7; 32]))?);
    let inventory = Inventory::new(store.clone());
    let host = inventory.add_host(NewHost {
        name: Some("disposable reconnect fixture".into()),
        address: "127.0.0.1".into(),
        port: Some(port),
        username: "smoke".into(),
        sign_in: SignIn::Password { password: String::from_utf8(fs::read(&args[4])?)? },
    })?;
    let profile = &host.logins[0].id;
    let manager = SessionManager::default();
    manager.reserve("fixture-terminal", true)?;
    let starts = Mutex::new(Vec::<String>::new());
    let ready = AtomicUsize::new(0);
    let retries = Mutex::new(Vec::<(u8, u8)>::new());
    let outputs = Mutex::new(BTreeMap::<Uuid, Vec<u8>>::new());
    let cut_once = AtomicBool::new(false);
    let failed = AtomicBool::new(false);
    let closed = AtomicBool::new(false);
    let result = tokio::time::timeout(
        Duration::from_secs(55),
        manager.run(
            "fixture-terminal",
            profile,
            None,
            true,
            store.clone(),
            |event| {
                match event {
                    SessionEvent::Starting { transport_id, automatic } => {
                        let mut starts = starts.lock().unwrap();
                        assert!(!starts.contains(&transport_id));
                        starts.push(transport_id);
                        assert_eq!(automatic, starts.len() > 1);
                        if mode == "stop-preparation" && automatic {
                            manager.stop("fixture-terminal")?;
                        }
                    }
                    SessionEvent::Preparation { event, .. } => match *event {
                        PreparationEvent::Trust { prompt_id, .. } => manager.respond(
                            "fixture-terminal",
                            &prompt_id,
                            PreparationResponse::AcceptHostKey,
                        )?,
                        PreparationEvent::Passphrase { .. } => {
                            panic!("password fixture must not request a key passphrase")
                        }
                        PreparationEvent::Progress { .. } => {}
                    },
                    SessionEvent::Ready { transport_id } => {
                        let count = ready.fetch_add(1, Ordering::SeqCst) + 1;
                        if count == 2 {
                            assert!(
                                manager
                                    .input(
                                        "fixture-terminal",
                                        &starts.lock().unwrap()[0],
                                        b"must-not-replay\n".to_vec()
                                    )
                                    .is_err()
                            );
                        }
                        let command = if count == 1 {
                            "printf '\\123COPLEN-FIRST\\n'\n"
                        } else {
                            "printf '\\123COPLEN-SECOND\\n'\n"
                        };
                        manager.input(
                            "fixture-terminal",
                            &transport_id,
                            command.as_bytes().to_vec(),
                        )?;
                    }
                    SessionEvent::Retrying { attempt, delay_seconds, .. } => {
                        retries.lock().unwrap().push((attempt, delay_seconds));
                        match mode {
                            "normal-exit" => panic!("normal shell exit must never retry"),
                            "stop-backoff" => manager.stop("fixture-terminal")?,
                            "config-change" => {
                                Repository::<AccessProfile>::new(&store)
                                    .update(
                                        Uuid::parse_str(profile).unwrap(),
                                        AccessProfileChange {
                                            username: Some("x".repeat(4097)),
                                            ..Default::default()
                                        },
                                    )
                                    .map_err(|error| error.to_string())?;
                            }
                            "auth-change" => {
                                let credential = Repository::<AccessProfile>::new(&store)
                                    .get(Uuid::parse_str(profile).unwrap())
                                    .map_err(|error| error.to_string())?
                                    .unwrap()
                                    .credential
                                    .unwrap();
                                Repository::<Credential>::new(&store)
                                    .update(
                                        credential,
                                        CredentialChange {
                                            secret: Edit::Set(SecretVec::new(
                                                b"wrong-disposable-password".to_vec(),
                                            )),
                                            ..Default::default()
                                        },
                                    )
                                    .map_err(|error| error.to_string())?;
                            }
                            _ => {}
                        }
                    }
                    SessionEvent::Closed => {
                        closed.store(true, Ordering::SeqCst);
                        manager.close("fixture-terminal")?;
                    }
                    SessionEvent::Failed { exhausted, .. } => {
                        assert!(
                            matches!(mode, "exhaustion" | "config-change" | "auth-change"),
                            "unexpected manager failure in {mode}"
                        );
                        assert_eq!(exhausted, mode == "exhaustion");
                        failed.store(true, Ordering::SeqCst);
                        manager.close("fixture-terminal")?;
                    }
                }
                Ok(())
            },
            |transport, bytes| {
                let replacement =
                    starts.lock().unwrap().first().is_some_and(|id| *id != transport.to_string());
                let mut output = outputs.lock().unwrap();
                let output = output.entry(transport).or_default();
                output.extend(bytes);
                assert!(output.len() <= 1_048_576);
                if replacement {
                    assert!(
                        !output
                            .windows(b"SCOPLEN-OLD-INPUT".len())
                            .any(|part| part == b"SCOPLEN-OLD-INPUT"),
                        "old input must not be replayed into the replacement shell"
                    );
                }
                if output.windows(b"SCOPLEN-FIRST".len()).any(|bytes| bytes == b"SCOPLEN-FIRST")
                    && !cut_once.swap(true, Ordering::SeqCst)
                {
                    if mode == "normal-exit" {
                        manager.input(
                            "fixture-terminal",
                            &transport.to_string(),
                            b"exit\n".to_vec(),
                        )?;
                    } else {
                        cut.send_replace(1);
                        if mode == "reconnect-input" {
                            let mut old_input = b"# SCOPLEN-OLD-INPUT ".to_vec();
                            old_input.resize(65_536, b'x');
                            for _ in 0..64 {
                                manager.input(
                                    "fixture-terminal",
                                    &transport.to_string(),
                                    old_input.clone(),
                                )?;
                            }
                        } else if mode == "reconnect-resize" {
                            for columns in 80..143 {
                                manager.resize(
                                    "fixture-terminal",
                                    &transport.to_string(),
                                    columns,
                                    24,
                                )?;
                            }
                            manager.input(
                                "fixture-terminal",
                                &transport.to_string(),
                                b"printf '\\123COPLEN-OLD-INPUT\\n'\n".to_vec(),
                            )?;
                        }
                        if mode == "exhaustion" {
                            stop_listener.send_replace(true);
                        }
                    }
                }
                if output.windows(b"SCOPLEN-SECOND".len()).any(|bytes| bytes == b"SCOPLEN-SECOND") {
                    manager.input(
                        "fixture-terminal",
                        &transport.to_string(),
                        b"exit\n".to_vec(),
                    )?;
                }
                Ok(())
            },
            |_, _| {},
        ),
    )
    .await;
    stop_listener.send_replace(true);
    relay.await?.map_err(|error| error.to_string())?;
    result??;

    let starts = starts.lock().unwrap();
    let retries = retries.lock().unwrap();
    match mode {
        "normal-exit" => {
            assert_eq!(ready.load(Ordering::SeqCst), 1);
            assert!(retries.is_empty());
        }
        "stop-backoff" => {
            assert_eq!(starts.len(), 1);
            assert_eq!(*retries, [(1, 1)]);
        }
        "stop-preparation" => {
            assert_eq!(starts.len(), 2);
            assert_eq!(ready.load(Ordering::SeqCst), 1);
        }
        "exhaustion" => {
            assert_eq!(starts.len(), 6);
            assert_eq!(*retries, [(1, 1), (2, 2), (3, 4), (4, 8), (5, 16)]);
        }
        "config-change" | "auth-change" => {
            assert_eq!(starts.len(), 2);
            assert_eq!(ready.load(Ordering::SeqCst), 1);
            assert_eq!(retries.len(), 1);
        }
        "reconnect" | "reconnect-input" | "reconnect-resize" => {
            assert_eq!(ready.load(Ordering::SeqCst), 2);
            assert_eq!(*retries, [(1, 1)]);
        }
        _ => unreachable!(),
    }
    assert_eq!(
        failed.load(Ordering::SeqCst),
        matches!(mode, "exhaustion" | "config-change" | "auth-change")
    );
    assert_eq!(closed.load(Ordering::SeqCst), !failed.load(Ordering::SeqCst));
    let recent = store.recent_sessions(20)?;
    assert_eq!(recent.len(), starts.len());
    assert!(recent.iter().all(|entry| entry.ended_at.is_some()));
    println!("{mode}: real OpenSSH session policy passed");
    Ok(())
}
