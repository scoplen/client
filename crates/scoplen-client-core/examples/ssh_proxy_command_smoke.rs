// SPDX-License-Identifier: Apache-2.0

//! Saved ProxyCommand preparation, real SSH, and observable child ownership.

use std::{
    env, fs,
    io::{self, Read as _, Write as _},
    net::{Shutdown, TcpStream},
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use scoplen_client_core::{
    connection::preparation::{
        PreparationControl, PreparationEvent, PreparationResponse, prepare_connection,
    },
    repository::{
        AccessProfile, AccessProfileChange, Credential, CredentialBinding, CredentialChange,
        CredentialKind, Edit, Host, HostChange, Repository, Route, RouteChange, RouteChoice,
        RouteKind, TrustRecord,
    },
    store::Store,
};
use scoplen_crypto::{LocalDatabaseKey, SecretVec};
use tokio::{io::AsyncReadExt, net::TcpListener};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("helper") {
        return helper(&args);
    }
    if args.len() != 4 {
        return Err("usage: ssh_proxy_command_smoke <OpenSSH-port> <user> <key-file>".into());
    }
    let port = args[1].parse()?;
    let key = fs::read(&args[3])?;
    let scratch = tempfile::tempdir()?;
    let executable =
        scratch.path().join(if cfg!(windows) { "proxy helper.exe" } else { "proxy helper" });
    fs::copy(env::current_exe()?, &executable)?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        for mode in [
            "success",
            "reject-trust",
            "wrong-user",
            "exit",
            "timeout",
            "cancel-setup",
            "drop",
            "missing-program",
            "invalid-command",
            "invalid-username",
            "success",
        ] {
            run_case(mode, &executable, port, &args[2], &key).await?;
            println!("saved ProxyCommand {mode}: passed");
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

fn helper(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 10
        || args[4] != "target.example"
        || args[7] != "%"
        || args[8] != "shell | > $HOME"
        || !args[9].is_empty()
    {
        return Err("ProxyCommand argv expansion changed".into());
    }
    let mut lease = TcpStream::connect(("127.0.0.1", args[3].parse()?))?;
    lease.write_all(b"+")?;
    match args[2].as_str() {
        "exit" => std::process::exit(7),
        "stall" => {
            std::thread::sleep(Duration::from_secs(60));
            return Ok(());
        }
        "relay" => {}
        _ => return Err("unknown helper mode".into()),
    }
    let target = TcpStream::connect(("127.0.0.1", args[5].parse()?))?;
    let mut upstream = target.try_clone()?;
    let input = std::thread::spawn(move || {
        let result = io::copy(&mut io::stdin().lock(), &mut upstream);
        let _ = upstream.shutdown(Shutdown::Write);
        result
    });
    let result = (|| {
        let mut output = io::stdout().lock();
        let mut buffer = [0; 16 * 1024];
        loop {
            let size = (&target).read(&mut buffer)?;
            if size == 0 {
                return Ok::<_, io::Error>(());
            }
            output.write_all(&buffer[..size])?;
            output.flush()?;
        }
    })();
    let _ = target.shutdown(Shutdown::Both);
    input.join().map_err(|_| "helper stdin thread panicked")??;
    result?;
    drop(lease);
    Ok(())
}

async fn run_case(
    mode: &str,
    executable: &Path,
    port: u16,
    username: &str,
    key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let scratch = tempfile::tempdir()?;
    let store = Store::open(&scratch.path().join("local.db"), &LocalDatabaseKey::new([7; 32]))?;
    let host = Repository::<Host>::new(&store).create(HostChange {
        name: Some("ProxyCommand target".into()),
        address: Some("target.example".into()),
        port: Edit::Set(port),
        ..Default::default()
    })?;
    let credential = Repository::<Credential>::new(&store).create(CredentialChange {
        kind: Some(CredentialKind::PrivateKey),
        binding: Some(CredentialBinding::Shared),
        secret: Edit::Set(SecretVec::new(key.to_vec())),
        ..Default::default()
    })?;
    let lease_listener = TcpListener::bind("127.0.0.1:0").await?;
    let behavior = match mode {
        "timeout" | "cancel-setup" => "stall",
        "exit" => "exit",
        _ => "relay",
    };
    let command = if mode == "invalid-command" {
        format!("\"{}\" %unknown", executable.display())
    } else {
        let program = if mode == "missing-program" {
            executable.with_file_name("missing helper")
        } else {
            executable.to_owned()
        };
        let remote_user = if mode == "invalid-username" { "literal-user" } else { "%r" };
        format!(
            "\"{}\" helper {behavior} {} %h %p {remote_user} %% 'shell | > $HOME' \"\"",
            program.display(),
            lease_listener.local_addr()?.port()
        )
    };
    let route = Repository::<Route>::new(&store).create(RouteChange {
        name: Some("local stdio helper".into()),
        kind: Some(RouteKind::Command { command }),
    })?;
    let profile = Repository::<AccessProfile>::new(&store).create(AccessProfileChange {
        host: Some(host.meta.id),
        username: Some(match mode {
            "wrong-user" => "scoplen-missing-user".into(),
            "invalid-username" => "x".repeat(4097),
            _ => username.into(),
        }),
        credential: Edit::Set(credential.meta.id),
        route: Some(RouteChoice::Route(route.meta.id)),
        ..Default::default()
    })?;
    let control = PreparationControl::default();
    let prompts = AtomicUsize::new(0);
    let progress = AtomicUsize::new(0);
    let started = Instant::now();
    let mut preparation =
        Box::pin(prepare_connection(&store, profile.meta.id, &control, |event| {
            match event {
                PreparationEvent::Trust { prompt_id, .. } => {
                    prompts.fetch_add(1, Ordering::SeqCst);
                    if mode == "reject-trust" {
                        control.cancel();
                    } else {
                        control.respond(&prompt_id, PreparationResponse::AcceptHostKey)?;
                    }
                }
                PreparationEvent::Progress { .. } => {
                    progress.fetch_add(1, Ordering::SeqCst);
                }
                PreparationEvent::Verified { .. } => {}
                PreparationEvent::Passphrase { .. }
                | PreparationEvent::KeyboardInteractive { .. } => {
                    return Err("unexpected key passphrase".into());
                }
            }
            Ok(())
        }));
    let has_child = !["missing-program", "invalid-command", "invalid-username"].contains(&mode);
    let (result, lease) =
        tokio::join!(tokio::time::timeout(Duration::from_secs(20), &mut preparation), async {
            if !has_child {
                return Ok(None);
            }
            let (mut lease, _) =
                tokio::time::timeout(Duration::from_secs(5), lease_listener.accept())
                    .await
                    .map_err(|_| format!("{mode}: helper did not connect its lease"))??;
            let mut marker = [0];
            tokio::time::timeout(Duration::from_secs(5), lease.read_exact(&mut marker)).await??;
            assert_eq!(marker, *b"+", "helper connected before proxy execution");
            if mode == "cancel-setup" {
                control.cancel();
            }
            Ok::<_, Box<dyn std::error::Error>>(Some(lease))
        },);
    drop(preparation);
    let result = result.map_err(|_| format!("{mode}: preparation exceeded its deadline"))?;
    let mut lease = lease?;
    if ["success", "drop"].contains(&mode) {
        let connection = result.map_err(io::Error::other)?;
        assert_eq!(prompts.load(Ordering::SeqCst), 1);
        let mut session = connection.open_session().await?;
        let output = session.exec(b"printf scoplen-command-ok", None).await?;
        assert_eq!(output.stdout, b"scoplen-command-ok");
        assert_eq!(output.exit_status, Some(0));
        drop(session);
        if mode == "success" {
            connection.close().await?;
        } else {
            drop(connection);
        }
    } else {
        let error = result.err().ok_or("expected ProxyCommand failure")?.to_string();
        if mode == "timeout" {
            assert!(started.elapsed() >= Duration::from_secs(9), "setup timeout fired prematurely");
            assert!(error.contains("timed out"), "timeout must remain actionable: {error}");
        }
        if ["reject-trust", "cancel-setup"].contains(&mode) {
            assert_eq!(error, "connection was cancelled");
        }
        if ["invalid-command", "invalid-username"].contains(&mode) {
            assert!(error.contains(if mode == "invalid-command" {
                "ProxyCommand is invalid"
            } else {
                "the SSH username must contain 1-4096 bytes without NUL"
            }));
            assert_eq!(
                progress.load(Ordering::SeqCst),
                0,
                "preflight precedes network/child activity"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(100), lease_listener.accept())
                    .await
                    .is_err(),
                "invalid local input started the helper"
            );
        }
        if [
            "reject-trust",
            "cancel-setup",
            "exit",
            "timeout",
            "missing-program",
            "invalid-command",
            "invalid-username",
        ]
        .contains(&mode)
        {
            assert!(Repository::<TrustRecord>::new(&store).list()?.is_empty());
        }
    }
    if let Some(ref mut lease) = lease {
        let mut byte = [0];
        let released = tokio::time::timeout(Duration::from_secs(5), lease.read(&mut byte))
            .await
            .map_err(|_| format!("{mode}: child retained its lease after connection release"))?;
        assert!(
            matches!(released, Ok(0))
                || released.is_err_and(|error| error.kind() == io::ErrorKind::ConnectionReset),
            "proxy child retained its ownership socket"
        );
    }
    Ok(())
}
