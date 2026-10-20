// SPDX-License-Identifier: Apache-2.0

//! Public saved-object preparation against three independent OpenSSH servers.

use scoplen_client_core::{
    connection::preparation::{
        PreparationControl, PreparationEvent, PreparationPhase, PreparationResponse,
        prepare_connection,
    },
    repository::{
        AccessProfile, AccessProfileChange, Credential, CredentialBinding, CredentialChange,
        CredentialKind, Edit, Host, HostChange, Repository, Route, RouteChange, RouteChoice,
        RouteKind, TrustRecord, TrustRecordChange,
    },
    store::Store,
};
use scoplen_crypto::{Ed25519SigningKey, LocalDatabaseKey, SecretVec};
use scoplen_ssh::{AgentIdentity, AgentMessage, Ed25519SshSigner, Signer};
use std::{
    collections::BTreeSet,
    env, fs,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 12
        || ![
            "success",
            "changed-1",
            "changed-2",
            "changed-3",
            "cancel-1",
            "cancel-2",
            "cancel-3",
            "wrong-password",
            "closed",
            "denied",
            "timeout",
            "cancel-setup",
            "agent-1",
            "agent-2",
            "agent-3",
        ]
        .contains(&args[1].as_str())
    {
        return Err("usage: ssh_jump_smoke <success|changed-1|changed-2|changed-3|cancel-1|cancel-2|cancel-3|wrong-password|closed|denied|timeout|cancel-setup|agent-1|agent-2|agent-3> <first-host> <first-port> <next-host> <next-port> <target-host> <target-port> <password-file> <encrypted-key-file> <passphrase-file> <agent-key-file>".into());
    }
    let mode = args[1].as_str();
    let agent_position = mode.strip_prefix("agent-").and_then(|v| v.parse::<u32>().ok());
    let scratch = tempfile::tempdir()?;
    let store = Store::open(&scratch.path().join("local.db"), &LocalDatabaseKey::new([7; 32]))?;
    let signs = Arc::new(AtomicUsize::new(0));
    let agent = if agent_position.is_some() {
        Some(start_agent(&args[11], signs.clone()).await?)
    } else {
        None
    };
    let mut profiles = Vec::new();
    for index in 0..3 {
        let host = Repository::<Host>::new(&store).create(HostChange {
            name: Some(format!("OpenSSH {}", index + 1)),
            address: Some(args[2 + index * 2].clone()),
            port: Edit::Set(args[3 + index * 2].parse()?),
            ..Default::default()
        })?;
        let is_agent = agent_position == Some(index as u32 + 1);
        let kind = if is_agent {
            CredentialKind::Agent
        } else if index == 0 {
            CredentialKind::Password
        } else {
            CredentialKind::PrivateKey
        };
        let secret = match kind {
            CredentialKind::Password => Some(if mode == "wrong-password" {
                b"wrong-disposable-password".to_vec()
            } else {
                fs::read(&args[8])?
            }),
            CredentialKind::PrivateKey => Some(fs::read(&args[9])?),
            _ => None,
        };
        let credential = Repository::<Credential>::new(&store).create(CredentialChange {
            kind: Some(kind),
            binding: Some(if is_agent {
                CredentialBinding::None
            } else {
                CredentialBinding::Shared
            }),
            secret: secret.map_or(Edit::Keep, |secret| Edit::Set(SecretVec::new(secret))),
            public_key: if is_agent {
                Edit::Set(
                    ssh_key::PrivateKey::from_openssh(fs::read(&args[11])?)?
                        .public_key()
                        .to_openssh()?,
                )
            } else {
                Edit::Keep
            },
            ..Default::default()
        })?;
        profiles.push(
            Repository::<AccessProfile>::new(&store)
                .create(AccessProfileChange {
                    host: Some(host.meta.id),
                    username: Some("smoke".into()),
                    credential: Edit::Set(credential.meta.id),
                    ..Default::default()
                })?
                .meta
                .id,
        );
    }
    let route = Repository::<Route>::new(&store).create(RouteChange {
        name: Some("two independent jump hosts".into()),
        kind: Some(RouteKind::Jump { hops: profiles[..2].to_vec() }),
    })?;
    Repository::<AccessProfile>::new(&store).update(
        profiles[2],
        AccessProfileChange {
            route: Some(RouteChoice::Route(route.meta.id)),
            ..Default::default()
        },
    )?;
    let cancel_position = mode.strip_prefix("cancel-").and_then(|v| v.parse::<u32>().ok());
    let changed_position = mode.strip_prefix("changed-").and_then(|v| v.parse::<u32>().ok());
    if let Some(position) = changed_position {
        let host = Repository::<AccessProfile>::new(&store)
            .get(profiles[position as usize - 1])?
            .unwrap()
            .host;
        let previous_key = ssh_key::PrivateKey::from_openssh(fs::read(&args[11])?)?;
        Repository::<TrustRecord>::new(&store).create(TrustRecordChange {
            host: Edit::Set(host),
            key: Edit::Set(previous_key.public_key().to_openssh()?),
            fingerprint: Edit::Set(previous_key.fingerprint(ssh_key::HashAlg::Sha256).to_string()),
            ..Default::default()
        })?;
    }
    let rounds = if mode == "success" { 2 } else { 1 };
    for round in 0..rounds {
        let control = PreparationControl::default();
        let fingerprints = Mutex::new(BTreeSet::new());
        let trust_positions = Mutex::new(Vec::new());
        let key_prompts = AtomicUsize::new(0);
        let mut preparation =
            Box::pin(prepare_connection(&store, profiles[2], &control, |event| {
                match event {
                    PreparationEvent::Trust { context, prompt_id, host_key } => {
                        assert_eq!(host_key.changed, changed_position == Some(context.position));
                        if agent_position == Some(context.position) {
                            assert_eq!(
                                signs.load(Ordering::SeqCst),
                                0,
                                "agent accessed before host trust"
                            );
                        }
                        trust_positions.lock().unwrap().push(context.position);
                        fingerprints.lock().unwrap().insert(host_key.fingerprint);
                        if cancel_position == Some(context.position) {
                            control.cancel();
                            assert!(
                                control
                                    .respond(&prompt_id, PreparationResponse::AcceptHostKey)
                                    .is_err()
                            );
                        } else {
                            control.respond(&prompt_id, PreparationResponse::AcceptHostKey)?;
                        }
                    }
                    PreparationEvent::Passphrase { prompt_id, incorrect, .. } => {
                        key_prompts.fetch_add(1, Ordering::SeqCst);
                        // A local bad passphrase must not discard the reviewed SSH connection.
                        let passphrase = if incorrect {
                            fs::read(&args[10]).map_err(|e| e.to_string())?
                        } else {
                            b"wrong-disposable-passphrase".to_vec()
                        };
                        control.respond(
                            &prompt_id,
                            PreparationResponse::Passphrase(SecretVec::new(passphrase)),
                        )?;
                    }
                    PreparationEvent::Progress { context, phase: PreparationPhase::Connecting }
                        if mode == "cancel-setup" && context.target =>
                    {
                        let control = control.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            control.cancel();
                        });
                    }
                    _ => {}
                }
                Ok(())
            }));
        let result = tokio::time::timeout(Duration::from_secs(35), &mut preparation).await?;
        drop(preparation);
        if cancel_position.is_some()
            || ["wrong-password", "closed", "denied", "timeout", "cancel-setup"].contains(&mode)
        {
            let error = result.err().ok_or("expected failure was accepted")?;
            if mode == "timeout" && !error.contains("timed out") {
                return Err(format!("unexpected timeout result: {error}").into());
            }
            if mode.starts_with("cancel-") && !error.contains("cancelled") {
                return Err(format!("unexpected cancellation: {error}").into());
            }
            let expected_trusts = match mode {
                "wrong-password" | "denied" => 1,
                "closed" | "timeout" | "cancel-setup" => 2,
                _ => cancel_position.unwrap() as usize,
            };
            assert_eq!(
                trust_positions.lock().unwrap().len(),
                expected_trusts,
                "failure must occur at the intended hop: {error}"
            );
            if let Some(position) = cancel_position {
                let records = Repository::<TrustRecord>::new(&store).list()?;
                let host = Repository::<AccessProfile>::new(&store)
                    .get(profiles[position as usize - 1])?
                    .unwrap()
                    .host;
                assert!(!records.iter().any(|record| record.host == Some(host) && !record.revoked));
            }
            println!("jump {mode} rejected and released");
            break;
        }
        let connection = result?;
        if round == 0 {
            assert_eq!(*trust_positions.lock().unwrap(), vec![1, 2, 3]);
            assert_eq!(
                fingerprints.lock().unwrap().len(),
                3,
                "fixture must have distinct host keys"
            );
        } else {
            assert!(
                trust_positions.lock().unwrap().is_empty(),
                "reconnect reuses exact saved host trust"
            );
        }
        let expected_keys = if agent_position.is_some_and(|p| p > 1) { 2 } else { 4 };
        assert_eq!(key_prompts.load(Ordering::SeqCst), expected_keys);
        let mut session = connection.open_session().await?;
        let output = session.exec(b"printf scoplen-jump-ok", None).await?;
        assert_eq!(output.stdout, b"scoplen-jump-ok");
        assert_eq!(output.exit_status, Some(0));
        connection.close().await?;
        if let Some(position) = changed_position {
            let host = Repository::<AccessProfile>::new(&store)
                .get(profiles[position as usize - 1])?
                .unwrap()
                .host;
            let trust = Repository::<TrustRecord>::new(&store).list()?;
            assert_eq!(trust.iter().filter(|r| r.host == Some(host) && r.revoked).count(), 1);
            assert_eq!(trust.iter().filter(|r| r.host == Some(host) && !r.revoked).count(), 1);
        }
        println!("jump {mode} round {} authenticated and executed", round + 1);
    }
    if let Some(agent) = agent {
        agent.abort();
    }
    Ok(())
}

async fn start_agent(
    path: &str,
    signs: Arc<AtomicUsize>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let key = ssh_key::PrivateKey::from_openssh(fs::read(path)?)?;
    let private = key.key_data().ed25519().ok_or("fixture requires Ed25519")?;
    let signer =
        Arc::new(Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(private.private.as_ref())?));
    let socket =
        env::var_os("SSH_AUTH_SOCK").ok_or("isolated fixture SSH_AUTH_SOCK is required")?;
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ServerOptions;
        let mut listener = ServerOptions::new().first_pipe_instance(true).create(&socket)?;
        Ok(tokio::spawn(async move {
            loop {
                if listener.connect().await.is_err() {
                    break;
                }
                let connected = listener;
                listener = match ServerOptions::new().create(&socket) {
                    Ok(next) => next,
                    Err(_) => break,
                };
                let signer = signer.clone();
                let signs = signs.clone();
                tokio::spawn(async move {
                    let _ = serve_agent(connected, signer, signs).await;
                });
            }
        }))
    }
    #[cfg(unix)]
    {
        let listener = tokio::net::UnixListener::bind(socket)?;
        Ok(tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let signer = signer.clone();
                let signs = signs.clone();
                tokio::spawn(async move {
                    let _ = serve_agent(stream, signer, signs).await;
                });
            }
        }))
    }
}

async fn serve_agent<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    signer: Arc<Ed25519SshSigner>,
    signs: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    loop {
        let length = match stream.read_u32().await {
            Ok(length) => length,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if length > 262_144 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let mut frame = length.to_be_bytes().to_vec();
        frame.resize(length as usize + 4, 0);
        stream.read_exact(&mut frame[4..]).await?;
        let message = AgentMessage::decode_frame(&frame).map_err(std::io::Error::other)?;
        let reply = match message {
            AgentMessage::RequestIdentities => AgentMessage::IdentitiesAnswer {
                identities: vec![
                    AgentIdentity::new(
                        signer.public_key_blob().map_err(std::io::Error::other)?,
                        b"disposable fixture".to_vec(),
                    )
                    .map_err(std::io::Error::other)?,
                ],
            },
            AgentMessage::SignRequest { key_blob, data, flags }
                if flags == 0
                    && key_blob == signer.public_key_blob().map_err(std::io::Error::other)? =>
            {
                signs.fetch_add(1, Ordering::SeqCst);
                let body = signer.sign(&data).map_err(std::io::Error::other)?;
                let algorithm = b"ssh-ed25519";
                let mut signature = (algorithm.len() as u32).to_be_bytes().to_vec();
                signature.extend_from_slice(algorithm);
                signature.extend_from_slice(&(body.len() as u32).to_be_bytes());
                signature.extend_from_slice(&body);
                AgentMessage::SignResponse { signature }
            }
            _ => AgentMessage::Failure,
        };
        stream.write_all(&reply.encode_frame().map_err(std::io::Error::other)?).await?;
    }
}
