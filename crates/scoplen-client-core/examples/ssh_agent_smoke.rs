// SPDX-License-Identifier: Apache-2.0

//! Public client-core SSH-agent login and cancellation checks against OpenSSH.

use std::{env, fs, sync::Arc, time::Duration};

use scoplen_client_core::{
    connection::{
        HostKeyPresentation, HostKeyTrust, SshConnection, SshConnectionError, probe_host_key,
    },
    repository::{
        AccessProfile, AccessProfileChange, Credential, CredentialBinding, CredentialChange,
        CredentialKind, Edit, Host, HostChange, Repository,
    },
    store::Store,
};
use scoplen_crypto::LocalDatabaseKey;
use scoplen_ssh::{AgentIdentity, AgentMessage, ClientError, HostKey, HostKeyVerificationError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod support {
    pub mod agent_peer;
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 6 {
        return Err("usage: ssh_agent_smoke <success|missing|untrusted|unavailable|refused|disconnected|timeout|cancel> <host> <port> <user> <public-key-file>".into());
    }
    let public_key = fs::read_to_string(&args[5])?;
    let (address, port, _server) = if env::var_os("SCOPLEN_AGENT_LOOPBACK").is_some() {
        let (port, server) = support::agent_peer::start(&public_key).await?;
        ("127.0.0.1".to_owned(), port, Some(server))
    } else {
        (args[2].clone(), args[3].parse()?, None)
    };
    // Exercise the real saved-object resolver rather than bypassing credential selection.
    let scratch = tempfile::tempdir()?;
    let store = Store::open(&scratch.path().join("local.db"), &LocalDatabaseKey::new([7; 32]))?;
    let host = Repository::<Host>::new(&store).create(HostChange {
        name: Some("fixture".into()),
        address: Some(address),
        port: Edit::Set(port),
        ..Default::default()
    })?;
    let credential = Repository::<Credential>::new(&store).create(CredentialChange {
        kind: Some(CredentialKind::Agent),
        binding: Some(CredentialBinding::None),
        public_key: Edit::Set(public_key.clone()),
        ..Default::default()
    })?;
    let profile = Repository::<AccessProfile>::new(&store).create(AccessProfileChange {
        host: Some(host.meta.id),
        username: Some(args[4].clone()),
        credential: Edit::Set(credential.meta.id),
        ..Default::default()
    })?;
    let plan = scoplen_client_core::connection::resolve_connection_plan(&store, profile.meta.id)?;
    let presented =
        probe_host_key(&plan).await.map_err(|error| format!("host-key probe: {error}"))?;
    let expected = if args[1] == "untrusted" {
        HostKeyPresentation {
            algorithm: "wrong".into(),
            key: "wrong".into(),
            fingerprint: "wrong".into(),
        }
    } else {
        presented
    };
    let trust: HostKeyTrust = Arc::new(move |_: &str, key: &HostKey| {
        if HostKeyPresentation::from_host_key(key) == expected {
            Ok(())
        } else {
            Err(HostKeyVerificationError::Rejected("fixture host pin mismatch".into()))
        }
    });
    let connection = SshConnection::connect(&plan, Some(trust)).await;
    if args[1] == "untrusted" {
        if !matches!(connection, Err(SshConnectionError::Engine(ClientError::HostKey(_)))) {
            return Err("incorrect host pin was accepted".into());
        }
        println!("agent untrusted rejected before credential use");
        return Ok(());
    }
    let mut connection = connection.map_err(|error| format!("SSH handshake: {error}"))?;
    let mode = args[1].as_str();
    if ["refused", "disconnected", "timeout", "cancel"].contains(&mode) {
        let public = ssh_key::PublicKey::from_openssh(&public_key)?.to_bytes()?;
        let (requested, request_seen) = tokio::sync::oneshot::channel();
        let fake = fake_agent(public, mode.to_owned(), requested).await?;
        if mode == "cancel" {
            let authentication = tokio::spawn(async move { connection.authenticate().await });
            tokio::time::timeout(Duration::from_secs(3), request_seen).await??;
            authentication.abort();
            let _ = authentication.await;
            tokio::time::timeout(Duration::from_secs(2), fake).await???;
            println!("agent cancellation closed pending signer transport");
            return Ok(());
        }
        let result = connection.authenticate().await;
        tokio::time::timeout(Duration::from_secs(2), fake).await???;
        let expected = match mode {
            "timeout" => matches!(result, Err(SshConnectionError::AgentTimeout)),
            _ => matches!(result, Err(SshConnectionError::AgentSigningFailed)),
        };
        if !expected {
            return Err(format!("unexpected {mode} result: {result:?}").into());
        }
        if connection.open_session().await.is_ok() {
            return Err("failed authentication opened session".into());
        }
        println!("agent {mode} rejected");
        return Ok(());
    }
    let result = connection.authenticate().await;
    if mode == "missing" || mode == "unavailable" {
        let expected = if mode == "missing" {
            matches!(result, Err(SshConnectionError::AgentIdentityMissing))
        } else {
            matches!(result, Err(SshConnectionError::AgentUnavailable))
        };
        if !expected {
            return Err(format!("unexpected {mode} result: {result:?}").into());
        }
        if connection.open_session().await.is_ok() {
            return Err("failed authentication opened session".into());
        }
        println!("agent {mode} rejected");
        return Ok(());
    }
    if mode != "success" {
        return Err("unknown fixture mode".into());
    }
    result?;
    let mut session = connection.open_session().await?;
    let result = session.exec(b"printf scoplen-agent-ok", None).await?;
    if result.stdout != b"scoplen-agent-ok" || result.exit_status != Some(0) {
        return Err("agent-authenticated command returned unexpected output".into());
    }
    connection.close().await?;
    println!("saved agent key authenticated and executed command");
    Ok(())
}

async fn fake_agent(
    key_blob: Vec<u8>,
    mode: String,
    requested: tokio::sync::oneshot::Sender<()>,
) -> Result<tokio::task::JoinHandle<Result<(), std::io::Error>>, Box<dyn std::error::Error>> {
    let path = env::var_os("SSH_AUTH_SOCK").ok_or("fixture socket not specified")?;
    #[cfg(unix)]
    {
        let listener = tokio::net::UnixListener::bind(path)?;
        Ok(tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            serve_fake(stream, key_blob, &mode, requested).await
        }))
    }
    #[cfg(windows)]
    {
        let pipe = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(path)?;
        Ok(tokio::spawn(async move {
            pipe.connect().await?;
            serve_fake(pipe, key_blob, &mode, requested).await
        }))
    }
}

async fn serve_fake<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    key_blob: Vec<u8>,
    mode: &str,
    requested: tokio::sync::oneshot::Sender<()>,
) -> std::io::Result<()> {
    let message = read_message(&mut stream).await?;
    assert!(matches!(message, AgentMessage::RequestIdentities));
    let answer = AgentMessage::IdentitiesAnswer {
        identities: vec![
            AgentIdentity::new(key_blob, b"disposable fixture".to_vec())
                .map_err(std::io::Error::other)?,
        ],
    }
    .encode_frame()
    .map_err(std::io::Error::other)?;
    stream.write_all(&answer).await?;
    assert!(matches!(read_message(&mut stream).await?, AgentMessage::SignRequest { .. }));
    let _ = requested.send(());
    match mode {
        "refused" => stream.write_all(&AgentMessage::Failure.encode_frame().unwrap()).await,
        "disconnected" => Ok(()),
        _ => {
            // Cancellation and the absolute deadline both close the local transport.
            let count = stream.read(&mut [0; 1]).await?;
            assert_eq!(count, 0);
            Ok(())
        }
    }
}

async fn read_message<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<AgentMessage> {
    let length = stream.read_u32().await?;
    if length > 262_144 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut frame = length.to_be_bytes().to_vec();
    frame.resize(4 + length as usize, 0);
    stream.read_exact(&mut frame[4..]).await?;
    AgentMessage::decode_frame(&frame).map_err(std::io::Error::other)
}
