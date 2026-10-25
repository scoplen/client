// SPDX-License-Identifier: Apache-2.0

//! Saved client preparation against pinned disposable OpenSSH/PAM listeners.

use std::{
    collections::BTreeSet,
    env, fs, io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use scoplen_client_core::{
    connection::{
        SshConnection, SshConnectionError,
        preparation::{
            PreparationControl, PreparationError, PreparationEvent, PreparationResponse,
            prepare_connection,
        },
    },
    inventory::{Inventory, NewHost, SignIn},
    repository::{
        AccessProfile, AccessProfileChange, Credential, CredentialChange, Edit, Repository, Route,
        RouteChange, RouteChoice, RouteKind,
    },
    store::Store,
};
use scoplen_crypto::{Ed25519SigningKey, LocalDatabaseKey, SecretVec};
use scoplen_ssh::{AgentIdentity, AgentMessage, ClientError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

const DEADLINE: Duration = Duration::from_secs(25);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(run())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 7 {
        return Err("usage: ssh_keyboard_interactive_smoke <interactive-port> <key-port> <password-port> <password-file> <key-file> <wrong-key-file>".into());
    }
    let expected_key =
        ssh_key::PublicKey::from_openssh(&env::var("SCOPLEN_INTERACTIVE_HOST_KEY")?)?.to_bytes()?;
    let answer = SecretVec::new(fs::read(&args[4])?);
    let scratch = tempfile::tempdir()?;
    let store =
        Arc::new(Store::open(&scratch.path().join("local.db"), &LocalDatabaseKey::new([7; 32]))?);
    let inventory = Inventory::new(store.clone());
    let mut profiles = Vec::new();
    for (port, sign_in) in [
        (args[1].parse()?, SignIn::KeyboardInteractive),
        (args[2].parse()?, SignIn::KeyText { key: fs::read_to_string(&args[5])? }),
        (
            args[3].parse()?,
            SignIn::Password { password: String::from_utf8(answer.as_bytes().to_vec())? },
        ),
    ] {
        let host = inventory.add_host(NewHost {
            name: Some("disposable PAM fixture".into()),
            address: "127.0.0.1".into(),
            port: Some(port),
            username: "scoplen".into(),
            sign_in,
        })?;
        profiles.push(Uuid::parse_str(&host.logins[0].id)?);
    }
    let agent_key = ssh_key::PrivateKey::from_openssh(fs::read(&args[5])?)?;
    let public_key = agent_key.public_key().to_openssh()?;
    let _agent = start_agent(agent_key).await?;
    let agent_host = inventory.add_host(NewHost {
        name: Some("disposable saved Agent PAM fixture".into()),
        address: "127.0.0.1".into(),
        port: Some(args[2].parse()?),
        username: "scoplen".into(),
        sign_in: SignIn::Agent,
    })?;
    let agent_profile = Uuid::parse_str(&agent_host.logins[0].id)?;
    let credential = Repository::<AccessProfile>::new(&store)
        .get(agent_profile)?
        .ok_or("agent Login missing")?
        .credential
        .ok_or("agent credential missing")?;
    Repository::<Credential>::new(&store).update(
        credential,
        CredentialChange { public_key: Edit::Set(public_key), ..Default::default() },
    )?;
    profiles.push(agent_profile);
    for profile in &profiles {
        for accepted in [true, false, true] {
            let control = PreparationControl::default();
            let rounds = AtomicUsize::new(0);
            let wrong = SecretVec::new(b"wrong-disposable-answer".to_vec());
            let result = tokio::time::timeout(
                DEADLINE,
                prepare_answer(
                    &store,
                    *profile,
                    &control,
                    &expected_key,
                    if accepted { &answer } else { &wrong },
                    &rounds,
                    1,
                ),
            )
            .await?;
            if rounds.load(Ordering::SeqCst) == 0 {
                return Err("PAM did not request an answer".into());
            }
            if accepted {
                verify_command(result?).await?;
            } else if !matches!(
                result,
                Err(PreparationError::Connection(SshConnectionError::Engine(
                    ClientError::AuthenticationRejected { partial_success: false, .. }
                )))
            ) {
                return Err("wrong PAM answer was not rejected".into());
            }
        }
    }
    let rejected = inventory.add_host(NewHost {
        name: Some("wrong-key fixture".into()),
        address: "127.0.0.1".into(),
        port: Some(args[2].parse()?),
        username: "scoplen".into(),
        sign_in: SignIn::KeyText { key: fs::read_to_string(&args[6])? },
    })?;
    let rounds = AtomicUsize::new(0);
    let control = PreparationControl::default();
    let result = tokio::time::timeout(
        DEADLINE,
        prepare_answer(
            &store,
            Uuid::parse_str(&rejected.logins[0].id)?,
            &control,
            &expected_key,
            &answer,
            &rounds,
            1,
        ),
    )
    .await?;
    if !matches!(
        result,
        Err(PreparationError::Connection(SshConnectionError::Engine(
            ClientError::AuthenticationRejected { partial_success: false, .. }
        )))
    ) || rounds.load(Ordering::SeqCst) != 0
    {
        return Err("wrong key triggered interactive fallback".into());
    }

    let pending_control = PreparationControl::default();
    let (prompt_tx, mut prompt_rx) = tokio::sync::mpsc::unbounded_channel();
    let pending = Box::pin(prepare_connection(&store, profiles[0], &pending_control, |event| {
        match event {
            PreparationEvent::Trust { prompt_id, host_key, .. } => {
                check_key(&host_key.key, &expected_key)?;
                pending_control.respond(&prompt_id, PreparationResponse::AcceptHostKey)?;
            }
            PreparationEvent::KeyboardInteractive { prompt_id, .. } => {
                prompt_tx.send(prompt_id).map_err(|_| "prompt receiver closed")?;
            }
            _ => {}
        }
        Ok(())
    }));
    let cancel = async {
        let prompt = prompt_rx.recv().await.ok_or("pending PAM prompt missing")?;
        let independent = PreparationControl::default();
        let rounds = AtomicUsize::new(0);
        verify_command(
            prepare_answer(&store, profiles[0], &independent, &expected_key, &answer, &rounds, 1)
                .await?,
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(25)).await;
        pending_control.cancel();
        if pending_control
            .respond(
                &prompt,
                PreparationResponse::keyboard_interactive(vec![answer.as_bytes().to_vec()])?,
            )
            .is_ok()
        {
            return Err("late cancelled PAM response was accepted".into());
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    let (pending, cancel) =
        tokio::time::timeout(DEADLINE, async { tokio::join!(pending, cancel) }).await?;
    cancel?;
    if pending.is_ok() {
        return Err("cancelled PAM preparation succeeded".into());
    }

    let target = inventory.add_host(NewHost {
        name: Some("PAM target behind PAM jump".into()),
        address: "127.0.0.1".into(),
        port: Some(2222),
        username: "scoplen".into(),
        sign_in: SignIn::KeyboardInteractive,
    })?;
    let route = Repository::<Route>::new(&store).create(RouteChange {
        name: Some("disposable interactive jump".into()),
        kind: Some(RouteKind::Jump { hops: vec![profiles[0]] }),
    })?;
    let target_id = Uuid::parse_str(&target.logins[0].id)?;
    Repository::<AccessProfile>::new(&store).update(
        target_id,
        AccessProfileChange {
            route: Some(RouteChoice::Route(route.meta.id)),
            ..Default::default()
        },
    )?;
    for _ in 0..2 {
        let control = PreparationControl::default();
        let rounds = AtomicUsize::new(0);
        let connection = tokio::time::timeout(
            DEADLINE,
            prepare_answer(&store, target_id, &control, &expected_key, &answer, &rounds, 2),
        )
        .await??;
        verify_command(connection).await?;
    }
    println!(
        "saved Interactive, password/key/agent continuation, wrong answer/key refusal, fresh reconnect, independent pending connection, cancellation/late-answer fencing, and Jump PAM commands passed"
    );
    Ok(())
}

struct AgentFixture(tokio::task::JoinHandle<io::Result<()>>);

impl Drop for AgentFixture {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn start_agent(key: ssh_key::PrivateKey) -> Result<AgentFixture, Box<dyn std::error::Error>> {
    let path = env::var_os("SSH_AUTH_SOCK").ok_or("disposable agent socket was not specified")?;
    let public = key.public_key().to_bytes()?;
    let key = Ed25519SigningKey::from_bytes(
        key.key_data().ed25519().ok_or("expected disposable Ed25519 agent key")?.private.as_ref(),
    )?;
    #[cfg(unix)]
    {
        let listener = tokio::net::UnixListener::bind(path)?;
        Ok(AgentFixture(tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await?;
                serve_agent(stream, &public, &key).await?;
            }
        })))
    }
    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ServerOptions;
        let mut pipe = ServerOptions::new().first_pipe_instance(true).create(&path)?;
        Ok(AgentFixture(tokio::spawn(async move {
            loop {
                pipe.connect().await?;
                serve_agent(pipe, &public, &key).await?;
                pipe = ServerOptions::new().create(&path)?;
            }
        })))
    }
}

async fn serve_agent<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    public: &[u8],
    key: &Ed25519SigningKey,
) -> io::Result<()> {
    if !matches!(read_agent_message(&mut stream).await?, AgentMessage::RequestIdentities) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    stream
        .write_all(
            &AgentMessage::IdentitiesAnswer {
                identities: vec![
                    AgentIdentity::new(public, b"disposable PAM fixture".to_vec())
                        .map_err(io::Error::other)?,
                ],
            }
            .encode_frame()
            .map_err(io::Error::other)?,
        )
        .await?;
    let AgentMessage::SignRequest { key_blob, data, flags } =
        read_agent_message(&mut stream).await?
    else {
        return Err(io::ErrorKind::InvalidData.into());
    };
    if key_blob != public || flags != 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let raw = key.sign(&data);
    let mut signature = 11u32.to_be_bytes().to_vec();
    signature.extend_from_slice(b"ssh-ed25519");
    signature.extend_from_slice(&64u32.to_be_bytes());
    signature.extend_from_slice(&raw);
    stream
        .write_all(
            &AgentMessage::SignResponse { signature }.encode_frame().map_err(io::Error::other)?,
        )
        .await
}

async fn read_agent_message<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<AgentMessage> {
    let length = stream.read_u32().await?;
    if length > 262_144 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut frame = length.to_be_bytes().to_vec();
    frame.resize(4 + length as usize, 0);
    stream.read_exact(&mut frame[4..]).await?;
    AgentMessage::decode_frame(&frame).map_err(io::Error::other)
}

fn check_key(presented: &str, expected: &[u8]) -> Result<(), String> {
    let key = ssh_key::PublicKey::from_openssh(presented)
        .and_then(|key| key.to_bytes())
        .map_err(|_| "invalid fixture host key")?;
    if key != expected {
        return Err("unexpected fixture host key".into());
    }
    Ok(())
}

async fn prepare_answer(
    store: &Store,
    profile: Uuid,
    control: &PreparationControl,
    expected_key: &[u8],
    answer: &SecretVec,
    rounds: &AtomicUsize,
    total: u32,
) -> Result<SshConnection, PreparationError> {
    let positions = Mutex::new(BTreeSet::new());
    let connection = Box::pin(prepare_connection(store, profile, control, |event| {
        match event {
            PreparationEvent::Trust { prompt_id, host_key, .. } => {
                check_key(&host_key.key, expected_key)?;
                control.respond(&prompt_id, PreparationResponse::AcceptHostKey)?;
            }
            PreparationEvent::KeyboardInteractive { context, prompt_id, prompts, .. } => {
                if context.total != total
                    || context.target != (context.position == total)
                    || context.username != "scoplen"
                {
                    return Err("PAM challenge lost trusted hop identity".into());
                }
                positions.lock().unwrap().insert(context.position);
                let responses = if prompts.is_empty() {
                    Vec::new()
                } else if prompts.len() == 1 && !prompts[0].echo {
                    rounds.fetch_add(1, Ordering::SeqCst);
                    vec![answer.as_bytes().to_vec()]
                } else {
                    return Err("expected one non-echo PAM prompt".into());
                };
                control
                    .respond(&prompt_id, PreparationResponse::keyboard_interactive(responses)?)?;
            }
            PreparationEvent::Passphrase { .. } => {
                return Err("unexpected software-key passphrase".into());
            }
            _ => {}
        }
        Ok(())
    }))
    .await?;
    if *positions.lock().unwrap() != (1..=total).collect() {
        return Err("PAM did not challenge every saved hop".into());
    }
    Ok(connection)
}

async fn verify_command(connection: SshConnection) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = connection.open_session().await?;
    let result = session.exec(b"printf scoplen-client-pam-ok", None).await?;
    if result.stdout != b"scoplen-client-pam-ok"
        || !result.stderr.is_empty()
        || result.exit_status != Some(0)
    {
        return Err("PAM command output or exit status did not match".into());
    }
    connection.close().await?;
    Ok(())
}
