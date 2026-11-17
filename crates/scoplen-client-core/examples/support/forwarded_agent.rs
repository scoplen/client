// SPDX-License-Identifier: Apache-2.0

//! Disposable local SSH-agent protocol fixture with two loaded identities.

use std::{
    io,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use scoplen_crypto::{Ed25519SigningKey, SecretVec};
use scoplen_ssh::{
    AgentError, AgentIdentity, AgentKeyStore, AgentMessage, AgentServer, Ed25519SshSigner, Signer,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
    task::JoinHandle,
};

struct SourceKey {
    identity: AgentIdentity,
    signer: Ed25519SshSigner,
}

struct State {
    keys: [SourceKey; 2],
    refuse: AtomicBool,
    stall: AtomicBool,
    other_signatures: AtomicUsize,
    unsupported: AtomicUsize,
    signatures: watch::Sender<u64>,
    disconnected: watch::Sender<u64>,
}

struct SourceStore(Arc<State>);

impl AgentKeyStore for SourceStore {
    fn identities(&self) -> Result<Vec<AgentIdentity>, AgentError> {
        Ok(self.0.keys.iter().map(|key| key.identity.clone()).collect())
    }

    fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>, AgentError> {
        let key = self
            .0
            .keys
            .iter()
            .position(|key| key.identity.key_blob() == key_blob)
            .ok_or(AgentError::AgentFailure)?;
        if key != 0 {
            self.0.other_signatures.fetch_add(1, Ordering::SeqCst);
        }
        if flags != 0 || self.0.refuse.load(Ordering::SeqCst) {
            return Err(AgentError::AgentFailure);
        }
        let bytes = self.0.keys[key].signer.sign(data).map_err(|_| AgentError::AgentFailure)?;
        let signature = ssh_key::Signature::new(ssh_key::Algorithm::Ed25519, bytes)
            .map_err(|_| AgentError::AgentFailure)?;
        Vec::<u8>::try_from(signature).map_err(|_| AgentError::AgentFailure)
    }
}

/// Two disposable loaded keys and observable source requests on one owned local socket.
pub struct SourceAgent {
    state: Arc<State>,
    task: JoinHandle<io::Result<()>>,
}

impl Drop for SourceAgent {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl SourceAgent {
    /// Bind only the fixture's explicitly configured socket or named pipe.
    pub async fn start(selected: &Path, other: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        fn key(path: &Path) -> Result<SourceKey, Box<dyn std::error::Error>> {
            let bytes = SecretVec::new(std::fs::read(path)?);
            let key = ssh_key::PrivateKey::from_openssh(bytes.as_bytes())?;
            let seed = key.key_data().ed25519().ok_or("fixture requires Ed25519")?;
            Ok(SourceKey {
                identity: AgentIdentity::new(key.public_key().to_bytes()?, Vec::new())?,
                signer: Ed25519SshSigner::new(Ed25519SigningKey::from_bytes(
                    seed.private.as_ref(),
                )?),
            })
        }
        let path = std::env::var_os("SSH_AUTH_SOCK").ok_or("owned fixture socket is required")?;
        let state = Arc::new(State {
            keys: [key(selected)?, key(other)?],
            refuse: AtomicBool::new(false),
            stall: AtomicBool::new(false),
            other_signatures: AtomicUsize::new(0),
            unsupported: AtomicUsize::new(0),
            signatures: watch::channel(0).0,
            disconnected: watch::channel(0).0,
        });
        let source = state.clone();
        #[cfg(unix)]
        let task = {
            let listener = tokio::net::UnixListener::bind(path)?;
            tokio::spawn(async move {
                let mut peers = tokio::task::JoinSet::new();
                loop {
                    let (stream, _) = listener.accept().await?;
                    while peers.try_join_next().is_some() {}
                    if peers.len() >= 8 {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    peers.spawn(serve(stream, source.clone()));
                }
            })
        };
        #[cfg(windows)]
        let task = {
            use tokio::net::windows::named_pipe::ServerOptions;
            let mut listener = ServerOptions::new().first_pipe_instance(true).create(&path)?;
            tokio::spawn(async move {
                let mut peers = tokio::task::JoinSet::new();
                loop {
                    listener.connect().await?;
                    let next = ServerOptions::new().create(&path)?;
                    let stream = std::mem::replace(&mut listener, next);
                    while peers.try_join_next().is_some() {}
                    if peers.len() >= 8 {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    peers.spawn(serve(stream, source.clone()));
                }
            })
        };
        Ok(Self { state, task })
    }

    /// Count every source signature request, including an intentional refusal or stall.
    pub fn signatures(&self) -> u64 {
        *self.state.signatures.borrow()
    }

    /// Refuse later signatures without removing either loaded key.
    pub fn refuse(&self, refuse: bool) {
        self.state.refuse.store(refuse, Ordering::SeqCst);
    }

    /// Hold a later request until the forwarding owner closes its local source connection.
    pub fn stall(&self) {
        self.state.stall.store(true, Ordering::SeqCst);
    }

    /// Wait for a new source request without relying on a timing sleep.
    pub async fn requested_after(&self, count: u64) {
        self.state.signatures.subscribe().wait_for(|current| *current > count).await.unwrap();
    }

    /// Wait for the held source request to be closed by cancellation.
    pub async fn held_request_closed(&self) {
        self.state.disconnected.subscribe().wait_for(|count| *count != 0).await.unwrap();
    }

    /// Verify that other identities and forbidden operations never reached the source.
    pub fn assert_scoped(&self) {
        assert_eq!(self.state.other_signatures.load(Ordering::SeqCst), 0);
        assert_eq!(self.state.unsupported.load(Ordering::SeqCst), 0);
    }
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    state: Arc<State>,
) -> io::Result<()> {
    let server = AgentServer::new(SourceStore(state.clone()));
    loop {
        let length = match stream.read_u32().await {
            Ok(length) if length <= 262_144 => length,
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        let mut frame = length.to_be_bytes().to_vec();
        frame.resize(4 + length as usize, 0);
        stream.read_exact(&mut frame[4..]).await?;
        let request = AgentMessage::decode_frame(&frame).map_err(io::Error::other)?;
        match &request {
            AgentMessage::SignRequest { .. } => {
                state.signatures.send_modify(|count| *count += 1);
                if state.stall.load(Ordering::SeqCst) {
                    let closed = stream.read(&mut [0; 1]).await? == 0;
                    if !closed {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    state.disconnected.send_modify(|count| *count += 1);
                    return Ok(());
                }
            }
            AgentMessage::RequestIdentities => {}
            _ => {
                state.unsupported.fetch_add(1, Ordering::SeqCst);
            }
        }
        let response = server.dispatch(request).encode_frame().map_err(io::Error::other)?;
        stream.write_all(&response).await?;
    }
}
