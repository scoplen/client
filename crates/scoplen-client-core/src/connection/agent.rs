// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use scoplen_client_platform::ssh_agent::{AgentStream, connect_system_agent};
use scoplen_ssh::{AgentClient, AgentSshSigner, FramedAgentChannel};
use ssh_key::PublicKey;
use tokio::{sync::Semaphore, task::AbortHandle};

use super::{ClientError, SignatureAlgorithm, SshConnection, SshConnectionError};

const AGENT_TIMEOUT: Duration = Duration::from_secs(10);
static WORKERS: Semaphore = Semaphore::const_new(4);

pub(super) fn parse_public_key(value: Option<&str>) -> Result<PublicKey, SshConnectionError> {
    let value = value
        .filter(|value| value.len() <= super::MAX_SSH_INPUT)
        .ok_or(SshConnectionError::InvalidAgentPublicKey)?;
    let key =
        PublicKey::from_openssh(value).map_err(|_| SshConnectionError::InvalidAgentPublicKey)?;
    match key.algorithm().as_str() {
        "ssh-ed25519"
        | "ssh-rsa"
        | "ecdsa-sha2-nistp256"
        | "ecdsa-sha2-nistp384"
        | "ecdsa-sha2-nistp521"
        | "sk-ssh-ed25519@openssh.com"
        | "sk-ecdsa-sha2-nistp256@openssh.com" => Ok(key),
        _ => Err(SshConnectionError::InvalidAgentPublicKey),
    }
}

fn algorithm(key: &PublicKey) -> SignatureAlgorithm {
    match key.algorithm().as_str() {
        "ssh-ed25519" => SignatureAlgorithm::Ed25519,
        "ecdsa-sha2-nistp256" => SignatureAlgorithm::EcdsaSha2Nistp256,
        "ecdsa-sha2-nistp384" => SignatureAlgorithm::EcdsaSha2Nistp384,
        "ecdsa-sha2-nistp521" => SignatureAlgorithm::EcdsaSha2Nistp521,
        "sk-ssh-ed25519@openssh.com" => SignatureAlgorithm::SkEd25519,
        "sk-ecdsa-sha2-nistp256@openssh.com" => SignatureAlgorithm::SkEcdsaSha2Nistp256,
        _ => SignatureAlgorithm::RsaSha2_512,
    }
}

struct CancelAgent {
    stream: AbortHandle,
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for CancelAgent {
    fn drop(&mut self) {
        self.stream.abort();
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

fn selected_client(
    stream: AgentStream,
    key_blob: &[u8],
) -> Result<AgentClient<FramedAgentChannel<AgentStream>>, SshConnectionError> {
    let mut client = AgentClient::new(FramedAgentChannel::new(stream));
    let identities = client.identities().map_err(|_| SshConnectionError::AgentUnavailable)?;
    if !identities.iter().any(|identity| identity.key_blob() == key_blob) {
        return Err(SshConnectionError::AgentIdentityMissing);
    }
    Ok(client)
}

impl SshConnection {
    pub(super) async fn authenticate_agent(
        &mut self,
        username: &str,
        public_key: Option<&str>,
    ) -> Result<(), SshConnectionError> {
        let key = parse_public_key(public_key)?;
        let key_blob = key.to_bytes().map_err(|_| SshConnectionError::InvalidAgentPublicKey)?;
        let permit = WORKERS.try_acquire().map_err(|_| SshConnectionError::AgentBusy)?;
        let deadline = std::time::Instant::now() + AGENT_TIMEOUT;
        let stream = connect_system_agent(deadline).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut {
                SshConnectionError::AgentTimeout
            } else {
                SshConnectionError::AgentUnavailable
            }
        })?;
        let (cancel, mut cancelled) = tokio::sync::oneshot::channel();
        let guard = CancelAgent { stream: stream.abort_handle(), cancel: Some(cancel) };
        let mut connection = self.connection.take().ok_or(SshConnectionError::AgentCancelled)?;
        let username = username.to_owned();
        let runtime = tokio::runtime::Handle::current();
        // Signer::sign is synchronous. Its bounded local I/O must not block the
        // application's executor, including a single-threaded test runtime.
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let result = (|| {
                let client = selected_client(stream, &key_blob)?;
                runtime.block_on(async {
                    tokio::select! {
                        biased;
                        _ = &mut cancelled => Err(SshConnectionError::AgentCancelled),
                        result = tokio::time::timeout_at(deadline.into(), async {
                            let algorithm = if key.algorithm().as_str() == "ssh-rsa" {
                                super::rsa_signature_algorithm(connection.server_rsa_sha2_selection().await?)?
                            } else {
                                algorithm(&key)
                            };
                            let signer = AgentSshSigner::new(client, algorithm, key_blob)
                                .map_err(|_| SshConnectionError::InvalidAgentPublicKey)?;
                            connection.authenticate_publickey(&username, &signer).await.map_err(|error| {
                                if matches!(error, ClientError::PublicKey(_)) {
                                    SshConnectionError::AgentSigningFailed
                                } else {
                                    SshConnectionError::Engine(error)
                                }
                            })
                        }) => result.unwrap_or(Err(SshConnectionError::AgentTimeout)),
                    }
                })
            })();
            let result = if cancelled.try_recv().is_ok() {
                Err(SshConnectionError::AgentCancelled)
            } else if result.is_err() && std::time::Instant::now() >= deadline {
                Err(SshConnectionError::AgentTimeout)
            } else {
                result
            };
            (connection, result)
        });
        let (connection, result) =
            worker.await.map_err(|_| SshConnectionError::AgentUnavailable)?;
        // A dropped caller owns no connection or result; the guard cancels the
        // worker and closes its agent transport. Only this live caller restores it.
        self.connection = Some(connection);
        drop(guard);
        result
    }
}
