// SPDX-License-Identifier: Apache-2.0

//! A Login opts in one exact agent identity for one live terminal attempt.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

use scoplen_client_platform::ssh_agent::connect_system_agent;
use scoplen_ssh::{
    AgentError, AgentForwardingAuthorizer, AgentForwardingPolicy, AgentIdentity, AgentKeyStore,
    AgentServer, ForwardedChannel, ForwardedChannelKind, ForwardedChannelReceiver,
};
use tokio::{
    runtime::Handle,
    sync::{Semaphore, watch},
    task::{AbortHandle, JoinHandle, JoinSet},
};
use uuid::Uuid;

use super::{CredentialMaterial, agent, preparation::PreparationControl};
use crate::repository::AccessProfile;

const SIGN_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_AGENT_CHANNELS: usize = 4;
static SIGNERS: Semaphore = Semaphore::const_new(MAX_AGENT_CHANNELS);
static CHANNELS: Semaphore = Semaphore::const_new(MAX_AGENT_CHANNELS);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForwardedAgent {
    identity: AgentIdentity,
}

impl ForwardedAgent {
    pub(super) fn capture(
        profile: &AccessProfile,
        credential_id: Uuid,
        credential: &CredentialMaterial,
    ) -> Result<Option<Self>, String> {
        if !profile.agent_forwarding {
            return Ok(None);
        }
        let invalid = || {
            "Agent forwarding requires this Login to select an Agent credential with its exact public key. Select that credential or turn forwarding off.".to_owned()
        };
        let CredentialMaterial::Agent { public_key } = credential else {
            return Err(invalid());
        };
        if profile.credential != Some(credential_id) {
            return Err(invalid());
        }
        let key = agent::parse_public_key(public_key.as_deref()).map_err(|_| invalid())?;
        let identity = AgentIdentity::new(key.to_bytes().map_err(|_| invalid())?, Vec::new())
            .map_err(|_| invalid())?;
        Ok(Some(Self { identity }))
    }
}

struct ServingState {
    active: AtomicBool,
    control: PreparationControl,
    stopped: watch::Sender<bool>,
    streams: Mutex<HashMap<Uuid, AbortHandle>>,
}

impl ServingState {
    fn new(control: PreparationControl) -> Arc<Self> {
        let (stopped, _) = watch::channel(false);
        Arc::new(Self {
            active: AtomicBool::new(true),
            control,
            stopped,
            streams: Mutex::default(),
        })
    }

    fn check(&self) -> Result<(), AgentError> {
        if !self.active.load(Ordering::Acquire) || self.control.is_cancelled() {
            Err(AgentError::AgentFailure)
        } else {
            Ok(())
        }
    }

    fn stop(&self) {
        self.active.store(false, Ordering::Release);
        self.stopped.send_replace(true);
        if let Ok(mut streams) = self.streams.lock() {
            for (_, stream) in streams.drain() {
                stream.abort();
            }
        }
    }

    async fn cancelled(&self) {
        let mut stopped = self.stopped.subscribe();
        tokio::select! {
            _ = stopped.wait_for(|stopped| *stopped) => {},
            _ = self.control.cancelled() => {},
        }
    }

    fn retain(self: &Arc<Self>, stream: AbortHandle) -> Result<AgentIo, AgentError> {
        let mut streams = self.streams.lock().map_err(|_| AgentError::AgentFailure)?;
        self.check()?;
        let id = Uuid::now_v7();
        streams.insert(id, stream);
        Ok(AgentIo { state: self.clone(), id })
    }
}

struct AgentIo {
    state: Arc<ServingState>,
    id: Uuid,
}

impl Drop for AgentIo {
    fn drop(&mut self) {
        if let Ok(mut streams) = self.state.streams.lock() {
            streams.remove(&self.id);
        }
    }
}

#[derive(Clone)]
struct SelectedAgent {
    selected: ForwardedAgent,
    state: Arc<ServingState>,
    runtime: Handle,
}

impl AgentForwardingAuthorizer for SelectedAgent {
    fn authorize_signature(
        &self,
        key_blob: &[u8],
        _data: &[u8],
        _flags: u32,
    ) -> Result<(), AgentError> {
        self.state.check()?;
        if key_blob == self.selected.identity.key_blob() {
            Ok(())
        } else {
            Err(AgentError::AgentFailure)
        }
    }
}

impl AgentKeyStore for SelectedAgent {
    fn identities(&self) -> Result<Vec<AgentIdentity>, AgentError> {
        self.state.check()?;
        Ok(vec![self.selected.identity.clone()])
    }

    fn sign(&self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>, AgentError> {
        self.authorize_signature(key_blob, data, flags)?;
        let _permit = SIGNERS.try_acquire().map_err(|_| AgentError::AgentFailure)?;
        let deadline = Instant::now() + SIGN_TIMEOUT;
        let (opened, stream) = mpsc::sync_channel(1);
        let state = self.state.clone();
        // The shared async serving adapter calls this synchronous signer from a
        // blocking worker. Submit local connection I/O to the existing executor
        // without entering another block_on inside that adapter's runtime context.
        self.runtime.spawn(async move {
            let result = tokio::select! { biased;
                _ = state.cancelled() => Err(AgentError::AgentFailure),
                stream = connect_system_agent(deadline) => stream.map_err(|_| AgentError::AgentFailure),
            };
            let _ = opened.send(result);
        });
        let remaining =
            deadline.checked_duration_since(Instant::now()).ok_or(AgentError::AgentFailure)?;
        let stream = stream.recv_timeout(remaining).map_err(|_| AgentError::AgentFailure)??;
        let _io = self.state.retain(stream.abort_handle())?;
        let mut client =
            agent::selected_client(stream, key_blob).map_err(|_| AgentError::AgentFailure)?;
        self.authorize_signature(key_blob, data, flags)?;
        let signature = client.sign(key_blob, data, flags)?;
        self.state.check()?;
        Ok(signature)
    }
}

/// Owns only incoming agent channels and bounded system-agent workers for this attempt.
pub(crate) struct AgentForwardingService {
    state: Arc<ServingState>,
    driver: Option<JoinHandle<()>>,
}

impl AgentForwardingService {
    pub(crate) fn start(
        selected: ForwardedAgent,
        control: PreparationControl,
        mut incoming: ForwardedChannelReceiver,
    ) -> Self {
        let state = ServingState::new(control);
        let source = SelectedAgent { selected, state: state.clone(), runtime: Handle::current() };
        let driver = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            loop {
                let channel = tokio::select! { biased;
                    _ = source.state.cancelled() => break,
                    channel = incoming.recv() => channel,
                };
                let Some(channel) = channel else { break };
                Self::accept(&source, &mut workers, channel);
            }
            source.state.stop();
            while workers.join_next().await.is_some() {}
        });
        Self { state, driver: Some(driver) }
    }

    fn accept(source: &SelectedAgent, workers: &mut JoinSet<()>, channel: ForwardedChannel) {
        if !matches!(channel.kind(), ForwardedChannelKind::Agent) || source.state.check().is_err() {
            return;
        }
        while workers.try_join_next().is_some() {}
        let Ok(permit) = CHANNELS.try_acquire() else { return };
        let source = source.clone();
        workers.spawn_blocking(move || {
            let _permit = permit;
            let runtime = source.runtime.clone();
            runtime.block_on(async {
                tokio::select! { biased;
                    _ = source.state.cancelled() => {},
                    _ = channel.serve_agent(
                        AgentServer::new(source.clone()),
                        AgentForwardingPolicy::enabled(source.clone()),
                    ) => {},
                }
            });
        });
    }

    pub(crate) async fn settle(&mut self) {
        self.state.stop();
        if let Some(driver) = self.driver.take() {
            let _ = driver.await;
        }
    }
}

impl Drop for AgentForwardingService {
    fn drop(&mut self) {
        self.state.stop();
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use scoplen_ssh::AgentMessage;

    use super::*;

    fn selected(control: PreparationControl) -> SelectedAgent {
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        SelectedAgent {
            selected: ForwardedAgent {
                identity: AgentIdentity::new(key.public_key().to_bytes().unwrap(), Vec::new())
                    .unwrap(),
            },
            state: ServingState::new(control),
            runtime: Handle::current(),
        }
    }

    #[tokio::test]
    async fn only_selected_identity_is_exposed_and_each_signature_checks_live_attempt() {
        let control = PreparationControl::default();
        let source = selected(control.clone());
        let key = source.selected.identity.key_blob().to_vec();
        assert_eq!(source.identities().unwrap(), vec![source.selected.identity.clone()]);
        assert!(source.authorize_signature(&key, b"data", 0).is_ok());
        assert!(source.authorize_signature(b"unselected", b"data", 0).is_err());
        assert!(source.sign(b"unselected", b"data", 0).is_err());
        control.cancel();
        assert!(source.authorize_signature(&key, b"late", 0).is_err());
        assert!(source.identities().is_err());
        assert!(source.sign(&key, b"late", 0).is_err());
    }

    #[tokio::test]
    async fn forwarded_management_extensions_and_unselected_signing_preserve_identity_queries() {
        let source = selected(PreparationControl::default());
        let policy = AgentForwardingPolicy::enabled(source.clone());
        let identity = source.selected.identity.clone();
        let server = AgentServer::new(source);
        for request in [
            AgentMessage::RemoveAllIdentities,
            AgentMessage::ExtensionRequest {
                name: b"session-bind@openssh.com".to_vec(),
                contents: vec![],
            },
            AgentMessage::SignRequest {
                key_blob: b"unselected".to_vec(),
                data: b"data".to_vec(),
                flags: 0,
            },
        ] {
            assert!(matches!(server.dispatch_forwarded(request, &policy), AgentMessage::Failure));
            assert_eq!(
                server.dispatch_forwarded(AgentMessage::RequestIdentities, &policy),
                AgentMessage::IdentitiesAnswer { identities: vec![identity.clone()] }
            );
        }
    }

    #[tokio::test]
    async fn ending_forwarding_refuses_queued_requests_without_cancelling_the_terminal() {
        let control = PreparationControl::default();
        let source = selected(control.clone());
        let key = source.selected.identity.key_blob().to_vec();
        source.state.stop();
        source.state.cancelled().await;
        assert!(!control.is_cancelled());
        assert!(source.identities().is_err());
        assert!(source.sign(&key, b"late", 0).is_err());
    }
}
