// SPDX-License-Identifier: Apache-2.0

//! Cancellable, per-hop SSH preparation. No authentication precedes host trust.

use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use scoplen_crypto::SecretVec;
use scoplen_ssh::{HostKey, HostKeyVerificationError, HostKeyVerifier};
use serde::Serialize;
use specta::Type;
use tokio::sync::{oneshot, watch};
use uuid::Uuid;

use super::trust::TrustPolicy;
use super::{
    ConnectionPlan, ConnectionRoute, HostKeyPresentation, HostKeyReview, HostKeyStatus,
    HostKeyTrustSource, MAX_PRIVATE_KEY_PASSPHRASE, SshConnection, SshConnectionError,
    assess_host_key, private_key_passphrase_required, resolve_connection_plan, transport_route,
    validate_credential,
};
use crate::repository::{
    AccessProfile, Change, Edit, Host, Provenance, Record, RecordError, Repository, TrustRecord,
    TrustRecordChange,
};
use crate::store::{LocalWrite, Store};

/// Safe identity shown on every progress event and prompt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PreparationContext {
    /// Login identifier.
    pub profile_id: String,
    /// Host identifier.
    pub host_id: String,
    /// Saved Login label, or its username.
    pub login: String,
    /// Saved Host label, or its address.
    pub host: String,
    /// Remote username.
    pub username: String,
    /// DNS name or IP literal.
    pub address: String,
    /// SSH port.
    pub port: u16,
    /// One-based position, including the target.
    pub position: u32,
    /// Number of hops plus target.
    pub total: u32,
    /// Whether this is the target rather than a jump host.
    pub target: bool,
}

/// Display-safe host key associated with the current unauthed connection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PreparationHostKey {
    /// Algorithm identifier.
    pub algorithm: String,
    /// OpenSSH public key.
    pub key: String,
    /// OpenSSH SHA-256 fingerprint.
    pub fingerprint: String,
    /// An active record exists but does not match.
    pub changed: bool,
    /// A matching key needs review because its source is no longer trusted.
    pub review: Option<HostKeyReview>,
    /// Previously verified provenance, present only for an authenticated source.
    pub previous_source: Option<HostKeyTrustSource>,
}

/// States emitted by the core, never inferred by the renderer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum PreparationPhase {
    /// Dialing or SSH key exchange.
    Connecting,
    /// Authentication after host trust.
    Authenticating,
}

/// Typed progress and current user intent requested by Rust.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum PreparationEvent {
    /// Trust resolved on the retained connection, before credentials are used.
    Verified {
        /// Current hop.
        context: PreparationContext,
        /// Presented algorithm.
        algorithm: String,
        /// Presented fingerprint.
        fingerprint: String,
        /// Verified origin of the trust used for this connection.
        source: HostKeyTrustSource,
    },
    /// No user response is expected.
    Progress {
        /// Current hop.
        context: PreparationContext,
        /// Current operation.
        phase: PreparationPhase,
    },
    /// Confirm the actual key on this still unauthenticated connection.
    Trust {
        /// Current hop.
        context: PreparationContext,
        /// Fresh one-use response token.
        prompt_id: String,
        /// Key presented by this hop.
        host_key: PreparationHostKey,
    },
    /// Enter a one-time passphrase for this hop's encrypted software key.
    Passphrase {
        /// Current hop.
        context: PreparationContext,
        /// Fresh one-use response token.
        prompt_id: String,
        /// A preceding local decryption failed.
        incorrect: bool,
    },
}

/// One response converted at the IPC boundary. Secret debug output is redacted.
#[derive(Debug)]
pub enum PreparationResponse {
    /// Accept the exact key retained by the core.
    AcceptHostKey,
    /// One-time key passphrase.
    Passphrase(SecretVec),
}

/// A preparation failure whose network cause remains available to session policy.
#[derive(Debug, thiserror::Error)]
pub enum PreparationError {
    /// Typed transport, authentication, or protocol failure.
    #[error(transparent)]
    Connection(#[from] SshConnectionError),
    /// Local configuration, cancellation, prompt, or frontend failure.
    #[error("{0}")]
    Local(String),
}

impl From<String> for PreparationError {
    fn from(value: String) -> Self {
        Self::Local(value)
    }
}

impl From<&str> for PreparationError {
    fn from(value: &str) -> Self {
        Self::Local(value.into())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PromptKind {
    Trust,
    Passphrase,
}

struct PendingPrompt {
    id: String,
    kind: PromptKind,
    sender: oneshot::Sender<PreparationResponse>,
}

#[derive(Default)]
struct ControlState {
    cancelled: bool,
    pending: Option<PendingPrompt>,
}

/// Session-owned cancellation and prompt fencing, shared with the IPC registry.
#[derive(Clone)]
pub struct PreparationControl {
    state: Arc<Mutex<ControlState>>,
    close: watch::Sender<bool>,
}

impl Default for PreparationControl {
    fn default() -> Self {
        let (close, _) = watch::channel(false);
        Self { state: Arc::default(), close }
    }
}

impl PreparationControl {
    /// Whether the person has cancelled this exact preparation attempt.
    pub fn is_cancelled(&self) -> bool {
        self.state.lock().map_or(true, |state| state.cancelled)
    }

    /// Cancel pending I/O and prompts. Linearizes against trust writes.
    pub fn cancel(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.cancelled = true;
            state.pending.take();
            self.close.send_replace(true);
        }
    }

    /// Wait until cancellation, including cancellation before subscription.
    pub async fn cancelled(&self) {
        let mut close = self.close.subscribe();
        let _ = close.wait_for(|closed| *closed).await;
    }

    /// Supply exactly one correctly typed response to the current prompt.
    pub fn respond(&self, prompt_id: &str, response: PreparationResponse) -> Result<(), String> {
        if let PreparationResponse::Passphrase(secret) = &response
            && (secret.as_bytes().is_empty() || secret.len() > MAX_PRIVATE_KEY_PASSPHRASE)
        {
            return Err("enter a private-key passphrase of 1-4096 bytes".into());
        }
        let mut state = self.state.lock().map_err(|_| "preparation is unavailable")?;
        let kind = match response {
            PreparationResponse::AcceptHostKey => PromptKind::Trust,
            PreparationResponse::Passphrase(_) => PromptKind::Passphrase,
        };
        if state.cancelled
            || !state.pending.as_ref().is_some_and(|p| p.id == prompt_id && p.kind == kind)
        {
            return Err("this connection prompt has expired".into());
        }
        let pending = state.pending.take().expect("checked pending prompt");
        pending.sender.send(response).map_err(|_| "this connection prompt has expired".into())
    }

    fn active<T>(&self, operation: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let state = self.state.lock().map_err(|_| "preparation is unavailable")?;
        if state.cancelled {
            return Err("connection was cancelled".into());
        }
        operation()
    }

    async fn run<T>(
        &self,
        operation: impl Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        tokio::select! { biased;
            _ = self.cancelled() => Err("connection was cancelled".into()),
            result = operation => result,
        }
    }

    async fn prompt(
        &self,
        kind: PromptKind,
        event: impl FnOnce(String) -> PreparationEvent,
        emit: &impl Fn(PreparationEvent) -> Result<(), String>,
    ) -> Result<PreparationResponse, String> {
        let id = Uuid::now_v7().to_string();
        let (sender, receiver) = oneshot::channel();
        {
            let mut state = self.state.lock().map_err(|_| "preparation is unavailable")?;
            if state.cancelled {
                return Err("connection was cancelled".into());
            }
            state.pending = Some(PendingPrompt { id: id.clone(), kind, sender });
        }
        emit(event(id))?;
        self.run(async { receiver.await.map_err(|_| "connection prompt was cancelled".into()) })
            .await
    }
}

/// Captures only the first negotiated key. Rekey may never change it, even
/// while the user is still reviewing that first key.
#[derive(Default)]
struct PresentedKey(Mutex<Option<HostKeyPresentation>>);

impl HostKeyVerifier for PresentedKey {
    fn verify(&self, _host: &str, key: &HostKey) -> Result<(), HostKeyVerificationError> {
        let presentation = HostKeyPresentation::from_host_key(key);
        let mut first = self.0.lock().map_err(|_| {
            HostKeyVerificationError::Rejected("host-key state is unavailable".into())
        })?;
        match first.as_ref() {
            Some(expected) if expected != &presentation => Err(HostKeyVerificationError::Rejected(
                "host key changed during this connection".into(),
            )),
            Some(_) => Ok(()),
            None => {
                *first = Some(presentation);
                Ok(())
            }
        }
    }
}

struct Step {
    plan: ConnectionPlan,
    context: PreparationContext,
    passphrase: bool,
}

struct ConnectionStack(Vec<SshConnection>);

impl Drop for ConnectionStack {
    fn drop(&mut self) {
        while self.0.pop().is_some() {}
    }
}

fn resolve_steps(store: &Store, target_id: Uuid) -> Result<Vec<Step>, String> {
    let target = resolve_connection_plan(store, target_id).map_err(|e| e.to_string())?;
    let mut plans = Vec::new();
    if let ConnectionRoute::Jump { hops } = &target.route {
        if hops.is_empty() {
            return Err("the jump route has no Logins; edit the route before connecting".into());
        }
        let mut profiles = HashSet::from([target.profile_id]);
        let mut hosts = HashSet::from([target.host_id]);
        for id in hops {
            let plan = resolve_connection_plan(store, *id)
                .map_err(|e| format!("jump Login could not be resolved: {e}"))?;
            if !profiles.insert(plan.profile_id) || !hosts.insert(plan.host_id) {
                return Err("the jump route repeats a Login or Host, or returns to the target; edit the route before connecting".into());
            }
            if plan.route != ConnectionRoute::Direct {
                return Err("a jump Login has its own non-Direct route; select Direct on each jump Login before connecting".into());
            }
            plans.push(plan);
        }
        let mut target = target;
        target.route = ConnectionRoute::Direct;
        plans.push(target);
    } else {
        plans.push(target);
    }
    let total = u32::try_from(plans.len()).map_err(|_| "the jump route is too large")?;
    let mut steps = Vec::with_capacity(plans.len());
    for (index, plan) in plans.into_iter().enumerate() {
        transport_route(&plan).map_err(|e| e.to_string())?;
        validate_credential(&plan.credential).map_err(|e| e.to_string())?;
        let passphrase =
            private_key_passphrase_required(&plan.credential).map_err(|e| e.to_string())?;
        let profile = Repository::<AccessProfile>::new(store)
            .get(plan.profile_id)
            .map_err(|e| e.to_string())?
            .ok_or("the Login was not found")?;
        let host = Repository::<Host>::new(store)
            .get(plan.host_id)
            .map_err(|e| e.to_string())?
            .ok_or("the Host was not found")?;
        let context = PreparationContext {
            profile_id: plan.profile_id.to_string(),
            host_id: plan.host_id.to_string(),
            login: profile.name.unwrap_or_else(|| plan.username.clone()),
            host: host.name,
            username: plan.username.clone(),
            address: plan.address.clone(),
            port: plan.port,
            position: index as u32 + 1,
            total,
            target: index as u32 + 1 == total,
        };
        steps.push(Step { plan, context, passphrase });
    }
    Ok(steps)
}

fn accept_key(store: &Store, host: Uuid, key: &HostKeyPresentation) -> Result<(), String> {
    let records = Repository::<TrustRecord>::new(store).list().map_err(|e| e.to_string())?;
    let policy = TrustPolicy::load(store, &records)?;
    let account = policy.acceptance_account();
    store
        .write_batch_with_snapshot::<RecordError>(TrustRecord::TYPE, |objects| {
            let records = objects.iter().map(TrustRecord::read).collect::<Result<Vec<_>, _>>()?;
            if policy.assess(host, key, &records).status == HostKeyStatus::Trusted {
                return Ok(Vec::new());
            }
            let mut writes = Vec::new();
            for record in records.iter().filter(|r| {
                r.host == Some(host)
                    && !r.revoked
                    && !r.ca
                    && (r.key.as_deref() != Some(&key.key)
                        || r.fingerprint.as_deref() != Some(&key.fingerprint))
            }) {
                writes.push(LocalWrite {
                    id: Some(record.meta.id),
                    object_type: TrustRecord::TYPE,
                    fields: TrustRecordChange { revoked: Some(true), ..Default::default() }
                        .into_writes()?,
                });
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis().try_into().unwrap_or(u64::MAX));
            writes.push(LocalWrite {
                id: None,
                object_type: TrustRecord::TYPE,
                fields: TrustRecordChange {
                    host: Edit::Set(host),
                    key: Edit::Set(key.key.clone()),
                    fingerprint: Edit::Set(key.fingerprint.clone()),
                    provenance: Some(Provenance::Manual),
                    accepted_at: Edit::Set(now),
                    accepted_by_device: Edit::Set(store.device_id()),
                    accepted_by_account: account.map_or(Edit::Keep, Edit::Set),
                    ..Default::default()
                }
                .into_writes()?,
            });
            Ok(writes)
        })
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Resolve the entire chain locally, then prepare each hop in order.
/// The returned target owns all parents. Errors close every retained connection
/// in reverse order, including the currently unauthenticated hop.
pub async fn prepare_connection(
    store: &Store,
    profile_id: Uuid,
    control: &PreparationControl,
    emit: impl Fn(PreparationEvent) -> Result<(), String>,
) -> Result<SshConnection, PreparationError> {
    let steps = resolve_steps(store, profile_id)?;
    let mut connections = ConnectionStack(Vec::new());
    let result = async {
        for step in steps {
            control.active(|| Ok(()))?;
            emit(PreparationEvent::Progress {
                context: step.context.clone(),
                phase: PreparationPhase::Connecting,
            })?;
            let presented = Arc::new(PresentedKey::default());
            let connection = control
                .run(async {
                    Ok(SshConnection::connect_over(
                        &step.plan,
                        Some(presented.clone()),
                        connections.0.last(),
                    )
                    .await)
                })
                .await??;
            connections.0.push(connection);
            let key = presented
                .0
                .lock()
                .map_err(|_| "host-key state is unavailable")?
                .clone()
                .ok_or("SSH server did not present a host key")?;
            let assessment = assess_host_key(store, step.plan.host_id, &key)?;
            let status = assessment.status;
            if status != HostKeyStatus::Trusted {
                control
                    .prompt(
                        PromptKind::Trust,
                        |prompt_id| PreparationEvent::Trust {
                            context: step.context.clone(),
                            prompt_id,
                            host_key: PreparationHostKey {
                                algorithm: key.algorithm.clone(),
                                key: key.key.clone(),
                                fingerprint: key.fingerprint.clone(),
                                changed: status == HostKeyStatus::Changed,
                                review: assessment.review,
                                previous_source: assessment.source.clone(),
                            },
                        },
                        &emit,
                    )
                    .await?;
                control.active(|| accept_key(store, step.plan.host_id, &key))?;
            }
            let confirmed = assess_host_key(store, step.plan.host_id, &key)?;
            if confirmed.status != HostKeyStatus::Trusted {
                return Err(
                    "host-key trust changed during preparation; connect again to review it".into(),
                );
            }
            emit(PreparationEvent::Verified {
                context: step.context.clone(),
                algorithm: key.algorithm,
                fingerprint: key.fingerprint,
                source: confirmed.source.ok_or("host-key provenance is unavailable")?,
            })?;
            let connection = connections.0.last_mut().expect("current connection retained");
            let mut incorrect = false;
            loop {
                let passphrase = if step.passphrase {
                    match control
                        .prompt(
                            PromptKind::Passphrase,
                            |prompt_id| PreparationEvent::Passphrase {
                                context: step.context.clone(),
                                prompt_id,
                                incorrect,
                            },
                            &emit,
                        )
                        .await?
                    {
                        PreparationResponse::Passphrase(secret) => Some(secret),
                        _ => return Err("unexpected connection response".into()),
                    }
                } else {
                    None
                };
                control.active(|| Ok(()))?;
                emit(PreparationEvent::Progress {
                    context: step.context.clone(),
                    phase: PreparationPhase::Authenticating,
                })?;
                let authenticated = control
                    .run(async { Ok(connection.authenticate_with_passphrase(passphrase).await) })
                    .await?;
                match authenticated {
                    Err(SshConnectionError::InvalidPrivateKeyPassphrase) if step.passphrase => {
                        incorrect = true
                    }
                    result => {
                        result?;
                        break;
                    }
                }
            }
        }
        Ok::<(), PreparationError>(())
    }
    .await;
    if let Err(error) = result {
        while let Some(connection) = connections.0.pop() {
            let _ = connection.close().await;
        }
        return Err(error);
    }
    let mut target = connections.0.pop().expect("target step exists");
    target.parents = std::mem::take(&mut connections.0)
        .into_iter()
        .filter_map(|mut connection| connection.connection.take())
        .collect();
    Ok(target)
}

#[cfg(test)]
mod tests;
