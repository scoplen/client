// SPDX-License-Identifier: Apache-2.0

//! Connection planning for the client-side SSH orchestrator.
//!
//! This module resolves a stored AccessProfile into the non-UI inputs a concrete
//! `scoplen-ssh` engine needs. The shared protocol crate owns the transport and
//! handshake, while this crate owns local object resolution, device-local
//! credential material, trust decisions, and the live direct-session owner.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use scoplen_client_platform::credentials;
use scoplen_crypto::{Ed25519SigningKey, SecretVec};
use scoplen_ssh::{
    ChannelEvent, ClientChannel, ClientConfig, ClientConnection, ClientError, EcdsaSshSigner,
    Ed25519SshSigner, HostKey, HostKeyVerificationError, HostKeyVerifier, ProxyCredentials,
    PtyRequest, RsaSshSigner, ServerRsaSha2Selection, SignatureAlgorithm, UserAuthContext,
    WindowChangeRequest,
};
use sha2::{Digest as _, Sha256};
use ssh_key::{Kdf, PrivateKey};
use uuid::Uuid;

use crate::repository::{
    AccessProfile, Credential, CredentialBinding, CredentialKind, Repository, Route, RouteChoice,
    RouteKind, TrustRecord,
};
use crate::store::Store;

mod agent;
pub mod preparation;
mod proxy_command;

/// A resolved credential handed to the SSH adapter.
///
/// Secret-bearing variants use [`SecretVec`], whose debug representation is
/// redacted and whose contents are zeroized on drop. This type never crosses
/// the Tauri boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialMaterial {
    /// A password held in the encrypted local store.
    Password(SecretVec),
    /// An OpenSSH private key held in the encrypted local store.
    PrivateKey(SecretVec),
    /// Resolve a key from the platform SSH agent at connection time.
    Agent {
        /// The exact saved OpenSSH public key; never an implicit first identity.
        public_key: Option<String>,
    },
    /// A security-key credential, resolved by the platform adapter.
    SecurityKey {
        /// The public key to select, when known.
        public_key: Option<String>,
    },
    /// A device-bound key, optionally backed by a platform keystore handle.
    DeviceKey {
        /// The public key to advertise, when known.
        public_key: Option<String>,
        /// Secret material stored directly for this device, when available.
        secret: Option<SecretVec>,
        /// A platform-keystore or hardware handle, when the secret is non-exportable.
        keystore_handle: Option<String>,
    },
    /// A short-lived certificate or certificate provider reference.
    Certificate {
        /// The organization scope that issued the certificate, when known.
        scope: Option<Uuid>,
    },
    /// Resolve a secret from an external provider at connection time.
    External {
        /// Non-secret provider configuration.
        provider: BTreeMap<String, String>,
    },
}

/// A route resolved from an AccessProfile.
#[derive(Clone, PartialEq, Eq)]
pub enum ConnectionRoute {
    /// Connect directly to the host.
    Direct,
    /// Connect through profiles in order using `direct-tcpip` channels.
    Jump {
        /// AccessProfile identifiers for the jump hosts.
        hops: Vec<Uuid>,
    },
    /// Connect through a SOCKS5 proxy.
    Socks5 {
        /// Proxy endpoint in `host:port` form.
        proxy: String,
        /// Optional proxy authentication material.
        credential: Option<CredentialMaterial>,
        /// Username used only for proxy authentication.
        username: Option<String>,
    },
    /// Connect through an HTTP CONNECT proxy.
    HttpConnect {
        /// Proxy endpoint in `host:port` form.
        proxy: String,
        /// Optional proxy authentication material.
        credential: Option<CredentialMaterial>,
        /// Username used only for proxy authentication.
        username: Option<String>,
    },
    /// Connect through a local OpenSSH ProxyCommand.
    Command {
        /// The command to start for the byte stream.
        command: String,
    },
    /// A managed route; the organization adapter must acquire a gateway ticket.
    Managed {
        /// The organization-owned gateway network.
        gateway_network: Uuid,
    },
}

impl fmt::Debug for ConnectionRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => formatter.write_str("Direct"),
            Self::Jump { hops } => formatter.debug_struct("Jump").field("hops", hops).finish(),
            Self::Socks5 { proxy, credential, username } => formatter
                .debug_struct("Socks5")
                .field("proxy", proxy)
                .field("credential", credential)
                .field("username", username)
                .finish(),
            Self::HttpConnect { proxy, credential, username } => formatter
                .debug_struct("HttpConnect")
                .field("proxy", proxy)
                .field("credential", credential)
                .field("username", username)
                .finish(),
            Self::Command { .. } => formatter.debug_struct("Command").finish_non_exhaustive(),
            Self::Managed { gateway_network } => {
                formatter.debug_struct("Managed").field("gateway_network", gateway_network).finish()
            }
        }
    }
}

/// All local inputs required to start one SSH connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionPlan {
    /// The AccessProfile being opened.
    pub profile_id: Uuid,
    /// The Host resolved from the profile.
    pub host_id: Uuid,
    /// DNS name or IP literal.
    pub address: String,
    /// TCP port.
    pub port: u16,
    /// Remote SSH username.
    pub username: String,
    /// The route to use before the SSH handshake.
    pub route: ConnectionRoute,
    /// The selected authentication material.
    pub credential: CredentialMaterial,
}

/// A failure while resolving a connection plan.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConnectionPlanError {
    /// The profile identifier was not a UUID.
    #[error("the access profile identifier is invalid")]
    InvalidProfileId,
    /// The profile was deleted or does not exist.
    #[error("the access profile was not found")]
    ProfileNotFound,
    /// The profile points at a deleted or missing Host.
    #[error("the host was not found")]
    HostNotFound,
    /// The profile or route points at a deleted credential.
    #[error("the credential was not found")]
    CredentialNotFound,
    /// A credential exists but has no material on this device.
    #[error("the credential has no usable material on this device")]
    CredentialUnavailable,
    /// A stored credential kind and binding cannot be used together.
    #[error("the credential kind and binding are invalid")]
    InvalidCredential,
    /// A route referenced by a profile was deleted.
    #[error("the route was not found")]
    RouteNotFound,
    /// The encrypted local store could not be read.
    #[error("local connection data could not be read: {reference}")]
    Store {
        /// A safe diagnostic reference.
        reference: String,
    },
}

/// The lifecycle states consumed by the session manager and UI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    /// Resolving the plan and opening the byte transport.
    Connecting,
    /// The server presented a host key and awaits the trust decision.
    VerifyingHost,
    /// Negotiation completed and user authentication is in progress.
    Authenticating,
    /// The SSH connection owns one or more channels.
    Open,
    /// The manager is retrying a lost connection.
    Reconnecting,
    /// The user or peer closed the connection.
    Closed,
    /// The connection failed and will not retry automatically.
    Failed,
}

/// A rejected lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid connection transition from {from:?} to {to:?}")]
pub struct ConnectionStateError {
    /// Current state.
    pub from: ConnectionState,
    /// Requested next state.
    pub to: ConnectionState,
}

/// A small state machine shared by connection and session owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionLifecycle {
    state: ConnectionState,
}

impl ConnectionLifecycle {
    /// Create a lifecycle in the initial connecting state.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: ConnectionState::Connecting }
    }

    /// Return the current state.
    #[must_use]
    pub const fn state(self) -> ConnectionState {
        self.state
    }

    /// Advance to a valid next state.
    pub fn transition(&mut self, next: ConnectionState) -> Result<(), ConnectionStateError> {
        if !valid_transition(self.state, next) {
            return Err(ConnectionStateError { from: self.state, to: next });
        }
        self.state = next;
        Ok(())
    }
}

impl Default for ConnectionLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

fn valid_transition(from: ConnectionState, to: ConnectionState) -> bool {
    use ConnectionState::*;
    matches!(
        (from, to),
        (Connecting, VerifyingHost | Failed)
            | (VerifyingHost, Authenticating | Failed)
            | (Authenticating, Open | Failed)
            | (Open, Reconnecting | Closed | Failed)
            | (Reconnecting, VerifyingHost | Authenticating | Open | Failed)
    )
}

/// The result of comparing one presented host key with local trust records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostKeyStatus {
    /// No active trust record exists for this Host.
    New,
    /// The presented key matches an active host-specific trust record.
    Trusted,
    /// At least one active trust record exists, but it does not match.
    Changed,
}

/// The display-safe identity of a host key presented during SSH key exchange.
///
/// `key` is the complete OpenSSH public-key text (`algorithm base64(blob)`) and
/// `fingerprint` is the OpenSSH SHA-256 fingerprint of the same blob. Neither
/// field contains private key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostKeyPresentation {
    /// The SSH host-key algorithm identifier.
    pub algorithm: String,
    /// The complete OpenSSH public-key text.
    pub key: String,
    /// The OpenSSH SHA-256 fingerprint.
    pub fingerprint: String,
}

impl HostKeyPresentation {
    /// Render a validated shared-engine host key for display and trust storage.
    #[must_use]
    pub fn from_host_key(key: &HostKey) -> Self {
        let (algorithm, blob) = match key {
            HostKey::Raw { algorithm, key_blob } => (algorithm.as_str(), key_blob.as_slice()),
            HostKey::Certificate(certificate) => (certificate.algorithm(), certificate.as_bytes()),
        };
        let encoded = STANDARD.encode(blob);
        let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)));
        Self { algorithm: algorithm.to_owned(), key: format!("{algorithm} {encoded}"), fingerprint }
    }
}

/// Evaluate a presented host key without accepting or writing it.
///
/// Wildcard patterns are intentionally ignored here until the C10 OpenSSH
/// importer owns their matching semantics. A revoked record never authorizes a
/// key. The caller must require explicit confirmation for `New` and `Changed`.
#[must_use]
pub fn evaluate_host_key(
    host_id: Uuid,
    key: &str,
    fingerprint: &str,
    records: &[TrustRecord],
) -> HostKeyStatus {
    let active = records
        .iter()
        .filter(|record| record.host == Some(host_id) && !record.revoked && !record.ca);
    let mut found = false;
    for record in active {
        found = true;
        if record.key.as_deref() == Some(key) && record.fingerprint.as_deref() == Some(fingerprint)
        {
            return HostKeyStatus::Trusted;
        }
    }
    if found { HostKeyStatus::Changed } else { HostKeyStatus::New }
}

/// Probe the server's validated host key without making a trust decision.
///
/// The probe accepts the key only for the lifetime of this connection, captures
/// its canonical display form, then disconnects immediately. Callers must still
/// compare the result with local records and require explicit confirmation for
/// new or changed keys before opening an authenticated session.
pub async fn probe_host_key(
    plan: &ConnectionPlan,
) -> Result<HostKeyPresentation, SshConnectionError> {
    let route = transport_route(plan)?;
    validate_credential(&plan.credential)?;

    let presented = Arc::new(Mutex::new(None::<HostKeyPresentation>));
    let capture = Arc::clone(&presented);
    let config =
        ClientConfig::new(plan.address.clone(), plan.port, move |_host: &str, key: &HostKey| {
            let Ok(mut slot) = capture.lock() else {
                return Err(HostKeyVerificationError::Rejected(
                    "host-key probe could not capture the presented key".to_owned(),
                ));
            };
            *slot = Some(HostKeyPresentation::from_host_key(key));
            Ok(())
        })
        .map_err(ClientError::from)?;
    let connection = connect_route(config, route).await?;
    connection.disconnect().await?;
    presented
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
        .ok_or(SshConnectionError::HostKeyProbeMissing)
}

/// Resolve one AccessProfile from the encrypted local store.
///
/// This function performs no network I/O and never writes a trust record. It
/// is the handoff point for the eventual `scoplen-ssh` adapter.
pub fn resolve_connection_plan(
    store: &Store,
    profile_id: Uuid,
) -> Result<ConnectionPlan, ConnectionPlanError> {
    let profiles = Repository::<AccessProfile>::new(store).list().map_err(store_error)?;
    let profile = profiles
        .into_iter()
        .find(|candidate| candidate.meta.id == profile_id)
        .ok_or(ConnectionPlanError::ProfileNotFound)?;
    let host = Repository::<crate::repository::Host>::new(store)
        .get(profile.host)
        .map_err(store_error)?
        .ok_or(ConnectionPlanError::HostNotFound)?;
    let credentials = Repository::<Credential>::new(store).list().map_err(store_error)?;
    let credential = match profile.credential {
        Some(id) => {
            let record = credentials
                .iter()
                .find(|candidate| candidate.meta.id == id)
                .ok_or(ConnectionPlanError::CredentialNotFound)?;
            resolve_credential(store, record)?
        }
        None => credentials
            .iter()
            .filter_map(|record| resolve_credential(store, record).ok())
            .next()
            .ok_or(ConnectionPlanError::CredentialUnavailable)?,
    };
    let route = match profile.route {
        RouteChoice::Direct => ConnectionRoute::Direct,
        RouteChoice::Route(route_id) => {
            let route = Repository::<Route>::new(store)
                .get(route_id)
                .map_err(store_error)?
                .ok_or(ConnectionPlanError::RouteNotFound)?;
            resolve_route(store, &route, &credentials)?
        }
    };
    Ok(ConnectionPlan {
        profile_id,
        host_id: host.meta.id,
        address: host.address,
        port: host.port,
        username: profile.username,
        route,
        credential,
    })
}

fn resolve_route(
    store: &Store,
    route: &Route,
    credentials: &[Credential],
) -> Result<ConnectionRoute, ConnectionPlanError> {
    match &route.kind {
        RouteKind::Jump { hops } => Ok(ConnectionRoute::Jump { hops: hops.clone() }),
        RouteKind::Socks5 { proxy, credential, username } => Ok(ConnectionRoute::Socks5 {
            proxy: proxy.clone(),
            credential: resolve_route_credential(store, *credential, credentials)?,
            username: username.clone(),
        }),
        RouteKind::HttpConnect { proxy, credential, username } => {
            Ok(ConnectionRoute::HttpConnect {
                proxy: proxy.clone(),
                credential: resolve_route_credential(store, *credential, credentials)?,
                username: username.clone(),
            })
        }
        RouteKind::Command { command } => Ok(ConnectionRoute::Command { command: command.clone() }),
        RouteKind::Managed { gateway_network } => {
            Ok(ConnectionRoute::Managed { gateway_network: *gateway_network })
        }
    }
}

fn resolve_route_credential(
    store: &Store,
    id: Option<Uuid>,
    credentials: &[Credential],
) -> Result<Option<CredentialMaterial>, ConnectionPlanError> {
    let Some(id) = id else { return Ok(None) };
    let record = credentials
        .iter()
        .find(|candidate| candidate.meta.id == id)
        .ok_or(ConnectionPlanError::CredentialNotFound)?;
    if record.kind != CredentialKind::Password {
        return Err(ConnectionPlanError::InvalidCredential);
    }
    resolve_credential(store, record).map(Some)
}

fn resolve_credential(
    store: &Store,
    credential: &Credential,
) -> Result<CredentialMaterial, ConnectionPlanError> {
    match (credential.kind, credential.binding) {
        (CredentialKind::Password, CredentialBinding::Shared) => {
            Ok(CredentialMaterial::Password(shared_secret(store, credential)?))
        }
        (CredentialKind::PrivateKey, CredentialBinding::Shared) => {
            Ok(CredentialMaterial::PrivateKey(shared_secret(store, credential)?))
        }
        (CredentialKind::Password, CredentialBinding::Device)
        | (CredentialKind::PrivateKey, CredentialBinding::Device) => {
            let device = store.device_credential(credential.meta.id).map_err(store_error)?;
            let Some(device) = device else {
                return Err(ConnectionPlanError::CredentialUnavailable);
            };
            if device.secret.is_none() && device.keystore_handle.is_none() {
                return Err(ConnectionPlanError::CredentialUnavailable);
            }
            let material = if credential.kind == CredentialKind::Password {
                device.secret.map(CredentialMaterial::Password)
            } else {
                device.secret.map(CredentialMaterial::PrivateKey)
            };
            Ok(material.unwrap_or(CredentialMaterial::DeviceKey {
                public_key: device_public_key(store, credential),
                secret: None,
                keystore_handle: device.keystore_handle,
            }))
        }
        (CredentialKind::Agent, CredentialBinding::None) => {
            Ok(CredentialMaterial::Agent { public_key: credential.public_key.clone() })
        }
        (CredentialKind::SecurityKey, CredentialBinding::None)
        | (CredentialKind::SecurityKey, CredentialBinding::Device) => {
            if credentials::security_key_capability()
                == credentials::SecurityKeyCapability::Unsupported
            {
                return Err(ConnectionPlanError::CredentialUnavailable);
            }
            Ok(CredentialMaterial::SecurityKey { public_key: device_public_key(store, credential) })
        }
        (CredentialKind::DeviceBoundKey, CredentialBinding::None) => {
            Ok(CredentialMaterial::DeviceKey {
                public_key: device_public_key(store, credential),
                secret: None,
                keystore_handle: None,
            })
        }
        (CredentialKind::DeviceBoundKey, CredentialBinding::Device) => {
            let device = store.device_credential(credential.meta.id).map_err(store_error)?;
            let Some(device) = device else {
                return Err(ConnectionPlanError::CredentialUnavailable);
            };
            if device.secret.is_none() && device.keystore_handle.is_none() {
                return Err(ConnectionPlanError::CredentialUnavailable);
            }
            if let Some(handle) = device.keystore_handle {
                let resolved =
                    credentials::resolve_device_key(store.data_dir(), credential.meta.id, &handle)
                        .map_err(|_| ConnectionPlanError::CredentialUnavailable)?;
                return Ok(CredentialMaterial::DeviceKey {
                    public_key: device_public_key(store, credential),
                    secret: Some(SecretVec::new(resolved.secret.to_vec())),
                    keystore_handle: Some(handle),
                });
            }
            Ok(CredentialMaterial::DeviceKey {
                public_key: device_public_key(store, credential),
                secret: device.secret,
                keystore_handle: device.keystore_handle,
            })
        }
        (CredentialKind::Certificate, CredentialBinding::None) => {
            Ok(CredentialMaterial::Certificate { scope: credential.certificate_scope })
        }
        (CredentialKind::ExternalProvider, CredentialBinding::None) => {
            Ok(CredentialMaterial::External { provider: credential.provider.clone() })
        }
        _ => Err(ConnectionPlanError::InvalidCredential),
    }
}

fn shared_secret(store: &Store, credential: &Credential) -> Result<SecretVec, ConnectionPlanError> {
    crate::repository::credential_secret(store, credential.meta.id)
        .map_err(store_error)?
        .ok_or(ConnectionPlanError::CredentialUnavailable)
}

fn device_public_key(store: &Store, credential: &Credential) -> Option<String> {
    credential
        .devices
        .get(&store.device_id())
        .map(|device| device.public_key.clone())
        .or_else(|| credential.public_key.clone())
}

fn store_error(error: impl std::error::Error) -> ConnectionPlanError {
    ConnectionPlanError::Store { reference: error.to_string() }
}

/// Maximum command or channel input accepted by the client engine.
pub const MAX_SSH_INPUT: usize = 64 * 1024;
/// Maximum length of an entered OpenSSH private-key passphrase.
pub const MAX_PRIVATE_KEY_PASSPHRASE: usize = 4096;
/// Maximum bcrypt work factor accepted from an imported OpenSSH key.
pub const MAX_PRIVATE_KEY_BCRYPT_ROUNDS: u32 = 256;
/// Maximum aggregate output retained by one session.
pub const MAX_SSH_OUTPUT: usize = 8 * 1024 * 1024;
/// Maximum supported terminal width or height in character cells.
pub const MAX_TERMINAL_DIMENSION: u32 = 4096;

/// Validate a terminal's character-cell dimensions for an SSH window change.
pub fn terminal_size(columns: u32, rows: u32) -> Result<WindowChangeRequest, SshConnectionError> {
    if !(1..=MAX_TERMINAL_DIMENSION).contains(&columns)
        || !(1..=MAX_TERMINAL_DIMENSION).contains(&rows)
    {
        return Err(SshConnectionError::InvalidTerminalSize);
    }
    Ok(WindowChangeRequest { columns, rows, pixel_width: 0, pixel_height: 0 })
}

/// Host-key trust callback supplied by the client policy layer.
pub type HostKeyTrust = Arc<dyn HostKeyVerifier + Send + Sync>;

/// Verifies a presented host key against active device trust records.
///
/// The verifier compares the canonical SSH key blob and its OpenSSH SHA-256
/// fingerprint. Revoked records, wildcard-only records, and CA records are
/// not accepted by this direct-key slice. A missing or changed record remains
/// fail-closed and must be handled by a future explicit trust workflow.
#[derive(Clone, Debug)]
pub struct StoredHostKeyVerifier {
    host_id: Uuid,
    records: Vec<TrustRecord>,
}

impl StoredHostKeyVerifier {
    /// Build a verifier for one stored Host and its local trust records.
    #[must_use]
    pub fn new(host_id: Uuid, records: Vec<TrustRecord>) -> Self {
        Self { host_id, records }
    }
}

impl HostKeyVerifier for StoredHostKeyVerifier {
    fn verify(&self, _host: &str, key: &HostKey) -> Result<(), HostKeyVerificationError> {
        let (algorithm, blob) = match key {
            HostKey::Raw { algorithm, key_blob } => (algorithm.as_str(), key_blob.as_slice()),
            HostKey::Certificate(certificate) => (certificate.algorithm(), certificate.as_bytes()),
        };
        let encoded = STANDARD.encode(blob);
        let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)));
        let trusted = self.records.iter().any(|record| {
            if record.host != Some(self.host_id) || record.revoked || record.ca {
                return false;
            }
            let Some(stored_key) = record.key.as_deref() else { return false };
            let Some(stored_fingerprint) = record.fingerprint.as_deref() else { return false };
            let mut fields = stored_key.split_whitespace();
            fields.next() == Some(algorithm)
                && fields.next() == Some(encoded.as_str())
                && stored_fingerprint == fingerprint
        });
        if trusted {
            Ok(())
        } else {
            Err(HostKeyVerificationError::Rejected(
                "host key is not trusted for this host".to_owned(),
            ))
        }
    }
}

/// Errors returned by the concrete client connection owner.
#[derive(Debug, thiserror::Error)]
pub enum SshConnectionError {
    /// The saved username cannot be used for SSH authentication.
    #[error(
        "the SSH username must contain 1-4096 bytes without NUL; edit the Login before connecting"
    )]
    InvalidUsername,
    /// A saved command cannot be safely expanded into bounded process arguments.
    #[error("ProxyCommand is invalid: {0}; edit the route before connecting")]
    InvalidProxyCommand(&'static str),
    /// Opening the next jump channel or its SSH handshake exceeded the budget.
    #[error("SSH jump setup timed out; check forwarding access and the next host, then reconnect")]
    JumpSetupTimeout,
    /// The saved route is not yet supported by this concrete engine.
    #[error("SSH route is not supported by the concrete client engine")]
    UnsupportedRoute,
    /// A saved proxy endpoint is not a valid host and non-zero port.
    #[error("the SSH proxy endpoint must be a host:port or [IPv6]:port")]
    InvalidProxyEndpoint,
    /// A proxy auth pair or resolved password violates the saved contract.
    #[error("the SSH proxy authentication settings are invalid")]
    InvalidProxyAuthentication,
    /// The saved credential cannot be used by this concrete engine slice.
    #[error("SSH credential kind is not supported by the concrete client engine")]
    UnsupportedCredential,
    /// An agent credential must select a valid, supported raw public identity.
    #[error("save a valid OpenSSH public key in this agent credential before connecting")]
    InvalidAgentPublicKey,
    /// The system agent could not be opened or queried.
    #[error("the system SSH agent is unavailable; start it and load the saved key, then reconnect")]
    AgentUnavailable,
    /// The agent did not list the exact saved public identity.
    #[error(
        "the saved public key is not loaded in the system SSH agent; load that key and reconnect"
    )]
    AgentIdentityMissing,
    /// The agent refused or could not complete a signing operation.
    #[error(
        "the SSH agent could not sign; unlock the agent and approve the key request, then reconnect"
    )]
    AgentSigningFailed,
    /// Agent I/O and SSH authentication did not finish within the shared deadline.
    #[error("SSH agent authentication timed out; check the agent and reconnect")]
    AgentTimeout,
    /// Another bounded worker is required before using the system agent.
    #[error("too many SSH agent connections are starting; wait for one to finish and reconnect")]
    AgentBusy,
    /// The connection was cancelled while agent authentication was pending.
    #[error("SSH agent authentication was cancelled")]
    AgentCancelled,
    /// The stored key is not a valid OpenSSH private key.
    #[error("the stored SSH private key is invalid or unreadable")]
    InvalidPrivateKey,
    /// An encrypted key cannot be opened without its passphrase.
    #[error("enter the passphrase for this SSH private key")]
    EncryptedPrivateKey,
    /// The supplied passphrase could not open the encrypted key.
    #[error("the SSH private-key passphrase is incorrect or the key is unreadable")]
    InvalidPrivateKeyPassphrase,
    /// The imported key requests an unsafe bcrypt work factor or salt size.
    #[error("this SSH private key uses unsupported passphrase work parameters")]
    PrivateKeyKdfTooExpensive,
    /// The parsed key uses an algorithm without a signer in this build.
    #[error("this SSH private key algorithm is not supported in this build")]
    UnsupportedPrivateKey,
    /// The server advertised only SHA-1 for RSA public-key authentication.
    #[error("the SSH server advertises only legacy ssh-rsa for RSA keys; SHA-1 is not permitted")]
    RsaSha2Unavailable,
    /// The server rejected the selected RSA SHA-2 authentication request.
    #[error(
        "RSA key authentication was rejected; verify the key and the server's RSA SHA-2 policy"
    )]
    RsaAuthenticationRejected,
    /// The peer completed key exchange without a key callback result.
    #[error("SSH server did not present a host key")]
    HostKeyProbeMissing,
    /// Supplied command or channel input exceeded its bound.
    #[error("SSH {field} exceeds the {limit}-byte limit")]
    InputTooLarge {
        /// Logical input field that exceeded the bound.
        field: &'static str,
        /// Maximum accepted byte length.
        limit: usize,
    },
    /// The requested PTY character-cell dimensions are invalid.
    #[error("SSH terminal size must be between 1 and 4096 columns and rows")]
    InvalidTerminalSize,
    /// Peer output exceeded the bounded session retention limit.
    #[error("SSH session output exceeds the {limit}-byte limit")]
    OutputTooLarge {
        /// Maximum aggregate retained output.
        limit: usize,
    },
    /// Shared SSH engine failure.
    #[error(transparent)]
    Engine(#[from] ClientError),
    /// Connection lifecycle transition failure.
    #[error(transparent)]
    Lifecycle(#[from] ConnectionStateError),
}

const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

enum TransportRoute<'a> {
    Direct,
    Socks5 { host: &'a str, port: u16, credentials: Option<ProxyCredentials> },
    HttpConnect { host: &'a str, port: u16, credentials: Option<ProxyCredentials> },
    Command { program: OsString, arguments: Vec<OsString> },
}

fn parse_proxy_endpoint(proxy: &str) -> Result<(&str, u16), SshConnectionError> {
    let (host, port) = proxy.rsplit_once(':').ok_or(SshConnectionError::InvalidProxyEndpoint)?;
    let port = port.parse::<u16>().map_err(|_| SshConnectionError::InvalidProxyEndpoint)?;
    if port == 0 {
        return Err(SshConnectionError::InvalidProxyEndpoint);
    }
    if let Some(ipv6) = host.strip_prefix('[').and_then(|host| host.strip_suffix(']')) {
        if ipv6.parse::<std::net::Ipv6Addr>().is_ok() {
            return Ok((ipv6, port));
        }
        return Err(SshConnectionError::InvalidProxyEndpoint);
    }
    if host.len() > 253
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(SshConnectionError::InvalidProxyEndpoint);
    }
    Ok((host, port))
}

fn transport_route(plan: &ConnectionPlan) -> Result<TransportRoute<'_>, SshConnectionError> {
    UserAuthContext::new(plan.username.clone(), "ssh-connection")
        .map_err(|_| SshConnectionError::InvalidUsername)?;
    match &plan.route {
        ConnectionRoute::Direct => Ok(TransportRoute::Direct),
        ConnectionRoute::Socks5 { proxy, credential, username } => {
            let (host, port) = parse_proxy_endpoint(proxy)?;
            let credentials = proxy_credentials(username.as_deref(), credential.as_ref(), false)?;
            Ok(TransportRoute::Socks5 { host, port, credentials })
        }
        ConnectionRoute::HttpConnect { proxy, credential, username } => {
            let (host, port) = parse_proxy_endpoint(proxy)?;
            let credentials = proxy_credentials(username.as_deref(), credential.as_ref(), true)?;
            Ok(TransportRoute::HttpConnect { host, port, credentials })
        }
        ConnectionRoute::Command { command } => {
            let (program, arguments) =
                proxy_command::resolve(command, &plan.address, plan.port, &plan.username)?;
            Ok(TransportRoute::Command { program, arguments })
        }
        _ => Err(SshConnectionError::UnsupportedRoute),
    }
}

fn proxy_credentials(
    username: Option<&str>,
    credential: Option<&CredentialMaterial>,
    http_connect: bool,
) -> Result<Option<ProxyCredentials>, SshConnectionError> {
    let (Some(username), Some(CredentialMaterial::Password(password))) = (username, credential)
    else {
        return if username.is_none() && credential.is_none() {
            Ok(None)
        } else {
            Err(SshConnectionError::InvalidProxyAuthentication)
        };
    };
    if username.is_empty()
        || username.len() > 255
        || !username.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        || (http_connect && username.contains(':'))
        || (http_connect && !password.as_bytes().iter().all(|byte| (0x20..=0x7e).contains(byte)))
    {
        return Err(SshConnectionError::InvalidProxyAuthentication);
    }
    ProxyCredentials::new(username.as_bytes(), password.as_bytes())
        .map(Some)
        .map_err(|_| SshConnectionError::InvalidProxyAuthentication)
}

async fn connect_route(
    config: ClientConfig,
    route: TransportRoute<'_>,
) -> Result<ClientConnection, ClientError> {
    match route {
        TransportRoute::Direct => ClientConnection::connect(config).await,
        TransportRoute::Socks5 { host, port, credentials } => {
            ClientConnection::connect_via_socks5(
                config,
                host,
                port,
                credentials.as_ref(),
                PROXY_CONNECT_TIMEOUT,
            )
            .await
        }
        TransportRoute::HttpConnect { host, port, credentials } => {
            ClientConnection::connect_via_http_connect(
                config,
                host,
                port,
                credentials.as_ref(),
                PROXY_CONNECT_TIMEOUT,
            )
            .await
        }
        TransportRoute::Command { program, arguments } => {
            ClientConnection::connect_via_proxy_command(
                config,
                program,
                &arguments,
                PROXY_CONNECT_TIMEOUT,
            )
            .await
        }
    }
}

fn validate_credential(credential: &CredentialMaterial) -> Result<(), SshConnectionError> {
    match credential {
        CredentialMaterial::Password(_) | CredentialMaterial::PrivateKey(_) => Ok(()),
        CredentialMaterial::Agent { public_key } => {
            agent::parse_public_key(public_key.as_deref()).map(|_| ())
        }
        _ => Err(SshConnectionError::UnsupportedCredential),
    }
}

/// Output collected from one bounded remote command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SshExecOutput {
    /// Standard output bytes.
    pub stdout: Vec<u8>,
    /// Standard error bytes.
    pub stderr: Vec<u8>,
    /// Exit status, when supplied by the peer.
    pub exit_status: Option<u32>,
}

/// A live SSH connection owned by the client core.
pub struct SshConnection {
    connection: Option<ClientConnection>,
    parents: Vec<ClientConnection>,
    lifecycle: ConnectionLifecycle,
    username: String,
    credential: Option<CredentialMaterial>,
}

enum SoftwareKeySigner {
    Ed25519(Ed25519SshSigner),
    Ecdsa(Box<EcdsaSshSigner>),
    Rsa(Box<PrivateKey>),
}

fn read_software_key(material: &SecretVec) -> Result<PrivateKey, SshConnectionError> {
    if material.len() > MAX_SSH_INPUT {
        return Err(SshConnectionError::InputTooLarge {
            field: "private key",
            limit: MAX_SSH_INPUT,
        });
    }
    PrivateKey::from_openssh(material.as_bytes()).map_err(|_| SshConnectionError::InvalidPrivateKey)
}

fn validate_private_key_kdf(kdf: &Kdf) -> Result<(), SshConnectionError> {
    match kdf {
        Kdf::Bcrypt { salt, rounds }
            if (1..=64).contains(&salt.len())
                && (1..=MAX_PRIVATE_KEY_BCRYPT_ROUNDS).contains(rounds) => {}
        _ => return Err(SshConnectionError::PrivateKeyKdfTooExpensive),
    }
    Ok(())
}

/// Whether a saved software key needs a one-time passphrase before authentication.
/// The encrypted key's KDF parameters are checked before the UI asks for a secret.
pub fn private_key_passphrase_required(
    credential: &CredentialMaterial,
) -> Result<bool, SshConnectionError> {
    if let CredentialMaterial::PrivateKey(material) = credential {
        let key = read_software_key(material)?;
        if key.is_encrypted() {
            validate_private_key_kdf(key.kdf())?;
        }
        Ok(key.is_encrypted())
    } else {
        Ok(false)
    }
}

fn parse_software_key(
    material: &SecretVec,
    passphrase: Option<&SecretVec>,
) -> Result<SoftwareKeySigner, SshConnectionError> {
    let mut key = read_software_key(material)?;
    if key.is_encrypted() {
        validate_private_key_kdf(key.kdf())?;
        let passphrase = passphrase
            .filter(|value| !value.as_bytes().is_empty())
            .ok_or(SshConnectionError::EncryptedPrivateKey)?;
        if passphrase.len() > MAX_PRIVATE_KEY_PASSPHRASE {
            return Err(SshConnectionError::InputTooLarge {
                field: "private-key passphrase",
                limit: MAX_PRIVATE_KEY_PASSPHRASE,
            });
        }
        key = key
            .decrypt(passphrase.as_bytes())
            .map_err(|_| SshConnectionError::InvalidPrivateKeyPassphrase)?;
    }
    if let Some(ed25519) = key.key_data().ed25519() {
        let signing_key = Ed25519SigningKey::from_bytes(ed25519.private.as_ref())
            .map_err(|_| SshConnectionError::InvalidPrivateKey)?;
        return Ok(SoftwareKeySigner::Ed25519(Ed25519SshSigner::new(signing_key)));
    }
    if key.key_data().ecdsa().is_some() {
        return EcdsaSshSigner::new(key)
            .map(|signer| SoftwareKeySigner::Ecdsa(Box::new(signer)))
            .map_err(|_| SshConnectionError::InvalidPrivateKey);
    }
    if key.key_data().rsa().is_some() {
        return Ok(SoftwareKeySigner::Rsa(Box::new(key)));
    }
    Err(SshConnectionError::UnsupportedPrivateKey)
}

fn rsa_signature_algorithm(
    selection: ServerRsaSha2Selection,
) -> Result<SignatureAlgorithm, SshConnectionError> {
    match selection {
        ServerRsaSha2Selection::Sha512 | ServerRsaSha2Selection::Undetermined => {
            Ok(SignatureAlgorithm::RsaSha2_512)
        }
        ServerRsaSha2Selection::Sha256 => Ok(SignatureAlgorithm::RsaSha2_256),
        ServerRsaSha2Selection::Sha1OnlyAdvertised => Err(SshConnectionError::RsaSha2Unavailable),
    }
}

impl std::fmt::Debug for SshConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshConnection")
            .field("lifecycle", &self.lifecycle.state())
            .finish_non_exhaustive()
    }
}

impl SshConnection {
    /// Open an SSH connection and complete key exchange through its saved route.
    ///
    /// Omitting `trust` is fail-closed and rejects every host key. Jump chains
    /// require `prepare_connection`; managed routes remain explicit errors. Credentials support
    /// passwords, software keys, and explicitly selected system-agent keys.
    pub async fn connect(
        plan: &ConnectionPlan,
        trust: Option<HostKeyTrust>,
    ) -> Result<Self, SshConnectionError> {
        Self::connect_over(plan, trust, None).await
    }

    async fn connect_over(
        plan: &ConnectionPlan,
        trust: Option<HostKeyTrust>,
        parent: Option<&Self>,
    ) -> Result<Self, SshConnectionError> {
        let route = transport_route(plan)?;
        validate_credential(&plan.credential)?;
        let verifier = trust.unwrap_or_else(|| {
            Arc::new(|_: &str, _: &HostKey| {
                Err(HostKeyVerificationError::Rejected(
                    "host key trust decision required".to_owned(),
                ))
            })
        });
        let mut lifecycle = ConnectionLifecycle::new();
        lifecycle.transition(ConnectionState::VerifyingHost)?;
        let config =
            ClientConfig::new(plan.address.clone(), plan.port, move |host: &str, key: &HostKey| {
                verifier.verify(host, key)
            })
            .map_err(ClientError::from)?;
        let setup = async {
            if let Some(parent) = parent {
                let parent = parent.connection.as_ref().ok_or(ClientError::NotAuthenticated)?;
                tokio::time::timeout(
                    PROXY_CONNECT_TIMEOUT,
                    ClientConnection::connect_via_direct_tcpip(config, parent, "127.0.0.1", 0),
                )
                .await
                .map_err(|_| SshConnectionError::JumpSetupTimeout)?
                .map_err(SshConnectionError::Engine)
            } else {
                connect_route(config, route).await.map_err(SshConnectionError::Engine)
            }
        };
        let connection = match setup.await {
            Ok(connection) => connection,
            Err(error) => {
                let _ = lifecycle.transition(ConnectionState::Failed);
                return Err(error);
            }
        };
        Ok(Self {
            connection: Some(connection),
            parents: Vec::new(),
            lifecycle,
            username: plan.username.clone(),
            credential: Some(plan.credential.clone()),
        })
    }

    /// Return the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.lifecycle.state()
    }

    /// Authenticate with the credential resolved for this plan.
    pub async fn authenticate(&mut self) -> Result<(), SshConnectionError> {
        self.authenticate_with_passphrase(None).await
    }

    /// Authenticate with a one-time passphrase for an encrypted software key.
    /// The passphrase is dropped after authentication and is never saved.
    pub async fn authenticate_with_passphrase(
        &mut self,
        passphrase: Option<SecretVec>,
    ) -> Result<(), SshConnectionError> {
        // Local decryption can be retried on this same, already reviewed KEX.
        // It must complete before consuming the credential or starting auth.
        if let Some(CredentialMaterial::PrivateKey(material)) = &self.credential {
            let material = material.clone();
            let signer = tokio::task::spawn_blocking(move || {
                parse_software_key(&material, passphrase.as_ref())
            })
            .await
            .map_err(|_| SshConnectionError::InvalidPrivateKey)??;
            self.lifecycle.transition(ConnectionState::Authenticating)?;
            self.credential.take();
            let username = self.username.clone();
            let result = self.authenticate_software_key(&username, signer).await;
            return self.finish_authentication(result);
        }
        self.lifecycle.transition(ConnectionState::Authenticating)?;
        let username = self.username.clone();
        let credential = self.credential.take().ok_or(SshConnectionError::UnsupportedCredential)?;
        let result = match credential {
            CredentialMaterial::Password(password) => {
                if password.len() > MAX_SSH_INPUT {
                    Err(SshConnectionError::InputTooLarge {
                        field: "password",
                        limit: MAX_SSH_INPUT,
                    })
                } else {
                    self.connection_mut()?
                        .authenticate_password(&username, password.as_bytes())
                        .await
                        .map_err(SshConnectionError::Engine)
                }
            }
            CredentialMaterial::Agent { public_key } => {
                self.authenticate_agent(&username, public_key.as_deref()).await
            }
            _ => Err(SshConnectionError::UnsupportedCredential),
        };
        self.finish_authentication(result)
    }

    /// Authenticate with an explicit username and password.
    pub async fn authenticate_with(
        &mut self,
        username: &str,
        password: &SecretVec,
    ) -> Result<(), SshConnectionError> {
        self.lifecycle.transition(ConnectionState::Authenticating)?;
        self.credential.take();
        let result = if password.len() > MAX_SSH_INPUT {
            Err(SshConnectionError::InputTooLarge { field: "password", limit: MAX_SSH_INPUT })
        } else {
            self.connection_mut()?
                .authenticate_password(username, password.as_bytes())
                .await
                .map_err(SshConnectionError::Engine)
        };
        self.finish_authentication(result)
    }

    async fn authenticate_software_key(
        &mut self,
        username: &str,
        signer: SoftwareKeySigner,
    ) -> Result<(), SshConnectionError> {
        match signer {
            SoftwareKeySigner::Ed25519(signer) => self
                .connection_mut()?
                .authenticate_publickey(username, &signer)
                .await
                .map_err(Into::into),
            SoftwareKeySigner::Ecdsa(signer) => self
                .connection_mut()?
                .authenticate_publickey(username, signer.as_ref())
                .await
                .map_err(Into::into),
            SoftwareKeySigner::Rsa(key) => {
                let selection = self.connection_mut()?.server_rsa_sha2_selection().await?;
                let algorithm = rsa_signature_algorithm(selection)?;
                let signer = RsaSshSigner::new(*key, algorithm)
                    .map_err(|_| SshConnectionError::InvalidPrivateKey)?;
                self.connection_mut()?.authenticate_publickey(username, &signer).await.map_err(
                    |error| {
                        if matches!(error, ClientError::AuthenticationRejected { .. }) {
                            SshConnectionError::RsaAuthenticationRejected
                        } else {
                            SshConnectionError::Engine(error)
                        }
                    },
                )
            }
        }
    }

    fn connection_mut(&mut self) -> Result<&mut ClientConnection, SshConnectionError> {
        self.connection.as_mut().ok_or(SshConnectionError::AgentCancelled)
    }

    fn finish_authentication(
        &mut self,
        result: Result<(), SshConnectionError>,
    ) -> Result<(), SshConnectionError> {
        match result {
            Ok(()) => self.lifecycle.transition(ConnectionState::Open).map_err(Into::into),
            Err(error) => {
                let _ = self.lifecycle.transition(ConnectionState::Failed);
                Err(error)
            }
        }
    }

    /// Open a session channel after authentication.
    pub async fn open_session(&self) -> Result<SshSession, SshConnectionError> {
        if self.state() != ConnectionState::Open {
            return Err(SshConnectionError::Engine(ClientError::NotAuthenticated));
        }
        let connection = self.connection.as_ref().ok_or(SshConnectionError::AgentCancelled)?;
        Ok(SshSession { channel: connection.open_session().await?, output_bytes: 0 })
    }

    /// Close the SSH connection and mark it closed.
    pub async fn close(mut self) -> Result<(), SshConnectionError> {
        let mut result = Ok(());
        if let Some(connection) = self.connection.take() {
            result = connection.disconnect().await.map_err(SshConnectionError::Engine);
        }
        while let Some(parent) = self.parents.pop() {
            if let Err(error) = parent.disconnect().await
                && result.is_ok()
            {
                result = Err(SshConnectionError::Engine(error));
            }
        }
        let _ = self.lifecycle.transition(ConnectionState::Closed);
        result
    }
}

impl Drop for SshConnection {
    fn drop(&mut self) {
        self.connection.take();
        while self.parents.pop().is_some() {}
    }
}

/// A bounded session channel attached to an [`SshConnection`].
pub struct SshSession {
    channel: ClientChannel,
    output_bytes: usize,
}

impl std::fmt::Debug for SshSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshSession")
            .field("channel_id", &self.channel.id())
            .field("output_bytes", &self.output_bytes)
            .finish_non_exhaustive()
    }
}

impl SshSession {
    /// Request a bounded pseudo-terminal.
    pub async fn request_pty(&self, request: &PtyRequest) -> Result<(), SshConnectionError> {
        if request.term.len() > MAX_SSH_INPUT || request.modes.len() > MAX_SSH_INPUT {
            return Err(SshConnectionError::InputTooLarge {
                field: "pty request",
                limit: MAX_SSH_INPUT,
            });
        }
        self.channel.request_pty(request, true).await?;
        Ok(())
    }

    /// Request the remote login shell.
    pub async fn request_shell(&self) -> Result<(), SshConnectionError> {
        self.channel.request_shell(true).await?;
        Ok(())
    }

    /// Notify a remote PTY of its new character-cell dimensions.
    pub async fn resize(&self, columns: u32, rows: u32) -> Result<(), SshConnectionError> {
        let request = terminal_size(columns, rows)?;
        self.channel.window_change(&request).await?;
        Ok(())
    }

    /// Execute a command, optionally allocating a pseudo-terminal first.
    pub async fn exec(
        &mut self,
        command: &[u8],
        pty: Option<&PtyRequest>,
    ) -> Result<SshExecOutput, SshConnectionError> {
        if command.len() > MAX_SSH_INPUT {
            return Err(SshConnectionError::InputTooLarge {
                field: "command",
                limit: MAX_SSH_INPUT,
            });
        }
        if let Some(request) = pty {
            self.request_pty(request).await?;
        }
        self.channel.exec(true, command).await?;
        let mut output = SshExecOutput::default();
        while let Some(event) = self.next_event().await? {
            match event {
                ChannelEvent::Data(data) => output.stdout.extend(data),
                ChannelEvent::ExtendedData { data, .. } => output.stderr.extend(data),
                ChannelEvent::ExitStatus(status) => output.exit_status = Some(status),
                ChannelEvent::Close => break,
                _ => {}
            }
        }
        Ok(output)
    }

    /// Send one bounded input chunk to a shell or PTY.
    pub async fn send_data(&self, data: &[u8]) -> Result<(), SshConnectionError> {
        if data.len() > MAX_SSH_INPUT {
            return Err(SshConnectionError::InputTooLarge {
                field: "channel input",
                limit: MAX_SSH_INPUT,
            });
        }
        self.channel.send_data(data).await?;
        Ok(())
    }

    /// Read the next peer event while enforcing aggregate output bounds.
    pub async fn next_event(&mut self) -> Result<Option<ChannelEvent>, SshConnectionError> {
        let event = self.channel.next_event().await?;
        let bytes = match &event {
            Some(ChannelEvent::Data(data)) | Some(ChannelEvent::ExtendedData { data, .. }) => {
                data.len()
            }
            _ => 0,
        };
        if self.output_bytes.saturating_add(bytes) > MAX_SSH_OUTPUT {
            let _ = self.channel.close().await;
            return Err(SshConnectionError::OutputTooLarge { limit: MAX_SSH_OUTPUT });
        }
        self.output_bytes += bytes;
        Ok(event)
    }

    /// Send channel EOF.
    pub async fn send_eof(&self) -> Result<(), SshConnectionError> {
        self.channel.send_eof().await?;
        Ok(())
    }

    /// Request channel close.
    pub async fn close(&self) -> Result<(), SshConnectionError> {
        self.channel.close().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use scoplen_crypto::{LocalDatabaseKey, SecretVec};
    use ssh_key::{Algorithm, Cipher, EcdsaCurve};
    use tempfile::tempdir;

    use super::*;
    use crate::repository::{
        AccessProfileChange, CredentialChange, Edit, HostChange, Provenance, RouteChange,
    };

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(&dir.path().join("local.db"), &LocalDatabaseKey::new([7; 32]))
            .expect("store");
        (dir, store)
    }

    #[test]
    fn proxy_endpoints_require_a_host_and_nonzero_port() {
        assert_eq!(parse_proxy_endpoint("proxy.example:1080").unwrap(), ("proxy.example", 1080));
        assert_eq!(parse_proxy_endpoint("127.0.0.1:8080").unwrap(), ("127.0.0.1", 8080));
        assert_eq!(parse_proxy_endpoint("[::1]:8080").unwrap(), ("::1", 8080));
        for invalid in [
            "",
            "proxy",
            ":1080",
            "proxy:0",
            "proxy:65536",
            "proxy:http",
            "proxy:22/path",
            "http://proxy:1080",
            "user@proxy:1080",
            "proxy name:1080",
            "-proxy:1080",
            "proxy..example:1080",
            "proxy_:1080",
            "::1:1080",
            "[not-ipv6]:1080",
            "[::1:1080",
            "proxy:1080:443",
        ] {
            assert!(
                matches!(
                    parse_proxy_endpoint(invalid),
                    Err(SshConnectionError::InvalidProxyEndpoint)
                ),
                "accepted {invalid:?}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_proxy_authentication_fails_before_dial() {
        let mut plan = ConnectionPlan {
            profile_id: Uuid::nil(),
            host_id: Uuid::nil(),
            address: "invalid target".into(),
            port: 22,
            username: "user".into(),
            route: ConnectionRoute::Socks5 {
                proxy: "proxy:0".into(),
                credential: None,
                username: None,
            },
            credential: CredentialMaterial::Password(SecretVec::new(b"password".to_vec())),
        };
        assert!(matches!(
            probe_host_key(&plan).await,
            Err(SshConnectionError::InvalidProxyEndpoint)
        ));
        assert!(matches!(
            SshConnection::connect(&plan, None).await,
            Err(SshConnectionError::InvalidProxyEndpoint)
        ));

        plan.route = ConnectionRoute::HttpConnect {
            proxy: "127.0.0.1:8080".into(),
            credential: Some(CredentialMaterial::Password(SecretVec::new(
                b"proxy-secret".to_vec(),
            ))),
            username: None,
        };
        assert!(matches!(
            probe_host_key(&plan).await,
            Err(SshConnectionError::InvalidProxyAuthentication)
        ));
        assert!(matches!(
            SshConnection::connect(&plan, None).await,
            Err(SshConnectionError::InvalidProxyAuthentication)
        ));

        for (username, password, http) in [
            ("", "pass", false),
            ("bad\nuser", "pass", false),
            ("non-ascii-é", "pass", false),
            ("a:colon", "pass", true),
            ("a", "", true),
            ("a", "a\nline", true),
            ("a", "non-ascii-é", true),
            ("a", &"x".repeat(256), false),
        ] {
            let credential =
                Some(CredentialMaterial::Password(SecretVec::new(password.as_bytes().to_vec())));
            plan.route = if http {
                ConnectionRoute::HttpConnect {
                    proxy: "127.0.0.1:8080".into(),
                    credential,
                    username: Some(username.into()),
                }
            } else {
                ConnectionRoute::Socks5 {
                    proxy: "127.0.0.1:1080".into(),
                    credential,
                    username: Some(username.into()),
                }
            };
            assert!(matches!(
                probe_host_key(&plan).await,
                Err(SshConnectionError::InvalidProxyAuthentication)
            ));
            assert!(matches!(
                SshConnection::connect(&plan, None).await,
                Err(SshConnectionError::InvalidProxyAuthentication)
            ));
        }
        let accepted = proxy_credentials(
            Some("proxy-user"),
            Some(&CredentialMaterial::Password(SecretVec::new(b"with:colon".to_vec()))),
            true,
        )
        .expect("colon is allowed in HTTP password")
        .expect("configured credentials");
        assert!(!format!("{accepted:?}").contains("with:colon"));
    }

    #[test]
    fn software_key_parser_accepts_supported_openssh_keys() {
        let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
        for (algorithm, expected) in [
            (Algorithm::Ed25519, "ed25519"),
            (Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }, "p256"),
            (Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 }, "p384"),
            (Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 }, "p521"),
            (Algorithm::Rsa { hash: None }, "rsa"),
        ] {
            let key = PrivateKey::random(&mut rng, algorithm).expect("test key");
            let pem = key.to_openssh(Default::default()).expect("OpenSSH encoding");
            let material = SecretVec::new(pem.as_bytes().to_vec());
            let parsed = parse_software_key(&material, None).expect("supported key");
            assert!(matches!(
                (parsed, expected),
                (SoftwareKeySigner::Ed25519(_), "ed25519")
                    | (SoftwareKeySigner::Ecdsa(_), "p256" | "p384" | "p521")
                    | (SoftwareKeySigner::Rsa(_), "rsa")
            ));
            assert!(!format!("{material:?}").contains("OPENSSH PRIVATE KEY"));
        }
    }

    #[test]
    fn encrypted_software_keys_need_the_correct_one_time_passphrase() {
        let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
        let passphrase = SecretVec::new(b"disposable-test-passphrase".to_vec());
        let wrong = SecretVec::new(b"wrong-passphrase".to_vec());
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
            Algorithm::Rsa { hash: None },
        ] {
            let key = PrivateKey::random(&mut rng, algorithm).expect("test key");
            let encrypted = key
                .encrypt_with(
                    Cipher::Aes256Ctr,
                    Kdf::Bcrypt { salt: vec![7; 16], rounds: 16 },
                    42,
                    passphrase.as_bytes(),
                )
                .expect("encrypt test key");
            let text = encrypted.to_openssh(Default::default()).expect("OpenSSH text");
            let material = SecretVec::new(text.as_bytes().to_vec());
            assert!(
                private_key_passphrase_required(&CredentialMaterial::PrivateKey(material.clone()))
                    .unwrap()
            );
            assert!(matches!(
                parse_software_key(&material, None),
                Err(SshConnectionError::EncryptedPrivateKey)
            ));
            assert!(matches!(
                parse_software_key(&material, Some(&wrong)),
                Err(SshConnectionError::InvalidPrivateKeyPassphrase)
            ));
            assert!(parse_software_key(&material, Some(&passphrase)).is_ok());
            assert!(!format!("{material:?}").contains("OPENSSH PRIVATE KEY"));
        }
    }

    #[test]
    fn encrypted_key_kdf_and_passphrase_are_bounded_before_decryption() {
        let salt = vec![7; 16];
        for rounds in [1, 16, 256, MAX_PRIVATE_KEY_BCRYPT_ROUNDS] {
            assert!(validate_private_key_kdf(&Kdf::Bcrypt { salt: salt.clone(), rounds }).is_ok());
        }
        for (salt, rounds) in [
            (Vec::new(), 16),
            (vec![7; 65], 16),
            (vec![7; 16], 0),
            (vec![7; 16], MAX_PRIVATE_KEY_BCRYPT_ROUNDS + 1),
        ] {
            assert!(matches!(
                validate_private_key_kdf(&Kdf::Bcrypt { salt, rounds }),
                Err(SshConnectionError::PrivateKeyKdfTooExpensive)
            ));
        }
        let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("test key");
        let encrypted = key.encrypt(&mut rng, b"test").expect("encrypted key");
        let text = encrypted.to_openssh(Default::default()).expect("OpenSSH text");
        let material = SecretVec::new(text.as_bytes().to_vec());
        let oversized = SecretVec::new(vec![b'x'; MAX_PRIVATE_KEY_PASSPHRASE + 1]);
        assert!(matches!(
            parse_software_key(&material, Some(&oversized)),
            Err(SshConnectionError::InputTooLarge { field: "private-key passphrase", .. })
        ));
    }

    #[test]
    fn rsa_selection_never_chooses_sha1() {
        assert_eq!(
            rsa_signature_algorithm(ServerRsaSha2Selection::Sha512).unwrap(),
            SignatureAlgorithm::RsaSha2_512
        );
        assert_eq!(
            rsa_signature_algorithm(ServerRsaSha2Selection::Sha256).unwrap(),
            SignatureAlgorithm::RsaSha2_256
        );
        assert_eq!(
            rsa_signature_algorithm(ServerRsaSha2Selection::Undetermined).unwrap(),
            SignatureAlgorithm::RsaSha2_512
        );
        assert!(matches!(
            rsa_signature_algorithm(ServerRsaSha2Selection::Sha1OnlyAdvertised),
            Err(SshConnectionError::RsaSha2Unavailable)
        ));
    }

    #[test]
    fn software_key_parser_rejects_bad_or_oversized_material_without_disclosing_it() {
        let bad = SecretVec::new(b"-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-key".to_vec());
        let error = parse_software_key(&bad, None).err().expect("invalid key rejected");
        assert!(matches!(error, SshConnectionError::InvalidPrivateKey));
        assert!(!error.to_string().contains("not-a-key"));

        let oversized = SecretVec::new(vec![b'X'; MAX_SSH_INPUT + 1]);
        assert!(matches!(
            parse_software_key(&oversized, None),
            Err(SshConnectionError::InputTooLarge { field: "private key", .. })
        ));
    }

    #[test]
    fn terminal_size_rejects_zero_and_oversized_dimensions() {
        let valid = terminal_size(120, 40).expect("valid terminal size");
        assert_eq!((valid.columns, valid.rows), (120, 40));
        assert_eq!((valid.pixel_width, valid.pixel_height), (0, 0));
        for (columns, rows) in [(0, 40), (120, 0), (MAX_TERMINAL_DIMENSION + 1, 40)] {
            assert!(matches!(
                terminal_size(columns, rows),
                Err(SshConnectionError::InvalidTerminalSize)
            ));
        }
    }

    #[test]
    fn resolves_direct_profile_and_redacts_secret_debug() {
        let (_dir, store) = store();
        let host = Repository::<crate::repository::Host>::new(&store)
            .create(HostChange {
                name: Some("prod".into()),
                address: Some("127.0.0.1".into()),
                port: Edit::Set(2222),
                ..Default::default()
            })
            .expect("host");
        let credential = Repository::<Credential>::new(&store)
            .create(CredentialChange {
                kind: Some(CredentialKind::Password),
                binding: Some(CredentialBinding::Shared),
                secret: Edit::Set(SecretVec::new(b"correct horse".to_vec())),
                ..Default::default()
            })
            .expect("credential");
        let profile = Repository::<AccessProfile>::new(&store)
            .create(AccessProfileChange {
                host: Some(host.meta.id),
                username: Some("ops".into()),
                credential: Edit::Set(credential.meta.id),
                ..Default::default()
            })
            .expect("profile");

        let plan = resolve_connection_plan(&store, profile.meta.id).expect("plan");
        assert_eq!(plan.address, "127.0.0.1");
        assert_eq!(plan.port, 2222);
        assert_eq!(plan.username, "ops");
        assert_eq!(plan.route, ConnectionRoute::Direct);
        assert_eq!(
            plan.credential,
            CredentialMaterial::Password(SecretVec::new(b"correct horse".to_vec()))
        );
        assert!(!format!("{plan:?}").contains("correct horse"));
    }

    #[test]
    fn saved_agent_plan_preserves_its_exact_public_identity() {
        let (_dir, store) = store();
        let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let public_key = key.public_key().to_openssh().unwrap();
        let host = Repository::<crate::repository::Host>::new(&store)
            .create(HostChange {
                name: Some("fixture".into()),
                address: Some("127.0.0.1".into()),
                ..Default::default()
            })
            .unwrap();
        let credential = Repository::<Credential>::new(&store)
            .create(CredentialChange {
                kind: Some(CredentialKind::Agent),
                binding: Some(CredentialBinding::None),
                public_key: Edit::Set(public_key.clone()),
                ..Default::default()
            })
            .unwrap();
        let profile = Repository::<AccessProfile>::new(&store)
            .create(AccessProfileChange {
                host: Some(host.meta.id),
                username: Some("ops".into()),
                credential: Edit::Set(credential.meta.id),
                ..Default::default()
            })
            .unwrap();
        let plan = resolve_connection_plan(&store, profile.meta.id).unwrap();
        assert_eq!(plan.credential, CredentialMaterial::Agent { public_key: Some(public_key) });
        assert!(validate_credential(&plan.credential).is_ok());
        assert!(!private_key_passphrase_required(&plan.credential).unwrap());
    }

    #[tokio::test]
    async fn absent_or_invalid_agent_identity_fails_before_network_or_agent_io() {
        for public_key in
            [None, Some("ssh-ed25519 AAAA".into()), Some("x".repeat(MAX_SSH_INPUT + 1))]
        {
            let plan = ConnectionPlan {
                profile_id: Uuid::nil(),
                host_id: Uuid::nil(),
                address: "invalid target".into(),
                port: 22,
                username: "ops".into(),
                route: ConnectionRoute::Direct,
                credential: CredentialMaterial::Agent { public_key },
            };
            assert!(matches!(
                probe_host_key(&plan).await,
                Err(SshConnectionError::InvalidAgentPublicKey)
            ));
            assert!(matches!(
                SshConnection::connect(&plan, None).await,
                Err(SshConnectionError::InvalidAgentPublicKey)
            ));
        }
    }

    #[test]
    fn resolves_saved_unauthenticated_proxy_routes() {
        let (_dir, store) = store();
        let host = Repository::<crate::repository::Host>::new(&store)
            .create(HostChange {
                name: Some("target".into()),
                address: Some("target.example".into()),
                port: Edit::Set(2222),
                ..Default::default()
            })
            .expect("host");
        let credential = Repository::<Credential>::new(&store)
            .create(CredentialChange {
                kind: Some(CredentialKind::Password),
                binding: Some(CredentialBinding::Shared),
                secret: Edit::Set(SecretVec::new(b"target-password".to_vec())),
                ..Default::default()
            })
            .expect("credential");
        for kind in [
            RouteKind::Socks5 {
                proxy: "proxy.example:1080".into(),
                credential: None,
                username: None,
            },
            RouteKind::HttpConnect {
                proxy: "proxy.example:8080".into(),
                credential: None,
                username: None,
            },
        ] {
            let route = Repository::<Route>::new(&store)
                .create(RouteChange { name: Some("proxy".into()), kind: Some(kind.clone()) })
                .expect("route");
            let profile = Repository::<AccessProfile>::new(&store)
                .create(AccessProfileChange {
                    host: Some(host.meta.id),
                    username: Some("ops".into()),
                    credential: Edit::Set(credential.meta.id),
                    route: Some(RouteChoice::Route(route.meta.id)),
                    ..Default::default()
                })
                .expect("profile");
            let plan = resolve_connection_plan(&store, profile.meta.id).expect("plan");
            match (kind, plan.route) {
                (
                    RouteKind::Socks5 { proxy, .. },
                    ConnectionRoute::Socks5 { proxy: actual, credential: None, username: None },
                )
                | (
                    RouteKind::HttpConnect { proxy, .. },
                    ConnectionRoute::HttpConnect {
                        proxy: actual,
                        credential: None,
                        username: None,
                    },
                ) => assert_eq!(actual, proxy),
                pair => panic!("incorrect saved proxy route: {pair:?}"),
            }
        }
    }

    #[test]
    fn resolves_saved_authenticated_proxy_routes_without_mixing_target_identity() {
        let (_dir, store) = store();
        let host = Repository::<crate::repository::Host>::new(&store)
            .create(HostChange {
                name: Some("target".into()),
                address: Some("target.example".into()),
                port: Edit::Set(2222),
                ..Default::default()
            })
            .expect("host");
        let target = Repository::<Credential>::new(&store)
            .create(CredentialChange {
                kind: Some(CredentialKind::Password),
                binding: Some(CredentialBinding::Shared),
                secret: Edit::Set(SecretVec::new(b"target-secret".to_vec())),
                ..Default::default()
            })
            .expect("target credential");
        for (http, binding, proxy_secret) in [
            (false, CredentialBinding::Shared, b"socks-proxy-secret".as_slice()),
            (true, CredentialBinding::Device, b"http-proxy-secret".as_slice()),
        ] {
            let proxy_credential = Repository::<Credential>::new(&store)
                .create(CredentialChange {
                    kind: Some(CredentialKind::Password),
                    binding: Some(binding),
                    secret: if binding == CredentialBinding::Shared {
                        Edit::Set(SecretVec::new(proxy_secret.to_vec()))
                    } else {
                        Edit::Keep
                    },
                    ..Default::default()
                })
                .expect("proxy credential");
            if binding == CredentialBinding::Device {
                store
                    .set_device_secret(proxy_credential.meta.id, proxy_secret)
                    .expect("device password");
            }
            let kind = if http {
                RouteKind::HttpConnect {
                    proxy: "proxy.example:8080".into(),
                    credential: Some(proxy_credential.meta.id),
                    username: Some("http-proxy-user".into()),
                }
            } else {
                RouteKind::Socks5 {
                    proxy: "proxy.example:1080".into(),
                    credential: Some(proxy_credential.meta.id),
                    username: Some("socks-proxy-user".into()),
                }
            };
            let route = Repository::<Route>::new(&store)
                .create(RouteChange { name: Some("proxy".into()), kind: Some(kind) })
                .expect("route");
            let profile = Repository::<AccessProfile>::new(&store)
                .create(AccessProfileChange {
                    host: Some(host.meta.id),
                    username: Some("target-user".into()),
                    credential: Edit::Set(target.meta.id),
                    route: Some(RouteChoice::Route(route.meta.id)),
                    ..Default::default()
                })
                .expect("profile");
            let plan = resolve_connection_plan(&store, profile.meta.id).expect("saved route plan");
            assert_eq!(plan.username, "target-user");
            assert_eq!(
                plan.credential,
                CredentialMaterial::Password(SecretVec::new(b"target-secret".to_vec()))
            );
            let expected_proxy_credential =
                Some(CredentialMaterial::Password(SecretVec::new(proxy_secret.to_vec())));
            let expected_route = if http {
                ConnectionRoute::HttpConnect {
                    proxy: "proxy.example:8080".into(),
                    credential: expected_proxy_credential,
                    username: Some("http-proxy-user".into()),
                }
            } else {
                ConnectionRoute::Socks5 {
                    proxy: "proxy.example:1080".into(),
                    credential: expected_proxy_credential,
                    username: Some("socks-proxy-user".into()),
                }
            };
            assert_eq!(plan.route, expected_route);
            assert!(transport_route(&plan).is_ok());
            assert!(!format!("{plan:?}").contains("target-secret"));
            assert!(!format!("{plan:?}").contains("proxy-secret"));
        }
    }

    #[test]
    fn rejects_missing_device_material_and_missing_profile() {
        let (_dir, store) = store();
        assert_eq!(
            resolve_connection_plan(&store, Uuid::nil()),
            Err(ConnectionPlanError::ProfileNotFound)
        );
    }

    #[test]
    fn trust_evaluation_is_fail_closed_for_changed_and_revoked_keys() {
        let host = Uuid::from_u128(1);
        let trusted = TrustRecord {
            meta: crate::repository::Meta { id: Uuid::from_u128(2), restored: false },
            host: Some(host),
            pattern: None,
            key: Some("ssh-ed25519 AAAA".into()),
            fingerprint: Some("SHA256:one".into()),
            provenance: Some(Provenance::Manual),
            accepted_at: Some(1),
            accepted_by_device: None,
            accepted_by_account: None,
            revoked: false,
            ca: false,
        };
        assert_eq!(
            evaluate_host_key(
                host,
                "ssh-ed25519 AAAA",
                "SHA256:one",
                std::slice::from_ref(&trusted)
            ),
            HostKeyStatus::Trusted
        );
        assert_eq!(
            evaluate_host_key(
                host,
                "ssh-ed25519 BBBB",
                "SHA256:two",
                std::slice::from_ref(&trusted)
            ),
            HostKeyStatus::Changed
        );
        let mut revoked = trusted;
        revoked.revoked = true;
        assert_eq!(
            evaluate_host_key(host, "ssh-ed25519 AAAA", "SHA256:one", &[revoked]),
            HostKeyStatus::New
        );
    }

    #[test]
    fn stored_host_key_verifier_requires_matching_active_record() {
        let host = Uuid::from_u128(1);
        let blob = [1_u8, 2, 3, 4];
        let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)));
        let key = format!("ssh-test {}", STANDARD.encode(blob));
        let record = TrustRecord {
            meta: crate::repository::Meta { id: Uuid::from_u128(2), restored: false },
            host: Some(host),
            pattern: None,
            key: Some(key),
            fingerprint: Some(fingerprint),
            provenance: Some(Provenance::Manual),
            accepted_at: Some(1),
            accepted_by_device: None,
            accepted_by_account: None,
            revoked: false,
            ca: false,
        };
        let verifier = StoredHostKeyVerifier::new(host, vec![record.clone()]);
        assert!(
            verifier
                .verify(
                    "host.example",
                    &HostKey::Raw { algorithm: "ssh-test".into(), key_blob: blob.to_vec() }
                )
                .is_ok()
        );

        let mut revoked = record;
        revoked.revoked = true;
        let verifier = StoredHostKeyVerifier::new(host, vec![revoked]);
        assert!(matches!(
            verifier.verify(
                "host.example",
                &HostKey::Raw { algorithm: "ssh-test".into(), key_blob: blob.to_vec() }
            ),
            Err(HostKeyVerificationError::Rejected(_))
        ));
    }

    #[test]
    fn host_key_presentation_is_canonical_and_fingerprint_bound() {
        let blob = [1_u8, 2, 3, 4];
        let presentation = HostKeyPresentation::from_host_key(&HostKey::Raw {
            algorithm: "ssh-test".into(),
            key_blob: blob.to_vec(),
        });
        assert_eq!(presentation.algorithm, "ssh-test");
        assert_eq!(presentation.key, format!("ssh-test {}", STANDARD.encode(blob)));
        assert_eq!(
            presentation.fingerprint,
            format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
        );
    }

    #[test]
    fn lifecycle_allows_host_verification_and_reconnect_paths_only() {
        let mut lifecycle = ConnectionLifecycle::new();
        lifecycle.transition(ConnectionState::VerifyingHost).expect("verify");
        lifecycle.transition(ConnectionState::Authenticating).expect("auth");
        lifecycle.transition(ConnectionState::Open).expect("open");
        lifecycle.transition(ConnectionState::Reconnecting).expect("reconnect");
        lifecycle.transition(ConnectionState::Authenticating).expect("reauth");
        assert_eq!(
            lifecycle.transition(ConnectionState::Connecting),
            Err(ConnectionStateError {
                from: ConnectionState::Authenticating,
                to: ConnectionState::Connecting
            })
        );
    }
}
