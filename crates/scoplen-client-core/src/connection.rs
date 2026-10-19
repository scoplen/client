// SPDX-License-Identifier: Apache-2.0

//! Connection planning for the client-side SSH orchestrator.
//!
//! This module resolves a stored AccessProfile into the non-UI inputs a concrete
//! `scoplen-ssh` engine needs. The shared protocol crate owns the transport and
//! handshake, while this crate owns local object resolution, device-local
//! credential material, trust decisions, and the live direct-session owner.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use scoplen_client_platform::credentials;
use scoplen_crypto::{Ed25519SigningKey, P256SigningKey, SecretVec};
use scoplen_ssh::{
    ChannelEvent, ClientChannel, ClientConfig, ClientConnection, ClientError, Ed25519SshSigner,
    HostKey, HostKeyVerificationError, HostKeyVerifier, P256SshSigner, PtyRequest, RsaSshSigner,
    SignatureAlgorithm, WindowChangeRequest,
};
use sha2::{Digest as _, Sha256};
use ssh_key::{PrivateKey, private::EcdsaKeypair};
use uuid::Uuid;

use crate::repository::{
    AccessProfile, Credential, CredentialBinding, CredentialKind, Repository, Route, RouteChoice,
    RouteKind, TrustRecord,
};
use crate::store::Store;

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
    Agent,
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    },
    /// Connect through an HTTP CONNECT proxy.
    HttpConnect {
        /// Proxy endpoint in `host:port` form.
        proxy: String,
        /// Optional proxy authentication material.
        credential: Option<CredentialMaterial>,
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
    let active = records.iter().filter(|record| record.host == Some(host_id) && !record.revoked);
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
    if !matches!(&plan.route, ConnectionRoute::Direct) {
        return Err(SshConnectionError::UnsupportedRoute);
    }
    if !matches!(
        &plan.credential,
        CredentialMaterial::Password(_) | CredentialMaterial::PrivateKey(_)
    ) {
        return Err(SshConnectionError::UnsupportedCredential);
    }

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
    let connection = ClientConnection::connect(config).await?;
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
        RouteKind::Socks5 { proxy, credential } => Ok(ConnectionRoute::Socks5 {
            proxy: proxy.clone(),
            credential: resolve_route_credential(store, *credential, credentials)?,
        }),
        RouteKind::HttpConnect { proxy, credential } => Ok(ConnectionRoute::HttpConnect {
            proxy: proxy.clone(),
            credential: resolve_route_credential(store, *credential, credentials)?,
        }),
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
        (CredentialKind::Agent, CredentialBinding::None) => Ok(CredentialMaterial::Agent),
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
    /// The saved route is not yet supported by this concrete engine.
    #[error("SSH route is not supported by the concrete client engine")]
    UnsupportedRoute,
    /// The saved credential cannot be used by this concrete engine slice.
    #[error("SSH credential kind is not supported by the concrete client engine")]
    UnsupportedCredential,
    /// The stored key is not a valid OpenSSH private key.
    #[error("the stored SSH private key is invalid or unreadable")]
    InvalidPrivateKey,
    /// An encrypted key needs a passphrase flow before it can be used.
    #[error("this SSH private key is encrypted; passphrase entry is not available yet")]
    EncryptedPrivateKey,
    /// The parsed key uses an algorithm without a signer in this build.
    #[error("this SSH private key algorithm is not supported in this build")]
    UnsupportedPrivateKey,
    /// The server rejected RSA-SHA2-512; this build cannot discover or offer SHA-256.
    #[error(
        "RSA key authentication was rejected; verify the key and whether the server accepts rsa-sha2-512 (rsa-sha2-256 selection is not available in this build)"
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
    connection: ClientConnection,
    lifecycle: ConnectionLifecycle,
    username: String,
    credential: Option<CredentialMaterial>,
}

enum SoftwareKeySigner {
    Ed25519(Ed25519SshSigner),
    P256(P256SshSigner),
    Rsa(Box<RsaSshSigner>),
}

fn parse_software_key(material: &SecretVec) -> Result<SoftwareKeySigner, SshConnectionError> {
    if material.len() > MAX_SSH_INPUT {
        return Err(SshConnectionError::InputTooLarge {
            field: "private key",
            limit: MAX_SSH_INPUT,
        });
    }
    let key = PrivateKey::from_openssh(material.as_bytes())
        .map_err(|_| SshConnectionError::InvalidPrivateKey)?;
    if key.is_encrypted() {
        return Err(SshConnectionError::EncryptedPrivateKey);
    }
    if let Some(ed25519) = key.key_data().ed25519() {
        let signing_key = Ed25519SigningKey::from_bytes(ed25519.private.as_ref())
            .map_err(|_| SshConnectionError::InvalidPrivateKey)?;
        return Ok(SoftwareKeySigner::Ed25519(Ed25519SshSigner::new(signing_key)));
    }
    if let Some(EcdsaKeypair::NistP256 { private, .. }) = key.key_data().ecdsa() {
        let signing_key = P256SigningKey::from_bytes(private.as_ref())
            .map_err(|_| SshConnectionError::InvalidPrivateKey)?;
        return Ok(SoftwareKeySigner::P256(P256SshSigner::new(signing_key)));
    }
    if key.key_data().rsa().is_some() {
        return RsaSshSigner::new(key, SignatureAlgorithm::RsaSha2_512)
            .map(|signer| SoftwareKeySigner::Rsa(Box::new(signer)))
            .map_err(|_| SshConnectionError::InvalidPrivateKey);
    }
    Err(SshConnectionError::UnsupportedPrivateKey)
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
    /// Open a direct SSH connection and complete key exchange.
    ///
    /// Omitting `trust` is fail-closed and rejects every host key. Route
    /// composition and credentials other than passwords and software keys
    /// remain explicit errors until their adapters are connected.
    pub async fn connect(
        plan: &ConnectionPlan,
        trust: Option<HostKeyTrust>,
    ) -> Result<Self, SshConnectionError> {
        if !matches!(&plan.route, ConnectionRoute::Direct) {
            return Err(SshConnectionError::UnsupportedRoute);
        }
        if !matches!(
            &plan.credential,
            CredentialMaterial::Password(_) | CredentialMaterial::PrivateKey(_)
        ) {
            return Err(SshConnectionError::UnsupportedCredential);
        }
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
        let connection = match ClientConnection::connect(config).await {
            Ok(connection) => connection,
            Err(error) => {
                let _ = lifecycle.transition(ConnectionState::Failed);
                return Err(SshConnectionError::Engine(error));
            }
        };
        Ok(Self {
            connection,
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
                    self.connection
                        .authenticate_password(&username, password.as_bytes())
                        .await
                        .map_err(SshConnectionError::Engine)
                }
            }
            CredentialMaterial::PrivateKey(key) => {
                self.authenticate_private_key(&username, &key).await
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
            self.connection
                .authenticate_password(username, password.as_bytes())
                .await
                .map_err(SshConnectionError::Engine)
        };
        self.finish_authentication(result)
    }

    async fn authenticate_private_key(
        &mut self,
        username: &str,
        material: &SecretVec,
    ) -> Result<(), SshConnectionError> {
        let signer = parse_software_key(material)?;
        match signer {
            SoftwareKeySigner::Ed25519(signer) => {
                self.connection.authenticate_publickey(username, &signer).await.map_err(Into::into)
            }
            SoftwareKeySigner::P256(signer) => {
                self.connection.authenticate_publickey(username, &signer).await.map_err(Into::into)
            }
            SoftwareKeySigner::Rsa(signer) => {
                self.connection.authenticate_publickey(username, signer.as_ref()).await.map_err(
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
        Ok(SshSession { channel: self.connection.open_session().await?, output_bytes: 0 })
    }

    /// Close the SSH connection and mark it closed.
    pub async fn close(mut self) -> Result<(), SshConnectionError> {
        self.connection.disconnect().await?;
        let _ = self.lifecycle.transition(ConnectionState::Closed);
        Ok(())
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
    use ssh_key::{Algorithm, EcdsaCurve};
    use tempfile::tempdir;

    use super::*;
    use crate::repository::{AccessProfileChange, CredentialChange, Edit, HostChange, Provenance};

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempdir().expect("tempdir");
        let store = Store::open(&dir.path().join("local.db"), &LocalDatabaseKey::new([7; 32]))
            .expect("store");
        (dir, store)
    }

    #[test]
    fn software_key_parser_accepts_supported_openssh_keys() {
        let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
        for (algorithm, expected) in [
            (Algorithm::Ed25519, "ed25519"),
            (Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }, "p256"),
            (Algorithm::Rsa { hash: None }, "rsa"),
        ] {
            let key = PrivateKey::random(&mut rng, algorithm).expect("test key");
            let pem = key.to_openssh(Default::default()).expect("OpenSSH encoding");
            let material = SecretVec::new(pem.as_bytes().to_vec());
            let parsed = parse_software_key(&material).expect("supported key");
            assert!(matches!(
                (parsed, expected),
                (SoftwareKeySigner::Ed25519(_), "ed25519")
                    | (SoftwareKeySigner::P256(_), "p256")
                    | (SoftwareKeySigner::Rsa(_), "rsa")
            ));
            assert!(!format!("{material:?}").contains("OPENSSH PRIVATE KEY"));
        }
    }

    #[test]
    fn software_key_parser_rejects_bad_or_oversized_material_without_disclosing_it() {
        let bad = SecretVec::new(b"-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-key".to_vec());
        let error = parse_software_key(&bad).err().expect("invalid key rejected");
        assert!(matches!(error, SshConnectionError::InvalidPrivateKey));
        assert!(!error.to_string().contains("not-a-key"));

        let oversized = SecretVec::new(vec![b'X'; MAX_SSH_INPUT + 1]);
        assert!(matches!(
            parse_software_key(&oversized),
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
