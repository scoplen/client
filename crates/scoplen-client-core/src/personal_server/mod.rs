// SPDX-License-Identifier: Apache-2.0
//! Personal invitation enrollment and fresh enrolled-device authentication.
//!
//! This module keeps identity, request material, and credentials inside Rust and
//! SQLCipher. Enrollment is claimed durably once; recovery always authenticates
//! the retained identity with a new challenge instead of replaying an invitation.

mod identity;
mod transport;

use std::{fs::OpenOptions, io::Write as _, path::Path, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::auth::{
    AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthJwks, AuthTokenResponse,
};
use scoplen_crypto::{
    DeviceAccessToken, DeviceAuthContext, P256SigningKey, RecoveryKey, SecretVec,
    TrustedDeviceAccessTokenKeys, dpop_jwk_thumbprint, validate_server_origin,
};
use serde::Serialize;
use specta::Type;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::store::{Store, personal::PersonalRecord};
use transport::Transport;

/// Redacted progress of this device's Personal server enrollment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum PersonalServerPhase {
    /// No invitation has been prepared.
    NotConfigured,
    /// Save the generated recovery key and confirm that it is kept safely.
    RecoveryRequired,
    /// The single invitation redemption may now be submitted.
    ReadyToEnroll,
    /// Enrollment may have committed; only fresh device authentication is safe.
    EnrollmentUnconfirmed,
    /// This identity has an unexpired, verified device access token.
    Authenticated,
}

/// Public metadata only. No token, invitation, recovery key, or private key crosses IPC.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PersonalServerStatus {
    /// Current safe next action.
    pub phase: PersonalServerPhase,
    /// The exact user-selected canonical HTTPS origin.
    pub origin: Option<String>,
    /// The retained account identity.
    pub account_id: Option<String>,
    /// The retained device identity.
    pub device_id: Option<String>,
    /// The retained Personal vault identity; existing local objects remain local.
    pub personal_vault_id: Option<String>,
    /// This device's user-selected name.
    pub device_name: Option<String>,
    /// A native recovery-file save completed successfully.
    pub recovery_key_saved: bool,
    /// The user explicitly confirmed keeping the recovery key safely.
    pub recovery_key_confirmed: bool,
}

/// Safe failures contain no source body, URL fragment, token, or underlying network diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub enum PersonalServerError {
    /// The encrypted store is unavailable or an operation could not be committed.
    #[error("The encrypted local data is unavailable. Unlock it and try again.")]
    Storage,
    /// An operation is already running.
    #[error("A Personal server operation is already running. Wait for it to finish.")]
    Busy,
    /// An invitation did not have the exact canonical HTTPS fragment form.
    #[error("Use the complete HTTPS Personal invitation link supplied by your server operator.")]
    Invitation,
    /// A certificate display name must be a bounded, nonempty printable string.
    #[error("Enter a device name containing 1 to 128 UTF-8 bytes without control characters.")]
    DeviceName,
    /// A persisted identity must not be silently replaced.
    #[error("This device already has a prepared Personal identity. Continue its existing setup.")]
    AlreadyConfigured,
    /// A generated key or stored identity is unavailable.
    #[error(
        "The Personal identity could not be prepared or read. Its existing keys were retained."
    )]
    Identity,
    /// Setup has not reached the required phase.
    #[error("Save the recovery key and confirm that it is kept safely before joining the server.")]
    RecoveryRequired,
    /// The recovery file was not written.
    #[error(
        "The recovery key could not be saved. Choose a new file in a private location and try again."
    )]
    RecoverySave,
    /// An attempted redemption cannot be replayed.
    #[error(
        "Enrollment was already attempted. Retry device authentication with the retained identity."
    )]
    AlreadyAttempted,
    /// An encrypted-store identity must exist before any network operation.
    #[error("Prepare a Personal invitation before continuing.")]
    NotConfigured,
    /// A bounded verified HTTPS exchange did not complete.
    #[error(
        "The HTTPS exchange did not complete. Check the server address, certificate, and connection, then retry device authentication."
    )]
    Network,
    /// The connector failed before sending an HTTP request, without any timeout.
    #[error(
        "The HTTPS connection could not be established before sending a request. Check the server address, certificate, and connection, then retry this step."
    )]
    ConnectionBeforeRequest,
    /// Authentication was denied without exposing arbitrary server content.
    #[error(
        "The server did not authenticate this device. Its identity was retained; ask the operator to check enrollment, then retry device authentication."
    )]
    Authentication,
    /// A bounded response or its cryptographic binding was invalid.
    #[error(
        "The server returned an invalid or mismatched authentication response. No credentials were accepted."
    )]
    InvalidResponse,
}

/// Serializes mutating Personal operations while retaining no credentials in frontend state.
pub struct PersonalServer {
    operation: Mutex<()>,
    transport: Result<Transport, PersonalServerError>,
}

impl Default for PersonalServer {
    fn default() -> Self {
        Self { operation: Mutex::new(()), transport: Transport::new() }
    }
}

impl PersonalServer {
    /// Read only redacted metadata; this does not open a network connection.
    pub fn status(&self, store: &Store) -> Result<PersonalServerStatus, PersonalServerError> {
        status(store)
    }

    /// Parse the invitation and persist the generated identity before any network request.
    pub async fn prepare(
        &self,
        store: Arc<Store>,
        invitation_url: Zeroizing<String>,
        device_name: String,
    ) -> Result<PersonalServerStatus, PersonalServerError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        tokio::task::spawn_blocking(move || {
            if store.personal_record().map_err(storage)?.is_some() {
                return Err(PersonalServerError::AlreadyConfigured);
            }
            if device_name.is_empty()
                || device_name.len() > 128
                || device_name.chars().any(char::is_control)
            {
                return Err(PersonalServerError::DeviceName);
            }
            let invitation = Invitation::parse(&invitation_url)?;
            let record = identity::prepare(&store, invitation, device_name)?;
            store.insert_personal_record(&record).map_err(storage)?;
            status(&store)
        })
        .await
        .map_err(|_| PersonalServerError::Identity)?
    }

    /// Save the recovery key directly to a new native-selected file. Secrets never cross IPC.
    pub async fn save_recovery_key(
        &self,
        store: Arc<Store>,
        path: std::path::PathBuf,
    ) -> Result<PersonalServerStatus, PersonalServerError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        tokio::task::spawn_blocking(move || {
            let record = record(&store)?;
            let secrets = identity::Secrets::parse(&record.private_material)?;
            let recovery = RecoveryKey::from_bytes(secrets.recovery())
                .map_err(|_| PersonalServerError::Identity)?;
            let display = Zeroizing::new(recovery.encode_display());
            let contents = Zeroizing::new(format!("Scoplen Personal recovery key\nServer: {}\nAccount: {}\n\n{}\n\nKeep this file private and offline. Anyone with this key can recover the account.\n",
                record.origin, record.account_id, display.as_str()));
            save_private_file(&path, contents.as_bytes())?;
            if !store.save_personal_recovery().map_err(storage)? {
                return Err(PersonalServerError::Storage);
            }
            status(&store)
        }).await.map_err(|_| PersonalServerError::RecoverySave)?
    }

    /// Record the user's explicit confirmation after a successful native export.
    pub async fn confirm_recovery_key(
        &self,
        store: Arc<Store>,
    ) -> Result<PersonalServerStatus, PersonalServerError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        tokio::task::spawn_blocking(move || {
            if !store.confirm_personal_recovery().map_err(storage)? {
                return Err(PersonalServerError::RecoveryRequired);
            }
            status(&store)
        })
        .await
        .map_err(|_| PersonalServerError::Storage)?
    }

    /// Claim redemption once before I/O; always confirm by fresh device authentication.
    pub async fn submit(
        &self,
        store: Arc<Store>,
    ) -> Result<PersonalServerStatus, PersonalServerError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let pending = record(&store)?;
        if pending.enrollment_attempted {
            return Err(PersonalServerError::AlreadyAttempted);
        }
        if !pending.recovery_confirmed {
            return Err(PersonalServerError::RecoveryRequired);
        }
        let transport = self.transport.as_ref().map_err(|error| *error)?;
        let body = pending.enrollment_request.as_ref().ok_or(PersonalServerError::Identity)?;
        if !store.claim_personal_enrollment().map_err(storage)? {
            return Err(PersonalServerError::AlreadyAttempted);
        }
        let response = transport
            .post(&pending.origin, "/api/v1/auth/personal-enroll", body.as_bytes(), 256)
            .await;
        if matches!(response, Err(PersonalServerError::ConnectionBeforeRequest)) {
            store.release_unsent_personal_enrollment().map_err(storage)?;
            return Err(PersonalServerError::ConnectionBeforeRequest);
        }
        // A missing, malformed, denied, or uncertain response never replaces or replays identity.
        // Authentication is the only authoritative recovery for a possibly committed enrollment.
        if let Ok(response) = response
            && response.status == 201
        {
            let enrolled = scoplen_api::personal_enrollment::PersonalEnrollmentResponse::from_json(
                response.body.as_bytes(),
            )
            .map_err(|_| PersonalServerError::InvalidResponse)?;
            if enrolled.account_id != pending.account_id
                || enrolled.device_id != store.device_id()
                || enrolled.personal_vault_id != pending.personal_vault_id
            {
                return Err(PersonalServerError::InvalidResponse);
            }
        }
        authenticate(&store, &pending, transport).await?;
        status(&store)
    }

    /// Retry using a fresh challenge. Never sends the invitation redemption again.
    pub async fn authenticate(
        &self,
        store: Arc<Store>,
    ) -> Result<PersonalServerStatus, PersonalServerError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let pending = record(&store)?;
        if !pending.enrollment_attempted {
            return Err(PersonalServerError::RecoveryRequired);
        }
        store.clear_personal_tokens().map_err(storage)?;
        let transport = self.transport.as_ref().map_err(|error| *error)?;
        authenticate(&store, &pending, transport).await?;
        status(&store)
    }
}

fn storage(_: crate::store::StoreError) -> PersonalServerError {
    PersonalServerError::Storage
}

fn record(store: &Store) -> Result<PersonalRecord, PersonalServerError> {
    store.personal_record().map_err(storage)?.ok_or(PersonalServerError::NotConfigured)
}

fn status(store: &Store) -> Result<PersonalServerStatus, PersonalServerError> {
    let Some(record) = store.personal_record().map_err(storage)? else {
        return Ok(PersonalServerStatus {
            phase: PersonalServerPhase::NotConfigured,
            origin: None,
            account_id: None,
            device_id: None,
            personal_vault_id: None,
            device_name: None,
            recovery_key_saved: false,
            recovery_key_confirmed: false,
        });
    };
    let phase =
        if record.access_expires_at.is_some_and(|expires| expires > now().unwrap_or(u64::MAX)) {
            PersonalServerPhase::Authenticated
        } else if record.enrollment_attempted {
            PersonalServerPhase::EnrollmentUnconfirmed
        } else if record.recovery_confirmed {
            PersonalServerPhase::ReadyToEnroll
        } else {
            PersonalServerPhase::RecoveryRequired
        };
    Ok(PersonalServerStatus {
        phase,
        origin: Some(record.origin),
        account_id: Some(record.account_id.to_string()),
        device_id: Some(store.device_id().to_string()),
        personal_vault_id: Some(record.personal_vault_id.to_string()),
        device_name: Some(record.device_name),
        recovery_key_saved: record.recovery_saved,
        recovery_key_confirmed: record.recovery_confirmed,
    })
}

fn now() -> Result<u64, PersonalServerError> {
    scoplen_model::system_time_millis()
        .map(|time| time / 1_000)
        .map_err(|_| PersonalServerError::Identity)
}

struct Invitation {
    origin: String,
    token: SecretVec,
}

impl Invitation {
    fn parse(input: &str) -> Result<Self, PersonalServerError> {
        let (origin, encoded) =
            input.split_once("/invite#token=").ok_or(PersonalServerError::Invitation)?;
        validate_server_origin(origin).map_err(|_| PersonalServerError::Invitation)?;
        if encoded.len() != 43 {
            return Err(PersonalServerError::Invitation);
        }
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD.decode(encoded).map_err(|_| PersonalServerError::Invitation)?,
        );
        let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(&*bytes));
        if bytes.len() != 32 || canonical.as_str() != encoded {
            return Err(PersonalServerError::Invitation);
        }
        Ok(Self { origin: origin.to_owned(), token: SecretVec::new(bytes.to_vec()) })
    }
}

async fn authenticate(
    store: &Store,
    pending: &PersonalRecord,
    transport: &Transport,
) -> Result<(), PersonalServerError> {
    let request =
        AuthChallengeRequest::new(store.device_id()).map_err(|_| PersonalServerError::Identity)?;
    let response = transport
        .post(
            &pending.origin,
            "/api/v1/auth/challenge",
            request.to_json().map_err(|_| PersonalServerError::Identity)?.as_bytes(),
            4_096,
        )
        .await?;
    if response.status != 200 {
        return Err(PersonalServerError::Authentication);
    }
    let challenge = AuthChallengeResponse::from_json(response.text()?)
        .map_err(|_| PersonalServerError::InvalidResponse)?;
    let secrets = identity::Secrets::parse(&pending.private_material)?;
    let signing =
        P256SigningKey::from_bytes(secrets.signing()).map_err(|_| PersonalServerError::Identity)?;
    let context = DeviceAuthContext::new(&pending.origin, &challenge.nonce, store.device_id())
        .map_err(|_| PersonalServerError::InvalidResponse)?;
    let signature = signing.sign(&context.signature_input());
    let hex: String = signature.iter().map(|byte| format!("{byte:02x}")).collect();
    let request = AuthDeviceRequest::new(store.device_id(), challenge.nonce, hex)
        .map_err(|_| PersonalServerError::Identity)?;
    let response = transport
        .post(
            &pending.origin,
            "/api/v1/auth/device",
            request.to_json().map_err(|_| PersonalServerError::Identity)?.as_bytes(),
            16_384,
        )
        .await?;
    if response.status != 200 {
        return Err(PersonalServerError::Authentication);
    }
    let tokens = AuthTokenResponse::from_json(response.text()?)
        .map_err(|_| PersonalServerError::InvalidResponse)?;
    let access = Zeroizing::new(tokens.access_token);
    let refresh = Zeroizing::new(tokens.refresh_token);
    let jwks = transport.get(&pending.origin, "/.well-known/jwks.json", 4_096).await?;
    if jwks.status != 200 {
        return Err(PersonalServerError::InvalidResponse);
    }
    let jwks = AuthJwks::from_json(jwks.body.as_bytes())
        .map_err(|_| PersonalServerError::InvalidResponse)?;
    let mut trusted = TrustedDeviceAccessTokenKeys::new(&pending.origin)
        .map_err(|_| PersonalServerError::Identity)?;
    for key in jwks.keys() {
        trusted
            .insert(key.kid(), key.public_key())
            .map_err(|_| PersonalServerError::InvalidResponse)?;
    }
    let current_time = now()?;
    let verified = DeviceAccessToken::parse(&access)
        .and_then(|token| token.verify(&trusted, current_time))
        .map_err(|_| PersonalServerError::InvalidResponse)?;
    let claims = verified.claims();
    if claims.sub != pending.account_id
        || claims.did != store.device_id()
        || claims.cnf_jkt
            != dpop_jwk_thumbprint(&signing.public_key_sec1())
                .map_err(|_| PersonalServerError::Identity)?
    {
        return Err(PersonalServerError::InvalidResponse);
    }
    let access_expires = current_time.saturating_add(tokens.expires_in).min(verified.expires_at());
    let refresh_expires = current_time.saturating_add(tokens.refresh_expires_in);
    store
        .save_personal_tokens(
            access.as_bytes(),
            refresh.as_bytes(),
            access_expires,
            refresh_expires,
        )
        .map_err(storage)
}

fn save_private_file(path: &Path, contents: &[u8]) -> Result<(), PersonalServerError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| PersonalServerError::RecoverySave)?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|_| PersonalServerError::RecoverySave)
}

#[cfg(test)]
mod tests;
