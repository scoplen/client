// SPDX-License-Identifier: Apache-2.0
//! Retained admitted-device authentication and Personal synchronization.
//!
//! This module keeps identity, request material, and credentials inside Rust and
//! SQLCipher. Neutral admission anchors verify locally; explicit retained-device
//! revalidation uses only current authentication and K-4, never retired entry operations.

mod account;
mod background;
mod identity;
mod notification;

mod refresh;
mod registration;
mod retained;
mod revalidation;
mod sync;
mod transport;
pub(crate) mod trust;

pub use account::{PersonalAccountDevice, PersonalAccountSnapshot};
pub use background::{PersonalBackgroundStatus, PersonalSyncRuntime};
pub use registration::{RegistrationError, RegistrationPhase, RegistrationStatus};
pub use sync::{
    PersonalInventoryIntent, PersonalInventoryProgress, PersonalSyncBootstrap, PersonalSyncError,
};

use std::sync::Arc;

use scoplen_api::auth::{
    AuthChallengeRequest, AuthChallengeResponse, AuthDeviceRequest, AuthJwks, AuthTokenResponse,
};
use scoplen_crypto::{
    DeviceAccessToken, DeviceAuthContext, P256SigningKey, SecretVec, TrustedDeviceAccessTokenKeys,
    dpop_jwk_thumbprint,
};
use serde::Serialize;
use specta::Type;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::store::{
    Store,
    personal::{PersonalRecord, PersonalTokens},
};
use transport::Transport;

/// Redacted state of this device's retained Account identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "snake_case")]
pub enum PersonalServerPhase {
    /// No Account is bound to this store; password sign-in is not implemented yet.
    NotConfigured,
    /// Historical pending data is retained, but its entry protocol is retired.
    RetiredEntry,
    /// Retained keys can explicitly prove current device authority before local installation.
    RevalidationRequired,
    /// The verified session is usable, including refresh on an explicit network operation.
    Authenticated,
    /// The established session needs a fresh signed-device challenge; local data is retained.
    AuthenticationRequired,
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
    /// Historical pending data cannot authorize current account access.
    #[error(
        "This unfinished account setup uses a retired protocol. Its data is unchanged. Reopen a confirmed profile or restore a verified local backup."
    )]
    RetiredEntry,
    /// Historical success evidence or immutable ownership could not be verified.
    #[error(
        "The saved account identity could not be verified. Its data is unchanged. Reopen its original profile or restore a verified local backup."
    )]
    AdmissionUnverified,
    /// The encrypted store is unavailable or an operation could not be committed.
    #[error("The encrypted local data is unavailable. Unlock it and try again.")]
    Storage,
    /// An operation is already running.
    #[error("A Personal server operation is already running. Wait for it to finish.")]
    Busy,
    /// A generated key or stored identity is unavailable.
    #[error(
        "The Personal identity could not be prepared or read. Its existing keys were retained."
    )]
    Identity,
    /// An encrypted-store identity must exist before any network operation.
    #[error("No confirmed account profile is open. Open an existing profile before continuing.")]
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
        "The server did not authenticate this device. Its identity was retained; ask the operator to check device access before authenticating again."
    )]
    Authentication,
    /// A bounded response or its cryptographic binding was invalid.
    #[error(
        "The server returned an invalid or mismatched authentication response. No credentials were accepted."
    )]
    InvalidResponse,
    /// A spent, expired, uncertain, or mismatched session must not replay its refresh token.
    #[error(
        "Authenticate this device again with its saved identity. Local data and sync keys were retained."
    )]
    AuthenticationRequired,
    /// A verified unchanged refresh response allows a later explicit retry.
    #[error(
        "The server could not refresh this session. Wait before trying sync again, or authenticate this device."
    )]
    RefreshDeferred,
    /// A verified token no longer grants the operation's exact required scope.
    #[error(
        "This device session does not permit this operation. Ask your server operator to check its access."
    )]
    PermissionDenied,
    /// The complete account and signed-device snapshot could not be verified.
    #[error(
        "The account or device response was invalid. The previous local snapshot was retained."
    )]
    InvalidAccountResponse,
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

    /// Authenticate an admitted identity with a fresh signed-device challenge.
    pub async fn authenticate(
        &self,
        store: Arc<Store>,
    ) -> Result<PersonalServerStatus, PersonalServerError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let pending = record(&store)?;
        if !pending.authentication_allowed() {
            return Err(PersonalServerError::RetiredEntry);
        }
        let transport = self.transport.as_ref().map_err(|error| *error)?;
        authenticate(&store, &pending, transport).await?.require_authenticated()?;
        status(&store)
    }
}

fn storage(error: crate::store::StoreError) -> PersonalServerError {
    match error {
        crate::store::StoreError::AccountContext => PersonalServerError::AdmissionUnverified,
        _ => PersonalServerError::Storage,
    }
}

fn record(store: &Store) -> Result<PersonalRecord, PersonalServerError> {
    let identity =
        store.personal_record().map_err(storage)?.ok_or(PersonalServerError::NotConfigured)?;
    retained::RetainedAccount::load(store, &identity)?;
    Ok(identity)
}

fn status(store: &Store) -> Result<PersonalServerStatus, PersonalServerError> {
    let Some(record) = store.personal_record().map_err(storage)? else {
        return Ok(PersonalServerStatus {
            phase: if store.has_archived_personal_entry().map_err(storage)? {
                PersonalServerPhase::RetiredEntry
            } else {
                PersonalServerPhase::NotConfigured
            },
            origin: None,
            account_id: None,
            device_id: None,
            personal_vault_id: None,
            device_name: None,
            recovery_key_saved: false,
            recovery_key_confirmed: false,
        });
    };
    let current = now().unwrap_or(u64::MAX);
    let admission = retained::RetainedAccount::load(store, &record);
    let admitted = match admission {
        Ok(_) => true,
        Err(PersonalServerError::RetiredEntry | PersonalServerError::AdmissionUnverified)
            if !record.admitted =>
        {
            revalidation::verify_material(store, &record)?;
            false
        }
        Err(error) => return Err(error),
    };
    let phase = if !admitted {
        PersonalServerPhase::RevalidationRequired
    } else if record.auth_scope.is_some()
        && (record.access_expires_at.is_some_and(|expires| expires > current)
            || record.refresh_available
                && record.refresh_expires_at.is_some_and(|expires| expires > current))
    {
        PersonalServerPhase::Authenticated
    } else {
        PersonalServerPhase::AuthenticationRequired
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

enum AuthenticationOutcome {
    Authenticated,
    DeviceDenied,
}

impl AuthenticationOutcome {
    fn require_authenticated(self) -> Result<(), PersonalServerError> {
        match self {
            Self::Authenticated => Ok(()),
            Self::DeviceDenied => Err(PersonalServerError::Authentication),
        }
    }
}

async fn authenticate(
    store: &Store,
    pending: &PersonalRecord,
    transport: &Transport,
) -> Result<AuthenticationOutcome, PersonalServerError> {
    let generation = store
        .begin_personal_authentication(pending)
        .map_err(storage)?
        .ok_or(PersonalServerError::Busy)?;
    let Some(tokens) = authentication_tokens(store, pending, transport, || Ok(())).await? else {
        return Ok(AuthenticationOutcome::DeviceDenied);
    };
    if !store.finish_personal_session(pending, generation, false, &tokens, None).map_err(storage)? {
        return Err(PersonalServerError::Busy);
    }
    Ok(AuthenticationOutcome::Authenticated)
}

async fn authentication_tokens(
    store: &Store,
    pending: &PersonalRecord,
    transport: &Transport,
    current: impl Fn() -> Result<(), PersonalServerError>,
) -> Result<Option<PersonalTokens>, PersonalServerError> {
    current()?;
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
    current()?;
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
        if response.status == 401
            && response.problem_json
            && let Ok(problem) =
                serde_json::from_slice::<scoplen_api::ProblemDetails>(response.body.as_bytes())
            && problem.status == 401
            && problem.code.as_str() == "auth.authentication_required"
            && !problem.retryable
        {
            return Ok(None);
        }
        return Err(PersonalServerError::Authentication);
    }
    let tokens = AuthTokenResponse::from_json(response.text()?)
        .map_err(|_| PersonalServerError::InvalidResponse)?;
    let access = Zeroizing::new(tokens.access_token);
    let refresh = Zeroizing::new(tokens.refresh_token);
    if refresh.is_empty() || refresh.len() > scoplen_api::auth::MAX_REFRESH_TOKEN_BYTES {
        return Err(PersonalServerError::InvalidResponse);
    }
    current()?;
    let trusted = trusted_token_keys(transport, &pending.origin).await?;
    current()?;
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
        || claims.scope != scoplen_api::auth::INITIAL_DEVICE_ACCESS_SCOPE
        || !claims.org.is_empty()
    {
        return Err(PersonalServerError::InvalidResponse);
    }
    let access_expires = current_time.saturating_add(tokens.expires_in).min(verified.expires_at());
    let refresh_expires = claims
        .iat
        .checked_add(tokens.refresh_expires_in)
        .filter(|expires| *expires <= i64::MAX as u64 && *expires > current_time)
        .ok_or(PersonalServerError::InvalidResponse)?;
    Ok(Some(PersonalTokens {
        access: SecretVec::new(access.as_bytes().to_vec()),
        refresh: SecretVec::new(refresh.as_bytes().to_vec()),
        access_expires_at: access_expires,
        refresh_expires_at: refresh_expires,
        scope: claims.scope.clone(),
    }))
}

async fn trusted_token_keys(
    transport: &Transport,
    origin: &str,
) -> Result<TrustedDeviceAccessTokenKeys, PersonalServerError> {
    let jwks = transport.get(origin, "/.well-known/jwks.json", 4_096).await?;
    if jwks.status != 200 {
        return Err(PersonalServerError::InvalidResponse);
    }
    let jwks = AuthJwks::from_json(jwks.body.as_bytes())
        .map_err(|_| PersonalServerError::InvalidResponse)?;
    let mut trusted =
        TrustedDeviceAccessTokenKeys::new(origin).map_err(|_| PersonalServerError::Identity)?;
    for key in jwks.keys() {
        trusted
            .insert(key.kid(), key.public_key())
            .map_err(|_| PersonalServerError::InvalidResponse)?;
    }
    Ok(trusted)
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(all(test, feature = "live-server-integration"))]
mod live_server;
