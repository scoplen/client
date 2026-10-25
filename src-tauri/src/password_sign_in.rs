// SPDX-License-Identifier: Apache-2.0
//! Thin native password sign-in intents over independent Device admission.

use crate::{
    account_registration::{RegistrationIntent, drain, operation},
    profile_context::{NativeProfiles, ProfileRequest, ProfileSnapshot},
};
use scoplen_client_core::personal_server::{
    PasswordLoginError, PasswordLoginPhase, PasswordLoginStatus, PersonalServer, RegistrationAction,
};
use scoplen_crypto::SecretVec;
use serde::Serialize;
use specta::Type;
use std::sync::Arc;
use tauri::Manager as _;

/// Explicit next action for one original Device admission.
#[derive(Clone, Copy, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum PasswordSignInStep {
    /// Password verified; explicit admission Submit remains.
    Ready,
    /// Only exact original receipt confirmation is safe.
    OutcomeUnknown,
    /// Trusted unchanged result permits explicit Retry.
    RetryAvailable,
    /// Known unchanged or never-sent work needs fresh password options.
    SignInRequired,
    /// Historical admission confirmed; current Device installation remains.
    Committed,
}

/// Safe pending metadata without password, capability, proof or keys.
#[derive(Clone, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PasswordSignInView {
    /// Explicit next action.
    pub phase: PasswordSignInStep,
    /// Stable original admission operation.
    pub operation_id: String,
    /// Canonical deployment origin.
    pub origin: String,
    /// Canonical existing username.
    pub username: String,
    /// Trusted retry deadline as decimal Unix milliseconds.
    pub retry_not_before_ms: Option<String>,
}

impl From<PasswordLoginStatus> for PasswordSignInView {
    fn from(value: PasswordLoginStatus) -> Self {
        Self {
            phase: match value.phase {
                PasswordLoginPhase::Ready => PasswordSignInStep::Ready,
                PasswordLoginPhase::OutcomeUnknown => PasswordSignInStep::OutcomeUnknown,
                PasswordLoginPhase::RetryAvailable => PasswordSignInStep::RetryAvailable,
                PasswordLoginPhase::SignInRequired => PasswordSignInStep::SignInRequired,
                PasswordLoginPhase::Committed => PasswordSignInStep::Committed,
            },
            operation_id: value.operation_id.to_string(),
            origin: value.origin,
            username: value.username,
            retry_not_before_ms: value.retry_not_before_ms.map(|time| time.to_string()),
        }
    }
}

fn failure(error: PasswordLoginError) -> String {
    use PasswordLoginError::*;
    match error {
        Busy => "busy",
        ContextChanged => "profileChanged",
        ExistingProfile => "signInExisting",
        InvalidInput => "invalidInput",
        Verification | InvalidResponse | RequestRejected => "verification",
        Storage => "storage",
        NotPrepared => "notPrepared",
        OutcomeUnknown => "outcomeUnknown",
        AdmissionConflict => "signInAgain",
        ExplicitRetryRequired | RetryUnavailable => "explicitRetryRequired",
        RetryDeferred | RateLimited { .. } => "retryDeferred",
        Cancelled => "cancelled",
        Network | Timeout => "network",
        UnsupportedService => "unsupportedService",
        AuthenticationDenied => "signInDenied",
        PolicyDenied => "signInPolicy",
        QuotaExceeded => "deviceQuota",
        ServiceUnavailable => "serviceUnavailable",
    }
    .into()
}

/// Read retained sign-in metadata without requesting fresh password options or network access.
#[tauri::command]
#[specta::specta]
pub async fn password_sign_in_status(
    app: tauri::AppHandle,
    context: ProfileRequest,
) -> Result<Option<PasswordSignInView>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let (profiles, source) = context.account_context()?;
        app.state::<PersonalServer>()
            .password_login_status(profiles, source)
            .map(|status| status.map(Into::into))
            .map_err(failure)
    })
    .await
    .map_err(|_| "storage")?
}

/// Verify the password through real HTTPS and durably prepare an independent Device admission.
#[tauri::command]
#[specta::specta]
pub async fn begin_password_sign_in(
    app: tauri::AppHandle,
    context: ProfileRequest,
    ticket: String,
    origin: String,
    username: String,
    device_name: String,
    password: String,
) -> Result<PasswordSignInView, String> {
    let password = SecretVec::new(password.into_bytes());
    let run = context.owner.register_operation(ticket)?;
    let (profiles, source) = context.account_context()?;
    app.state::<PersonalServer>()
        .begin_password_login(
            profiles,
            source,
            &origin,
            &username,
            &device_name,
            password,
            &run.cancellation,
        )
        .await
        .map(Into::into)
        .map_err(failure)
}

/// Submit, exactly confirm, or explicitly retry only the retained original Device admission.
#[tauri::command]
#[specta::specta]
pub async fn exchange_password_sign_in(
    app: tauri::AppHandle,
    context: ProfileRequest,
    ticket: String,
    operation_id: String,
    intent: RegistrationIntent,
) -> Result<PasswordSignInView, String> {
    let run = context.owner.register_operation(ticket)?;
    let (profiles, source) = context.account_context()?;
    let action = match intent {
        RegistrationIntent::Submit => RegistrationAction::Submit,
        RegistrationIntent::Confirm => RegistrationAction::Confirm,
        RegistrationIntent::Retry => RegistrationAction::Retry,
    };
    app.state::<PersonalServer>()
        .exchange_password_login(
            profiles,
            source,
            operation(&operation_id)?,
            action,
            &run.cancellation,
        )
        .await
        .map(Into::into)
        .map_err(failure)
}

/// Discard only a never-sent or durably proven unchanged admission; unknown work remains retained.
#[tauri::command]
#[specta::specta]
pub async fn discard_password_sign_in(
    app: tauri::AppHandle,
    context: ProfileRequest,
    operation_id: String,
) -> Result<(), String> {
    let operation_id = operation(&operation_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let (profiles, source) = context.account_context()?;
        app.state::<PersonalServer>()
            .cancel_password_login(profiles, source, operation_id)
            .map_err(failure)
    })
    .await
    .map_err(|_| "storage")?
}

/// Install exact confirmed admission only after fresh normal Device authentication and complete K-4.
#[tauri::command]
#[specta::specta]
pub async fn install_password_sign_in_profile(
    app: tauri::AppHandle,
    profiles: tauri::State<'_, Arc<NativeProfiles>>,
    generation: String,
    ticket: String,
    operation_id: String,
    local_passphrase: Option<String>,
) -> Result<ProfileSnapshot, String> {
    let local_passphrase = local_passphrase.map(|value| SecretVec::new(value.into_bytes()));
    let run = profiles.register_operation(ticket.clone())?;
    let switch = profiles.begin_switch(&app, &generation, Some(&ticket))?;
    drain(&app, profiles.inner().clone()).await?;
    run.check()?;
    let source = switch.catalog.current().map_err(|_| "profileChanged")?;
    app.state::<PersonalServer>()
        .install_password_login_profile(
            &switch.catalog,
            &source,
            operation(&operation_id)?,
            local_passphrase,
            &run.cancellation,
        )
        .await
        .map_err(|error| match error {
            scoplen_client_core::profiles::AccountProfileError::PasswordLogin(error) => {
                failure(error)
            }
            scoplen_client_core::profiles::AccountProfileError::PassphraseRequired => {
                "passphraseRequired".into()
            }
            scoplen_client_core::profiles::AccountProfileError::Locked => "profileUnlock".into(),
            scoplen_client_core::profiles::AccountProfileError::Cancelled => "cancelled".into(),
            scoplen_client_core::profiles::AccountProfileError::ContextChanged => {
                "profileChanged".into()
            }
            scoplen_client_core::profiles::AccountProfileError::Busy => "busy".into(),
            _ => "installation".into(),
        })?;
    drop(switch);
    profiles.publish(&app)
}
