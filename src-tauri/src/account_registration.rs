// SPDX-License-Identifier: Apache-2.0
//! Native registration intents. Secret material and recovery export stay in Rust.

use crate::profile_context::{NativeProfiles, ProfileRequest, ProfileSnapshot};
use scoplen_client_core::personal_server::{
    PersonalServer, RegistrationAction, RegistrationError, RegistrationPhase, RegistrationStatus,
};
use scoplen_crypto::SecretVec;
use serde::{Deserialize, Serialize};
use specta::Type;
use std::sync::Arc;
use tauri::Manager as _;

#[derive(Clone, Copy, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
/// Explicit next action for one retained registration.
pub enum RegistrationStep {
    /// Recovery export and safe-storage confirmation are still required.
    RecoveryRequired,
    /// Explicit Submit may create the account.
    Ready,
    /// Only exact historical confirmation is safe.
    OutcomeUnknown,
    /// Trusted unchanged result permits explicit Retry.
    RetryAvailable,
    /// Historical commit is confirmed; current Device installation remains separate.
    Committed,
}

#[derive(Clone, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
/// Path-free public state; key material remains in the native encrypted store.
pub struct RegistrationView {
    /// Safe explicit next action.
    pub phase: RegistrationStep,
    /// Stable original operation identity.
    pub operation_id: String,
    /// Canonical Personal deployment.
    pub origin: String,
    /// Canonical username.
    pub username: String,
    /// Native recovery export completed.
    pub recovery_saved: bool,
    /// The person explicitly confirmed safe storage.
    pub recovery_confirmed: bool,
    /// Trusted retry deadline as decimal Unix milliseconds.
    pub retry_not_before_ms: Option<String>,
}

impl From<RegistrationStatus> for RegistrationView {
    fn from(status: RegistrationStatus) -> Self {
        Self {
            phase: match status.phase {
                RegistrationPhase::RecoveryRequired => RegistrationStep::RecoveryRequired,
                RegistrationPhase::Ready => RegistrationStep::Ready,
                RegistrationPhase::OutcomeUnknown => RegistrationStep::OutcomeUnknown,
                RegistrationPhase::RetryAvailable => RegistrationStep::RetryAvailable,
                RegistrationPhase::Committed => RegistrationStep::Committed,
            },
            operation_id: status.operation_id.to_string(),
            origin: status.origin,
            username: status.username,
            recovery_saved: status.recovery_saved,
            recovery_confirmed: status.recovery_confirmed,
            retry_not_before_ms: status.retry_not_before_ms.map(|value| value.to_string()),
        }
    }
}

fn failure(error: RegistrationError) -> String {
    use RegistrationError::*;
    match error {
        InvalidInput => "invalidInput",
        Busy => "busy",
        ContextChanged => "profileChanged",
        ExistingProfile => "existingProfile",
        NotPrepared => "notPrepared",
        RecoveryRequired => "recoveryRequired",
        RecoverySave => "recoverySave",
        OutcomeUnknown => "outcomeUnknown",
        Cancelled => "cancelled",
        Timeout | Network => "network",
        UnsupportedService => "unsupportedService",
        PolicyDenied => "policyDenied",
        RegistrationDenied => "registrationDenied",
        QuotaExceeded => "quotaExceeded",
        RateLimited { .. } | RetryDeferred => "retryDeferred",
        ExplicitRetryRequired | RetryUnavailable => "explicitRetryRequired",
        RequestRejected | AuthenticationDenied | InvalidResponse | Identity => "verification",
        ServiceUnavailable => "serviceUnavailable",
        Storage => "storage",
    }
    .into()
}

pub(crate) fn operation(id: &str) -> Result<uuid::Uuid, String> {
    uuid::Uuid::parse_str(id).map_err(|_| "invalidInput".into())
}

/// Open the catalog locally and subscribe to its captured-profile events.
#[tauri::command]
#[specta::specta]
pub fn account_profiles_snapshot(
    app: tauri::AppHandle,
    profiles: tauri::State<'_, Arc<NativeProfiles>>,
) -> Result<ProfileSnapshot, String> {
    profiles.publish(&app)
}

/// Read and reverify pending registration locally without network activity.
#[tauri::command]
#[specta::specta]
pub async fn registration_status(
    app: tauri::AppHandle,
    context: ProfileRequest,
) -> Result<Option<RegistrationView>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let local = context.get().map_err(|_| "profileChanged")?;
        let store = context.store().ok_or("profileChanged")?;
        app.state::<PersonalServer>()
            .registration_status(&local, &store)
            .map(|status| status.map(Into::into))
            .map_err(failure)
    })
    .await
    .map_err(|_| "storage")?
}

/// Derive real password material and save an independent pending registration in Rust.
#[tauri::command]
#[specta::specta]
pub async fn prepare_account_registration(
    app: tauri::AppHandle,
    context: ProfileRequest,
    ticket: String,
    origin: String,
    username: String,
    device_name: String,
    password: String,
) -> Result<RegistrationView, String> {
    let password = SecretVec::new(password.into_bytes());
    let run = context.owner.register_operation(ticket)?;
    tauri::async_runtime::spawn_blocking(move || {
        run.check()?;
        let local = context.get().map_err(|_| "profileChanged")?;
        let store = context.store().ok_or("profileChanged")?;
        let result = app
            .state::<PersonalServer>()
            .prepare_registration(&local, &store, &origin, &username, &device_name, password)
            .map(Into::into)
            .map_err(failure);
        run.check()?;
        result
    })
    .await
    .map_err(|_| "storage")?
}

/// Export the recovery key to a new native file without returning its key or path.
#[tauri::command]
#[specta::specta]
pub async fn save_registration_recovery(
    app: tauri::AppHandle,
    context: ProfileRequest,
    operation_id: String,
    ticket: String,
) -> Result<Option<RegistrationView>, String> {
    let operation_id = operation(&operation_id)?;
    let run = context.owner.register_operation(ticket)?;
    tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt as _;
        let path =
            app.dialog().file().set_file_name("scoplen-recovery-key.txt").blocking_save_file();
        let Some(path) = path else {
            return Ok(None);
        };
        run.check()?;
        let path = path.into_path().map_err(|_| "recoverySave")?;
        let local = context.get().map_err(|_| "profileChanged")?;
        let store = context.store().ok_or("profileChanged")?;
        app.state::<PersonalServer>()
            .save_registration_recovery(&local, &store, operation_id, &path)
            .map(|status| Some(status.into()))
            .map_err(failure)
    })
    .await
    .map_err(|_| "recoverySave")?
}

/// Record explicit safe-storage confirmation for the original recovery key.
#[tauri::command]
#[specta::specta]
pub async fn confirm_registration_recovery(
    app: tauri::AppHandle,
    context: ProfileRequest,
    operation_id: String,
) -> Result<RegistrationView, String> {
    let operation_id = operation(&operation_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let local = context.get().map_err(|_| "profileChanged")?;
        let store = context.store().ok_or("profileChanged")?;
        app.state::<PersonalServer>()
            .confirm_registration_recovery(&local, &store, operation_id)
            .map(Into::into)
            .map_err(failure)
    })
    .await
    .map_err(|_| "storage")?
}

#[derive(Clone, Copy, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
/// Explicit mutation or exact-result recovery intent shared by account entry flows.
pub enum RegistrationIntent {
    /// First handoff of the original signed business request.
    Submit,
    /// Recover the exact original receipt without mutation.
    Confirm,
    /// Explicitly retry only after a trusted unchanged result.
    Retry,
}

/// Submit, exactly confirm, or explicitly retry the captured original registration.
#[tauri::command]
#[specta::specta]
pub async fn exchange_account_registration(
    app: tauri::AppHandle,
    context: ProfileRequest,
    ticket: String,
    operation_id: String,
    intent: RegistrationIntent,
) -> Result<RegistrationView, String> {
    let run = context.owner.register_operation(ticket)?;
    let local = context.get().map_err(|_| "profileChanged")?;
    let store = context.store().ok_or("profileChanged")?;
    let action = match intent {
        RegistrationIntent::Submit => RegistrationAction::Submit,
        RegistrationIntent::Confirm => RegistrationAction::Confirm,
        RegistrationIntent::Retry => RegistrationAction::Retry,
    };
    app.state::<PersonalServer>()
        .exchange_registration(&local, store, operation(&operation_id)?, action, &run.cancellation)
        .await
        .map(Into::into)
        .map_err(failure)
}

/// Stops only the captured exchange; it never discards a possibly committed registration.
#[tauri::command]
#[specta::specta]
pub fn stop_account_operation(profiles: tauri::State<'_, Arc<NativeProfiles>>, ticket: String) {
    profiles.cancel_operation(Some(&ticket));
}

/// Discard only a safe, never-dispatched registration preparation.
#[tauri::command]
#[specta::specta]
pub async fn discard_registration_preparation(
    app: tauri::AppHandle,
    context: ProfileRequest,
    operation_id: String,
) -> Result<(), String> {
    let operation_id = operation(&operation_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let local = context.get().map_err(|_| "profileChanged")?;
        let store = context.store().ok_or("profileChanged")?;
        app.state::<PersonalServer>()
            .cancel_registration(&local, &store, operation_id)
            .map_err(failure)
    })
    .await
    .map_err(|_| "storage")?
}

pub(crate) async fn drain(
    app: &tauri::AppHandle,
    profiles: Arc<NativeProfiles>,
) -> Result<(), String> {
    app.state::<crate::ssh::SessionManager>().close_all()?;
    app.state::<crate::forwards::ForwardManager>()
        .stop_all()
        .await
        .map_err(|_| "tunnelShutdown")?;
    tauri::async_runtime::spawn_blocking(move || profiles.wait_drained())
        .await
        .map_err(|_| "profileUnavailable")?
}

/// Close running native work, then explicitly open Local or a ready Account.
#[tauri::command]
#[specta::specta]
pub async fn select_account_profile(
    app: tauri::AppHandle,
    profiles: tauri::State<'_, Arc<NativeProfiles>>,
    generation: String,
    profile_id: Option<String>,
    local_passphrase: Option<String>,
) -> Result<ProfileSnapshot, String> {
    let local_passphrase = local_passphrase.map(|value| SecretVec::new(value.into_bytes()));
    let switch = profiles.begin_switch(&app, &generation, None)?;
    drain(&app, profiles.inner().clone()).await?;
    tauri::async_runtime::spawn_blocking(move || {
        if let Some(id) = profile_id {
            switch.catalog.open(operation(&id)?, local_passphrase).map_err(|_| "profileUnlock")?;
        } else {
            switch.catalog.open_local().map_err(|_| "profileUnavailable")?;
        }
        drop(switch);
        app.state::<Arc<NativeProfiles>>().publish(&app)
    })
    .await
    .map_err(|_| "profileUnavailable")?
}

/// Install a confirmed registration only after fresh current Device verification.
#[tauri::command]
#[specta::specta]
pub async fn install_registered_profile(
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
    let lease = switch.catalog.current().map_err(|_| "profileChanged")?;
    app.state::<PersonalServer>()
        .install_registration_profile(
            &switch.catalog,
            &lease,
            operation(&operation_id)?,
            local_passphrase,
            &run.cancellation,
        )
        .await
        .map_err(|error| match error {
            scoplen_client_core::profiles::AccountProfileError::PassphraseRequired => {
                "passphraseRequired"
            }
            scoplen_client_core::profiles::AccountProfileError::Locked => "profileUnlock",
            scoplen_client_core::profiles::AccountProfileError::Cancelled => "cancelled",
            scoplen_client_core::profiles::AccountProfileError::ContextChanged => "profileChanged",
            scoplen_client_core::profiles::AccountProfileError::Busy => "busy",
            _ => "installation",
        })?;
    drop(switch);
    profiles.publish(&app)
}
