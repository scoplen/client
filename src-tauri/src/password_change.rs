// SPDX-License-Identifier: Apache-2.0
//! Thin Settings intents for the original Account's credential replacement.

use crate::{
    account_registration::{RegistrationIntent, operation},
    profile_context::ProfileRequest,
};
use scoplen_client_core::personal_server::{
    PasswordChangeError, PasswordChangePhase, PasswordChangeStatus, PersonalServer,
    RegistrationAction,
};
use scoplen_crypto::SecretVec;
use serde::Serialize;
use specta::Type;
use tauri::Manager as _;

/// Explicit next action, independent of the current native access session.
#[derive(Clone, Copy, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum PasswordChangeStep {
    /// Verified bytes are ready for explicit Submit.
    Ready,
    /// Only fresh exact confirmation is available.
    OutcomeUnknown,
    /// A trusted unchanged result permits explicit Retry or discard.
    RetryAvailable,
    /// Discard unchanged work before verifying the current password again.
    SignInRequired,
    /// Historical success; it establishes no current authority.
    Committed,
}
/// Safe password-change metadata, without protected payloads or credentials.
#[derive(Clone, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChangeView {
    /// Safe next action for this original operation.
    pub phase: PasswordChangeStep,
    /// Stable operation identity.
    pub operation_id: String,
    /// Bounded retry deadline as decimal Unix milliseconds.
    pub retry_not_before_ms: Option<String>,
}
impl From<PasswordChangeStatus> for PasswordChangeView {
    fn from(value: PasswordChangeStatus) -> Self {
        Self {
            phase: match value.phase {
                PasswordChangePhase::Ready => PasswordChangeStep::Ready,
                PasswordChangePhase::OutcomeUnknown => PasswordChangeStep::OutcomeUnknown,
                PasswordChangePhase::RetryAvailable => PasswordChangeStep::RetryAvailable,
                PasswordChangePhase::SignInRequired => PasswordChangeStep::SignInRequired,
                PasswordChangePhase::Committed => PasswordChangeStep::Committed,
            },
            operation_id: value.operation_id.to_string(),
            retry_not_before_ms: value.retry_not_before_ms.map(|v| v.to_string()),
        }
    }
}
fn failure(error: PasswordChangeError) -> String {
    use PasswordChangeError::*;
    match error {
        Busy => "busy",
        ContextChanged => "profileChanged",
        InvalidInput => "invalidInput",
        SamePassword => "samePassword",
        Verification => "verification",
        Storage => "storage",
        NotPrepared => "notPrepared",
        OutcomeUnknown => "outcomeUnknown",
        SignInRequired => "signInRequired",
        ExplicitRetryRequired | RetryUnavailable => "explicitRetryRequired",
        RetryDeferred => "retryDeferred",
        Cancelled => "cancelled",
        Network => "network",
        UnsupportedService => "unsupportedService",
        AuthenticationDenied => "authenticationDenied",
        PolicyDenied => "policyDenied",
        ServiceUnavailable => "serviceUnavailable",
    }
    .into()
}

/// Inspect durable state without requesting options, password derivation or a session.
#[tauri::command]
#[specta::specta]
pub async fn password_change_status(
    app: tauri::AppHandle,
    context: ProfileRequest,
) -> Result<Option<PasswordChangeView>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let (profiles, source) = context.account_context()?;
        app.state::<PersonalServer>()
            .password_change_status(profiles, source)
            .map(|s| s.map(Into::into))
            .map_err(failure)
    })
    .await
    .map_err(|_| "storage")?
}
/// Verify the current password and save one original replacement in the Account store.
#[tauri::command]
#[specta::specta]
pub async fn begin_password_change(
    app: tauri::AppHandle,
    context: ProfileRequest,
    ticket: String,
    old_password: String,
    new_password: String,
) -> Result<PasswordChangeView, String> {
    let old_password = SecretVec::new(old_password.into_bytes());
    let new_password = SecretVec::new(new_password.into_bytes());
    let run = context.owner.register_operation(ticket)?;
    let (profiles, source) = context.account_context()?;
    app.state::<PersonalServer>()
        .begin_password_change(profiles, source, old_password, new_password, &run.cancellation)
        .await
        .map(Into::into)
        .map_err(failure)
}
/// Submit, confirm or explicitly retry only the saved original operation.
#[tauri::command]
#[specta::specta]
pub async fn exchange_password_change(
    app: tauri::AppHandle,
    context: ProfileRequest,
    ticket: String,
    operation_id: String,
    intent: RegistrationIntent,
) -> Result<PasswordChangeView, String> {
    let run = context.owner.register_operation(ticket)?;
    let (profiles, source) = context.account_context()?;
    let action = match intent {
        RegistrationIntent::Submit => RegistrationAction::Submit,
        RegistrationIntent::Confirm => RegistrationAction::Confirm,
        RegistrationIntent::Retry => RegistrationAction::Retry,
    };
    app.state::<PersonalServer>()
        .exchange_password_change(
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
/// Discard only never-sent/known-unchanged data, or acknowledge verified historical success.
#[tauri::command]
#[specta::specta]
pub async fn discard_password_change(
    app: tauri::AppHandle,
    context: ProfileRequest,
    operation_id: String,
) -> Result<(), String> {
    let operation_id = operation(&operation_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let (profiles, source) = context.account_context()?;
        app.state::<PersonalServer>()
            .discard_password_change(profiles, source, operation_id)
            .map_err(failure)
    })
    .await
    .map_err(|_| "storage")?
}
