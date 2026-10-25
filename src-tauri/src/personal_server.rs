// SPDX-License-Identifier: Apache-2.0
//! Thin native adapters for retained admitted-device access.

use std::sync::Arc;

use scoplen_client_core::{
    personal_server::{
        PersonalAccountSnapshot, PersonalServer, PersonalServerError, PersonalServerStatus,
        PersonalSyncError,
    },
    store::Store,
};
use serde::Serialize;
use specta::Type;
use tauri::Manager as _;

use crate::local_data::LocalDataState;

/// Read the native background owner's state without activating network activity.
#[tauri::command]
#[specta::specta]
pub fn personal_sync_background_status(
    runtime: tauri::State<'_, Arc<scoplen_client_core::personal_server::PersonalSyncRuntime>>,
) -> scoplen_client_core::personal_server::PersonalBackgroundStatus {
    runtime.status()
}

fn store(local: &LocalDataState) -> Result<Arc<Store>, PersonalServerError> {
    local.store().ok_or(PersonalServerError::Storage)
}

/// Read and locally reverify the last complete manual account query, without network I/O.
#[tauri::command]
#[specta::specta]
pub async fn personal_account_snapshot(
    app: tauri::AppHandle,
    local: tauri::State<'_, LocalDataState>,
) -> Result<Option<PersonalAccountSnapshot>, PersonalServerError> {
    let store = store(&local)?;
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<PersonalServer>().account_snapshot(&store)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Explicitly query the account and complete signed device set; never mutates device membership.
#[tauri::command]
#[specta::specta]
pub async fn query_personal_account(
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PersonalAccountSnapshot, PersonalServerError> {
    personal.query_account(store(&local)?).await
}

/// Locally reverified key availability; never contains wrapped or unwrapped key material.
#[derive(Clone, Copy, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum PersonalSyncKeyStatus {
    /// No verified bootstrap has been saved on this device.
    NotConnected,
    /// The saved account, device and vault keys passed local cryptographic verification.
    Verified,
}

/// Sync-specific failures contain no server body or key material.
#[derive(Clone, Copy, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum PersonalSyncFailure {
    /// Renew device authentication before requesting sync keys.
    AuthenticationRequired,
    /// Server artifacts did not match the retained identity or key material.
    InvalidSyncResponse,
    /// This client cannot yet accept rotated account or vault keys.
    RotationRequired,
}

/// Reuses the safe account failures and adds actionable sync failures.
#[derive(Clone, Copy, Debug, Serialize, Type)]
#[serde(untagged)]
pub enum PersonalSyncCommandError {
    /// Existing redacted account or local-store failure.
    Personal(PersonalServerError),
    /// A failure specific to verifying sync keys.
    Sync(PersonalSyncFailure),
}

impl From<PersonalSyncError> for PersonalSyncCommandError {
    fn from(error: PersonalSyncError) -> Self {
        match error {
            PersonalSyncError::Personal(error) => Self::Personal(error),
            PersonalSyncError::AuthenticationRequired => {
                Self::Sync(PersonalSyncFailure::AuthenticationRequired)
            }
            PersonalSyncError::RotationRequired => {
                Self::Sync(PersonalSyncFailure::RotationRequired)
            }
            _ => Self::Sync(PersonalSyncFailure::InvalidSyncResponse),
        }
    }
}

/// Revalidate saved Personal sync keys locally without making a server request.
#[tauri::command]
#[specta::specta]
pub async fn personal_sync_key_status(
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PersonalSyncKeyStatus, PersonalSyncCommandError> {
    let store = store(&local).map_err(PersonalSyncCommandError::Personal)?;
    Ok(if personal.load_sync_bootstrap(&store)?.is_some() {
        PersonalSyncKeyStatus::Verified
    } else {
        PersonalSyncKeyStatus::NotConnected
    })
}

/// Verify and save the retained account's sync keys without uploading local inventory.
#[tauri::command]
#[specta::specta]
pub async fn connect_personal_sync(
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PersonalSyncKeyStatus, PersonalSyncCommandError> {
    let store = store(&local).map_err(PersonalSyncCommandError::Personal)?;
    personal.bootstrap_sync(store).await?;
    Ok(PersonalSyncKeyStatus::Verified)
}

/// Return public Personal server metadata without opening a network connection.
#[tauri::command]
#[specta::specta]
pub async fn personal_server_status(
    app: tauri::AppHandle,
    local: tauri::State<'_, LocalDataState>,
) -> Result<PersonalServerStatus, PersonalServerError> {
    let store = store(&local)?;
    tauri::async_runtime::spawn_blocking(move || app.state::<PersonalServer>().status(&store))
        .await
        .map_err(|_| PersonalServerError::Storage)?
}

/// Authenticate the current confirmed profile with its retained device key.
#[tauri::command]
#[specta::specta]
pub async fn authenticate_personal_server(
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PersonalServerStatus, PersonalServerError> {
    personal.authenticate(store(&local)?).await
}
