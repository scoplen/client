// SPDX-License-Identifier: Apache-2.0
//! Thin native adapters for the Rust-owned Personal enrollment workflow.

use std::sync::Arc;

use scoplen_client_core::{
    personal_server::{PersonalServer, PersonalServerError, PersonalServerStatus},
    store::Store,
};
use tauri_plugin_dialog::DialogExt as _;
use zeroize::Zeroizing;

use crate::local_data::LocalDataState;

fn store(local: &LocalDataState) -> Result<Arc<Store>, PersonalServerError> {
    local.store().ok_or(PersonalServerError::Storage)
}

/// Return public Personal server metadata without opening a network connection.
#[tauri::command]
#[specta::specta]
pub async fn personal_server_status(
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PersonalServerStatus, PersonalServerError> {
    let store = store(&local)?;
    personal.status(&store)
}

/// Persist the invitation's generated identity locally before any network request.
#[tauri::command]
#[specta::specta]
pub async fn prepare_personal_enrollment(
    invitation_url: String,
    device_name: String,
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PersonalServerStatus, PersonalServerError> {
    let invitation_url = Zeroizing::new(invitation_url);
    personal.prepare(store(&local)?, invitation_url, device_name).await
}

/// Save the recovery key directly from Rust through a native file picker.
#[tauri::command]
#[specta::specta]
pub async fn save_personal_recovery_key(
    app: tauri::AppHandle,
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PersonalServerStatus, PersonalServerError> {
    let store = store(&local)?;
    let path = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_title("Save your Scoplen recovery key")
            .set_file_name("scoplen-recovery-key.txt")
            .add_filter("Recovery key", &["txt"])
            .blocking_save_file()
    })
    .await
    .map_err(|_| PersonalServerError::RecoverySave)?;
    let Some(path) = path else {
        return personal.status(&store);
    };
    let path = path.into_path().map_err(|_| PersonalServerError::RecoverySave)?;
    personal.save_recovery_key(store, path).await
}

/// Confirm that the recovery key has been saved safely before invitation redemption.
#[tauri::command]
#[specta::specta]
pub async fn confirm_personal_recovery_key(
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PersonalServerStatus, PersonalServerError> {
    personal.confirm_recovery_key(store(&local)?).await
}

/// Redeem the invitation at most once and confirm the retained device identity.
#[tauri::command]
#[specta::specta]
pub async fn submit_personal_enrollment(
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PersonalServerStatus, PersonalServerError> {
    personal.submit(store(&local)?).await
}

/// Retry fresh device authentication without replaying invitation redemption.
#[tauri::command]
#[specta::specta]
pub async fn authenticate_personal_server(
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PersonalServerStatus, PersonalServerError> {
    personal.authenticate(store(&local)?).await
}

/// Import a same-origin invitation after fresh authentication, retaining the existing identity.
#[tauri::command]
#[specta::specta]
pub async fn update_personal_invitation(
    invitation_url: String,
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PersonalServerStatus, PersonalServerError> {
    let invitation_url = Zeroizing::new(invitation_url);
    personal.update_invitation(store(&local)?, invitation_url).await
}
