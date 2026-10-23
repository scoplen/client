// SPDX-License-Identifier: Apache-2.0
//! Thin adapters for the Rust-owned Personal inventory review and sync workflow.

use crate::local_data::LocalDataState;
use scoplen_client_core::{
    personal_inventory::{
        PersonalInventoryError, PersonalInventoryPreview, PersonalInventoryResult,
        PersonalInventorySettings, PersonalInventoryStatus,
    },
    personal_server::PersonalServer,
    store::Store,
};
use std::sync::Arc;
use tauri::Manager as _;

fn store(local: &LocalDataState) -> Result<Arc<Store>, PersonalInventoryError> {
    local.store().ok_or(PersonalInventoryError::Storage)
}

/// Read public inventory metadata and durable sync progress without network access.
#[tauri::command]
#[specta::specta]
pub async fn personal_inventory_status(
    local: tauri::State<'_, LocalDataState>,
    settings: tauri::State<'_, Arc<PersonalInventorySettings>>,
) -> Result<PersonalInventoryStatus, PersonalInventoryError> {
    let store = store(&local)?;
    let settings = settings.inner().clone();
    tauri::async_runtime::spawn_blocking(move || settings.status(&store))
        .await
        .map_err(|_| PersonalInventoryError::Storage)?
}

/// Preview exact ids and missing references; keys and object content remain in Rust.
#[tauri::command]
#[specta::specta]
pub async fn preview_personal_inventory(
    local: tauri::State<'_, LocalDataState>,
    settings: tauri::State<'_, Arc<PersonalInventorySettings>>,
    ids: Vec<String>,
) -> Result<PersonalInventoryPreview, PersonalInventoryError> {
    let store = store(&local)?;
    let settings = settings.inner().clone();
    tauri::async_runtime::spawn_blocking(move || settings.preview(&store, ids))
        .await
        .map_err(|_| PersonalInventoryError::Storage)?
}

/// Synchronize existing Personal objects, optionally consuming one explicitly confirmed review.
#[tauri::command]
#[specta::specta]
pub async fn synchronize_personal_inventory(
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
    settings: tauri::State<'_, Arc<PersonalInventorySettings>>,
    review_token: Option<String>,
) -> Result<PersonalInventoryResult, PersonalInventoryError> {
    settings.synchronize(&personal, store(&local)?, review_token).await
}

/// Restore immutable adoption copies as new local objects without changing the server.
#[tauri::command]
#[specta::specta]
pub async fn restore_personal_inventory(
    app: tauri::AppHandle,
    local: tauri::State<'_, LocalDataState>,
    settings: tauri::State<'_, Arc<PersonalInventorySettings>>,
    ids: Vec<String>,
) -> Result<u32, PersonalInventoryError> {
    let store = store(&local)?;
    let settings = settings.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        settings.restore(&app.state::<PersonalServer>(), &store, ids)
    })
    .await
    .map_err(|_| PersonalInventoryError::Storage)?
}
