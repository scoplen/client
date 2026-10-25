// SPDX-License-Identifier: Apache-2.0
//! Thin adapters for the Rust-owned Personal inventory review and sync workflow.

use crate::profile_context::ProfileRequest as LocalDataState;
use scoplen_client_core::{
    personal_inventory::{
        PersonalInventoryError, PersonalInventoryHistory, PersonalInventoryPreview,
        PersonalInventoryResult, PersonalInventorySettings, PersonalInventoryStatus,
    },
    personal_server::PersonalServer,
    store::Store,
};
use std::sync::Arc;
use tauri::Manager as _;

fn store(local: &LocalDataState) -> Result<Arc<Store>, PersonalInventoryError> {
    local.store().ok_or(PersonalInventoryError::Storage)
}

/// Query complete verified history without exposing object fields or envelopes.
#[tauri::command]
#[specta::specta]
pub async fn query_personal_inventory_history(
    local: LocalDataState,
    personal: tauri::State<'_, PersonalServer>,
    settings: tauri::State<'_, Arc<PersonalInventorySettings>>,
    object_id: String,
) -> Result<PersonalInventoryHistory, PersonalInventoryError> {
    settings.query_history(&personal, store(&local)?, object_id).await
}

/// Restore one reviewed version as a fresh local copy; no server write is sent.
#[tauri::command]
#[specta::specta]
pub async fn restore_personal_inventory_history(
    app: tauri::AppHandle,
    local: LocalDataState,
    settings: tauri::State<'_, Arc<PersonalInventorySettings>>,
    review_token: String,
    sequence: String,
) -> Result<(), PersonalInventoryError> {
    let store = store(&local)?;
    let settings = settings.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        settings.restore_history(&app.state::<PersonalServer>(), store, review_token, sequence)
    })
    .await
    .map_err(|_| PersonalInventoryError::Storage)?
}

/// Read public inventory metadata and durable sync progress without network access.
#[tauri::command]
#[specta::specta]
pub async fn personal_inventory_status(
    local: LocalDataState,
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
    local: LocalDataState,
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
    local: LocalDataState,
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
    local: LocalDataState,
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

/// Restore explicit copies of edits quarantined by a complete server reconciliation.
#[tauri::command]
#[specta::specta]
pub async fn restore_personal_inventory_recovery(
    app: tauri::AppHandle,
    local: LocalDataState,
    settings: tauri::State<'_, Arc<PersonalInventorySettings>>,
    ids: Vec<String>,
) -> Result<u32, PersonalInventoryError> {
    let store = store(&local)?;
    let settings = settings.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        settings.restore_recovery(&app.state::<PersonalServer>(), &store, ids)
    })
    .await
    .map_err(|_| PersonalInventoryError::Storage)?
}
