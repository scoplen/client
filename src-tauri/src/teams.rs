// SPDX-License-Identifier: Apache-2.0
//! Generation-bound adapters; Rust retains all team requests, sessions and recovery state.

use std::sync::Arc;

use scoplen_client_core::{
    personal_server::{
        PersonalServer, PersonalServerError, TeamCreationView, TeamError, TeamPageView,
    },
    store::Store,
};
use tauri::Manager as _;

use crate::profile_context::ProfileRequest;

fn store(context: &ProfileRequest) -> Result<Arc<Store>, TeamError> {
    context.store().ok_or_else(|| PersonalServerError::Storage.into())
}

/// Read one current membership page only after the user requests it.
#[tauri::command]
#[specta::specta]
pub async fn teams_page(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    cursor: Option<String>,
) -> Result<TeamPageView, TeamError> {
    personal.teams_page(store(&context)?, cursor.as_deref()).await
}

/// Read local pending state without contacting the server.
#[tauri::command]
#[specta::specta]
pub async fn pending_team_creation(
    app: tauri::AppHandle,
    context: ProfileRequest,
) -> Result<Option<TeamCreationView>, TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<PersonalServer>().pending_team_creation(&store)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Persist a new canonical creation; no network operation occurs here.
#[tauri::command]
#[specta::specta]
pub async fn prepare_team_creation(
    app: tauri::AppHandle,
    context: ProfileRequest,
    name: String,
) -> Result<TeamCreationView, TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<PersonalServer>().prepare_team_creation(&store, name)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Dispatch or explicitly retry only this Account's retained original creation.
#[tauri::command]
#[specta::specta]
pub async fn submit_team_creation(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    operation_id: String,
) -> Result<TeamCreationView, TeamError> {
    personal.submit_team_creation(store(&context)?, &operation_id).await
}

/// Clear only a prepared, confirmed or explicitly reviewed expired operation.
#[tauri::command]
#[specta::specta]
pub async fn discard_team_creation(
    app: tauri::AppHandle,
    context: ProfileRequest,
    operation_id: String,
) -> Result<(), TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<PersonalServer>().discard_team_creation(&store, &operation_id)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}
