// SPDX-License-Identifier: Apache-2.0
//! Account-generation-bound team SSH setup; private signing material never crosses IPC.

use std::sync::Arc;

use scoplen_client_core::{
    personal_server::{
        PersonalServer, PersonalServerError, TeamSshError, TeamSshOperationKind,
        TeamSshOperationView, TeamSshSource, TeamUserCaView,
    },
    store::Store,
};
use tauri::Manager as _;

use crate::profile_context::ProfileRequest;

fn store(context: &ProfileRequest) -> Result<Arc<Store>, TeamSshError> {
    context.store().ok_or_else(|| PersonalServerError::Storage.into())
}

/// Read safe local recovery state without starting or retrying a server request.
#[tauri::command]
#[specta::specta]
pub async fn team_ssh_operations(
    app: tauri::AppHandle,
    context: ProfileRequest,
    source: TeamSshSource,
) -> Result<Vec<TeamSshOperationView>, TeamSshError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<PersonalServer>().team_ssh_operations(&store, &source)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Fetch only this team's current authenticated public user CA.
#[tauri::command]
#[specta::specta]
pub async fn team_user_ca(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    source: TeamSshSource,
) -> Result<Option<TeamUserCaView>, TeamSshError> {
    personal.team_user_ca(store(&context)?, &source).await
}

/// Persist the original setup operation before the administrator submits it.
#[tauri::command]
#[specta::specta]
pub async fn prepare_team_user_ca(
    app: tauri::AppHandle,
    context: ProfileRequest,
    source: TeamSshSource,
) -> Result<TeamSshOperationView, TeamSshError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<PersonalServer>().prepare_team_user_ca(&store, &source)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Explicitly confirm the original key/body, never silently minting a replacement request.
#[tauri::command]
#[specta::specta]
pub async fn confirm_team_ssh_operation(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    source: TeamSshSource,
    kind: TeamSshOperationKind,
    operation_id: String,
) -> Result<TeamSshOperationView, TeamSshError> {
    personal.confirm_team_ssh_operation(store(&context)?, &source, kind, &operation_id).await
}

/// Clear known setup state or explicitly archive an expired unknown operation.
#[tauri::command]
#[specta::specta]
pub async fn discard_team_ssh_operation(
    app: tauri::AppHandle,
    context: ProfileRequest,
    source: TeamSshSource,
    kind: TeamSshOperationKind,
    operation_id: String,
) -> Result<(), TeamSshError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<PersonalServer>().discard_team_ssh_operation(
            &store,
            &source,
            kind,
            &operation_id,
        )
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}
