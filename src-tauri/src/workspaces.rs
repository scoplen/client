// SPDX-License-Identifier: Apache-2.0

//! Profile-bound saved terminal/tunnel intents. Validation never opens a connection.

use crate::profile_context::ProfileRequest;
use scoplen_client_core::workspaces::{
    OpenedWorkspace, WorkspaceInput, WorkspaceIssue, WorkspaceView, Workspaces,
};

async fn operation<T: Send + 'static>(
    local: ProfileRequest,
    action: impl FnOnce(Workspaces) -> Result<T, WorkspaceIssue> + Send + 'static,
) -> Result<T, WorkspaceIssue> {
    tauri::async_runtime::spawn_blocking(move || {
        local
            .with_store(|store| action(Workspaces::new(store.clone())))
            .unwrap_or(Err(WorkspaceIssue::Unavailable))
    })
    .await
    .map_err(|_| WorkspaceIssue::Storage)?
}

/// List complete saved definitions and fixed unavailable reasons.
#[tauri::command]
#[specta::specta]
pub async fn workspaces_list(local: ProfileRequest) -> Result<Vec<WorkspaceView>, WorkspaceIssue> {
    operation(local, |workspaces| workspaces.list()).await
}

/// Save complete terminal trees and explicitly selected saved tunnels as a local object.
#[tauri::command]
#[specta::specta]
pub async fn workspaces_create(
    local: ProfileRequest,
    input: WorkspaceInput,
) -> Result<WorkspaceView, WorkspaceIssue> {
    operation(local, move |workspaces| workspaces.create(input)).await
}

/// Preflight all slots, then project fresh terminal trees and ordered saved-tunnel starts.
#[tauri::command]
#[specta::specta]
pub async fn workspaces_open(
    local: ProfileRequest,
    id: String,
) -> Result<OpenedWorkspace, WorkspaceIssue> {
    operation(local, move |workspaces| workspaces.open(&id)).await
}

/// Tombstone a selected definition, including unsupported retained definitions.
#[tauri::command]
#[specta::specta]
pub async fn workspaces_delete(local: ProfileRequest, id: String) -> Result<(), WorkspaceIssue> {
    operation(local, move |workspaces| workspaces.delete(&id)).await
}
