// SPDX-License-Identifier: Apache-2.0

//! Independent and terminal-attached tunnel intents.

use crate::{profile_context::ProfileRequest as LocalDataState, ssh::SessionPreparationIntent};
use scoplen_client_core::forward_manager::{
    ForwardIssue, ForwardSnapshot, ForwardStartIntent, SessionForwardSnapshot,
};
use serde::Serialize;
use specta::Type;
use tauri_specta::Event as _;

pub use scoplen_client_core::forward_manager::ForwardManager;

/// A display-safe snapshot of one Rust-owned run.
#[derive(Clone, Debug, Serialize, Type, tauri_specta::Event)]
#[serde(rename_all = "camelCase")]
pub struct ForwardChanged {
    /// Source profile opening.
    pub profile_generation: String,
    /// The latest revision of the registered run.
    pub snapshot: ForwardSnapshot,
}

/// Start a saved or temporary tunnel using the explicitly selected Login.
#[tauri::command]
#[specta::specta]
pub async fn forward_start(
    app: tauri::AppHandle,
    local: LocalDataState,
    manager: tauri::State<'_, ForwardManager>,
    intent: ForwardStartIntent,
) -> Result<ForwardSnapshot, ForwardIssue> {
    let profile_generation = local.generation();
    local
        .with_store(|store| {
            manager.start(store.clone(), intent, move |snapshot| {
                let _ = ForwardChanged { profile_generation: profile_generation.clone(), snapshot }
                    .emit(&app);
            })
        })
        .unwrap_or(Err(ForwardIssue::Unavailable))
}

/// List the current store's live runs and retained terminal snapshots.
#[tauri::command]
#[specta::specta]
pub async fn forward_list(
    local: LocalDataState,
    manager: tauri::State<'_, ForwardManager>,
) -> Result<Vec<ForwardSnapshot>, ForwardIssue> {
    local.with_store(|store| manager.list(store)).unwrap_or(Err(ForwardIssue::Unavailable))
}

/// Read a run without changing its lifetime.
#[tauri::command]
#[specta::specta]
pub async fn forward_snapshot(
    local: LocalDataState,
    manager: tauri::State<'_, ForwardManager>,
    run_id: String,
) -> Result<ForwardSnapshot, ForwardIssue> {
    local
        .with_store(|store| manager.snapshot(store, &run_id))
        .unwrap_or(Err(ForwardIssue::Unavailable))
}

/// Answer the current SSH preparation challenge for one independent run.
#[tauri::command]
#[specta::specta]
pub async fn forward_respond(
    local: LocalDataState,
    manager: tauri::State<'_, ForwardManager>,
    run_id: String,
    prompt_id: String,
    intent: SessionPreparationIntent,
) -> Result<(), ForwardIssue> {
    let response = intent.into_response().map_err(|_| ForwardIssue::InvalidConfiguration)?;
    local
        .with_store(|store| manager.respond(store, &run_id, &prompt_id, response))
        .unwrap_or(Err(ForwardIssue::Unavailable))
}

/// Fence new accepts immediately and begin cancelling one run.
#[tauri::command]
#[specta::specta]
pub async fn forward_stop(
    local: LocalDataState,
    manager: tauri::State<'_, ForwardManager>,
    run_id: String,
) -> Result<(), ForwardIssue> {
    local.with_store(|store| manager.stop(store, &run_id)).unwrap_or(Err(ForwardIssue::Unavailable))
}

/// Read every selected attachment result for the exact current terminal transport.
#[tauri::command]
#[specta::specta]
pub async fn session_forward_list(
    local: LocalDataState,
    manager: tauri::State<'_, crate::ssh::SessionManager>,
    session_id: String,
    transport_id: String,
) -> Result<Vec<SessionForwardSnapshot>, ForwardIssue> {
    local
        .with_store(|store| manager.forward_list(store, &session_id, &transport_id))
        .unwrap_or(Err(ForwardIssue::Expired))
}

/// Suppress one attachment for this logical terminal without closing its SSH connection.
#[tauri::command]
#[specta::specta]
pub async fn session_forward_stop(
    local: LocalDataState,
    manager: tauri::State<'_, crate::ssh::SessionManager>,
    session_id: String,
    transport_id: String,
    forward_id: String,
) -> Result<(), ForwardIssue> {
    local
        .with_store(|store| manager.forward_stop(store, &session_id, &transport_id, &forward_id))
        .unwrap_or(Err(ForwardIssue::Expired))
}
