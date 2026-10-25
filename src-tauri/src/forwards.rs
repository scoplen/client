// SPDX-License-Identifier: Apache-2.0

//! Independent tunnel intents. Losing an event observer never closes a run.

use crate::{local_data::LocalDataState, ssh::SessionPreparationIntent};
use scoplen_client_core::forward_manager::{ForwardIssue, ForwardSnapshot};
use serde::Serialize;
use specta::Type;
use tauri_specta::Event as _;

pub use scoplen_client_core::forward_manager::ForwardManager;

/// A display-safe snapshot of one Rust-owned run.
#[derive(Clone, Debug, Serialize, Type, tauri_specta::Event)]
#[serde(rename_all = "camelCase")]
pub struct ForwardChanged {
    /// The latest revision of the independent run.
    pub snapshot: ForwardSnapshot,
}

/// Start a saved tunnel using the explicitly selected Login.
#[tauri::command]
#[specta::specta]
pub async fn forward_start(
    app: tauri::AppHandle,
    local: tauri::State<'_, LocalDataState>,
    manager: tauri::State<'_, ForwardManager>,
    forward_id: String,
    profile_id: String,
) -> Result<ForwardSnapshot, ForwardIssue> {
    local
        .with_store(|store| {
            manager.start(store.clone(), &forward_id, &profile_id, move |snapshot| {
                let _ = ForwardChanged { snapshot }.emit(&app);
            })
        })
        .unwrap_or(Err(ForwardIssue::Unavailable))
}

/// List the current store's live runs and retained terminal snapshots.
#[tauri::command]
#[specta::specta]
pub async fn forward_list(
    local: tauri::State<'_, LocalDataState>,
    manager: tauri::State<'_, ForwardManager>,
) -> Result<Vec<ForwardSnapshot>, ForwardIssue> {
    local.with_store(|store| manager.list(store)).unwrap_or(Err(ForwardIssue::Unavailable))
}

/// Read a run without changing its lifetime.
#[tauri::command]
#[specta::specta]
pub async fn forward_snapshot(
    local: tauri::State<'_, LocalDataState>,
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
    local: tauri::State<'_, LocalDataState>,
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

/// Fence new accepts immediately and begin cancelling one independent run.
#[tauri::command]
#[specta::specta]
pub async fn forward_stop(
    local: tauri::State<'_, LocalDataState>,
    manager: tauri::State<'_, ForwardManager>,
    run_id: String,
) -> Result<(), ForwardIssue> {
    local.with_store(|store| manager.stop(store, &run_id)).unwrap_or(Err(ForwardIssue::Unavailable))
}
