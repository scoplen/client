// SPDX-License-Identifier: Apache-2.0

//! Generation-bound, local-only terminal appearance intents.

use crate::profile_context::ProfileRequest;
use scoplen_client_core::store::Store;
use scoplen_client_core::store::terminal_profiles::{
    TerminalProfileDirectory, TerminalProfileIssue, TerminalProfileSettings,
};

async fn operation(
    local: ProfileRequest,
    action: impl FnOnce(&Store) -> Result<TerminalProfileDirectory, TerminalProfileIssue>
    + Send
    + 'static,
) -> Result<TerminalProfileDirectory, TerminalProfileIssue> {
    tauri::async_runtime::spawn_blocking(move || {
        local.with_store(|store| action(store)).unwrap_or(Err(TerminalProfileIssue::Unavailable))
    })
    .await
    .map_err(|_| TerminalProfileIssue::Storage)?
}

/// Read the captured Store's appearance directory without network access.
#[tauri::command]
#[specta::specta]
pub async fn terminal_profiles_list(
    local: ProfileRequest,
) -> Result<TerminalProfileDirectory, TerminalProfileIssue> {
    operation(local, Store::terminal_profiles).await
}

/// Create an exact name from the current Default.
#[tauri::command]
#[specta::specta]
pub async fn terminal_profiles_create(
    local: ProfileRequest,
    name: String,
) -> Result<TerminalProfileDirectory, TerminalProfileIssue> {
    operation(local, move |store| store.create_terminal_profile(&name)).await
}

/// Save the separate Default or an existing exact named entry.
#[tauri::command]
#[specta::specta]
pub async fn terminal_profiles_save(
    local: ProfileRequest,
    name: Option<String>,
    settings: TerminalProfileSettings,
) -> Result<TerminalProfileDirectory, TerminalProfileIssue> {
    operation(local, move |store| store.save_terminal_profile(name.as_deref(), &settings)).await
}

/// Reset Default to the shipped settings, leaving all named entries intact.
#[tauri::command]
#[specta::specta]
pub async fn terminal_profiles_reset_default(
    local: ProfileRequest,
) -> Result<TerminalProfileDirectory, TerminalProfileIssue> {
    operation(local, |store| store.save_terminal_profile(None, &TerminalProfileSettings::default()))
        .await
}

/// Delete a local entry without modifying any Login reference.
#[tauri::command]
#[specta::specta]
pub async fn terminal_profiles_delete(
    local: ProfileRequest,
    name: String,
) -> Result<TerminalProfileDirectory, TerminalProfileIssue> {
    operation(local, move |store| store.delete_terminal_profile(&name)).await
}
