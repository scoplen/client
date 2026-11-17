// SPDX-License-Identifier: Apache-2.0

//! Profile-bound saved Snippet intents; rendering stays in the Rust core.

use std::collections::BTreeMap;

use crate::profile_context::ProfileRequest;
use scoplen_client_core::snippets::{
    PreparedSnippet, SnippetInput, SnippetIssue, SnippetView, Snippets,
    team::{
        PreparedTeamSnippet, SnippetTerminal, TeamSnippetFence, TeamSnippetLibrary,
        TeamSnippetSendOutcome,
    },
};
use scoplen_client_core::{session_manager::SessionManager, store::Store};
use tauri::Manager as _;

async fn operation<T: Send + 'static>(
    local: ProfileRequest,
    action: impl FnOnce(Snippets) -> Result<T, SnippetIssue> + Send + 'static,
) -> Result<T, SnippetIssue> {
    tauri::async_runtime::spawn_blocking(move || {
        local
            .with_store(|store| action(Snippets::new(store.clone())))
            .unwrap_or(Err(SnippetIssue::Unavailable))
    })
    .await
    .map_err(|_| SnippetIssue::Storage)?
}

/// List retained safe definitions in the captured local store.
#[tauri::command]
#[specta::specta]
pub async fn snippets_list(local: ProfileRequest) -> Result<Vec<SnippetView>, SnippetIssue> {
    operation(local, |snippets| snippets.list()).await
}

/// Save a validated nonsecret definition, without sending terminal input.
#[tauri::command]
#[specta::specta]
pub async fn snippets_create(
    local: ProfileRequest,
    input: SnippetInput,
) -> Result<SnippetView, SnippetIssue> {
    operation(local, move |snippets| snippets.create(input)).await
}

/// Replace the editable fields of one existing nonsecret definition.
#[tauri::command]
#[specta::specta]
pub async fn snippets_update(
    local: ProfileRequest,
    id: String,
    input: SnippetInput,
) -> Result<SnippetView, SnippetIssue> {
    operation(local, move |snippets| snippets.update(&id, input)).await
}

/// Delete an editable definition through its ordinary tombstone.
#[tauri::command]
#[specta::specta]
pub async fn snippets_delete(local: ProfileRequest, id: String) -> Result<(), SnippetIssue> {
    operation(local, move |snippets| snippets.delete(&id)).await
}

/// Produce a bounded exact preview; this command performs no SSH input.
#[tauri::command]
#[specta::specta]
pub async fn snippets_prepare(
    local: ProfileRequest,
    id: String,
    values: BTreeMap<String, String>,
) -> Result<PreparedSnippet, SnippetIssue> {
    operation(local, move |snippets| snippets.prepare(&id, values)).await
}

async fn team_operation<T: Send + 'static>(
    context: ProfileRequest,
    app: tauri::AppHandle,
    action: impl FnOnce(&SessionManager, &Store) -> Result<T, SnippetIssue> + Send + 'static,
) -> Result<T, SnippetIssue> {
    tauri::async_runtime::spawn_blocking(move || {
        context
            .with_store(|store| action(&app.state::<SessionManager>(), store))
            .unwrap_or(Err(SnippetIssue::Unavailable))
    })
    .await
    .map_err(|_| SnippetIssue::Storage)?
}

/// List the originating ready transport's complete, acknowledged Team library locally.
#[tauri::command]
#[specta::specta]
pub async fn team_snippets(
    context: ProfileRequest,
    app: tauri::AppHandle,
    origin: SnippetTerminal,
) -> Result<TeamSnippetLibrary, SnippetIssue> {
    team_operation(context, app, move |manager, store| manager.team_snippets(store, &origin)).await
}

/// Review one current Team template and the complete same-source existing target set.
#[tauri::command]
#[specta::specta]
pub async fn prepare_team_snippet(
    context: ProfileRequest,
    app: tauri::AppHandle,
    origin: SnippetTerminal,
    fence: TeamSnippetFence,
    id: String,
    values: BTreeMap<String, String>,
    targets: Vec<SnippetTerminal>,
) -> Result<PreparedTeamSnippet, SnippetIssue> {
    team_operation(context, app, move |manager, store| {
        manager.prepare_team_snippet(store, origin, fence, &id, values, targets)
    })
    .await
}

/// Admit exact reviewed bytes to one original Team transport, with no automatic retry.
#[tauri::command]
#[specta::specta]
pub async fn send_team_snippet(
    context: ProfileRequest,
    app: tauri::AppHandle,
    prepared: PreparedTeamSnippet,
    index: u32,
) -> Result<TeamSnippetSendOutcome, SnippetIssue> {
    team_operation(context, app, move |manager, store| {
        manager.send_team_snippet(store, &prepared, index as usize)
    })
    .await
}
