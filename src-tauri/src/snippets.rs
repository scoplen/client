// SPDX-License-Identifier: Apache-2.0

//! Profile-bound saved Snippet intents; rendering stays in the Rust core.

use std::collections::BTreeMap;

use crate::profile_context::ProfileRequest;
use scoplen_client_core::snippets::{
    PreparedSnippet, SnippetInput, SnippetIssue, SnippetView, Snippets,
};

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
