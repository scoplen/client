// SPDX-License-Identifier: Apache-2.0
//! Captured-profile native file selection and Rust-owned Organization batches.

use scoplen_client_core::locale::Locale;
use scoplen_client_core::{
    personal_server::{
        PersonalServer, PersonalServerError, TeamImportError, TeamImportInventoryReview,
        TeamImportPending, TeamImportPreview, TeamImportSavedPage, TeamImportSource,
    },
    store::Store,
};
use std::sync::Arc;
use tauri::Manager as _;

use crate::profile_context::ProfileRequest;

fn store(context: &ProfileRequest) -> Result<Arc<Store>, TeamImportError> {
    context.store().ok_or_else(|| PersonalServerError::Storage.into())
}

/// Read only saved destination ids for this Account, including unavailable teams.
#[tauri::command]
#[specta::specta]
pub async fn retained_team_inventory_imports(
    app: tauri::AppHandle,
    context: ProfileRequest,
    cursor: Option<String>,
) -> Result<TeamImportSavedPage, TeamImportError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<PersonalServer>().retained_team_inventory_imports(&store, cursor.as_deref())
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Read one explicitly selected file; no path or raw source enters the renderer.
#[tauri::command]
#[specta::specta]
pub async fn choose_team_inventory_import(
    app: tauri::AppHandle,
    context: ProfileRequest,
    organization_id: String,
    source: TeamImportSource,
    locale: Locale,
) -> Result<Option<TeamImportPreview>, TeamImportError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt as _;
        let _context = context;
        let dialog = app.dialog().file().set_title(match (source, locale) {
            (TeamImportSource::Csv, Locale::En) => "Choose team inventory CSV",
            (TeamImportSource::OpenSsh, Locale::En) => "Choose a Direct OpenSSH configuration",
            (TeamImportSource::Csv, Locale::ZhHans) => "选择团队资产 CSV 文件",
            (TeamImportSource::OpenSsh, Locale::ZhHans) => "选择直连 OpenSSH 配置文件",
        });
        let Some(file) = dialog.blocking_pick_file() else {
            return Ok(None);
        };
        let path = file.into_path().map_err(|_| TeamImportError::FileUnavailable)?;
        app.state::<PersonalServer>()
            .preview_team_inventory_import_file(&store, &organization_id, source, &path)
            .map(Some)
    })
    .await
    .map_err(|_| TeamImportError::FileUnavailable)?
}

/// Clear only the captured source review when its view changes or closes.
#[tauri::command]
#[specta::specta]
pub async fn clear_team_inventory_import_preview(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    preview_id: String,
) -> Result<(), TeamImportError> {
    personal.clear_team_inventory_import_preview(&store(&context)?, &preview_id)
}

/// Retain exactly one reviewed Ready subset before any network dispatch.
#[tauri::command]
#[specta::specta]
pub async fn prepare_team_inventory_import(
    app: tauri::AppHandle,
    context: ProfileRequest,
    organization_id: String,
    preview_id: String,
    selected: Vec<u32>,
) -> Result<TeamImportPending, TeamImportError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<PersonalServer>().prepare_team_inventory_import(
            &store,
            &organization_id,
            &preview_id,
            selected,
        )
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Read saved original intent; this never authenticates or submits it.
#[tauri::command]
#[specta::specta]
pub async fn pending_team_inventory_import(
    app: tauri::AppHandle,
    context: ProfileRequest,
    organization_id: String,
) -> Result<Option<TeamImportPending>, TeamImportError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<PersonalServer>().pending_team_inventory_import(&store, &organization_id)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Explicitly dispatch or confirm the exact retained key/body with fresh Device proofs.
#[tauri::command]
#[specta::specta]
pub async fn submit_team_inventory_import(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    operation_id: String,
) -> Result<TeamImportPending, TeamImportError> {
    personal.submit_team_inventory_import(store(&context)?, &organization_id, &operation_id).await
}

/// Refresh current member inventory without changing the original historical result.
#[tauri::command]
#[specta::specta]
pub async fn review_team_inventory_import(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    operation_id: String,
) -> Result<TeamImportInventoryReview, TeamImportError> {
    personal.review_team_inventory_import(store(&context)?, &organization_id, &operation_id).await
}

/// Cancel prepared state, dismiss confirmation, or archive explicitly reviewed expiry.
#[tauri::command]
#[specta::specta]
pub async fn discard_team_inventory_import(
    app: tauri::AppHandle,
    context: ProfileRequest,
    organization_id: String,
    operation_id: String,
) -> Result<(), TeamImportError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<PersonalServer>().discard_team_inventory_import(
            &store,
            &organization_id,
            &operation_id,
        )
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}
