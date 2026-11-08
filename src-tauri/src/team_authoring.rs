// SPDX-License-Identifier: Apache-2.0
//! Account-generation-bound Organization authoring; Rust owns requests and recovery.

use crate::profile_context::ProfileRequest;
use scoplen_client_core::{
    personal_server::{
        PersonalServer, PersonalServerError, TeamAuthoringCollection, TeamAuthoringCreateView,
        TeamAuthoringData, TeamAuthoringPageView, TeamAuthoringResourceView, TeamError,
        TeamSimpleRuleInput, TeamSimpleRulePreview,
    },
    store::Store,
};
use std::sync::Arc;
use tauri::Manager as _;

fn store(context: &ProfileRequest) -> Result<Arc<Store>, TeamError> {
    context.store().ok_or_else(|| PersonalServerError::Storage.into())
}

/// Read one live, independently authorized administration page.
#[tauri::command]
#[specta::specta]
pub async fn team_authoring_page(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    collection: TeamAuthoringCollection,
    cursor: Option<String>,
) -> Result<TeamAuthoringPageView, TeamError> {
    personal
        .team_authoring_page(store(&context)?, &organization_id, collection, cursor.as_deref())
        .await
}

/// Capture this resource's complete fields and original strong ETag before editing.
#[tauri::command]
#[specta::specta]
pub async fn team_authoring_resource(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    collection: TeamAuthoringCollection,
    resource_id: String,
) -> Result<TeamAuthoringResourceView, TeamError> {
    personal
        .team_authoring_resource(store(&context)?, &organization_id, collection, &resource_id)
        .await
}

/// Read this team's exact retained create without making a request.
#[tauri::command]
#[specta::specta]
pub async fn pending_team_authoring(
    app: tauri::AppHandle,
    context: ProfileRequest,
    organization_id: String,
) -> Result<Option<TeamAuthoringCreateView>, TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<PersonalServer>().pending_team_authoring(&store, &organization_id)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Validate shared typed fields and retain one canonical original create before dispatch.
#[tauri::command]
#[specta::specta]
pub async fn prepare_team_authoring(
    app: tauri::AppHandle,
    context: ProfileRequest,
    organization_id: String,
    data: TeamAuthoringData,
) -> Result<TeamAuthoringCreateView, TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<PersonalServer>().prepare_team_authoring(&store, &organization_id, data)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Dispatch or explicitly confirm the retained original key and payload.
#[tauri::command]
#[specta::specta]
pub async fn submit_team_authoring(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    operation_id: String,
) -> Result<TeamAuthoringCreateView, TeamError> {
    personal.submit_team_authoring(store(&context)?, &organization_id, &operation_id).await
}

/// Complete prepared/confirmed state, or archive expired uncertainty after explicit review.
#[tauri::command]
#[specta::specta]
pub async fn discard_team_authoring(
    app: tauri::AppHandle,
    context: ProfileRequest,
    organization_id: String,
    operation_id: String,
) -> Result<(), TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<PersonalServer>().discard_team_authoring(
            &store,
            &organization_id,
            &operation_id,
        )
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Replace complete typed fields using only the form's captured original ETag.
#[tauri::command]
#[specta::specta]
pub async fn update_team_authoring(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    resource_id: String,
    etag: String,
    data: TeamAuthoringData,
) -> Result<TeamAuthoringResourceView, TeamError> {
    personal
        .update_team_authoring(store(&context)?, &organization_id, &resource_id, &etag, data)
        .await
}

/// Delete the reviewed team resource using its captured original ETag.
#[tauri::command]
#[specta::specta]
pub async fn delete_team_authoring(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    collection: TeamAuthoringCollection,
    resource_id: String,
    etag: String,
) -> Result<(), TeamError> {
    personal
        .delete_team_authoring(store(&context)?, &organization_id, collection, &resource_id, &etag)
        .await
}

/// Preview one shared-generated independent view/connect rule without granting access.
#[tauri::command]
#[specta::specta]
pub async fn preview_team_simple_rule(
    app: tauri::AppHandle,
    context: ProfileRequest,
    organization_id: String,
    input: TeamSimpleRuleInput,
) -> Result<TeamSimpleRulePreview, TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<PersonalServer>().preview_team_simple_rule(&store, &organization_id, input)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}
