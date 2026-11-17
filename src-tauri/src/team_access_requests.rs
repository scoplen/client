// SPDX-License-Identifier: Apache-2.0
//! Generation-bound access-request intents; original inputs and recovery remain in Rust.

use std::sync::Arc;

use scoplen_client_core::{
    personal_server::{
        PersonalServer, PersonalServerError, TeamAccessRequestAction, TeamAccessRequestCheckView,
        TeamAccessRequestDraft, TeamAccessRequestError, TeamAccessRequestList,
        TeamAccessRequestLogin, TeamAccessRequestOperationView, TeamAccessRequestPageView,
        TeamAccessRequestReviewView, TeamAccessRequests,
    },
    session_manager::SessionManager,
    store::Store,
};
use tauri::Manager as _;

use crate::profile_context::ProfileRequest;

fn store(context: &ProfileRequest) -> Result<Arc<Store>, TeamAccessRequestError> {
    context.store().ok_or_else(|| PersonalServerError::Storage.into())
}

/// Check only a retained, authenticated policy refusal belonging to this terminal.
#[tauri::command]
#[specta::specta]
pub async fn check_team_access_request(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    sessions: tauri::State<'_, SessionManager>,
    requests: tauri::State<'_, TeamAccessRequests>,
    session_id: String,
    draft: TeamAccessRequestDraft,
) -> Result<TeamAccessRequestCheckView, TeamAccessRequestError> {
    requests.check(&personal, &sessions, store(&context)?, &session_id, draft).await
}

/// Read one real current Mine or Approvals page.
#[tauri::command]
#[specta::specta]
pub async fn team_access_request_page(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    requests: tauri::State<'_, TeamAccessRequests>,
    organization_id: String,
    view: TeamAccessRequestList,
    cursor: Option<String>,
) -> Result<TeamAccessRequestPageView, TeamAccessRequestError> {
    requests.page(&personal, store(&context)?, &organization_id, view, cursor.as_deref()).await
}

/// GET and retain the original Resource version for an explicit action.
#[tauri::command]
#[specta::specta]
pub async fn review_team_access_request(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    requests: tauri::State<'_, TeamAccessRequests>,
    organization_id: String,
    request_id: String,
) -> Result<TeamAccessRequestReviewView, TeamAccessRequestError> {
    requests.review(&personal, store(&context)?, &organization_id, &request_id).await
}

/// Retain one canonical Create using only the exact Rust-owned successful check.
#[tauri::command]
#[specta::specta]
pub async fn prepare_team_access_request(
    app: tauri::AppHandle,
    context: ProfileRequest,
    check_id: String,
) -> Result<TeamAccessRequestOperationView, TeamAccessRequestError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<TeamAccessRequests>().prepare_create(
            &app.state::<PersonalServer>(),
            &store,
            &check_id,
        )
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Retain one whole action using only the complete reviewed original Resource and ETag.
#[tauri::command]
#[specta::specta]
pub async fn prepare_team_access_request_action(
    app: tauri::AppHandle,
    context: ProfileRequest,
    intent_id: String,
    action: TeamAccessRequestAction,
) -> Result<TeamAccessRequestOperationView, TeamAccessRequestError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<TeamAccessRequests>().prepare_action(
            &app.state::<PersonalServer>(),
            &store,
            &intent_id,
            action,
        )
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Inspect retained local state without a network request or automatic replay.
#[tauri::command]
#[specta::specta]
pub async fn pending_team_access_request(
    app: tauri::AppHandle,
    context: ProfileRequest,
    organization_id: String,
) -> Result<Option<TeamAccessRequestOperationView>, TeamAccessRequestError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<TeamAccessRequests>().pending(&store, &organization_id)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Submit or explicitly confirm exactly the original operation; never replace its precondition.
#[tauri::command]
#[specta::specta]
pub async fn submit_team_access_request(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    requests: tauri::State<'_, TeamAccessRequests>,
    organization_id: String,
    operation_id: String,
) -> Result<TeamAccessRequestOperationView, TeamAccessRequestError> {
    requests.submit(&personal, store(&context)?, &organization_id, &operation_id).await
}

/// Complete retained prepared/confirmed state, or explicitly archive expired uncertainty.
#[tauri::command]
#[specta::specta]
pub async fn discard_team_access_request(
    app: tauri::AppHandle,
    context: ProfileRequest,
    organization_id: String,
    operation_id: String,
) -> Result<(), TeamAccessRequestError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<TeamAccessRequests>().discard(
            &app.state::<PersonalServer>(),
            &store,
            &organization_id,
            &operation_id,
        )
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Offer a separate ordinary Connect for an exact approved original Host and username.
#[tauri::command]
#[specta::specta]
pub async fn team_access_request_logins(
    app: tauri::AppHandle,
    context: ProfileRequest,
    intent_id: String,
) -> Result<Vec<TeamAccessRequestLogin>, TeamAccessRequestError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<TeamAccessRequests>().connection_targets(
            &app.state::<PersonalServer>(),
            &store,
            &intent_id,
        )
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}
