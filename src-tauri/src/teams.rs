// SPDX-License-Identifier: Apache-2.0
//! Generation-bound adapters; Rust retains all team requests, sessions and recovery state.

use std::sync::Arc;

use scoplen_client_core::{
    personal_server::{
        PersonalServer, PersonalServerError, TeamAssetsView, TeamCreationView, TeamError,
        TeamFailure, TeamInvitationPageView, TeamInvitationView, TeamMemberPageView,
        TeamMemberView, TeamOperationKind, TeamOperationView, TeamPageView, TeamSettingsView,
    },
    store::Store,
};
use tauri::Manager as _;

use crate::profile_context::ProfileRequest;

fn store(context: &ProfileRequest) -> Result<Arc<Store>, TeamError> {
    context.store().ok_or_else(|| PersonalServerError::Storage.into())
}

/// Read this team's complete current projection without starting a request.
#[tauri::command]
#[specta::specta]
pub async fn team_assets(
    app: tauri::AppHandle,
    context: ProfileRequest,
    organization_id: String,
) -> Result<TeamAssetsView, TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        app.state::<PersonalServer>().team_assets(&store, &organization_id)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Publish every permitted asset in one source-bound view, then acknowledge that revision.
#[tauri::command]
#[specta::specta]
pub async fn refresh_team_assets(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
) -> Result<TeamAssetsView, TeamError> {
    personal.refresh_team_assets(store(&context)?, &organization_id).await
}

/// Read only safe local retained lifecycle state.
#[tauri::command]
#[specta::specta]
pub async fn pending_team_operations(
    app: tauri::AppHandle,
    context: ProfileRequest,
) -> Result<Vec<TeamOperationView>, TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<PersonalServer>().pending_team_operations(&store)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Protect the generated separate invitation password before any creation request.
#[tauri::command]
#[specta::specta]
pub async fn prepare_team_invitation(
    app: tauri::AppHandle,
    context: ProfileRequest,
    organization_id: String,
    recipient_username: String,
    roles: Vec<String>,
) -> Result<TeamOperationView, TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<PersonalServer>().prepare_team_invitation(
            &store,
            &organization_id,
            recipient_username,
            roles,
        )
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Preview the exact named recipient's invitation without accepting it.
#[tauri::command]
#[specta::specta]
pub async fn preview_team_invitation(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    link: String,
) -> Result<TeamInvitationView, TeamError> {
    personal.preview_team_invitation(store(&context)?, &link).await
}

/// Transfer the uncontrolled password directly into its protected acceptance operation.
#[tauri::command]
#[specta::specta]
pub async fn prepare_team_acceptance(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    link: String,
    preview_etag: String,
    password: String,
) -> Result<TeamOperationView, TeamError> {
    let password = scoplen_crypto::SecretVec::new(password.into_bytes());
    personal.prepare_team_acceptance(store(&context)?, &link, &preview_etag, password).await
}

/// Preserve the exact reviewed Organization precondition for explicit dissolution.
#[tauri::command]
#[specta::specta]
pub async fn prepare_team_dissolution(
    app: tauri::AppHandle,
    context: ProfileRequest,
    organization_id: String,
    etag: String,
) -> Result<TeamOperationView, TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<PersonalServer>().prepare_team_dissolution(&store, &organization_id, &etag)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Send only a retained original lifecycle request with a fresh proof.
#[tauri::command]
#[specta::specta]
pub async fn submit_team_operation(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    kind: TeamOperationKind,
    operation_id: String,
) -> Result<TeamOperationView, TeamError> {
    personal.submit_team_operation(store(&context)?, kind, &operation_id).await
}

/// Erase the local secret preparation or explicitly archive an expired unknown outcome.
#[tauri::command]
#[specta::specta]
pub async fn discard_team_operation(
    app: tauri::AppHandle,
    context: ProfileRequest,
    kind: TeamOperationKind,
    operation_id: String,
) -> Result<(), TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<PersonalServer>().discard_team_operation(&store, kind, &operation_id)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Reveal only to the explicit transient invitation-password control.
#[tauri::command]
#[specta::specta]
pub async fn reveal_team_invitation_password(
    app: tauri::AppHandle,
    context: ProfileRequest,
    operation_id: String,
) -> Result<String, TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let password =
            app.state::<PersonalServer>().team_invitation_password(&store, &operation_id)?;
        String::from_utf8(password.as_bytes().to_vec())
            .map_err(|_| PersonalServerError::Storage.into())
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Copy the protected separate password through the native platform boundary.
#[tauri::command]
#[specta::specta]
pub async fn copy_team_invitation_password(
    app: tauri::AppHandle,
    context: ProfileRequest,
    operation_id: String,
) -> Result<(), TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        let password =
            app.state::<PersonalServer>().team_invitation_password(&store, &operation_id)?;
        let text =
            std::str::from_utf8(password.as_bytes()).map_err(|_| PersonalServerError::Storage)?;
        scoplen_client_platform::clipboard::write_text(text)
            .map_err(|_| TeamFailure::ClipboardUnavailable.into())
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Copy only the confirmed public locator, never its separate password.
#[tauri::command]
#[specta::specta]
pub async fn copy_team_invitation_link(
    app: tauri::AppHandle,
    context: ProfileRequest,
    operation_id: String,
) -> Result<(), TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        let _context = context;
        let link = app.state::<PersonalServer>().team_invitation_link(&store, &operation_id)?;
        scoplen_client_platform::clipboard::write_text(&link)
            .map_err(|_| TeamFailure::ClipboardUnavailable.into())
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Read one current invitation page only on request.
#[tauri::command]
#[specta::specta]
pub async fn team_invitations(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    cursor: Option<String>,
) -> Result<TeamInvitationPageView, TeamError> {
    personal.team_invitations(store(&context)?, &organization_id, cursor.as_deref()).await
}

/// Read one current administrative member page only on request.
#[tauri::command]
#[specta::specta]
pub async fn team_members(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    cursor: Option<String>,
) -> Result<TeamMemberPageView, TeamError> {
    personal.team_members(store(&context)?, &organization_id, cursor.as_deref()).await
}

/// Revoke the captured invitation without a hidden refresh or replay.
#[tauri::command]
#[specta::specta]
pub async fn revoke_team_invitation(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    invitation_id: String,
    etag: String,
) -> Result<(), TeamError> {
    personal.revoke_team_invitation(store(&context)?, &organization_id, &invitation_id, &etag).await
}

/// Apply exactly the reviewed role/status edit and precondition.
#[tauri::command]
#[specta::specta]
pub async fn update_team_member(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    membership_id: String,
    etag: String,
    roles: Vec<String>,
    status: String,
) -> Result<TeamMemberView, TeamError> {
    personal
        .update_team_member(
            store(&context)?,
            &organization_id,
            &membership_id,
            &etag,
            roles,
            &status,
        )
        .await
}

/// Remove a reviewed member or leave through the captured own-membership projection.
#[tauri::command]
#[specta::specta]
pub async fn remove_team_member(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    membership_id: String,
    etag: String,
) -> Result<(), TeamError> {
    personal.remove_team_member(store(&context)?, &organization_id, &membership_id, &etag).await
}

/// Read one current membership page only after the user requests it.
#[tauri::command]
#[specta::specta]
pub async fn teams_page(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    cursor: Option<String>,
) -> Result<TeamPageView, TeamError> {
    personal.teams_page(store(&context)?, cursor.as_deref()).await
}

/// Capture one current team's metadata and exact precondition for an explicit edit.
#[tauri::command]
#[specta::specta]
pub async fn team_settings(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
) -> Result<TeamSettingsView, TeamError> {
    personal.team_settings(store(&context)?, &organization_id).await
}

/// Send one name update without changing or refreshing its captured precondition.
#[tauri::command]
#[specta::specta]
pub async fn update_team_name(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    etag: String,
    name: String,
) -> Result<TeamSettingsView, TeamError> {
    personal.update_team_name(store(&context)?, &organization_id, &etag, name).await
}

/// Read local pending state without contacting the server.
#[tauri::command]
#[specta::specta]
pub async fn pending_team_creation(
    app: tauri::AppHandle,
    context: ProfileRequest,
) -> Result<Option<TeamCreationView>, TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<PersonalServer>().pending_team_creation(&store)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Persist a new canonical creation; no network operation occurs here.
#[tauri::command]
#[specta::specta]
pub async fn prepare_team_creation(
    app: tauri::AppHandle,
    context: ProfileRequest,
    name: String,
) -> Result<TeamCreationView, TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<PersonalServer>().prepare_team_creation(&store, name)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}

/// Dispatch or explicitly retry only this Account's retained original creation.
#[tauri::command]
#[specta::specta]
pub async fn submit_team_creation(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    operation_id: String,
) -> Result<TeamCreationView, TeamError> {
    personal.submit_team_creation(store(&context)?, &operation_id).await
}

/// Clear only a prepared, confirmed or explicitly reviewed expired operation.
#[tauri::command]
#[specta::specta]
pub async fn discard_team_creation(
    app: tauri::AppHandle,
    context: ProfileRequest,
    operation_id: String,
) -> Result<(), TeamError> {
    let store = store(&context)?;
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<PersonalServer>().discard_team_creation(&store, &operation_id)
    })
    .await
    .map_err(|_| PersonalServerError::Storage)?
}
