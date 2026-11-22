// SPDX-License-Identifier: Apache-2.0
//! Typed IPC for current Organization Host Grant administration.

use scoplen_client_core::{
    personal_server::{PersonalServer, PersonalServerError, TeamError, TeamGrantPageView},
    store::Store,
};
use std::sync::Arc;

use crate::profile_context::ProfileRequest;

fn store(context: &ProfileRequest) -> Result<Arc<Store>, TeamError> {
    context.store().ok_or_else(|| PersonalServerError::Storage.into())
}

/// Read one current, server-authorized Grant page.
#[tauri::command]
#[specta::specta]
pub async fn team_grants_page(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    cursor: Option<String>,
) -> Result<TeamGrantPageView, TeamError> {
    personal.team_grants_page(store(&context)?, &organization_id, cursor.as_deref()).await
}

/// Withdraw one Grant using the exact strong ETag visible in the current page.
#[tauri::command]
#[specta::specta]
pub async fn withdraw_team_grant(
    context: ProfileRequest,
    personal: tauri::State<'_, PersonalServer>,
    organization_id: String,
    grant_id: String,
    etag: String,
) -> Result<(), TeamError> {
    personal.withdraw_team_grant(store(&context)?, &organization_id, &grant_id, &etag).await
}
