// SPDX-License-Identifier: Apache-2.0

//! Typed inventory commands. The implementation stays in
//! `scoplen-client-core`; this module only supplies process state and IPC
//! adapters.

use crate::events::{SessionChangeKind, SessionChanged};
use crate::local_data::LocalDataState;
use scoplen_client_core::inventory::{
    AccessProfileInput, AccessProfileSummary, AddHostError, Areas, CredentialInput,
    CredentialSummary, Deletion, DeletionStore, EditHost, EditHostError, Failure, ForwardSummary,
    GroupError, GroupInput, GroupSummary, HostDetails, HostSource, HostSummary, Inventory, NewHost,
    ObjectEditError, OpenSshImportError, OpenSshImportPreview, OpenSshImportResult, RecentSession,
    RecentSessionKind, RecentSessionOutcome, ReconnectTarget, RouteInput, RouteSummary,
    SessionError,
};
use tauri_specta::Event as _;

/// Process-local undo state shared by inventory command calls.
#[derive(Clone, Default)]
pub struct InventoryState {
    deletions: DeletionStore,
}

fn facade(local: &LocalDataState, state: &InventoryState) -> Result<Inventory, Failure> {
    let store = local
        .store()
        .ok_or_else(|| Failure::Failed { reference: "local data is locked".into() })?;
    Ok(Inventory::with_deletions(store, state.deletions.clone()))
}

async fn blocking<T>(
    operation: impl FnOnce() -> Result<T, Failure> + Send + 'static,
) -> Result<T, Failure>
where
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(operation)
        .await
        .map_err(|error| Failure::Failed { reference: error.to_string() })?
}

async fn blocking_add<T>(
    operation: impl FnOnce() -> Result<T, AddHostError> + Send + 'static,
) -> Result<T, AddHostError>
where
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(operation)
        .await
        .map_err(|error| AddHostError::Failed { reference: error.to_string() })?
}

async fn blocking_session<T>(
    operation: impl FnOnce() -> Result<T, SessionError> + Send + 'static,
) -> Result<T, SessionError>
where
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(operation)
        .await
        .map_err(|error| SessionError::Failed { reference: error.to_string() })?
}

/// Returns which inventory areas have content.
#[tauri::command]
#[specta::specta]
pub async fn inventory_areas(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
) -> Result<Areas, Failure> {
    let inventory = facade(&local, &state)?;
    blocking(move || inventory.areas()).await
}

/// Lists groups with live-host counts.
#[tauri::command]
#[specta::specta]
pub async fn inventory_groups(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
) -> Result<Vec<GroupSummary>, Failure> {
    let inventory = facade(&local, &state)?;
    blocking(move || inventory.groups()).await
}

/// Lists hosts from a source, filtered by the optional query.
#[tauri::command]
#[specta::specta]
pub async fn inventory_hosts(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    source: HostSource,
    query: String,
) -> Result<Vec<HostSummary>, Failure> {
    let inventory = facade(&local, &state)?;
    blocking(move || inventory.hosts(source, query)).await
}

/// Lists the newest live entries in the device-local Recent session history.
#[tauri::command]
#[specta::specta]
pub async fn inventory_recent_sessions(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
) -> Result<Vec<RecentSession>, Failure> {
    let inventory = facade(&local, &state)?;
    blocking(move || inventory.recent_sessions()).await
}

/// Records that a real connection owner opened a device-local session.
#[tauri::command]
#[specta::specta]
pub async fn session_open(
    app: tauri::AppHandle,
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    profile_id: String,
    kind: RecentSessionKind,
) -> Result<RecentSession, SessionError> {
    let inventory = facade_session(&local, &state)?;
    let opened = blocking_session(move || inventory.open_session(profile_id, kind)).await?;
    let _ = SessionChanged { session_id: opened.id.clone(), change: SessionChangeKind::Opened }
        .emit(&app);
    Ok(opened)
}

/// Records the outcome reported by a real connection owner.
#[tauri::command]
#[specta::specta]
pub async fn session_close(
    app: tauri::AppHandle,
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    session_id: String,
    outcome: RecentSessionOutcome,
) -> Result<(), SessionError> {
    let inventory = facade_session(&local, &state)?;
    let event_session_id = session_id.clone();
    blocking_session(move || inventory.close_session(session_id, outcome)).await?;
    let _ = SessionChanged { session_id: event_session_id, change: SessionChangeKind::Closed }
        .emit(&app);
    Ok(())
}

/// Resolves an ended terminal session to its current login without opening a connection.
#[tauri::command]
#[specta::specta]
pub async fn session_reconnect(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    session_id: String,
) -> Result<ReconnectTarget, SessionError> {
    let inventory = facade_session(&local, &state)?;
    blocking_session(move || inventory.reconnect_session(session_id)).await
}

/// Forgets one ended session and its saved local scrollback.
#[tauri::command]
#[specta::specta]
pub async fn session_forget(
    app: tauri::AppHandle,
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    session_id: String,
) -> Result<(), SessionError> {
    let inventory = facade_session(&local, &state)?;
    blocking_session({
        let session_id = session_id.clone();
        move || inventory.forget_session(session_id)
    })
    .await?;
    let _ = SessionChanged { session_id, change: SessionChangeKind::Forgotten }.emit(&app);
    Ok(())
}

fn facade_session(
    local: &LocalDataState,
    state: &InventoryState,
) -> Result<Inventory, SessionError> {
    let store = local
        .store()
        .ok_or_else(|| SessionError::Failed { reference: "local data is locked".into() })?;
    Ok(Inventory::with_deletions(store, state.deletions.clone()))
}

/// Reads one host and its logins.
#[tauri::command]
#[specta::specta]
pub async fn inventory_host(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    id: String,
) -> Result<Option<HostDetails>, Failure> {
    let inventory = facade(&local, &state)?;
    blocking(move || inventory.host(id)).await
}

/// Creates a host, credential, and default login as one operation.
#[tauri::command]
#[specta::specta]
pub async fn inventory_add_host(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    host: NewHost,
) -> Result<HostDetails, AddHostError> {
    let store = local
        .store()
        .ok_or_else(|| AddHostError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    blocking_add(move || inventory.add_host(host)).await
}

/// Changes a host's favorite marker.
#[tauri::command]
#[specta::specta]
pub async fn inventory_set_favorite(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    id: String,
    favorite: bool,
) -> Result<(), Failure> {
    let inventory = facade(&local, &state)?;
    blocking(move || inventory.set_favorite(id, favorite)).await
}

/// Updates host metadata, tags, and group memberships in one core operation.
#[tauri::command]
#[specta::specta]
pub async fn inventory_update_host(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    id: String,
    host: EditHost,
) -> Result<HostDetails, EditHostError> {
    let store = local
        .store()
        .ok_or_else(|| EditHostError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.update_host(id, host))
        .await
        .map_err(|error| EditHostError::Failed { reference: error.to_string() })?
}

/// Creates a host group.
#[tauri::command]
#[specta::specta]
pub async fn inventory_create_group(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    group: GroupInput,
) -> Result<GroupSummary, GroupError> {
    let inventory = facade(&local, &state)
        .map_err(|error| GroupError::Failed { reference: error.to_string() })?;
    tauri::async_runtime::spawn_blocking(move || inventory.create_group(group))
        .await
        .map_err(|error| GroupError::Failed { reference: error.to_string() })?
}

/// Updates a host group name and parent.
#[tauri::command]
#[specta::specta]
pub async fn inventory_update_group(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    id: String,
    group: GroupInput,
) -> Result<GroupSummary, GroupError> {
    let inventory = facade(&local, &state)
        .map_err(|error| GroupError::Failed { reference: error.to_string() })?;
    tauri::async_runtime::spawn_blocking(move || inventory.update_group(id, group))
        .await
        .map_err(|error| GroupError::Failed { reference: error.to_string() })?
}

/// Lists independent access profiles with redacted references.
#[tauri::command]
#[specta::specta]
pub async fn inventory_access_profiles(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
) -> Result<Vec<AccessProfileSummary>, ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.access_profiles())
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Lists saved tunnels that can be attached to an access profile.
#[tauri::command]
#[specta::specta]
pub async fn inventory_forwards(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
) -> Result<Vec<ForwardSummary>, ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.forwards_objects())
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Creates an independent access profile.
#[tauri::command]
#[specta::specta]
pub async fn inventory_create_access_profile(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    profile: AccessProfileInput,
) -> Result<AccessProfileSummary, ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.create_access_profile(profile))
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Replaces an independent access profile.
#[tauri::command]
#[specta::specta]
pub async fn inventory_update_access_profile(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    id: String,
    profile: AccessProfileInput,
) -> Result<AccessProfileSummary, ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.update_access_profile(id, profile))
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Deletes an independent access profile after reference checks.
#[tauri::command]
#[specta::specta]
pub async fn inventory_delete_access_profile(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    id: String,
) -> Result<(), ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.delete_access_profile(id))
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Restores the tombstoned host that leaves an access profile orphaned.
#[tauri::command]
#[specta::specta]
pub async fn inventory_restore_orphaned_host(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    id: String,
) -> Result<(), ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.restore_orphaned_host(id))
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Restores a tombstoned user-owned object that another live object references.
#[tauri::command]
#[specta::specta]
pub async fn inventory_restore_orphaned_object(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    id: String,
) -> Result<(), ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.restore_orphaned_object(id))
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Lists redacted independent credentials.
#[tauri::command]
#[specta::specta]
pub async fn inventory_credentials(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
) -> Result<Vec<CredentialSummary>, ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.credentials_objects())
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Creates a redacted independent credential.
#[tauri::command]
#[specta::specta]
pub async fn inventory_create_credential(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    credential: CredentialInput,
) -> Result<CredentialSummary, ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.create_credential(credential))
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Replaces a redacted independent credential.
#[tauri::command]
#[specta::specta]
pub async fn inventory_update_credential(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    id: String,
    credential: CredentialInput,
) -> Result<CredentialSummary, ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.update_credential(id, credential))
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Deletes an independent credential after reference checks.
#[tauri::command]
#[specta::specta]
pub async fn inventory_delete_credential(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    id: String,
) -> Result<(), ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.delete_credential(id))
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Lists independent routes.
#[tauri::command]
#[specta::specta]
pub async fn inventory_routes(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
) -> Result<Vec<RouteSummary>, ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.routes_objects())
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Creates an independent route.
#[tauri::command]
#[specta::specta]
pub async fn inventory_create_route(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    route: RouteInput,
) -> Result<RouteSummary, ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.create_route(route))
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Replaces an independent route.
#[tauri::command]
#[specta::specta]
pub async fn inventory_update_route(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    id: String,
    route: RouteInput,
) -> Result<RouteSummary, ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.update_route(id, route))
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Deletes an independent route after reference checks.
#[tauri::command]
#[specta::specta]
pub async fn inventory_delete_route(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    id: String,
) -> Result<(), ObjectEditError> {
    let store = local
        .store()
        .ok_or_else(|| ObjectEditError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.delete_route(id))
        .await
        .map_err(|error| ObjectEditError::Failed { reference: error.to_string() })?
}

/// Tombstones a host and returns a short-lived undo token.
#[tauri::command]
#[specta::specta]
pub async fn inventory_delete_host(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    id: String,
) -> Result<Deletion, Failure> {
    let inventory = facade(&local, &state)?;
    blocking(move || inventory.delete_host(id)).await
}

/// Restores a deletion made by this running desktop process.
#[tauri::command]
#[specta::specta]
pub async fn inventory_undo_delete(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    token: String,
) -> Result<(), Failure> {
    let inventory = facade(&local, &state)?;
    blocking(move || inventory.undo_delete(token)).await
}

/// Reads an OpenSSH config for the empty-inventory preview without modifying
/// the source file or local store.
#[tauri::command]
#[specta::specta]
pub async fn inventory_preview_open_ssh_config(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    path: String,
) -> Result<OpenSshImportPreview, OpenSshImportError> {
    let store = local
        .store()
        .ok_or_else(|| OpenSshImportError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.preview_open_ssh_config(path))
        .await
        .map_err(|error| OpenSshImportError::Failed { reference: error.to_string() })?
}

/// Imports a previously previewed OpenSSH config into an empty inventory.
#[tauri::command]
#[specta::specta]
pub async fn inventory_import_open_ssh_config(
    local: tauri::State<'_, LocalDataState>,
    state: tauri::State<'_, InventoryState>,
    preview: OpenSshImportPreview,
) -> Result<OpenSshImportResult, OpenSshImportError> {
    let store = local
        .store()
        .ok_or_else(|| OpenSshImportError::Failed { reference: "local data is locked".into() })?;
    let inventory = Inventory::with_deletions(store, state.deletions.clone());
    tauri::async_runtime::spawn_blocking(move || inventory.import_open_ssh_config(preview))
        .await
        .map_err(|error| OpenSshImportError::Failed { reference: error.to_string() })?
}

/// Opens the conventional `~/.ssh/config` picker used by the empty-list
/// onboarding flow. Cancellation returns `null`.
#[tauri::command]
#[specta::specta]
pub async fn choose_open_ssh_config(app: tauri::AppHandle) -> Result<Option<String>, Failure> {
    let path = tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt as _;
        app.dialog()
            .file()
            .set_title("Choose an OpenSSH configuration")
            .add_filter("OpenSSH config", &["", "conf"])
            .blocking_pick_file()
    })
    .await
    .map_err(|error| Failure::Failed { reference: error.to_string() })?;
    Ok(path.and_then(|path| path.into_path().ok()).map(|path| path.to_string_lossy().into_owned()))
}

/// Opens the native private-key file picker; `null` means cancellation.
#[tauri::command]
#[specta::specta]
pub async fn choose_key_file(app: tauri::AppHandle) -> Result<Option<String>, Failure> {
    let path = tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt as _;
        app.dialog()
            .file()
            .set_title("Choose a private key")
            .add_filter("OpenSSH private key", &["", "key", "pem"])
            .blocking_pick_file()
    })
    .await
    .map_err(|error| Failure::Failed { reference: error.to_string() })?;
    Ok(path.and_then(|path| path.into_path().ok()).map(|path| path.to_string_lossy().into_owned()))
}
