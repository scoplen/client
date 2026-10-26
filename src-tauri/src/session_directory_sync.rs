// SPDX-License-Identifier: Apache-2.0

//! Native folder selection and explicit current-directory synchronization intents.

use scoplen_client_core::locale::Locale;
use scoplen_client_core::session_directory_sync::{
    SessionDirectorySyncApplyResult, SessionDirectorySyncIssue, SessionDirectorySyncPrepareResult,
};
use scoplen_client_core::session_manager::SessionManager;
use scoplen_client_core::session_transfers::{SessionTransferDirection, SessionTransferIssue};

/// Select an ordinary local folder and compare contents without writing files.
#[tauri::command]
#[specta::specta]
#[allow(clippy::too_many_arguments)]
pub async fn session_prepare_directory_sync(
    _context: crate::profile_context::ProfileRequest,
    app: tauri::AppHandle,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    operation_id: String,
    remote_path: Vec<u8>,
    direction: SessionTransferDirection,
    locale: Locale,
) -> Result<SessionDirectorySyncPrepareResult, SessionDirectorySyncIssue> {
    let title = match locale {
        Locale::En => "Choose local directory",
        Locale::ZhHans => "选择本地目录",
    };
    manager
        .prepare_directory_sync_with_picker(
            &session_id,
            &transport_id,
            &operation_id,
            remote_path,
            direction,
            move || async move {
                tauri::async_runtime::spawn_blocking(move || {
                    use tauri_plugin_dialog::DialogExt as _;
                    app.dialog()
                        .file()
                        .set_title(title)
                        .blocking_pick_folder()
                        .map(|path| {
                            path.into_path().map_err(|_| SessionTransferIssue::InvalidSelection)
                        })
                        .transpose()
                })
                .await
                .map_err(|_| SessionTransferIssue::SelectionFailed)?
            },
        )
        .await
}

/// Queue only the reviewed Create and Changed files through the existing FIFO.
#[tauri::command]
#[specta::specta]
pub async fn session_apply_directory_sync(
    _context: crate::profile_context::ProfileRequest,
    app: tauri::AppHandle,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    plan_id: String,
    locale: Locale,
) -> Result<SessionDirectorySyncApplyResult, SessionDirectorySyncIssue> {
    manager
        .apply_directory_sync(&session_id, &transport_id, &plan_id, move |review| {
            crate::session_transfers::confirm_replace(app.clone(), locale, review)
        })
        .await
}

/// Discard one unapplied comparison without changing admitted queue rows.
#[tauri::command]
#[specta::specta]
pub fn session_discard_directory_sync(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    plan_id: String,
) -> Result<(), SessionDirectorySyncIssue> {
    manager.discard_directory_sync(&session_id, &plan_id)
}
