// SPDX-License-Identifier: Apache-2.0

//! Native selection and explicit actions for retained local working copies.

use scoplen_client_core::locale::Locale;
use scoplen_client_core::session_editor::{
    SessionEditorIssue, SessionEditorSnapshot, SessionEditorStartResult,
};
use scoplen_client_core::session_manager::SessionManager;
use scoplen_client_core::session_transfers::SessionTransferEnqueueResult;

/// Read display-only state without starting a local or remote action.
#[tauri::command]
#[specta::specta]
pub fn session_editor_snapshot(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
) -> Result<Option<SessionEditorSnapshot>, SessionEditorIssue> {
    manager.editor_snapshot(&session_id)
}

/// Save a user-selected local text copy and open the fixed platform text editor.
#[tauri::command]
#[specta::specta]
pub async fn session_edit_file(
    _context: crate::profile_context::ProfileRequest,
    app: tauri::AppHandle,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    remote_path: Vec<u8>,
    locale: Locale,
) -> Result<SessionEditorStartResult, SessionEditorIssue> {
    let confirm_app = app.clone();
    let suggested = crate::ssh::suggested_download_name(&remote_path);
    let title = match locale {
        Locale::En => "Save local working copy",
        Locale::ZhHans => "保存本地工作副本",
    };
    manager
        .edit_file_with_picker(
            &session_id,
            &transport_id,
            remote_path,
            move || crate::session_transfers::pick_file(app, title, Some(suggested)),
            move |review| crate::session_transfers::confirm_replace(confirm_app, locale, review),
            |path| async move {
                tauri::async_runtime::spawn_blocking(move || {
                    scoplen_client_platform::text_editor::open_text_editor(&path)
                        .map_err(|_| SessionEditorIssue::EditorLaunchFailed)
                })
                .await
                .map_err(|_| SessionEditorIssue::EditorLaunchFailed)?
            },
        )
        .await
}

/// Explicitly open the saved copy again after a failed or completed launch.
#[tauri::command]
#[specta::specta]
pub async fn session_editor_open(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    editor_id: String,
) -> Result<(), SessionEditorIssue> {
    manager.open_editor(&session_id, &editor_id).await
}

/// Queue the current local save for an explicitly confirmed remote replacement.
#[tauri::command]
#[specta::specta]
pub async fn session_editor_upload(
    _context: crate::profile_context::ProfileRequest,
    app: tauri::AppHandle,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    editor_id: String,
    locale: Locale,
) -> Result<SessionTransferEnqueueResult, SessionEditorIssue> {
    manager
        .upload_editor(&session_id, &transport_id, &editor_id, move |review| {
            crate::session_transfers::confirm_replace(app, locale, review)
        })
        .await
}

/// Stop observation and further uploads while preserving the selected local copy.
#[tauri::command]
#[specta::specta]
pub fn session_editor_stop(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    editor_id: String,
) -> Result<(), SessionEditorIssue> {
    manager.stop_editor(&session_id, &editor_id)
}
