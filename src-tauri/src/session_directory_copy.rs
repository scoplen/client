// SPDX-License-Identifier: Apache-2.0

//! Native folder selection for one reviewed, queue-owned directory copy.

use scoplen_client_core::locale::Locale;
use scoplen_client_core::session_directory_copy::{
    SessionDirectoryCopyIssue, SessionDirectoryCopyPrepareResult,
};
use scoplen_client_core::session_manager::SessionManager;
use scoplen_client_core::session_transfers::{
    SessionTransferDirection, SessionTransferEnqueueResult, SessionTransferIssue,
};

/// Select a native source folder or destination parent without starting a copy.
#[tauri::command]
#[specta::specta]
#[allow(clippy::too_many_arguments)]
pub async fn session_prepare_directory_copy(
    _context: crate::profile_context::ProfileRequest,
    app: tauri::AppHandle,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    remote_path: Vec<u8>,
    direction: SessionTransferDirection,
    locale: Locale,
) -> Result<SessionDirectoryCopyPrepareResult, SessionDirectoryCopyIssue> {
    let title = match (locale, direction) {
        (Locale::En, SessionTransferDirection::Upload) => "Choose folder to upload",
        (Locale::En, SessionTransferDirection::Download) => "Choose destination parent folder",
        (Locale::ZhHans, SessionTransferDirection::Upload) => "选择要上传的文件夹",
        (Locale::ZhHans, SessionTransferDirection::Download) => "选择目标父文件夹",
    };
    manager
        .prepare_directory_copy_with_picker(
            &session_id,
            &transport_id,
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

/// Admit a reviewed new-root copy once through the existing transfer queue.
#[tauri::command]
#[specta::specta]
pub fn session_enqueue_directory_copy(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    selection_id: String,
    root_name: String,
) -> Result<SessionTransferEnqueueResult, SessionDirectoryCopyIssue> {
    manager.enqueue_directory_copy(&session_id, &transport_id, &selection_id, &root_name)
}

/// Release an unapplied native selection and its reserved queue slot.
#[tauri::command]
#[specta::specta]
pub fn session_discard_directory_copy(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    selection_id: String,
) -> Result<(), SessionDirectoryCopyIssue> {
    manager.discard_directory_copy(&session_id, &selection_id)
}
