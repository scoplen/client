// SPDX-License-Identifier: Apache-2.0

//! Native selection and typed intents for the Rust-owned session transfer queue.

use std::path::PathBuf;

use scoplen_client_core::locale::Locale;
use scoplen_client_core::session_manager::SessionManager;
use scoplen_client_core::session_transfers::{
    SessionTransferDirection, SessionTransferEnqueueResult, SessionTransferIssue,
    SessionTransferQueueSnapshot, SessionTransferReview,
};

/// Read a complete queue snapshot without changing any transfer's lifetime.
#[tauri::command]
#[specta::specta]
pub fn session_transfer_queue(
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
) -> Result<SessionTransferQueueSnapshot, SessionTransferIssue> {
    manager.transfer_queue_snapshot(&session_id)
}

/// Select a local source, then leave its transfer owned by the logical session.
#[tauri::command]
#[specta::specta]
pub async fn session_enqueue_upload(
    app: tauri::AppHandle,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    directory_path: Vec<u8>,
    locale: Locale,
) -> Result<SessionTransferEnqueueResult, SessionTransferIssue> {
    let confirm_app = app.clone();
    let title = match locale {
        Locale::En => "Upload local file",
        Locale::ZhHans => "选择要上传的本地文件",
    };
    manager
        .enqueue_upload_with_picker(
            &session_id,
            &transport_id,
            directory_path,
            move || pick_file(app, title, None),
            move |review| confirm_replace(confirm_app, locale, review),
        )
        .await
}

/// Select a native destination without sending its path to the renderer.
#[tauri::command]
#[specta::specta]
pub async fn session_enqueue_download(
    app: tauri::AppHandle,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    remote_path: Vec<u8>,
    locale: Locale,
) -> Result<SessionTransferEnqueueResult, SessionTransferIssue> {
    let confirm_app = app.clone();
    let suggested = crate::ssh::suggested_download_name(&remote_path);
    let title = match locale {
        Locale::En => "Download remote file",
        Locale::ZhHans => "下载远程文件",
    };
    manager
        .enqueue_download_with_picker(
            &session_id,
            &transport_id,
            remote_path,
            move || pick_file(app, title, Some(suggested)),
            move |review| confirm_replace(confirm_app, locale, review),
        )
        .await
}

/// Cancel only the queue item and execution the person selected.
#[tauri::command]
#[specta::specta]
pub fn session_cancel_transfer(
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    queue_id: String,
    item_id: String,
    execution_id: String,
) -> Result<(), SessionTransferIssue> {
    manager.cancel_transfer(&session_id, &queue_id, &item_id, &execution_id)
}

/// Clear one unknown-result reminder without retrying or asserting a successful save.
#[tauri::command]
#[specta::specta]
pub fn session_acknowledge_transfer(
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    queue_id: String,
    item_id: String,
    execution_id: String,
) -> Result<(), SessionTransferIssue> {
    manager.acknowledge_transfer(&session_id, &queue_id, &item_id, &execution_id)
}

async fn pick_file(
    app: tauri::AppHandle,
    title: &'static str,
    suggested: Option<String>,
) -> Result<Option<PathBuf>, SessionTransferIssue> {
    tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt as _;
        let dialog = app.dialog().file().set_title(title);
        let selected = match suggested {
            Some(name) => dialog.set_file_name(name).blocking_save_file(),
            None => dialog.blocking_pick_file(),
        };
        selected
            .map(|path| path.into_path().map_err(|_| SessionTransferIssue::InvalidSelection))
            .transpose()
    })
    .await
    .map_err(|_| SessionTransferIssue::SelectionFailed)?
}

async fn confirm_replace(
    app: tauri::AppHandle,
    locale: Locale,
    review: SessionTransferReview,
) -> Result<bool, SessionTransferIssue> {
    tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::{DialogExt as _, MessageDialogButtons, MessageDialogKind};
        let target = match locale {
            Locale::En => format!(
                "Host: {}\nLogin: {}\nAddress: {}\nPort: {}",
                review.host, review.username, review.address, review.port,
            ),
            Locale::ZhHans => format!(
                "主机：{}\n登录：{}\n地址：{}\n端口：{}",
                review.host, review.username, review.address, review.port,
            ),
        };
        let name = review.name;
        let (title, message, replace, keep) = match (locale, review.direction) {
            (Locale::En, SessionTransferDirection::Upload) => (
                "Replace remote file",
                format!("Replace remote file \"{name}\"?\n\n{target}\n\nThe existing file stays in place until the upload is complete."),
                "Replace file",
                "Keep existing",
            ),
            (Locale::En, SessionTransferDirection::Download) => (
                "Replace local file",
                format!("Replace local file \"{name}\"?\n\n{target}\n\nThe destination is checked again before saving. If the check finds a change, the download stops."),
                "Replace file",
                "Keep existing",
            ),
            (Locale::ZhHans, SessionTransferDirection::Upload) => (
                "替换远程文件",
                format!("要替换远程文件“{name}”吗？\n\n{target}\n\n上传完成前，原文件会保持不变。"),
                "替换文件",
                "保留原文件",
            ),
            (Locale::ZhHans, SessionTransferDirection::Download) => (
                "替换本地文件",
                format!("要替换本地文件“{name}”吗？\n\n{target}\n\n保存前会再次检查目标文件；如果检查发现变更，将停止下载。"),
                "替换文件",
                "保留原文件",
            ),
        };
        app.dialog()
            .message(message)
            .title(title)
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(replace.into(), keep.into()))
            .blocking_show()
    })
    .await
    .map_err(|_| SessionTransferIssue::SelectionFailed)
}
