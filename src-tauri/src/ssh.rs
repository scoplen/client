// SPDX-License-Identifier: Apache-2.0

//! Thin terminal-session intents and binary channel adapters over the Rust manager.

use crate::events::{SessionChangeKind, SessionChanged};
use crate::frames::SessionMessage;
use crate::profile_context::ProfileRequest as LocalDataState;
use scoplen_client_core::connection::preparation::PreparationResponse;
use scoplen_client_core::locale::Locale;
use scoplen_client_core::session_files::{
    RemoteDirectory, RemoteFileKind, RemoteTextPreview, RemoteTextPreviewIssue,
    SessionFileMutationResult,
};
use scoplen_client_core::session_manager::HistoryChange;
use scoplen_crypto::SecretVec;
use serde::Deserialize;
use specta::Type;
use tauri::ipc::Channel;
use tauri_specta::Event as _;

pub use scoplen_client_core::session_manager::SessionManager;
use scoplen_client_core::terminal_output::{SavedOutputError, TerminalSnapshot};

/// Checkpoint rendered output without letting a late caller select its store or history row.
#[tauri::command]
#[specta::specta]
pub async fn session_save_output(
    local: LocalDataState,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    sequence: u32,
    snapshot: TerminalSnapshot,
) -> Result<(), SavedOutputError> {
    local
        .with_store(|store| {
            manager.save_output(store, &session_id, &transport_id, sequence, &snapshot)
        })
        .unwrap_or(Err(SavedOutputError::StaleCheckpoint))
}

/// Reserve a logical session before starting its cancellable manager task.
#[tauri::command]
#[specta::specta]
pub fn session_reserve_transport(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    pty: bool,
) -> Result<(), String> {
    manager.reserve(&session_id, pty)
}

/// A one-time response to the current attempt's preparation prompt.
#[derive(Deserialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SessionPreparationIntent {
    /// Ordered one-time answers to the exact current server challenge.
    KeyboardInteractive {
        /// Answers are consumed and never returned to the renderer.
        answers: Vec<String>,
    },
    /// Accept only the exact host key retained by Rust.
    AcceptHostKey,
    /// Supply a write-only key passphrase, never returned to the renderer.
    Passphrase {
        /// One-time secret input.
        value: String,
    },
}

impl SessionPreparationIntent {
    /// Consume write-only answers immediately into the common redacting response.
    pub(crate) fn into_response(self) -> Result<PreparationResponse, String> {
        match self {
            Self::KeyboardInteractive { answers } => PreparationResponse::keyboard_interactive(
                answers.into_iter().map(String::into_bytes).collect(),
            ),
            Self::AcceptHostKey => Ok(PreparationResponse::AcceptHostKey),
            Self::Passphrase { value } => {
                Ok(PreparationResponse::Passphrase(SecretVec::new(value.into_bytes())))
            }
        }
    }
}

/// Reply to the current session-owned, one-use preparation prompt.
#[tauri::command]
#[specta::specta]
pub fn session_respond(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    prompt_id: String,
    intent: SessionPreparationIntent,
) -> Result<(), String> {
    let response = intent.into_response()?;
    manager.respond(&session_id, &transport_id, &prompt_id, response)
}

/// Own one logical terminal until tab closure. Ended terminals await manual retry.
#[tauri::command]
#[specta::specta]
#[allow(clippy::too_many_arguments)]
pub async fn session_connect(
    app: tauri::AppHandle,
    local: LocalDataState,
    manager: tauri::State<'_, SessionManager>,
    profile_id: String,
    command: Option<String>,
    pty: bool,
    session_id: String,
    messages: Channel<SessionMessage>,
) -> Result<(), String> {
    let store = match local.store() {
        Some(store) => store,
        None => {
            let _ = manager.close(&session_id);
            return Err("local data is locked".into());
        }
    };
    let profile_generation = local.generation();
    manager
        .run(
            &session_id,
            &profile_id,
            command.as_deref(),
            pty,
            store,
            |event| {
                messages
                    .send(SessionMessage::Event(event))
                    .map_err(|_| "session event channel is closed".into())
            },
            |transport, bytes| {
                messages
                    .send(SessionMessage::Output(transport, bytes))
                    .map_err(|_| "session output channel is closed".into())
            },
            move |id, change| {
                let change = match change {
                    HistoryChange::Opened => SessionChangeKind::Opened,
                    HistoryChange::Closed => SessionChangeKind::Closed,
                };
                let _ = SessionChanged {
                    profile_generation: profile_generation.clone(),
                    session_id: id.to_owned(),
                    change,
                }
                .emit(&app);
            },
        )
        .await
}

/// Route one bounded input frame to the exact ready transport.
#[tauri::command]
#[specta::specta]
pub fn session_input(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    data: Vec<u8>,
) -> Result<(), String> {
    manager.input(&session_id, &transport_id, data)
}

/// Resize the exact ready transport's pseudo-terminal.
#[tauri::command]
#[specta::specta]
pub fn session_resize(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    columns: u32,
    rows: u32,
) -> Result<(), String> {
    manager.resize(&session_id, &transport_id, columns, rows)
}

/// Browse files on the terminal's authenticated SSH connection.
#[tauri::command]
#[specta::specta]
pub async fn session_list_files(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    operation_id: String,
    path: Vec<u8>,
) -> Result<RemoteDirectory, String> {
    manager.list_files(&session_id, &transport_id, &operation_id, path).await
}

/// Preview complete bounded text without saving or executing it.
#[tauri::command]
#[specta::specta]
pub async fn session_preview_file(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    operation_id: String,
    path: Vec<u8>,
) -> Result<RemoteTextPreview, RemoteTextPreviewIssue> {
    manager.preview_file(&session_id, &transport_id, &operation_id, path).await
}

/// Create one directory inside the current remote Files directory.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
#[specta::specta]
pub async fn session_create_remote_directory(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    operation_id: String,
    directory_path: Vec<u8>,
    name: String,
    locale: Locale,
) -> Result<SessionFileMutationResult, String> {
    let _ = locale;
    manager
        .create_remote_directory(&session_id, &transport_id, &operation_id, directory_path, &name)
        .await
}

/// Rename one ordinary remote entry without offering replacement.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
#[specta::specta]
pub async fn session_rename_remote_entry(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    operation_id: String,
    directory_path: Vec<u8>,
    entry_path: Vec<u8>,
    new_name: String,
    locale: Locale,
) -> Result<SessionFileMutationResult, String> {
    let _ = locale;
    manager
        .rename_remote_entry(
            &session_id,
            &transport_id,
            &operation_id,
            directory_path,
            entry_path,
            &new_name,
        )
        .await
}

/// Delete one ordinary remote file or empty directory after native confirmation.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
#[specta::specta]
pub async fn session_delete_remote_entry(
    _context: crate::profile_context::ProfileRequest,
    app: tauri::AppHandle,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    operation_id: String,
    directory_path: Vec<u8>,
    entry_path: Vec<u8>,
    locale: Locale,
) -> Result<SessionFileMutationResult, String> {
    manager
        .delete_remote_entry_with_confirmation(
            &session_id,
            &transport_id,
            &operation_id,
            directory_path,
            entry_path,
            move |kind, name| async move {
                tauri::async_runtime::spawn_blocking(move || {
                    use tauri_plugin_dialog::{DialogExt as _, MessageDialogButtons, MessageDialogKind};
                    let (title, message, delete, keep) = match (locale, kind) {
                        (Locale::En, RemoteFileKind::File) => (
                            "Delete remote file",
                            format!("Delete remote file \"{name}\" permanently?"),
                            "Delete file",
                            "Keep file",
                        ),
                        (Locale::En, RemoteFileKind::Directory) => (
                            "Delete remote directory",
                            format!("Delete remote directory \"{name}\" permanently?\n\nOnly empty directories can be deleted."),
                            "Delete directory",
                            "Keep directory",
                        ),
                        (Locale::ZhHans, RemoteFileKind::File) => (
                            "删除远程文件",
                            format!("要永久删除远程文件“{name}”吗？"),
                            "删除文件",
                            "保留文件",
                        ),
                        (Locale::ZhHans, RemoteFileKind::Directory) => (
                            "删除远程目录",
                            format!("要永久删除远程目录“{name}”吗？\n\n只能删除空目录。"),
                            "删除目录",
                            "保留目录",
                        ),
                        (_, RemoteFileKind::Other) => unreachable!("preflight rejects special entries"),
                    };
                    app.dialog()
                        .message(message)
                        .title(title)
                        .kind(MessageDialogKind::Warning)
                        .buttons(MessageDialogButtons::OkCancelCustom(delete.into(), keep.into()))
                        .blocking_show()
                })
                .await
                .map_err(|_| "the delete confirmation failed".to_owned())
            },
        )
        .await
}

/// Stop only the matching SFTP operation, leaving the terminal connected.
#[tauri::command]
#[specta::specta]
pub fn session_cancel_file_operation(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    operation_id: String,
) -> Result<(), String> {
    manager.cancel_file_operation(&session_id, &transport_id, &operation_id)
}

pub(crate) fn suggested_download_name(remote_path: &[u8]) -> String {
    let name = remote_path.rsplit(|byte| *byte == b'/').next().unwrap_or_default();
    let mut suggested: String = String::from_utf8_lossy(name)
        .chars()
        .take(128)
        .map(|character| {
            if character.is_control()
                || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
                || matches!(character, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
            {
                '_'
            } else {
                character
            }
        })
        .collect();
    suggested = suggested.trim_end_matches([' ', '.']).to_owned();
    if suggested.is_empty() { "download".into() } else { suggested }
}

/// Begin an explicit reconnect with a fresh automatic retry budget.
#[tauri::command]
#[specta::specta]
pub fn session_retry_transport(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
) -> Result<(), String> {
    manager.retry(&session_id)
}

/// Cancel preparation or back-off while preserving the terminal for manual retry.
#[tauri::command]
#[specta::specta]
pub fn session_stop_reconnecting(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
) -> Result<(), String> {
    manager.stop(&session_id)
}

/// Stop an unusable terminal without triggering automatic reconnect.
#[tauri::command]
#[specta::specta]
pub fn session_fail_transport(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
) -> Result<(), String> {
    manager.fail(&session_id)
}

/// End the complete logical session, including every timer, prompt, and transport.
#[tauri::command]
#[specta::specta]
pub fn session_close_transport(
    _context: crate::profile_context::ProfileRequest,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
) -> Result<(), String> {
    manager.close(&session_id)
}

#[cfg(test)]
mod tests {
    use super::suggested_download_name;

    #[test]
    fn suggested_download_name_replaces_bidi_format_controls() {
        assert_eq!(suggested_download_name("./report\u{202e}cod.exe".as_bytes()), "report_cod.exe");
        assert_eq!(suggested_download_name("./\u{2066}name\u{2069}".as_bytes()), "_name_");
    }
}
