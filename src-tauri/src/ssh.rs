// SPDX-License-Identifier: Apache-2.0

//! Thin terminal-session intents and binary channel adapters over the Rust manager.

use crate::events::{SessionChangeKind, SessionChanged};
use crate::frames::SessionMessage;
use crate::local_data::LocalDataState;
use scoplen_client_core::connection::preparation::PreparationResponse;
use scoplen_client_core::session_files::RemoteDirectory;
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
    local: tauri::State<'_, LocalDataState>,
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
    /// Accept only the exact host key retained by Rust.
    AcceptHostKey,
    /// Supply a write-only key passphrase, never returned to the renderer.
    Passphrase {
        /// One-time secret input.
        value: String,
    },
}

/// Reply to the current session-owned, one-use preparation prompt.
#[tauri::command]
#[specta::specta]
pub fn session_respond(
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    prompt_id: String,
    intent: SessionPreparationIntent,
) -> Result<(), String> {
    let response = match intent {
        SessionPreparationIntent::AcceptHostKey => PreparationResponse::AcceptHostKey,
        SessionPreparationIntent::Passphrase { value } => {
            PreparationResponse::Passphrase(SecretVec::new(value.into_bytes()))
        }
    };
    manager.respond(&session_id, &prompt_id, response)
}

/// Own one logical terminal until tab closure. Ended terminals await manual retry.
#[tauri::command]
#[specta::specta]
#[allow(clippy::too_many_arguments)]
pub async fn session_connect(
    app: tauri::AppHandle,
    local: tauri::State<'_, LocalDataState>,
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
                let _ = SessionChanged { session_id: id.to_owned(), change }.emit(&app);
            },
        )
        .await
}

/// Route one bounded input frame to the exact ready transport.
#[tauri::command]
#[specta::specta]
pub fn session_input(
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
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    operation_id: String,
    path: Vec<u8>,
) -> Result<RemoteDirectory, String> {
    manager.list_files(&session_id, &transport_id, &operation_id, path).await
}

/// Download a regular remote file to a destination chosen in the native picker.
#[tauri::command]
#[specta::specta]
pub async fn session_download_file(
    app: tauri::AppHandle,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    operation_id: String,
    remote_path: Vec<u8>,
) -> Result<bool, String> {
    let suggested = suggested_download_name(&remote_path);
    manager
        .download_file_with_picker(
            &session_id,
            &transport_id,
            &operation_id,
            remote_path,
            || async move {
                let destination = tauri::async_runtime::spawn_blocking(move || {
                    use tauri_plugin_dialog::DialogExt as _;
                    app.dialog()
                        .file()
                        .set_title("Download remote file")
                        .set_file_name(&suggested)
                        .blocking_save_file()
                })
                .await
                .map_err(|_| "the download destination picker failed".to_owned())?;
                destination
                    .map(|path| {
                        path.into_path().map_err(|_| "choose a local file destination".to_owned())
                    })
                    .transpose()
            },
        )
        .await
}

/// Stop only the matching SFTP operation, leaving the terminal connected.
#[tauri::command]
#[specta::specta]
pub fn session_cancel_file_operation(
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    operation_id: String,
) -> Result<(), String> {
    manager.cancel_file_operation(&session_id, &transport_id, &operation_id)
}

fn suggested_download_name(remote_path: &[u8]) -> String {
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
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
) -> Result<(), String> {
    manager.retry(&session_id)
}

/// Cancel preparation or back-off while preserving the terminal for manual retry.
#[tauri::command]
#[specta::specta]
pub fn session_stop_reconnecting(
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
) -> Result<(), String> {
    manager.stop(&session_id)
}

/// Stop an unusable terminal without triggering automatic reconnect.
#[tauri::command]
#[specta::specta]
pub fn session_fail_transport(
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
) -> Result<(), String> {
    manager.fail(&session_id)
}

/// End the complete logical session, including every timer, prompt, and transport.
#[tauri::command]
#[specta::specta]
pub fn session_close_transport(
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
