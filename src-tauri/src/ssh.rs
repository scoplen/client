// SPDX-License-Identifier: Apache-2.0

//! Thin terminal-session intents and binary channel adapters over the Rust manager.

use crate::events::{SessionChangeKind, SessionChanged};
use crate::frames::SessionMessage;
use crate::local_data::LocalDataState;
use scoplen_client_core::connection::preparation::PreparationResponse;
use scoplen_client_core::session_manager::HistoryChange;
use scoplen_crypto::SecretVec;
use serde::Deserialize;
use specta::Type;
use tauri::ipc::Channel;
use tauri_specta::Event as _;

pub use scoplen_client_core::session_manager::SessionManager;

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
