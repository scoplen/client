// SPDX-License-Identifier: Apache-2.0
//! Dedicated transient password boundary and Rust-owned pairing progress.

use std::sync::{Arc, Mutex};

use scoplen_client_core::{
    personal_server::{
        PairingError, PairingPhase, PairingStatus, PersonalServer, PersonalServerError,
    },
    store::Store,
};
use serde::Serialize;
use specta::Type;
use tauri::ipc::Channel;
use zeroize::{Zeroize as _, Zeroizing};

use crate::local_data::LocalDataState;

/// One foreground observer; replacing or closing it fences late progress notifications.
#[derive(Default)]
pub struct PairingWatchState(Mutex<Option<String>>);

impl PairingWatchState {
    fn register(&self) -> Result<String, PairingError> {
        let id = scoplen_model::new_uuid_v7().map_err(|_| storage_error())?.to_string();
        *self.0.lock().map_err(|_| storage_error())? = Some(id.clone());
        Ok(id)
    }

    fn current(&self, id: &str) -> Result<bool, PairingError> {
        Ok(self.0.lock().map_err(|_| storage_error())?.as_deref() == Some(id))
    }

    fn stop(&self, id: &str) -> Result<(), PairingError> {
        let mut active = self.0.lock().map_err(|_| storage_error())?;
        if active.as_deref() == Some(id) {
            *active = None;
        }
        Ok(())
    }
}

fn storage_error() -> PairingError {
    PairingError::Personal(PersonalServerError::Storage)
}

fn store(local: &LocalDataState) -> Result<Arc<Store>, PairingError> {
    local.store().ok_or_else(storage_error)
}

/// The D-114 one-time display exception. Never used by the general status command.
#[derive(Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PairingPasswordDisplay {
    /// Public local ceremony state.
    pub status: PairingStatus,
    /// Display once on the new device; never save or automatically copy this value.
    pub password: String,
}

impl Drop for PairingPasswordDisplay {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// Inspect the encrypted local pairing checkpoint without network access.
#[tauri::command]
#[specta::specta]
pub async fn personal_pairing_status(
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PairingStatus, PairingError> {
    let store = store(&local)?;
    personal.pairing_status(&store)
}

/// Explicitly create a new-device session and display its password once.
#[tauri::command]
#[specta::specta]
pub async fn create_personal_pairing(
    origin: String,
    device_name: String,
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PairingPasswordDisplay, PairingError> {
    let started = personal.pairing_create(store(&local)?, origin, device_name).await?;
    let password = std::str::from_utf8(started.password.as_bytes())
        .map_err(|_| PairingError::InvalidResponse)?
        .to_owned();
    Ok(PairingPasswordDisplay { status: started.status, password })
}

/// Submit the separate password through this write-only pairing boundary.
#[tauri::command]
#[specta::specta]
pub async fn join_personal_pairing(
    public_link: String,
    password: String,
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PairingStatus, PairingError> {
    personal.pairing_join(store(&local)?, public_link, Zeroizing::new(password)).await
}

/// Drive bounded Rust progress only while this explicitly started observer is attached.
#[tauri::command]
#[specta::specta]
pub async fn watch_personal_pairing(
    watch_id: String,
    messages: Channel<PairingStatus>,
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
    watches: tauri::State<'_, PairingWatchState>,
) -> Result<(), PairingError> {
    let store = store(&local)?;
    let result = async {
        loop {
            if !watches.current(&watch_id)? {
                return Ok(());
            }
            let status = personal.pairing_status(&store)?;
            if !progresses(status.phase) {
                return Ok(());
            }
            let status = personal.pairing_progress(store.clone()).await?;
            if !watches.current(&watch_id)? {
                return Ok(());
            }
            let progressing = progresses(status.phase);
            if messages.send(status).is_err() || !progressing {
                return Ok(());
            }
        }
    }
    .await;
    watches.stop(&watch_id)?;
    result
}

/// Register before scheduling an observer so an earlier detach cannot be undone.
#[tauri::command]
#[specta::specta]
pub fn prepare_personal_pairing_watch(
    watches: tauri::State<'_, PairingWatchState>,
) -> Result<String, PairingError> {
    watches.register()
}

fn progresses(phase: PairingPhase) -> bool {
    matches!(
        phase,
        PairingPhase::Waiting | PairingPhase::Exchanging | PairingPhase::WaitingAcceptance
    )
}

/// Stop this observer without cancelling or replacing the durable pairing checkpoint.
#[tauri::command]
#[specta::specta]
pub fn stop_personal_pairing_watch(
    watch_id: String,
    watches: tauri::State<'_, PairingWatchState>,
) -> Result<(), PairingError> {
    watches.stop(&watch_id)
}

/// Approve the authenticated peer metadata and prepare the exact membership handoff.
#[tauri::command]
#[specta::specta]
pub async fn confirm_personal_pairing(
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PairingStatus, PairingError> {
    personal.pairing_confirm(store(&local)?).await
}

/// Explicitly recover the saved ceremony without creating another identity or CPace attempt.
#[tauri::command]
#[specta::specta]
pub async fn recover_personal_pairing(
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PairingStatus, PairingError> {
    personal.pairing_recover(store(&local)?).await
}

/// Explicitly cancel the session while retaining any authenticated pending identity.
#[tauri::command]
#[specta::specta]
pub async fn cancel_personal_pairing(
    local: tauri::State<'_, LocalDataState>,
    personal: tauri::State<'_, PersonalServer>,
) -> Result<PairingStatus, PairingError> {
    personal.pairing_cancel(store(&local)?).await
}

#[cfg(test)]
mod tests {
    use super::PairingWatchState;

    #[test]
    fn detached_observer_cannot_clear_or_emit_for_its_replacement() {
        let watches = PairingWatchState::default();
        let old = watches.register().unwrap();
        let new = watches.register().unwrap();
        watches.stop(&old).unwrap();
        assert!(!watches.current(&old).unwrap());
        assert!(watches.current(&new).unwrap());
        watches.stop(&new).unwrap();
        assert!(!watches.current(&new).unwrap());
    }

    #[test]
    fn detached_registration_cannot_start_a_late_observer() {
        let watches = PairingWatchState::default();
        let id = watches.register().unwrap();
        watches.stop(&id).unwrap();
        assert!(!watches.current(&id).unwrap());
    }
}
