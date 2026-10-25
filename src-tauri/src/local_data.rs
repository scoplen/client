// SPDX-License-Identifier: Apache-2.0

//! Commands for opening the local store and protecting its key.

use std::path::PathBuf;
use std::sync::Arc;

use scoplen_client_core::local_data::{LocalData, LocalDataError, Status};
use tauri::Manager as _;
use zeroize::Zeroizing;

/// The local data, or why it could not be prepared at startup.
pub struct LocalDataState(Result<Arc<LocalData>, LocalDataError>);

impl LocalDataState {
    /// Prepares the local data in the application's data directory, or in
    /// `SPL_DATA_DIR` when that is set (used by tests and launch checks to
    /// keep their data separate).
    pub fn start(app: &tauri::AppHandle) -> LocalDataState {
        let dir = match std::env::var_os("SPL_DATA_DIR") {
            Some(dir) => Ok(PathBuf::from(dir)),
            None => app
                .path()
                .app_data_dir()
                .map_err(|e| LocalDataError::Failed { reference: e.to_string() }),
        };
        let data = dir.and_then(|dir| {
            let keystore = scoplen_client_platform::keystore::local_key_store(&dir);
            LocalData::start(&dir, keystore)
        });
        LocalDataState(data.map(Arc::new))
    }

    /// Forwards committed changes, if the local data could be prepared.
    pub fn on_change(
        &self,
        listener: impl Fn(&scoplen_client_core::store::Change) + Send + Sync + 'static,
    ) {
        if let Ok(data) = &self.0 {
            data.on_change(listener);
        }
    }

    /// The open store, if the local data is open.
    pub fn store(&self) -> Option<Arc<scoplen_client_core::store::Store>> {
        self.0.as_ref().ok().and_then(|data| data.store())
    }

    /// Prevent local-store replacement during one bounded persistence operation.
    pub fn with_store<T>(
        &self,
        operation: impl FnOnce(&Arc<scoplen_client_core::store::Store>) -> T,
    ) -> Option<T> {
        self.0.as_ref().ok().and_then(|data| data.with_store(operation))
    }

    pub(crate) fn get(&self) -> Result<Arc<LocalData>, LocalDataError> {
        self.0.clone()
    }
}

/// Runs a key operation off the interface thread: deriving a key from a
/// passphrase deliberately takes about a second.
async fn blocking<T: Send + 'static>(
    state: &LocalDataState,
    operation: impl FnOnce(&LocalData) -> Result<T, LocalDataError> + Send + 'static,
) -> Result<T, LocalDataError> {
    let data = state.get()?;
    tauri::async_runtime::spawn_blocking(move || operation(&data))
        .await
        .map_err(|e| LocalDataError::Failed { reference: e.to_string() })?
}

/// Where the local data stands.
#[tauri::command]
#[specta::specta]
pub fn local_data_status(
    state: tauri::State<'_, LocalDataState>,
) -> Result<Status, LocalDataError> {
    Ok(state.get()?.status())
}

/// Opens the store with the local passphrase.
#[tauri::command]
#[specta::specta]
pub async fn unlock_local_data(
    app: tauri::AppHandle,
    state: tauri::State<'_, LocalDataState>,
    passphrase: String,
) -> Result<Status, LocalDataError> {
    let passphrase = Zeroizing::new(passphrase);
    let status = blocking(&state, move |data| data.unlock(&passphrase)).await?;
    background_store(&app, &state);
    Ok(status)
}

/// On a system without a keystore, chooses the passphrase for new local data.
#[tauri::command]
#[specta::specta]
pub async fn create_local_passphrase(
    app: tauri::AppHandle,
    state: tauri::State<'_, LocalDataState>,
    passphrase: String,
) -> Result<Status, LocalDataError> {
    let passphrase = Zeroizing::new(passphrase);
    let status = blocking(&state, move |data| data.create(&passphrase)).await?;
    background_store(&app, &state);
    Ok(status)
}

/// Sets or changes the local passphrase.
#[tauri::command]
#[specta::specta]
pub async fn set_local_passphrase(
    state: tauri::State<'_, LocalDataState>,
    passphrase: String,
) -> Result<Status, LocalDataError> {
    let passphrase = Zeroizing::new(passphrase);
    blocking(&state, move |data| data.set_passphrase(&passphrase)).await
}

/// Removes the local passphrase, leaving the key in the keystore.
#[tauri::command]
#[specta::specta]
pub async fn remove_local_passphrase(
    state: tauri::State<'_, LocalDataState>,
) -> Result<Status, LocalDataError> {
    blocking(&state, |data| data.remove_passphrase()).await
}

/// Keeps unreadable local data aside and starts with empty local data.
#[tauri::command]
#[specta::specta]
pub async fn start_with_empty_local_data(
    app: tauri::AppHandle,
    state: tauri::State<'_, LocalDataState>,
) -> Result<Status, LocalDataError> {
    if !matches!(state.get()?.status(), Status::Unreadable { .. }) {
        return Err(LocalDataError::InvalidState);
    }
    app.state::<crate::forwards::ForwardManager>().stop_all().await.map_err(|_| {
        LocalDataError::Failed {
            reference: "Existing tunnels could not be stopped before replacing local data".into(),
        }
    })?;
    let runtime = app.state::<Arc<scoplen_client_core::personal_server::PersonalSyncRuntime>>();
    runtime.set_store(None);
    let result = blocking(&state, |data| data.start_fresh()).await;
    background_store(&app, &state);
    result
}

fn background_store(app: &tauri::AppHandle, local: &LocalDataState) {
    app.state::<Arc<scoplen_client_core::personal_server::PersonalSyncRuntime>>()
        .set_store(local.store());
}
