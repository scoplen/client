// SPDX-License-Identifier: Apache-2.0
//! Profile-bound native file selection and publication for portable inventory archives.

use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use crate::profile_context::ProfileRequest;
use scoplen_client_core::{
    locale::Locale,
    portable_archive::{
        ArchiveSecretMode, ExportOptions, ExportResult, ImportConsent, ImportPreview, ImportResult,
        PortableArchiveError, PortableArchives,
    },
};
use scoplen_crypto::PortableExportPassphrase;
use tauri_plugin_dialog::DialogExt as _;

#[derive(Clone)]
struct Source {
    path: PathBuf,
    generation: String,
}

#[derive(Default)]
/// Selected paths and secret-free reviews remain in Rust, outside frontend and receipts.
pub struct PortableArchiveState {
    archives: PortableArchives,
    source: Mutex<Option<Source>>,
}

impl PortableArchiveState {
    fn select(&self, path: PathBuf, generation: String) {
        self.archives.clear();
        *self.source.lock().unwrap_or_else(|error| error.into_inner()) =
            Some(Source { path, generation });
    }

    fn source(&self, generation: &str) -> Result<PathBuf, PortableArchiveError> {
        let source = self.source.lock().unwrap_or_else(|error| error.into_inner());
        let source = source.as_ref().ok_or(PortableArchiveError::PreviewExpired)?;
        if source.generation != generation {
            return Err(PortableArchiveError::ContextChanged);
        }
        Ok(source.path.clone())
    }

    fn clear(&self) {
        self.archives.clear();
        self.source.lock().unwrap_or_else(|error| error.into_inner()).take();
    }
}

fn passphrase(
    value: Option<String>,
) -> Result<Option<PortableExportPassphrase>, PortableArchiveError> {
    value
        .map(PortableExportPassphrase::new)
        .transpose()
        .map_err(|_| PortableArchiveError::PassphraseRequired)
}

/// Select a source or reread the selected file; no decrypted fields cross IPC.
#[tauri::command]
#[specta::specta]
pub async fn portable_archive_preview(
    local: ProfileRequest,
    state: tauri::State<'_, Arc<PortableArchiveState>>,
    app: tauri::AppHandle,
    choose_file: bool,
    passphrase: Option<String>,
    locale: Locale,
) -> Result<Option<ImportPreview>, PortableArchiveError> {
    let passphrase = self::passphrase(passphrase)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        if local.store().is_none() {
            return Err(PortableArchiveError::ContextChanged);
        }
        if choose_file {
            let title = match locale {
                Locale::En => "Choose a Scoplen inventory archive",
                Locale::ZhHans => "选择 Scoplen 资产文件",
            };
            let Some(path) = app
                .dialog()
                .file()
                .set_title(title)
                .add_filter("Scoplen JSON / age", &["json", "age"])
                .blocking_pick_file()
            else {
                return Ok(None);
            };
            state.select(
                path.into_path().map_err(|_| PortableArchiveError::Io)?,
                local.generation(),
            );
        }
        let path = state.source(&local.generation())?;
        let file = File::open(path).map_err(|_| PortableArchiveError::Io)?;
        local
            .with_store(|store| {
                state.archives.preview(store, BufReader::new(file), passphrase.as_ref())
            })
            .unwrap_or(Err(PortableArchiveError::ContextChanged))
            .map(Some)
    })
    .await
    .map_err(|_| PortableArchiveError::Storage)?
}

/// Reopen the Rust-selected source and atomically apply exactly the reviewed import.
#[tauri::command]
#[specta::specta]
pub async fn portable_archive_import(
    local: ProfileRequest,
    state: tauri::State<'_, Arc<PortableArchiveState>>,
    preview_id: String,
    passphrase: Option<String>,
    consent: ImportConsent,
) -> Result<ImportResult, PortableArchiveError> {
    let passphrase = self::passphrase(passphrase)?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let path = state.source(&local.generation())?;
        let file = File::open(path).map_err(|_| PortableArchiveError::Io)?;
        let result = local
            .with_store(|store| {
                state.archives.import(
                    store,
                    BufReader::new(file),
                    passphrase.as_ref(),
                    &preview_id,
                    consent,
                )
            })
            .unwrap_or(Err(PortableArchiveError::ContextChanged))?;
        state.clear();
        Ok(result)
    })
    .await
    .map_err(|_| PortableArchiveError::Storage)?
}

/// Write only finalized output bytes to a new file selected by the user.
#[tauri::command]
#[specta::specta]
pub async fn portable_archive_export(
    local: ProfileRequest,
    state: tauri::State<'_, Arc<PortableArchiveState>>,
    app: tauri::AppHandle,
    options: ExportOptions,
    passphrase: Option<String>,
    locale: Locale,
) -> Result<Option<ExportResult>, PortableArchiveError> {
    let passphrase = self::passphrase(passphrase)?;
    if options.secrets == ArchiveSecretMode::Included && passphrase.is_none() {
        return Err(PortableArchiveError::PassphraseRequired);
    }
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        if local.store().is_none() {
            return Err(PortableArchiveError::ContextChanged);
        }
        let title = match locale {
            Locale::En => "Export Scoplen inventory",
            Locale::ZhHans => "导出 Scoplen 资产",
        };
        let (filename, extension) = match options.secrets {
            ArchiveSecretMode::Omitted => ("scoplen-export.json", "json"),
            ArchiveSecretMode::Included => ("scoplen-export.age", "age"),
        };
        let Some(path) = app
            .dialog()
            .file()
            .set_title(title)
            .set_file_name(filename)
            .add_filter("Scoplen", &[extension])
            .blocking_save_file()
        else {
            return Ok(None);
        };
        let path = path.into_path().map_err(|_| PortableArchiveError::Io)?;
        local
            .with_store(|store| {
                publish(&path, |file| {
                    state.archives.export(store, file, options, passphrase.as_ref())
                })
            })
            .unwrap_or(Err(PortableArchiveError::ContextChanged))
            .map(Some)
    })
    .await
    .map_err(|_| PortableArchiveError::Storage)?
}

/// Drop an abandoned source and its safe confirmation metadata.
#[tauri::command]
#[specta::specta]
pub async fn portable_archive_discard(
    local: ProfileRequest,
    state: tauri::State<'_, Arc<PortableArchiveState>>,
) -> Result<(), PortableArchiveError> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        if local.store().is_none() {
            return Err(PortableArchiveError::ContextChanged);
        }
        state.clear();
        Ok(())
    })
    .await
    .map_err(|_| PortableArchiveError::Storage)?
}

fn publish<T>(
    destination: &Path,
    write: impl FnOnce(&mut File) -> Result<T, PortableArchiveError>,
) -> Result<T, PortableArchiveError> {
    let parent = destination.parent().ok_or(PortableArchiveError::Io)?;
    let mut output = tempfile::Builder::new()
        .prefix(".scoplen-export-")
        .suffix(".partial")
        .tempfile_in(parent)
        .map_err(|_| PortableArchiveError::Io)?;
    // The core writes the selected output format directly: secret-bearing JSON reaches
    // this file only through the age writer, which must finish before publication.
    let result = write(output.as_file_mut())?;
    output.as_file().sync_all().map_err(|_| PortableArchiveError::Io)?;
    output.persist_noclobber(destination).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            PortableArchiveError::DestinationExists
        } else {
            PortableArchiveError::Io
        }
    })?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn incomplete_output_is_never_published_and_staging_is_removed() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("inventory.age");
        let result: Result<(), _> = publish(&destination, |output| {
            output.write_all(b"incomplete encrypted output").unwrap();
            assert!(!destination.exists());
            Err(PortableArchiveError::Encryption)
        });
        assert_eq!(result, Err(PortableArchiveError::Encryption));
        assert!(!destination.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn final_output_is_complete_and_never_replaces_an_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("inventory.json");
        publish(&destination, |output| {
            assert!(!destination.exists());
            output.write_all(b"completed output").map_err(|_| PortableArchiveError::Io)
        })
        .unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"completed output");
        let result = publish(&destination, |output| {
            output.write_all(b"replacement").map_err(|_| PortableArchiveError::Io)
        });
        assert_eq!(result, Err(PortableArchiveError::DestinationExists));
        assert_eq!(std::fs::read(&destination).unwrap(), b"completed output");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
