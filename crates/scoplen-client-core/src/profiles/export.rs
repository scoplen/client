// SPDX-License-Identifier: Apache-2.0
//! Existing-store reads for explicit OpenSSH generation, without desktop startup effects.

use super::*;
use crate::{
    local_key::{LocalKeyError, STORE_FILE, Unlock},
    store::StoreError,
};

/// A content-free refusal to open existing Local or Personal data for OpenSSH generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OpenSshExportProfileError {
    /// The command never initializes missing data.
    #[error("Existing local data was not found. Open the desktop client to set it up first.")]
    MissingData,
    /// The desktop must migrate an older store; a newer store needs a matching client.
    #[error("This store needs a matching desktop version. Open it there before generating config.")]
    Schema,
    /// The required existing local passphrase was not supplied.
    #[error("This store is locked. Supply its local passphrase file and try again.")]
    Locked,
    /// The supplied local passphrase did not open the existing key.
    #[error("The local passphrase is not correct. Check the selected passphrase file.")]
    WrongPassphrase,
    /// Existing local key material is missing or unavailable on this device.
    #[error(
        "The existing local key is unavailable. Unlock this store in the desktop client first."
    )]
    KeyUnavailable,
    /// The existing native slot requires OS permission before it can be read.
    #[error(
        "The system keychain requires user interaction. Unlock it or authorize this helper in an interactive session."
    )]
    InteractionRequired,
    /// Only a ready installed Account profile may be selected.
    #[error("This ready account profile was not found. Use --list-profiles to choose one.")]
    ProfileUnavailable,
    /// Stored immutable identity or retained offline keys did not verify.
    #[error(
        "The saved account identity or keys could not be verified. Reopen its desktop profile."
    )]
    Verification,
    /// A previously captured ready profile changed before publication.
    #[error("The saved profile changed after review. Review the command again.")]
    ContextChanged,
    /// An existing encrypted file or catalog could not be read.
    #[error("The existing local data could not be read. Check it in the desktop client.")]
    ReadFailed,
}

/// A bounded export opening of one explicit namespace, independent of desktop selection.
pub struct OpenSshExportProfile {
    catalog: Arc<Store>,
    store: Arc<Store>,
    record: Option<ProfileRecord>,
}

impl OpenSshExportProfile {
    /// List ready saved Account profiles without selecting one or changing the catalog.
    ///
    /// # Errors
    /// Requires existing, unlocked Local data with the current schema and valid catalog rows.
    pub fn list(
        data_dir: &Path,
        passphrase: Option<&str>,
    ) -> Result<Vec<AccountProfile>, OpenSshExportProfileError> {
        let keys: KeyStoreFactory = Arc::new(scoplen_client_platform::keystore::local_key_store);
        Self::list_with_keystores(data_dir, passphrase, &keys)
    }

    /// Read one existing Local namespace (`None`) or ready Personal Account profile.
    /// The catalog and selected Account store retain independent local passphrases.
    ///
    /// # Errors
    /// Refuses missing data, keys, older/newer schemas, incomplete or unverifiable profiles.
    pub fn open(
        data_dir: &Path,
        profile: Option<Uuid>,
        catalog_passphrase: Option<&str>,
        passphrase: Option<&str>,
    ) -> Result<Self, OpenSshExportProfileError> {
        let keys: KeyStoreFactory = Arc::new(scoplen_client_platform::keystore::local_key_store);
        Self::with_keystores(data_dir, profile, catalog_passphrase, passphrase, &keys)
    }

    /// The read-only store supplying the existing inventory renderer.
    pub fn store(&self) -> Arc<Store> {
        self.store.clone()
    }

    /// Recheck the captured installed identity and offline key state before publication.
    ///
    /// # Errors
    /// Refuses changed catalog/binding/bootstrap state without selecting or restarting anything.
    pub fn recheck(&self) -> Result<(), OpenSshExportProfileError> {
        match &self.record {
            Some(expected) => {
                let current = self
                    .catalog
                    .profile_record(expected.profile.id)
                    .map_err(read_error)?
                    .ok_or(OpenSshExportProfileError::ContextChanged)?;
                if !current.profile.ready || !crate::store::profiles::same(&current, expected) {
                    return Err(OpenSshExportProfileError::ContextChanged);
                }
                let binding = self.store.account_profile_binding().map_err(read_error)?;
                if !binding
                    .as_ref()
                    .is_some_and(|actual| crate::store::profiles::same(actual, expected))
                {
                    return Err(OpenSshExportProfileError::ContextChanged);
                }
                load_retained_bootstrap(&self.store)
                    .map_err(|_| OpenSshExportProfileError::Verification)?
                    .ok_or(OpenSshExportProfileError::Verification)?;
            }
            None => {
                if self.store.account_profile_binding().map_err(read_error)?.is_some()
                    || self.store.personal_record().map_err(read_error)?.is_some()
                {
                    return Err(OpenSshExportProfileError::ContextChanged);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn with_keystores(
        data_dir: &Path,
        profile: Option<Uuid>,
        catalog_passphrase: Option<&str>,
        passphrase: Option<&str>,
        keys: &KeyStoreFactory,
    ) -> Result<Self, OpenSshExportProfileError> {
        let local_passphrase = if profile.is_none() { passphrase } else { catalog_passphrase };
        let catalog = existing_store(data_dir, None, local_passphrase, keys)?;
        let (store, record) = match profile {
            Some(id) => {
                let record = catalog
                    .profile_record(id)
                    .map_err(read_error)?
                    .filter(|record| record.profile.ready)
                    .ok_or(OpenSshExportProfileError::ProfileUnavailable)?;
                validate(&record.profile).map_err(|_| OpenSshExportProfileError::Verification)?;
                let accounts = data_dir.join("accounts");
                no_link(&accounts).map_err(|_| OpenSshExportProfileError::Verification)?;
                let directory = accounts.join(id.to_string());
                no_link(&directory).map_err(|_| OpenSshExportProfileError::Verification)?;
                let store = existing_store(&directory, Some(&record), passphrase, keys)?;
                (store, Some(record))
            }
            None => (catalog.clone(), None),
        };
        let opening = Self { catalog, store, record };
        opening.recheck()?;
        Ok(opening)
    }

    pub(crate) fn list_with_keystores(
        data_dir: &Path,
        passphrase: Option<&str>,
        keys: &KeyStoreFactory,
    ) -> Result<Vec<AccountProfile>, OpenSshExportProfileError> {
        let catalog = existing_store(data_dir, None, passphrase, keys)?;
        let profiles = catalog.profile_catalog().map_err(read_error)?;
        if profiles.len() > 128 {
            return Err(OpenSshExportProfileError::Verification);
        }
        for profile in &profiles {
            validate(profile).map_err(|_| OpenSshExportProfileError::Verification)?;
        }
        Ok(profiles.into_iter().filter(|profile| profile.ready).collect())
    }
}

fn existing_store(
    directory: &Path,
    profile: Option<&ProfileRecord>,
    passphrase: Option<&str>,
    keys: &KeyStoreFactory,
) -> Result<Arc<Store>, OpenSshExportProfileError> {
    let path = directory.join(STORE_FILE);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => return Err(OpenSshExportProfileError::Verification),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(OpenSshExportProfileError::MissingData);
        }
        Err(_) => return Err(OpenSshExportProfileError::ReadFailed),
    }
    let keys = LocalKeys::new(directory, keys(directory));
    let key = match keys.existing().map_err(key_error)? {
        Unlock::Ready(key, _) => key,
        Unlock::NeedsPassphrase(_) => {
            let passphrase = passphrase
                .filter(|text| !text.is_empty())
                .ok_or(OpenSshExportProfileError::Locked)?;
            keys.unlock(passphrase).map_err(key_error)?.0
        }
        Unlock::NeedsNewPassphrase => return Err(OpenSshExportProfileError::KeyUnavailable),
    };
    Store::open_export_profile(&path, &key, profile).map(Arc::new).map_err(read_error)
}

fn key_error(error: LocalKeyError) -> OpenSshExportProfileError {
    match error {
        LocalKeyError::Keystore(
            scoplen_client_platform::keystore::KeystoreError::InteractionRequired,
        ) => OpenSshExportProfileError::InteractionRequired,
        LocalKeyError::WrongPassphrase => OpenSshExportProfileError::WrongPassphrase,
        _ => OpenSshExportProfileError::KeyUnavailable,
    }
}

fn read_error(error: StoreError) -> OpenSshExportProfileError {
    match error {
        StoreError::NewerSchema { .. } | StoreError::MigrationRequired => {
            OpenSshExportProfileError::Schema
        }
        StoreError::AccountContext | StoreError::InvalidIdentifier => {
            OpenSshExportProfileError::Verification
        }
        StoreError::WrongKey => OpenSshExportProfileError::KeyUnavailable,
        _ => OpenSshExportProfileError::ReadFailed,
    }
}

#[cfg(test)]
mod tests;
