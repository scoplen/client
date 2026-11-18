// SPDX-License-Identifier: Apache-2.0

//! Protection of the local database key (`scoplen-docs/05-cryptography-and-keys.md` §9).
//!
//! The key is 32 random bytes generated on first launch. It is held in the
//! platform keystore. When the user sets a local passphrase, or the platform
//! has no keystore, it is additionally wrapped with a key derived from the
//! passphrase by Argon2id, and only that wrapped form is kept:
//!
//! | Protection | Where the key is kept |
//! |---|---|
//! | Keystore | The keystore holds the key. |
//! | Keystore and passphrase | The keystore holds the passphrase envelope. |
//! | Passphrase only | A file next to the store holds the passphrase envelope. |

use std::path::{Path, PathBuf};

use scoplen_client_platform::keystore::{Keystore, KeystoreError};
use scoplen_crypto::{
    Argon2idParams, LocalDatabaseKey, LocalDatabaseKeyEnvelope, generate_symmetric_key,
};
use serde::Serialize;
use specta::Type;

const SLOT_KEY: u8 = 1;
const SLOT_ENVELOPE: u8 = 2;
/// The passphrase envelope when there is no keystore.
const ENVELOPE_FILE: &str = "local-key.envelope";
/// The store; its presence distinguishes a first launch from a lost key.
pub const STORE_FILE: &str = "local.db";

/// How the local database key is protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum Protection {
    /// The platform keystore alone.
    Keystore,
    /// The platform keystore and a local passphrase.
    KeystoreAndPassphrase,
    /// A local passphrase alone, on a platform without a keystore.
    PassphraseOnly,
}

/// What is needed to open the store.
#[derive(Debug)]
pub enum Unlock {
    /// The key is available.
    Ready(LocalDatabaseKey, Protection),
    /// The key is protected by a passphrase the user must enter.
    NeedsPassphrase(Protection),
    /// First launch on a platform without a keystore: the user must choose a
    /// passphrase before anything can be stored.
    NeedsNewPassphrase,
}

/// A failure to obtain or change the local database key.
#[derive(Debug, thiserror::Error)]
pub enum LocalKeyError {
    /// The passphrase does not open the key.
    #[error("the passphrase is not correct")]
    WrongPassphrase,
    /// A passphrase was empty.
    #[error("the passphrase is empty")]
    EmptyPassphrase,
    /// The passphrase cannot be removed because there is no keystore to hold
    /// the key without it.
    #[error("this system has no keystore, so the local passphrase cannot be removed")]
    PassphraseRequired,
    /// The store exists but its key is gone from the keystore, so the store
    /// cannot be opened on this device.
    #[error("the local data exists but its key is missing from the {0}")]
    KeyMissing(&'static str),
    /// The stored key or envelope is malformed.
    #[error("the stored local database key is malformed")]
    Malformed,
    /// The platform keystore failed.
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
    /// A key operation failed.
    #[error("the local database key could not be generated or wrapped")]
    Crypto(#[source] scoplen_crypto::PrimitiveError),
    /// Reading or writing the envelope file failed.
    #[error("the local key file could not be {0}")]
    File(&'static str, #[source] std::io::Error),
}

/// Obtains and changes the local database key for the store in one directory.
pub struct LocalKeys {
    data_dir: PathBuf,
    keystore: Option<Box<dyn Keystore>>,
    params: Argon2idParams,
}

impl LocalKeys {
    /// Key protection for the store in `data_dir`, using `keystore` when the
    /// platform has one.
    pub fn new(data_dir: &Path, keystore: Option<Box<dyn Keystore>>) -> LocalKeys {
        LocalKeys { data_dir: data_dir.to_owned(), keystore, params: Argon2idParams::default() }
    }

    /// Uses cheaper Argon2id parameters; for tests only.
    #[cfg(test)]
    pub(crate) fn with_params(mut self, params: Argon2idParams) -> LocalKeys {
        self.params = params;
        self
    }

    /// The path of the store.
    pub fn store_path(&self) -> PathBuf {
        self.data_dir.join(STORE_FILE)
    }

    /// Determines what is needed to open the store. On first launch with a
    /// keystore, a new key is generated and stored, so the result is ready.
    pub fn begin(&self) -> Result<Unlock, LocalKeyError> {
        let store_exists = self.store_path().exists();
        match &self.keystore {
            Some(keystore) => match keystore.load()? {
                Some(slot) => stored_slot(&slot),
                None if store_exists => Err(LocalKeyError::KeyMissing(keystore.name())),
                None => {
                    let key = generate_symmetric_key().map_err(LocalKeyError::Crypto)?;
                    keystore.store(&slot(SLOT_KEY, key.as_ref()))?;
                    Ok(Unlock::Ready(key, Protection::Keystore))
                }
            },
            None if self.envelope_path().exists() => {
                Ok(Unlock::NeedsPassphrase(Protection::PassphraseOnly))
            }
            None if store_exists => Err(LocalKeyError::KeyMissing("local key file")),
            None => Ok(Unlock::NeedsNewPassphrase),
        }
    }

    pub(crate) fn existing(&self) -> Result<Unlock, LocalKeyError> {
        match &self.keystore {
            Some(keystore) => {
                stored_slot(&keystore.load()?.ok_or(LocalKeyError::KeyMissing(keystore.name()))?)
            }
            None if self.envelope_path().is_file() => {
                Ok(Unlock::NeedsPassphrase(Protection::PassphraseOnly))
            }
            None => Err(LocalKeyError::KeyMissing("local key file")),
        }
    }

    /// Opens the key with the user's passphrase.
    pub fn unlock(
        &self,
        passphrase: &str,
    ) -> Result<(LocalDatabaseKey, Protection), LocalKeyError> {
        let (envelope, protection) = match &self.keystore {
            Some(keystore) => {
                let slot = keystore.load()?.ok_or(LocalKeyError::KeyMissing(keystore.name()))?;
                match slot.split_first() {
                    Some((&SLOT_ENVELOPE, envelope)) => {
                        (envelope.to_vec(), Protection::KeystoreAndPassphrase)
                    }
                    _ => return Err(LocalKeyError::Malformed),
                }
            }
            None => (
                std::fs::read(self.envelope_path()).map_err(|e| LocalKeyError::File("read", e))?,
                Protection::PassphraseOnly,
            ),
        };
        let envelope =
            LocalDatabaseKeyEnvelope::decode(&envelope).map_err(|_| LocalKeyError::Malformed)?;
        let key =
            envelope.open(passphrase.as_bytes()).map_err(|_| LocalKeyError::WrongPassphrase)?;
        Ok((key, protection))
    }

    /// First launch without a keystore: generates the key under a passphrase.
    pub fn create_with_passphrase(
        &self,
        passphrase: &str,
    ) -> Result<LocalDatabaseKey, LocalKeyError> {
        let key = generate_symmetric_key().map_err(LocalKeyError::Crypto)?;
        self.set_passphrase(&key, passphrase)?;
        Ok(key)
    }

    /// Sets or changes the local passphrase. The key itself is unchanged, so
    /// the store does not need to be re-encrypted.
    pub fn set_passphrase(
        &self,
        key: &LocalDatabaseKey,
        passphrase: &str,
    ) -> Result<Protection, LocalKeyError> {
        if passphrase.is_empty() {
            return Err(LocalKeyError::EmptyPassphrase);
        }
        let mut salt = [0u8; 16];
        scoplen_crypto::random_bytes(&mut salt).map_err(LocalKeyError::Crypto)?;
        let nonce = scoplen_crypto::random_nonce().map_err(LocalKeyError::Crypto)?;
        let envelope = LocalDatabaseKeyEnvelope::wrap_with_parameters_and_nonce(
            passphrase.as_bytes(),
            key,
            self.params,
            salt,
            nonce,
        )
        .and_then(|e| e.encode())
        .map_err(LocalKeyError::Crypto)?;
        match &self.keystore {
            Some(keystore) => {
                keystore.store(&slot(SLOT_ENVELOPE, &envelope))?;
                Ok(Protection::KeystoreAndPassphrase)
            }
            None => {
                let path = self.envelope_path();
                let partial = path.with_extension("envelope.partial");
                std::fs::create_dir_all(&self.data_dir)
                    .map_err(|e| LocalKeyError::File("written", e))?;
                std::fs::write(&partial, &envelope)
                    .map_err(|e| LocalKeyError::File("written", e))?;
                std::fs::rename(&partial, &path).map_err(|e| LocalKeyError::File("written", e))?;
                Ok(Protection::PassphraseOnly)
            }
        }
    }

    /// Removes the local passphrase, leaving the key in the keystore alone.
    pub fn remove_passphrase(&self, key: &LocalDatabaseKey) -> Result<Protection, LocalKeyError> {
        let keystore = self.keystore.as_ref().ok_or(LocalKeyError::PassphraseRequired)?;
        keystore.store(&slot(SLOT_KEY, key.as_ref()))?;
        Ok(Protection::Keystore)
    }

    /// Forgets the key and moves the unreadable store aside, so that the user
    /// can start again after the key was lost. The old file is kept, renamed
    /// with the time, not deleted. Returns its new path.
    pub fn set_aside(&self) -> Result<Option<PathBuf>, LocalKeyError> {
        if let Some(keystore) = &self.keystore {
            keystore.delete()?;
        }
        let _ = std::fs::remove_file(self.envelope_path());
        let store = self.store_path();
        if !store.exists() {
            return Ok(None);
        }
        let stamp = scoplen_model::system_time_millis().unwrap_or_default();
        let aside = self.data_dir.join(format!("local.unreadable-{stamp}.db"));
        std::fs::rename(&store, &aside).map_err(|e| LocalKeyError::File("moved aside", e))?;
        for suffix in ["-wal", "-shm"] {
            let companion = PathBuf::from(format!("{}{suffix}", store.display()));
            let _ = std::fs::rename(&companion, format!("{}{suffix}", aside.display()));
        }
        Ok(Some(aside))
    }

    fn envelope_path(&self) -> PathBuf {
        self.data_dir.join(ENVELOPE_FILE)
    }
}

fn slot(tag: u8, bytes: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
    let mut slot = zeroize::Zeroizing::new(Vec::with_capacity(bytes.len() + 1));
    slot.push(tag);
    slot.extend_from_slice(bytes);
    slot
}

fn stored_slot(slot: &[u8]) -> Result<Unlock, LocalKeyError> {
    match slot.split_first() {
        Some((&SLOT_KEY, key)) => {
            let key = LocalDatabaseKey::from_slice(key).ok_or(LocalKeyError::Malformed)?;
            Ok(Unlock::Ready(key, Protection::Keystore))
        }
        Some((&SLOT_ENVELOPE, _)) => Ok(Unlock::NeedsPassphrase(Protection::KeystoreAndPassphrase)),
        _ => Err(LocalKeyError::Malformed),
    }
}

#[cfg(test)]
mod tests;
