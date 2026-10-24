// SPDX-License-Identifier: Apache-2.0

//! Opening the local store: obtaining its key, asking for the passphrase
//! when one is set, and changing how the key is protected.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use scoplen_client_platform::keystore::Keystore;
use scoplen_crypto::LocalDatabaseKey;
use serde::Serialize;
use specta::Type;

use crate::local_key::{LocalKeyError, LocalKeys, Protection, Unlock};
use crate::store::{Change, Store, StoreError, Subscription};

type ChangeListener = Arc<dyn Fn(&Change) + Send + Sync>;

/// Whether the local data can be used, and if not, what is needed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum Status {
    /// The store is open.
    Open {
        /// How its key is protected.
        protection: Protection,
    },
    /// The user must enter the local passphrase.
    NeedsPassphrase {
        /// How the key is protected.
        protection: Protection,
    },
    /// First launch without a keystore: the user must choose a passphrase.
    NeedsNewPassphrase,
    /// The store exists but cannot be opened on this device.
    Unreadable {
        /// Why.
        reason: UnreadableReason,
    },
}

/// Why the local store cannot be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum UnreadableReason {
    /// Its key is missing from the keystore.
    KeyMissing,
    /// The key does not decrypt it.
    WrongKey,
    /// It was written by a newer version of Scoplen.
    NewerVersion,
}

/// A failure of an operation on the local data, as shown to the user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type, thiserror::Error)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum LocalDataError {
    /// The passphrase is not correct. Nothing changed.
    #[error("the passphrase is not correct")]
    WrongPassphrase,
    /// The passphrase is empty. Nothing changed.
    #[error("the passphrase is empty")]
    EmptyPassphrase,
    /// The passphrase cannot be removed without a keystore. Nothing changed.
    #[error("the passphrase cannot be removed on this system")]
    PassphraseRequired,
    /// The operation needs the store to be in another state, for example
    /// unlocked. Nothing changed.
    #[error("the local data is not in a state that allows this")]
    InvalidState,
    /// The platform or the disk failed. Nothing changed.
    #[error("{reference}")]
    Failed {
        /// A diagnostic reference for support, free of secrets.
        reference: String,
    },
}

impl From<LocalKeyError> for LocalDataError {
    fn from(error: LocalKeyError) -> Self {
        match error {
            LocalKeyError::WrongPassphrase => LocalDataError::WrongPassphrase,
            LocalKeyError::EmptyPassphrase => LocalDataError::EmptyPassphrase,
            LocalKeyError::PassphraseRequired => LocalDataError::PassphraseRequired,
            other => LocalDataError::Failed { reference: diagnostic(&other) },
        }
    }
}

impl From<StoreError> for LocalDataError {
    fn from(error: StoreError) -> Self {
        LocalDataError::Failed { reference: diagnostic(&error) }
    }
}

/// The error and its causes on one line, for the user to copy into a report.
fn diagnostic(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

enum State {
    Locked(Status),
    Open {
        store: Arc<Store>,
        key: LocalDatabaseKey,
        protection: Protection,
        /// Keeps the change listener attached to this store; dropping it
        /// detaches the listener.
        subscription: Option<Subscription>,
    },
}

/// The device's local data and the state of its store.
pub struct LocalData {
    keys: LocalKeys,
    state: Mutex<State>,
    listener: Mutex<Option<ChangeListener>>,
}

impl LocalData {
    /// Prepares the local data in `data_dir`, opening the store when no
    /// passphrase is needed.
    pub fn start(
        data_dir: &Path,
        keystore: Option<Box<dyn Keystore>>,
    ) -> Result<LocalData, LocalDataError> {
        std::fs::create_dir_all(data_dir)
            .map_err(|e| LocalDataError::Failed { reference: diagnostic(&e) })?;
        LocalData::with_keys(LocalKeys::new(data_dir, keystore))
    }

    fn with_keys(keys: LocalKeys) -> Result<LocalData, LocalDataError> {
        let data = LocalData {
            keys,
            state: Mutex::new(State::Locked(Status::NeedsNewPassphrase)),
            listener: Mutex::new(None),
        };
        data.restart()?;
        Ok(data)
    }

    /// Where the local data stands.
    pub fn status(&self) -> Status {
        match &*self.state() {
            State::Locked(status) => status.clone(),
            State::Open { protection, .. } => Status::Open { protection: *protection },
        }
    }

    /// Calls `listener` after every committed change to the local data, in
    /// whichever store is open now or later.
    pub fn on_change(&self, listener: impl Fn(&Change) + Send + Sync + 'static) {
        let listener: ChangeListener = Arc::new(listener);
        *self.listener.lock().unwrap_or_else(|e| e.into_inner()) = Some(listener.clone());
        if let State::Open { store, subscription, .. } = &mut *self.state() {
            *subscription = Some(store.subscribe(move |change| listener(change)));
        }
    }

    /// The open store, if it is open.
    pub fn store(&self) -> Option<Arc<Store>> {
        match &*self.state() {
            State::Open { store, .. } => Some(store.clone()),
            State::Locked(_) => None,
        }
    }

    /// Run a bounded local operation while preventing store replacement.
    pub fn with_store<T>(&self, operation: impl FnOnce(&Arc<Store>) -> T) -> Option<T> {
        match &*self.state() {
            State::Open { store, .. } => Some(operation(store)),
            State::Locked(_) => None,
        }
    }

    /// Opens the store with the local passphrase.
    pub fn unlock(&self, passphrase: &str) -> Result<Status, LocalDataError> {
        let mut state = self.state();
        if !matches!(&*state, State::Locked(Status::NeedsPassphrase { .. })) {
            return Err(LocalDataError::InvalidState);
        }
        let (key, protection) = self.keys.unlock(passphrase)?;
        *state = self.open(key, protection)?;
        Ok(status_of(&state))
    }

    /// First launch without a keystore: creates the key under a passphrase
    /// and opens a new store.
    pub fn create(&self, passphrase: &str) -> Result<Status, LocalDataError> {
        let mut state = self.state();
        if !matches!(&*state, State::Locked(Status::NeedsNewPassphrase)) {
            return Err(LocalDataError::InvalidState);
        }
        let key = self.keys.create_with_passphrase(passphrase)?;
        *state = self.open(key, Protection::PassphraseOnly)?;
        Ok(status_of(&state))
    }

    /// Sets or changes the local passphrase of the open store.
    pub fn set_passphrase(&self, passphrase: &str) -> Result<Status, LocalDataError> {
        let mut state = self.state();
        let State::Open { key, protection, .. } = &mut *state else {
            return Err(LocalDataError::InvalidState);
        };
        *protection = self.keys.set_passphrase(key, passphrase)?;
        Ok(status_of(&state))
    }

    /// Removes the local passphrase of the open store.
    pub fn remove_passphrase(&self) -> Result<Status, LocalDataError> {
        let mut state = self.state();
        let State::Open { key, protection, .. } = &mut *state else {
            return Err(LocalDataError::InvalidState);
        };
        *protection = self.keys.remove_passphrase(key)?;
        Ok(status_of(&state))
    }

    /// Moves an unreadable store aside, keeping the file, and starts with
    /// empty local data.
    pub fn start_fresh(&self) -> Result<Status, LocalDataError> {
        if !matches!(&*self.state(), State::Locked(Status::Unreadable { .. })) {
            return Err(LocalDataError::InvalidState);
        }
        self.keys.set_aside()?;
        self.restart()?;
        Ok(self.status())
    }

    fn restart(&self) -> Result<(), LocalDataError> {
        let next = match self.keys.begin() {
            Ok(Unlock::Ready(key, protection)) => self.open(key, protection)?,
            Ok(Unlock::NeedsPassphrase(protection)) => {
                State::Locked(Status::NeedsPassphrase { protection })
            }
            Ok(Unlock::NeedsNewPassphrase) => State::Locked(Status::NeedsNewPassphrase),
            Err(LocalKeyError::KeyMissing(_)) => {
                State::Locked(Status::Unreadable { reason: UnreadableReason::KeyMissing })
            }
            Err(other) => return Err(other.into()),
        };
        *self.state() = next;
        Ok(())
    }

    fn open(&self, key: LocalDatabaseKey, protection: Protection) -> Result<State, LocalDataError> {
        match Store::open(&self.keys.store_path(), &key) {
            Ok(store) => {
                let store = Arc::new(store);
                let listener = self.listener.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let subscription =
                    listener.map(|listener| store.subscribe(move |change| listener(change)));
                Ok(State::Open { store, key, protection, subscription })
            }
            Err(StoreError::WrongKey) => {
                Ok(State::Locked(Status::Unreadable { reason: UnreadableReason::WrongKey }))
            }
            Err(StoreError::NewerSchema { .. }) => {
                Ok(State::Locked(Status::Unreadable { reason: UnreadableReason::NewerVersion }))
            }
            Err(other) => Err(other.into()),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn status_of(state: &State) -> Status {
    match state {
        State::Locked(status) => status.clone(),
        State::Open { protection, .. } => Status::Open { protection: *protection },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FAST, MemoryKeystore};

    fn start(dir: &Path, keystore: Option<&MemoryKeystore>) -> LocalData {
        let keystore = keystore.map(|k| Box::new(k.clone()) as Box<dyn Keystore>);
        LocalData::with_keys(LocalKeys::new(dir, keystore).with_params(FAST)).unwrap()
    }

    #[test]
    fn with_a_keystore_the_store_opens_without_asking() {
        let dir = tempfile::tempdir().unwrap();
        let data = start(dir.path(), Some(&MemoryKeystore::default()));
        assert_eq!(data.status(), Status::Open { protection: Protection::Keystore });
        assert!(data.store().is_some());
    }

    #[test]
    fn a_passphrase_locks_the_next_launch_until_entered() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = MemoryKeystore::default();
        let device = {
            let data = start(dir.path(), Some(&keystore));
            assert_eq!(data.set_passphrase("").unwrap_err(), LocalDataError::EmptyPassphrase);
            data.set_passphrase("pass phrase").unwrap();
            data.store().unwrap().device_id()
        };
        let data = start(dir.path(), Some(&keystore));
        assert_eq!(
            data.status(),
            Status::NeedsPassphrase { protection: Protection::KeystoreAndPassphrase }
        );
        assert!(data.store().is_none());
        assert_eq!(data.set_passphrase("x").unwrap_err(), LocalDataError::InvalidState);
        assert_eq!(data.unlock("wrong").unwrap_err(), LocalDataError::WrongPassphrase);
        assert_eq!(
            data.status(),
            Status::NeedsPassphrase { protection: Protection::KeystoreAndPassphrase }
        );
        data.unlock("pass phrase").unwrap();
        assert_eq!(data.store().unwrap().device_id(), device, "the same store opened");
        assert_eq!(
            data.remove_passphrase().unwrap(),
            Status::Open { protection: Protection::Keystore }
        );
    }

    #[test]
    fn without_a_keystore_the_first_launch_asks_for_a_new_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let data = start(dir.path(), None);
        assert_eq!(data.status(), Status::NeedsNewPassphrase);
        assert_eq!(data.unlock("x").unwrap_err(), LocalDataError::InvalidState);
        data.create("chosen").unwrap();
        assert_eq!(data.status(), Status::Open { protection: Protection::PassphraseOnly });
        assert_eq!(data.remove_passphrase().unwrap_err(), LocalDataError::PassphraseRequired);

        let again = start(dir.path(), None);
        assert_eq!(
            again.status(),
            Status::NeedsPassphrase { protection: Protection::PassphraseOnly }
        );
        again.unlock("chosen").unwrap();
    }

    #[test]
    fn a_store_whose_key_is_lost_can_be_set_aside() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = MemoryKeystore::default();
        drop(start(dir.path(), Some(&keystore)));
        keystore.delete().unwrap();

        let data = start(dir.path(), Some(&keystore));
        assert_eq!(data.status(), Status::Unreadable { reason: UnreadableReason::KeyMissing });
        assert_eq!(data.start_fresh().unwrap(), Status::Open { protection: Protection::Keystore });
        let kept = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().starts_with("local.unreadable-"));
        assert!(kept, "the unreadable store is kept, not deleted");
        assert_eq!(data.start_fresh().unwrap_err(), LocalDataError::InvalidState);
    }

    #[test]
    fn a_wrong_key_in_the_keystore_makes_the_store_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let keystore = MemoryKeystore::default();
        drop(start(dir.path(), Some(&keystore)));
        let mut other = vec![1u8];
        other.extend([0x55; 32]);
        keystore.store(&other).unwrap();
        let data = start(dir.path(), Some(&keystore));
        assert_eq!(data.status(), Status::Unreadable { reason: UnreadableReason::WrongKey });
    }

    #[test]
    fn change_listeners_follow_the_store_across_unlocking() {
        use std::sync::Mutex as StdMutex;
        let dir = tempfile::tempdir().unwrap();
        let keystore = MemoryKeystore::default();
        drop(start(dir.path(), Some(&keystore)).set_passphrase("p"));
        let data = start(dir.path(), Some(&keystore));
        let heard = Arc::new(StdMutex::new(0));
        let count = heard.clone();
        data.on_change(move |_| *count.lock().unwrap() += 1);
        data.unlock("p").unwrap();
        let store = data.store().unwrap();
        let hosts = crate::repository::Repository::<crate::repository::Host>::new(&store);
        hosts
            .create(crate::repository::HostChange {
                name: Some("a".into()),
                address: Some("a".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(*heard.lock().unwrap(), 1);
    }

    #[test]
    fn failures_carry_a_reference_without_secrets() {
        let error: LocalDataError = LocalKeyError::Malformed.into();
        assert_eq!(
            error,
            LocalDataError::Failed {
                reference: "the stored local database key is malformed".into()
            }
        );
    }
}
