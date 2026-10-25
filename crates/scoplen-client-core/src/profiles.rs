// SPDX-License-Identifier: Apache-2.0
//! Independent Account stores; Local remains the catalog and never changes account identity.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use scoplen_client_platform::keystore::Keystore;
use scoplen_crypto::{SecretVec, validate_server_origin};
use tokio::sync::watch;
use uuid::Uuid;

use crate::{
    local_data::{LocalData, Status},
    local_key::LocalKeys,
    personal_server::{
        PersonalServerError, PersonalSyncRuntime, RegistrationError, load_retained_bootstrap,
    },
    store::{
        Store,
        personal::{PasswordLoginRecord, RegistrationRecord},
        profiles::ProfileRecord,
    },
};

/// Redacted catalog metadata. The Account identity is the canonical origin plus Account id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountProfile {
    /// Device-local directory identity, independent of the server's Account id.
    pub id: Uuid,
    /// Canonical deployment origin.
    pub origin: String,
    /// Account id within this origin.
    pub account_id: Uuid,
    /// This Account's Personal vault.
    pub personal_vault_id: Uuid,
    /// The independent Device identity retained from confirmed Account entry.
    pub device_id: Uuid,
    /// Original confirmed registration or Device-admission operation.
    pub operation_id: Uuid,
    /// Complete identity, current-device authentication and verified bootstrap were installed.
    /// This historical local flag does not claim the device is currently authorized online.
    pub ready: bool,
}

/// A captured open-profile generation. Resolve every bounded read/write through the catalog.
#[derive(Clone)]
pub struct ProfileLease {
    generation: i64,
    profile: Option<AccountProfile>,
    pub(crate) store: Arc<Store>,
}

impl ProfileLease {
    /// Account metadata, or None for the independent Local namespace.
    pub fn account(&self) -> Option<&AccountProfile> {
        self.profile.as_ref()
    }
    /// This opening's generation; reopening the same profile never reuses a generation.
    pub fn generation(&self) -> u64 {
        self.generation as u64
    }
}

impl std::fmt::Debug for ProfileLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileLease")
            .field("generation", &self.generation)
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

/// Content-free profile failures. Original keys, files and Local assets are retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AccountProfileError {
    /// The captured profile or Local catalog generation has changed.
    #[error("The open profile changed. Reopen the account view before continuing.")]
    ContextChanged,
    /// Another Personal operation owns the explicit network boundary.
    #[error("Another account operation is still running. Wait for it to finish.")]
    Busy,
    /// The catalog or requested Account store needs its own local passphrase.
    #[error("Unlock this profile with its local passphrase before continuing.")]
    Locked,
    /// A platform without a keystore needs an explicitly supplied local passphrase.
    #[error("Choose a local data passphrase to protect this profile on this system.")]
    PassphraseRequired,
    /// Retain existing profiles when the device-local catalog reaches its bounded capacity.
    #[error("This device already holds 128 account profiles. Its existing profiles were retained.")]
    Limit,
    /// No catalog entry matches the requested profile or operation.
    #[error("This account profile has not been installed on this device.")]
    NotFound,
    /// Existing files or identity belong to another operation or Account.
    #[error(
        "This profile belongs to another account or operation. Its existing data was retained."
    )]
    Conflict,
    /// A key, catalog or SQLCipher write failed.
    #[error("The account profile could not be saved. Its original data and keys were retained.")]
    Storage,
    /// The operation was explicitly cancelled.
    #[error("Account installation was cancelled. Its confirmed operation and keys were retained.")]
    Cancelled,
    /// Account entry has not reached exact committed confirmation.
    #[error("Confirm this account setup's original result before installing its profile.")]
    ConfirmationRequired,
    /// Local origin, identity, roots or shared artifacts failed validation.
    #[error(
        "The account identity or encrypted keys could not be verified. No usable profile was installed."
    )]
    Verification,
    /// Ordinary Device authentication or current-key verification failed.
    #[error(transparent)]
    Personal(#[from] PersonalServerError),
    /// Preparation validation failed without exposing private inputs.
    #[error(transparent)]
    Registration(#[from] RegistrationError),
    /// Password Device admission failed before usable installation.
    #[error(transparent)]
    PasswordLogin(#[from] crate::personal_server::PasswordLoginError),
}

type KeyStoreFactory = Arc<dyn Fn(&Path) -> Option<Box<dyn Keystore>> + Send + Sync>;

struct State {
    root: Arc<Store>,
    current: ProfileLease,
    selected_data: Option<Arc<LocalData>>,
    last_selected: Option<Uuid>,
}

pub(crate) struct ProfileUseGuard<'a> {
    _state: MutexGuard<'a, State>,
    _local: crate::local_data::CurrentStoreGuard<'a>,
}

/// Rust-owned profile catalog and selection. Construct after Local unlock, and run the supplied
/// PersonalSyncRuntime once on the native async runtime. Opening and key operations are synchronous
/// and belong on a blocking worker. This API never imports, adopts or uploads Local objects.
pub struct AccountProfiles {
    pub(crate) local: Arc<LocalData>,
    state: Mutex<State>,
    changes: watch::Sender<i64>,
    runtime: Arc<PersonalSyncRuntime>,
    keys: KeyStoreFactory,
    directory: PathBuf,
}

impl AccountProfiles {
    /// Start a new owner, preserving the last selected profile as a reopen hint. Local is the
    /// initial namespace until an explicit open; that open revalidates the saved Account binding.
    ///
    /// # Errors
    /// Requires unlocked account-free Local data and a writable encrypted catalog.
    pub fn new(
        local: Arc<LocalData>,
        runtime: Arc<PersonalSyncRuntime>,
    ) -> Result<Self, AccountProfileError> {
        Self::with_keystores(
            local,
            runtime,
            Arc::new(scoplen_client_platform::keystore::local_key_store),
        )
    }

    pub(crate) fn with_keystores(
        local: Arc<LocalData>,
        runtime: Arc<PersonalSyncRuntime>,
        keys: KeyStoreFactory,
    ) -> Result<Self, AccountProfileError> {
        let root = local.store().ok_or(AccountProfileError::Locked)?;
        let (generation, last_selected) = local
            .with_current_store(&root, || root.start_profile_catalog())
            .ok_or(AccountProfileError::ContextChanged)?
            .map_err(storage)?;
        runtime.set_store(None);
        let directory = root.data_dir().join("accounts");
        Ok(Self {
            local,
            state: Mutex::new(State {
                root: root.clone(),
                current: ProfileLease { generation, profile: None, store: root },
                selected_data: None,
                last_selected,
            }),
            changes: watch::channel(generation).0,
            runtime,
            keys,
            directory,
        })
    }

    /// Capture the active profile for a later operation or event.
    ///
    /// # Errors
    /// Rejects a replaced or closed Local catalog.
    pub fn current(&self) -> Result<ProfileLease, AccountProfileError> {
        self.with_state(None, |state| Ok(state.current.clone()))
    }

    /// Read safe catalog metadata, including retained installations that need an explicit retry.
    ///
    /// # Errors
    /// Rejects a replaced catalog, invalid metadata or more than 128 saved Account profiles.
    pub fn list(&self) -> Result<Vec<AccountProfile>, AccountProfileError> {
        self.with_state(None, |state| {
            let profiles = state.root.profile_catalog().map_err(storage)?;
            if profiles.len() > 128 {
                return Err(AccountProfileError::Conflict);
            }
            for profile in &profiles {
                validate(profile)?;
            }
            Ok(profiles)
        })
    }

    /// The last durable selection; it is a reopen hint and supplies no current authority.
    ///
    /// # Errors
    /// Rejects a replaced or closed catalog.
    pub fn last_selected(&self) -> Result<Option<Uuid>, AccountProfileError> {
        self.with_state(None, |state| Ok(state.last_selected))
    }

    /// Execute one bounded read/write in its captured namespace. Do not await or call back into
    /// this catalog inside the closure. A stale lease cannot resolve even equal object UUIDs.
    ///
    /// # Errors
    /// Rejects foreign or reopened profile generations before invoking the closure.
    pub fn with_current_store<T>(
        &self,
        lease: &ProfileLease,
        operation: impl FnOnce(&Arc<Store>) -> T,
    ) -> Result<T, AccountProfileError> {
        self.with_state(Some(lease), |_| Ok(operation(&lease.store)))
    }

    /// Reopen a fully installed Account using its own local key protection and a fresh Store Arc.
    /// The optional passphrase unlocks existing protection; it does not change an unlocked profile.
    /// Locally verified retained keys start the supplied background owner; errors preserve the
    /// previously selected namespace. No Account password or Local inventory is transferred.
    ///
    /// # Errors
    /// Rejects incomplete installations, wrong local passphrases, conflicts and invalid anchors.
    pub fn open(
        &self,
        id: Uuid,
        local_passphrase: Option<SecretVec>,
    ) -> Result<ProfileLease, AccountProfileError> {
        self.with_state(None, |state| {
            let record = state
                .root
                .profile_record(id)
                .map_err(storage)?
                .ok_or(AccountProfileError::NotFound)?;
            if !record.profile.ready {
                return Err(AccountProfileError::ConfirmationRequired);
            }
            let data = self.open_candidate(&record, local_passphrase)?;
            let store = data.store().ok_or(AccountProfileError::Locked)?;
            load_retained_bootstrap(&store)
                .map_err(|_| AccountProfileError::Verification)?
                .ok_or(AccountProfileError::Verification)?;
            let generation = state
                .root
                .select_profile(state.current.generation, Some(id), None)
                .map_err(storage)?;
            self.publish(state, record.profile, data, store, generation)
        })
    }

    /// Return to Local without moving, deleting or relabeling objects in any Account store.
    /// All previous leases are invalidated, including a previous opening of Local.
    ///
    /// # Errors
    /// Rejects a replaced catalog or failed local reopen/selection transaction.
    pub fn open_local(&self) -> Result<ProfileLease, AccountProfileError> {
        let mut state = self.state();
        self.local
            .with_current_store(&state.root, || {
                if state.root.profile_generation().map_err(storage)? != state.current.generation {
                    return Err(AccountProfileError::ContextChanged);
                }
                Ok(())
            })
            .ok_or(AccountProfileError::ContextChanged)??;
        let root = self.local.reopen_generation().map_err(|_| AccountProfileError::Storage)?;
        if root.device_id() != state.root.device_id() {
            return Err(AccountProfileError::Conflict);
        }
        state.root = root.clone();
        let generation = self
            .local
            .with_current_store(&root, || root.select_profile(state.current.generation, None, None))
            .ok_or(AccountProfileError::ContextChanged)?
            .map_err(storage)?;
        self.runtime.set_store(None);
        self.changes.send_replace(generation);
        state.current = ProfileLease { generation, profile: None, store: root };
        state.selected_data = None;
        state.last_selected = None;
        Ok(state.current.clone())
    }

    pub(crate) fn changes(&self) -> watch::Receiver<i64> {
        self.changes.subscribe()
    }

    pub(crate) fn generation_guard(
        &self,
        lease: &ProfileLease,
    ) -> Result<ProfileUseGuard<'_>, AccountProfileError> {
        let state = self.state();
        let local = self
            .local
            .current_store_guard(&state.root)
            .ok_or(AccountProfileError::ContextChanged)?;
        if state.current.generation != lease.generation
            || !Arc::ptr_eq(&state.current.store, &lease.store)
            || state.root.profile_generation().map_err(storage)? != lease.generation
        {
            return Err(AccountProfileError::ContextChanged);
        }
        Ok(ProfileUseGuard { _state: state, _local: local })
    }

    pub(crate) fn root_record(
        &self,
        lease: &ProfileLease,
        operation: Uuid,
    ) -> Result<(Option<RegistrationRecord>, Option<ProfileRecord>), AccountProfileError> {
        self.with_state(Some(lease), |state| {
            if lease.profile.is_some() {
                return Err(AccountProfileError::ContextChanged);
            }
            let pending = state.root.pending_registration().map_err(storage)?;
            let profile = state
                .root
                .profile_catalog()
                .map_err(storage)?
                .into_iter()
                .find(|p| p.operation_id == operation)
                .map(|p| state.root.profile_record(p.id))
                .transpose()
                .map_err(storage)?
                .flatten();
            Ok((pending, profile))
        })
    }

    pub(crate) fn root_password_login_record(
        &self,
        lease: &ProfileLease,
        operation: Uuid,
    ) -> Result<(Option<PasswordLoginRecord>, Option<ProfileRecord>), AccountProfileError> {
        self.with_state(Some(lease), |state| {
            if lease.profile.is_some() {
                return Err(AccountProfileError::ContextChanged);
            }
            let pending = state.root.pending_password_login().map_err(storage)?;
            let existing = state
                .root
                .profile_catalog()
                .map_err(storage)?
                .into_iter()
                .find(|p| p.operation_id == operation)
                .map(|p| state.root.profile_record(p.id))
                .transpose()
                .map_err(storage)?
                .flatten();
            Ok((pending, existing))
        })
    }

    pub(crate) fn reserve(
        &self,
        lease: &ProfileLease,
        candidate: &ProfileRecord,
        pending: &RegistrationRecord,
    ) -> Result<ProfileRecord, AccountProfileError> {
        self.with_state(Some(lease), |state| {
            state
                .root
                .reserve_profile(candidate, pending, state.current.generation)
                .map_err(storage)
        })
    }

    pub(crate) fn open_candidate(
        &self,
        record: &ProfileRecord,
        passphrase: Option<SecretVec>,
    ) -> Result<Arc<LocalData>, AccountProfileError> {
        validate(&record.profile)?;
        let directory = self.directory.clone();
        no_link(&directory)?;
        std::fs::create_dir_all(&directory).map_err(|_| AccountProfileError::Storage)?;
        let directory = directory.join(record.profile.id.to_string());
        no_link(&directory)?;
        if record.profile.ready && !directory.join("local.db").is_file() {
            return Err(AccountProfileError::Storage);
        }
        std::fs::create_dir_all(&directory).map_err(|_| AccountProfileError::Storage)?;
        no_link(&directory.join("local.db"))?;
        let keys = LocalKeys::new(&directory, (self.keys)(&directory));
        let data = LocalData::with_profile(keys, Some(record.clone()))
            .map_err(|_| AccountProfileError::Storage)?;
        let text = passphrase
            .as_ref()
            .map(|p| std::str::from_utf8(p.as_bytes()).map_err(|_| AccountProfileError::Locked))
            .transpose()?;
        match data.status() {
            Status::Open { .. } => {}
            Status::NeedsPassphrase { .. } => {
                data.unlock(text.ok_or(AccountProfileError::Locked)?)
                    .map_err(|_| AccountProfileError::Locked)?;
            }
            Status::NeedsNewPassphrase => {
                data.create(text.ok_or(AccountProfileError::PassphraseRequired)?)
                    .map_err(|_| AccountProfileError::Storage)?;
            }
            Status::Unreadable { .. } => return Err(AccountProfileError::Storage),
        }
        Ok(Arc::new(data))
    }

    pub(crate) fn finish(
        &self,
        lease: &ProfileLease,
        record: &ProfileRecord,
        pending: Option<&RegistrationRecord>,
        data: Arc<LocalData>,
    ) -> Result<ProfileLease, AccountProfileError> {
        self.with_state(Some(lease), |state| {
            let store = data.store().ok_or(AccountProfileError::Locked)?;
            let generation = state
                .root
                .select_profile(state.current.generation, Some(record.profile.id), pending)
                .map_err(storage)?;
            let mut profile = record.profile.clone();
            profile.ready = true;
            self.publish(state, profile, data, store, generation)
        })
    }

    fn publish(
        &self,
        state: &mut State,
        profile: AccountProfile,
        data: Arc<LocalData>,
        store: Arc<Store>,
        generation: i64,
    ) -> Result<ProfileLease, AccountProfileError> {
        self.runtime.set_store(None);
        self.changes.send_replace(generation);
        state.last_selected = Some(profile.id);
        state.current = ProfileLease { generation, profile: Some(profile), store: store.clone() };
        state.selected_data = Some(data);
        self.runtime.set_store(Some(store));
        Ok(state.current.clone())
    }

    fn with_state<T>(
        &self,
        lease: Option<&ProfileLease>,
        operation: impl FnOnce(&mut State) -> Result<T, AccountProfileError>,
    ) -> Result<T, AccountProfileError> {
        let mut state = self.state();
        let root = state.root.clone();
        self.local
            .with_current_store(&root, || {
                if root.profile_generation().map_err(storage)? != state.current.generation
                    || lease.is_some_and(|lease| {
                        lease.generation != state.current.generation
                            || !Arc::ptr_eq(&lease.store, &state.current.store)
                    })
                {
                    return Err(AccountProfileError::ContextChanged);
                }
                operation(&mut state)
            })
            .ok_or(AccountProfileError::ContextChanged)?
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
}

impl Drop for AccountProfiles {
    fn drop(&mut self) {
        self.runtime.release_store(&self.state().current.store);
        self.changes.send_replace(-1);
    }
}

fn validate(profile: &AccountProfile) -> Result<(), AccountProfileError> {
    validate_server_origin(&profile.origin).map_err(|_| AccountProfileError::Verification)?;
    if [
        profile.id,
        profile.account_id,
        profile.personal_vault_id,
        profile.device_id,
        profile.operation_id,
    ]
    .iter()
    .any(|id| id.get_version_num() != 7)
    {
        return Err(AccountProfileError::Verification);
    }
    Ok(())
}

fn no_link(path: &Path) -> Result<(), AccountProfileError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(AccountProfileError::Conflict),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(AccountProfileError::Storage),
    }
}

fn storage(error: crate::store::StoreError) -> AccountProfileError {
    match error {
        crate::store::StoreError::ProfileLimit => AccountProfileError::Limit,
        crate::store::StoreError::AccountContext => AccountProfileError::ContextChanged,
        _ => AccountProfileError::Storage,
    }
}
