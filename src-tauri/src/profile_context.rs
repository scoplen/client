// SPDX-License-Identifier: Apache-2.0
//! Request admission and profile replacement for the native desktop boundary.

use std::sync::{Arc, Condvar, Mutex};

use scoplen_client_core::{
    local_data::{LocalData, LocalDataError},
    personal_server::{PersonalSyncRuntime, RegistrationCancellation},
    profiles::{AccountProfiles, ProfileLease},
    store::{Store, Subscription},
};
use serde::Serialize;
use specta::Type;
use tauri::Manager as _;
use tauri_specta::Event as _;

/// Captured profile opening supplied by the generation-bound frontend invoker.
pub const PROFILE_HEADER: &str = "x-scoplen-profile-generation";

#[derive(Clone, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
/// Safe selection metadata, without Device keys or local paths.
pub struct AccountProfileSummary {
    /// Device-local catalog identity.
    pub id: String,
    /// Canonical Personal deployment.
    pub origin: String,
    /// Account identity within the deployment.
    pub account_id: String,
    /// Current Device authentication and verified bootstrap were installed.
    pub ready: bool,
}

#[derive(Clone, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
/// Active namespace and available independent Account stores.
pub struct ProfileSnapshot {
    /// Fresh opening identity; reopening the same Account changes it.
    pub generation: String,
    /// Selected catalog identity, or None for Local or a retained root.
    pub selected: Option<String>,
    /// Public catalog entries.
    pub accounts: Vec<AccountProfileSummary>,
    /// An existing account-bearing root retains its original identity and data.
    pub retained_profile: bool,
}

#[derive(Clone, Debug, Serialize, Type, tauri_specta::Event)]
#[serde(rename_all = "camelCase")]
/// Published only after a replacement namespace becomes current.
pub struct ProfileChanged {
    /// Fresh selection state.
    pub snapshot: ProfileSnapshot,
}

#[derive(Default)]
struct State {
    catalog: Option<Arc<AccountProfiles>>,
    retained: Option<(String, Arc<Store>)>,
    subscription: Option<Subscription>,
    background_subscription: Option<tauri::async_runtime::JoinHandle<()>>,
    active: usize,
    switching: bool,
    registration: Option<(String, RegistrationCancellation, Arc<std::sync::atomic::AtomicBool>)>,
    stopped_tickets: std::collections::VecDeque<String>,
}

#[derive(Default)]
/// Owns native request admission and account-operation cancellation.
pub struct NativeProfiles {
    state: Mutex<State>,
    drained: Condvar,
}

impl NativeProfiles {
    pub(crate) fn catalog(&self, app: &tauri::AppHandle) -> Result<Arc<AccountProfiles>, String> {
        let mut state = self.state.lock().map_err(|_| "profileUnavailable")?;
        if let Some(catalog) = &state.catalog {
            return Ok(catalog.clone());
        }
        if state.retained.is_some() {
            return Err("retainedProfile".into());
        }
        let local = app
            .state::<crate::local_data::LocalDataState>()
            .get()
            .map_err(|_| "profileUnavailable")?;
        let runtime = app.state::<Arc<PersonalSyncRuntime>>().inner().clone();
        let root = local.store().ok_or("profileUnavailable")?;
        let catalog = match AccountProfiles::new(local, runtime) {
            Ok(catalog) => Arc::new(catalog),
            Err(scoplen_client_core::profiles::AccountProfileError::ContextChanged) => {
                state.retained.get_or_insert_with(|| (uuid::Uuid::now_v7().to_string(), root));
                return Err("retainedProfile".into());
            }
            Err(_) => return Err("profileUnavailable".into()),
        };
        state.catalog = Some(catalog.clone());
        Ok(catalog)
    }

    pub(crate) fn snapshot(&self, app: &tauri::AppHandle) -> Result<ProfileSnapshot, String> {
        let catalog = match self.catalog(app) {
            Ok(catalog) => catalog,
            Err(error) if error == "retainedProfile" => {
                let state = self.state.lock().map_err(|_| "profileUnavailable")?;
                let (generation, _) = state.retained.as_ref().ok_or("profileUnavailable")?;
                return Ok(ProfileSnapshot {
                    generation: generation.clone(),
                    selected: None,
                    accounts: Vec::new(),
                    retained_profile: true,
                });
            }
            Err(error) => return Err(error),
        };
        let lease = catalog.current().map_err(|_| "profileChanged")?;
        let accounts = catalog
            .list()
            .map_err(|_| "profileUnavailable")?
            .into_iter()
            .map(|p| AccountProfileSummary {
                id: p.id.to_string(),
                origin: p.origin,
                account_id: p.account_id.to_string(),
                ready: p.ready,
            })
            .collect();
        Ok(ProfileSnapshot {
            generation: lease.generation().to_string(),
            selected: lease.account().map(|p| p.id.to_string()),
            accounts,
            retained_profile: false,
        })
    }

    fn capture(
        self: &Arc<Self>,
        app: &tauri::AppHandle,
        generation: &str,
    ) -> Result<ProfileRequest, String> {
        let catalog = match self.catalog(app) {
            Ok(catalog) => Some(catalog),
            Err(error) if error == "retainedProfile" => None,
            Err(error) => return Err(error),
        };
        let local = app
            .state::<crate::local_data::LocalDataState>()
            .get()
            .map_err(|_| "profileUnavailable")?;
        let mut state = self.state.lock().map_err(|_| "profileUnavailable")?;
        if state.switching {
            return Err("profileChanging".into());
        }
        let binding = if let Some(catalog) = catalog {
            let lease = catalog.current().map_err(|_| "profileChanged")?;
            if generation != lease.generation().to_string() {
                return Err("profileChanged".into());
            }
            Binding::Catalog { catalog, lease }
        } else {
            let (expected, store) = state.retained.as_ref().ok_or("profileUnavailable")?;
            if generation != expected {
                return Err("profileChanged".into());
            }
            let current = local.store().ok_or("profileChanged")?;
            if !Arc::ptr_eq(&current, store) {
                return Err("profileChanged".into());
            }
            Binding::Retained { store: store.clone(), generation: expected.clone() }
        };
        state.active = state.active.checked_add(1).ok_or("profileUnavailable")?;
        Ok(ProfileRequest { owner: self.clone(), binding, local })
    }

    pub(crate) fn begin_switch(
        self: &Arc<Self>,
        app: &tauri::AppHandle,
        generation: &str,
        keep_ticket: Option<&str>,
    ) -> Result<ProfileSwitch, String> {
        let catalog = self.catalog(app)?;
        let mut state = self.state.lock().map_err(|_| "profileUnavailable")?;
        if state.switching {
            return Err("profileChanging".into());
        }
        if catalog.current().map_err(|_| "profileChanged")?.generation().to_string() != generation {
            return Err("profileChanged".into());
        }
        state.switching = true;
        if let Some((ticket, cancellation, stopped)) = &state.registration
            && keep_ticket != Some(ticket.as_str())
        {
            stopped.store(true, std::sync::atomic::Ordering::Release);
            cancellation.cancel();
        }
        Ok(ProfileSwitch { owner: self.clone(), catalog })
    }

    pub(crate) fn wait_drained(&self) -> Result<(), String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        self.wait_drained_until(deadline)
    }

    fn wait_drained_until(&self, deadline: std::time::Instant) -> Result<(), String> {
        let mut state = self.state.lock().map_err(|_| "profileUnavailable")?;
        while state.active != 0 {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err("finishNativeDialog".into());
            }
            state =
                self.drained.wait_timeout(state, remaining).map_err(|_| "profileUnavailable")?.0;
        }
        Ok(())
    }

    pub(crate) fn end_switch(&self) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).switching = false;
    }

    pub(crate) fn cancel_operation(&self, ticket: Option<&str>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ticket) = ticket
            && ticket.len() <= 128
        {
            if state.stopped_tickets.len() == 256 {
                state.stopped_tickets.pop_front();
            }
            state.stopped_tickets.push_back(ticket.to_owned());
        }
        if let Some((current, cancellation, stopped)) = &state.registration
            && ticket.is_none_or(|ticket| current == ticket)
        {
            stopped.store(true, std::sync::atomic::Ordering::Release);
            cancellation.cancel();
        }
    }

    pub(crate) fn register_operation(
        self: &Arc<Self>,
        ticket: String,
    ) -> Result<RegistrationRun, String> {
        if ticket.is_empty() || ticket.len() > 128 {
            return Err("invalidInput".into());
        }
        let mut state = self.state.lock().map_err(|_| "profileUnavailable")?;
        if state.stopped_tickets.contains(&ticket) {
            return Err("cancelled".into());
        }
        if state.switching || state.registration.is_some() {
            return Err("busy".into());
        }
        let cancellation = RegistrationCancellation::default();
        let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        state.registration = Some((ticket.clone(), cancellation.clone(), stopped.clone()));
        Ok(RegistrationRun { owner: self.clone(), ticket, cancellation, stopped })
    }

    pub(crate) fn publish(&self, app: &tauri::AppHandle) -> Result<ProfileSnapshot, String> {
        let snapshot = self.snapshot(app)?;
        let store = if snapshot.retained_profile {
            app.state::<crate::local_data::LocalDataState>().store().ok_or("profileChanged")?
        } else {
            let catalog = self.catalog(app)?;
            let lease = catalog.current().map_err(|_| "profileChanged")?;
            catalog.with_current_store(&lease, Arc::clone).map_err(|_| "profileChanged")?
        };
        let generation = snapshot.generation.clone();
        let handle = app.clone();
        let subscription = store.subscribe(move |change| {
            let mut event = crate::events::StoreChanged::from(change);
            event.profile_generation = generation.clone();
            let _ = event.emit(&handle);
        });
        let mut state = self.state.lock().map_err(|_| "profileUnavailable")?;
        state.subscription = Some(subscription);
        if let Some(previous) = state.background_subscription.take() {
            previous.abort();
        }
        let mut status = app.state::<Arc<PersonalSyncRuntime>>().subscribe();
        let handle = app.clone();
        let generation = snapshot.generation.clone();
        state.background_subscription = Some(tauri::async_runtime::spawn(async move {
            while status.changed().await.is_ok() {
                let current = *status.borrow_and_update();
                let _ = crate::events::PersonalSyncChanged {
                    profile_generation: generation.clone(),
                    status: current,
                }
                .emit(&handle);
            }
        }));
        drop(state);
        let _ = ProfileChanged { snapshot: snapshot.clone() }.emit(app);
        Ok(snapshot)
    }
}

/// Tauri injects this value from a bound invocation header before scheduling an async command.
/// Its lifetime prevents publishing a replacement context while the command is still running.
pub struct ProfileRequest {
    pub(crate) owner: Arc<NativeProfiles>,
    binding: Binding,
    local: Arc<LocalData>,
}

enum Binding {
    Catalog { catalog: Arc<AccountProfiles>, lease: ProfileLease },
    Retained { store: Arc<Store>, generation: String },
}

impl ProfileRequest {
    pub(crate) fn account_context(&self) -> Result<(&AccountProfiles, &ProfileLease), String> {
        match &self.binding {
            Binding::Catalog { catalog, lease } => Ok((catalog, lease)),
            Binding::Retained { .. } => Err("retainedProfile".into()),
        }
    }
    pub(crate) fn store(&self) -> Option<Arc<Store>> {
        self.with_store(Arc::clone)
    }
    pub(crate) fn with_store<T>(&self, operation: impl FnOnce(&Arc<Store>) -> T) -> Option<T> {
        match &self.binding {
            Binding::Catalog { catalog, lease } => {
                catalog.with_current_store(lease, operation).ok()
            }
            Binding::Retained { store, .. } => self
                .local
                .with_store(|current| Arc::ptr_eq(current, store).then(|| operation(store)))
                .flatten(),
        }
    }
    pub(crate) fn get(&self) -> Result<Arc<LocalData>, LocalDataError> {
        if matches!(&self.binding, Binding::Catalog { lease, .. } if lease.account().is_some()) {
            return Err(LocalDataError::InvalidState);
        }
        Ok(self.local.clone())
    }
    pub(crate) fn generation(&self) -> String {
        match &self.binding {
            Binding::Catalog { lease, .. } => lease.generation().to_string(),
            Binding::Retained { generation, .. } => generation.clone(),
        }
    }
}

pub(crate) struct ProfileSwitch {
    owner: Arc<NativeProfiles>,
    pub(crate) catalog: Arc<AccountProfiles>,
}

impl Drop for ProfileSwitch {
    fn drop(&mut self) {
        self.owner.end_switch();
    }
}

impl Drop for ProfileRequest {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
        state.active -= 1;
        self.owner.drained.notify_all();
    }
}

impl<'de> tauri::ipc::CommandArg<'de, tauri::Wry> for ProfileRequest {
    fn from_command(
        item: tauri::ipc::CommandItem<'de, tauri::Wry>,
    ) -> Result<Self, tauri::ipc::InvokeError> {
        let app = item.message.webview_ref().app_handle();
        let owner = app.state::<Arc<NativeProfiles>>().inner().clone();
        let generation = item
            .message
            .headers()
            .get(PROFILE_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or("profileChanged")?;
        owner.capture(app, generation).map_err(Into::into)
    }
}

impl specta::function::FunctionArg for ProfileRequest {
    fn to_datatype(_: &mut specta::Types) -> Option<specta::datatype::DataType> {
        None
    }
}

pub(crate) struct RegistrationRun {
    owner: Arc<NativeProfiles>,
    ticket: String,
    pub(crate) cancellation: RegistrationCancellation,
    stopped: Arc<std::sync::atomic::AtomicBool>,
}

impl RegistrationRun {
    pub(crate) fn check(&self) -> Result<(), String> {
        if self.stopped.load(std::sync::atomic::Ordering::Acquire) {
            Err("cancelled".into())
        } else {
            Ok(())
        }
    }
}

impl Drop for RegistrationRun {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.registration.as_ref().is_some_and(|(ticket, _, _)| ticket == &self.ticket) {
            state.registration = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_before_dispatch_and_unknown_stop_cannot_cancel_another_run() {
        let profiles = Arc::new(NativeProfiles::default());
        profiles.cancel_operation(Some("not-dispatched"));
        assert!(
            matches!(profiles.register_operation("not-dispatched".into()), Err(error) if error == "cancelled")
        );
        let current = profiles.register_operation("current".into()).unwrap();
        profiles.cancel_operation(Some("another"));
        current.check().unwrap();
        profiles.cancel_operation(Some("current"));
        assert_eq!(current.check().unwrap_err(), "cancelled");
        assert!(profiles.register_operation("parallel".into()).is_err());
        drop(current);
        profiles.register_operation("next".into()).unwrap().check().unwrap();
    }

    #[test]
    fn close_cancels_active_work_and_switching_rejects_new_work() {
        let profiles = Arc::new(NativeProfiles::default());
        let current = profiles.register_operation("current".into()).unwrap();
        profiles.cancel_operation(None);
        assert_eq!(current.check().unwrap_err(), "cancelled");
        drop(current);
        profiles.state.lock().unwrap().switching = true;
        assert!(
            matches!(profiles.register_operation("next".into()), Err(error) if error == "busy")
        );
        profiles.end_switch();
        profiles.register_operation("next".into()).unwrap().check().unwrap();
    }

    #[test]
    fn profile_drain_is_bounded_and_wakes_when_original_requests_finish() {
        let profiles = Arc::new(NativeProfiles::default());
        profiles.state.lock().unwrap().active = 1;
        assert_eq!(
            profiles.wait_drained_until(std::time::Instant::now()).unwrap_err(),
            "finishNativeDialog"
        );
        let worker = {
            let profiles = profiles.clone();
            std::thread::spawn(move || {
                let mut state = profiles.state.lock().unwrap();
                state.active = 0;
                profiles.drained.notify_all();
            })
        };
        profiles
            .wait_drained_until(std::time::Instant::now() + std::time::Duration::from_secs(1))
            .unwrap();
        worker.join().unwrap();
    }
}
