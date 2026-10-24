// SPDX-License-Identifier: Apache-2.0
//! Store-owned notification and inventory scheduling, independent of Settings.

use std::{
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use serde::Serialize;
use specta::Type;
use tokio::{
    sync::{Notify, watch},
    time::{Instant, sleep_until},
};

use super::{
    PersonalInventoryIntent, PersonalServer, PersonalServerError, PersonalSyncError, notification,
    record,
};
use crate::store::Store;

const POLL: Duration = Duration::from_secs(60);
const COALESCE: Duration = Duration::from_millis(250);

/// Redacted background state. Neither server diagnostics nor credentials cross IPC.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum PersonalBackgroundStatus {
    /// No open store with locally verified Personal sync keys.
    #[default]
    Inactive,
    /// Preparing the first authenticated notification connection.
    Connecting,
    /// Notifications are ready; hints and adopted local edits schedule sync.
    Connected,
    /// Notifications are unavailable; adopted inventory is polled every 60 seconds.
    Polling,
    /// An explicit fresh device authentication is required.
    AuthenticationRequired,
    /// Current keys cannot be safely rotated; background transfer is paused.
    RotationRequired,
    /// The current token lacks the operation's scope.
    PermissionDenied,
    /// A local, verification, clock or reconciliation failure needs an explicit retry.
    Failed,
}

#[derive(Clone, Default)]
struct Control {
    store: Option<Arc<Store>>,
    run: Option<Arc<Run>>,
    shutdown: bool,
}

/// Serializes cancellation with each synchronous commit, never with network waits.
#[derive(Default)]
pub(super) struct Run(Mutex<bool>);

impl Run {
    fn cancel(&self) {
        *self.0.lock().unwrap_or_else(|error| error.into_inner()) = true;
    }

    pub(super) fn guard(&self) -> Result<MutexGuard<'_, bool>, PersonalServerError> {
        let guard = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if *guard {
            return Err(PersonalServerError::Busy);
        }
        Ok(guard)
    }
}

pub(super) fn guard(
    run: Option<&Arc<Run>>,
) -> Result<Option<MutexGuard<'_, bool>>, PersonalServerError> {
    run.map(|run| run.guard()).transpose()
}

/// One cancellable Rust owner for native Personal notifications, polling and sync.
/// Start [`Self::run`] once on the native async runtime; replace its store on unlock/reset.
pub struct PersonalSyncRuntime {
    control: watch::Sender<Control>,
    status: watch::Sender<PersonalBackgroundStatus>,
    running: AtomicBool,
}

impl Default for PersonalSyncRuntime {
    fn default() -> Self {
        Self {
            control: watch::channel(Control::default()).0,
            status: watch::channel(PersonalBackgroundStatus::Inactive).0,
            running: AtomicBool::new(false),
        }
    }
}

impl PersonalSyncRuntime {
    /// Change the open store. Dropping the old run cancels its timers and transports.
    pub fn set_store(&self, store: Option<Arc<Store>>) {
        self.control.send_if_modified(|control| {
            if control.shutdown || matches!((&control.store, &store), (Some(old), Some(new)) if Arc::ptr_eq(old, new))
                || control.store.is_none() && store.is_none() { return false; }
            if let Some(run) = &control.run { run.cancel(); }
            control.run = store.as_ref().map(|_| Arc::new(Run::default()));
            control.store = store;
            true
        });
    }

    /// Cancel owned background work during native shutdown.
    pub fn shutdown(&self) {
        self.control.send_modify(|control| {
            if let Some(run) = &control.run {
                run.cancel();
            }
            *control = Control { shutdown: true, ..Control::default() };
        });
    }

    /// Read current safe state without starting a connection or performing network I/O.
    pub fn status(&self) -> PersonalBackgroundStatus {
        *self.status.borrow()
    }

    /// Observe safe state changes; observing does not activate synchronization.
    pub fn subscribe(&self) -> watch::Receiver<PersonalBackgroundStatus> {
        self.status.subscribe()
    }

    /// Run once independently of any frontend observer. Store replacement cancels the
    /// complete old future, including connection drivers and in-flight HTTP work.
    pub async fn run(&self, server: &PersonalServer) {
        if self.running.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut control = self.control.subscribe();
        loop {
            let selected = control.borrow_and_update().clone();
            self.status.send_if_modified(|status| {
                let changed = *status != PersonalBackgroundStatus::Inactive;
                *status = PersonalBackgroundStatus::Inactive;
                changed
            });
            if selected.shutdown {
                return;
            }
            if let (Some(store), Some(run)) = (selected.store, selected.run) {
                tokio::select! {
                    biased;
                    _ = control.changed() => {},
                    _ = self.run_store(server, store, run) => {},
                }
            } else if control.changed().await.is_err() {
                return;
            }
        }
    }

    fn set_status(&self, run: &Run, value: PersonalBackgroundStatus) {
        let Ok(_active) = run.guard() else {
            return;
        };
        self.status.send_if_modified(|status| {
            let changed = *status != value;
            *status = value;
            changed
        });
    }

    async fn run_store(&self, server: &PersonalServer, store: Arc<Store>, run: Arc<Run>) {
        let mut changes = store.personal_changes();
        loop {
            // Revalidate retained anchors before the first network request after reopening.
            match server.load_sync_bootstrap(&store) {
                Ok(Some(_)) => break,
                Ok(None) => self.set_status(&run, PersonalBackgroundStatus::Inactive),
                Err(PersonalSyncError::Personal(PersonalServerError::Busy)) => {
                    tokio::select! { _ = tokio::time::sleep(COALESCE) => {}, _ = changes.changed() => {} }
                    continue;
                }
                Err(PersonalSyncError::RotationRequired) => {
                    self.set_status(&run, PersonalBackgroundStatus::RotationRequired)
                }
                Err(_) => self.set_status(&run, PersonalBackgroundStatus::Failed),
            }
            if changes.changed().await.is_err() {
                return;
            }
        }
        let Ok(identity) = record(&store) else {
            return;
        };
        let vault = identity.personal_vault_id;
        self.set_status(&run, PersonalBackgroundStatus::Connecting);
        let (hints, observed) = watch::channel(notification::Hints::default());
        tokio::select! {
            _ = notification::run(server, &store, hints, &run) => {},
            _ = self.schedule(server, &store, vault, changes, observed, &run) => {},
        }
    }

    async fn schedule(
        &self,
        server: &PersonalServer,
        store: &Arc<Store>,
        vault: uuid::Uuid,
        mut changes: watch::Receiver<u64>,
        mut hints: watch::Receiver<notification::Hints>,
        run: &Arc<Run>,
    ) {
        let local = Arc::new(Notify::new());
        let weak = Arc::downgrade(store);
        let changed = local.clone();
        let _subscription = store.subscribe(move |_| {
            if weak.upgrade().is_some_and(|store| {
                store.pending_personal_objects(vault, 1).is_ok_and(|objects| !objects.is_empty())
            }) {
                changed.notify_one();
            }
        });
        let mut pending = true;
        let mut due = Instant::now() + COALESCE;
        let mut poll = tokio::time::interval_at(Instant::now() + POLL, POLL);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut seen = notification::Hints::default();
        let mut generation = generations(store);
        let mut rotation_seen = store.personal_rotation();
        let mut paused = false;
        loop {
            tokio::select! {
                biased;
                _ = changes.changed() => {
                    let current = generations(store);
                    if current != generation {
                        generation = current;
                        paused = false;
                        pending = true;
                        due = Instant::now() + COALESCE;
                    }
                    let rotation = store.personal_rotation();
                    if rotation != rotation_seen && !paused {
                        pending = true;
                        due = due.min(Instant::now() + COALESCE);
                    }
                    rotation_seen = rotation;
                }
                _ = hints.changed() => {
                    let current = *hints.borrow_and_update();
                    if (current.connection != seen.connection || current.sequence > seen.sequence)
                        && (current.connection != seen.connection || current.sequence > store.personal_sync_cursor(vault).unwrap_or(0)) {
                        pending = true;
                        due = due.min(Instant::now() + COALESCE);
                    }
                    seen = current;
                    if !paused { self.set_status(run, if seen.connected { PersonalBackgroundStatus::Connected } else { PersonalBackgroundStatus::Polling }); }
                }
                _ = local.notified() => {
                    if store.pending_personal_objects(vault, 1).is_ok_and(|objects| !objects.is_empty()) {
                        pending = true;
                        due = due.min(Instant::now() + COALESCE);
                    }
                }
                _ = poll.tick() => {
                    if !seen.connected { pending = true; due = Instant::now(); }
                }
                _ = sleep_until(due), if pending && !paused => {
                    pending = false;
                    let rotation = store.personal_rotation();
                    match server.sync_personal_inventory_background(store.clone(), PersonalInventoryIntent { vault_id: vault, adopt: vec![] }, run.clone()).await {
                        Ok(progress) => {
                            pending = progress.more;
                            due = Instant::now() + COALESCE;
                            self.set_status(run, if seen.connected { PersonalBackgroundStatus::Connected } else { PersonalBackgroundStatus::Polling });
                        }
                        Err(PersonalSyncError::Personal(PersonalServerError::Busy)) => { pending = true; due = Instant::now() + COALESCE; }
                        Err(_) if store.personal_rotation() != rotation => { pending = true; due = Instant::now() + COALESCE; }
                        Err(PersonalSyncError::RotationRequired) => { paused = true; self.set_status(run, PersonalBackgroundStatus::RotationRequired); }
                        Err(PersonalSyncError::AuthenticationRequired | PersonalSyncError::Personal(PersonalServerError::AuthenticationRequired)) => { paused = true; self.set_status(run, PersonalBackgroundStatus::AuthenticationRequired); }
                        Err(PersonalSyncError::Personal(PersonalServerError::PermissionDenied)) => { paused = true; self.set_status(run, PersonalBackgroundStatus::PermissionDenied); }
                        Err(PersonalSyncError::Personal(PersonalServerError::Network | PersonalServerError::ConnectionBeforeRequest | PersonalServerError::RefreshDeferred)
                            | PersonalSyncError::WriteOutcomeUnknown | PersonalSyncError::AcknowledgementUnknown | PersonalSyncError::ConcurrentChanges) => {
                            pending = true;
                            due = Instant::now() + POLL;
                            self.set_status(run, PersonalBackgroundStatus::Polling);
                        }
                        Err(_) => { paused = true; self.set_status(run, PersonalBackgroundStatus::Failed); }
                    }
                    // Bootstrap/refresh writes made by this cycle are already accounted for.
                    generation = generations(store);
                    changes.borrow_and_update();
                }
            }
        }
    }
}

fn generations(store: &Store) -> (i64, i64) {
    (
        record(store).map_or(-1, |record| record.auth_generation),
        store.personal_sync_record().ok().flatten().map_or(-1, |record| record.generation),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_serializes_with_commit_and_rejects_later_commits() {
        let run = Arc::new(Run::default());
        let commit = run.guard().unwrap();
        let cancelling = run.clone();
        let (sent, received) = std::sync::mpsc::channel();
        let task = std::thread::spawn(move || {
            cancelling.cancel();
            sent.send(()).unwrap();
        });
        assert!(received.recv_timeout(Duration::from_millis(20)).is_err());
        drop(commit);
        received.recv_timeout(Duration::from_secs(1)).unwrap();
        task.join().unwrap();
        assert!(run.guard().is_err());
    }
}
