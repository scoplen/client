// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::collections::BTreeSet;

/// Exact terminal transport borrowing a tunnel's authenticated connection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct ForwardAttachment {
    /// Logical terminal identity.
    pub session_id: String,
    /// One authenticated attempt of that terminal.
    pub transport_id: String,
}

/// One selected definition, including failures which have no runnable configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionForwardSnapshot {
    /// Original saved reference, never replaced by a Forward's default Login.
    pub forward_id: String,
    /// Current readable name, absent when the referenced definition is unavailable.
    pub name: Option<String>,
    /// Registered run, when configuration and shared admission succeeded.
    pub run: Option<ForwardSnapshot>,
    /// Failure before a run could be registered.
    pub issue: Option<ForwardIssue>,
    /// Explicitly suppressed for this logical terminal, including after reconnect.
    pub stopped: bool,
}

pub(crate) struct AttachedForwardSelection {
    login: PreparationContext,
    ids: BTreeSet<Uuid>,
    vault: Option<Uuid>,
}

impl AttachedForwardSelection {
    pub(crate) fn capture(store: &Store, login: &PreparationContext) -> Result<Self, ForwardIssue> {
        let profile =
            Uuid::parse_str(&login.profile_id).map_err(|_| ForwardIssue::InvalidConfiguration)?;
        let saved = Repository::<AccessProfile>::new(store)
            .get(profile)
            .map_err(|_| ForwardIssue::Unavailable)?
            .ok_or(ForwardIssue::NotFound)?;
        Ok(Self {
            login: login.clone(),
            ids: saved.forwards,
            vault: store.object_vault(profile).map_err(|_| ForwardIssue::Unavailable)?,
        })
    }
}

struct Entry {
    id: Uuid,
    name: Option<String>,
    run: Option<Arc<Run>>,
    issue: Option<ForwardIssue>,
}

pub(crate) struct AttachedForwardState {
    pub(crate) transport: Uuid,
    store: Weak<Store>,
    entries: Vec<Entry>,
    stopped: Arc<Mutex<BTreeSet<Uuid>>>,
    changed: watch::Sender<bool>,
}

impl AttachedForwardState {
    pub(crate) fn belongs_to(&self, store: &Arc<Store>, transport: Uuid) -> bool {
        self.transport == transport && self.store.ptr_eq(&Arc::downgrade(store))
    }

    pub(crate) fn snapshots(&self) -> Result<Vec<SessionForwardSnapshot>, ForwardIssue> {
        let stopped = self.stopped.lock().map_err(|_| ForwardIssue::Unavailable)?;
        self.entries
            .iter()
            .map(|entry| {
                Ok(SessionForwardSnapshot {
                    forward_id: entry.id.to_string(),
                    name: entry.name.clone(),
                    run: entry.run.as_ref().map(|run| run.snapshot()).transpose()?,
                    issue: entry.issue,
                    stopped: stopped.contains(&entry.id),
                })
            })
            .collect()
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<bool> {
        self.changed.subscribe()
    }

    pub(crate) fn stop_entry(&self, id: Uuid) -> Result<(), ForwardIssue> {
        let entry =
            self.entries.iter().find(|entry| entry.id == id).ok_or(ForwardIssue::Expired)?;
        self.stopped.lock().map_err(|_| ForwardIssue::Unavailable)?.insert(id);
        if let Some(run) = &entry.run {
            run.stop();
        }
        self.changed.send_modify(|changed| *changed = !*changed);
        Ok(())
    }

    fn stop_all(&self) {
        for entry in &self.entries {
            if let Some(run) = &entry.run {
                run.stop();
            }
        }
    }
}

/// Session-owned tasks borrow the transport and have no authority to close it.
pub(crate) struct AttachedForwardLease {
    pub(crate) state: Arc<AttachedForwardState>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

struct AttachedRunGuard {
    manager: ForwardManager,
    run: Arc<Run>,
}

impl Drop for AttachedRunGuard {
    fn drop(&mut self) {
        if self.run.snapshot().is_ok_and(|snapshot| snapshot.phase.live()) {
            self.manager.complete(&self.run, Err(ForwardIssue::ConnectionLost));
        }
    }
}

impl Drop for AttachedForwardLease {
    fn drop(&mut self) {
        self.state.stop_all();
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl AttachedForwardLease {
    pub(crate) async fn settle(&mut self, manager: &ForwardManager) {
        self.state.stop_all();
        let settled = tokio::time::timeout(CLOSE_TIMEOUT, async {
            while let Some(task) = self.tasks.last_mut() {
                let _ = task.await;
                self.tasks.pop();
            }
        })
        .await;
        if settled.is_err() {
            for entry in &self.state.entries {
                if let Some(run) = &entry.run
                    && run.snapshot().is_ok_and(|snapshot| snapshot.phase.live())
                {
                    manager.complete(run, Err(ForwardIssue::ShutdownFailed));
                }
            }
            for task in &self.tasks {
                task.abort();
            }
            for task in self.tasks.drain(..) {
                let _ = task.await;
            }
        } else {
            self.tasks.clear();
        }
    }
}

impl ForwardManager {
    pub(crate) fn attach(
        &self,
        store: &Arc<Store>,
        selection: AttachedForwardSelection,
        attachment: ForwardAttachment,
        stopped: Arc<Mutex<BTreeSet<Uuid>>>,
        connection: &Arc<SshConnection>,
    ) -> AttachedForwardLease {
        let (changed, _) = watch::channel(false);
        let mut entries = Vec::with_capacity(selection.ids.len());
        let mut tasks = Vec::new();
        for id in selection.ids {
            let mut entry = Entry { id, name: None, run: None, issue: None };
            let configured = (|| {
                if store.object_vault(id).map_err(|_| ForwardIssue::Unavailable)? != selection.vault
                {
                    return Err(ForwardIssue::NotFound);
                }
                let forward = Repository::<Forward>::new(store)
                    .get(id)
                    .map_err(|_| ForwardIssue::InvalidConfiguration)?
                    .ok_or(ForwardIssue::NotFound)?;
                entry.name = Some(forward.name.clone());
                if stopped.lock().map_err(|_| ForwardIssue::Unavailable)?.contains(&id) {
                    return Ok(None);
                }
                if forward.kind == ForwardKind::Remote {
                    return Err(ForwardIssue::UnsupportedDefinition);
                }
                let definition = saved_definition(forward)?;
                validate_definition(&definition)?;
                Ok(Some(definition_configuration(
                    ForwardSource::Saved { forward_id: id.to_string() },
                    selection.login.clone(),
                    definition,
                )))
            })();
            let configuration = match configured {
                Ok(Some(configuration)) => configuration,
                Ok(None) => {
                    entries.push(entry);
                    continue;
                }
                Err(issue) => {
                    entry.issue = Some(issue);
                    entries.push(entry);
                    continue;
                }
            };
            let notify = changed.clone();
            let registered = self.register(
                store,
                configuration,
                Some(attachment.clone()),
                Some(stopped.clone()),
                Arc::new(move |_| notify.send_modify(|changed| *changed = !*changed)),
            );
            match registered {
                Ok((run, _)) => {
                    entry.run = Some(run.clone());
                    let manager = self.clone();
                    let mut connection = connection.clone();
                    let guard = AttachedRunGuard { manager: manager.clone(), run: run.clone() };
                    tasks.push(tokio::spawn(async move {
                        let _guard = guard;
                        let mut stop = run.stop.subscribe();
                        let result = serve(&run, &mut connection, &mut stop).await;
                        // Release the borrowed transport before notifying its session owner.
                        drop(connection);
                        manager.complete(&run, result);
                    }));
                }
                Err(issue) => entry.issue = Some(issue),
            }
            entries.push(entry);
        }
        AttachedForwardLease {
            state: Arc::new(AttachedForwardState {
                transport: Uuid::parse_str(&attachment.transport_id)
                    .expect("session transport UUID"),
                store: Arc::downgrade(store),
                entries,
                stopped,
                changed,
            }),
            tasks,
        }
    }
}
