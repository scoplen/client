// SPDX-License-Identifier: Apache-2.0

//! Device-local saved terminal tabs. Opening only validates and projects intent.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use scoplen_model::{
    MAX_TEXT_BYTES, MAX_WORKSPACE_LAYOUT_BYTES, Object, ObjectType, cbor, cbor::Value,
};
use serde::{Deserialize, Serialize};
use specta::Type;
use uuid::Uuid;

use crate::repository::{
    AccessProfile, Credential, Edit, Host, Record, RecordError, Repository, Route, RouteChoice,
    RouteKind, SessionKind, SessionSpec, Workspace, WorkspaceChange,
};
use crate::store::{Store, StoreError};

/// One visible tab supplied by the shell, including outputs that cannot be saved.
#[derive(Clone, Debug, Deserialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum WorkspaceTabInput {
    /// An ordinary terminal retains only its Login reference.
    Terminal {
        /// Canonical Login object identifier.
        #[serde(rename = "profileId")]
        profile_id: String,
    },
    /// Offline output must not silently become a new SSH connection.
    SavedOutput,
}

/// The ordered tab intent; no output, connection state or commands are accepted.
#[derive(Clone, Debug, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceInput {
    /// Display name for a newly created object.
    pub name: String,
    /// Complete current tab order, excluding Hosts.
    pub tabs: Vec<WorkspaceTabInput>,
    /// Selected tab index, or Hosts when absent.
    pub active: Option<u32>,
}

/// One saved definition, including retained unsupported and orphaned objects.
#[derive(Clone, Debug, Serialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceView {
    /// Canonical Workspace identifier.
    pub id: String,
    /// Retained display name.
    pub name: String,
    /// Number of saved terminal slots, when readable.
    pub tab_count: u32,
    /// A fixed reason Open is unavailable; Delete remains explicit.
    pub issue: Option<WorkspaceIssue>,
}

/// A fresh runtime tab, resolved without reserving or connecting a session.
#[derive(Clone, Debug, Serialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceTerminal {
    /// Fresh Rust-generated runtime identifier for this Open.
    pub session_id: String,
    /// Existing Login used by the ordinary SSH session path.
    pub profile_id: String,
    /// Current Host and Login display text.
    pub label: String,
}

/// A complete tab set that the shell appends only after successful validation.
#[derive(Clone, Debug, Serialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenedWorkspace {
    /// Saved order with fresh runtime identities.
    pub tabs: Vec<WorkspaceTerminal>,
    /// Selected fresh tab identifier, or Hosts when absent.
    pub active_session_id: Option<String>,
}

/// Content-free failures suitable for localized interface messages.
#[derive(Clone, Copy, Debug, Serialize, Type, PartialEq, Eq, thiserror::Error)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum WorkspaceIssue {
    /// The selected local profile is no longer available.
    #[error("local data is unavailable")]
    Unavailable,
    /// The supplied object identifier is invalid.
    #[error("the workspace identifier is invalid")]
    InvalidId,
    /// The live Workspace no longer exists.
    #[error("the workspace no longer exists")]
    NotFound,
    /// The supplied name is blank or exceeds the existing text bound.
    #[error("enter a nonempty workspace name within the text limit")]
    InvalidName,
    /// At least one ordinary terminal is required.
    #[error("open a terminal tab before saving a workspace")]
    EmptyTabs,
    /// Saving the complete tab set would convert offline output into SSH intent.
    #[error("close saved-output tabs before saving a workspace")]
    SavedOutputUnsupported,
    /// The selected index is outside the supplied tab order.
    #[error("the selected tab does not belong to this workspace")]
    InvalidActive,
    /// This build cannot interpret the complete retained definition.
    #[error("this workspace layout is unsupported")]
    UnsupportedLayout,
    /// A current Login or one of its dependencies is missing or unreadable.
    #[error("repair this workspace's Login and inventory dependencies before opening")]
    MissingDependency,
    /// A reference belongs to another account or an unsupported vault.
    #[error("this workspace references inventory outside the current personal profile")]
    ForeignDependency,
    /// The existing layout/object model limit was exceeded.
    #[error("this workspace exceeds the saved layout or object limits")]
    DefinitionTooLarge,
    /// The store could not complete the operation.
    #[error("the workspace could not be read or saved; try again")]
    Storage,
}

impl From<StoreError> for WorkspaceIssue {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Model(_) => Self::DefinitionTooLarge,
            _ => Self::Storage,
        }
    }
}

impl From<RecordError> for WorkspaceIssue {
    fn from(error: RecordError) -> Self {
        match error {
            RecordError::Store(error) => error.into(),
            RecordError::Model(_) => Self::DefinitionTooLarge,
            _ => Self::UnsupportedLayout,
        }
    }
}

/// The current profile's saved Workspace facade. None of its methods connects.
pub struct Workspaces {
    store: Arc<Store>,
}

impl Workspaces {
    /// Capture one local store; native ProfileRequest supplies generation fencing.
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// Project each object separately so unsupported entries cannot hide others.
    pub fn list(&self) -> Result<Vec<WorkspaceView>, WorkspaceIssue> {
        let vault = self.personal_vault()?;
        let mut views = Vec::new();
        for object in self.store.list(ObjectType::WORKSPACE)? {
            match self.ownership(object.id, vault) {
                Ok(()) => views.push(self.view(&object, vault)?),
                Err(WorkspaceIssue::ForeignDependency) => {}
                Err(issue) => return Err(issue),
            }
        }
        views.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        Ok(views)
    }

    /// Create a new local object, never overwriting or adopting another object.
    pub fn create(&self, input: WorkspaceInput) -> Result<WorkspaceView, WorkspaceIssue> {
        if input.name.trim().is_empty() || input.name.len() > MAX_TEXT_BYTES {
            return Err(WorkspaceIssue::InvalidName);
        }
        if input.tabs.iter().any(|tab| matches!(tab, WorkspaceTabInput::SavedOutput)) {
            return Err(WorkspaceIssue::SavedOutputUnsupported);
        }
        if input.tabs.is_empty() {
            return Err(WorkspaceIssue::EmptyTabs);
        }
        if input.active.is_some_and(|index| index as usize >= input.tabs.len()) {
            return Err(WorkspaceIssue::InvalidActive);
        }
        let mut sessions = BTreeMap::new();
        let mut order = Vec::with_capacity(input.tabs.len());
        let vault = self.personal_vault()?;
        for tab in input.tabs {
            let WorkspaceTabInput::Terminal { profile_id } = tab else { unreachable!() };
            let profile = identifier(&profile_id)?;
            self.login(profile, vault)?;
            let slot = Uuid::now_v7();
            order.push(slot);
            sessions.insert(
                slot,
                Some(SessionSpec {
                    profile,
                    kind: SessionKind::Terminal,
                    forward: None,
                    working_directory: None,
                }),
            );
        }
        let active = input.active.map(|index| order[index as usize]);
        let layout = encode_layout(&order, active)?;
        let record = Repository::<Workspace>::new(&self.store).create(WorkspaceChange {
            name: Some(input.name),
            layout: Edit::Set(layout),
            sessions,
        })?;
        Ok(WorkspaceView {
            id: record.meta.id.to_string(),
            name: record.name,
            tab_count: order.len() as u32,
            issue: None,
        })
    }

    /// Validate every slot before returning any fresh tab. No session is reserved.
    pub fn open(&self, id: &str) -> Result<OpenedWorkspace, WorkspaceIssue> {
        let object = self.object(id)?;
        let vault = self.personal_vault()?;
        self.ownership(object.id, vault)?;
        let (record, order, active) = definition(&object)?;
        let mut tabs = Vec::with_capacity(order.len());
        let mut active_session_id = None;
        for slot in order {
            let profile = record.sessions[&slot].profile;
            let label = self.login(profile, vault)?;
            let session_id = Uuid::now_v7().to_string();
            if active == Some(slot) {
                active_session_id = Some(session_id.clone());
            }
            tabs.push(WorkspaceTerminal { session_id, profile_id: profile.to_string(), label });
        }
        Ok(OpenedWorkspace { tabs, active_session_id })
    }

    /// Explicit deletion can tombstone unsupported definitions without reading them.
    pub fn delete(&self, id: &str) -> Result<(), WorkspaceIssue> {
        let object = self.object(id)?;
        self.ownership(object.id, self.personal_vault()?)?;
        self.store.delete(object.id)?;
        Ok(())
    }

    fn object(&self, id: &str) -> Result<Object, WorkspaceIssue> {
        self.store
            .get(identifier(id)?)?
            .filter(|object| object.object_type == ObjectType::WORKSPACE && !object.is_tombstoned())
            .ok_or(WorkspaceIssue::NotFound)
    }

    fn personal_vault(&self) -> Result<Option<Uuid>, WorkspaceIssue> {
        Ok(self.store.personal_record()?.map(|record| record.personal_vault_id))
    }

    fn ownership(&self, id: Uuid, vault: Option<Uuid>) -> Result<(), WorkspaceIssue> {
        if self.store.object_vault(id)?.is_some_and(|owner| Some(owner) != vault) {
            return Err(WorkspaceIssue::ForeignDependency);
        }
        Ok(())
    }

    fn login(&self, id: Uuid, vault: Option<Uuid>) -> Result<String, WorkspaceIssue> {
        let mut pending = vec![id];
        let mut visited = BTreeSet::new();
        while let Some(next) = pending.pop() {
            if !visited.insert(next) {
                continue;
            }
            let object = self
                .store
                .get(next)?
                .filter(|object| !object.is_tombstoned())
                .ok_or(WorkspaceIssue::MissingDependency)?;
            self.ownership(next, vault)?;
            match object.object_type {
                ObjectType::ACCESS_PROFILE => {
                    let profile = self.required::<AccessProfile>(next)?;
                    self.required::<Host>(profile.host)?;
                    if let Some(credential) = profile.credential {
                        self.required::<Credential>(credential)?;
                    }
                    if let RouteChoice::Route(route) = profile.route {
                        self.required::<Route>(route)?;
                    }
                }
                ObjectType::HOST => {
                    self.required::<Host>(next)?;
                }
                ObjectType::CREDENTIAL => {
                    self.required::<Credential>(next)?;
                }
                ObjectType::ROUTE => match self.required::<Route>(next)?.kind {
                    RouteKind::Jump { hops } => {
                        for hop in hops {
                            self.required::<AccessProfile>(hop)?;
                        }
                    }
                    RouteKind::Socks5 { credential, .. }
                    | RouteKind::HttpConnect { credential, .. } => {
                        if let Some(credential) = credential {
                            self.required::<Credential>(credential)?;
                        }
                    }
                    RouteKind::Managed { .. } => return Err(WorkspaceIssue::ForeignDependency),
                    RouteKind::Command { .. } => {}
                },
                _ => {}
            }
            pending.extend(scoplen_model::references(&object));
        }
        let profile = Repository::<AccessProfile>::new(&self.store)
            .get(id)
            .map_err(|_| WorkspaceIssue::MissingDependency)?
            .ok_or(WorkspaceIssue::MissingDependency)?;
        let host = Repository::<Host>::new(&self.store)
            .get(profile.host)
            .map_err(|_| WorkspaceIssue::MissingDependency)?
            .ok_or(WorkspaceIssue::MissingDependency)?;
        Ok(format!("{} · {}", host.name, profile.name.unwrap_or(profile.username)))
    }

    fn required<R: Record>(&self, id: Uuid) -> Result<R, WorkspaceIssue> {
        Repository::<R>::new(&self.store)
            .get(id)
            .map_err(|_| WorkspaceIssue::MissingDependency)?
            .ok_or(WorkspaceIssue::MissingDependency)
    }

    fn view(&self, object: &Object, vault: Option<Uuid>) -> Result<WorkspaceView, WorkspaceIssue> {
        let name = match object.set_field(1).map(|field| &field.value) {
            Some(Value::Text(name)) => name.clone(),
            _ => String::new(),
        };
        let mut view = WorkspaceView { id: object.id.to_string(), name, tab_count: 0, issue: None };
        let result = (|| {
            let (record, order, _) = definition(object)?;
            view.tab_count = order.len() as u32;
            for slot in order {
                self.login(record.sessions[&slot].profile, vault)?;
            }
            Ok(())
        })();
        match result {
            Err(WorkspaceIssue::Storage) => Err(WorkspaceIssue::Storage),
            Err(issue) => {
                view.issue = Some(issue);
                Ok(view)
            }
            Ok(()) => Ok(view),
        }
    }
}

fn identifier(text: &str) -> Result<Uuid, WorkspaceIssue> {
    let id = Uuid::parse_str(text).map_err(|_| WorkspaceIssue::InvalidId)?;
    if id.get_version_num() != 7 || id.to_string() != text {
        return Err(WorkspaceIssue::InvalidId);
    }
    Ok(id)
}

fn slot(value: &Value) -> Result<Uuid, WorkspaceIssue> {
    let Value::Bytes(bytes) = value else { return Err(WorkspaceIssue::UnsupportedLayout) };
    Uuid::from_slice(bytes)
        .ok()
        .filter(|id| id.get_version_num() == 7)
        .ok_or(WorkspaceIssue::UnsupportedLayout)
}

fn encode_layout(order: &[Uuid], active: Option<Uuid>) -> Result<Vec<u8>, WorkspaceIssue> {
    let bytes = cbor::encode(&Value::Map(vec![
        (Value::UInt(1), Value::UInt(1)),
        (
            Value::UInt(2),
            Value::Array(order.iter().map(|id| Value::Bytes(id.as_bytes().to_vec())).collect()),
        ),
        (Value::UInt(3), active.map_or(Value::Null, |id| Value::Bytes(id.as_bytes().to_vec()))),
    ]))
    .map_err(|_| WorkspaceIssue::DefinitionTooLarge)?;
    if bytes.len() > MAX_WORKSPACE_LAYOUT_BYTES {
        return Err(WorkspaceIssue::DefinitionTooLarge);
    }
    Ok(bytes)
}

fn definition(object: &Object) -> Result<(Workspace, Vec<Uuid>, Option<Uuid>), WorkspaceIssue> {
    let unsupported = || WorkspaceIssue::UnsupportedLayout;
    let record = Workspace::read(object).map_err(|_| unsupported())?;
    let bytes = record.layout.as_deref().ok_or_else(unsupported)?;
    if bytes.len() > MAX_WORKSPACE_LAYOUT_BYTES {
        return Err(unsupported());
    }
    let Value::Map(fields) = cbor::decode(bytes).map_err(|_| unsupported())? else {
        return Err(unsupported());
    };
    let [
        (Value::UInt(1), Value::UInt(1)),
        (Value::UInt(2), Value::Array(order)),
        (Value::UInt(3), active),
    ] = fields.as_slice()
    else {
        return Err(unsupported());
    };
    let order = order.iter().map(slot).collect::<Result<Vec<_>, _>>()?;
    let unique = order.iter().copied().collect::<BTreeSet<_>>();
    if order.is_empty()
        || unique.len() != order.len()
        || unique != record.sessions.keys().copied().collect()
        || record.sessions.values().any(|session| {
            session.kind != SessionKind::Terminal
                || session.forward.is_some()
                || session.working_directory.is_some()
        })
    {
        return Err(unsupported());
    }
    let active = if matches!(active, Value::Null) { None } else { Some(slot(active)?) };
    if active.is_some_and(|id| !unique.contains(&id)) {
        return Err(unsupported());
    }
    Ok((record, order, active))
}

#[cfg(test)]
mod tests;
