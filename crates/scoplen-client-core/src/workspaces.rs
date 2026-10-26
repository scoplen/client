// SPDX-License-Identifier: Apache-2.0

//! Device-local terminal layouts. Opening only validates and projects intent.

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

/// Equal-half terminal split direction.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum WorkspaceSplitDirection {
    /// Left and right children.
    Horizontal,
    /// Top and bottom children.
    Vertical,
}

/// One complete tree supplied by the shell, including unsupported offline output.
#[derive(Clone, Debug, Deserialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum WorkspaceTreeInput {
    /// An ordinary terminal retains only its Login reference.
    Terminal {
        /// Canonical Login object identifier.
        #[serde(rename = "profileId")]
        profile_id: String,
    },
    /// Offline output must not silently become a new SSH connection.
    SavedOutput,
    /// An ordered pair of equal-half children.
    Split {
        /// Orientation of the first and second child.
        direction: WorkspaceSplitDirection,
        /// Left or top subtree.
        first: Box<WorkspaceTreeInput>,
        /// Right or bottom subtree.
        second: Box<WorkspaceTreeInput>,
    },
}

/// A complete tab and its remembered depth-first pane selection.
#[derive(Clone, Debug, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceTabInput {
    /// Entire tree, including inactive panes.
    pub tree: WorkspaceTreeInput,
    /// Zero-based depth-first leaf index.
    pub focused: u32,
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
    /// Number of saved terminal tabs, when readable.
    pub tab_count: u32,
    /// A fixed reason Open is unavailable; Delete remains explicit.
    pub issue: Option<WorkspaceIssue>,
}

/// A fresh runtime pane, resolved without reserving or connecting a session.
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

/// A restored tree using fresh ordinary runtime session identities.
#[derive(Clone, Debug, Serialize, Type, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum WorkspaceTree {
    /// A fresh ordinary terminal.
    Terminal {
        /// Safe current Login projection.
        terminal: WorkspaceTerminal,
    },
    /// A saved equal-half split.
    Split {
        /// Saved orientation.
        direction: WorkspaceSplitDirection,
        /// Left or top subtree.
        first: Box<WorkspaceTree>,
        /// Right or bottom subtree.
        second: Box<WorkspaceTree>,
    },
}

/// A restored tab with its own remembered focused pane.
#[derive(Clone, Debug, Serialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceTab {
    /// Complete restored tree.
    pub tree: WorkspaceTree,
    /// One terminal identity in this tree.
    pub focused_session_id: String,
}

/// A complete tab set that the shell appends only after successful validation.
#[derive(Clone, Debug, Serialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenedWorkspace {
    /// Saved order with fresh runtime identities.
    pub tabs: Vec<WorkspaceTab>,
    /// Selected tab index, or Hosts when absent.
    pub active: Option<u32>,
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
            let mut leaves = Vec::new();
            let tree = self.capture_tree(tab.tree, 0, vault, &mut sessions, &mut leaves)?;
            let focused = *leaves.get(tab.focused as usize).ok_or(WorkspaceIssue::InvalidActive)?;
            order.push(SavedTab { tree, focused });
        }
        let layout = encode_layout(&order, input.active)?;
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
        // Resolve the entire definition before returning any ordinary-session intent.
        let mut terminals = BTreeMap::new();
        for (slot, session) in &record.sessions {
            let label = self.login(session.profile, vault)?;
            terminals.insert(
                *slot,
                WorkspaceTerminal {
                    session_id: Uuid::now_v7().to_string(),
                    profile_id: session.profile.to_string(),
                    label,
                },
            );
        }
        let mut tabs = Vec::with_capacity(order.len());
        for tab in order {
            tabs.push(WorkspaceTab {
                focused_session_id: terminals[&tab.focused].session_id.clone(),
                tree: tab.tree.open(&terminals),
            });
        }
        Ok(OpenedWorkspace { tabs, active })
    }

    fn capture_tree(
        &self,
        input: WorkspaceTreeInput,
        depth: usize,
        vault: Option<Uuid>,
        sessions: &mut BTreeMap<Uuid, Option<SessionSpec>>,
        leaves: &mut Vec<Uuid>,
    ) -> Result<SavedTree, WorkspaceIssue> {
        if depth > 3 {
            return Err(WorkspaceIssue::DefinitionTooLarge);
        }
        match input {
            WorkspaceTreeInput::SavedOutput => Err(WorkspaceIssue::SavedOutputUnsupported),
            WorkspaceTreeInput::Terminal { profile_id } => {
                if leaves.len() >= 8 || sessions.len() >= 64 {
                    return Err(WorkspaceIssue::DefinitionTooLarge);
                }
                let profile = identifier(&profile_id)?;
                self.login(profile, vault)?;
                let slot = Uuid::now_v7();
                leaves.push(slot);
                sessions.insert(
                    slot,
                    Some(SessionSpec {
                        profile,
                        kind: SessionKind::Terminal,
                        forward: None,
                        working_directory: None,
                    }),
                );
                Ok(SavedTree::Leaf(slot))
            }
            WorkspaceTreeInput::Split { direction, first, second } => Ok(SavedTree::Split(
                direction,
                Box::new(self.capture_tree(*first, depth + 1, vault, sessions, leaves)?),
                Box::new(self.capture_tree(*second, depth + 1, vault, sessions, leaves)?),
            )),
        }
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
            for session in record.sessions.values() {
                self.login(session.profile, vault)?;
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
    if id.get_version_num() != 7
        || id.get_variant() != uuid::Variant::RFC4122
        || id.to_string() != text
    {
        return Err(WorkspaceIssue::InvalidId);
    }
    Ok(id)
}

fn slot(value: &Value) -> Result<Uuid, WorkspaceIssue> {
    let Value::Bytes(bytes) = value else { return Err(WorkspaceIssue::UnsupportedLayout) };
    Uuid::from_slice(bytes)
        .ok()
        .filter(|id| id.get_version_num() == 7 && id.get_variant() == uuid::Variant::RFC4122)
        .ok_or(WorkspaceIssue::UnsupportedLayout)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SavedTab {
    tree: SavedTree,
    focused: Uuid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SavedTree {
    Leaf(Uuid),
    Split(WorkspaceSplitDirection, Box<SavedTree>, Box<SavedTree>),
}

impl SavedTree {
    fn value(&self) -> Value {
        match self {
            Self::Leaf(id) => Value::Bytes(id.as_bytes().to_vec()),
            Self::Split(direction, first, second) => Value::Array(vec![
                Value::UInt(match direction {
                    WorkspaceSplitDirection::Horizontal => 0,
                    WorkspaceSplitDirection::Vertical => 1,
                }),
                first.value(),
                second.value(),
            ]),
        }
    }

    fn open(&self, terminals: &BTreeMap<Uuid, WorkspaceTerminal>) -> WorkspaceTree {
        match self {
            Self::Leaf(id) => WorkspaceTree::Terminal { terminal: terminals[id].clone() },
            Self::Split(direction, first, second) => WorkspaceTree::Split {
                direction: *direction,
                first: Box::new(first.open(terminals)),
                second: Box::new(second.open(terminals)),
            },
        }
    }
}

fn encode_layout(order: &[SavedTab], active: Option<u32>) -> Result<Vec<u8>, WorkspaceIssue> {
    let bytes = cbor::encode(&Value::Map(vec![
        (Value::UInt(1), Value::UInt(2)),
        (
            Value::UInt(2),
            Value::Array(
                order
                    .iter()
                    .map(|tab| {
                        Value::Array(vec![
                            tab.tree.value(),
                            Value::Bytes(tab.focused.as_bytes().to_vec()),
                        ])
                    })
                    .collect(),
            ),
        ),
        (Value::UInt(3), active.map_or(Value::Null, |index| Value::UInt(u64::from(index)))),
    ]))
    .map_err(|_| WorkspaceIssue::DefinitionTooLarge)?;
    if bytes.len() > MAX_WORKSPACE_LAYOUT_BYTES {
        return Err(WorkspaceIssue::DefinitionTooLarge);
    }
    Ok(bytes)
}

fn read_tree(
    value: &Value,
    depth: usize,
    leaves: &mut Vec<Uuid>,
) -> Result<SavedTree, WorkspaceIssue> {
    if depth > 3 {
        return Err(WorkspaceIssue::UnsupportedLayout);
    }
    if let Value::Bytes(_) = value {
        if leaves.len() >= 8 {
            return Err(WorkspaceIssue::UnsupportedLayout);
        }
        let id = slot(value)?;
        leaves.push(id);
        return Ok(SavedTree::Leaf(id));
    }
    let Value::Array(branch) = value else { return Err(WorkspaceIssue::UnsupportedLayout) };
    let [Value::UInt(direction), first, second] = branch.as_slice() else {
        return Err(WorkspaceIssue::UnsupportedLayout);
    };
    let direction = match direction {
        0 => WorkspaceSplitDirection::Horizontal,
        1 => WorkspaceSplitDirection::Vertical,
        _ => return Err(WorkspaceIssue::UnsupportedLayout),
    };
    Ok(SavedTree::Split(
        direction,
        Box::new(read_tree(first, depth + 1, leaves)?),
        Box::new(read_tree(second, depth + 1, leaves)?),
    ))
}

fn definition(object: &Object) -> Result<(Workspace, Vec<SavedTab>, Option<u32>), WorkspaceIssue> {
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
        (Value::UInt(1), Value::UInt(2)),
        (Value::UInt(2), Value::Array(order)),
        (Value::UInt(3), active),
    ] = fields.as_slice()
    else {
        return Err(unsupported());
    };
    let mut unique = BTreeSet::new();
    let order = order
        .iter()
        .map(|value| {
            let Value::Array(tab) = value else { return Err(unsupported()) };
            let [tree, focused] = tab.as_slice() else { return Err(unsupported()) };
            let mut leaves = Vec::new();
            let tree = read_tree(tree, 0, &mut leaves)?;
            let focused = slot(focused)?;
            if !leaves.contains(&focused) || leaves.into_iter().any(|id| !unique.insert(id)) {
                return Err(unsupported());
            }
            Ok(SavedTab { tree, focused })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if order.is_empty()
        || unique.len() > 64
        || unique != record.sessions.keys().copied().collect()
        || record.sessions.values().any(|session| {
            session.kind != SessionKind::Terminal
                || session.forward.is_some()
                || session.working_directory.is_some()
        })
    {
        return Err(unsupported());
    }
    let active = match active {
        Value::Null => None,
        Value::UInt(index) if *index < order.len() as u64 => Some(*index as u32),
        _ => return Err(unsupported()),
    };
    Ok((record, order, active))
}

#[cfg(test)]
mod tests;
