// SPDX-License-Identifier: Apache-2.0

//! Saved, nonsecret single-line commands for the current terminal (D-131).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use scoplen_model::{MAX_TEXT_BYTES, Object, ObjectType, cbor::Value};
use serde::{Deserialize, Serialize};
use specta::Type;
use uuid::Uuid;

use crate::connection::MAX_SSH_INPUT;
use crate::repository::{
    Edit, Record, RecordError, Repository, Snippet, SnippetChange, Variable, VariableKind,
};
use crate::store::{Store, StoreError};

/// Variable kinds in the editor and retained read-only definitions.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SnippetVariableKind {
    /// Literal text, including an explicit empty value.
    Text,
    /// Canonical signed 64-bit decimal.
    Integer,
    /// One exact member of a saved list.
    Choice,
    /// Retained metadata only; this workflow cannot edit or execute secrets.
    Secret,
}

impl From<VariableKind> for SnippetVariableKind {
    fn from(kind: VariableKind) -> Self {
        match kind {
            VariableKind::Text => Self::Text,
            VariableKind::Integer => Self::Integer,
            VariableKind::Choice => Self::Choice,
            VariableKind::Secret => Self::Secret,
        }
    }
}

impl From<SnippetVariableKind> for VariableKind {
    fn from(kind: SnippetVariableKind) -> Self {
        match kind {
            SnippetVariableKind::Text => Self::Text,
            SnippetVariableKind::Integer => Self::Integer,
            SnippetVariableKind::Choice => Self::Choice,
            SnippetVariableKind::Secret => Self::Secret,
        }
    }
}

/// A definition submitted to the nonsecret editor.
#[derive(Clone, Deserialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnippetVariableInput {
    /// Exact placeholder name.
    pub name: String,
    /// Value validation rule.
    pub kind: SnippetVariableKind,
    /// Optional default, using the repository's string projection.
    pub default: Option<String>,
    /// Exact values for Choice; empty for other kinds.
    pub choices: Vec<String>,
}

impl std::fmt::Debug for SnippetVariableInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut view = f.debug_struct("SnippetVariableInput");
        view.field("name", &self.name).field("kind", &self.kind);
        if self.kind == SnippetVariableKind::Secret {
            view.field("has_default", &self.default.is_some());
        } else {
            view.field("default", &self.default).field("choices", &self.choices);
        }
        view.finish()
    }
}

/// A complete editable Snippet description; storage retains unknown fields.
#[derive(Clone, Debug, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SnippetInput {
    /// User-visible name.
    pub name: String,
    /// Single-line command and exact placeholders.
    pub template: String,
    /// Distinct named variable definitions.
    pub variables: Vec<SnippetVariableInput>,
    /// Search labels.
    pub tags: Vec<String>,
    /// Optional folder label.
    pub folder: Option<String>,
}

/// A safe definition, excluding any retained Secret default or choices.
#[derive(Clone, Debug, Serialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnippetVariableView {
    /// Exact placeholder name.
    pub name: String,
    /// Value validation rule.
    pub kind: SnippetVariableKind,
    /// Nonsecret default; always absent for Secret.
    pub default: Option<String>,
    /// Nonsecret Choice members; always empty for Secret.
    pub choices: Vec<String>,
    /// Distinguishes a redacted default from an absent default.
    pub has_default: bool,
}

/// Display-safe contents of one retained Snippet.
#[derive(Clone, Debug, Serialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnippetView {
    /// Canonical object identifier.
    pub id: String,
    /// User-visible name.
    pub name: String,
    /// Command template, never expanded with a Secret.
    pub template: String,
    /// Safe variable definitions.
    pub variables: Vec<SnippetVariableView>,
    /// Search labels.
    pub tags: Vec<String>,
    /// Optional folder label.
    pub folder: Option<String>,
    /// This editor cannot alter retained Secret or unreadable definitions.
    pub read_only: bool,
    /// Why this definition is unavailable for preparation.
    pub issue: Option<SnippetIssue>,
}

/// An exact nonsecret preview; the Send action adds one CR.
#[derive(Clone, Debug, Serialize, Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PreparedSnippet {
    /// The definition used for this preparation.
    pub snippet_id: String,
    /// Complete literal command, without a terminating CR.
    pub command: String,
}

/// Fixed failures carry variable names but never their submitted values.
#[derive(Clone, Debug, Serialize, Type, PartialEq, Eq, thiserror::Error)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SnippetIssue {
    /// The owning local data context is unavailable.
    #[error("local data is unavailable")]
    Unavailable,
    /// An identifier is not a canonical UUIDv7.
    #[error("the snippet identifier is invalid")]
    InvalidId,
    /// This live object does not exist in the current store.
    #[error("the snippet no longer exists")]
    NotFound,
    /// Retained unsupported contents cannot be changed by this editor.
    #[error("this snippet is read-only")]
    ReadOnly,
    /// Ordinary terminal input cannot provide Secret history exclusion.
    #[error("secret variables cannot be used in this workflow")]
    SecretUnsupported,
    /// The display name is blank or too long.
    #[error("enter a nonempty snippet name within the text limit")]
    InvalidName,
    /// A template is blank, too long or contains terminal controls.
    #[error("enter a single-line command without control characters")]
    InvalidTemplate,
    /// Placeholder names use the documented ASCII identifier grammar.
    #[error("a variable name is invalid")]
    InvalidVariableName,
    /// A submitted definition repeats a variable name.
    #[error("variable names must be unique")]
    DuplicateVariable,
    /// A saved object is outside the supported typed shape or model limits.
    #[error("this snippet definition is unsupported")]
    InvalidDefinition,
    /// A complete command and its final CR exceed the terminal input bound.
    #[error("the command and Enter exceed the terminal input limit")]
    CommandTooLarge,
    /// Storage failed without exposing its data or internal error text.
    #[error("the snippet could not be read or saved; try again")]
    Storage,
    /// A placeholder has no definition.
    #[error("a command placeholder has no variable definition")]
    UnknownPlaceholder {
        /// The undeclared placeholder identifier.
        name: String,
    },
    /// A definition has no unescaped placeholder.
    #[error("a variable is not used in the command")]
    UnusedVariable {
        /// The unused definition's identifier.
        name: String,
    },
    /// A saved default does not match the definition.
    #[error("a variable default is invalid")]
    InvalidDefault {
        /// The definition's identifier, never its default value.
        name: String,
    },
    /// Choices are missing, repeated or invalid for the variable kind.
    #[error("a variable's choices are invalid")]
    InvalidChoices {
        /// The definition's identifier, never a choice value.
        name: String,
    },
    /// Neither an explicit input nor a default is available.
    #[error("enter a value for every variable")]
    MissingValue {
        /// The missing input's identifier.
        name: String,
    },
    /// A submitted input does not name a saved variable.
    #[error("an input does not belong to this snippet")]
    UnknownValue {
        /// The unmatched input's identifier, never its submitted value.
        name: String,
    },
    /// A value violates its type or single-line input rule.
    #[error("a variable value is invalid")]
    InvalidValue {
        /// The definition's identifier, never the rejected input.
        name: String,
    },
}

impl From<StoreError> for SnippetIssue {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Model(_) => Self::InvalidDefinition,
            _ => Self::Storage,
        }
    }
}

impl From<RecordError> for SnippetIssue {
    fn from(error: RecordError) -> Self {
        match error {
            RecordError::Model(_) | RecordError::Shape(..) => Self::InvalidDefinition,
            RecordError::Store(error) => error.into(),
            _ => Self::Storage,
        }
    }
}

/// Store-bound production facade. Preparation never sends network input.
pub struct Snippets {
    store: Arc<Store>,
}

impl Snippets {
    /// Capture the caller's current local store.
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// List live objects, preserving unavailable synchronized definitions.
    pub fn list(&self) -> Result<Vec<SnippetView>, SnippetIssue> {
        let mut views = self.store.list(ObjectType::SNIPPET)?.iter().map(view).collect::<Vec<_>>();
        views.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        Ok(views)
    }

    /// Save a fully validated nonsecret command without executing it.
    pub fn create(&self, input: SnippetInput) -> Result<SnippetView, SnippetIssue> {
        validate(&input)?;
        let record = Repository::<Snippet>::new(&self.store).create(change(input, None))?;
        Ok(record_view(&record))
    }

    /// Replace known editable fields through ordinary per-field writes.
    pub fn update(&self, id: &str, input: SnippetInput) -> Result<SnippetView, SnippetIssue> {
        let object = self.object(id)?;
        let record = Snippet::read(&object).map_err(|_| SnippetIssue::ReadOnly)?;
        if has_secret(&record) {
            return Err(SnippetIssue::ReadOnly);
        }
        validate(&input)?;
        let updated = Repository::<Snippet>::new(&self.store)
            .update(record.meta.id, change(input, Some(&record)))?;
        Ok(record_view(&updated))
    }

    /// Tombstone one editable command; retained Secret objects stay intact.
    pub fn delete(&self, id: &str) -> Result<(), SnippetIssue> {
        let object = self.object(id)?;
        let record = Snippet::read(&object).map_err(|_| SnippetIssue::ReadOnly)?;
        if has_secret(&record) {
            return Err(SnippetIssue::ReadOnly);
        }
        Repository::<Snippet>::new(&self.store).delete(record.meta.id)?;
        Ok(())
    }

    /// Render one exact preview using current definitions and explicit values.
    pub fn prepare(
        &self,
        id: &str,
        values: BTreeMap<String, String>,
    ) -> Result<PreparedSnippet, SnippetIssue> {
        let object = self.object(id)?;
        let record = Snippet::read(&object).map_err(|_| SnippetIssue::InvalidDefinition)?;
        if has_secret(&record) {
            return Err(SnippetIssue::SecretUnsupported);
        }
        let input = input_of(&record);
        let parts = validate(&input)?;
        let definitions: BTreeMap<_, _> =
            input.variables.iter().map(|variable| (variable.name.as_str(), variable)).collect();
        for name in values.keys() {
            if !definitions.contains_key(name.as_str()) {
                return Err(SnippetIssue::UnknownValue { name: name.clone() });
            }
        }
        let mut resolved = BTreeMap::new();
        for (name, definition) in definitions {
            let value = values
                .get(name)
                .or(definition.default.as_ref())
                .ok_or_else(|| SnippetIssue::MissingValue { name: name.into() })?;
            if !valid_value(definition, value) {
                return Err(SnippetIssue::InvalidValue { name: name.into() });
            }
            resolved.insert(name, value.as_str());
        }
        let mut command = String::new();
        for part in parts {
            let text = match part {
                Part::Literal(text) => text,
                Part::Variable(name) => resolved[name],
            };
            if command.len() + text.len() >= MAX_SSH_INPUT {
                return Err(SnippetIssue::CommandTooLarge);
            }
            command.push_str(text);
        }
        Ok(PreparedSnippet { snippet_id: record.meta.id.to_string(), command })
    }

    fn object(&self, id: &str) -> Result<Object, SnippetIssue> {
        let parsed = Uuid::parse_str(id).map_err(|_| SnippetIssue::InvalidId)?;
        if parsed.get_version_num() != 7 || parsed.to_string() != id {
            return Err(SnippetIssue::InvalidId);
        }
        self.store
            .get(parsed)?
            .filter(|object| object.object_type == ObjectType::SNIPPET && !object.is_tombstoned())
            .ok_or(SnippetIssue::NotFound)
    }
}

fn has_secret(record: &Snippet) -> bool {
    record.variables.values().any(|variable| variable.kind == VariableKind::Secret)
}

fn input_of(record: &Snippet) -> SnippetInput {
    SnippetInput {
        name: record.name.clone(),
        template: record.template.clone(),
        variables: record
            .variables
            .iter()
            .map(|(name, variable)| SnippetVariableInput {
                name: name.clone(),
                kind: variable.kind.into(),
                default: variable.default.clone(),
                choices: variable.choices.clone(),
            })
            .collect(),
        tags: record.tags.iter().cloned().collect(),
        folder: record.folder.clone(),
    }
}

fn record_view(record: &Snippet) -> SnippetView {
    let secret = has_secret(record);
    let issue = if secret {
        Some(SnippetIssue::SecretUnsupported)
    } else {
        validate(&input_of(record)).err()
    };
    SnippetView {
        id: record.meta.id.to_string(),
        name: record.name.clone(),
        template: record.template.clone(),
        variables: record
            .variables
            .iter()
            .map(|(name, variable)| {
                let secret = variable.kind == VariableKind::Secret;
                SnippetVariableView {
                    name: name.clone(),
                    kind: variable.kind.into(),
                    default: if secret { None } else { variable.default.clone() },
                    choices: if secret { Vec::new() } else { variable.choices.clone() },
                    has_default: variable.default.is_some(),
                }
            })
            .collect(),
        tags: record.tags.iter().cloned().collect(),
        folder: record.folder.clone(),
        read_only: secret,
        issue,
    }
}

fn view(object: &Object) -> SnippetView {
    match Snippet::read(object) {
        Ok(record) => record_view(&record),
        Err(_) => {
            let text = |field| match object.set_field(field).map(|entry| &entry.value) {
                Some(Value::Text(text)) => Some(text.clone()),
                _ => None,
            };
            SnippetView {
                id: object.id.to_string(),
                name: text(1).unwrap_or_default(),
                template: text(2).unwrap_or_default(),
                variables: Vec::new(),
                tags: Vec::new(),
                folder: text(5),
                read_only: true,
                issue: Some(SnippetIssue::InvalidDefinition),
            }
        }
    }
}

fn change(input: SnippetInput, existing: Option<&Snippet>) -> SnippetChange {
    let mut variables: BTreeMap<_, _> = input
        .variables
        .into_iter()
        .map(|variable| {
            (
                variable.name,
                Some(Variable {
                    kind: variable.kind.into(),
                    default: variable.default,
                    choices: variable.choices,
                }),
            )
        })
        .collect();
    let mut tags: BTreeMap<_, _> = input.tags.into_iter().map(|tag| (tag, true)).collect();
    if let Some(existing) = existing {
        for name in existing.variables.keys() {
            variables.entry(name.clone()).or_insert(None);
        }
        for tag in &existing.tags {
            tags.entry(tag.clone()).or_insert(false);
        }
    }
    SnippetChange {
        name: Some(input.name),
        template: Some(input.template),
        variables,
        tags,
        folder: Edit::from_option(input.folder),
    }
}

enum Part<'a> {
    Literal(&'a str),
    Variable(&'a str),
}

fn identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn single_line(value: &str) -> bool {
    !value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
}

fn integer(value: &str) -> bool {
    value.parse::<i64>().is_ok_and(|number| number.to_string() == value)
}

fn valid_value(variable: &SnippetVariableInput, value: &str) -> bool {
    single_line(value)
        && match variable.kind {
            SnippetVariableKind::Text => true,
            SnippetVariableKind::Integer => integer(value),
            SnippetVariableKind::Choice => variable.choices.iter().any(|choice| choice == value),
            SnippetVariableKind::Secret => false,
        }
}

fn validate(input: &SnippetInput) -> Result<Vec<Part<'_>>, SnippetIssue> {
    if input.variables.iter().any(|variable| variable.kind == SnippetVariableKind::Secret) {
        return Err(SnippetIssue::SecretUnsupported);
    }
    if input.name.trim().is_empty() || input.name.len() > MAX_TEXT_BYTES {
        return Err(SnippetIssue::InvalidName);
    }
    if input.template.trim().is_empty()
        || input.template.len() > MAX_TEXT_BYTES
        || !single_line(&input.template)
    {
        return Err(SnippetIssue::InvalidTemplate);
    }
    if input.tags.iter().any(|tag| tag.len() > MAX_TEXT_BYTES)
        || input.folder.as_ref().is_some_and(|folder| folder.len() > MAX_TEXT_BYTES)
    {
        return Err(SnippetIssue::InvalidDefinition);
    }
    let mut definitions = BTreeSet::new();
    for variable in &input.variables {
        if !identifier(&variable.name) || variable.name.len() > MAX_TEXT_BYTES {
            return Err(SnippetIssue::InvalidVariableName);
        }
        if !definitions.insert(variable.name.as_str()) {
            return Err(SnippetIssue::DuplicateVariable);
        }
        let choices: BTreeSet<_> = variable.choices.iter().collect();
        if match variable.kind {
            SnippetVariableKind::Choice => {
                choices.is_empty()
                    || choices.len() != variable.choices.len()
                    || choices
                        .iter()
                        .any(|choice| choice.len() > MAX_TEXT_BYTES || !single_line(choice))
            }
            _ => !choices.is_empty(),
        } {
            return Err(SnippetIssue::InvalidChoices { name: variable.name.clone() });
        }
        if let Some(default) = &variable.default
            && (default.len() > MAX_TEXT_BYTES || !valid_value(variable, default))
        {
            return Err(SnippetIssue::InvalidDefault { name: variable.name.clone() });
        }
    }
    let mut parts = Vec::new();
    let mut used = BTreeSet::new();
    let mut remaining = input.template.as_str();
    while !remaining.is_empty() {
        if let Some(next) = remaining.strip_prefix("{{{{") {
            parts.push(Part::Literal("{{"));
            remaining = next;
        } else if let Some(next) = remaining.strip_prefix("}}}}") {
            parts.push(Part::Literal("}}"));
            remaining = next;
        } else if let Some(action) = remaining.strip_prefix("{{") {
            if let Some(end) = action.find("}}") {
                let name = &action[..end];
                if identifier(name) {
                    if !definitions.contains(name) {
                        return Err(SnippetIssue::UnknownPlaceholder { name: name.into() });
                    }
                    used.insert(name);
                    parts.push(Part::Variable(name));
                } else {
                    parts.push(Part::Literal(&remaining[..end + 4]));
                }
                remaining = &action[end + 2..];
            } else {
                parts.push(Part::Literal(remaining));
                break;
            }
        } else {
            let length = match remaining.find(['{', '}']) {
                Some(0) => 1,
                Some(index) => index,
                None => remaining.len(),
            };
            parts.push(Part::Literal(&remaining[..length]));
            remaining = &remaining[length..];
        }
    }
    if let Some(name) = definitions.difference(&used).next() {
        return Err(SnippetIssue::UnusedVariable { name: (*name).into() });
    }
    Ok(parts)
}

#[cfg(test)]
mod tests;
