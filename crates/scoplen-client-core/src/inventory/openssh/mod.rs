// SPDX-License-Identifier: Apache-2.0

//! Explicit, repeatable migration from read-only OpenSSH files.

mod export;
mod parse;
mod plan;

pub use export::*;

use super::*;

/// One explicit identity choice for a concrete OpenSSH alias.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSshImportChoice {
    /// Alias shown in the preview.
    pub alias: String,
    /// One of this alias's discovered identity files.
    pub identity_file: Option<String>,
    /// An existing usable local Credential, instead of a source identity file.
    pub credential_id: Option<String>,
}

/// What confirming this row will do to the imported objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum OpenSshImportAction {
    /// A new source Host will be created.
    Create,
    /// Existing source objects have reviewed changes.
    Update,
    /// No object field needs a write.
    Unchanged,
}

/// One current local Credential which passes ordinary SSH material preflight.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenSshImportCredential {
    /// The existing Credential identifier; never secret material.
    pub id: String,
    /// The saved display name, when present.
    pub name: Option<String>,
    /// The supported authentication kind.
    pub kind: CredentialKindInput,
}

/// A route already supported by the client connection orchestrator.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum OpenSshImportRoute {
    /// Ordinary direct SSH.
    Direct,
    /// Explicit concrete aliases, each using a direct Login.
    Jump {
        /// Ordered concrete aliases of direct jump Logins.
        hops: Vec<String>,
    },
    /// The existing literal-argument ProxyCommand transport.
    Command {
        /// The saved literal-argument command.
        command: String,
    },
}

/// Display-only import row. Private keys and passwords never enter this projection.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenSshImportEntry {
    /// The concrete source alias.
    pub alias: String,
    /// The evaluated SSH endpoint address.
    pub address: String,
    /// The evaluated nonzero SSH port.
    pub port: u16,
    /// The evaluated remote username.
    pub username: String,
    /// The source file containing this declaration.
    pub source_file: String,
    /// One-based source line for the displayed declaration.
    pub line: u32,
    /// The selected source identity file, if any.
    pub identity_file: Option<String>,
    /// Existing source or discovered identity files available for explicit selection.
    pub identity_files: Vec<String>,
    /// The selected existing Credential identifier, if any.
    pub credential_id: Option<String>,
    /// Confirmation is unavailable until this row has one usable identity.
    pub needs_credential: bool,
    /// The evaluated supported connection route.
    pub route: OpenSshImportRoute,
    /// The effect on the previously imported objects.
    pub action: OpenSshImportAction,
    /// Number of ordinary host keys associated with the included Hosts.
    pub trust_records: u32,
}

/// A source directive or trust entry with no faithful representation in this import.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenSshUnsupportedDirective {
    /// The source file containing this declaration.
    pub source_file: String,
    /// One-based source line for the displayed declaration.
    pub line: u32,
    /// The source keyword requiring correction or manual handling.
    pub directive: String,
}

/// Why importing an alias would change its configured meaning.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum OpenSshSkipReason {
    /// A matching source option has no executable client representation.
    UnsupportedDirective {
        /// The source keyword responsible for exclusion.
        directive: String,
    },
    /// A conditional rule cannot be frozen into a concrete Host.
    GlobalRules {
        /// The source keyword responsible for exclusion.
        directive: String,
    },
    /// A supported option has an unrepresentable value.
    InvalidValue {
        /// The source keyword responsible for exclusion.
        directive: String,
    },
    /// A Jump hop is unavailable or is itself routed.
    RouteDependency {
        /// The missing or routed hop alias.
        alias: String,
    },
}

/// A concrete alias that needs a source correction before importing.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenSshSkippedHost {
    /// The concrete source alias.
    pub alias: String,
    /// The source file containing this declaration.
    pub source_file: String,
    /// One-based source line for the displayed declaration.
    pub line: u32,
    /// The reason this alias cannot be imported faithfully.
    pub reason: OpenSshSkipReason,
}

/// A complete read-only preview bound to the source files and current imported objects.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenSshImportPreview {
    /// The canonical root configuration used as the local source identity.
    pub path: String,
    /// The explicit identity choices used to compute this preview.
    pub choices: Vec<OpenSshImportChoice>,
    /// The current safe Credential picker catalog, with secrets omitted.
    pub eligible_credentials: Vec<OpenSshImportCredential>,
    /// Fingerprint of all files actually read for this preview.
    pub source_revision: String,
    /// Fingerprint of the imported objects and selected Credential records.
    pub inventory_revision: String,
    /// Number of distinct configuration, identity and trust files read.
    pub files: u32,
    /// Concrete aliases included in this preview.
    pub entries: Vec<OpenSshImportEntry>,
    /// Aliases excluded with their source and explanation.
    pub skipped_hosts: Vec<OpenSshSkippedHost>,
    /// Every unrepresentable source declaration found during reading.
    pub unsupported: Vec<OpenSshUnsupportedDirective>,
}

/// The atomic import result, including unchanged rows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenSshImportResult {
    /// Imported Host details, including rows which were already current.
    pub hosts: Vec<HostDetails>,
    /// Number of new Host rows.
    pub created: u32,
    /// Number of existing Host rows with imported changes.
    pub updated: u32,
    /// Number of already-current Host rows.
    pub unchanged: u32,
    /// Number of ordinary host keys associated with the included Hosts.
    pub trust_records: u32,
    /// Aliases excluded with their source and explanation.
    pub skipped_hosts: Vec<OpenSshSkippedHost>,
    /// Every unrepresentable source declaration found during reading.
    pub unsupported: Vec<OpenSshUnsupportedDirective>,
}

/// An import failure leaves the inventory unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type, thiserror::Error)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum OpenSshImportError {
    /// A required configuration file could not be read.
    #[error("the OpenSSH configuration could not be read")]
    FileNotFound,
    /// A source file is not UTF-8 text.
    #[error("the OpenSSH configuration is not UTF-8 text")]
    NotText,
    /// The source collection exceeds the bounded import size.
    #[error("the OpenSSH files exceed the import limit")]
    TooLarge,
    /// There are no included concrete aliases.
    #[error("the OpenSSH configuration has no representable hosts")]
    NoHosts,
    /// Reviewed source files changed and require a fresh preview.
    #[error("the source files changed after preview")]
    SourceChanged,
    /// Reviewed imported objects changed and require a fresh preview.
    #[error("the imported inventory changed after preview")]
    InventoryChanged,
    /// At least one included alias still needs an explicit identity.
    #[error("choose an identity for every included host before importing")]
    CredentialsRequired,
    /// A selected local Credential cannot authenticate this alias.
    #[error("the selected credential is unavailable for this host")]
    CredentialUnavailable {
        /// Alias requiring a new identity choice.
        alias: String,
    },
    /// A chosen source identity could not be read.
    #[error("the configured identity file could not be read")]
    IdentityNotFound {
        /// The chosen local source path.
        path: String,
    },
    /// The local operation failed without partial changes.
    #[error("{reference}")]
    Failed {
        /// A safe explanation without credential contents.
        reference: String,
    },
}

impl Inventory {
    /// Preview the selected file and its includes without changing files or local data.
    pub fn preview_open_ssh_config(
        &self,
        path: String,
    ) -> Result<OpenSshImportPreview, OpenSshImportError> {
        self.preview_open_ssh_config_with_choices(path, Vec::new())
    }

    /// Recompute a preview after explicit identity selection.
    pub fn preview_open_ssh_config_with_choices(
        &self,
        path: String,
        choices: Vec<OpenSshImportChoice>,
    ) -> Result<OpenSshImportPreview, OpenSshImportError> {
        Ok(plan::prepare(self, path, choices)?.preview)
    }

    /// Recheck the reviewed inputs and commit objects plus import identities atomically.
    pub fn import_open_ssh_config(
        &self,
        preview: OpenSshImportPreview,
    ) -> Result<OpenSshImportResult, OpenSshImportError> {
        let prepared = plan::prepare(self, preview.path.clone(), preview.choices.clone())?;
        if prepared.preview.source_revision != preview.source_revision {
            return Err(OpenSshImportError::SourceChanged);
        }
        if prepared.preview.inventory_revision != preview.inventory_revision {
            return Err(OpenSshImportError::InventoryChanged);
        }
        let mut expected = prepared.preview.clone();
        // The picker catalog is informational; only a selected Credential affects this import.
        expected.eligible_credentials.clone_from(&preview.eligible_credentials);
        if expected != preview {
            return Err(OpenSshImportError::SourceChanged);
        }
        if preview.entries.is_empty() {
            return Err(OpenSshImportError::NoHosts);
        }
        if preview.entries.iter().any(|row| row.needs_credential) {
            return Err(OpenSshImportError::CredentialsRequired);
        }
        if !self
            .store
            .commit_openssh_import(
                &preview.path,
                &prepared.credentials,
                &preview.inventory_revision,
                prepared.writes,
                prepared.removed_trust,
            )
            .map_err(failure)?
        {
            return Err(OpenSshImportError::InventoryChanged);
        }
        let hosts = prepared
            .hosts
            .into_iter()
            .map(|id| {
                self.host_without_promotion(id.to_string()).map_err(failure)?.ok_or_else(|| {
                    OpenSshImportError::Failed {
                        reference: "the imported host is unavailable".into(),
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(OpenSshImportResult {
            hosts,
            created: preview
                .entries
                .iter()
                .filter(|row| row.action == OpenSshImportAction::Create)
                .count() as u32,
            updated: preview
                .entries
                .iter()
                .filter(|row| row.action == OpenSshImportAction::Update)
                .count() as u32,
            unchanged: preview
                .entries
                .iter()
                .filter(|row| row.action == OpenSshImportAction::Unchanged)
                .count() as u32,
            trust_records: preview.entries.iter().map(|row| row.trust_records).sum(),
            skipped_hosts: preview.skipped_hosts,
            unsupported: preview.unsupported,
        })
    }
}

fn failure(error: impl std::fmt::Display) -> OpenSshImportError {
    OpenSshImportError::Failed { reference: error.to_string() }
}

#[cfg(test)]
mod tests;
