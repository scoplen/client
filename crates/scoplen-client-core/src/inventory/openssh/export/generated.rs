// SPDX-License-Identifier: Apache-2.0
//! Explicit generation of one namespace's native-owned OpenSSH configuration.

use super::*;
use crate::portable_archive::ArchiveDestination;

/// Why a Host cannot receive an additional friendly alias.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum OpenSshGeneratedAliasProblem {
    /// The complete Host name is outside the supported ASCII grammar.
    InvalidName,
    /// Another live Host has the same ASCII case-insensitive name.
    DuplicateName,
    /// The name is reserved for stable UUID aliases.
    ReservedName,
    /// The Host has no live Login.
    MissingLogin,
    /// The selected default or first Login cannot be exported.
    IncompatibleLogin,
}

/// One Host's friendly alias decision, independent of UUID alias compatibility.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenSshGeneratedAlias {
    /// Saved Host identifier.
    pub host_id: String,
    /// Complete saved display name.
    pub host_name: String,
    /// Selected default or first live Login, before export compatibility checks.
    pub profile_id: Option<String>,
    /// Additional lowercase alias, only when it will be emitted.
    pub alias: Option<String>,
    /// Why no friendly alias will be emitted.
    pub problem: Option<OpenSshGeneratedAliasProblem>,
}

/// Current native-owned Include endpoint, derived from the active profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenSshGeneratedStatus {
    /// Exact current Local or Personal namespace.
    pub destination: ArchiveDestination,
    /// Stable wrapper path, never the user's own OpenSSH config.
    pub include_path: String,
    /// Complete line to add manually to the user's own configuration.
    pub include_line: String,
    /// A complete generation is referenced, including a generation with no Login blocks.
    /// Missing output and the empty wrapper published by Clear report false.
    pub active: bool,
}

/// Secret-free review retained and revalidated by the native boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenSshGeneratedPreview {
    /// Native receipt identity; the frontend does not choose output generations.
    pub id: String,
    /// Exact reviewed namespace.
    pub destination: ArchiveDestination,
    /// Existing authentication, strict-trust and per-Login compatibility report.
    pub report: OpenSshExportPreview,
    /// Friendly alias outcome for every live Host, including excluded Hosts.
    pub aliases: Vec<OpenSshGeneratedAlias>,
}

/// Counts of a complete published configuration generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenSshGeneratedResult {
    /// Stable endpoint after successful publication.
    pub status: OpenSshGeneratedStatus,
    /// Compatible Login blocks in the new generation.
    pub hosts: u32,
    /// Files in the new generation, excluding the stable wrapper.
    pub files: u32,
}

/// Publication errors are structured and never contain secret material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type, thiserror::Error)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum OpenSshGeneratedError {
    /// The selected profile or its Personal ownership changed.
    #[error("the current account profile changed or is locked")]
    ContextChanged,
    /// The review was discarded, replaced or already consumed.
    #[error("review the generated OpenSSH configuration again")]
    PreviewExpired,
    /// The scoped inventory changed after review.
    #[error("the inventory changed after preview")]
    InventoryChanged,
    /// A selected source changed after review.
    #[error("an external key file changed after preview")]
    SourceChanged,
    /// The stable target changed after review or is no longer owned.
    #[error("the generated OpenSSH configuration changed after preview")]
    TargetChanged,
    /// A choice or path cannot be represented safely.
    #[error("the generated OpenSSH selection is invalid")]
    InvalidSelection,
    /// The old active wrapper was retained; partial output is identified if necessary.
    #[error("the generated OpenSSH configuration could not be published")]
    WriteFailed {
        /// Owned incomplete generation retained only when cleanup fails.
        directory: Option<String>,
    },
    /// An empty wrapper was published, but some owned generations remain.
    #[error("the Include was cleared but some generated files could not be removed")]
    ClearFailed {
        /// Owned scope directory containing the retained files.
        directory: String,
    },
}

impl From<OpenSshExportError> for OpenSshGeneratedError {
    fn from(error: OpenSshExportError) -> Self {
        match error {
            OpenSshExportError::InventoryChanged => Self::InventoryChanged,
            OpenSshExportError::SourceChanged => Self::SourceChanged,
            OpenSshExportError::ContextChanged => Self::ContextChanged,
            OpenSshExportError::WriteFailed { directory } => Self::WriteFailed { directory },
            OpenSshExportError::Empty
            | OpenSshExportError::InvalidSelection
            | OpenSshExportError::DestinationExists => Self::InvalidSelection,
        }
    }
}

/// Quote a native-owned path for one literal OpenSSH Include directive.
pub fn generated_open_ssh_include_line(path: &Path) -> Result<String, OpenSshGeneratedError> {
    if !path.is_absolute() || !path_supported(path) {
        return Err(OpenSshGeneratedError::InvalidSelection);
    }
    let text = export_path(path);
    // Include expands glob patterns even inside quotes; never broaden a native path.
    if text.contains(['*', '?', '[', ']']) {
        return Err(OpenSshGeneratedError::InvalidSelection);
    }
    Ok(format!("Include {}", quoted(&text)))
}

fn prepared(
    inventory: &Inventory,
    choices: Vec<OpenSshExportChoice>,
) -> Result<(ArchiveDestination, Prepared, Vec<OpenSshGeneratedAlias>), OpenSshGeneratedError> {
    let (destination, snapshot) = inventory
        .store
        .openssh_generated_snapshot()
        .map_err(|_| OpenSshGeneratedError::ContextChanged)?;
    let hosts = records::<Host>(&snapshot)?;
    let profiles = records::<AccessProfile>(&snapshot)?;
    let prepared = prepare_snapshot(inventory, choices, snapshot)?;
    let mut names = BTreeMap::<String, usize>::new();
    for host in &hosts {
        *names.entry(host.name.to_ascii_lowercase()).or_default() += 1;
    }
    let mut aliases = Vec::with_capacity(hosts.len());
    for host in hosts {
        let mut logins =
            profiles.iter().filter(|profile| profile.host == host.meta.id).collect::<Vec<_>>();
        logins.sort_by_key(|profile| profile.meta.id);
        let selected = host
            .default_profile
            .and_then(|id| logins.iter().find(|profile| profile.meta.id == id).copied())
            .or_else(|| logins.first().copied());
        let name = host.name.to_ascii_lowercase();
        let valid = host.name.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
            && host.name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        let reserved = name.strip_prefix("scoplen-").is_some_and(|suffix| {
            suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        });
        let problem = if !valid {
            Some(OpenSshGeneratedAliasProblem::InvalidName)
        } else if names[&name] != 1 {
            Some(OpenSshGeneratedAliasProblem::DuplicateName)
        } else if reserved {
            Some(OpenSshGeneratedAliasProblem::ReservedName)
        } else if let Some(profile) = selected {
            (!prepared
                .preview
                .entries
                .iter()
                .any(|entry| entry.profile_id == profile.meta.id.to_string()))
            .then_some(OpenSshGeneratedAliasProblem::IncompatibleLogin)
        } else {
            Some(OpenSshGeneratedAliasProblem::MissingLogin)
        };
        aliases.push(OpenSshGeneratedAlias {
            host_id: host.meta.id.to_string(),
            host_name: host.name,
            profile_id: selected.map(|profile| profile.meta.id.to_string()),
            alias: problem.is_none().then_some(name),
            problem,
        });
    }
    Ok((destination, prepared, aliases))
}

fn recheck(
    inventory: &Inventory,
    preview: &OpenSshGeneratedPreview,
) -> Result<Prepared, OpenSshGeneratedError> {
    let (destination, prepared, aliases) = prepared(inventory, preview.report.choices.clone())?;
    if destination != preview.destination {
        return Err(OpenSshGeneratedError::ContextChanged);
    }
    let (old_inventory, _) = preview.report.revision.split_once(':').unwrap_or_default();
    let (new_inventory, _) = prepared.preview.revision.split_once(':').unwrap_or_default();
    if old_inventory != new_inventory {
        return Err(OpenSshGeneratedError::InventoryChanged);
    }
    if preview.report.revision != prepared.preview.revision {
        return Err(OpenSshGeneratedError::SourceChanged);
    }
    if preview.report != prepared.preview || preview.aliases != aliases {
        return Err(OpenSshGeneratedError::InvalidSelection);
    }
    Ok(prepared)
}

impl Inventory {
    /// Resolve only the active Local or admitted Personal namespace.
    pub fn generated_open_ssh_destination(
        &self,
    ) -> Result<ArchiveDestination, OpenSshGeneratedError> {
        self.store
            .openssh_generated_destination()
            .map_err(|_| OpenSshGeneratedError::ContextChanged)
    }

    /// Review exact scoped inventory without publishing files or modifying the user config.
    pub fn preview_generated_open_ssh(
        &self,
        choices: Vec<OpenSshExportChoice>,
    ) -> Result<OpenSshGeneratedPreview, OpenSshGeneratedError> {
        let (destination, prepared, aliases) = prepared(self, choices)?;
        Ok(OpenSshGeneratedPreview {
            id: scoplen_model::new_uuid_v7()
                .map_err(|_| OpenSshGeneratedError::InvalidSelection)?
                .to_string(),
            destination,
            report: prepared.preview,
            aliases,
        })
    }

    /// Revalidate all reviewed source and inventory state before native publication.
    pub fn recheck_generated_open_ssh(
        &self,
        preview: &OpenSshGeneratedPreview,
    ) -> Result<(), OpenSshGeneratedError> {
        recheck(self, preview).map(|_| ())
    }

    /// Write one fresh complete generation. Empty inventories remain valid generations.
    /// The native owner publishes its stable wrapper only after this succeeds.
    pub fn write_generated_open_ssh(
        &self,
        preview: &OpenSshGeneratedPreview,
        directory: &Path,
    ) -> Result<OpenSshExportResult, OpenSshGeneratedError> {
        if !directory.is_absolute() || !path_supported(directory) {
            return Err(OpenSshGeneratedError::InvalidSelection);
        }
        let prepared = recheck(self, preview)?;
        let aliases = preview
            .aliases
            .iter()
            .filter_map(|alias| Some((alias.profile_id.clone()?, alias.alias.clone()?)))
            .collect();
        Ok(write_with_aliases(&prepared, directory, &aliases)?)
    }
}

#[cfg(test)]
mod tests;
