// SPDX-License-Identifier: Apache-2.0

//! Explicit standard OpenSSH export without copying private credentials.

use super::*;
use std::{
    io::Write,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    connection::{
        CredentialMaterial, HostKeyPresentation, HostKeyStatus, assess_host_key,
        private_key_passphrase_required, resolve_credential, validate_credential,
    },
    repository::TrustRecord,
    store::openssh::ExportSnapshot,
};

/// An existing external private-key file selected for one Login.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenSshExportChoice {
    /// The saved Login identifier.
    pub profile_id: String,
    /// The source file to reference, never copy.
    pub identity_file: String,
}

/// The external authentication an exported Login requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum OpenSshExportAuthentication {
    /// OpenSSH asks for the password; no saved password is exported.
    Password,
    /// The exact public identity must already be loaded in the system agent.
    Agent,
    /// OpenSSH reads the verified existing private-key source file.
    IdentityFile,
}

/// One complete standard Host block that will be written.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenSshExportEntry {
    /// Saved Host identifier.
    pub host_id: String,
    /// Saved Login identifier.
    pub profile_id: String,
    /// Stable concrete alias for external OpenSSH.
    pub alias: String,
    /// Saved Host display name.
    pub host_name: String,
    /// Saved Login display name, or its username.
    pub login_name: String,
    /// Actual SSH endpoint.
    pub address: String,
    /// Actual SSH port.
    pub port: u16,
    /// Remote username.
    pub username: String,
    /// External credential mechanism, without secret material.
    pub authentication: OpenSshExportAuthentication,
    /// Existing private-key source path; absent for password and agent.
    pub identity_file: Option<String>,
    /// Direct or explicit Direct-hop Jump route.
    pub route: OpenSshImportRoute,
}

/// Why a saved Host or Login cannot be represented by this export.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum OpenSshExportSkipReason {
    /// The Host has no saved Login.
    MissingLogin,
    /// The assigned Credential is missing or unusable.
    UnavailableCredential,
    /// A software key needs a matching existing external private-key file.
    IdentityFileRequired,
    /// The selected external file does not match the actual saved private key.
    IdentityFileMismatch,
    /// This Credential kind cannot be represented without exporting a secret.
    UnsupportedCredential,
    /// This route has no supported standard representation.
    UnsupportedRoute,
    /// A required direct Jump Login cannot be exported.
    RouteDependency,
    /// Saved options or trust semantics cannot be represented faithfully.
    UnsupportedOptions,
    /// An endpoint or username cannot be represented safely.
    InvalidValue,
}

/// A complete per-row refusal, including Hosts without Logins.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenSshExportSkipped {
    /// Saved Host identifier.
    pub host_id: String,
    /// Saved Login identifier, absent when the Host has none.
    pub profile_id: Option<String>,
    /// Saved Host display name.
    pub host_name: String,
    /// Saved Login display name, absent when the Host has none.
    pub login_name: Option<String>,
    /// Why no Host block will be written.
    pub reason: OpenSshExportSkipReason,
}

/// Read-only review of all inventory in the current Local or Personal profile.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenSshExportPreview {
    /// Fingerprint of reviewed inventory and external source files.
    pub revision: String,
    /// Explicit existing-key source choices used for this review.
    pub choices: Vec<OpenSshExportChoice>,
    /// Complete Host blocks, including independently usable Jump Logins.
    pub entries: Vec<OpenSshExportEntry>,
    /// Every excluded Host or Login and its reason.
    pub skipped: Vec<OpenSshExportSkipped>,
    /// Ordinary exact trusted host keys that will be written.
    pub trust_records: u32,
}

/// The newly created export directory and its actual written counts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct OpenSshExportResult {
    /// Fresh directory containing config, known_hosts and public identities only.
    pub directory: String,
    /// Number of Host blocks written.
    pub hosts: u32,
    /// Number of regular files written.
    pub files: u32,
}

/// An export refusal never overwrites an existing destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type, thiserror::Error)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum OpenSshExportError {
    /// No complete Host block is available.
    #[error("there are no exportable Logins")]
    Empty,
    /// Saved inventory changed after review.
    #[error("the inventory changed after preview")]
    InventoryChanged,
    /// An external key source changed after review.
    #[error("an external key file changed after preview")]
    SourceChanged,
    /// A source choice or destination is invalid.
    #[error("the export selection is invalid")]
    InvalidSelection,
    /// The fresh destination already exists and was left untouched.
    #[error("the export destination already exists")]
    DestinationExists,
    /// Writing failed; any retained partial export is identified explicitly.
    #[error("the OpenSSH export could not be written")]
    WriteFailed {
        /// Partial owned directory if cleanup failed; otherwise absent.
        directory: Option<String>,
    },
    /// The originating profile is no longer available.
    #[error("the current account profile changed or is locked")]
    ContextChanged,
}

struct Prepared {
    preview: OpenSshExportPreview,
    public_identities: BTreeMap<Uuid, String>,
    profile_credentials: BTreeMap<String, Uuid>,
    known_hosts: BTreeSet<String>,
}

impl Inventory {
    /// Review all saved Logins without changing files, inventory or agent state.
    pub fn preview_open_ssh_export(
        &self,
        choices: Vec<OpenSshExportChoice>,
    ) -> Result<OpenSshExportPreview, OpenSshExportError> {
        Ok(prepare(self, choices)?.preview)
    }

    /// Recheck a reviewed export and create a fresh child of the selected parent.
    /// No existing file or external private key is overwritten or copied.
    pub fn export_open_ssh_config(
        &self,
        preview: OpenSshExportPreview,
        parent: PathBuf,
    ) -> Result<OpenSshExportResult, OpenSshExportError> {
        let parent = parent.canonicalize().map_err(|_| OpenSshExportError::InvalidSelection)?;
        if !parent.is_dir() || !path_supported(&parent) {
            return Err(OpenSshExportError::InvalidSelection);
        }
        let millis = scoplen_model::system_time_millis()
            .map_err(|_| OpenSshExportError::InvalidSelection)?;
        self.export_open_ssh_into(preview, parent.join(format!("scoplen-openssh-{millis}")))
    }

    fn export_open_ssh_into(
        &self,
        preview: OpenSshExportPreview,
        directory: PathBuf,
    ) -> Result<OpenSshExportResult, OpenSshExportError> {
        let prepared = prepare(self, preview.choices.clone())?;
        let (old_inventory, _) = preview.revision.split_once(':').unwrap_or_default();
        let (new_inventory, _) = prepared.preview.revision.split_once(':').unwrap_or_default();
        if old_inventory != new_inventory {
            return Err(OpenSshExportError::InventoryChanged);
        }
        if prepared.preview.revision != preview.revision {
            return Err(OpenSshExportError::SourceChanged);
        }
        if prepared.preview != preview {
            return Err(OpenSshExportError::InvalidSelection);
        }
        if preview.entries.is_empty() {
            return Err(OpenSshExportError::Empty);
        }
        write(&prepared, &directory)
    }
}

fn records<T: Record>(snapshot: &ExportSnapshot) -> Result<Vec<T>, OpenSshExportError> {
    snapshot
        .objects
        .values()
        .filter(|object| object.object_type == T::TYPE)
        .map(|object| T::read(object).map_err(|_| OpenSshExportError::ContextChanged))
        .collect()
}

fn prepare(
    inventory: &Inventory,
    mut choices: Vec<OpenSshExportChoice>,
) -> Result<Prepared, OpenSshExportError> {
    let snapshot = inventory
        .store
        .openssh_export_snapshot()
        .map_err(|_| OpenSshExportError::ContextChanged)?;
    let hosts = records::<Host>(&snapshot)?;
    let profiles = records::<AccessProfile>(&snapshot)?;
    let credentials = records::<Credential>(&snapshot)?;
    let routes = records::<Route>(&snapshot)?;
    let trust = records::<TrustRecord>(&snapshot)?;
    choices.sort_by(|a, b| a.profile_id.cmp(&b.profile_id));
    if choices.len() > profiles.len()
        || choices.iter().enumerate().any(|(index, choice)| {
            index > 0 && choices[index - 1].profile_id == choice.profile_id
                || !profiles.iter().any(|profile| profile.meta.id.to_string() == choice.profile_id)
        })
    {
        return Err(OpenSshExportError::InvalidSelection);
    }
    let mut result = Prepared {
        preview: OpenSshExportPreview {
            revision: String::new(),
            choices,
            entries: Vec::new(),
            skipped: Vec::new(),
            trust_records: 0,
        },
        public_identities: BTreeMap::new(),
        profile_credentials: BTreeMap::new(),
        known_hosts: BTreeSet::new(),
    };
    let mut sources = Sha256::new();
    let mut host_trust = BTreeMap::new();
    for host in &hosts {
        host_trust.insert(host.meta.id, compatible_trust(inventory, host, &trust));
        let logins =
            profiles.iter().filter(|profile| profile.host == host.meta.id).collect::<Vec<_>>();
        if logins.is_empty() {
            result.preview.skipped.push(skipped(host, None, OpenSshExportSkipReason::MissingLogin));
        }
        for profile in logins {
            let evaluated = entry(
                inventory,
                host,
                profile,
                &credentials,
                &routes,
                &snapshot,
                &result.preview.choices,
                &mut sources,
            )
            .and_then(|(entry, public, credential)| {
                if host_trust[&host.meta.id].is_err() {
                    return Err(OpenSshExportSkipReason::UnsupportedOptions);
                }
                if let Some(public) = public {
                    result.public_identities.insert(credential, public);
                }
                result.profile_credentials.insert(entry.profile_id.clone(), credential);
                Ok(entry)
            });
            match evaluated {
                Ok(row) => result.preview.entries.push(row),
                Err(reason) => result.preview.skipped.push(skipped(host, Some(profile), reason)),
            }
        }
    }
    let direct = result
        .preview
        .entries
        .iter()
        .filter(|row| row.route == OpenSshImportRoute::Direct)
        .map(|row| (row.alias.clone(), row.host_id.clone()))
        .collect::<BTreeMap<_, _>>();
    result.preview.entries.retain(|row| {
        if let OpenSshImportRoute::Jump { hops } = &row.route
            && (hops.iter().any(|hop| !direct.contains_key(hop) || direct[hop] == row.host_id)
                || hops.iter().filter_map(|hop| direct.get(hop)).collect::<BTreeSet<_>>().len()
                    != hops.len())
        {
            result.preview.skipped.push(OpenSshExportSkipped {
                host_id: row.host_id.clone(),
                profile_id: Some(row.profile_id.clone()),
                host_name: row.host_name.clone(),
                login_name: Some(row.login_name.clone()),
                reason: OpenSshExportSkipReason::RouteDependency,
            });
            false
        } else {
            true
        }
    });
    let included =
        result.preview.entries.iter().map(|row| row.host_id.clone()).collect::<BTreeSet<_>>();
    for (host, lines) in host_trust {
        if included.contains(&host.to_string()) {
            result.known_hosts.extend(lines.unwrap_or_default());
        }
    }
    // Bind the review to the trust decisions as well as their saved records.
    for line in &result.known_hosts {
        sources.update((line.len() as u64).to_be_bytes());
        sources.update(line.as_bytes());
    }
    result.preview.trust_records = result.known_hosts.len() as u32;
    result.preview.revision = format!("{}:{:x}", snapshot.revision, sources.finalize());
    result.preview.entries.sort_by(|a, b| a.alias.cmp(&b.alias));
    result
        .preview
        .skipped
        .sort_by(|a, b| (&a.host_id, &a.profile_id).cmp(&(&b.host_id, &b.profile_id)));
    Ok(result)
}

fn skipped(
    host: &Host,
    profile: Option<&AccessProfile>,
    reason: OpenSshExportSkipReason,
) -> OpenSshExportSkipped {
    OpenSshExportSkipped {
        host_id: host.meta.id.to_string(),
        profile_id: profile.map(|p| p.meta.id.to_string()),
        host_name: host.name.clone(),
        login_name: profile.map(login_name),
        reason,
    }
}

fn login_name(profile: &AccessProfile) -> String {
    profile.name.clone().unwrap_or_else(|| profile.username.clone())
}

fn alias(profile: Uuid) -> String {
    format!("scoplen-{}", profile.simple())
}

#[allow(clippy::too_many_arguments)]
fn entry(
    inventory: &Inventory,
    host: &Host,
    profile: &AccessProfile,
    credentials: &[Credential],
    routes: &[Route],
    snapshot: &ExportSnapshot,
    choices: &[OpenSshExportChoice],
    sources: &mut Sha256,
) -> Result<(OpenSshExportEntry, Option<String>, Uuid), OpenSshExportSkipReason> {
    use OpenSshExportSkipReason as Skip;
    if host.port == 0
        || host.address.is_empty()
        || host.address.starts_with('-')
        || host.address.chars().any(|c| c.is_whitespace() || c.is_control())
        || host.address.contains(['%', '$', '#', '"', '\'', '\\', '*', '?', ',', '[', ']'])
        || profile.username.is_empty()
        || profile.username.chars().any(char::is_control)
        || profile.username.contains(['%', '$'])
    {
        return Err(Skip::InvalidValue);
    }
    if !host.ssh_options.is_empty()
        || !host.mosh.is_empty()
        || profile.startup_command.is_some()
        || !profile.forwards.is_empty()
        || profile.agent_forwarding
    {
        return Err(Skip::UnsupportedOptions);
    }
    let route = match profile.route {
        RouteChoice::Direct => OpenSshImportRoute::Direct,
        RouteChoice::Route(id) => {
            match routes.iter().find(|route| route.meta.id == id).map(|r| &r.kind) {
                Some(RouteKind::Jump { hops })
                    if !hops.is_empty()
                        && hops.len() <= 8
                        && hops.iter().collect::<BTreeSet<_>>().len() == hops.len() =>
                {
                    OpenSshImportRoute::Jump { hops: hops.iter().map(|hop| alias(*hop)).collect() }
                }
                _ => return Err(Skip::UnsupportedRoute),
            }
        }
    };
    let credential = profile
        .credential
        .and_then(|id| credentials.iter().find(|c| c.meta.id == id))
        .ok_or(Skip::UnavailableCredential)?;
    if !matches!(
        credential.kind,
        CredentialKind::Password | CredentialKind::PrivateKey | CredentialKind::Agent
    ) {
        return Err(Skip::UnsupportedCredential);
    }
    let material = resolve_credential(&inventory.store, credential)
        .map_err(|_| Skip::UnavailableCredential)?;
    validate_credential(&material).map_err(|_| Skip::UnavailableCredential)?;
    private_key_passphrase_required(&material).map_err(|_| Skip::UnavailableCredential)?;
    let (authentication, identity_file, public) = match material {
        CredentialMaterial::Password(secret)
            if !secret.as_bytes().is_empty() && std::str::from_utf8(secret.as_bytes()).is_ok() =>
        {
            (OpenSshExportAuthentication::Password, None, None)
        }
        CredentialMaterial::Agent { public_key: Some(public_key) } => {
            let mut public = ssh_key::PublicKey::from_openssh(&public_key)
                .map_err(|_| Skip::UnavailableCredential)?;
            public.set_comment("");
            (
                OpenSshExportAuthentication::Agent,
                None,
                Some(public.to_openssh().map_err(|_| Skip::UnavailableCredential)?),
            )
        }
        CredentialMaterial::PrivateKey(secret) => {
            let private = ssh_key::PrivateKey::from_openssh(secret.as_bytes())
                .map_err(|_| Skip::UnavailableCredential)?;
            let selected = choices.iter().find(|c| c.profile_id == profile.meta.id.to_string());
            let candidates = selected.map(|c| vec![c.identity_file.clone()]).unwrap_or_else(|| {
                snapshot.identity_files.get(&credential.meta.id).cloned().unwrap_or_default()
            });
            let mut matching = None;
            for candidate in candidates {
                if let Some(path) = matching_source(&candidate, private.public_key(), sources) {
                    matching = Some(path);
                    break;
                }
            }
            let file = matching.ok_or(if selected.is_some() {
                Skip::IdentityFileMismatch
            } else {
                Skip::IdentityFileRequired
            })?;
            (OpenSshExportAuthentication::IdentityFile, Some(file), None)
        }
        _ => return Err(Skip::UnavailableCredential),
    };
    Ok((
        OpenSshExportEntry {
            host_id: host.meta.id.to_string(),
            profile_id: profile.meta.id.to_string(),
            alias: alias(profile.meta.id),
            host_name: host.name.clone(),
            login_name: login_name(profile),
            address: host.address.clone(),
            port: host.port,
            username: profile.username.clone(),
            authentication,
            identity_file,
            route,
        },
        public,
        credential.meta.id,
    ))
}

fn matching_source(
    candidate: &str,
    public: &ssh_key::PublicKey,
    hash: &mut Sha256,
) -> Option<String> {
    let path = Path::new(candidate).canonicalize().ok()?;
    if !path.is_file() || !path_supported(&path) {
        return None;
    }
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(&path).ok()?.take(65537).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 65536 {
        return None;
    }
    let private = ssh_key::PrivateKey::from_openssh(bytes.as_slice()).ok()?;
    if private.public_key().key_data() != public.key_data() {
        return None;
    }
    let file = export_path(&path);
    hash.update((file.len() as u64).to_be_bytes());
    hash.update(file.as_bytes());
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes.as_slice());
    Some(file)
}

fn compatible_trust(
    inventory: &Inventory,
    host: &Host,
    trust: &[TrustRecord],
) -> Result<Vec<String>, ()> {
    let endpoint = if host.port == 22 {
        host.address.clone()
    } else {
        format!("[{}]:{}", host.address, host.port)
    };
    let mut lines = Vec::new();
    for record in trust.iter().filter(|r| r.host == Some(host.meta.id)) {
        if record.revoked || record.ca || record.pattern.as_ref().is_some_and(|p| p != &endpoint) {
            return Err(());
        }
        let key =
            ssh_key::PublicKey::from_openssh(record.key.as_deref().ok_or(())?).map_err(|_| ())?;
        let text = key.to_openssh().map_err(|_| ())?;
        let presentation = HostKeyPresentation {
            algorithm: key.algorithm().as_str().into(),
            key: text.clone(),
            fingerprint: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        };
        if assess_host_key(&inventory.store, host.meta.id, &presentation).map_err(|_| ())?.status
            != HostKeyStatus::Trusted
        {
            return Err(());
        }
        lines.push(format!("scoplen-host-{} {text}", host.meta.id.simple()));
    }
    Ok(lines)
}

fn path_supported(path: &Path) -> bool {
    path.to_str()
        .is_some_and(|text| !text.chars().any(char::is_control) && !text.contains(['%', '$']))
}

fn export_path(path: &Path) -> String {
    let text = parse::display(path);
    #[cfg(windows)]
    {
        if let Some(rest) = text.strip_prefix("\\\\?\\UNC\\") {
            return format!("//{}", rest.replace('\\', "/"));
        }
        text.strip_prefix("\\\\?\\").unwrap_or(&text).replace('\\', "/")
    }
    #[cfg(not(windows))]
    text
}

fn quoted(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

fn write(prepared: &Prepared, directory: &Path) -> Result<OpenSshExportResult, OpenSshExportError> {
    std::fs::create_dir(directory).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            OpenSshExportError::DestinationExists
        } else {
            OpenSshExportError::WriteFailed { directory: None }
        }
    })?;
    let outcome = write_files(prepared, directory);
    match outcome {
        Ok(files) => Ok(OpenSshExportResult {
            directory: parse::display(directory),
            hosts: prepared.preview.entries.len() as u32,
            files,
        }),
        Err(_) => {
            let retained =
                std::fs::remove_dir_all(directory).err().map(|_| parse::display(directory));
            Err(OpenSshExportError::WriteFailed { directory: retained })
        }
    }
}

fn write_files(prepared: &Prepared, directory: &Path) -> std::io::Result<u32> {
    let mut config =
        String::from("# Generated by Scoplen. Passwords and private keys are not included.\n");
    let known = quoted(&export_path(&directory.join("known_hosts")));
    let mut identities = BTreeMap::new();
    for row in &prepared.preview.entries {
        let label = format!("{} / {}", row.host_name, row.login_name)
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect::<String>();
        config.push_str(&format!("\n# {label}\n"));
        config.push_str(&format!(
            "\nHost {}\n  HostName {}\n  Port {}\n  User {}\n  HostKeyAlias scoplen-host-{}\n  UserKnownHostsFile {}\n",
            row.alias,
            quoted(&row.address),
            row.port,
            quoted(&row.username),
            Uuid::parse_str(&row.host_id).expect("prepared Host identifier").simple(),
            known
        ));
        match row.authentication {
            OpenSshExportAuthentication::Password => {
                config.push_str("  PreferredAuthentications password\n  IdentityFile none\n");
            }
            OpenSshExportAuthentication::Agent => {
                let id = prepared.profile_credentials[&row.profile_id];
                let file = directory.join("identities").join(format!("{id}.pub"));
                config.push_str(&format!("  PreferredAuthentications publickey\n  IdentitiesOnly yes\n  IdentityFile {}\n", quoted(&export_path(&file))));
                identities.insert(id, file);
            }
            OpenSshExportAuthentication::IdentityFile => {
                config.push_str(&format!("  PreferredAuthentications publickey\n  IdentitiesOnly yes\n  IdentityAgent none\n  IdentityFile {}\n", quoted(row.identity_file.as_deref().unwrap_or_default())));
            }
        }
        if let OpenSshImportRoute::Jump { hops } = &row.route {
            config.push_str(&format!("  ProxyJump {}\n", hops.join(",")));
        }
    }
    if !identities.is_empty() {
        std::fs::create_dir(directory.join("identities"))?;
    }
    for (id, file) in &identities {
        new_file(file, format!("{}\n", prepared.public_identities[id]).as_bytes())?;
    }
    new_file(&directory.join("config"), config.as_bytes())?;
    let mut known_hosts = prepared.known_hosts.iter().cloned().collect::<Vec<_>>().join("\n");
    if !known_hosts.is_empty() {
        known_hosts.push('\n');
    }
    new_file(&directory.join("known_hosts"), known_hosts.as_bytes())?;
    Ok(2 + identities.len() as u32)
}

fn new_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests;
