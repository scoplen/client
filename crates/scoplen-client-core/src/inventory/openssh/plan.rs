// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use scoplen_model::{ObjectType, cbor::Value};
use zeroize::Zeroizing;

use crate::{
    connection::{
        CredentialMaterial, private_key_passphrase_required, resolve_credential,
        validate_credential,
    },
    store::openssh::{ImportSnapshot, ImportWrite},
};

use super::*;

pub(super) struct Prepared {
    pub preview: OpenSshImportPreview,
    pub writes: Vec<ImportWrite>,
    pub hosts: Vec<Uuid>,
    pub credentials: Vec<Uuid>,
    pub removed_trust: Vec<Uuid>,
}

struct Builder {
    snapshot: ImportSnapshot,
    identities: BTreeMap<String, Uuid>,
    writes: BTreeMap<String, ImportWrite>,
}

impl Builder {
    fn id(&mut self, key: &str, object_type: ObjectType) -> Result<Uuid, OpenSshImportError> {
        if let Some(id) = self.identities.get(key) {
            return Ok(*id);
        }
        let existing = self.snapshot.mappings.get(key).copied().filter(|id| {
            self.snapshot
                .objects
                .get(id)
                .is_some_and(|object| !object.is_tombstoned() && object.object_type == object_type)
        });
        let id = existing.map(Ok).unwrap_or_else(|| new_id().map_err(failure))?;
        self.identities.insert(key.into(), id);
        Ok(id)
    }

    fn write(
        &mut self,
        key: String,
        file: String,
        object_type: ObjectType,
        fields: Vec<(FieldPath, Value)>,
        implicit: bool,
    ) -> Result<(Uuid, bool), OpenSshImportError> {
        let id = self.id(&key, object_type)?;
        if let Some(write) = self.writes.get(&key) {
            return Ok((id, write.changed));
        }
        let existing = self
            .snapshot
            .objects
            .get(&id)
            .filter(|object| !object.is_tombstoned() && object.object_type == object_type);
        let changed = existing.is_none_or(|object| {
            fields.iter().any(|(path, value)| {
                let previous = object.fields.get(path).map(|field| &field.value);
                if *value == Value::Null {
                    previous.is_some_and(|previous| *previous != Value::Null)
                } else {
                    previous != Some(value)
                }
            })
        });
        self.writes.insert(
            key.clone(),
            ImportWrite {
                key,
                file,
                object: NewObject { id, object_type, fields },
                existing: existing.is_some(),
                changed,
                implicit,
            },
        );
        Ok((id, changed))
    }
}

pub(super) fn prepare(
    inventory: &Inventory,
    path: String,
    mut choices: Vec<OpenSshImportChoice>,
) -> Result<Prepared, OpenSshImportError> {
    let mut parsed = parse::read(&path)?;
    if choices.len() > 256 {
        return Err(OpenSshImportError::TooLarge);
    }
    choices.sort_by(|a, b| a.alias.cmp(&b.alias));
    for (index, choice) in choices.iter().enumerate() {
        if !parsed.hosts.iter().any(|host| host.row.alias == choice.alias)
            || index > 0 && choices[index - 1].alias == choice.alias
            || choice.identity_file.is_some() == choice.credential_id.is_some()
        {
            return Err(OpenSshImportError::CredentialUnavailable { alias: choice.alias.clone() });
        }
    }
    let records = Repository::<Credential>::new(&inventory.store).list().map_err(failure)?;
    let eligible = records
        .iter()
        .filter(|credential| usable(&inventory.store, credential))
        .map(|credential| OpenSshImportCredential {
            id: credential.meta.id.to_string(),
            name: credential.name.clone(),
            kind: credential_kind_input(credential.kind),
        })
        .collect::<Vec<_>>();
    let initial = inventory.store.openssh_import_snapshot(&parsed.path, &[]).map_err(failure)?;
    let mut credentials = Vec::new();
    for host in &mut parsed.hosts {
        let choice = choices.iter().find(|choice| choice.alias == host.row.alias);
        let previous = initial
            .mappings
            .get(&format!("profile:{}", host.row.alias))
            .and_then(|id| initial.objects.get(id))
            .filter(|object| !object.is_tombstoned())
            .and_then(|object| object.set_field(4))
            .and_then(|field| match &field.value {
                Value::Bytes(bytes) => Uuid::from_slice(bytes).ok(),
                _ => None,
            });
        if let Some(id) = choice.and_then(|choice| choice.credential_id.clone()) {
            let id = Uuid::parse_str(&id).map_err(|_| {
                OpenSshImportError::CredentialUnavailable { alias: host.row.alias.clone() }
            })?;
            if !eligible.iter().any(|credential| credential.id == id.to_string()) {
                return Err(OpenSshImportError::CredentialUnavailable {
                    alias: host.row.alias.clone(),
                });
            }
            host.row.credential_id = Some(id.to_string());
            credentials.push(id);
        } else if let Some(file) = choice.and_then(|choice| choice.identity_file.clone()) {
            if !host.row.identity_files.contains(&file) {
                return Err(OpenSshImportError::IdentityNotFound { path: file });
            }
            host.row.identity_file = Some(file);
        } else {
            let previous_file = previous.and_then(|id| {
                host.keys.iter().find(|path| {
                    path.canonicalize().ok().is_some_and(|path| {
                        initial.mappings.get(&format!("credential:{}", parse::display(&path)))
                            == Some(&id)
                    })
                })
            });
            let external = previous.filter(|id| {
                eligible.iter().any(|credential| credential.id == id.to_string())
                    && !initial
                        .mappings
                        .iter()
                        .any(|(key, mapped)| key.starts_with("credential:") && mapped == id)
            });
            if let Some(path) = previous_file {
                host.row.identity_file = Some(parse::display(path));
            } else if let Some(id) = external {
                host.row.credential_id = Some(id.to_string());
                credentials.push(id);
            } else if host.keys.len() == 1 {
                host.row.identity_file = Some(parse::display(&host.keys[0]));
            }
        }
        if choice.is_none()
            && host.row.identity_file.as_deref().is_some_and(|file| {
                identity_material(&mut parsed.sources, file, &host.row.alias).is_err()
            })
        {
            host.row.identity_file = None;
        }
        host.row.needs_credential =
            host.row.identity_file.is_none() && host.row.credential_id.is_none();
    }
    credentials.sort();
    credentials.dedup();
    let snapshot =
        inventory.store.openssh_import_snapshot(&parsed.path, &credentials).map_err(failure)?;
    let revision = snapshot.revision.clone();
    let mut builder = Builder { snapshot, identities: BTreeMap::new(), writes: BTreeMap::new() };
    for host in &parsed.hosts {
        builder.id(&format!("host:{}", host.row.alias), ObjectType::HOST)?;
        builder.id(&format!("profile:{}", host.row.alias), ObjectType::ACCESS_PROFILE)?;
    }
    let account =
        crate::connection::host_key_acceptance_account(&inventory.store).map_err(failure)?;
    let now = scoplen_model::system_time_millis().map_err(failure)?;
    let mut hosts = Vec::new();
    let mut removed_trust = Vec::new();
    for host in &mut parsed.hosts {
        let alias = &host.row.alias;
        let host_key = format!("host:{alias}");
        let profile_key = format!("profile:{alias}");
        let host_id = builder.id(&host_key, ObjectType::HOST)?;
        let profile_id = builder.id(&profile_key, ObjectType::ACCESS_PROFILE)?;
        let created = !builder.snapshot.objects.get(&host_id).is_some_and(|o| !o.is_tombstoned());
        let (credential, mut changed) = if let Some(file) = host.row.identity_file.as_deref() {
            let (material, public) = identity_material(&mut parsed.sources, file, alias)?;
            let (kind, binding, secret) = match material {
                CredentialMaterial::PrivateKey(secret) => {
                    (CredentialKind::PrivateKey, CredentialBinding::Shared, Some(secret))
                }
                _ => (CredentialKind::Agent, CredentialBinding::None, None),
            };
            let mut fields = vec![
                (field(2), uint(kind as u64)),
                (field(3), uint(binding as u64)),
                (field(6), text(public)),
            ];
            fields.push((
                field(4),
                secret.map(|value| Value::Bytes(value.as_bytes().to_vec())).unwrap_or(Value::Null),
            ));
            let key = format!(
                "credential:{}",
                parse::display(&Path::new(file).canonicalize().map_err(failure)?)
            );
            let (id, changed) =
                builder.write(key, file.into(), ObjectType::CREDENTIAL, fields, false)?;
            (Some(id), changed)
        } else {
            (host.row.credential_id.as_deref().and_then(|id| Uuid::parse_str(id).ok()), false)
        };
        let route = match &host.row.route {
            OpenSshImportRoute::Direct => Value::UInt(0),
            OpenSshImportRoute::Command { command } => {
                let (id, c) = builder.write(
                    format!("route:{alias}"),
                    host.row.source_file.clone(),
                    ObjectType::ROUTE,
                    vec![
                        (field(1), text(format!("{alias} route"))),
                        (field(2), uint(4)),
                        (field(3), Value::Null),
                        (field(6), text(command.clone())),
                    ],
                    true,
                )?;
                changed |= c;
                uuid_value(id)
            }
            OpenSshImportRoute::Jump { hops } => {
                let hop_ids = hops
                    .iter()
                    .map(|alias| {
                        builder
                            .id(&format!("profile:{alias}"), ObjectType::ACCESS_PROFILE)
                            .map(uuid_value)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let (id, c) = builder.write(
                    format!("route:{alias}"),
                    host.row.source_file.clone(),
                    ObjectType::ROUTE,
                    vec![
                        (field(1), text(format!("{alias} route"))),
                        (field(2), uint(1)),
                        (field(3), Value::Array(hop_ids)),
                        (field(6), Value::Null),
                    ],
                    true,
                )?;
                changed |= c;
                uuid_value(id)
            }
        };
        let (_, c) = builder.write(
            host_key,
            host.row.source_file.clone(),
            ObjectType::HOST,
            vec![
                (field(1), text(alias.clone())),
                (field(2), text(host.row.address.clone())),
                (field(3), uint(host.row.port as u64)),
                (field(8), uuid_value(profile_id)),
            ],
            false,
        )?;
        changed |= c;
        let (_, c) = builder.write(
            profile_key,
            host.row.source_file.clone(),
            ObjectType::ACCESS_PROFILE,
            vec![
                (field(1), uuid_value(host_id)),
                (field(3), text(host.row.username.clone())),
                (field(4), credential.map(uuid_value).unwrap_or(Value::Null)),
                (field(5), route),
            ],
            true,
        )?;
        changed |= c;
        for (algorithm, public) in &host.trust {
            let key = format!("trust:{alias}:{algorithm}");
            let id = builder.id(&key, ObjectType::TRUST_RECORD)?;
            let public = public.to_openssh().map_err(failure)?;
            let previous = builder.snapshot.objects.get(&id);
            let same = previous
                .and_then(|o| o.set_field(3))
                .is_some_and(|entry| entry.value == Value::Text(public.clone()));
            let accepted = if same {
                previous.and_then(|o| o.set_field(6)).map(|f| f.value.clone()).unwrap_or(uint(now))
            } else {
                uint(now)
            };
            let fingerprint = ssh_key::PublicKey::from_openssh(&public)
                .map_err(failure)?
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string();
            let (_, c) = builder.write(
                key,
                host.row.source_file.clone(),
                ObjectType::TRUST_RECORD,
                vec![
                    (field(1), uuid_value(host_id)),
                    (field(3), text(public)),
                    (field(4), text(fingerprint)),
                    (field(5), uint(2)),
                    (field(6), accepted),
                    (field(7), uuid_value(inventory.store.device_id())),
                    (field(8), account.map(uuid_value).unwrap_or(Value::Null)),
                    (field(9), Value::Bool(false)),
                    (field(10), Value::Bool(false)),
                ],
                false,
            )?;
            changed |= c;
        }
        let prefix = format!("trust:{alias}:");
        for (key, id) in &builder.snapshot.mappings {
            if key.starts_with(&prefix)
                && !builder.writes.contains_key(key)
                && builder.snapshot.objects.get(id).is_some_and(|object| {
                    !object.is_tombstoned() && object.object_type == ObjectType::TRUST_RECORD
                })
            {
                removed_trust.push(*id);
                changed = true;
            }
        }
        host.row.action = if created {
            OpenSshImportAction::Create
        } else if changed {
            OpenSshImportAction::Update
        } else {
            OpenSshImportAction::Unchanged
        };
        hosts.push(host_id);
    }
    Ok(Prepared {
        preview: OpenSshImportPreview {
            path: parsed.path,
            choices,
            eligible_credentials: eligible,
            source_revision: parsed.sources.revision(),
            inventory_revision: revision,
            files: parsed.sources.count(),
            entries: parsed.hosts.into_iter().map(|host| host.row).collect(),
            skipped_hosts: parsed.skipped,
            unsupported: parsed.unsupported,
        },
        writes: builder.writes.into_values().collect(),
        hosts,
        credentials,
        removed_trust,
    })
}

fn identity_material(
    sources: &mut parse::Sources,
    file: &str,
    alias: &str,
) -> Result<(CredentialMaterial, String), OpenSshImportError> {
    let bytes = Zeroizing::new(
        sources
            .read(Path::new(file), 65536)
            .map_err(|_| OpenSshImportError::IdentityNotFound { path: file.into() })?,
    );
    let unavailable = || OpenSshImportError::CredentialUnavailable { alias: alias.into() };
    if let Ok(private) = ssh_key::PrivateKey::from_openssh(bytes.as_slice()) {
        if !matches!(
            private.algorithm().as_str(),
            "ssh-ed25519"
                | "ssh-rsa"
                | "ecdsa-sha2-nistp256"
                | "ecdsa-sha2-nistp384"
                | "ecdsa-sha2-nistp521"
        ) {
            return Err(unavailable());
        }
        let material = CredentialMaterial::PrivateKey(SecretVec::new(bytes.to_vec()));
        private_key_passphrase_required(&material).map_err(|_| unavailable())?;
        Ok((material, private.public_key().to_openssh().map_err(|_| unavailable())?))
    } else {
        let public = ssh_key::PublicKey::from_openssh(
            std::str::from_utf8(&bytes).map_err(|_| unavailable())?,
        )
        .and_then(|public| public.to_openssh())
        .map_err(|_| unavailable())?;
        let material = CredentialMaterial::Agent { public_key: Some(public.clone()) };
        validate_credential(&material).map_err(|_| unavailable())?;
        Ok((material, public))
    }
}

fn usable(store: &Store, credential: &Credential) -> bool {
    resolve_credential(store, credential).is_ok_and(|material| {
        !matches!(&material, CredentialMaterial::Password(secret) if secret.as_bytes().is_empty() || std::str::from_utf8(secret.as_bytes()).is_err())
            && validate_credential(&material).is_ok()
            && private_key_passphrase_required(&material).is_ok()
    })
}

fn field(number: u64) -> FieldPath {
    FieldPath::Field(number)
}
