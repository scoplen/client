// SPDX-License-Identifier: Apache-2.0

//! The record and change of every registry type (`scoplen-docs/04-object-model.md` §4).
//!
//! Field names are those of the specification, which documents each one; they
//! are not documented again here.
#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};

use scoplen_crypto::SecretVec;
use scoplen_model::cbor::Value;
use scoplen_model::{FieldPath, MapKey, Object, ObjectType};
use uuid::Uuid;

use super::fields::{self, Edit, Writes, text_key, text_value, uuid_key, uuid_value};
use super::{Change, Meta, Record, RecordError};

type Fields = Vec<(FieldPath, Value)>;

fn uint_value(n: impl Into<u64>) -> Value {
    Value::UInt(n.into())
}

/// Converts a set change (`true` adds, `false` removes) to map entries.
fn membership<K: Ord>(changes: BTreeMap<K, bool>) -> BTreeMap<K, Option<bool>> {
    changes.into_iter().map(|(k, add)| (k, add.then_some(true))).collect()
}

fn known<T>(object: &Object, field: u64, value: Option<T>) -> Result<T, RecordError> {
    value.ok_or(RecordError::Shape(object.object_type, field))
}

// --- Host (1) ---

/// A host (`04` §4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    /// Identity and restoration.
    pub meta: Meta,
    /// Display name.
    pub name: String,
    /// DNS name or IP literal.
    pub address: String,
    /// SSH port; 22 when not set.
    pub port: u16,
    /// Tags, key to value.
    pub tags: BTreeMap<String, String>,
    /// Groups the host belongs to.
    pub groups: BTreeSet<Uuid>,
    /// Marked as a favorite.
    pub favorite: bool,
    /// Plain-text notes.
    pub notes: Option<String>,
    /// The login used when none is chosen.
    pub default_profile: Option<Uuid>,
    /// OpenSSH options without a first-class field.
    pub ssh_options: BTreeMap<String, String>,
    /// Mosh settings.
    pub mosh: BTreeMap<String, String>,
}

/// A change to a host. Map fields name the entries to set (`Some`) or
/// remove (`None`); `groups` names memberships to add (`true`) or remove.
#[derive(Clone, Debug, Default)]
pub struct HostChange {
    pub name: Option<String>,
    pub address: Option<String>,
    pub port: Edit<u16>,
    pub tags: BTreeMap<String, Option<String>>,
    pub groups: BTreeMap<Uuid, bool>,
    pub favorite: Option<bool>,
    pub notes: Edit<String>,
    pub default_profile: Edit<Uuid>,
    pub ssh_options: BTreeMap<String, Option<String>>,
    pub mosh: BTreeMap<String, Option<String>>,
}

impl Record for Host {
    const TYPE: ObjectType = ObjectType::HOST;
    type Change = HostChange;

    fn read(o: &Object) -> Result<Self, RecordError> {
        Ok(Host {
            meta: Meta::of(o),
            name: fields::required_text(o, 1)?,
            address: fields::required_text(o, 2)?,
            port: fields::port(o, 3)?.unwrap_or(22),
            tags: fields::text_map(o, 4)?,
            groups: fields::uuid_set(o, 5)?,
            favorite: fields::flag(o, 6)?,
            notes: fields::text(o, 7)?,
            default_profile: fields::uuid(o, 8)?,
            ssh_options: fields::text_map(o, 9)?,
            mosh: fields::text_map(o, 10)?,
        })
    }
}

impl Change for HostChange {
    fn into_writes(self) -> Result<Fields, RecordError> {
        let mut w = Writes::default();
        w.set(1, self.name.map(text_value));
        w.set(2, self.address.map(text_value));
        w.edit(3, self.port, uint_value);
        w.entries(4, self.tags, text_key, text_value)?;
        w.entries(5, membership(self.groups), uuid_key, Value::Bool)?;
        w.set(6, self.favorite.map(Value::Bool));
        w.edit(7, self.notes, text_value);
        w.edit(8, self.default_profile, uuid_value);
        w.entries(9, self.ssh_options, text_key, text_value)?;
        w.entries(10, self.mosh, text_key, text_value)?;
        Ok(w.0)
    }
}

// --- AccessProfile (2) ---

/// How a login reaches its host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteChoice {
    /// Directly.
    Direct,
    /// Through a route.
    Route(Uuid),
}

/// A login: a user on a host with a credential and route (`04` §4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessProfile {
    pub meta: Meta,
    pub host: Uuid,
    pub name: Option<String>,
    pub username: String,
    /// The credential; `None` uses any usable credential on this device.
    pub credential: Option<Uuid>,
    /// Direct unless a route is chosen.
    pub route: RouteChoice,
    pub terminal_profile: Option<String>,
    pub startup_command: Option<String>,
    /// Tunnels started with this login.
    pub forwards: BTreeSet<Uuid>,
    pub agent_forwarding: bool,
}

/// A change to a login.
#[derive(Clone, Debug, Default)]
pub struct AccessProfileChange {
    pub host: Option<Uuid>,
    pub name: Edit<String>,
    pub username: Option<String>,
    pub credential: Edit<Uuid>,
    pub route: Option<RouteChoice>,
    pub terminal_profile: Edit<String>,
    pub startup_command: Edit<String>,
    pub forwards: BTreeMap<Uuid, bool>,
    pub agent_forwarding: Option<bool>,
}

impl Record for AccessProfile {
    const TYPE: ObjectType = ObjectType::ACCESS_PROFILE;
    type Change = AccessProfileChange;

    fn read(o: &Object) -> Result<Self, RecordError> {
        let route = match o.set_field(5).map(|e| &e.value) {
            None | Some(Value::UInt(0)) => RouteChoice::Direct,
            Some(Value::Bytes(_)) => RouteChoice::Route(known(o, 5, fields::uuid(o, 5)?)?),
            Some(_) => return Err(RecordError::Shape(o.object_type, 5)),
        };
        Ok(AccessProfile {
            meta: Meta::of(o),
            host: known(o, 1, fields::uuid(o, 1)?)?,
            name: fields::text(o, 2)?,
            username: fields::required_text(o, 3)?,
            credential: fields::uuid(o, 4)?,
            route,
            terminal_profile: fields::text(o, 6)?,
            startup_command: fields::text(o, 7)?,
            forwards: fields::uuid_set(o, 8)?,
            agent_forwarding: fields::flag(o, 9)?,
        })
    }
}

impl Change for AccessProfileChange {
    fn into_writes(self) -> Result<Fields, RecordError> {
        let mut w = Writes::default();
        w.set(1, self.host.map(uuid_value));
        w.edit(2, self.name, text_value);
        w.set(3, self.username.map(text_value));
        w.edit(4, self.credential, uuid_value);
        w.set(
            5,
            self.route.map(|route| match route {
                RouteChoice::Direct => Value::UInt(0),
                RouteChoice::Route(id) => uuid_value(id),
            }),
        );
        w.edit(6, self.terminal_profile, text_value);
        w.edit(7, self.startup_command, text_value);
        w.entries(8, membership(self.forwards), uuid_key, Value::Bool)?;
        w.set(9, self.agent_forwarding.map(Value::Bool));
        Ok(w.0)
    }
}

// --- Credential (3) ---

/// What a credential is (`04` §4.4 field 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialKind {
    Password = 1,
    PrivateKey = 2,
    Certificate = 3,
    Agent = 4,
    SecurityKey = 5,
    DeviceBoundKey = 6,
    ExternalProvider = 7,
    KeyboardInteractive = 8,
}

/// Where a credential's secret lives (`04` §4.4 field 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialBinding {
    /// The secret is synchronized inside the encrypted object.
    Shared = 1,
    /// Each device holds its own key; the private key never leaves it.
    Device = 2,
    /// Resolved at connect time, for example from an agent.
    None = 3,
}

impl CredentialKind {
    fn from_wire(n: u64) -> Option<Self> {
        use CredentialKind::*;
        [
            Password,
            PrivateKey,
            Certificate,
            Agent,
            SecurityKey,
            DeviceBoundKey,
            ExternalProvider,
            KeyboardInteractive,
        ]
        .into_iter()
        .find(|k| *k as u64 == n)
    }
}

impl CredentialBinding {
    fn from_wire(n: u64) -> Option<Self> {
        [CredentialBinding::Shared, CredentialBinding::Device, CredentialBinding::None]
            .into_iter()
            .find(|b| *b as u64 == n)
    }
}

/// One device's public half of a device-bound credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceKey {
    /// OpenSSH public key.
    pub public_key: String,
    /// Label shown for the device.
    pub label: String,
}

/// A credential's description. The secret of a shared credential is never
/// part of the record; [`credential_secret`] reads it when a connection needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub meta: Meta,
    pub name: Option<String>,
    pub kind: CredentialKind,
    pub binding: CredentialBinding,
    /// Whether a shared secret is stored.
    pub has_secret: bool,
    pub devices: BTreeMap<Uuid, DeviceKey>,
    pub public_key: Option<String>,
    pub provider: BTreeMap<String, String>,
    pub certificate_scope: Option<Uuid>,
}

/// A change to a credential. The secret is zeroized when the change is
/// dropped and redacted when the change is formatted.
#[derive(Clone, Debug, Default)]
pub struct CredentialChange {
    pub name: Edit<String>,
    pub kind: Option<CredentialKind>,
    pub binding: Option<CredentialBinding>,
    pub secret: Edit<SecretVec>,
    pub devices: BTreeMap<Uuid, Option<DeviceKey>>,
    pub public_key: Edit<String>,
    pub provider: BTreeMap<String, Option<String>>,
    pub certificate_scope: Edit<Uuid>,
}

impl Record for Credential {
    const TYPE: ObjectType = ObjectType::CREDENTIAL;
    type Change = CredentialChange;

    fn read(o: &Object) -> Result<Self, RecordError> {
        let kind = known(o, 2, fields::uint(o, 2)?.and_then(CredentialKind::from_wire))?;
        let binding = known(o, 3, fields::uint(o, 3)?.and_then(CredentialBinding::from_wire))?;
        let devices = fields::map_entries(o, 5)
            .map(|(key, value)| {
                let id = fields::map_uuid(o, 5, key)?;
                match (fields::nested(value, 1), fields::nested(value, 2)) {
                    (Some(Value::Text(public_key)), Some(Value::Text(label))) => {
                        Ok((id, DeviceKey { public_key: public_key.clone(), label: label.clone() }))
                    }
                    _ => Err(RecordError::Shape(o.object_type, 5)),
                }
            })
            .collect::<Result<_, _>>()?;
        Ok(Credential {
            meta: Meta::of(o),
            name: fields::text(o, 1)?,
            kind,
            binding,
            has_secret: o.set_field(4).is_some(),
            devices,
            public_key: fields::text(o, 6)?,
            provider: fields::text_map(o, 7)?,
            certificate_scope: fields::uuid(o, 8)?,
        })
    }
}

impl Change for CredentialChange {
    fn into_writes(self) -> Result<Fields, RecordError> {
        let mut w = Writes::default();
        w.edit(1, self.name, text_value);
        w.set(2, self.kind.map(|k| Value::UInt(k as u64)));
        w.set(3, self.binding.map(|b| Value::UInt(b as u64)));
        w.edit(4, self.secret, |secret| Value::Bytes(secret.as_bytes().to_vec()));
        w.entries(5, self.devices, uuid_key, |d| {
            Value::Map(vec![
                (Value::UInt(1), Value::Text(d.public_key)),
                (Value::UInt(2), Value::Text(d.label)),
            ])
        })?;
        w.edit(6, self.public_key, text_value);
        w.entries(7, self.provider, text_key, text_value)?;
        w.edit(8, self.certificate_scope, uuid_value);
        Ok(w.0)
    }
}

/// The synchronized secret of a shared credential, for a connection that
/// needs it. It is never part of a record, so it cannot reach the interface.
pub fn credential_secret(
    store: &crate::store::Store,
    id: Uuid,
) -> Result<Option<SecretVec>, RecordError> {
    let Some(object) = store.get(id)? else { return Ok(None) };
    if object.object_type != ObjectType::CREDENTIAL {
        return Err(RecordError::WrongType {
            id,
            actual: object.object_type,
            expected: ObjectType::CREDENTIAL,
        });
    }
    Ok(fields::bytes(&object, 4)?.map(SecretVec::new))
}

// --- Route (4) ---

/// How a route reaches a host (`04` §4.5 field 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteKind {
    /// Through jump hosts, in order (logins of the hops).
    Jump { hops: Vec<Uuid> },
    /// Through a SOCKS5 proxy at `host:port`.
    Socks5 { proxy: String, credential: Option<Uuid>, username: Option<String> },
    /// Through an HTTP CONNECT proxy at `host:port`.
    HttpConnect { proxy: String, credential: Option<Uuid>, username: Option<String> },
    /// Through a `ProxyCommand`.
    Command { command: String },
    /// Through the organization's bastion; organization vault only.
    Managed { gateway_network: Uuid },
}

/// A route (`04` §4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub meta: Meta,
    pub name: String,
    pub kind: RouteKind,
}

/// A change to a route. Setting `kind` replaces the kind and its fields and
/// clears the fields of every other kind.
#[derive(Clone, Debug, Default)]
pub struct RouteChange {
    pub name: Option<String>,
    pub kind: Option<RouteKind>,
}

impl Record for Route {
    const TYPE: ObjectType = ObjectType::ROUTE;
    type Change = RouteChange;

    fn read(o: &Object) -> Result<Self, RecordError> {
        let proxy = || known(o, 4, fields::text(o, 4)?);
        let kind = match known(o, 2, fields::uint(o, 2)?)? {
            1 => {
                let hops = match o.set_field(3).map(|e| &e.value) {
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|item| match item {
                            Value::Bytes(b) => Uuid::from_slice(b)
                                .map_err(|_| RecordError::Shape(o.object_type, 3)),
                            _ => Err(RecordError::Shape(o.object_type, 3)),
                        })
                        .collect::<Result<_, _>>()?,
                    _ => return Err(RecordError::Shape(o.object_type, 3)),
                };
                RouteKind::Jump { hops }
            }
            2 => RouteKind::Socks5 {
                proxy: proxy()?,
                credential: fields::uuid(o, 5)?,
                username: fields::text(o, 8)?,
            },
            3 => RouteKind::HttpConnect {
                proxy: proxy()?,
                credential: fields::uuid(o, 5)?,
                username: fields::text(o, 8)?,
            },
            4 => RouteKind::Command { command: known(o, 6, fields::text(o, 6)?)? },
            5 => RouteKind::Managed { gateway_network: known(o, 7, fields::uuid(o, 7)?)? },
            _ => return Err(RecordError::Shape(o.object_type, 2)),
        };
        Ok(Route { meta: Meta::of(o), name: fields::required_text(o, 1)?, kind })
    }
}

impl Change for RouteChange {
    fn into_writes(self) -> Result<Fields, RecordError> {
        let mut w = Writes::default();
        w.set(1, self.name.map(text_value));
        if let Some(kind) = self.kind {
            // Every kind-specific field is written, set or cleared, so that a
            // change of kind leaves no field of the previous kind behind.
            let (number, hops, proxy, credential, command, network, username) = match kind {
                RouteKind::Jump { hops } => (1u64, Some(hops), None, None, None, None, None),
                RouteKind::Socks5 { proxy, credential, username } => {
                    (2, None, Some(proxy), credential, None, None, username)
                }
                RouteKind::HttpConnect { proxy, credential, username } => {
                    (3, None, Some(proxy), credential, None, None, username)
                }
                RouteKind::Command { command } => (4, None, None, None, Some(command), None, None),
                RouteKind::Managed { gateway_network } => {
                    (5, None, None, None, None, Some(gateway_network), None)
                }
            };
            w.set(2, Some(Value::UInt(number)));
            w.edit(3, Edit::from_option(hops), |hops| {
                Value::Array(hops.into_iter().map(uuid_value).collect())
            });
            w.edit(4, Edit::from_option(proxy), text_value);
            w.edit(5, Edit::from_option(credential), uuid_value);
            w.edit(6, Edit::from_option(command), text_value);
            w.edit(7, Edit::from_option(network), uuid_value);
            w.edit(8, Edit::from_option(username), text_value);
        }
        Ok(w.0)
    }
}

// --- HostGroup (5) ---

/// A group of hosts (`04` §4.6). Membership is stored on the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostGroup {
    pub meta: Meta,
    pub name: String,
    pub parent: Option<Uuid>,
    pub color: Option<String>,
    /// Defaults for new hosts created in the group.
    pub defaults: BTreeMap<String, String>,
}

/// A change to a group.
#[derive(Clone, Debug, Default)]
pub struct HostGroupChange {
    pub name: Option<String>,
    pub parent: Edit<Uuid>,
    pub color: Edit<String>,
    pub defaults: BTreeMap<String, Option<String>>,
}

impl Record for HostGroup {
    const TYPE: ObjectType = ObjectType::HOST_GROUP;
    type Change = HostGroupChange;

    fn read(o: &Object) -> Result<Self, RecordError> {
        Ok(HostGroup {
            meta: Meta::of(o),
            name: fields::required_text(o, 1)?,
            parent: fields::uuid(o, 2)?,
            color: fields::text(o, 3)?,
            defaults: fields::text_map(o, 4)?,
        })
    }
}

impl Change for HostGroupChange {
    fn into_writes(self) -> Result<Fields, RecordError> {
        let mut w = Writes::default();
        w.set(1, self.name.map(text_value));
        w.edit(2, self.parent, uuid_value);
        w.edit(3, self.color, text_value);
        w.entries(4, self.defaults, text_key, text_value)?;
        Ok(w.0)
    }
}

// --- TrustRecord (6) ---

/// Where trust in a host key came from (`04` §4.7 field 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    Manual = 1,
    Imported = 2,
    HostCa = 3,
    OrganizationPolicy = 4,
}

/// A known host key (`04` §4.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustRecord {
    pub meta: Meta,
    pub host: Option<Uuid>,
    pub pattern: Option<String>,
    pub key: Option<String>,
    pub fingerprint: Option<String>,
    pub provenance: Option<Provenance>,
    pub accepted_at: Option<u64>,
    pub accepted_by_device: Option<Uuid>,
    pub accepted_by_account: Option<Uuid>,
    pub revoked: bool,
    pub ca: bool,
}

/// A change to a known host key.
#[derive(Clone, Debug, Default)]
pub struct TrustRecordChange {
    pub host: Edit<Uuid>,
    pub pattern: Edit<String>,
    pub key: Edit<String>,
    pub fingerprint: Edit<String>,
    pub provenance: Option<Provenance>,
    pub accepted_at: Edit<u64>,
    pub accepted_by_device: Edit<Uuid>,
    pub accepted_by_account: Edit<Uuid>,
    pub revoked: Option<bool>,
    pub ca: Option<bool>,
}

impl Record for TrustRecord {
    const TYPE: ObjectType = ObjectType::TRUST_RECORD;
    type Change = TrustRecordChange;

    fn read(o: &Object) -> Result<Self, RecordError> {
        use Provenance::*;
        let provenance = fields::uint(o, 5)?
            .map(|n| {
                [Manual, Imported, HostCa, OrganizationPolicy].into_iter().find(|p| *p as u64 == n)
            })
            .map(|p| known(o, 5, p))
            .transpose()?;
        Ok(TrustRecord {
            meta: Meta::of(o),
            host: fields::uuid(o, 1)?,
            pattern: fields::text(o, 2)?,
            key: fields::text(o, 3)?,
            fingerprint: fields::text(o, 4)?,
            provenance,
            accepted_at: fields::uint(o, 6)?,
            accepted_by_device: fields::uuid(o, 7)?,
            accepted_by_account: fields::uuid(o, 8)?,
            revoked: fields::flag(o, 9)?,
            ca: fields::flag(o, 10)?,
        })
    }
}

impl Change for TrustRecordChange {
    fn into_writes(self) -> Result<Fields, RecordError> {
        let mut w = Writes::default();
        w.edit(1, self.host, uuid_value);
        w.edit(2, self.pattern, text_value);
        w.edit(3, self.key, text_value);
        w.edit(4, self.fingerprint, text_value);
        w.set(5, self.provenance.map(|p| Value::UInt(p as u64)));
        w.edit(6, self.accepted_at, uint_value);
        w.edit(7, self.accepted_by_device, uuid_value);
        w.edit(8, self.accepted_by_account, uuid_value);
        w.set(9, self.revoked.map(Value::Bool));
        w.set(10, self.ca.map(Value::Bool));
        Ok(w.0)
    }
}

// --- Snippet (7) ---

/// The kind of a snippet variable (`04` §4.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VariableKind {
    Text = 1,
    Integer = 2,
    Choice = 3,
    Secret = 4,
}

/// A snippet variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Variable {
    pub kind: VariableKind,
    /// The default value, as text.
    pub default: Option<String>,
    /// The choices of a choice variable.
    pub choices: Vec<String>,
}

/// A command template (`04` §4.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snippet {
    pub meta: Meta,
    pub name: String,
    pub template: String,
    pub variables: BTreeMap<String, Variable>,
    pub tags: BTreeSet<String>,
    pub folder: Option<String>,
}

/// A change to a snippet.
#[derive(Clone, Debug, Default)]
pub struct SnippetChange {
    pub name: Option<String>,
    pub template: Option<String>,
    pub variables: BTreeMap<String, Option<Variable>>,
    pub tags: BTreeMap<String, bool>,
    pub folder: Edit<String>,
}

impl Record for Snippet {
    const TYPE: ObjectType = ObjectType::SNIPPET;
    type Change = SnippetChange;

    fn read(o: &Object) -> Result<Self, RecordError> {
        use VariableKind::*;
        let shape = || RecordError::Shape(o.object_type, 3);
        let variables = fields::map_entries(o, 3)
            .map(|(key, value)| {
                let MapKey::Text(name) = key else { return Err(shape()) };
                let kind = match fields::nested(value, 1) {
                    Some(Value::UInt(n)) => [Text, Integer, Choice, Secret]
                        .into_iter()
                        .find(|k| *k as u64 == *n)
                        .ok_or_else(shape)?,
                    _ => return Err(shape()),
                };
                let default = match fields::nested(value, 2) {
                    None | Some(Value::Null) => None,
                    Some(Value::Text(t)) => Some(t.clone()),
                    Some(Value::UInt(n)) => Some(n.to_string()),
                    Some(_) => return Err(shape()),
                };
                let choices = match fields::nested(value, 3) {
                    None => Vec::new(),
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|i| if let Value::Text(t) = i { Ok(t.clone()) } else { Err(shape()) })
                        .collect::<Result<_, _>>()?,
                    Some(_) => return Err(shape()),
                };
                Ok((name.clone(), Variable { kind, default, choices }))
            })
            .collect::<Result<_, _>>()?;
        Ok(Snippet {
            meta: Meta::of(o),
            name: fields::required_text(o, 1)?,
            template: fields::required_text(o, 2)?,
            variables,
            tags: fields::text_set(o, 4)?,
            folder: fields::text(o, 5)?,
        })
    }
}

impl Change for SnippetChange {
    fn into_writes(self) -> Result<Fields, RecordError> {
        let mut w = Writes::default();
        w.set(1, self.name.map(text_value));
        w.set(2, self.template.map(text_value));
        w.entries(3, self.variables, text_key, |v| {
            let mut spec = vec![(Value::UInt(1), Value::UInt(v.kind as u64))];
            if let Some(default) = v.default {
                let default = match (v.kind, default.parse::<u64>()) {
                    (VariableKind::Integer, Ok(n)) => Value::UInt(n),
                    _ => Value::Text(default),
                };
                spec.push((Value::UInt(2), default));
            }
            if !v.choices.is_empty() {
                spec.push((
                    Value::UInt(3),
                    Value::Array(v.choices.into_iter().map(Value::Text).collect()),
                ));
            }
            Value::Map(spec)
        })?;
        w.entries(4, membership(self.tags), text_key, Value::Bool)?;
        w.edit(5, self.folder, text_value);
        Ok(w.0)
    }
}

// --- Forward (8) ---

/// The direction of a tunnel (`04` §4.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardKind {
    Local = 1,
    Remote = 2,
    Dynamic = 3,
}

/// A tunnel (`04` §4.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    pub meta: Meta,
    pub name: String,
    pub kind: ForwardKind,
    pub bind_address: Option<String>,
    pub bind_port: Option<u16>,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub profile: Option<Uuid>,
}

/// A change to a tunnel.
#[derive(Clone, Debug, Default)]
pub struct ForwardChange {
    pub name: Option<String>,
    pub kind: Option<ForwardKind>,
    pub bind_address: Edit<String>,
    pub bind_port: Edit<u16>,
    pub target_host: Edit<String>,
    pub target_port: Edit<u16>,
    pub profile: Edit<Uuid>,
}

impl Record for Forward {
    const TYPE: ObjectType = ObjectType::FORWARD;
    type Change = ForwardChange;

    fn read(o: &Object) -> Result<Self, RecordError> {
        use ForwardKind::*;
        let kind = fields::uint(o, 2)?
            .and_then(|n| [Local, Remote, Dynamic].into_iter().find(|k| *k as u64 == n));
        let kind = known(o, 2, kind)?;
        let (target_host, target_port) =
            if kind == Dynamic { (None, None) } else { (fields::text(o, 5)?, fields::port(o, 6)?) };
        Ok(Forward {
            meta: Meta::of(o),
            name: fields::required_text(o, 1)?,
            kind,
            bind_address: fields::text(o, 3)?,
            bind_port: fields::port(o, 4)?,
            target_host,
            target_port,
            profile: fields::uuid(o, 7)?,
        })
    }
}

impl Change for ForwardChange {
    fn into_writes(self) -> Result<Fields, RecordError> {
        let mut w = Writes::default();
        w.set(1, self.name.map(text_value));
        w.set(2, self.kind.map(|k| Value::UInt(k as u64)));
        w.edit(3, self.bind_address, text_value);
        w.edit(4, self.bind_port, uint_value);
        w.edit(5, self.target_host, text_value);
        w.edit(6, self.target_port, uint_value);
        w.edit(7, self.profile, uuid_value);
        Ok(w.0)
    }
}

// --- Workspace (9) ---

/// What a workspace session opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    Terminal = 1,
    Files = 2,
    Forward = 3,
}

/// One session of a workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSpec {
    pub profile: Uuid,
    pub kind: SessionKind,
    pub forward: Option<Uuid>,
    pub working_directory: Option<String>,
}

/// A saved arrangement of sessions (`04` §4.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workspace {
    pub meta: Meta,
    pub name: String,
    /// The client-defined layout document.
    pub layout: Option<Vec<u8>>,
    pub sessions: BTreeMap<Uuid, SessionSpec>,
}

/// A change to a workspace.
#[derive(Clone, Debug, Default)]
pub struct WorkspaceChange {
    pub name: Option<String>,
    pub layout: Edit<Vec<u8>>,
    pub sessions: BTreeMap<Uuid, Option<SessionSpec>>,
}

impl Record for Workspace {
    const TYPE: ObjectType = ObjectType::WORKSPACE;
    type Change = WorkspaceChange;

    fn read(o: &Object) -> Result<Self, RecordError> {
        use SessionKind::*;
        let shape = || RecordError::Shape(o.object_type, 3);
        let sessions = fields::map_entries(o, 3)
            .map(|(key, value)| {
                let id = fields::map_uuid(o, 3, key)?;
                let profile = match fields::nested(value, 1) {
                    Some(Value::Bytes(b)) => Uuid::from_slice(b).map_err(|_| shape())?,
                    _ => return Err(shape()),
                };
                let kind = match fields::nested(value, 2) {
                    Some(Value::UInt(n)) => [Terminal, Files, Forward]
                        .into_iter()
                        .find(|k| *k as u64 == *n)
                        .ok_or_else(shape)?,
                    _ => return Err(shape()),
                };
                let forward = match fields::nested(value, 3) {
                    None => None,
                    Some(Value::Bytes(b)) => Some(Uuid::from_slice(b).map_err(|_| shape())?),
                    Some(_) => return Err(shape()),
                };
                let working_directory = match fields::nested(value, 4) {
                    None => None,
                    Some(Value::Text(t)) => Some(t.clone()),
                    Some(_) => return Err(shape()),
                };
                Ok((id, SessionSpec { profile, kind, forward, working_directory }))
            })
            .collect::<Result<_, _>>()?;
        Ok(Workspace {
            meta: Meta::of(o),
            name: fields::required_text(o, 1)?,
            layout: fields::bytes(o, 2)?,
            sessions,
        })
    }
}

impl Change for WorkspaceChange {
    fn into_writes(self) -> Result<Fields, RecordError> {
        let mut w = Writes::default();
        w.set(1, self.name.map(text_value));
        w.edit(2, self.layout, Value::Bytes);
        w.entries(3, self.sessions, uuid_key, |s| {
            let mut spec = vec![
                (Value::UInt(1), uuid_value(s.profile)),
                (Value::UInt(2), Value::UInt(s.kind as u64)),
            ];
            if let Some(forward) = s.forward {
                spec.push((Value::UInt(3), uuid_value(forward)));
            }
            if let Some(dir) = s.working_directory {
                spec.push((Value::UInt(4), Value::Text(dir)));
            }
            Value::Map(spec)
        })?;
        Ok(w.0)
    }
}

// --- Preference (10) ---

/// One preference; one object per preference so that they merge
/// independently (`04` §4.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preference {
    pub meta: Meta,
    pub key: String,
    /// The value, in its object-model form.
    pub value: Option<Value>,
}

/// A change to a preference.
#[derive(Clone, Debug, Default)]
pub struct PreferenceChange {
    pub key: Option<String>,
    pub value: Edit<Value>,
}

impl Record for Preference {
    const TYPE: ObjectType = ObjectType::PREFERENCE;
    type Change = PreferenceChange;

    fn read(o: &Object) -> Result<Self, RecordError> {
        Ok(Preference {
            meta: Meta::of(o),
            key: fields::required_text(o, 1)?,
            value: o.set_field(2).map(|e| e.value.clone()),
        })
    }
}

impl Change for PreferenceChange {
    fn into_writes(self) -> Result<Fields, RecordError> {
        let mut w = Writes::default();
        w.set(1, self.key.map(text_value));
        w.edit(2, self.value, |v| v);
        Ok(w.0)
    }
}

// --- GatewayNetwork (11) ---

/// A network reachable through the organization's bastion (`04` §4.8).
/// Authored by the organization's server; read-only on devices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayNetwork {
    pub meta: Meta,
    pub name: Option<String>,
    pub description: Option<String>,
}

/// Gateway networks cannot be changed on a device.
#[derive(Clone, Debug, Default)]
pub struct NoChange;

impl Record for GatewayNetwork {
    const TYPE: ObjectType = ObjectType::GATEWAY_NETWORK;
    type Change = NoChange;

    fn read(o: &Object) -> Result<Self, RecordError> {
        Ok(GatewayNetwork {
            meta: Meta::of(o),
            name: fields::text(o, 1)?,
            description: fields::text(o, 2)?,
        })
    }
}

impl Change for NoChange {
    fn into_writes(self) -> Result<Fields, RecordError> {
        Err(RecordError::ReadOnly(ObjectType::GATEWAY_NETWORK))
    }
}
