// SPDX-License-Identifier: Apache-2.0
//! Named form values for the shared Organization authoring contract.

use std::collections::BTreeMap;

use scoplen_api::inventory::InventoryType;
use serde::{Deserialize, Serialize};
use specta::Type;

/// One server-readable team collection, distinct from the Personal repository.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum TeamAuthoringCollection {
    /// SSH destination and metadata.
    Host,
    /// Same-team Host-bound SSH Login.
    Login,
    /// Explicit same-team connection route.
    Route,
    /// Named inventory Host grouping.
    HostGroup,
    /// Host public key or host-CA trust.
    TrustRecord,
    /// Command template and variable definitions.
    Snippet,
    /// Managed gateway metadata.
    GatewayNetwork,
    /// Local or identity-provider Membership group.
    Group,
    /// Persisted supported Cedar policy.
    Policy,
}

impl TeamAuthoringCollection {
    pub(super) fn inventory(self) -> Option<InventoryType> {
        match self {
            Self::Host => Some(InventoryType::Host),
            Self::Login => Some(InventoryType::AccessProfile),
            Self::Route => Some(InventoryType::Route),
            Self::HostGroup => Some(InventoryType::HostGroup),
            Self::TrustRecord => Some(InventoryType::TrustRecord),
            Self::Snippet => Some(InventoryType::Snippet),
            Self::GatewayNetwork => Some(InventoryType::GatewayNetwork),
            Self::Group | Self::Policy => None,
        }
    }

    pub(super) fn segment(self) -> &'static str {
        match self {
            Self::Group => "groups",
            Self::Policy => "policies",
            other => other.inventory().expect("inventory collection").segment(),
        }
    }
}

/// Host fields; no credential or Personal source is accepted.
#[derive(Clone, Default, Deserialize, Serialize, Type)]
#[serde(deny_unknown_fields)]
pub struct TeamHostFields {
    /// Optional display name, preserving permitted text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// DNS name or IP address.
    pub address: String,
    /// Explicit SSH port, otherwise the model default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Display tag keys and values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, String>>,
    /// Selected same-team Host group ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<BTreeMap<String, bool>>,
    /// Favorite display state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favorite: Option<bool>,
    /// Optional ordinary notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Same-team default Login id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    /// Named SSH option values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_options: Option<BTreeMap<String, String>>,
    /// Named Mosh option values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mosh: Option<BTreeMap<String, String>>,
}

/// Direct is integer zero; every other route value is a same-team Route id.
#[derive(Clone, Deserialize, Serialize, Type)]
#[serde(untagged)]
pub enum TeamRouteReference {
    /// Shared codec accepts only integer zero.
    Direct(u8),
    /// Opaque same-team Route id.
    Id(String),
}

/// An Organization Login without any Personal credential field.
#[derive(Clone, Deserialize, Serialize, Type)]
#[serde(deny_unknown_fields)]
pub struct TeamLoginFields {
    /// Independently readable same-team Host id.
    pub host: String,
    /// Optional Login label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Exact remote SSH username.
    pub username: String,
    /// Explicit Direct or same-team Route reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<TeamRouteReference>,
    /// Optional terminal profile name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_profile: Option<String>,
    /// Optional ordinary startup command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_command: Option<String>,
    /// Whether this Login permits agent forwarding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_forwarding: Option<bool>,
}

/// Explicit route fields, excluding proxy credentials.
#[derive(Clone, Deserialize, Serialize, Type)]
#[serde(deny_unknown_fields)]
pub struct TeamRouteFields {
    /// Optional route label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Shared route-kind number from one through five.
    pub kind: u8,
    /// Ordered same-team Login ids for Jump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hops: Option<Vec<String>>,
    /// SOCKS5 or HTTP CONNECT endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// Explicit local helper program and arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Same-team managed gateway id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_network: Option<String>,
    /// Optional ordinary proxy username, without a password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_username: Option<String>,
}

/// Inventory grouping and named inherited Host defaults.
#[derive(Clone, Deserialize, Serialize, Type)]
#[serde(deny_unknown_fields)]
pub struct TeamHostGroupFields {
    /// Group display name.
    pub name: String,
    /// Optional same-team parent Host group id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Optional display color.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Shared supported defaults, without Personal credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub defaults: Option<BTreeMap<String, String>>,
}

/// Writable public Host trust fields; acceptance attribution is server-owned.
#[derive(Clone, Deserialize, Serialize, Type)]
#[serde(deny_unknown_fields)]
pub struct TeamTrustFields {
    /// Optional exact same-team Host id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Optional Host matching pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// Canonical OpenSSH public key.
    pub key: String,
    /// Exact SHA-256 fingerprint of the public key.
    pub fingerprint: String,
    /// Shared trust-provenance number from one through four.
    pub provenance: u8,
    /// Explicit revocation state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
    /// Whether this public key is a Host CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<bool>,
}

/// Shared Snippet variable definition without a stored secret value.
#[derive(Clone, Deserialize, Serialize, Type)]
#[serde(deny_unknown_fields)]
pub struct TeamSnippetVariable {
    /// Shared text, integer, choice or secret kind number.
    pub kind: u8,
    /// Optional ordinary default; forbidden for secret input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Exact allowed values for a choice variable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choices: Option<Vec<String>>,
}

/// Ordinary named command template and non-secret variable definitions.
#[derive(Clone, Deserialize, Serialize, Type)]
#[serde(deny_unknown_fields)]
pub struct TeamSnippetFields {
    /// Snippet display name.
    pub name: String,
    /// Saved command template.
    pub template: String,
    /// Definitions keyed by exact variable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<BTreeMap<String, TeamSnippetVariable>>,
    /// Selected ordinary tag names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, bool>>,
    /// Optional display folder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
}

/// Organization-managed gateway metadata.
#[derive(Clone, Deserialize, Serialize, Type)]
#[serde(deny_unknown_fields)]
pub struct TeamGatewayNetworkFields {
    /// Gateway network display name.
    pub name: String,
    /// Optional ordinary description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Writable local Group values.
#[derive(Clone, Deserialize, Serialize, Type)]
#[serde(deny_unknown_fields)]
pub struct TeamGroupFields {
    /// Group display name.
    pub name: String,
    /// Current Organization Membership ids, never global Account ids.
    pub members: Vec<String>,
}

/// Complete desired persisted-policy state.
#[derive(Clone, Deserialize, Serialize, Type)]
#[serde(deny_unknown_fields)]
pub struct TeamPolicyFields {
    /// Policy display name.
    pub name: String,
    /// One policy in the supported Cedar profile.
    pub source: String,
    /// Whether the persisted policy is active.
    pub enabled: bool,
}

/// Named ordinary form values. Rust validates and encodes the shared typed wire request.
#[derive(Clone, Deserialize, Serialize, Type)]
#[serde(tag = "kind", content = "fields", rename_all = "camelCase")]
pub enum TeamAuthoringData {
    /// Complete Host form.
    Host(TeamHostFields),
    /// Complete Login form.
    Login(TeamLoginFields),
    /// Complete Route form.
    Route(TeamRouteFields),
    /// Complete inventory Host group form.
    HostGroup(TeamHostGroupFields),
    /// Writable public trust form.
    TrustRecord(TeamTrustFields),
    /// Complete Snippet form.
    Snippet(TeamSnippetFields),
    /// Complete gateway metadata form.
    GatewayNetwork(TeamGatewayNetworkFields),
    /// Complete local Membership group form.
    Group(TeamGroupFields),
    /// Complete persisted-policy form.
    Policy(TeamPolicyFields),
}

impl TeamAuthoringData {
    pub(super) fn collection(&self) -> TeamAuthoringCollection {
        match self {
            Self::Host(_) => TeamAuthoringCollection::Host,
            Self::Login(_) => TeamAuthoringCollection::Login,
            Self::Route(_) => TeamAuthoringCollection::Route,
            Self::HostGroup(_) => TeamAuthoringCollection::HostGroup,
            Self::TrustRecord(_) => TeamAuthoringCollection::TrustRecord,
            Self::Snippet(_) => TeamAuthoringCollection::Snippet,
            Self::GatewayNetwork(_) => TeamAuthoringCollection::GatewayNetwork,
            Self::Group(_) => TeamAuthoringCollection::Group,
            Self::Policy(_) => TeamAuthoringCollection::Policy,
        }
    }

    pub(super) fn fields_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        match self {
            Self::Host(value) => serde_json::to_vec(value),
            Self::Login(value) => serde_json::to_vec(value),
            Self::Route(value) => serde_json::to_vec(value),
            Self::HostGroup(value) => serde_json::to_vec(value),
            Self::TrustRecord(value) => serde_json::to_vec(value),
            Self::Snippet(value) => serde_json::to_vec(value),
            Self::GatewayNetwork(value) => serde_json::to_vec(value),
            Self::Group(value) => serde_json::to_vec(value),
            Self::Policy(value) => serde_json::to_vec(value),
        }
    }
}

/// Attribution belongs to the server and cannot be submitted as editable fields.
#[derive(Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamTrustAttribution {
    /// Server acceptance time as exact decimal Unix milliseconds.
    pub accepted_at: String,
    /// Enrolled Device recorded by the server.
    pub accepted_by_device: String,
    /// Account recorded by the server.
    pub accepted_by_account: String,
}

/// One complete current resource captured for an explicit administration intent.
#[derive(Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamAuthoringResourceView {
    /// Canonical authenticated deployment origin.
    pub origin: String,
    /// Captured enrolled Account.
    pub account_id: String,
    /// Exact selected Organization.
    pub organization_id: String,
    /// Immutable resource id.
    pub id: String,
    /// Exact strong ETag captured by this read.
    pub etag: String,
    /// Server UTC creation timestamp.
    pub created_at: String,
    /// Server UTC last content-change timestamp.
    pub updated_at: String,
    /// Complete writable typed fields.
    pub data: TeamAuthoringData,
    /// Identity-provider groups can be read, but not edited through local-group routes.
    pub read_only: bool,
    /// Trust acceptance metadata, separate from writable fields.
    pub trust_attribution: Option<TeamTrustAttribution>,
}

/// A bounded independently authorized administration directory page.
#[derive(Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamAuthoringPageView {
    /// Canonical authenticated deployment origin.
    pub origin: String,
    /// Captured enrolled Account.
    pub account_id: String,
    /// Exact selected Organization.
    pub organization_id: String,
    /// The requested collection.
    pub collection: TeamAuthoringCollection,
    /// Complete readable resource projections in page order.
    pub items: Vec<TeamAuthoringResourceView>,
    /// Opaque next UUIDv7 continuation, when present.
    pub next_cursor: Option<String>,
}

/// Permitted next action for the retained original create.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum TeamAuthoringCreatePhase {
    /// Saved locally and safe to send or discard.
    Prepared,
    /// Dispatched with no confirmed original result.
    Unknown,
    /// Original response validated and durably retained.
    Confirmed,
    /// The fixed original confirmation window ended.
    Expired,
}

/// One retained original create, with its own immutable identity and source.
#[derive(Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamAuthoringCreateView {
    /// Canonical deployment owning this retained request.
    pub origin: String,
    /// Account owning this retained request.
    pub account_id: String,
    /// Organization owning the resource.
    pub organization_id: String,
    /// Original immutable idempotency key.
    pub operation_id: String,
    /// Original immutable resource id.
    pub resource_id: String,
    /// Explicitly permitted recovery action.
    pub phase: TeamAuthoringCreatePhase,
    /// Exact original mutable fields for review.
    pub data: TeamAuthoringData,
}

/// Input for the shared generator; one subject and one independent permission.
#[derive(Clone, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeamSimpleRuleInput {
    /// One current Membership subject, exclusive with group_id.
    pub membership_id: Option<String>,
    /// One local Group subject, exclusive with membership_id.
    pub group_id: Option<String>,
    /// Exactly one independent view or connect grant.
    pub permission: TeamSimplePermission,
    /// Explicit typed resources selected for this rule.
    pub resources: Vec<TeamSimpleRuleResource>,
    /// Exact remote SSH user, required only for connect.
    pub remote_user: Option<String>,
}

/// Independent access-rule permission.
#[derive(Clone, Copy, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum TeamSimplePermission {
    /// View selected typed assets without implicit dependencies.
    View,
    /// Connect to selected Hosts/groups as one exact SSH user.
    Connect,
}

/// One exact typed inventory selector.
#[derive(Clone, Deserialize, Serialize, Type)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeamSimpleRuleResource {
    /// Expected inventory type; Group and Policy are rejected.
    pub collection: TeamAuthoringCollection,
    /// Selected same-team resource id.
    pub id: String,
}

/// The source is an inspectable preview only; saving uses the normal policy operation.
#[derive(Clone, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TeamSimpleRulePreview {
    /// Shared generated Cedar source for explicit review.
    pub source: String,
    /// Explicit locators not selected for view; this never automatically grants dependencies.
    pub dependencies: Vec<TeamSimpleRuleResource>,
}
