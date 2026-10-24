// SPDX-License-Identifier: Apache-2.0

//! Events the core sends to the frontend.

use scoplen_client_core::store::Change;
use scoplen_model::ObjectType;
use serde::Serialize;
use specta::Type;

/// The type of a changed object, in the frontend's terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum RecordType {
    /// A host.
    Host,
    /// A login.
    AccessProfile,
    /// A key, password, or other credential.
    Credential,
    /// A jump route or proxy.
    Route,
    /// A group.
    HostGroup,
    /// A known host key.
    TrustRecord,
    /// A snippet.
    Snippet,
    /// A tunnel.
    Forward,
    /// A workspace.
    Workspace,
    /// A preference.
    Preference,
    /// A network reached through the bastion.
    GatewayNetwork,
    /// A type a newer version of Scoplen defines.
    Unknown,
}

impl From<ObjectType> for RecordType {
    fn from(object_type: ObjectType) -> Self {
        match object_type {
            ObjectType::HOST => RecordType::Host,
            ObjectType::ACCESS_PROFILE => RecordType::AccessProfile,
            ObjectType::CREDENTIAL => RecordType::Credential,
            ObjectType::ROUTE => RecordType::Route,
            ObjectType::HOST_GROUP => RecordType::HostGroup,
            ObjectType::TRUST_RECORD => RecordType::TrustRecord,
            ObjectType::SNIPPET => RecordType::Snippet,
            ObjectType::FORWARD => RecordType::Forward,
            ObjectType::WORKSPACE => RecordType::Workspace,
            ObjectType::PREFERENCE => RecordType::Preference,
            ObjectType::GATEWAY_NETWORK => RecordType::GatewayNetwork,
            _ => RecordType::Unknown,
        }
    }
}

/// Objects in the local store changed; views showing them should reload.
/// Sent after the change is committed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type, tauri_specta::Event)]
#[serde(rename_all = "camelCase")]
pub struct StoreChanged {
    /// The type of the changed objects.
    pub record_type: RecordType,
    /// Their identifiers, as lowercase hyphenated UUIDs.
    pub ids: Vec<String>,
}

/// Safe background status; no object content, key material or server diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type, tauri_specta::Event)]
#[serde(rename_all = "camelCase")]
pub struct PersonalSyncChanged {
    /// The native owner's current state.
    pub status: scoplen_client_core::personal_server::PersonalBackgroundStatus,
}

/// Why a device-local session view should reload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum SessionChangeKind {
    /// A connection owner recorded that a transport opened.
    Opened,
    /// A connection owner recorded a terminal outcome.
    Closed,
    /// The user removed an ended session from local history.
    Forgotten,
}

/// A device-local session lifecycle event; session history is not a replicated
/// object and therefore has its own event instead of `StoreChanged`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type, tauri_specta::Event)]
#[serde(rename_all = "camelCase")]
pub struct SessionChanged {
    /// The session identifier.
    pub session_id: String,
    /// The lifecycle transition.
    pub change: SessionChangeKind,
}

impl From<&Change> for StoreChanged {
    fn from(change: &Change) -> Self {
        StoreChanged {
            record_type: change.object_type.into(),
            ids: change.ids.iter().map(|id| id.to_string()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changes_become_typed_events() {
        let id = uuid::Uuid::now_v7();
        let event = StoreChanged::from(&Change { object_type: ObjectType::HOST, ids: vec![id] });
        assert_eq!(
            event,
            StoreChanged { record_type: RecordType::Host, ids: vec![id.to_string()] }
        );
        assert_eq!(RecordType::from(ObjectType::from_wire(77).unwrap()), RecordType::Unknown);
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["recordType"], "host");
    }

    #[test]
    fn session_changes_are_typed_and_redacted() {
        let event =
            SessionChanged { session_id: "session-1".into(), change: SessionChangeKind::Closed };
        let json = serde_json::to_value(event).unwrap();
        assert_eq!(json["sessionId"], "session-1");
        assert_eq!(json["change"], "closed");
    }
}
