// SPDX-License-Identifier: Apache-2.0
//! Secret-free settings facade for explicit Personal inventory synchronization.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use scoplen_model::{Object, ObjectType, cbor::Value};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use specta::Type;
use uuid::Uuid;

use crate::{
    personal_server::{
        PersonalInventoryIntent, PersonalServer, PersonalServerError, PersonalSyncError,
    },
    store::{Store, StoreError},
};

mod history;
pub use history::{PersonalInventoryHistory, PersonalInventoryVersion};

/// Display categories, never object fields or credential content.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum PersonalInventoryCategory {
    /// A saved machine.
    Host,
    /// A saved login.
    Login,
    /// A credential description and any shared secret.
    Credential,
    /// A saved network route.
    Route,
    /// A host group.
    Group,
    /// A saved host-key trust decision.
    Trust,
    /// A snippet, including its template and defaults.
    Snippet,
    /// A saved tunnel.
    Forward,
    /// A saved workspace.
    Workspace,
    /// A future object category.
    Other,
}

/// Public metadata safe to expose over IPC.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PersonalInventoryObject {
    /// Exact object identifier.
    pub id: String,
    /// Optional display name only, never a template, address, username, or secret.
    pub name: Option<String>,
    /// The content category the user is selecting.
    pub category: PersonalInventoryCategory,
    /// The K-1 credential contains synchronized secret bytes.
    pub shared_secret: bool,
    /// Already belongs to this Personal vault.
    pub personal: bool,
    /// A local change awaits confirmed synchronization.
    pub dirty: bool,
    /// A deletion waiting in the same durable queue.
    pub deleted: bool,
    /// Organization content cannot enter a Personal vault.
    pub excluded: bool,
}

/// Locally persisted status; reading it never connects to the server.
#[derive(Clone, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PersonalInventoryStatus {
    /// Retained Personal vault.
    pub vault_id: String,
    /// Local and already adopted objects, with public metadata only.
    pub objects: Vec<PersonalInventoryObject>,
    /// Immutable original adoption copies available for local restoration.
    pub backups: Vec<PersonalInventoryObject>,
    /// Modified objects missing from a complete server snapshot, awaiting explicit restoration.
    pub recovery: Vec<PersonalInventoryRecoveryCopy>,
    /// Number of dirty objects, including deletions.
    pub pending: u32,
    /// Applied sequence as decimal text, avoiding JavaScript integer truncation.
    pub applied_cursor: String,
    /// Confirmed acknowledgement as decimal text.
    pub acknowledged_cursor: String,
}

/// Public metadata for one immutable reconciliation copy. Its id names the copy, not an object.
#[derive(Clone, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PersonalInventoryRecoveryCopy {
    /// Exact local recovery-copy identifier.
    pub id: String,
    /// Metadata for the original object, with no content or device-local secrets.
    pub object: PersonalInventoryObject,
}

/// A preview grants no network or adoption permission by itself.
#[derive(Clone, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PersonalInventoryPreview {
    /// One-use, short-lived Rust-held review ticket; absent until references are selected.
    pub token: Option<String>,
    /// Exact selected objects and their content categories.
    pub objects: Vec<PersonalInventoryObject>,
    /// Existing referenced objects that must be selected explicitly.
    pub missing: Vec<PersonalInventoryObject>,
}

/// Counts from one explicit bounded sync cycle.
#[derive(Clone, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PersonalInventoryResult {
    /// Number of encrypted entries applied.
    pub downloaded: u32,
    /// Number of writes with confirmed assignments.
    pub uploaded: u32,
    /// Another bounded cycle is needed; the active native owner schedules continuation.
    pub more: bool,
}

/// Safe, localizable failures. No server body or underlying diagnostic crosses IPC.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type, thiserror::Error)]
#[serde(rename_all = "camelCase")]
#[error("Personal inventory action failed: {self:?}")]
pub enum PersonalInventoryError {
    /// Unlock or reopen local data.
    Storage,
    /// Wait for the current account or sync action.
    Busy,
    /// Complete Personal setup first.
    NotConfigured,
    /// Renew device authentication.
    AuthenticationRequired,
    /// The server confirmed no refresh change; a later explicit attempt is safe.
    RefreshDeferred,
    /// A narrowed session lacks the required operation scope.
    PermissionDenied,
    /// An HTTPS exchange failed.
    Network,
    /// Untrusted or mismatched sync artifacts were rejected.
    InvalidSyncResponse,
    /// This build cannot rotate the keys.
    RotationRequired,
    /// A write encountered a purged current object; pull again or restore a local copy.
    ReconciliationRequired,
    /// A write may have committed; the next cycle checks by pulling.
    WriteOutcomeUnknown,
    /// Local changes are applied but acknowledgement is unconfirmed.
    AcknowledgementUnknown,
    /// Conflict retries were exhausted or the complete snapshot changed during download.
    ConcurrentChanges,
    /// Check the device and server clock.
    Clock,
    /// Review exact object ids and references again.
    Selection,
    /// A bounded sync resource limit was reached.
    ResourceLimit,
    /// Trust provenance requires review.
    TrustReviewRequired,
    /// The review expired or local objects changed after it.
    PreviewExpired,
    /// The server has no retained history for this object.
    HistoryNotFound,
    /// A revoked device signed a version whose historical authorization cannot be proven.
    HistorySignerUnavailable,
}

impl From<PersonalSyncError> for PersonalInventoryError {
    fn from(error: PersonalSyncError) -> Self {
        match error {
            PersonalSyncError::Personal(PersonalServerError::Busy) => Self::Busy,
            PersonalSyncError::Personal(PersonalServerError::NotConfigured) => Self::NotConfigured,
            PersonalSyncError::Personal(
                PersonalServerError::Network | PersonalServerError::ConnectionBeforeRequest,
            ) => Self::Network,
            PersonalSyncError::Personal(PersonalServerError::Authentication)
            | PersonalSyncError::Personal(PersonalServerError::AuthenticationRequired)
            | PersonalSyncError::AuthenticationRequired => Self::AuthenticationRequired,
            PersonalSyncError::Personal(PersonalServerError::RefreshDeferred) => {
                Self::RefreshDeferred
            }
            PersonalSyncError::Personal(PersonalServerError::PermissionDenied) => {
                Self::PermissionDenied
            }
            PersonalSyncError::Personal(PersonalServerError::InvalidResponse) => {
                Self::InvalidSyncResponse
            }
            PersonalSyncError::Personal(_) => Self::Storage,
            PersonalSyncError::InvalidResponse => Self::InvalidSyncResponse,
            PersonalSyncError::RotationRequired => Self::RotationRequired,
            PersonalSyncError::ReconciliationRequired => Self::ReconciliationRequired,
            PersonalSyncError::WriteOutcomeUnknown => Self::WriteOutcomeUnknown,
            PersonalSyncError::AcknowledgementUnknown => Self::AcknowledgementUnknown,
            PersonalSyncError::ConcurrentChanges => Self::ConcurrentChanges,
            PersonalSyncError::Clock => Self::Clock,
            PersonalSyncError::Selection => Self::Selection,
            PersonalSyncError::ResourceLimit => Self::ResourceLimit,
            PersonalSyncError::TrustReviewRequired => Self::TrustReviewRequired,
            PersonalSyncError::HistorySignerUnavailable => Self::HistorySignerUnavailable,
        }
    }
}

fn storage(error: StoreError) -> PersonalInventoryError {
    match error {
        StoreError::RecoveryLimit => PersonalInventoryError::ResourceLimit,
        _ => PersonalInventoryError::Storage,
    }
}

struct Review {
    token: String,
    created: Instant,
    path: PathBuf,
    device: Uuid,
    vault: Uuid,
    expected: HashMap<Uuid, [u8; 32]>,
}

/// Process-local review state. Only a secret-free random ticket is returned to JavaScript.
#[derive(Default)]
pub struct PersonalInventorySettings {
    review: Mutex<Option<Review>>,
    history: Mutex<Option<history::HistoryReview>>,
}

impl PersonalInventorySettings {
    /// Read persisted metadata locally, including dirty objects and separate cursor states.
    pub fn status(&self, store: &Store) -> Result<PersonalInventoryStatus, PersonalInventoryError> {
        let vault = vault(store)?;
        let snapshot = store.personal_inventory_snapshot(vault).map_err(storage)?;
        Ok(PersonalInventoryStatus {
            vault_id: vault.to_string(),
            objects: snapshot
                .objects
                .iter()
                .map(|(object, personal, dirty)| summary(object, *personal, *dirty))
                .collect(),
            backups: snapshot.backups.iter().map(|object| summary(object, false, false)).collect(),
            recovery: snapshot
                .recovery
                .iter()
                .map(|(id, object)| PersonalInventoryRecoveryCopy {
                    id: id.to_string(),
                    object: summary(object, false, false),
                })
                .collect(),
            pending: snapshot.pending,
            applied_cursor: snapshot.applied.to_string(),
            acknowledged_cursor: snapshot.acknowledged.to_string(),
        })
    }

    /// Preview exact local ids without expanding their selection or opening a connection.
    pub fn preview(
        &self,
        store: &Store,
        selected: Vec<String>,
    ) -> Result<PersonalInventoryPreview, PersonalInventoryError> {
        let mut guard = self.review.lock().unwrap_or_else(|error| error.into_inner());
        *guard = None;
        let selected = selection(&selected)?;
        if selected.is_empty() {
            return Err(PersonalInventoryError::Selection);
        }
        let selected_set = selected.iter().copied().collect::<HashSet<_>>();
        let vault = vault(store)?;
        let snapshot = store.personal_inventory_snapshot(vault).map_err(storage)?;
        let objects = snapshot
            .objects
            .iter()
            .map(|(object, personal, _)| (object.id, (object, *personal)))
            .collect::<HashMap<_, _>>();
        let mut expected = HashMap::new();
        let mut summaries = Vec::new();
        let mut missing = HashSet::new();
        for id in &selected {
            let (object, personal) = objects.get(id).ok_or(PersonalInventoryError::Selection)?;
            let display = summary(object, false, false);
            if *personal || display.deleted || display.excluded {
                return Err(PersonalInventoryError::Selection);
            }
            for reference in scoplen_model::references(object) {
                if let Some((_, personal)) = objects.get(&reference)
                    && !personal
                    && !selected_set.contains(&reference)
                {
                    missing.insert(reference);
                }
            }
            expected.insert(
                *id,
                Sha256::digest(object.encode().map_err(|_| PersonalInventoryError::Storage)?)
                    .into(),
            );
            summaries.push(display);
        }
        let mut missing =
            missing.into_iter().map(|id| summary(objects[&id].0, false, false)).collect::<Vec<_>>();
        missing.sort_by(|a, b| a.id.cmp(&b.id));
        let token = if missing.is_empty() {
            let token = scoplen_model::new_uuid_v7()
                .map_err(|_| PersonalInventoryError::Storage)?
                .to_string();
            *guard = Some(Review {
                token: token.clone(),
                created: Instant::now(),
                path: store.data_dir().to_owned(),
                device: store.device_id(),
                vault,
                expected,
            });
            Some(token)
        } else {
            None
        };
        Ok(PersonalInventoryPreview { token, objects: summaries, missing })
    }

    /// Consume an explicitly confirmed preview, or synchronize only already adopted objects.
    pub async fn synchronize(
        &self,
        personal: &PersonalServer,
        store: Arc<Store>,
        token: Option<String>,
    ) -> Result<PersonalInventoryResult, PersonalInventoryError> {
        let vault = vault(&store)?;
        let reviewed = if let Some(token) = token {
            let review = self
                .review
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take()
                .ok_or(PersonalInventoryError::PreviewExpired)?;
            if token != review.token
                || review.created.elapsed() > Duration::from_secs(300)
                || review.path != store.data_dir()
                || review.device != store.device_id()
                || review.vault != vault
            {
                return Err(PersonalInventoryError::PreviewExpired);
            }
            Some(review.expected)
        } else {
            None
        };
        let adopt =
            reviewed.as_ref().map(|review| review.keys().copied().collect()).unwrap_or_default();
        let progress = personal
            .sync_personal_inventory_expected(
                store,
                PersonalInventoryIntent { vault_id: vault, adopt },
                reviewed,
            )
            .await?;
        Ok(PersonalInventoryResult {
            downloaded: progress.downloaded as u32,
            uploaded: progress.uploaded as u32,
            more: progress.more,
        })
    }

    /// Create fresh local copies from immutable snapshots, without contacting the server.
    pub fn restore(
        &self,
        personal: &PersonalServer,
        store: &Store,
        selected: Vec<String>,
    ) -> Result<u32, PersonalInventoryError> {
        let selected = selection(&selected)?;
        if selected.is_empty() {
            return Err(PersonalInventoryError::Selection);
        }
        Ok(personal.restore_personal_inventory_copies(store, vault(store)?, &selected)?.len()
            as u32)
    }

    /// Restore selected reconciliation copies locally. They require fresh D-112 consent to upload.
    pub fn restore_recovery(
        &self,
        personal: &PersonalServer,
        store: &Store,
        selected: Vec<String>,
    ) -> Result<u32, PersonalInventoryError> {
        let selected = selection(&selected)?;
        if selected.is_empty() {
            return Err(PersonalInventoryError::Selection);
        }
        Ok(personal.restore_personal_reconciliation_copies(store, vault(store)?, &selected)?.len()
            as u32)
    }
}

fn selection(ids: &[String]) -> Result<Vec<Uuid>, PersonalInventoryError> {
    if ids.len() > crate::store::MAX_OBJECTS_PER_VAULT as usize {
        return Err(PersonalInventoryError::ResourceLimit);
    }
    let parsed = ids
        .iter()
        .map(|id| {
            if id.len() != 36 {
                return Err(PersonalInventoryError::Selection);
            }
            Uuid::parse_str(id).map_err(|_| PersonalInventoryError::Selection)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if parsed.iter().collect::<HashSet<_>>().len() != parsed.len() {
        return Err(PersonalInventoryError::Selection);
    }
    Ok(parsed)
}

fn vault(store: &Store) -> Result<Uuid, PersonalInventoryError> {
    store
        .personal_record()
        .map_err(storage)?
        .filter(|record| record.authentication_allowed())
        .map(|record| record.personal_vault_id)
        .ok_or(PersonalInventoryError::NotConfigured)
}

fn summary(object: &Object, personal: bool, dirty: bool) -> PersonalInventoryObject {
    use PersonalInventoryCategory as Category;
    let category = match object.object_type {
        ObjectType::HOST => Category::Host,
        ObjectType::ACCESS_PROFILE => Category::Login,
        ObjectType::CREDENTIAL => Category::Credential,
        ObjectType::ROUTE => Category::Route,
        ObjectType::HOST_GROUP => Category::Group,
        ObjectType::TRUST_RECORD => Category::Trust,
        ObjectType::SNIPPET => Category::Snippet,
        ObjectType::FORWARD => Category::Forward,
        ObjectType::WORKSPACE => Category::Workspace,
        _ => Category::Other,
    };
    let name_field = if category == Category::Login { 2 } else { 1 };
    let name = match object.set_field(name_field).map(|entry| &entry.value) {
        Some(Value::Text(name)) if !matches!(category, Category::Trust | Category::Other) => {
            Some(name.chars().take(160).collect())
        }
        _ => None,
    };
    PersonalInventoryObject {
        id: object.id.to_string(),
        name,
        category,
        shared_secret: object.object_type == ObjectType::CREDENTIAL
            && object.required_uint(3).ok() == Some(1)
            && object.set_field(4).is_some(),
        personal,
        dirty,
        deleted: object.is_tombstoned(),
        excluded: object.object_type == ObjectType::GATEWAY_NETWORK
            || object.object_type == ObjectType::ROUTE && object.required_uint(2).ok() == Some(5),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LocalWrite;

    #[tokio::test]
    async fn expired_review_stops_before_network_and_new_preview_invalidates_previous_ticket() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            Store::open(
                &dir.path().join("review.db"),
                &scoplen_crypto::SymmetricKey::new([61; 32]),
            )
            .unwrap(),
        );
        let manager = PersonalServer::default();
        crate::personal_server::tests::legacy_profile(&store, "https://example.test", true);
        manager.status(&store).unwrap();
        let object = store
            .write(LocalWrite {
                id: None,
                object_type: ObjectType::HOST,
                fields: vec![
                    (scoplen_model::FieldPath::Field(1), Value::Text("Local host".into())),
                    (scoplen_model::FieldPath::Field(2), Value::Text("192.0.2.1".into())),
                ],
            })
            .unwrap();
        let settings = PersonalInventorySettings::default();
        let first = settings.preview(&store, vec![object.id.to_string()]).unwrap();
        let second = settings.preview(&store, vec![object.id.to_string()]).unwrap();
        assert_ne!(first.token, second.token);
        settings.review.lock().unwrap().as_mut().unwrap().created =
            Instant::now() - Duration::from_secs(301);
        assert_eq!(
            settings.synchronize(&manager, store.clone(), second.token).await.unwrap_err(),
            PersonalInventoryError::PreviewExpired
        );
        assert!(settings.status(&store).unwrap().backups.is_empty());
        assert!(!settings.status(&store).unwrap().objects[0].personal);
    }
}
