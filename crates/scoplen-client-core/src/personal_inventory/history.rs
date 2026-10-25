// SPDX-License-Identifier: Apache-2.0
//! A short-lived, store-bound history review keeps all object content inside Rust.

use scoplen_crypto::SecretVec;
use std::sync::Weak;

use super::*;

/// One verified version's safe metadata. Sequences are decimal text, never JS numbers.
#[derive(Clone, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PersonalInventoryVersion {
    /// Exact server sequence of this version.
    pub sequence: String,
    /// Public category, name and content flags only.
    pub object: PersonalInventoryObject,
}

/// Complete verified history, retained in Rust behind one short-lived review ticket.
#[derive(Clone, Debug, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PersonalInventoryHistory {
    /// Single-use reference to the verified source retained inside Rust.
    pub token: String,
    /// Exact adopted object requested by the user.
    pub object_id: String,
    /// All retained versions, in ascending sequence order.
    pub versions: Vec<PersonalInventoryVersion>,
}

pub(super) struct HistoryReview {
    token: String,
    created: Instant,
    store: Weak<Store>,
    account: Uuid,
    vault: Uuid,
    versions: Vec<(String, SecretVec)>,
}

impl PersonalInventorySettings {
    /// Query all retained versions explicitly. A failed query invalidates an older review.
    pub async fn query_history(
        &self,
        personal: &PersonalServer,
        store: Arc<Store>,
        object_id: String,
    ) -> Result<PersonalInventoryHistory, PersonalInventoryError> {
        self.history.lock().unwrap_or_else(|error| error.into_inner()).take();
        let ids = selection(&[object_id])?;
        let id = ids[0];
        let record = store
            .personal_record()
            .map_err(storage)?
            .ok_or(PersonalInventoryError::NotConfigured)?;
        let versions = personal
            .personal_object_history(store.clone(), id)
            .await?
            .ok_or(PersonalInventoryError::HistoryNotFound)?;
        let token =
            scoplen_model::new_uuid_v7().map_err(|_| PersonalInventoryError::Storage)?.to_string();
        let mut retained = Vec::with_capacity(versions.len());
        let mut display = Vec::with_capacity(versions.len());
        for version in versions {
            let sequence = version.seq.to_string();
            display.push(PersonalInventoryVersion {
                sequence: sequence.clone(),
                object: summary(&version.object, true, false),
            });
            retained.push((
                sequence,
                SecretVec::new(
                    version
                        .object
                        .encode()
                        .map_err(|_| PersonalInventoryError::InvalidSyncResponse)?,
                ),
            ));
        }
        *self.history.lock().unwrap_or_else(|error| error.into_inner()) = Some(HistoryReview {
            token: token.clone(),
            created: Instant::now(),
            store: Arc::downgrade(&store),
            account: record.account_id,
            vault: record.personal_vault_id,
            versions: retained,
        });
        Ok(PersonalInventoryHistory { token, object_id: id.to_string(), versions: display })
    }

    /// Consume one exact reviewed version and create a new unsynchronized local copy.
    pub fn restore_history(
        &self,
        personal: &PersonalServer,
        store: Arc<Store>,
        token: String,
        sequence: String,
    ) -> Result<(), PersonalInventoryError> {
        let review = self
            .history
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or(PersonalInventoryError::PreviewExpired)?;
        let record = store
            .personal_record()
            .map_err(storage)?
            .ok_or(PersonalInventoryError::NotConfigured)?;
        if token != review.token
            || review.created.elapsed() >= Duration::from_secs(300)
            || !review.store.upgrade().is_some_and(|expected| Arc::ptr_eq(&expected, &store))
            || record.account_id != review.account
            || record.personal_vault_id != review.vault
        {
            return Err(PersonalInventoryError::PreviewExpired);
        }
        let encoded = review
            .versions
            .into_iter()
            .find(|(selected, _)| *selected == sequence)
            .ok_or(PersonalInventoryError::Selection)?
            .1;
        let object = Object::decode(encoded.as_bytes())
            .map_err(|_| PersonalInventoryError::InvalidSyncResponse)?;
        personal.restore_personal_history_copy(&store, review.account, review.vault, object)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LocalWrite;
    use scoplen_crypto::SymmetricKey;
    use scoplen_model::FieldPath;

    #[tokio::test]
    async fn history_review_rejects_expiry_reopen_account_and_selection_and_is_consumed_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.db");
        let store = Arc::new(Store::open(&path, &SymmetricKey::new([61; 32])).unwrap());
        let manager = PersonalServer::default();
        crate::personal_server::tests::fixture_profile(&store, "https://example.test", true);
        manager.status(&store).unwrap();
        let record = store.personal_record().unwrap().unwrap();
        let object = store
            .write(LocalWrite {
                id: None,
                object_type: ObjectType::HOST,
                fields: vec![
                    (FieldPath::Field(1), Value::Text("Retained version".into())),
                    (FieldPath::Field(2), Value::Text("192.0.2.1".into())),
                ],
            })
            .unwrap();
        for fault in 0..6 {
            let settings = PersonalInventorySettings::default();
            *settings.history.lock().unwrap() = Some(HistoryReview {
                token: "review".into(),
                created: if fault == 0 {
                    Instant::now() - Duration::from_secs(300)
                } else {
                    Instant::now()
                },
                store: Arc::downgrade(&store),
                account: if fault == 2 {
                    scoplen_model::new_uuid_v7().unwrap()
                } else {
                    record.account_id
                },
                vault: if fault == 3 {
                    scoplen_model::new_uuid_v7().unwrap()
                } else {
                    record.personal_vault_id
                },
                versions: vec![(
                    "9007199254740993".into(),
                    SecretVec::new(object.encode().unwrap()),
                )],
            });
            let selected_store = if fault == 1 {
                Arc::new(Store::open(&path, &SymmetricKey::new([61; 32])).unwrap())
            } else {
                store.clone()
            };
            assert_eq!(
                settings.restore_history(
                    &manager,
                    selected_store,
                    if fault == 4 { "wrong" } else { "review" }.into(),
                    if fault == 5 { "9007199254740992" } else { "9007199254740993" }.into()
                ),
                Err(if fault == 5 {
                    PersonalInventoryError::Selection
                } else {
                    PersonalInventoryError::PreviewExpired
                })
            );
            assert_eq!(
                settings.restore_history(
                    &manager,
                    store.clone(),
                    "review".into(),
                    "9007199254740993".into()
                ),
                Err(PersonalInventoryError::PreviewExpired)
            );
            assert_eq!(
                store.list(ObjectType::HOST).unwrap().as_slice(),
                std::slice::from_ref(&object)
            );
        }
    }
}
