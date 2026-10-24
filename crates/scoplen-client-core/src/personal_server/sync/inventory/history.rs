// SPDX-License-Identifier: Apache-2.0
//! Complete, authenticated history reads; querying never changes inventory or cursors.

use scoplen_api::{ProblemDetails, sync::SyncVersionsResponse};

use super::*;

impl PersonalServer {
    pub(crate) async fn personal_object_history(
        &self,
        store: Arc<Store>,
        id: Uuid,
    ) -> Result<Option<Vec<RemoteObject>>, PersonalSyncError> {
        let _operation = self.operation.lock().await;
        let vault = record(&store)?.personal_vault_id;
        let source = store.personal_history_object(vault, id).map_err(local)?;
        let context = self.bootstrap_inner(&store, false, None).await?;
        let path = format!("/sync/v1/vaults/{vault}/objects/{id}/versions");
        let response = context.request(self, &path, None, None, RESPONSE_LIMIT).await?;
        if store.personal_rotation() != context.rotation {
            return Err(PersonalSyncError::RotationRequired);
        }
        if response.status == 404 && response.problem_cbor {
            let problem = ProblemDetails::from_cbor(response.body.as_bytes()).map_err(invalid)?;
            if problem.status == 404
                && problem.code.as_str() == "sync.object_not_found"
                && !problem.changed
                && !problem.retryable
            {
                return Ok(None);
            }
        }
        if response.status != 200 {
            return Err(remote_error(&response));
        }
        let history =
            SyncVersionsResponse::from_cbor_with_limits(response.body.as_bytes(), READ_LIMITS)
                .and_then(|history| {
                    history.validate_for_object_with_limits(id, READ_LIMITS)?;
                    Ok(history)
                })
                .map_err(invalid)?;
        let versions = history
            .versions
            .iter()
            .map(|version| {
                let remote = context.decrypt(version)?;
                if remote.object.object_type != source.object_type
                    || remote.object.schema != source.schema
                    || remote.object.schema > scoplen_model::CURRENT_SCHEMA_VERSION
                {
                    return Err(PersonalSyncError::InvalidResponse);
                }
                Ok(remote)
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Local edits may continue during the read. They are never overwritten by a history query.
        store.personal_history_object(vault, id).map_err(local)?;
        Ok(Some(versions))
    }

    pub(crate) fn restore_personal_history_copy(
        &self,
        store: &Store,
        account: Uuid,
        vault: Uuid,
        source: Object,
    ) -> Result<(), PersonalSyncError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        store.restore_personal_history(account, vault, source).map_err(local)
    }
}
