// SPDX-License-Identifier: Apache-2.0
//! Download a complete, stable snapshot before changing live SQLCipher inventory.

use std::{collections::HashSet, time::Duration};

use scoplen_api::sync::SyncSnapshotResponse;

use super::*;

const SNAPSHOT_PAGE_SIZE: u16 = 32;
const SNAPSHOT_BYTES: usize = 32 * 1024 * 1024;
const SNAPSHOT_DEADLINE: Duration = Duration::from_secs(60);

struct Snapshot {
    objects: Vec<RemoteObject>,
    cursor: u64,
    date: (std::time::SystemTime, Instant),
}

impl PersonalServer {
    pub(super) async fn reconcile_inventory(
        &self,
        store: &Store,
        context: &SyncContext,
        progress: &mut PersonalInventoryProgress,
    ) -> Result<(std::time::SystemTime, Instant), PersonalSyncError> {
        let snapshot = tokio::time::timeout(SNAPSHOT_DEADLINE, self.download_snapshot(context))
            .await
            .map_err(|_| PersonalSyncError::ResourceLimit)??;
        store
            .reconcile_personal_snapshot(
                context.identity.personal_vault_id,
                progress.applied_cursor,
                snapshot.cursor,
                &snapshot.objects,
            )
            .map_err(local)?;
        progress.applied_cursor = snapshot.cursor;
        progress.downloaded += snapshot.objects.len() as u64;
        self.ack_inventory(store, context, progress).await?;
        Ok(snapshot.date)
    }

    async fn download_snapshot(
        &self,
        context: &SyncContext,
    ) -> Result<Snapshot, PersonalSyncError> {
        let announced = context
            .bootstrap
            .session
            .vaults
            .iter()
            .find(|vault| vault.id == context.identity.personal_vault_id)
            .ok_or(PersonalSyncError::InvalidResponse)?
            .seq;
        let path = format!("/sync/v1/vaults/{}/snapshot", context.identity.personal_vault_id);
        let mut after = 0;
        let mut objects = Vec::new();
        let mut seen = HashSet::new();
        let mut bytes = 0_usize;
        // A server may return a shorter nonempty prefix than the requested count.
        // The object count, total body bytes and wall-clock deadline bound the whole pass.
        for _ in 0..=crate::store::MAX_OBJECTS_PER_VAULT {
            let query = SyncChangesQuery { after, limit: SNAPSHOT_PAGE_SIZE };
            let response = context
                .request(
                    self,
                    &path,
                    Some(&query.to_query().map_err(invalid)?),
                    None,
                    RESPONSE_LIMIT,
                )
                .await?;
            if response.status != 200 {
                return Err(remote_error(&response));
            }
            bytes = bytes
                .checked_add(response.body.as_bytes().len())
                .ok_or(PersonalSyncError::ResourceLimit)?;
            if bytes > SNAPSHOT_BYTES {
                return Err(PersonalSyncError::ResourceLimit);
            }
            let page =
                SyncSnapshotResponse::from_cbor_with_limits(response.body.as_bytes(), READ_LIMITS)
                    .and_then(|page| {
                        page.validate_for_query_with_limits(&query, READ_LIMITS)?;
                        Ok(page)
                    })
                    .map_err(invalid)?;
            if page.next_cursor > announced {
                // This is legitimate concurrent server activity, not permanent corruption.
                // Without a cross-page snapshot token, retry from a new explicit session.
                return Err(PersonalSyncError::ConcurrentChanges);
            }
            for change in &page.objects {
                if !seen.insert(change.object_id) {
                    return Err(PersonalSyncError::InvalidResponse);
                }
                if objects.len() >= crate::store::MAX_OBJECTS_PER_VAULT as usize {
                    return Err(PersonalSyncError::ResourceLimit);
                }
                objects.push(context.decrypt(change)?);
            }
            after = page.next_cursor;
            if !page.more {
                if after != announced {
                    return Err(PersonalSyncError::InvalidResponse);
                }
                return Ok(Snapshot {
                    objects,
                    cursor: after,
                    date: response.date.unwrap_or((UNIX_EPOCH, Instant::now())),
                });
            }
        }
        Err(PersonalSyncError::ResourceLimit)
    }
}
