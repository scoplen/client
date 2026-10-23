// SPDX-License-Identifier: Apache-2.0
//! Explicit, bounded first-device Personal inventory synchronization.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Instant, UNIX_EPOCH},
};

use scoplen_api::{
    ProblemDetails,
    sync::{
        SyncAckRequest, SyncAckResponse, SyncChange, SyncChangesQuery, SyncChangesResponse,
        SyncConflictProblem, SyncReadLimits, SyncWrite, SyncWriteBatch, SyncWriteBatchResponse,
        SyncWriteLimits,
    },
};
use scoplen_crypto::{DpopProof, DpopTarget, DpopToken, ObjectEnvelope};
use scoplen_model::{Object, ObjectType};
use uuid::Uuid;

use super::{
    PersonalServer, PersonalServerError, PersonalSyncError, SyncContext, invalid, now, record,
    storage,
};
use crate::personal_server::transport::Response;
use crate::store::{
    Store, StoreError,
    sync::{PendingObject, RemoteObject},
};

const MAX_ENVELOPE: usize = 1024 * 1024;
const RESPONSE_LIMIT: usize = 9 * 1024 * 1024;
const PAGE_SIZE: u16 = 8;
const MAX_PAGES: usize = 64;
const MAX_BATCHES: usize = 64;
const MAX_CONFLICTS: usize = 3;
const READ_LIMITS: SyncReadLimits =
    SyncReadLimits { max_envelope_bytes: MAX_ENVELOPE, max_body_bytes: RESPONSE_LIMIT };

mod reconciliation;

/// An explicit intent for the retained Personal vault. Empty `adopt` only synchronizes
/// previously adopted objects; it never selects local inventory automatically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonalInventoryIntent {
    /// The retained Personal vault whose ownership the user reviewed.
    pub vault_id: Uuid,
    /// Exact confirmed local object ids. References never expand this set.
    pub adopt: Vec<Uuid>,
}

/// Public counts and applied progress only; no object content or secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersonalInventoryProgress {
    /// Highest remote sequence durably applied in the encrypted store.
    pub applied_cursor: u64,
    /// Highest applied cursor whose explicit acknowledgement was confirmed and saved.
    pub acknowledged_cursor: u64,
    /// Encrypted change entries applied or already present during this cycle.
    pub downloaded: u64,
    /// Object writes with validated, durably retained server assignments.
    pub uploaded: u64,
    /// A bounded cycle completed, but another explicit cycle is needed for remaining work.
    pub more: bool,
}

impl PersonalServer {
    /// Restore immutable adoption copies as new local objects, returning original/new ids.
    /// This is a local action; it neither undoes remote writes nor copies device secrets.
    pub fn restore_personal_inventory_copies(
        &self,
        store: &Store,
        vault: Uuid,
        selected: &[Uuid],
    ) -> Result<Vec<(Uuid, Uuid)>, PersonalSyncError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        store.restore_personal_adoption(vault, selected).map_err(local)
    }

    /// Restore edits quarantined by full reconciliation as new, unsynchronized local objects.
    pub fn restore_personal_reconciliation_copies(
        &self,
        store: &Store,
        vault: Uuid,
        selected: &[Uuid],
    ) -> Result<Vec<(Uuid, Uuid)>, PersonalSyncError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        store.restore_personal_recovery(vault, selected).map_err(local)
    }

    /// Pull and merge before every write attempt. The desktop calls this Rust-owned path
    /// after its explicit selection preview and confirmation (D-112).
    pub async fn sync_personal_inventory(
        &self,
        store: Arc<Store>,
        intent: PersonalInventoryIntent,
    ) -> Result<PersonalInventoryProgress, PersonalSyncError> {
        self.sync_personal_inventory_expected(store, intent, None).await
    }

    pub(crate) async fn sync_personal_inventory_expected(
        &self,
        store: Arc<Store>,
        intent: PersonalInventoryIntent,
        reviewed: Option<HashMap<Uuid, [u8; 32]>>,
    ) -> Result<PersonalInventoryProgress, PersonalSyncError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        if record(&store)?.personal_vault_id != intent.vault_id {
            return Err(PersonalSyncError::Selection);
        }
        if intent.adopt.len() > crate::store::MAX_OBJECTS_PER_VAULT as usize {
            return Err(PersonalSyncError::ResourceLimit);
        }
        let context = self.bootstrap_inner(&store, true).await?;
        for id in &intent.adopt {
            let object = store.get(*id).map_err(local)?.ok_or(PersonalSyncError::Selection)?;
            context.validate_inventory(&object)?;
        }
        if let Some(reviewed) = reviewed.as_ref() {
            store
                .adopt_personal_objects_reviewed(intent.vault_id, &intent.adopt, Some(reviewed))
                .map_err(local)?;
        } else {
            store.adopt_personal_objects(intent.vault_id, &intent.adopt).map_err(local)?;
        }
        let mut progress = PersonalInventoryProgress {
            applied_cursor: store.personal_sync_cursor(intent.vault_id).map_err(local)?,
            acknowledged_cursor: store
                .personal_acknowledged_cursor(intent.vault_id)
                .map_err(local)?,
            downloaded: 0,
            uploaded: 0,
            more: false,
        };
        let mut conflicts = 0;
        for _ in 0..MAX_BATCHES {
            let Some(server_clock) = self.pull_inventory(&store, &context, &mut progress).await?
            else {
                progress.more = true;
                return Ok(progress);
            };
            let limits = selected_write_limits(&context)?;
            let pending = store
                .pending_personal_objects(intent.vault_id, limits.max_batch_objects)
                .map_err(local)?;
            if pending.is_empty() {
                return Ok(progress);
            }
            check_clock(server_clock)?;
            let (pending, batch, encoded) = encrypted_batch(&context, pending, limits)?;
            let path = format!("/sync/v1/vaults/{}/objects", intent.vault_id);
            // Any transport or decoding failure after POST might follow a committed batch.
            // Preserve the outbox; the next cycle starts by pulling authoritative state.
            let response = context
                .request(self, &path, None, Some(&encoded), RESPONSE_LIMIT)
                .await
                .map_err(|error| match error {
                    PersonalSyncError::AuthenticationRequired => error,
                    _ => PersonalSyncError::WriteOutcomeUnknown,
                })?;
            match response.status {
                200 => {
                    let assignments = SyncWriteBatchResponse::from_cbor_with_limits(
                        response.body.as_bytes(),
                        limits,
                    )
                    .and_then(|assignments| {
                        assignments.validate_for_batch_with_limits(&batch, limits)?;
                        Ok(assignments)
                    })
                    .map_err(|_| PersonalSyncError::WriteOutcomeUnknown)?;
                    store
                        .settle_personal_write(intent.vault_id, &pending, &assignments)
                        .map_err(|_| PersonalSyncError::WriteOutcomeUnknown)?;
                    progress.uploaded += assignments.assignments.len() as u64;
                    conflicts = 0;
                }
                409 if response.problem_cbor => {
                    let conflict = SyncConflictProblem::from_cbor_with_limits(
                        response.body.as_bytes(),
                        limits,
                    )
                    .and_then(|conflict| {
                        conflict.validate_for_batch_with_limits(&batch, limits)?;
                        Ok(conflict)
                    })
                    .map_err(|_| PersonalSyncError::WriteOutcomeUnknown)?;
                    let remote = conflict
                        .conflicts
                        .iter()
                        .map(|entry| {
                            let current = entry
                                .current
                                .as_ref()
                                .ok_or(PersonalSyncError::ReconciliationRequired)?;
                            context.decrypt(current)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    store.merge_personal_conflicts(intent.vault_id, &remote).map_err(local)?;
                    conflicts += 1;
                    if conflicts >= MAX_CONFLICTS {
                        return Err(PersonalSyncError::ConcurrentChanges);
                    }
                }
                401 | 403 => return Err(PersonalSyncError::AuthenticationRequired),
                _ => return Err(write_problem(&response)),
            }
        }
        // Apply and acknowledge our final write before reporting its cursor. If the page
        // budget is exhausted, its durable cursor is still a safe continuation point.
        let caught_up = self.pull_inventory(&store, &context, &mut progress).await?.is_some();
        progress.more = !caught_up
            || !store.pending_personal_objects(intent.vault_id, 1).map_err(local)?.is_empty();
        Ok(progress)
    }

    async fn pull_inventory(
        &self,
        store: &Store,
        context: &SyncContext,
        progress: &mut PersonalInventoryProgress,
    ) -> Result<Option<(std::time::SystemTime, Instant)>, PersonalSyncError> {
        let path = format!("/sync/v1/vaults/{}/changes", context.identity.personal_vault_id);
        for _ in 0..MAX_PAGES {
            let query = SyncChangesQuery { after: progress.applied_cursor, limit: PAGE_SIZE };
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
                if response.status == 410 && response.problem_cbor {
                    let problem =
                        ProblemDetails::from_cbor(response.body.as_bytes()).map_err(invalid)?;
                    if problem.status == 410
                        && problem.code.as_str() == "sync.cursor_expired"
                        && !problem.changed
                    {
                        return self.reconcile_inventory(store, context, progress).await.map(Some);
                    }
                }
                return Err(remote_error(&response));
            }
            let page =
                SyncChangesResponse::from_cbor_with_limits(response.body.as_bytes(), READ_LIMITS)
                    .and_then(|page| {
                        page.validate_for_query_with_limits(&query, READ_LIMITS)?;
                        Ok(page)
                    })
                    .map_err(invalid)?;
            let announced_seq = context
                .bootstrap
                .session
                .vaults
                .iter()
                .find(|vault| vault.id == context.identity.personal_vault_id)
                .ok_or(PersonalSyncError::InvalidResponse)?
                .seq;
            if !page.more && page.next_cursor < announced_seq {
                return Err(PersonalSyncError::InvalidResponse);
            }
            let objects = page
                .changes
                .iter()
                .map(|change| context.decrypt(change))
                .collect::<Result<Vec<_>, _>>()?;
            store
                .apply_personal_page(
                    context.identity.personal_vault_id,
                    query.after,
                    page.next_cursor,
                    &objects,
                )
                .map_err(local)?;
            progress.applied_cursor = page.next_cursor;
            progress.downloaded += objects.len() as u64;
            self.ack_inventory(store, context, progress).await?;
            if !page.more {
                // A Date is needed only when a queued object is about to be written.
                return Ok(Some(response.date.unwrap_or((UNIX_EPOCH, Instant::now()))));
            }
        }
        Ok(None)
    }

    async fn ack_inventory(
        &self,
        store: &Store,
        context: &SyncContext,
        progress: &mut PersonalInventoryProgress,
    ) -> Result<(), PersonalSyncError> {
        // Acknowledging a larger value reported by the server never advances our cursor.
        let request = SyncAckRequest { cursor: progress.applied_cursor };
        let ack_path = format!("/sync/v1/vaults/{}/ack", context.identity.personal_vault_id);
        let ack = context
            .request(
                self,
                &ack_path,
                None,
                Some(&request.to_cbor().map_err(invalid)?),
                RESPONSE_LIMIT,
            )
            .await
            .map_err(|error| {
                if error == PersonalSyncError::AuthenticationRequired {
                    error
                } else {
                    PersonalSyncError::AcknowledgementUnknown
                }
            })?;
        if ack.status != 200 {
            return Err(if matches!(ack.status, 401 | 403) {
                PersonalSyncError::AuthenticationRequired
            } else {
                PersonalSyncError::AcknowledgementUnknown
            });
        }
        SyncAckResponse::from_cbor(ack.body.as_bytes())
            .and_then(|response| response.validate_for_request(&request))
            .map_err(|_| PersonalSyncError::AcknowledgementUnknown)?;
        store
            .save_personal_acknowledgement(context.identity.personal_vault_id, request.cursor)
            .map_err(|_| PersonalSyncError::AcknowledgementUnknown)?;
        progress.acknowledged_cursor = store
            .personal_acknowledged_cursor(context.identity.personal_vault_id)
            .map_err(local)?;
        Ok(())
    }
}

impl SyncContext {
    async fn request(
        &self,
        manager: &PersonalServer,
        path: &str,
        query: Option<&str>,
        body: Option<&[u8]>,
        limit: usize,
    ) -> Result<Response, PersonalSyncError> {
        if self.expires_at <= now()? {
            return Err(PersonalSyncError::AuthenticationRequired);
        }
        let token = std::str::from_utf8(self.access.as_bytes()).map_err(invalid)?;
        let target = DpopTarget::new(
            if body.is_some() { "POST" } else { "GET" },
            &self.identity.origin,
            path,
        )
        .map_err(invalid)?;
        let proof = DpopProof::sign(
            &self.signing,
            &self.signing.public_key_sec1(),
            &target,
            DpopToken::Protected(token),
            now()?,
            None,
        )
        .map_err(invalid)?;
        let request_path = query.map_or_else(|| path.to_owned(), |query| format!("{path}?{query}"));
        manager
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .protected(&self.identity.origin, &request_path, body, token, &proof, limit)
            .await
            .map_err(Into::into)
    }

    fn decrypt(&self, change: &SyncChange) -> Result<RemoteObject, PersonalSyncError> {
        let envelope = ObjectEnvelope::decode(&change.payload).map_err(invalid)?;
        if envelope.key_epoch != 1 || change.signer_device_id != Some(envelope.signer_device_id) {
            return Err(PersonalSyncError::InvalidResponse);
        }
        let certificate = self
            .bootstrap
            .active_devices
            .iter()
            .find(|device| device.device_id == envelope.signer_device_id)
            .ok_or(PersonalSyncError::InvalidResponse)?;
        let object = envelope
            .decrypt(
                self.identity.personal_vault_id,
                change.object_id,
                &self.bootstrap.personal_vault_key,
                &certificate.signing_public_key,
            )
            .map_err(invalid)?;
        if object.is_tombstoned() != change.tombstone {
            return Err(PersonalSyncError::InvalidResponse);
        }
        self.validate_inventory(&object)?;
        Ok(RemoteObject { object, seq: change.seq })
    }

    fn validate_inventory(&self, object: &Object) -> Result<(), PersonalSyncError> {
        object.validate().map_err(invalid)?;
        // Organization inventory is never silently adopted into the opaque Personal tier.
        if object.object_type == ObjectType::GATEWAY_NETWORK
            || object.object_type == ObjectType::ROUTE && object.required_uint(2).ok() == Some(5)
        {
            return Err(PersonalSyncError::Selection);
        }
        if object.object_type == ObjectType::TRUST_RECORD {
            let account = object.required_uuid(8).ok();
            let device = object.required_uuid(7).ok();
            if account != Some(self.identity.account_id)
                || !self
                    .bootstrap
                    .active_devices
                    .iter()
                    .any(|active| Some(active.device_id) == device)
                || !matches!(object.required_uint(5), Ok(1 | 2))
            {
                return Err(PersonalSyncError::TrustReviewRequired);
            }
        }
        Ok(())
    }
}

fn selected_write_limits(context: &SyncContext) -> Result<SyncWriteLimits, PersonalSyncError> {
    let advertised =
        SyncWriteLimits::try_from(&context.bootstrap.session.limits).map_err(invalid)?;
    Ok(SyncWriteLimits {
        max_envelope_bytes: advertised.max_envelope_bytes.min(MAX_ENVELOPE),
        max_batch_objects: advertised.max_batch_objects.min(8),
        max_batch_bytes: advertised.max_batch_bytes.min(4 * 1024 * 1024),
    })
}

fn encrypted_batch(
    context: &SyncContext,
    pending: Vec<PendingObject>,
    limits: SyncWriteLimits,
) -> Result<(Vec<PendingObject>, SyncWriteBatch, Vec<u8>), PersonalSyncError> {
    let mut selected = Vec::new();
    let mut batch = SyncWriteBatch { writes: Vec::new() };
    let mut encoded = Vec::new();
    for object in pending {
        context.validate_inventory(&object.object)?;
        let payload = ObjectEnvelope::encrypt(
            context.identity.personal_vault_id,
            1,
            &object.object,
            &context.bootstrap.personal_vault_key,
            context.device_id,
            &context.signing,
        )
        .and_then(|envelope| envelope.encode())
        .map_err(invalid)?;
        batch.writes.push(SyncWrite {
            object_id: object.object.id,
            base_seq: object.base,
            payload,
            tombstone: object.object.is_tombstoned(),
        });
        match batch.to_cbor_with_limits(limits) {
            Ok(bytes) => {
                encoded = bytes;
                selected.push(object);
            }
            Err(_) if !selected.is_empty() => {
                batch.writes.pop();
                break;
            }
            Err(_) => return Err(PersonalSyncError::ResourceLimit),
        }
    }
    Ok((selected, batch, encoded))
}

fn check_clock(
    (server, received): (std::time::SystemTime, Instant),
) -> Result<(), PersonalSyncError> {
    if server == UNIX_EPOCH {
        return Err(PersonalSyncError::Clock);
    }
    let server = server
        .checked_add(received.elapsed())
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or(PersonalSyncError::Clock)?;
    scoplen_model::clock::ensure_write_clock(
        scoplen_model::system_time_millis().map_err(|_| PersonalSyncError::Clock)?,
        server,
    )
    .map_err(|_| PersonalSyncError::Clock)
}

fn local(error: StoreError) -> PersonalSyncError {
    match error {
        StoreError::SyncSelection | StoreError::NotFound(_) => PersonalSyncError::Selection,
        StoreError::SyncChanged => PersonalSyncError::ConcurrentChanges,
        StoreError::RecoveryLimit => PersonalSyncError::ResourceLimit,
        _ => storage(error).into(),
    }
}

fn remote_error(response: &Response) -> PersonalSyncError {
    if matches!(response.status, 401 | 403) {
        PersonalSyncError::AuthenticationRequired
    } else {
        PersonalSyncError::InvalidResponse
    }
}

fn write_problem(response: &Response) -> PersonalSyncError {
    if response.problem_cbor
        && let Ok(problem) = ProblemDetails::from_cbor(response.body.as_bytes())
        && problem.status == response.status
        && !problem.changed
    {
        return PersonalSyncError::InvalidResponse;
    }
    PersonalSyncError::WriteOutcomeUnknown
}
