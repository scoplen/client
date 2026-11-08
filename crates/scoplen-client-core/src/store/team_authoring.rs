// SPDX-License-Identifier: Apache-2.0
//! Original Organization creates remain durable in the encrypted Account store.

use rusqlite::{OptionalExtension, params};
use scoplen_crypto::SecretVec;
use uuid::Uuid;

use super::{Store, StoreError, personal::PersonalRecord};

pub(crate) struct TeamAuthoringRecord {
    pub organization: Uuid,
    pub operation: Uuid,
    pub resource: Uuid,
    pub collection: String,
    pub payload: SecretVec,
    pub phase: i64,
    pub first_attempt_ms: Option<u64>,
    pub response: Option<SecretVec>,
}

impl Store {
    pub(crate) fn team_authoring_pending(
        &self,
        identity: &PersonalRecord,
        organization: Uuid,
    ) -> Result<Option<TeamAuthoringRecord>, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Err(StoreError::AccountContext);
        }
        Ok(self.conn().query_row(
            "SELECT operation_id,resource_id,collection,payload,phase,first_attempt_ms,response,
                length(payload),length(response) FROM team_authoring
             WHERE origin=?1 AND account_id=?2 AND device_id=?3 AND organization_id=?4",
            params![identity.origin, identity.account_id.as_bytes().as_slice(),
                self.device_id().as_bytes().as_slice(), organization.as_bytes().as_slice()],
            |row| {
                let payload_size: i64 = row.get(7)?;
                let response_size: Option<i64> = row.get(8)?;
                if !(1..=2_097_152).contains(&payload_size)
                    || response_size.is_some_and(|size| !(1..=2_097_152).contains(&size))
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                let id = |index| Uuid::from_slice(&row.get::<_, Vec<u8>>(index)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery);
                Ok(TeamAuthoringRecord {
                    organization,
                    operation: id(0)?,
                    resource: id(1)?,
                    collection: row.get(2)?,
                    payload: SecretVec::new(row.get(3)?),
                    phase: row.get(4)?,
                    first_attempt_ms: row.get::<_, Option<i64>>(5)?
                        .map(u64::try_from).transpose().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    response: row.get::<_, Option<Vec<u8>>>(6)?.map(SecretVec::new),
                })
            },
        ).optional()?)
    }

    pub(crate) fn prepare_team_authoring(
        &self,
        identity: &PersonalRecord,
        pending: &TeamAuthoringRecord,
    ) -> Result<bool, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Ok(false);
        }
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "INSERT INTO team_authoring(origin,account_id,device_id,organization_id,operation_id,
                resource_id,collection,payload,phase)
             SELECT origin,account_id,?1,?2,?3,?4,?5,?6,0 FROM personal_server
             WHERE singleton=1 AND origin=?7 AND account_id=?8 AND private_material=?9
             ON CONFLICT(origin,account_id,device_id,organization_id) DO NOTHING",
            params![
                self.device_id().as_bytes().as_slice(),
                pending.organization.as_bytes().as_slice(),
                pending.operation.as_bytes().as_slice(),
                pending.resource.as_bytes().as_slice(),
                pending.collection,
                pending.payload.as_bytes(),
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                identity.private_material.as_bytes()
            ],
        )? == 1)
    }

    pub(crate) fn dispatch_team_authoring(
        &self,
        identity: &PersonalRecord,
        pending: &TeamAuthoringRecord,
        access: &SecretVec,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let current_ms = i64::try_from(now_ms).map_err(|_| StoreError::InvalidIdentifier)?;
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "UPDATE team_authoring SET phase=1,first_attempt_ms=COALESCE(first_attempt_ms,?1)
             WHERE origin=?2 AND account_id=?3 AND device_id=?4 AND organization_id=?5
                AND operation_id=?6 AND payload=?7 AND phase=?8 AND response IS NULL
                AND first_attempt_ms IS ?9
                AND EXISTS(SELECT 1 FROM personal_server WHERE singleton=1 AND origin=?2
                    AND account_id=?3 AND private_material=?10 AND auth_generation=?11
                    AND access_token=?12 AND access_expires_at>?13 AND refresh_claimed=0)",
            params![
                current_ms,
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                self.device_id().as_bytes().as_slice(),
                pending.organization.as_bytes().as_slice(),
                pending.operation.as_bytes().as_slice(),
                pending.payload.as_bytes(),
                pending.phase,
                pending.first_attempt_ms.map(|value| value as i64),
                identity.private_material.as_bytes(),
                identity.auth_generation,
                access.as_bytes(),
                current_ms / 1000
            ],
        )? == 1)
    }

    pub(crate) fn finish_team_authoring(
        &self,
        identity: &PersonalRecord,
        pending: &TeamAuthoringRecord,
        access: &SecretVec,
        response: Option<&[u8]>,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let current_ms = i64::try_from(now_ms).map_err(|_| StoreError::InvalidIdentifier)?;
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "UPDATE team_authoring SET phase=?1,response=?2
             WHERE origin=?3 AND account_id=?4 AND device_id=?5 AND organization_id=?6
                AND operation_id=?7 AND payload=?8 AND phase=1 AND first_attempt_ms IS ?9
                AND EXISTS(SELECT 1 FROM personal_server WHERE singleton=1 AND origin=?3
                    AND account_id=?4 AND private_material=?10 AND auth_generation=?11
                    AND access_token=?12 AND access_expires_at>?13 AND refresh_claimed=0)",
            params![
                if response.is_some() { 2 } else { 0 },
                response,
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                self.device_id().as_bytes().as_slice(),
                pending.organization.as_bytes().as_slice(),
                pending.operation.as_bytes().as_slice(),
                pending.payload.as_bytes(),
                pending.first_attempt_ms.map(|value| value as i64),
                identity.private_material.as_bytes(),
                identity.auth_generation,
                access.as_bytes(),
                current_ms / 1000
            ],
        )? == 1)
    }

    pub(crate) fn discard_team_authoring(
        &self,
        identity: &PersonalRecord,
        pending: &TeamAuthoringRecord,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Ok(false);
        }
        let cutoff = now_ms.saturating_sub(86_400_000).min(i64::MAX as u64) as i64;
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "DELETE FROM team_authoring WHERE origin=?1 AND account_id=?2 AND device_id=?3
                AND organization_id=?4 AND operation_id=?5 AND payload=?6 AND phase=?7
                AND first_attempt_ms IS ?8 AND (phase IN(0,2) OR first_attempt_ms<=?9)",
            params![
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                self.device_id().as_bytes().as_slice(),
                pending.organization.as_bytes().as_slice(),
                pending.operation.as_bytes().as_slice(),
                pending.payload.as_bytes(),
                pending.phase,
                pending.first_attempt_ms.map(|value| value as i64),
                cutoff
            ],
        )? == 1)
    }
}
