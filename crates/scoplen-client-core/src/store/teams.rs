// SPDX-License-Identifier: Apache-2.0
//! The original team-creation request remains inside its Account's encrypted store.

use rusqlite::{OptionalExtension, params};
use scoplen_api::organization::{
    MAX_ORGANIZATION_CREATE_BYTES, MAX_ORGANIZATION_RESOURCE_BYTES,
    ORGANIZATION_CREATION_RECEIPT_SECONDS,
};
use scoplen_crypto::SecretVec;
use uuid::Uuid;

use super::{Store, StoreError, personal::PersonalRecord};

pub(crate) struct TeamCreationRecord {
    pub operation_id: Uuid,
    pub payload: SecretVec,
    pub phase: i64,
    pub first_attempt_ms: Option<u64>,
    pub response: Option<SecretVec>,
}

impl Store {
    pub(crate) fn team_creation(
        &self,
        identity: &PersonalRecord,
    ) -> Result<Option<TeamCreationRecord>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT operation_id, payload, phase, first_attempt_ms, response,
                length(payload), length(response)
             FROM team_creation WHERE singleton=1 AND origin=?1 AND account_id=?2",
                params![identity.origin, identity.account_id.as_bytes().as_slice()],
                |row| {
                    let payload_size: i64 = row.get(5)?;
                    let response_size: Option<i64> = row.get(6)?;
                    if !(1..=MAX_ORGANIZATION_CREATE_BYTES as i64).contains(&payload_size)
                        || response_size.is_some_and(|size| {
                            !(1..=MAX_ORGANIZATION_RESOURCE_BYTES as i64).contains(&size)
                        })
                    {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    Ok(TeamCreationRecord {
                        operation_id: Uuid::from_slice(&row.get::<_, Vec<u8>>(0)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        payload: SecretVec::new(row.get(1)?),
                        phase: row.get(2)?,
                        first_attempt_ms: row
                            .get::<_, Option<i64>>(3)?
                            .map(u64::try_from)
                            .transpose()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        response: row.get::<_, Option<Vec<u8>>>(4)?.map(SecretVec::new),
                    })
                },
            )
            .optional()?)
    }

    pub(crate) fn prepare_team_creation(
        &self,
        identity: &PersonalRecord,
        pending: &TeamCreationRecord,
    ) -> Result<bool, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Ok(false);
        }
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "INSERT INTO team_creation(singleton,origin,account_id,operation_id,payload,phase)
             SELECT 1,origin,account_id,?1,?2,0 FROM personal_server
             WHERE singleton=1 AND origin=?3 AND account_id=?4 AND private_material=?5
             ON CONFLICT(singleton) DO NOTHING",
            params![
                pending.operation_id.as_bytes().as_slice(),
                pending.payload.as_bytes(),
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                identity.private_material.as_bytes()
            ],
        )? == 1)
    }

    pub(crate) fn dispatch_team_creation(
        &self,
        identity: &PersonalRecord,
        previous: &TeamCreationRecord,
        access: &SecretVec,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Ok(false);
        }
        let now_ms = i64::try_from(now_ms).map_err(|_| StoreError::InvalidIdentifier)?;
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "UPDATE team_creation SET phase=1, first_attempt_ms=COALESCE(first_attempt_ms,?1)
             WHERE singleton=1 AND operation_id=?2 AND payload=?3 AND phase=?4
                AND first_attempt_ms IS ?5 AND response IS NULL AND origin=?6 AND account_id=?7
                AND EXISTS(SELECT 1 FROM personal_server WHERE singleton=1 AND origin=?6
                    AND account_id=?7 AND private_material=?8 AND auth_generation=?9
                    AND access_token=?10 AND access_expires_at>?11 AND refresh_claimed=0)",
            params![
                now_ms,
                previous.operation_id.as_bytes().as_slice(),
                previous.payload.as_bytes(),
                previous.phase,
                previous.first_attempt_ms.map(|time| time as i64),
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                identity.private_material.as_bytes(),
                identity.auth_generation,
                access.as_bytes(),
                now_ms / 1000
            ],
        )? == 1)
    }

    pub(crate) fn finish_team_creation(
        &self,
        identity: &PersonalRecord,
        sent: &TeamCreationRecord,
        access: &SecretVec,
        response: Option<&[u8]>,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Ok(false);
        }
        let now_ms = i64::try_from(now_ms).map_err(|_| StoreError::InvalidIdentifier)?;
        let phase = if response.is_some() { 2 } else { 0 };
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "UPDATE team_creation SET phase=?1,response=?2 WHERE singleton=1 AND phase=1
                AND operation_id=?3 AND payload=?4 AND first_attempt_ms IS ?5
                AND origin=?6 AND account_id=?7
                AND EXISTS(SELECT 1 FROM personal_server WHERE singleton=1 AND origin=?6
                    AND account_id=?7 AND private_material=?8 AND auth_generation=?9
                    AND access_token=?10 AND access_expires_at>?11 AND refresh_claimed=0)",
            params![
                phase,
                response,
                sent.operation_id.as_bytes().as_slice(),
                sent.payload.as_bytes(),
                sent.first_attempt_ms.map(|time| time as i64),
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                identity.private_material.as_bytes(),
                identity.auth_generation,
                access.as_bytes(),
                now_ms / 1000
            ],
        )? == 1)
    }

    pub(crate) fn discard_team_creation(
        &self,
        identity: &PersonalRecord,
        previous: &TeamCreationRecord,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let cutoff = now_ms.saturating_sub(ORGANIZATION_CREATION_RECEIPT_SECONDS * 1000);
        Ok(conn.execute(
            "DELETE FROM team_creation WHERE singleton=1 AND origin=?1 AND account_id=?2
                AND operation_id=?3 AND payload=?4 AND phase=?5 AND first_attempt_ms IS ?6
                AND (phase IN(0,2) OR first_attempt_ms<=?7)",
            params![
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                previous.operation_id.as_bytes().as_slice(),
                previous.payload.as_bytes(),
                previous.phase,
                previous.first_attempt_ms.map(|time| time as i64),
                cutoff.min(i64::MAX as u64) as i64
            ],
        )? == 1)
    }
}
