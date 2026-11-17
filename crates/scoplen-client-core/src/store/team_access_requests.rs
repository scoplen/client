// SPDX-License-Identifier: Apache-2.0
//! Original access-request writes belong only to their encrypted Account store.

use rusqlite::{OptionalExtension, params};
use scoplen_crypto::SecretVec;
use uuid::Uuid;

use super::{Store, StoreError, personal::PersonalRecord};

pub(crate) struct TeamAccessRequestRecord {
    pub organization: Uuid,
    pub operation: Uuid,
    pub request: Uuid,
    pub kind: i64,
    pub payload: SecretVec,
    pub original: Option<SecretVec>,
    pub etag: Option<String>,
    pub phase: i64,
    pub first_attempt_ms: Option<u64>,
    pub response: Option<SecretVec>,
}

impl Store {
    pub(crate) fn team_access_request_pending(
        &self,
        identity: &PersonalRecord,
        organization: Uuid,
    ) -> Result<Option<TeamAccessRequestRecord>, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Err(StoreError::AccountContext);
        }
        Ok(self.conn().query_row(
            "SELECT operation_id,request_id,kind,payload,original,etag,phase,first_attempt_ms,response,
                length(payload),length(original),length(response) FROM team_access_requests
             WHERE origin=?1 AND account_id=?2 AND device_id=?3 AND organization_id=?4",
            params![identity.origin, identity.account_id.as_bytes().as_slice(),
                self.device_id().as_bytes().as_slice(), organization.as_bytes().as_slice()],
            |row| {
                let payload_size: i64 = row.get(9)?;
                let original_size: Option<i64> = row.get(10)?;
                let response_size: Option<i64> = row.get(11)?;
                if !(0..=4096).contains(&payload_size)
                    || original_size.is_some_and(|size| !(1..=8192).contains(&size))
                    || response_size.is_some_and(|size| !(1..=8192).contains(&size))
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                let id = |index| Uuid::from_slice(&row.get::<_, Vec<u8>>(index)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery);
                Ok(TeamAccessRequestRecord {
                    organization,
                    operation: id(0)?,
                    request: id(1)?,
                    kind: row.get(2)?,
                    payload: SecretVec::new(row.get(3)?),
                    original: row.get::<_, Option<Vec<u8>>>(4)?.map(SecretVec::new),
                    etag: row.get(5)?,
                    phase: row.get(6)?,
                    first_attempt_ms: row.get::<_, Option<i64>>(7)?
                        .map(u64::try_from).transpose().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    response: row.get::<_, Option<Vec<u8>>>(8)?.map(SecretVec::new),
                })
            },
        ).optional()?)
    }

    pub(crate) fn prepare_team_access_request(
        &self,
        identity: &PersonalRecord,
        pending: &TeamAccessRequestRecord,
    ) -> Result<bool, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Ok(false);
        }
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "INSERT INTO team_access_requests(origin,account_id,device_id,organization_id,
                operation_id,request_id,kind,payload,original,etag,phase)
             SELECT origin,account_id,?1,?2,?3,?4,?5,?6,?7,?8,0 FROM personal_server
             WHERE singleton=1 AND origin=?9 AND account_id=?10 AND private_material=?11
                AND auth_generation=?12
             ON CONFLICT(origin,account_id,device_id,organization_id) DO NOTHING",
            params![
                self.device_id().as_bytes().as_slice(),
                pending.organization.as_bytes().as_slice(),
                pending.operation.as_bytes().as_slice(),
                pending.request.as_bytes().as_slice(),
                pending.kind,
                pending.payload.as_bytes(),
                pending.original.as_ref().map(SecretVec::as_bytes),
                pending.etag,
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                identity.private_material.as_bytes(),
                identity.auth_generation
            ],
        )? == 1)
    }

    pub(crate) fn dispatch_team_access_request(
        &self,
        identity: &PersonalRecord,
        pending: &TeamAccessRequestRecord,
        access: &SecretVec,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let current = i64::try_from(now_ms).map_err(|_| StoreError::InvalidIdentifier)?;
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "UPDATE team_access_requests SET phase=1,first_attempt_ms=COALESCE(first_attempt_ms,?1)
             WHERE origin=?2 AND account_id=?3 AND device_id=?4 AND organization_id=?5
                AND operation_id=?6 AND payload=?7 AND phase=?8 AND response IS NULL
                AND first_attempt_ms IS ?9 AND kind=?14 AND etag IS ?15 AND original IS ?16
                AND EXISTS(SELECT 1 FROM personal_server WHERE singleton=1 AND origin=?2
                    AND account_id=?3 AND private_material=?10 AND auth_generation=?11
                    AND access_token=?12 AND access_expires_at>?13 AND refresh_claimed=0)",
            params![
                current,
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
                current / 1000,
                pending.kind,
                pending.etag,
                pending.original.as_ref().map(SecretVec::as_bytes)
            ],
        )? == 1)
    }

    pub(crate) fn finish_team_access_request(
        &self,
        identity: &PersonalRecord,
        pending: &TeamAccessRequestRecord,
        access: &SecretVec,
        response: Option<&[u8]>,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let current = i64::try_from(now_ms).map_err(|_| StoreError::InvalidIdentifier)?;
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "UPDATE team_access_requests SET phase=?1,response=?2
             WHERE origin=?3 AND account_id=?4 AND device_id=?5 AND organization_id=?6
                AND operation_id=?7 AND payload=?8 AND phase=1 AND first_attempt_ms IS ?9
                AND request_id=?14 AND kind=?15 AND etag IS ?16 AND original IS ?17
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
                current / 1000,
                pending.request.as_bytes().as_slice(),
                pending.kind,
                pending.etag,
                pending.original.as_ref().map(SecretVec::as_bytes)
            ],
        )? == 1)
    }

    pub(crate) fn discard_team_access_request(
        &self,
        identity: &PersonalRecord,
        pending: &TeamAccessRequestRecord,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Ok(false);
        }
        let cutoff = now_ms.saturating_sub(86_400_000).min(i64::MAX as u64) as i64;
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "DELETE FROM team_access_requests WHERE origin=?1 AND account_id=?2 AND device_id=?3
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
