// SPDX-License-Identifier: Apache-2.0
//! Original CA and certificate requests, retained before any network dispatch.

use rusqlite::{OptionalExtension, params};
use scoplen_crypto::SecretVec;
use uuid::Uuid;

use super::{Store, StoreError, team_ssh::TeamSshOwner};

pub(crate) struct TeamSshOperationRecord {
    pub kind: i64,
    pub id: Uuid,
    pub payload: SecretVec,
    pub ca: Option<SecretVec>,
    pub generation: Option<Uuid>,
    pub phase: i64,
    pub first_attempt: Option<u64>,
    pub response: Option<SecretVec>,
}

impl Store {
    pub(crate) fn team_ssh_operation(
        &self,
        owner: &TeamSshOwner,
        kind: i64,
    ) -> Result<Option<TeamSshOperationRecord>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT operation_id,payload,ca,generation,phase,first_attempt,response,
                length(payload),length(ca),length(response) FROM team_ssh_operations
             WHERE origin=?1 AND account_id=?2 AND organization_id=?3 AND device_id=?4 AND kind=?5",
                params![
                    owner.origin,
                    owner.account.as_bytes().as_slice(),
                    owner.organization.as_bytes().as_slice(),
                    owner.device.as_bytes().as_slice(),
                    kind
                ],
                |row| {
                    if !(1..=16384).contains(&row.get::<_, i64>(7)?)
                        || row
                            .get::<_, Option<i64>>(8)?
                            .is_some_and(|size| !(1..=16384).contains(&size))
                        || row
                            .get::<_, Option<i64>>(9)?
                            .is_some_and(|size| !(1..=131072).contains(&size))
                    {
                        return Err(rusqlite::Error::InvalidQuery);
                    }
                    let uuid = |bytes: Vec<u8>| {
                        Uuid::from_slice(&bytes).map_err(|_| rusqlite::Error::InvalidQuery)
                    };
                    Ok(TeamSshOperationRecord {
                        kind,
                        id: uuid(row.get(0)?)?,
                        payload: SecretVec::new(row.get(1)?),
                        ca: row.get::<_, Option<Vec<u8>>>(2)?.map(SecretVec::new),
                        generation: row.get::<_, Option<Vec<u8>>>(3)?.map(uuid).transpose()?,
                        phase: row.get(4)?,
                        first_attempt: row
                            .get::<_, Option<i64>>(5)?
                            .map(u64::try_from)
                            .transpose()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        response: row.get::<_, Option<Vec<u8>>>(6)?.map(SecretVec::new),
                    })
                },
            )
            .optional()?)
    }

    pub(crate) fn prepare_team_ssh_operation(
        &self,
        owner: &TeamSshOwner,
        operation: &TeamSshOperationRecord,
    ) -> Result<bool, StoreError> {
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "INSERT INTO team_ssh_operations(origin,account_id,organization_id,device_id,
                kind,operation_id,payload,ca,generation,phase)
             SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,0 WHERE EXISTS(
                SELECT 1 FROM personal_admission WHERE singleton=1 AND origin=?1
                    AND account_id=?2 AND device_id=?4)
             ON CONFLICT(origin,account_id,organization_id,device_id,kind) DO NOTHING",
            params![
                owner.origin,
                owner.account.as_bytes().as_slice(),
                owner.organization.as_bytes().as_slice(),
                owner.device.as_bytes().as_slice(),
                operation.kind,
                operation.id.as_bytes().as_slice(),
                operation.payload.as_bytes(),
                operation.ca.as_ref().map(SecretVec::as_bytes),
                operation.generation.as_ref().map(|id| id.as_bytes().as_slice())
            ],
        )? == 1)
    }

    pub(crate) fn dispatch_team_ssh_operation(
        &self,
        owner: &TeamSshOwner,
        operation: &TeamSshOperationRecord,
        access: &SecretVec,
        now: u64,
    ) -> Result<bool, StoreError> {
        let now = i64::try_from(now).map_err(|_| StoreError::InvalidIdentifier)?;
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "UPDATE team_ssh_operations SET phase=1,first_attempt=COALESCE(first_attempt,?1)
             WHERE origin=?2 AND account_id=?3 AND organization_id=?4 AND device_id=?5
                AND kind=?6 AND operation_id=?7 AND payload=?8 AND phase=?9
                AND first_attempt IS ?10 AND response IS NULL
                AND EXISTS(SELECT 1 FROM personal_server WHERE singleton=1 AND origin=?2
                    AND account_id=?3 AND access_token=?11 AND access_expires_at>?1 AND refresh_claimed=0)
                AND (kind=0 OR EXISTS(SELECT 1 FROM team_ssh_signers s
                    JOIN team_asset_views v USING(origin,account_id,organization_id)
                    WHERE s.origin=?2 AND s.account_id=?3 AND s.organization_id=?4
                        AND s.device_id=?5 AND s.active=1 AND s.generation=team_ssh_operations.generation
                        AND v.phase=1 AND v.vault_id=s.vault_id AND v.revision=s.revision))",
            params![now, owner.origin, owner.account.as_bytes().as_slice(),
                owner.organization.as_bytes().as_slice(), owner.device.as_bytes().as_slice(),
                operation.kind, operation.id.as_bytes().as_slice(), operation.payload.as_bytes(),
                operation.phase, operation.first_attempt.map(|time| time as i64), access.as_bytes()],
        )? == 1)
    }

    pub(crate) fn finish_team_ssh_operation(
        &self,
        owner: &TeamSshOwner,
        operation: &TeamSshOperationRecord,
        response: Option<&[u8]>,
    ) -> Result<bool, StoreError> {
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "UPDATE team_ssh_operations SET phase=?1,response=?2 WHERE origin=?3 AND account_id=?4
                AND organization_id=?5 AND device_id=?6 AND kind=?7 AND operation_id=?8
                AND payload=?9 AND phase=1 AND first_attempt IS ?10",
            params![
                if response.is_some() { 2 } else { 0 },
                response,
                owner.origin,
                owner.account.as_bytes().as_slice(),
                owner.organization.as_bytes().as_slice(),
                owner.device.as_bytes().as_slice(),
                operation.kind,
                operation.id.as_bytes().as_slice(),
                operation.payload.as_bytes(),
                operation.first_attempt.map(|time| time as i64)
            ],
        )? == 1)
    }

    pub(crate) fn discard_team_ssh_operation(
        &self,
        owner: &TeamSshOwner,
        operation: &TeamSshOperationRecord,
        now: u64,
    ) -> Result<bool, StoreError> {
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "DELETE FROM team_ssh_operations WHERE origin=?1 AND account_id=?2 AND organization_id=?3
                AND device_id=?4 AND kind=?5 AND operation_id=?6 AND payload=?7 AND phase=?8
                AND first_attempt IS ?9 AND (phase IN(0,2) OR first_attempt+86400<=?10)",
            params![owner.origin, owner.account.as_bytes().as_slice(),
                owner.organization.as_bytes().as_slice(), owner.device.as_bytes().as_slice(),
                operation.kind, operation.id.as_bytes().as_slice(), operation.payload.as_bytes(),
                operation.phase, operation.first_attempt.map(|time| time as i64),
                now.min(i64::MAX as u64) as i64],
        )? == 1)
    }
}
