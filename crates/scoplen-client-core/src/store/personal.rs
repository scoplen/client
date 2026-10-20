// SPDX-License-Identifier: Apache-2.0
//! Durable pending identity and credentials, inside the SQLCipher boundary.

use rusqlite::{OptionalExtension, params};
use scoplen_crypto::SecretVec;
use uuid::Uuid;

use super::{Store, StoreError, uuid_from};

#[derive(Debug)]
pub(crate) struct PersonalRecord {
    pub origin: String,
    pub account_id: Uuid,
    pub personal_vault_id: Uuid,
    pub device_name: String,
    pub private_material: SecretVec,
    pub enrollment_request: Option<SecretVec>,
    pub recovery_saved: bool,
    pub recovery_confirmed: bool,
    pub enrollment_attempted: bool,
    pub access_expires_at: Option<u64>,
}

impl Store {
    pub(crate) fn personal_record(&self) -> Result<Option<PersonalRecord>, StoreError> {
        let row = self
            .conn()
            .query_row(
                "SELECT origin, account_id, personal_vault_id, device_name, private_material,
                    enrollment_request, recovery_saved, recovery_confirmed,
                    enrollment_attempted, access_expires_at
             FROM personal_server WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        SecretVec::new(row.get(4)?),
                        row.get::<_, Option<Vec<u8>>>(5)?.map(SecretVec::new),
                        row.get::<_, bool>(6)?,
                        row.get::<_, bool>(7)?,
                        row.get::<_, bool>(8)?,
                        row.get::<_, Option<i64>>(9)?.map(|value| value as u64),
                    ))
                },
            )
            .optional()?;
        row.map(
            |(
                origin,
                account,
                vault,
                device_name,
                private_material,
                enrollment_request,
                recovery_saved,
                recovery_confirmed,
                enrollment_attempted,
                access_expires_at,
            )| {
                Ok(PersonalRecord {
                    origin,
                    account_id: uuid_from(&account)?,
                    personal_vault_id: uuid_from(&vault)?,
                    device_name,
                    private_material,
                    enrollment_request,
                    recovery_saved,
                    recovery_confirmed,
                    enrollment_attempted,
                    access_expires_at,
                })
            },
        )
        .transpose()
    }

    pub(crate) fn insert_personal_record(&self, record: &PersonalRecord) -> Result<(), StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let transaction = conn.transaction()?;
        transaction.execute(
            "INSERT INTO personal_server (singleton, origin, account_id, personal_vault_id,
                device_name, private_material, enrollment_request) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![record.origin, record.account_id.as_bytes().as_slice(),
                record.personal_vault_id.as_bytes().as_slice(), record.device_name,
                record.private_material.as_bytes(), record.enrollment_request.as_ref().map(SecretVec::as_bytes)],
        )?;
        let material = record.private_material.as_bytes();
        if material.len() != 225 || material[0] != 1 {
            return Err(StoreError::InvalidIdentifier);
        }
        transaction.execute("INSERT INTO device_key_pair (singleton, signing, kem, created_at) VALUES (1, ?1, ?2, ?3)",
            params![&material[1..33], &material[33..65], scoplen_model::system_time_millis()? as i64])?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn save_personal_recovery(&self) -> Result<bool, StoreError> {
        Ok(self
            .conn()
            .execute("UPDATE personal_server SET recovery_saved = 1 WHERE singleton = 1", [])?
            == 1)
    }

    pub(crate) fn confirm_personal_recovery(&self) -> Result<bool, StoreError> {
        Ok(self.conn().execute("UPDATE personal_server SET recovery_confirmed = 1 WHERE singleton = 1 AND recovery_saved = 1", [])? == 1)
    }

    pub(crate) fn claim_personal_enrollment(&self) -> Result<bool, StoreError> {
        // A crash after this commit must recover by authentication, never by redeeming again.
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "UPDATE personal_server SET enrollment_attempted = 1
             WHERE singleton = 1 AND recovery_confirmed = 1 AND enrollment_attempted = 0",
            [],
        )? == 1)
    }

    pub(crate) fn release_unsent_personal_enrollment(&self) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE personal_server SET enrollment_attempted = 0
            WHERE singleton = 1 AND enrollment_attempted = 1 AND access_token IS NULL",
            [],
        )?;
        Ok(())
    }

    pub(crate) fn clear_personal_tokens(&self) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE personal_server SET access_token = NULL, refresh_token = NULL,
            access_expires_at = NULL, refresh_expires_at = NULL WHERE singleton = 1",
            [],
        )?;
        Ok(())
    }

    pub(crate) fn save_personal_tokens(
        &self,
        access: &[u8],
        refresh: &[u8],
        access_expires_at: u64,
        refresh_expires_at: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE personal_server SET access_token = ?1, refresh_token = ?2, enrollment_request = NULL,
                access_expires_at = ?3, refresh_expires_at = ?4 WHERE singleton = 1",
            params![
                access,
                refresh,
                access_expires_at.min(i64::MAX as u64) as i64,
                refresh_expires_at.min(i64::MAX as u64) as i64
            ],
        )?;
        Ok(())
    }
}
