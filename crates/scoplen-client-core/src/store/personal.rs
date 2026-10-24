// SPDX-License-Identifier: Apache-2.0
//! Durable pending identity and credentials, inside the SQLCipher boundary.

use rusqlite::{OptionalExtension, params};
use scoplen_crypto::{MAX_DEVICE_ACCESS_TOKEN_BYTES, SecretVec};
use uuid::Uuid;

use super::{Store, StoreError, uuid_from};

mod account;
mod auth;
mod pairing;
pub(crate) use account::PersonalAccountRecord;
pub(crate) use auth::{PersonalRefreshClaim, PersonalTokens};
pub(crate) use pairing::{PairingDeviceRecord, PairingRecord};

#[derive(Debug)]
pub(crate) struct PersonalRecord {
    pub origin: String,
    pub account_id: Uuid,
    pub personal_vault_id: Uuid,
    pub device_name: String,
    pub private_material: SecretVec,
    pub enrollment_request: Option<SecretVec>,
    pub paired_handoff: Option<SecretVec>,
    pub recovery_saved: bool,
    pub recovery_confirmed: bool,
    pub enrollment_attempted: bool,
    pub access_expires_at: Option<u64>,
    pub refresh_expires_at: Option<u64>,
    pub auth_generation: i64,
    pub auth_scope: Option<String>,
    pub refresh_available: bool,
    pub session_established: bool,
    pub refresh_retry_at: Option<u64>,
}

impl PersonalRecord {
    pub fn device_secrets(&self) -> Result<(&[u8], &[u8]), StoreError> {
        let material = self.private_material.as_bytes();
        if !matches!((material.first(), material.len()), (Some(1), 225) | (Some(2), 193)) {
            return Err(StoreError::InvalidIdentifier);
        }
        Ok((&material[1..33], &material[33..65]))
    }

    pub fn authentication_allowed(&self) -> bool {
        self.enrollment_attempted || self.paired_handoff.is_some()
    }
}

pub(crate) struct PersonalSyncRecord {
    pub generation: i64,
    pub session: SecretVec,
    pub account_keys: SecretVec,
    pub vault_keys: SecretVec,
}

impl Store {
    pub(crate) fn personal_access_token(&self, now: u64) -> Result<Option<SecretVec>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT access_token FROM personal_server WHERE singleton = 1
             AND (enrollment_attempted = 1 OR paired_handoff IS NOT NULL)
             AND access_expires_at > ?1 AND refresh_claimed = 0
             AND length(access_token) BETWEEN 1 AND ?2",
                params![now.min(i64::MAX as u64) as i64, MAX_DEVICE_ACCESS_TOKEN_BYTES as i64],
                |row| Ok(SecretVec::new(row.get(0)?)),
            )
            .optional()?)
    }

    pub(crate) fn personal_sync_record(&self) -> Result<Option<PersonalSyncRecord>, StoreError> {
        Ok(self.conn().query_row(
            "SELECT generation, session, account_keys, vault_keys FROM personal_sync WHERE singleton = 1",
            [],
            |row| Ok(PersonalSyncRecord {
                generation: row.get(0)?,
                session: SecretVec::new(row.get(1)?),
                account_keys: SecretVec::new(row.get(2)?),
                vault_keys: SecretVec::new(row.get(3)?),
            }),
        ).optional()?)
    }

    pub(crate) fn save_personal_sync(
        &self,
        identity: &PersonalRecord,
        access: &SecretVec,
        expected_generation: Option<i64>,
        snapshot: &PersonalSyncRecord,
        now: u64,
    ) -> Result<bool, StoreError> {
        let (signing, kem) = identity.device_secrets()?;
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction()?;
        let matches: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM personal_server WHERE singleton = 1
                AND origin = ?1 AND account_id = ?2 AND personal_vault_id = ?3
                AND private_material = ?4 AND enrollment_request IS ?5 AND paired_handoff IS ?10
                AND access_token = ?6 AND access_expires_at > ?7
                AND (enrollment_attempted = 1 OR paired_handoff IS NOT NULL))
                AND EXISTS (SELECT 1 FROM device_key_pair WHERE singleton = 1
                    AND signing = ?8 AND kem = ?9)",
            params![
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                identity.personal_vault_id.as_bytes().as_slice(),
                identity.private_material.as_bytes(),
                identity.enrollment_request.as_ref().map(SecretVec::as_bytes),
                access.as_bytes(),
                now.min(i64::MAX as u64) as i64,
                signing,
                kem,
                identity.paired_handoff.as_ref().map(SecretVec::as_bytes)
            ],
            |row| row.get(0),
        )?;
        let generation: Option<i64> = tx
            .query_row("SELECT generation FROM personal_sync WHERE singleton = 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        if !matches || generation != expected_generation {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO personal_sync (singleton, generation, session, account_keys, vault_keys)
             VALUES (1, 1, ?1, ?2, ?3) ON CONFLICT (singleton) DO UPDATE SET
             generation = personal_sync.generation + 1, session = excluded.session,
             account_keys = excluded.account_keys, vault_keys = excluded.vault_keys",
            params![
                snapshot.session.as_bytes(),
                snapshot.account_keys.as_bytes(),
                snapshot.vault_keys.as_bytes()
            ],
        )?;
        tx.commit()?;
        self.personal_changed();
        Ok(true)
    }

    pub(crate) fn personal_record(&self) -> Result<Option<PersonalRecord>, StoreError> {
        let row = self
            .conn()
            .query_row(
                "SELECT origin, account_id, personal_vault_id, device_name, private_material,
                    enrollment_request, recovery_saved, recovery_confirmed,
                    enrollment_attempted, access_expires_at, refresh_expires_at,
                    auth_generation, auth_scope,
                    refresh_claimed = 0 AND length(refresh_token) BETWEEN 1 AND 2048,
                    session_established, refresh_retry_at, paired_handoff
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
                        row.get::<_, Option<i64>>(10)?.map(|value| value as u64),
                        row.get::<_, i64>(11)?,
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, Option<bool>>(13)?.unwrap_or(false),
                        row.get::<_, bool>(14)?,
                        row.get::<_, Option<i64>>(15)?.map(|value| value as u64),
                        row.get::<_, Option<Vec<u8>>>(16)?.map(SecretVec::new),
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
                refresh_expires_at,
                auth_generation,
                auth_scope,
                refresh_available,
                session_established,
                refresh_retry_at,
                paired_handoff,
            )| {
                Ok(PersonalRecord {
                    origin,
                    account_id: uuid_from(&account)?,
                    personal_vault_id: uuid_from(&vault)?,
                    device_name,
                    private_material,
                    enrollment_request,
                    paired_handoff,
                    recovery_saved,
                    recovery_confirmed,
                    enrollment_attempted,
                    access_expires_at,
                    refresh_expires_at,
                    auth_generation,
                    auth_scope,
                    refresh_available,
                    session_established,
                    refresh_retry_at,
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
        let (signing, kem) = record.device_secrets()?;
        transaction.execute("INSERT INTO device_key_pair (singleton, signing, kem, created_at) VALUES (1, ?1, ?2, ?3)",
            params![signing, kem, scoplen_model::system_time_millis()? as i64])?;
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

    #[cfg(test)]
    pub(crate) fn clear_personal_tokens(&self) -> Result<(), StoreError> {
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute(
            "UPDATE personal_server SET access_token = NULL, refresh_token = NULL,
            access_expires_at = NULL, refresh_expires_at = NULL, auth_scope = NULL,
            refresh_claimed = 0, auth_generation = auth_generation + 1 WHERE singleton = 1",
            [],
        )?;
        Ok(())
    }

    pub(crate) fn replace_personal_invitation(
        &self,
        expected: &SecretVec,
        replacement: &SecretVec,
    ) -> Result<bool, StoreError> {
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "UPDATE personal_server SET enrollment_request = ?1, enrollment_attempted = 0,
                auth_generation = auth_generation + 1
             WHERE singleton = 1 AND enrollment_attempted = 1 AND recovery_confirmed = 1
             AND enrollment_request = ?2 AND access_token IS NULL",
            params![replacement.as_bytes(), expected.as_bytes()],
        )? == 1)
    }

    #[cfg(test)]
    pub(crate) fn set_personal_session_metadata_for_test(
        &self,
        identity: &PersonalRecord,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE personal_server SET access_expires_at = ?1, refresh_expires_at = ?2,
                auth_scope = ?3, refresh_retry_at = ?4 WHERE singleton = 1",
            params![
                identity.access_expires_at.map(|value| value as i64),
                identity.refresh_expires_at.map(|value| value as i64),
                identity.auth_scope,
                identity.refresh_retry_at.map(|value| value as i64),
            ],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn save_personal_tokens(
        &self,
        access: &[u8],
        refresh: &[u8],
        access_expires_at: u64,
        refresh_expires_at: u64,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE personal_server SET access_token = ?1, refresh_token = ?2,
                access_expires_at = ?3, refresh_expires_at = ?4, auth_scope = ?5,
                refresh_claimed = 0, session_established = 1, auth_generation = auth_generation + 1
                WHERE singleton = 1",
            params![
                access,
                refresh,
                access_expires_at.min(i64::MAX as u64) as i64,
                refresh_expires_at.min(i64::MAX as u64) as i64,
                scoplen_api::auth::INITIAL_DEVICE_ACCESS_SCOPE,
            ],
        )?;
        self.personal_changed();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
