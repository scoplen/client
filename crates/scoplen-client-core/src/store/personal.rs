// SPDX-License-Identifier: Apache-2.0
//! Durable pending identity and credentials, inside the SQLCipher boundary.

use rusqlite::{OptionalExtension, params};
use scoplen_crypto::{MAX_DEVICE_ACCESS_TOKEN_BYTES, SecretVec};
use uuid::Uuid;

use super::{Store, StoreError, uuid_from};

mod account;
mod admission;
mod auth;
pub(crate) use account::PersonalAccountRecord;
pub(crate) use auth::{PersonalRefreshClaim, PersonalTokens};

#[derive(Debug)]
pub(crate) struct PersonalRecord {
    pub origin: String,
    pub account_id: Uuid,
    pub personal_vault_id: Uuid,
    pub device_name: String,
    pub private_material: SecretVec,
    pub recovery_saved: bool,
    pub recovery_confirmed: bool,
    pub access_expires_at: Option<u64>,
    pub refresh_expires_at: Option<u64>,
    pub auth_generation: i64,
    pub auth_scope: Option<String>,
    pub refresh_available: bool,
    pub refresh_retry_at: Option<u64>,
    pub admitted: bool,
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
        self.admitted
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
             AND EXISTS (SELECT 1 FROM personal_admission a WHERE a.singleton=1 AND a.origin=personal_server.origin AND a.account_id=personal_server.account_id AND a.personal_vault_id=personal_server.personal_vault_id)
             AND access_expires_at > ?1 AND refresh_claimed = 0
             AND length(access_token) BETWEEN 1 AND ?2",
                params![now.min(i64::MAX as u64) as i64, MAX_DEVICE_ACCESS_TOKEN_BYTES as i64],
                |row| Ok(SecretVec::new(row.get(0)?)),
            )
            .optional()?)
    }

    pub(crate) fn personal_sync_record(&self) -> Result<Option<PersonalSyncRecord>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT generation,
                CASE WHEN length(CAST(session AS BLOB)) BETWEEN 1 AND 4194304 THEN session END,
                CASE WHEN length(CAST(account_keys AS BLOB)) BETWEEN 1 AND 4194304 THEN account_keys END,
                CASE WHEN length(CAST(vault_keys AS BLOB)) BETWEEN 1 AND 4194304 THEN vault_keys END,
                length(CAST(session AS BLOB)), length(CAST(account_keys AS BLOB)),
                length(CAST(vault_keys AS BLOB))
             FROM personal_sync WHERE singleton = 1",
                [],
                |row| {
                    for column in 4..=6 {
                        if !(1..=4 * 1024 * 1024).contains(&row.get::<_, i64>(column)?) {
                            return Err(rusqlite::Error::InvalidQuery);
                        }
                    }
                    Ok(PersonalSyncRecord {
                        generation: row.get(0)?,
                        session: SecretVec::new(row.get(1)?),
                        account_keys: SecretVec::new(row.get(2)?),
                        vault_keys: SecretVec::new(row.get(3)?),
                    })
                },
            )
            .optional()?)
    }

    pub(crate) fn save_personal_sync(
        &self,
        identity: &PersonalRecord,
        access: &SecretVec,
        expected_generation: Option<i64>,
        snapshot: &PersonalSyncRecord,
        now: u64,
    ) -> Result<bool, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Ok(false);
        }
        let (signing, kem) = identity.device_secrets()?;
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction()?;
        let matches: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM personal_server WHERE singleton = 1
                AND origin = ?1 AND account_id = ?2 AND personal_vault_id = ?3
                AND private_material = ?4
                AND access_token = ?5 AND access_expires_at > ?6
                AND auth_generation=?9 AND refresh_claimed=0
                AND EXISTS (SELECT 1 FROM personal_admission a WHERE a.singleton=1 AND a.origin=personal_server.origin AND a.account_id=personal_server.account_id AND a.personal_vault_id=personal_server.personal_vault_id))
                AND EXISTS (SELECT 1 FROM device_key_pair WHERE singleton = 1
                    AND signing = ?7 AND kem = ?8)",
            params![
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                identity.personal_vault_id.as_bytes().as_slice(),
                identity.private_material.as_bytes(),
                access.as_bytes(),
                now.min(i64::MAX as u64) as i64,
                signing,
                kem,
                identity.auth_generation
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

    /// Active metadata and bounded private material; archived entry payloads stay in SQLite.
    pub(crate) fn personal_record(&self) -> Result<Option<PersonalRecord>, StoreError> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT origin, account_id, personal_vault_id, device_name,
                CASE WHEN length(private_material)<=225 THEN private_material ELSE X'' END,
                recovery_saved, recovery_confirmed, access_expires_at, refresh_expires_at,
                auth_generation, auth_scope,
                refresh_claimed = 0 AND length(refresh_token) BETWEEN 1 AND 2048,
                refresh_retry_at
             FROM personal_server WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        SecretVec::new(row.get(4)?),
                        row.get::<_, bool>(5)?,
                        row.get::<_, bool>(6)?,
                        row.get::<_, Option<i64>>(7)?.map(|value| value as u64),
                        row.get::<_, Option<i64>>(8)?.map(|value| value as u64),
                        row.get::<_, i64>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, Option<bool>>(11)?.unwrap_or(false),
                        row.get::<_, Option<i64>>(12)?.map(|value| value as u64),
                    ))
                },
            )
            .optional()?;
        drop(conn);
        row.map(
            |(
                origin,
                account,
                vault,
                device_name,
                private_material,
                recovery_saved,
                recovery_confirmed,
                access_expires_at,
                refresh_expires_at,
                auth_generation,
                auth_scope,
                refresh_available,
                refresh_retry_at,
            )| {
                let mut identity = PersonalRecord {
                    origin,
                    account_id: uuid_from(&account)?,
                    personal_vault_id: uuid_from(&vault)?,
                    device_name,
                    private_material,
                    recovery_saved,
                    recovery_confirmed,
                    access_expires_at,
                    refresh_expires_at,
                    auth_generation,
                    auth_scope,
                    refresh_available,
                    refresh_retry_at,
                    admitted: false,
                };
                identity.admitted = self.personal_admission(&identity)?.is_some();
                Ok(identity)
            },
        )
        .transpose()
    }

    pub(crate) fn has_archived_personal_entry(&self) -> Result<bool, StoreError> {
        Ok(self.conn().query_row(
            "SELECT EXISTS (SELECT 1 FROM personal_pairing WHERE singleton=1)",
            [],
            |row| row.get(0),
        )?)
    }

    #[cfg(test)]
    pub(crate) fn insert_personal_record(&self, record: &PersonalRecord) -> Result<(), StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let transaction = conn.transaction()?;
        transaction.execute(
            "INSERT INTO personal_server (singleton, origin, account_id, personal_vault_id,
                device_name, private_material) VALUES (1, ?1, ?2, ?3, ?4, ?5)",
            params![
                record.origin,
                record.account_id.as_bytes().as_slice(),
                record.personal_vault_id.as_bytes().as_slice(),
                record.device_name,
                record.private_material.as_bytes()
            ],
        )?;
        let (signing, kem) = record.device_secrets()?;
        transaction.execute("INSERT INTO device_key_pair (singleton, signing, kem, created_at) VALUES (1, ?1, ?2, ?3)",
            params![signing, kem, scoplen_model::system_time_millis()? as i64])?;
        transaction.commit()?;
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
