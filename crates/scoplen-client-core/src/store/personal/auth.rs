// SPDX-License-Identifier: Apache-2.0
//! Durable native session claims. No database lock is held across network I/O.

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use scoplen_crypto::SecretVec;

use super::{PersonalRecord, Store, StoreError};

pub(crate) struct PersonalTokens {
    pub access: SecretVec,
    pub refresh: SecretVec,
    pub access_expires_at: u64,
    pub refresh_expires_at: u64,
    pub scope: String,
}

pub(crate) struct PersonalRefreshClaim {
    pub generation: i64,
    pub previous: PersonalTokens,
}

impl Store {
    pub(crate) fn personal_session_current(
        &self,
        identity: &PersonalRecord,
        access: &SecretVec,
        now: u64,
    ) -> Result<bool, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Ok(false);
        }
        Ok(self.conn().query_row(
            "SELECT EXISTS (SELECT 1 FROM personal_server WHERE singleton = 1
            AND auth_generation = ?1 AND access_token = ?2 AND access_expires_at > ?3
            AND refresh_claimed = 0)",
            params![identity.auth_generation, access.as_bytes(), now.min(i64::MAX as u64) as i64],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn invalidate_personal_session(
        &self,
        identity: &PersonalRecord,
        access: &SecretVec,
    ) -> Result<(), StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Ok(());
        }
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute(
            "UPDATE personal_server SET access_token = NULL, refresh_token = NULL,
            access_expires_at = NULL, refresh_expires_at = NULL, auth_scope = NULL,
            refresh_claimed = 0, auth_generation = auth_generation + 1, refresh_retry_at = NULL
            WHERE singleton = 1 AND auth_generation = ?1 AND access_token = ?2",
            params![identity.auth_generation, access.as_bytes()],
        )?;
        self.personal_changed();
        Ok(())
    }

    /// An explicit fresh challenge supersedes unfinished requests from another process.
    pub(crate) fn begin_personal_authentication(
        &self,
        identity: &PersonalRecord,
    ) -> Result<Option<i64>, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Ok(None);
        }
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let generation = conn.query_row(
            "UPDATE personal_server SET auth_generation = auth_generation + 1,
                access_token = NULL, refresh_token = NULL, access_expires_at = NULL,
                refresh_expires_at = NULL, auth_scope = NULL, refresh_claimed = 0, refresh_retry_at = NULL
             WHERE singleton = 1 AND auth_generation = ?1 AND origin = ?2
                AND account_id = ?3 AND private_material = ?4
                AND EXISTS (SELECT 1 FROM personal_admission a WHERE a.singleton=1 AND a.origin=personal_server.origin AND a.account_id=personal_server.account_id AND a.personal_vault_id=personal_server.personal_vault_id)
             RETURNING auth_generation",
            params![identity.auth_generation, identity.origin, identity.account_id.as_bytes().as_slice(),
                identity.private_material.as_bytes()],
            |row| row.get(0),
        ).optional()?;
        self.personal_changed();
        Ok(generation)
    }

    pub(crate) fn claim_personal_refresh(
        &self,
        identity: &PersonalRecord,
        now: u64,
    ) -> Result<Option<PersonalRefreshClaim>, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Ok(None);
        }
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = tx.query_row(
            "SELECT access_token, refresh_token, access_expires_at, refresh_expires_at, auth_scope
             FROM personal_server WHERE singleton = 1 AND auth_generation = ?1
                AND origin = ?2 AND account_id = ?3 AND private_material = ?4
                AND EXISTS (SELECT 1 FROM personal_admission a WHERE a.singleton=1 AND a.origin=personal_server.origin AND a.account_id=personal_server.account_id AND a.personal_vault_id=personal_server.personal_vault_id) AND refresh_claimed = 0
                AND refresh_expires_at > ?5 AND length(refresh_token) BETWEEN 1 AND 2048
                AND length(access_token) BETWEEN 1 AND 4096 AND auth_scope IS NOT NULL
                AND (refresh_retry_at IS NULL OR refresh_retry_at <= ?5)",
            params![identity.auth_generation, identity.origin, identity.account_id.as_bytes().as_slice(),
                identity.private_material.as_bytes(), now.min(i64::MAX as u64) as i64],
            |row| Ok(PersonalTokens {
                access: SecretVec::new(row.get(0)?), refresh: SecretVec::new(row.get(1)?),
                access_expires_at: row.get::<_, i64>(2)? as u64,
                refresh_expires_at: row.get::<_, i64>(3)? as u64, scope: row.get(4)?,
            }),
        ).optional()?;
        let Some(previous) = previous else {
            return Ok(None);
        };
        tx.execute(
            "UPDATE personal_server SET auth_generation = auth_generation + 1,
                refresh_claimed = 1, access_token = NULL, refresh_token = NULL,
                access_expires_at = NULL WHERE singleton = 1",
            [],
        )?;
        tx.commit()?;
        self.personal_changed();
        Ok(Some(PersonalRefreshClaim { generation: identity.auth_generation + 1, previous }))
    }

    /// The claim is consumed on completion, including a verified no-change restoration.
    pub(crate) fn finish_personal_session(
        &self,
        identity: &PersonalRecord,
        generation: i64,
        refresh_claimed: bool,
        tokens: &PersonalTokens,
        retry_at: Option<u64>,
    ) -> Result<bool, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Ok(false);
        }
        let material = identity.private_material.as_bytes();
        let (signing, kem) = identity.device_secrets()?;
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let changed = conn.execute(
            "UPDATE personal_server SET access_token = ?1, refresh_token = ?2,
                access_expires_at = ?3, refresh_expires_at = ?4, auth_scope = ?5,
                refresh_claimed = 0, session_established = 1, auth_generation = auth_generation + 1,
                refresh_retry_at = ?14
             WHERE singleton = 1 AND auth_generation = ?6 AND refresh_claimed = ?7
                AND origin = ?8 AND account_id = ?9 AND personal_vault_id = ?10
                AND private_material = ?11
                AND EXISTS (SELECT 1 FROM personal_admission a WHERE a.singleton=1 AND a.origin=personal_server.origin AND a.account_id=personal_server.account_id AND a.personal_vault_id=personal_server.personal_vault_id)
                AND EXISTS (SELECT 1 FROM device_key_pair WHERE singleton = 1 AND signing = ?12 AND kem = ?13)",
            params![tokens.access.as_bytes(), tokens.refresh.as_bytes(),
                tokens.access_expires_at.min(i64::MAX as u64) as i64,
                tokens.refresh_expires_at.min(i64::MAX as u64) as i64, tokens.scope,
                generation, refresh_claimed, identity.origin, identity.account_id.as_bytes().as_slice(),
                identity.personal_vault_id.as_bytes().as_slice(), material,
                signing, kem, retry_at.map(|value| value.min(i64::MAX as u64) as i64)],
        )? == 1;
        self.personal_changed();
        Ok(changed)
    }
}
