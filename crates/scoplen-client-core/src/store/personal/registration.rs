// SPDX-License-Identifier: Apache-2.0
//! Exact D-128 pending bytes. These records never authorize authentication or sync.

use rusqlite::{OptionalExtension as _, TransactionBehavior, params};
use scoplen_crypto::SecretVec;

use super::{Store, StoreError};

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RegistrationRecord {
    pub payload: SecretVec,
    pub account_signature: [u8; 64],
    pub private_material: SecretVec,
    pub recovery_saved: bool,
    pub recovery_confirmed: bool,
    // 0: never handed to a sender, 1: may have committed, 2: exact historical confirmation.
    pub phase: i64,
    pub confirmation: Option<SecretVec>,
    pub dispatch_generation: i64,
    pub unchanged_generation: i64,
    pub retry_not_before_ms: i64,
}

impl std::fmt::Debug for RegistrationRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RegistrationRecord([REDACTED])")
    }
}

impl Store {
    pub(crate) fn registration_available(&self) -> Result<bool, StoreError> {
        Ok(self.conn().query_row(
            "SELECT NOT EXISTS (SELECT 1 FROM personal_server)
                AND NOT EXISTS (SELECT 1 FROM personal_admission)
                AND NOT EXISTS (SELECT 1 FROM personal_pairing)
                AND NOT EXISTS (SELECT 1 FROM personal_pairing_device)
                AND NOT EXISTS (SELECT 1 FROM personal_pairing_attempts)
                AND NOT EXISTS (SELECT 1 FROM device_key_pair)
                AND NOT EXISTS (SELECT 1 FROM personal_registration)
                AND NOT EXISTS (SELECT 1 FROM personal_password_login)",
            [],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn pending_registration(&self) -> Result<Option<RegistrationRecord>, StoreError> {
        Ok(self.conn().query_row(
            "SELECT
                CASE WHEN length(payload) BETWEEN 1 AND 262144 THEN payload END,
                CASE WHEN length(account_signature)=64 THEN account_signature END,
                CASE WHEN length(private_material)=225 THEN private_material END,
                recovery_saved,recovery_confirmed,phase,
                CASE WHEN length(confirmation) BETWEEN 1 AND 1024 THEN confirmation END,
                length(payload),length(account_signature),length(private_material),length(confirmation),
                dispatch_generation,unchanged_generation,retry_not_before_ms
             FROM personal_registration WHERE singleton=1",
            [],
            |row| {
                if !(1..=262_144).contains(&row.get::<_, i64>(7)?)
                    || row.get::<_, i64>(8)? != 64 || row.get::<_, i64>(9)? != 225
                    || row.get::<_, Option<i64>>(10)?.is_some_and(|n| !(1..=1024).contains(&n))
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                let signature: Vec<u8> = row.get(1)?;
                Ok(RegistrationRecord {
                    payload: SecretVec::new(row.get(0)?),
                    account_signature: signature.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    private_material: SecretVec::new(row.get(2)?),
                    recovery_saved: row.get(3)?, recovery_confirmed: row.get(4)?,
                    phase: row.get(5)?, confirmation: row.get::<_, Option<Vec<u8>>>(6)?.map(SecretVec::new),
                    dispatch_generation: row.get(11)?, unchanged_generation: row.get(12)?,
                    retry_not_before_ms: row.get(13)?,
                })
            },
        ).optional()?)
    }

    pub(crate) fn insert_registration(
        &self,
        record: &RegistrationRecord,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO personal_registration(singleton,payload,account_signature,private_material)
             VALUES(1,?1,?2,?3)",
            params![record.payload.as_bytes(), record.account_signature.as_slice(), record.private_material.as_bytes()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn update_registration(
        &self,
        previous: &RegistrationRecord,
        saved: bool,
        confirmed: bool,
        phase: i64,
        confirmation: Option<&[u8]>,
    ) -> Result<bool, StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let dispatch_generation = if phase == 1 {
            previous.dispatch_generation.checked_add(1).ok_or(rusqlite::Error::InvalidQuery)?
        } else {
            previous.dispatch_generation
        };
        let changed = tx.execute(
            "UPDATE personal_registration SET recovery_saved=?1,recovery_confirmed=?2,phase=?3,confirmation=?4,
                dispatch_generation=?12
             WHERE singleton=1 AND payload=?5 AND account_signature=?6 AND private_material=?7
                AND recovery_saved=?8 AND recovery_confirmed=?9 AND phase=?10 AND confirmation IS ?11
                AND dispatch_generation=?13 AND unchanged_generation=?14 AND retry_not_before_ms=?15",
            params![saved,confirmed,phase,confirmation,previous.payload.as_bytes(),
                previous.account_signature.as_slice(),previous.private_material.as_bytes(),
                previous.recovery_saved,previous.recovery_confirmed,previous.phase,
                previous.confirmation.as_ref().map(SecretVec::as_bytes),dispatch_generation,
                previous.dispatch_generation,previous.unchanged_generation,previous.retry_not_before_ms],
        )?;
        tx.commit()?;
        Ok(changed == 1)
    }

    pub(crate) fn registration_unchanged(
        &self,
        previous: &RegistrationRecord,
        retry_not_before_ms: i64,
    ) -> Result<bool, StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "UPDATE personal_registration SET unchanged_generation=dispatch_generation,retry_not_before_ms=?1
             WHERE singleton=1 AND phase=1 AND dispatch_generation=?2 AND unchanged_generation=?3
                AND payload=?4 AND account_signature=?5 AND private_material=?6
                AND retry_not_before_ms=?7 AND confirmation IS NULL",
            params![retry_not_before_ms,previous.dispatch_generation,previous.unchanged_generation,
                previous.payload.as_bytes(),previous.account_signature.as_slice(),previous.private_material.as_bytes(),
                previous.retry_not_before_ms],
        )?;
        tx.commit()?;
        Ok(changed == 1)
    }

    pub(crate) fn cancel_registration(
        &self,
        previous: &RegistrationRecord,
    ) -> Result<bool, StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "DELETE FROM personal_registration WHERE singleton=1 AND phase=0
                AND payload=?1 AND account_signature=?2 AND private_material=?3",
            params![
                previous.payload.as_bytes(),
                previous.account_signature.as_slice(),
                previous.private_material.as_bytes()
            ],
        )?;
        tx.commit()?;
        Ok(changed == 1)
    }
}
