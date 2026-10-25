// SPDX-License-Identifier: Apache-2.0
//! Durable next-Device business bytes, independent of registration and current authority.

use rusqlite::{OptionalExtension as _, TransactionBehavior, params};
use scoplen_crypto::{SecretBytes, SecretVec};

use super::{RegistrationRecord, Store, StoreError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PasswordLoginRecord {
    pub entry: RegistrationRecord,
    pub snapshot: SecretVec,
    pub token: SecretBytes<32>,
    pub expires_at_ms: u64,
    pub restart_required: bool,
}

impl Store {
    pub(crate) fn pending_password_login(&self) -> Result<Option<PasswordLoginRecord>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT CASE WHEN length(payload) BETWEEN 1 AND 4325376 THEN payload END,
                CASE WHEN length(account_signature)=64 THEN account_signature END,
                CASE WHEN length(private_material)=193 THEN private_material END,
                phase,CASE WHEN length(confirmation) BETWEEN 1 AND 1024 THEN confirmation END,
                dispatch_generation,unchanged_generation,retry_not_before_ms,
                CASE WHEN length(snapshot) BETWEEN 1 AND 9437184 THEN snapshot END,
                CASE WHEN length(token)=32 THEN token END,expires_at_ms,restart_required
             FROM personal_password_login WHERE singleton=1",
                [],
                |row| {
                    let signature: Vec<u8> = row.get(1)?;
                    let token = SecretVec::new(row.get(9)?);
                    let expiry: i64 = row.get(10)?;
                    Ok(PasswordLoginRecord {
                        entry: RegistrationRecord {
                            payload: SecretVec::new(row.get(0)?),
                            account_signature: signature
                                .try_into()
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                            private_material: SecretVec::new(row.get(2)?),
                            recovery_saved: false,
                            recovery_confirmed: false,
                            phase: row.get(3)?,
                            confirmation: row.get::<_, Option<Vec<u8>>>(4)?.map(SecretVec::new),
                            dispatch_generation: row.get(5)?,
                            unchanged_generation: row.get(6)?,
                            retry_not_before_ms: row.get(7)?,
                        },
                        snapshot: SecretVec::new(row.get(8)?),
                        token: SecretBytes::new(
                            token
                                .as_bytes()
                                .try_into()
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        ),
                        expires_at_ms: u64::try_from(expiry)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        restart_required: row.get(11)?,
                    })
                },
            )
            .optional()?)
    }

    pub(crate) fn insert_password_login(
        &self,
        record: &PasswordLoginRecord,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO personal_password_login(singleton,payload,account_signature,private_material,snapshot,token,expires_at_ms) VALUES(1,?1,?2,?3,?4,?5,?6)",
            params![record.entry.payload.as_bytes(), record.entry.account_signature.as_slice(),record.entry.private_material.as_bytes(),record.snapshot.as_bytes(),record.token.as_ref(),i64::try_from(record.expires_at_ms).map_err(|_| StoreError::InvalidIdentifier)?])?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn update_password_login(
        &self,
        previous: &PasswordLoginRecord,
        phase: i64,
        confirmation: Option<&[u8]>,
        unchanged: bool,
        retry_at: i64,
        restart_required: bool,
    ) -> Result<bool, StoreError> {
        let e = &previous.entry;
        let dispatch = if phase == 1 && !unchanged {
            e.dispatch_generation.checked_add(1).ok_or(StoreError::InvalidIdentifier)?
        } else {
            e.dispatch_generation
        };
        let expires_at =
            i64::try_from(previous.expires_at_ms).map_err(|_| StoreError::InvalidIdentifier)?;
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed=tx.execute("UPDATE personal_password_login SET phase=?1,confirmation=?2,dispatch_generation=?3,unchanged_generation=?4,retry_not_before_ms=?5,restart_required=?17 WHERE singleton=1 AND payload=?6 AND account_signature=?7 AND private_material=?8 AND phase=?9 AND confirmation IS ?10 AND dispatch_generation=?11 AND unchanged_generation=?12 AND retry_not_before_ms=?13 AND snapshot=?14 AND token=?15 AND expires_at_ms=?16",
            params![phase,confirmation,dispatch,if unchanged { dispatch } else { e.unchanged_generation },retry_at,e.payload.as_bytes(),e.account_signature.as_slice(),e.private_material.as_bytes(),e.phase,e.confirmation.as_ref().map(SecretVec::as_bytes),e.dispatch_generation,e.unchanged_generation,e.retry_not_before_ms,previous.snapshot.as_bytes(),previous.token.as_ref(),expires_at,restart_required || previous.restart_required])?;
        tx.commit()?;
        Ok(changed == 1)
    }

    pub(crate) fn cancel_password_login_record(
        &self,
        previous: &PasswordLoginRecord,
    ) -> Result<bool, StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let e = &previous.entry;
        let changed=tx.execute("DELETE FROM personal_password_login WHERE singleton=1 AND (phase=0 OR (phase=1 AND dispatch_generation=unchanged_generation)) AND payload=?1 AND account_signature=?2 AND private_material=?3 AND dispatch_generation=?4 AND unchanged_generation=?5",
            params![e.payload.as_bytes(),e.account_signature.as_slice(),e.private_material.as_bytes(),e.dispatch_generation,e.unchanged_generation])?;
        tx.commit()?;
        Ok(changed == 1)
    }

    pub(crate) fn login_bootstrap(&self) -> Result<Option<SecretVec>, StoreError> {
        Ok(self.conn().query_row("SELECT CASE WHEN length(snapshot) BETWEEN 1 AND 9437184 THEN snapshot END FROM password_login_bootstrap WHERE singleton=1",[],|r|Ok(SecretVec::new(r.get(0)?))).optional()?)
    }

    pub(crate) fn retain_login_bootstrap(&self, snapshot: &SecretVec) -> Result<(), StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = tx
            .query_row("SELECT CASE WHEN length(snapshot) BETWEEN 1 AND 9437184 THEN snapshot END FROM password_login_bootstrap WHERE singleton=1", [], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()?
        {
            if existing != snapshot.as_bytes() {
                return Err(StoreError::AccountContext);
            }
        } else {
            tx.execute(
                "INSERT INTO password_login_bootstrap(singleton,snapshot) VALUES(1,?1)",
                [snapshot.as_bytes()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}
