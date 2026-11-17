// SPDX-License-Identifier: Apache-2.0
//! One protected password replacement in its original installed Account store.

use rusqlite::{OptionalExtension as _, TransactionBehavior, params};
use scoplen_crypto::{SecretBytes, SecretVec};

use super::{Store, StoreError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PasswordChangeRecord {
    pub payload: SecretVec,
    pub account_signature: [u8; 64],
    pub snapshot: SecretVec,
    pub signing_public: [u8; 32],
    pub kem_public: [u8; 32],
    pub certificate: Vec<u8>,
    pub token: Option<SecretBytes<32>>,
    pub expires_at_ms: u64,
    pub phase: i64,
    pub confirmation: Option<SecretVec>,
    pub dispatch_generation: i64,
    pub unchanged_generation: i64,
    pub retry_not_before_ms: i64,
    pub restart_required: bool,
}

impl Store {
    pub(crate) fn pending_password_change(
        &self,
    ) -> Result<Option<PasswordChangeRecord>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT CASE WHEN length(payload) BETWEEN 1 AND 8192 THEN payload END,
                CASE WHEN length(account_signature)=64 THEN account_signature END,
                CASE WHEN length(snapshot) BETWEEN 1 AND 9437184 THEN snapshot END,
                CASE WHEN length(signing_public)=32 THEN signing_public END,
                CASE WHEN length(kem_public)=32 THEN kem_public END,
                CASE WHEN length(certificate) BETWEEN 1 AND 65536 THEN certificate END,
                CASE WHEN length(token)=32 THEN token END,expires_at_ms,phase,
                CASE WHEN length(confirmation) BETWEEN 1 AND 1024 THEN confirmation END,
                dispatch_generation,unchanged_generation,retry_not_before_ms,restart_required
             FROM personal_password_change WHERE singleton=1",
                [],
                |r| {
                    let fixed = |i| r.get::<_, Vec<u8>>(i);
                    let token = r.get::<_, Option<Vec<u8>>>(6)?.map(SecretVec::new);
                    Ok(PasswordChangeRecord {
                        payload: SecretVec::new(r.get(0)?),
                        account_signature: fixed(1)?
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        snapshot: SecretVec::new(r.get(2)?),
                        signing_public: fixed(3)?
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        kem_public: fixed(4)?
                            .try_into()
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        certificate: r.get(5)?,
                        token: token
                            .map(|v| {
                                v.as_bytes()
                                    .try_into()
                                    .map(SecretBytes::new)
                                    .map_err(|_| rusqlite::Error::InvalidQuery)
                            })
                            .transpose()?,
                        expires_at_ms: u64::try_from(r.get::<_, i64>(7)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        phase: r.get(8)?,
                        confirmation: r.get::<_, Option<Vec<u8>>>(9)?.map(SecretVec::new),
                        dispatch_generation: r.get(10)?,
                        unchanged_generation: r.get(11)?,
                        retry_not_before_ms: r.get(12)?,
                        restart_required: r.get(13)?,
                    })
                },
            )
            .optional()?)
    }

    pub(crate) fn credential_generation_floor(&self) -> Result<Option<u64>, StoreError> {
        let bytes = self
            .conn()
            .query_row(
                "SELECT generation FROM account_credential_floor WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        bytes
            .map(|bytes| {
                bytes.try_into().map(u64::from_be_bytes).map_err(|_| StoreError::InvalidIdentifier)
            })
            .transpose()
    }

    pub(crate) fn observe_credential_generation(&self, generation: u64) -> Result<(), StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        advance_floor(&tx, generation)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn insert_password_change(
        &self,
        r: &PasswordChangeRecord,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO personal_password_change(singleton,payload,account_signature,snapshot,signing_public,kem_public,certificate,token,expires_at_ms) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8)",
            params![r.payload.as_bytes(),r.account_signature.as_slice(),r.snapshot.as_bytes(),r.signing_public.as_slice(),r.kem_public.as_slice(),r.certificate,r.token.as_ref().map(|v|v.as_ref()),i64::try_from(r.expires_at_ms).map_err(|_|StoreError::InvalidIdentifier)?])?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn update_password_change(
        &self,
        previous: &PasswordChangeRecord,
        next: &PasswordChangeRecord,
        committed_generation: Option<u64>,
    ) -> Result<bool, StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed=tx.execute("UPDATE personal_password_change SET phase=?1,confirmation=?2,dispatch_generation=?3,unchanged_generation=?4,retry_not_before_ms=?5,restart_required=?6,token=?7
            WHERE singleton=1 AND payload=?8 AND account_signature=?9 AND phase=?10 AND confirmation IS ?11 AND dispatch_generation=?12 AND unchanged_generation=?13 AND retry_not_before_ms=?14 AND restart_required=?15 AND token IS ?16",
            params![next.phase,next.confirmation.as_ref().map(SecretVec::as_bytes),next.dispatch_generation,next.unchanged_generation,next.retry_not_before_ms,next.restart_required,next.token.as_ref().map(|v|v.as_ref()),previous.payload.as_bytes(),previous.account_signature.as_slice(),previous.phase,previous.confirmation.as_ref().map(SecretVec::as_bytes),previous.dispatch_generation,previous.unchanged_generation,previous.retry_not_before_ms,previous.restart_required,previous.token.as_ref().map(|v|v.as_ref())])?;
        if changed == 1
            && let Some(generation) = committed_generation
        {
            advance_floor(&tx, generation)?;
        }
        tx.commit()?;
        Ok(changed == 1)
    }

    pub(crate) fn discard_password_change(
        &self,
        previous: &PasswordChangeRecord,
    ) -> Result<bool, StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed=tx.execute("DELETE FROM personal_password_change WHERE singleton=1 AND (phase=0 OR phase=2 OR (phase=1 AND dispatch_generation=unchanged_generation)) AND payload=?1 AND account_signature=?2 AND phase=?3 AND dispatch_generation=?4 AND unchanged_generation=?5",
            params![previous.payload.as_bytes(),previous.account_signature.as_slice(),previous.phase,previous.dispatch_generation,previous.unchanged_generation])?;
        tx.commit()?;
        Ok(changed == 1)
    }
}

fn advance_floor(tx: &rusqlite::Transaction<'_>, generation: u64) -> Result<(), StoreError> {
    if generation == 0 {
        return Err(StoreError::InvalidIdentifier);
    }
    let bytes = generation.to_be_bytes();
    tx.execute(
        "UPDATE account_credential_floor SET generation=?1 WHERE singleton=1 AND generation<?1",
        [bytes.as_slice()],
    )?;
    tx.execute("INSERT INTO account_credential_floor(singleton,generation) SELECT 1,?1 WHERE NOT EXISTS(SELECT 1 FROM account_credential_floor)",[bytes.as_slice()])?;
    Ok(())
}
