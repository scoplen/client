// SPDX-License-Identifier: Apache-2.0
//! Atomic local admission conversion and immutable Account/store ownership.

use rusqlite::{OptionalExtension as _, TransactionBehavior, params};
use scoplen_crypto::SecretVec;

use super::{PairingRecord, PersonalRecord, PersonalSyncRecord, Store, StoreError};

impl Store {
    pub(crate) fn personal_admission(
        &self,
        identity: &PersonalRecord,
    ) -> Result<Option<SecretVec>, StoreError> {
        let row = self
            .conn()
            .query_row(
                "SELECT origin, account_id, personal_vault_id, device_id, anchors
             FROM personal_admission WHERE singleton=1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        SecretVec::new(row.get(4)?),
                    ))
                },
            )
            .optional()?;
        row.map(|(origin, account, vault, device, anchors)| {
            if origin != identity.origin
                || account != identity.account_id.as_bytes()
                || vault != identity.personal_vault_id.as_bytes()
                || device != self.device_id().as_bytes()
            {
                return Err(StoreError::AccountContext);
            }
            Ok(anchors)
        })
        .transpose()
    }

    pub(crate) fn save_personal_admission(
        &self,
        identity: &PersonalRecord,
        anchors: &[u8],
        snapshot: Option<&PersonalSyncRecord>,
        pairing: Option<&PairingRecord>,
    ) -> Result<bool, StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (signing, kem) = identity.device_secrets()?;
        let changed = tx.execute(
            "INSERT INTO personal_admission
                (singleton, origin, account_id, personal_vault_id, device_id, anchors)
             SELECT 1, origin, account_id, personal_vault_id, ?1, ?2 FROM personal_server
             WHERE singleton=1 AND origin=?3 AND account_id=?4 AND personal_vault_id=?5
                AND NOT EXISTS (SELECT 1 FROM personal_admission)
                AND private_material=?6 AND enrollment_request IS ?7 AND paired_handoff IS ?8
                AND auth_generation=?9 AND session_established=?10
                AND EXISTS (SELECT 1 FROM device_key_pair WHERE singleton=1 AND signing=?11 AND kem=?12)
                AND ((?13 IS NULL AND NOT EXISTS (SELECT 1 FROM personal_sync))
                    OR EXISTS (SELECT 1 FROM personal_sync WHERE singleton=1 AND generation=?13
                        AND session=?14 AND account_keys=?15 AND vault_keys=?16))
                AND (?17 IS NULL OR EXISTS (SELECT 1 FROM personal_pairing WHERE singleton=1
                    AND generation=?17 AND side=2 AND origin=?18 AND pairing_id=?19
                    AND peer_id IS ?20 AND phase='completed' AND certificate IS ?21))
                AND (session_established=1 OR ?13 IS NOT NULL OR ?17 IS NOT NULL)
                AND enrollment_attempted=?22
             ON CONFLICT (singleton) DO NOTHING",
            params![self.device_id().as_bytes().as_slice(), anchors, identity.origin,
                identity.account_id.as_bytes().as_slice(), identity.personal_vault_id.as_bytes().as_slice(),
                identity.private_material.as_bytes(), identity.enrollment_request.as_ref().map(SecretVec::as_bytes),
                identity.paired_handoff.as_ref().map(SecretVec::as_bytes), identity.auth_generation,
                identity.session_established, signing, kem,
                snapshot.map(|v| v.generation), snapshot.map(|v| v.session.as_bytes()),
                snapshot.map(|v| v.account_keys.as_bytes()), snapshot.map(|v| v.vault_keys.as_bytes()),
                pairing.map(|v| v.generation), pairing.map(|v| v.origin.as_str()),
                pairing.map(|v| v.pairing_id.as_bytes().as_slice()),
                pairing.and_then(|v| v.peer_id.as_ref().map(|id| id.as_bytes().as_slice())),
                pairing.and_then(|v| v.certificate.as_ref().map(SecretVec::as_bytes)),
                identity.enrollment_attempted],
        )?;
        tx.commit()?;
        self.personal_changed();
        Ok(changed == 1)
    }
}
