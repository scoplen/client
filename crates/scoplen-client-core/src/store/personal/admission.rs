// SPDX-License-Identifier: Apache-2.0
//! Atomic current-device revalidation and immutable Account/store ownership.

use rusqlite::{OptionalExtension as _, TransactionBehavior, params};
use scoplen_crypto::SecretVec;

use super::{PersonalAccountRecord, PersonalTokens};
use super::{PersonalRecord, PersonalSyncRecord, Store, StoreError};

impl Store {
    pub(crate) fn personal_revalidation_current(
        &self,
        identity: &PersonalRecord,
    ) -> Result<bool, StoreError> {
        let (signing, kem) = identity.device_secrets()?;
        Ok(self.conn().query_row(
            "SELECT EXISTS (SELECT 1 FROM personal_server p, device d, device_key_pair k
             WHERE p.singleton=1 AND d.singleton=1 AND k.singleton=1 AND p.origin=?1
                AND p.account_id=?2 AND p.personal_vault_id=?3 AND p.private_material=?4
                AND p.auth_generation=?5 AND d.device_id=?6 AND k.signing=?7 AND k.kem=?8
                AND NOT EXISTS (SELECT 1 FROM personal_admission)
                AND NOT EXISTS (SELECT 1 FROM account_profile_binding))",
            params![
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                identity.personal_vault_id.as_bytes().as_slice(),
                identity.private_material.as_bytes(),
                identity.auth_generation,
                self.device_id().as_bytes().as_slice(),
                signing,
                kem
            ],
            |row| row.get(0),
        )?)
    }

    /// The caller holds the captured open-profile generation fence. No claim or credentials
    /// are persisted before this transaction, so a failed revalidation leaves all old bytes.
    pub(crate) fn finish_personal_revalidation(
        &self,
        identity: &PersonalRecord,
        anchors: &[u8],
        tokens: &PersonalTokens,
        snapshot: &PersonalSyncRecord,
        previous: Option<&PersonalSyncRecord>,
        account: Option<&PersonalAccountRecord>,
    ) -> Result<bool, StoreError> {
        let access_expires =
            i64::try_from(tokens.access_expires_at).map_err(|_| StoreError::InvalidIdentifier)?;
        let refresh_expires =
            i64::try_from(tokens.refresh_expires_at).map_err(|_| StoreError::InvalidIdentifier)?;
        let account_queried = account
            .map(|value| i64::try_from(value.queried_at))
            .transpose()
            .map_err(|_| StoreError::InvalidIdentifier)?;
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (signing, kem) = identity.device_secrets()?;
        let matches: bool = tx.query_row(
            "SELECT EXISTS (SELECT 1 FROM personal_server p, device d, device_key_pair k
             WHERE p.singleton=1 AND d.singleton=1 AND k.singleton=1 AND p.origin=?1
                AND p.account_id=?2 AND p.personal_vault_id=?3 AND p.private_material=?4
                AND p.auth_generation=?5 AND d.device_id=?6 AND k.signing=?7 AND k.kem=?8
                AND NOT EXISTS (SELECT 1 FROM personal_admission)
                AND NOT EXISTS (SELECT 1 FROM account_profile_binding)
                AND ((?9 IS NULL AND NOT EXISTS (SELECT 1 FROM personal_sync))
                    OR EXISTS (SELECT 1 FROM personal_sync WHERE singleton=1 AND generation=?9
                        AND session=?10 AND account_keys=?11 AND vault_keys=?12))
                AND ((?13 IS NULL AND NOT EXISTS (SELECT 1 FROM personal_account_snapshot))
                    OR EXISTS (SELECT 1 FROM personal_account_snapshot WHERE singleton=1
                        AND origin=p.origin AND account_id=p.account_id
                        AND queried_at=?13 AND profile=?14 AND devices=?15)))",
            params![
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                identity.personal_vault_id.as_bytes().as_slice(),
                identity.private_material.as_bytes(),
                identity.auth_generation,
                self.device_id().as_bytes().as_slice(),
                signing,
                kem,
                previous.map(|v| v.generation),
                previous.map(|v| v.session.as_bytes()),
                previous.map(|v| v.account_keys.as_bytes()),
                previous.map(|v| v.vault_keys.as_bytes()),
                account_queried,
                account.map(|v| v.profile.as_bytes()),
                account.map(|v| v.devices.as_bytes())
            ],
            |row| row.get(0),
        )?;
        if !matches {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO personal_admission
            (singleton,origin,account_id,personal_vault_id,device_id,anchors)
            VALUES (1,?1,?2,?3,?4,?5)",
            params![
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                identity.personal_vault_id.as_bytes().as_slice(),
                self.device_id().as_bytes().as_slice(),
                anchors
            ],
        )?;
        tx.execute("UPDATE personal_server SET access_token=?1, refresh_token=?2,
            access_expires_at=?3, refresh_expires_at=?4, auth_scope=?5, refresh_claimed=0,
            session_established=1, auth_generation=auth_generation+1, refresh_retry_at=NULL WHERE singleton=1",
            params![tokens.access.as_bytes(), tokens.refresh.as_bytes(), access_expires,
                refresh_expires, tokens.scope])?;
        tx.execute(
            "INSERT INTO personal_sync (singleton,generation,session,account_keys,vault_keys)
            VALUES (1,1,?1,?2,?3) ON CONFLICT(singleton) DO UPDATE SET
            generation=personal_sync.generation+1, session=excluded.session,
            account_keys=excluded.account_keys, vault_keys=excluded.vault_keys",
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

    #[cfg(test)]
    pub(crate) fn insert_personal_admission(
        &self,
        identity: &PersonalRecord,
        anchors: &[u8],
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO personal_admission
             (singleton,origin,account_id,personal_vault_id,device_id,anchors)
             VALUES (1,?1,?2,?3,?4,?5)",
            params![
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                identity.personal_vault_id.as_bytes().as_slice(),
                self.device_id().as_bytes().as_slice(),
                anchors
            ],
        )?;
        Ok(())
    }
}
