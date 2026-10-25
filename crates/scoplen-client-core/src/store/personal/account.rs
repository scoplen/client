// SPDX-License-Identifier: Apache-2.0
//! Complete verified account snapshots remain local to the encrypted store.

use rusqlite::{OptionalExtension, params};
use scoplen_api::{
    account_devices::MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES,
    account_profile::MAX_ACCOUNT_PROFILE_BYTES,
};
use scoplen_crypto::SecretVec;

use super::{PersonalRecord, Store, StoreError};

pub(crate) struct PersonalAccountRecord {
    pub queried_at: u64,
    pub profile: SecretVec,
    pub devices: SecretVec,
}

impl Store {
    pub(crate) fn personal_account_snapshot(
        &self,
        identity: &PersonalRecord,
    ) -> Result<Option<PersonalAccountRecord>, StoreError> {
        Ok(self.conn().query_row(
            "SELECT queried_at, profile, devices, length(profile), length(devices)
             FROM personal_account_snapshot WHERE singleton = 1 AND origin = ?1 AND account_id = ?2",
            params![identity.origin, identity.account_id.as_bytes().as_slice()],
            |row| {
                let profile_size: i64 = row.get(3)?;
                let devices_size: i64 = row.get(4)?;
                if !(1..=MAX_ACCOUNT_PROFILE_BYTES as i64).contains(&profile_size)
                    || !(1..=MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES as i64).contains(&devices_size)
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok(PersonalAccountRecord {
                    queried_at: u64::try_from(row.get::<_, i64>(0)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    profile: SecretVec::new(row.get(1)?),
                    devices: SecretVec::new(row.get(2)?),
                })
            },
        ).optional()?)
    }

    pub(crate) fn save_personal_account_snapshot(
        &self,
        identity: &PersonalRecord,
        access: &SecretVec,
        snapshot: &PersonalAccountRecord,
        expected_devices: Option<&[u8]>,
        now: u64,
    ) -> Result<bool, StoreError> {
        if self.personal_admission(identity)?.is_none() {
            return Ok(false);
        }
        let queried_at =
            i64::try_from(snapshot.queried_at).map_err(|_| StoreError::InvalidIdentifier)?;
        let (signing, kem) = identity.device_secrets()?;
        let conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn.execute(
            "INSERT INTO personal_account_snapshot (singleton, origin, account_id, queried_at, profile, devices)
             SELECT 1, origin, account_id, ?1, ?2, ?3 FROM personal_server
             WHERE singleton = 1 AND auth_generation = ?4 AND access_token = ?5
                AND access_expires_at > ?6 AND refresh_claimed = 0
                AND origin = ?7 AND account_id = ?8 AND private_material = ?9
                AND personal_vault_id=?10
                AND EXISTS (SELECT 1 FROM personal_admission a WHERE a.singleton=1
                    AND a.origin=personal_server.origin AND a.account_id=personal_server.account_id
                    AND a.personal_vault_id=personal_server.personal_vault_id)
                AND EXISTS (SELECT 1 FROM device_key_pair WHERE singleton = 1 AND signing = ?11 AND kem = ?12)
             ON CONFLICT (singleton) DO UPDATE SET origin = excluded.origin, account_id = excluded.account_id,
                queried_at = excluded.queried_at, profile = excluded.profile, devices = excluded.devices
             WHERE personal_account_snapshot.devices IS ?13",
            params![queried_at, snapshot.profile.as_bytes(), snapshot.devices.as_bytes(),
                identity.auth_generation, access.as_bytes(), now.min(i64::MAX as u64) as i64,
                identity.origin, identity.account_id.as_bytes().as_slice(), identity.private_material.as_bytes(),
                identity.personal_vault_id.as_bytes().as_slice(), signing, kem, expected_devices],
        )? == 1)
    }
}
