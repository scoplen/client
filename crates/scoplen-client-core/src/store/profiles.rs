// SPDX-License-Identifier: Apache-2.0
//! Local catalog reservations and immutable Account-store provenance.

use rusqlite::{OptionalExtension as _, TransactionBehavior, params};
use scoplen_crypto::SecretVec;
use uuid::Uuid;

use super::{Store, StoreError, personal::RegistrationRecord, uuid_from};
use crate::profiles::AccountProfile;

#[derive(Clone)]
pub(crate) struct ProfileRecord {
    pub profile: AccountProfile,
    pub payload: SecretVec,
    pub signature: [u8; 64],
    pub confirmation: SecretVec,
}

pub(crate) struct AccountInstallation<'a> {
    pub provenance: &'a ProfileRecord,
    pub identity: &'a super::personal::PersonalRecord,
    pub anchors: &'a [u8],
    pub tokens: &'a super::personal::PersonalTokens,
    pub snapshot: &'a super::personal::PersonalSyncRecord,
    pub previous: Option<&'a super::personal::PersonalSyncRecord>,
    pub previous_admission: Option<&'a SecretVec>,
}

const COLUMNS: &str = "profile_id,origin,account_id,vault_id,device_id,operation_id,CASE WHEN length(payload) BETWEEN 1 AND 4325376 THEN payload END,CASE WHEN length(signature)=64 THEN signature END,CASE WHEN length(confirmation) BETWEEN 1 AND 1024 THEN confirmation END";

fn read(row: &rusqlite::Row<'_>, ready: bool) -> rusqlite::Result<ProfileRecord> {
    let uuid = |index| {
        uuid_from(&row.get::<_, Vec<u8>>(index)?).map_err(|_| rusqlite::Error::InvalidQuery)
    };
    let payload = SecretVec::new(row.get(6)?);
    let signature: Vec<u8> = row.get(7)?;
    let confirmation = SecretVec::new(row.get(8)?);
    if !(1..=4_325_376).contains(&payload.len()) || !(1..=1024).contains(&confirmation.len()) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(ProfileRecord {
        profile: AccountProfile {
            id: uuid(0)?,
            origin: row.get(1)?,
            account_id: uuid(2)?,
            personal_vault_id: uuid(3)?,
            device_id: uuid(4)?,
            operation_id: uuid(5)?,
            ready,
        },
        payload,
        signature: signature.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
        confirmation,
    })
}

pub(super) fn preflight(
    conn: &rusqlite::Connection,
    expected: Option<&ProfileRecord>,
) -> Result<(), StoreError> {
    let table: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='account_profile_binding')",
        [], |row| row.get(0),
    )?;
    if table {
        let actual = conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM account_profile_binding WHERE singleton=1"),
                [],
                |row| read(row, false),
            )
            .optional()?;
        if let Some(actual) = actual {
            if !expected.is_some_and(|expected| same(&actual, expected)) {
                return Err(StoreError::AccountContext);
            }
            return Ok(());
        }
    }
    if let Some(expected) = expected {
        let device_table: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='device')",
            [],
            |row| row.get(0),
        )?;
        if device_table {
            let id: Option<Vec<u8>> = conn
                .query_row("SELECT device_id FROM device WHERE singleton=1", [], |row| row.get(0))
                .optional()?;
            if id.is_some_and(|id| id.as_slice() != expected.profile.device_id.as_bytes()) {
                return Err(StoreError::AccountContext);
            }
        }
    }
    Ok(())
}

pub(crate) fn same(a: &ProfileRecord, b: &ProfileRecord) -> bool {
    a.profile.id == b.profile.id
        && a.profile.origin == b.profile.origin
        && a.profile.account_id == b.profile.account_id
        && a.profile.personal_vault_id == b.profile.personal_vault_id
        && a.profile.device_id == b.profile.device_id
        && a.profile.operation_id == b.profile.operation_id
        && a.payload == b.payload
        && a.signature == b.signature
        && a.confirmation == b.confirmation
}

impl Store {
    pub(crate) fn start_profile_catalog(&self) -> Result<(i64, Option<Uuid>), StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let local: bool = tx.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM account_profile_binding)
                AND NOT EXISTS(SELECT 1 FROM personal_server)",
            [],
            |row| row.get(0),
        )?;
        if !local {
            return Err(StoreError::AccountContext);
        }
        if tx.execute("UPDATE profile_selection SET generation=generation+1 WHERE singleton=1 AND generation<9223372036854775807", [])? != 1 {
            return Err(StoreError::AccountContext);
        }
        let (generation, selected): (i64, Option<Vec<u8>>) = tx.query_row(
            "SELECT generation,profile_id FROM profile_selection WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        tx.commit()?;
        Ok((generation, selected.map(|id| uuid_from(&id)).transpose()?))
    }

    pub(crate) fn profile_generation(&self) -> Result<i64, StoreError> {
        Ok(self.conn().query_row(
            "SELECT generation FROM profile_selection WHERE singleton=1",
            [],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn profile_catalog(&self) -> Result<Vec<AccountProfile>, StoreError> {
        let conn = self.conn();
        let mut statement = conn.prepare("SELECT profile_id,origin,account_id,vault_id,device_id,operation_id,ready FROM account_profiles ORDER BY origin,account_id LIMIT 129")?;
        let rows = statement.query_map([], |row| {
            let uuid = |index| {
                Uuid::from_slice(&row.get::<_, Vec<u8>>(index)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)
            };
            Ok(AccountProfile {
                id: uuid(0)?,
                origin: row.get(1)?,
                account_id: uuid(2)?,
                personal_vault_id: uuid(3)?,
                device_id: uuid(4)?,
                operation_id: uuid(5)?,
                ready: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub(crate) fn profile_record(&self, id: Uuid) -> Result<Option<ProfileRecord>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                &format!("SELECT {COLUMNS},ready FROM account_profiles WHERE profile_id=?1"),
                [id.as_bytes().as_slice()],
                |row| read(row, row.get(9)?),
            )
            .optional()?)
    }

    pub(crate) fn reserve_profile(
        &self,
        candidate: &ProfileRecord,
        pending: &RegistrationRecord,
        generation: i64,
    ) -> Result<ProfileRecord, StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM (
                SELECT phase,payload,account_signature,private_material,confirmation FROM personal_registration
                UNION ALL SELECT phase,payload,account_signature,private_material,confirmation FROM personal_password_login
                ),profile_selection
                WHERE phase=2 AND payload=?1 AND account_signature=?2 AND private_material=?3
                    AND confirmation=?4 AND generation=?5)",
            params![
                pending.payload.as_bytes(),
                pending.account_signature.as_slice(),
                pending.private_material.as_bytes(),
                pending.confirmation.as_ref().map(SecretVec::as_bytes),
                generation
            ],
            |row| row.get(0),
        )?;
        if !current {
            return Err(StoreError::AccountContext);
        }
        if let Some(existing) = tx
            .query_row(
                &format!(
                    "SELECT {COLUMNS},ready FROM account_profiles WHERE origin=?1 AND account_id=?2"
                ),
                params![
                    candidate.profile.origin,
                    candidate.profile.account_id.as_bytes().as_slice()
                ],
                |row| read(row, row.get(9)?),
            )
            .optional()?
        {
            let mut expected = candidate.clone();
            expected.profile.id = existing.profile.id;
            if !same(&expected, &existing) {
                return Err(StoreError::AccountContext);
            }
            return Ok(existing);
        }
        let count: i64 =
            tx.query_row("SELECT count(*) FROM account_profiles", [], |row| row.get(0))?;
        if count >= 128 {
            return Err(StoreError::ProfileLimit);
        }
        tx.execute(
            "INSERT INTO account_profiles(profile_id,origin,account_id,vault_id,device_id,operation_id,payload,signature,confirmation) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![candidate.profile.id.as_bytes().as_slice(),candidate.profile.origin,candidate.profile.account_id.as_bytes().as_slice(),candidate.profile.personal_vault_id.as_bytes().as_slice(),candidate.profile.device_id.as_bytes().as_slice(),candidate.profile.operation_id.as_bytes().as_slice(),candidate.payload.as_bytes(),candidate.signature.as_slice(),candidate.confirmation.as_bytes()],
        )?;
        tx.commit()?;
        Ok(candidate.clone())
    }

    pub(crate) fn initialize_account_profile(
        &self,
        provenance: &ProfileRecord,
        private: &SecretVec,
        device_name: &str,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = tx
            .query_row(
                &format!("SELECT {COLUMNS} FROM account_profile_binding WHERE singleton=1"),
                [],
                |row| read(row, false),
            )
            .optional()?
        {
            if !same(&existing, provenance) {
                return Err(StoreError::AccountContext);
            }
            let matches:bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM personal_server WHERE singleton=1 AND private_material=?1 AND device_name=?2)", params![private.as_bytes(),device_name], |row| row.get(0))?;
            if !matches {
                return Err(StoreError::AccountContext);
            }
            return Ok(());
        }
        tx.execute(
            "INSERT INTO account_profile_binding(singleton,profile_id,origin,account_id,vault_id,device_id,operation_id,payload,signature,confirmation) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![provenance.profile.id.as_bytes().as_slice(),provenance.profile.origin,provenance.profile.account_id.as_bytes().as_slice(),provenance.profile.personal_vault_id.as_bytes().as_slice(),provenance.profile.device_id.as_bytes().as_slice(),provenance.profile.operation_id.as_bytes().as_slice(),provenance.payload.as_bytes(),provenance.signature.as_slice(),provenance.confirmation.as_bytes()],
        )?;
        if !matches!((private.as_bytes().first(), private.len()), (Some(1), 225) | (Some(2), 193)) {
            return Err(StoreError::InvalidIdentifier);
        }
        tx.execute("INSERT INTO personal_server(singleton,origin,account_id,personal_vault_id,device_name,private_material,recovery_saved,recovery_confirmed) VALUES(1,?1,?2,?3,?4,?5,?6,?6)",
            params![provenance.profile.origin,provenance.profile.account_id.as_bytes().as_slice(),provenance.profile.personal_vault_id.as_bytes().as_slice(),device_name,private.as_bytes(),private.len()==225])?;
        tx.execute(
            "INSERT INTO device_key_pair(singleton,signing,kem,created_at) VALUES(1,?1,?2,?3)",
            params![
                &private.as_bytes()[1..33],
                &private.as_bytes()[33..65],
                i64::try_from(scoplen_model::system_time_millis()?)
                    .map_err(|_| StoreError::InvalidIdentifier)?
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn select_profile(
        &self,
        generation: i64,
        id: Option<Uuid>,
        installation: Option<&RegistrationRecord>,
    ) -> Result<i64, StoreError> {
        let next = generation.checked_add(1).ok_or(StoreError::InvalidIdentifier)?;
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(pending) = installation {
            let changed=tx.execute("UPDATE account_profiles SET ready=1 WHERE profile_id=?1 AND payload=?2 AND signature=?3 AND confirmation=?4",
                params![id.map(|v|v.as_bytes().to_vec()),pending.payload.as_bytes(),pending.account_signature.as_slice(),pending.confirmation.as_ref().map(SecretVec::as_bytes)])?;
            if changed != 1 {
                return Err(StoreError::AccountContext);
            }
            let mut changed = 0;
            for table in ["personal_registration", "personal_password_login"] {
                changed+=tx.execute(&format!("DELETE FROM {table} WHERE phase=2 AND payload=?1 AND account_signature=?2 AND private_material=?3 AND confirmation=?4"),
                    params![pending.payload.as_bytes(),pending.account_signature.as_slice(),pending.private_material.as_bytes(),pending.confirmation.as_ref().map(SecretVec::as_bytes)])?;
            }
            if changed != 1 {
                return Err(StoreError::AccountContext);
            }
        }
        let changed=tx.execute("UPDATE profile_selection SET generation=?1,profile_id=?2 WHERE singleton=1 AND generation=?3 AND (?2 IS NULL OR EXISTS(SELECT 1 FROM account_profiles WHERE profile_id=?2 AND ready=1))",
            params![next,id.map(|v|v.as_bytes().to_vec()),generation])?;
        if changed != 1 {
            return Err(StoreError::AccountContext);
        }
        tx.commit()?;
        Ok(next)
    }

    pub(crate) fn commit_account_installation(
        &self,
        installation: AccountInstallation<'_>,
    ) -> Result<bool, StoreError> {
        let AccountInstallation {
            provenance,
            identity,
            anchors,
            tokens,
            snapshot,
            previous,
            previous_admission,
        } = installation;
        let access =
            i64::try_from(tokens.access_expires_at).map_err(|_| StoreError::InvalidIdentifier)?;
        let refresh =
            i64::try_from(tokens.refresh_expires_at).map_err(|_| StoreError::InvalidIdentifier)?;
        let mut conn = self.conn();
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let actual = tx
            .query_row(
                &format!("SELECT {COLUMNS} FROM account_profile_binding WHERE singleton=1"),
                [],
                |row| read(row, false),
            )
            .optional()?;
        if !actual.as_ref().is_some_and(|actual| same(actual, provenance)) {
            return Err(StoreError::AccountContext);
        }
        let (signing, kem) = identity.device_secrets()?;
        let current: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM personal_server p,device d,device_key_pair k
                WHERE p.singleton=1 AND d.singleton=1 AND k.singleton=1 AND p.origin=?1
                    AND p.account_id=?2 AND p.personal_vault_id=?3 AND p.private_material=?4
                    AND p.auth_generation=?5 AND d.device_id=?6 AND k.signing=?7 AND k.kem=?8
                    AND ((?9 IS NULL AND NOT EXISTS(SELECT 1 FROM personal_admission))
                        OR EXISTS(SELECT 1 FROM personal_admission WHERE anchors=?9))
                    AND ((?10 IS NULL AND NOT EXISTS(SELECT 1 FROM personal_sync))
                        OR EXISTS(SELECT 1 FROM personal_sync WHERE generation=?10 AND session=?11
                            AND account_keys=?12 AND vault_keys=?13)))",
            params![
                identity.origin,
                identity.account_id.as_bytes().as_slice(),
                identity.personal_vault_id.as_bytes().as_slice(),
                identity.private_material.as_bytes(),
                identity.auth_generation,
                self.device_id().as_bytes().as_slice(),
                signing,
                kem,
                previous_admission.map(SecretVec::as_bytes),
                previous.map(|p| p.generation),
                previous.map(|p| p.session.as_bytes()),
                previous.map(|p| p.account_keys.as_bytes()),
                previous.map(|p| p.vault_keys.as_bytes())
            ],
            |row| row.get(0),
        )?;
        if !current {
            return Ok(false);
        }
        if previous_admission.is_none() {
            tx.execute("INSERT INTO personal_admission(singleton,origin,account_id,personal_vault_id,device_id,anchors) VALUES(1,?1,?2,?3,?4,?5)",
                params![identity.origin,identity.account_id.as_bytes().as_slice(),identity.personal_vault_id.as_bytes().as_slice(),self.device_id().as_bytes().as_slice(),anchors])?;
        }
        tx.execute("UPDATE personal_server SET access_token=?1,refresh_token=?2,access_expires_at=?3,refresh_expires_at=?4,auth_scope=?5,refresh_claimed=0,session_established=1,auth_generation=auth_generation+1,refresh_retry_at=NULL WHERE singleton=1",
            params![tokens.access.as_bytes(),tokens.refresh.as_bytes(),access,refresh,tokens.scope])?;
        tx.execute("INSERT INTO personal_sync(singleton,generation,session,account_keys,vault_keys) VALUES(1,1,?1,?2,?3) ON CONFLICT(singleton) DO UPDATE SET generation=personal_sync.generation+1,session=excluded.session,account_keys=excluded.account_keys,vault_keys=excluded.vault_keys",
            params![snapshot.session.as_bytes(),snapshot.account_keys.as_bytes(),snapshot.vault_keys.as_bytes()])?;
        tx.commit()?;
        self.personal_changed();
        Ok(true)
    }
}
