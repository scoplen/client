// SPDX-License-Identifier: Apache-2.0
//! Source-bound local Organization history and Host-key confirmations.

use std::collections::HashMap;

use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use super::{
    Store, StoreError,
    device::{SESSION_HISTORY_LIMIT, SessionKind},
};
use crate::personal_server::{TeamSshAuthority, TeamSshSource};

pub(crate) struct TeamSessionSource {
    pub source: TeamSshSource,
    pub vault: Uuid,
    pub revision: u64,
    pub host: Uuid,
}

pub(crate) struct TeamHostTrust {
    pub key: String,
    pub fingerprint: String,
    pub accepted_at: u64,
}

impl Store {
    pub(crate) fn record_team_session_start(
        &self,
        source: &TeamSshSource,
        authority: TeamSshAuthority,
        host: Uuid,
        profile: Uuid,
    ) -> Result<Uuid, StoreError> {
        let owner = source.owner(self).map_err(|_| StoreError::AccountContext)?;
        let id = scoplen_model::new_uuid_v7()?;
        let started = scoplen_model::system_time_millis()? as i64;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO session_history(id,profile,kind,started_at) VALUES(?1,?2,?3,?4)",
            params![
                id.as_bytes().as_slice(),
                profile.as_bytes().as_slice(),
                SessionKind::Terminal as i64,
                started
            ],
        )?;
        tx.execute("INSERT INTO team_session_sources(session_id,origin,account_id,organization_id,device_id,vault_id,revision,host_id)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![id.as_bytes().as_slice(), owner.origin, owner.account.as_bytes().as_slice(),
                owner.organization.as_bytes().as_slice(), owner.device.as_bytes().as_slice(),
                authority.vault.as_bytes().as_slice(), authority.revision.to_be_bytes().as_slice(), host.as_bytes().as_slice()])?;
        tx.execute(
            "DELETE FROM session_history WHERE id NOT IN
            (SELECT id FROM session_history ORDER BY started_at DESC,id DESC LIMIT ?1)",
            params![SESSION_HISTORY_LIMIT as i64],
        )?;
        tx.execute(
            "DELETE FROM scrollback WHERE session NOT IN (SELECT id FROM session_history)",
            [],
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub(crate) fn team_session_sources(
        &self,
    ) -> Result<HashMap<Uuid, TeamSessionSource>, StoreError> {
        let conn = self.conn();
        let mut query = conn.prepare_cached("SELECT session_id,origin,account_id,organization_id,device_id,vault_id,revision,host_id
            FROM team_session_sources")?;
        Ok(query
            .query_map([], |row| {
                let uuid = |column| -> rusqlite::Result<Uuid> {
                    Uuid::from_slice(&row.get::<_, Vec<u8>>(column)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)
                };
                let revision = row
                    .get::<_, Vec<u8>>(6)?
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok((
                    uuid(0)?,
                    TeamSessionSource {
                        source: TeamSshSource {
                            origin: row.get(1)?,
                            account_id: uuid(2)?.to_string(),
                            organization_id: uuid(3)?.to_string(),
                            device_id: uuid(4)?.to_string(),
                        },
                        vault: uuid(5)?,
                        revision,
                        host: uuid(7)?,
                    },
                ))
            })?
            .collect::<Result<_, _>>()?)
    }

    pub(crate) fn team_host_trust(
        &self,
        source: &TeamSshSource,
        host: Uuid,
    ) -> Result<Option<TeamHostTrust>, StoreError> {
        let owner = source.owner(self).map_err(|_| StoreError::AccountContext)?;
        Ok(self.conn().query_row("SELECT key,fingerprint,accepted_at FROM team_host_trust
            WHERE origin=?1 AND account_id=?2 AND organization_id=?3 AND device_id=?4 AND host_id=?5",
            params![owner.origin, owner.account.as_bytes().as_slice(), owner.organization.as_bytes().as_slice(),
                owner.device.as_bytes().as_slice(), host.as_bytes().as_slice()],
            |row| Ok(TeamHostTrust { key: row.get(0)?, fingerprint: row.get(1)?, accepted_at: row.get::<_, i64>(2)? as u64 }))
            .optional()?)
    }

    pub(crate) fn accept_team_host_key(
        &self,
        source: &TeamSshSource,
        host: Uuid,
        key: &str,
        fingerprint: &str,
    ) -> Result<(), StoreError> {
        let owner = source.owner(self).map_err(|_| StoreError::AccountContext)?;
        let accepted = scoplen_model::system_time_millis()? as i64;
        self.conn().execute("INSERT INTO team_host_trust(origin,account_id,organization_id,device_id,host_id,key,fingerprint,accepted_at)
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(origin,account_id,organization_id,device_id,host_id)
            DO UPDATE SET key=excluded.key,fingerprint=excluded.fingerprint,accepted_at=excluded.accepted_at",
            params![owner.origin, owner.account.as_bytes().as_slice(), owner.organization.as_bytes().as_slice(),
                owner.device.as_bytes().as_slice(), host.as_bytes().as_slice(), key, fingerprint, accepted])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use scoplen_crypto::LocalDatabaseKey;

    use super::*;

    #[test]
    fn failed_sidecar_insert_rolls_back_the_generic_history_row() {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Store::open(&dir.path().join("teams.db"), &LocalDatabaseKey::new([37; 32])).unwrap();
        let identity = crate::personal_server::tests::fixture_profile(
            &store,
            "https://team.example.test",
            true,
        )
        .record;
        let source = TeamSshSource {
            origin: identity.origin,
            account_id: identity.account_id.to_string(),
            organization_id: Uuid::now_v7().to_string(),
            device_id: store.device_id().to_string(),
        };
        let authority =
            TeamSshAuthority { vault: Uuid::now_v7(), revision: 1, generation: Uuid::now_v7() };
        store
            .conn()
            .execute_batch(
                "CREATE TEMP TRIGGER reject_team_history BEFORE INSERT ON team_session_sources
            BEGIN SELECT RAISE(ABORT, 'fixture sidecar failure'); END;",
            )
            .unwrap();
        assert!(
            store
                .record_team_session_start(&source, authority, Uuid::now_v7(), Uuid::now_v7())
                .is_err()
        );
        assert!(store.recent_sessions(1000).unwrap().is_empty());
        assert!(store.team_session_sources().unwrap().is_empty());
    }
}
