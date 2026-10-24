// SPDX-License-Identifier: Apache-2.0

//! Device-local records (`scoplen-docs/04-object-model.md` §4.9): what this
//! device keeps for itself and never replicates. They live in the same
//! encrypted store as everything else.

use rusqlite::{OptionalExtension, params};
use scoplen_crypto::SecretVec;
use uuid::Uuid;

use super::{Store, StoreError, uuid_from};
use crate::terminal_output::{
    MAX_SAVED_OUTPUT_BYTES, MAX_SNAPSHOT_BYTES, SavedOutputError, TerminalSnapshot,
};

/// How many sessions the history keeps; older ones are removed.
pub const SESSION_HISTORY_LIMIT: usize = 1_000;

/// This device's half of a device-bound credential.
#[derive(Debug, PartialEq, Eq)]
pub struct DeviceCredential {
    /// The secret held in the store: a password or an OpenSSH private key.
    pub secret: Option<SecretVec>,
    /// A reference to a key held by the platform keystore or hardware.
    pub keystore_handle: Option<String>,
}

/// The private parts of the device key pair, in `scoplen-crypto`'s encodings.
#[derive(Debug, PartialEq, Eq)]
pub struct DeviceKeyPair {
    /// The P-256 signing key.
    pub signing: SecretVec,
    /// The P-256 HPKE key.
    pub kem: SecretVec,
}

/// What a session was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionKind {
    /// A terminal.
    Terminal = 1,
    /// A file browser.
    Files = 2,
    /// A tunnel.
    Forward = 3,
}

/// How a session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionOutcome {
    /// Closed by the user or the host.
    Closed = 1,
    /// Failed to connect or was lost.
    Failed = 2,
}

/// One entry of the session history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionEntry {
    /// The session.
    pub id: Uuid,
    /// The login it used.
    pub profile: Uuid,
    /// What it was.
    pub kind: SessionKind,
    /// When it started, in Unix milliseconds.
    pub started_at: u64,
    /// When it ended, if it has.
    pub ended_at: Option<u64>,
    /// How it ended, if it has.
    pub outcome: Option<SessionOutcome>,
}

fn now() -> Result<i64, StoreError> {
    Ok(scoplen_model::system_time_millis()? as i64)
}

impl Store {
    /// Keeps this device's secret for a device-bound credential, replacing
    /// any previous one.
    pub fn set_device_secret(&self, credential: Uuid, secret: &[u8]) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO device_credentials (credential, secret, keystore_handle, updated_at) VALUES (?1, ?2, NULL, ?3)
             ON CONFLICT (credential) DO UPDATE SET secret = excluded.secret, keystore_handle = NULL, updated_at = excluded.updated_at",
            params![credential.as_bytes().as_slice(), secret, now()?],
        )?;
        Ok(())
    }

    /// Records that this device's key for a credential is held by the
    /// keystore or hardware under `handle`, replacing any stored secret.
    pub fn set_device_keystore_handle(
        &self,
        credential: Uuid,
        handle: &str,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO device_credentials (credential, secret, keystore_handle, updated_at) VALUES (?1, NULL, ?2, ?3)
             ON CONFLICT (credential) DO UPDATE SET secret = NULL, keystore_handle = excluded.keystore_handle, updated_at = excluded.updated_at",
            params![credential.as_bytes().as_slice(), handle, now()?],
        )?;
        Ok(())
    }

    /// This device's half of a credential, if it has one.
    pub fn device_credential(
        &self,
        credential: Uuid,
    ) -> Result<Option<DeviceCredential>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT secret, keystore_handle FROM device_credentials WHERE credential = ?1",
                params![credential.as_bytes().as_slice()],
                |row| {
                    Ok(DeviceCredential {
                        secret: row.get::<_, Option<Vec<u8>>>(0)?.map(SecretVec::new),
                        keystore_handle: row.get(1)?,
                    })
                },
            )
            .optional()?)
    }

    /// Forgets this device's half of a credential.
    pub fn remove_device_credential(&self, credential: Uuid) -> Result<(), StoreError> {
        self.conn().execute(
            "DELETE FROM device_credentials WHERE credential = ?1",
            params![credential.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Keeps the device key pair. It is created once, at sync enrollment.
    pub fn set_device_key_pair(&self, keys: &DeviceKeyPair) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO device_key_pair (singleton, signing, kem, created_at) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT (singleton) DO UPDATE SET signing = excluded.signing, kem = excluded.kem, created_at = excluded.created_at",
            params![keys.signing.as_bytes(), keys.kem.as_bytes(), now()?],
        )?;
        Ok(())
    }

    /// The device key pair, if this device has enrolled.
    pub fn device_key_pair(&self) -> Result<Option<DeviceKeyPair>, StoreError> {
        Ok(self
            .conn()
            .query_row("SELECT signing, kem FROM device_key_pair WHERE singleton = 1", [], |row| {
                Ok(DeviceKeyPair {
                    signing: SecretVec::new(row.get(0)?),
                    kem: SecretVec::new(row.get(1)?),
                })
            })
            .optional()?)
    }

    /// Records the start of a session and returns its identifier. The oldest
    /// entries beyond [`SESSION_HISTORY_LIMIT`] are removed.
    pub fn record_session_start(
        &self,
        profile: Uuid,
        kind: SessionKind,
    ) -> Result<Uuid, StoreError> {
        let id = scoplen_model::new_uuid_v7()?;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO session_history (id, profile, kind, started_at) VALUES (?1, ?2, ?3, ?4)",
            params![id.as_bytes().as_slice(), profile.as_bytes().as_slice(), kind as i64, now()?],
        )?;
        tx.execute(
            "DELETE FROM session_history WHERE id NOT IN
             (SELECT id FROM session_history ORDER BY started_at DESC, id DESC LIMIT ?1)",
            params![SESSION_HISTORY_LIMIT as i64],
        )?;
        tx.execute(
            "DELETE FROM scrollback WHERE session NOT IN (SELECT id FROM session_history)",
            [],
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Records how a session ended.
    pub fn record_session_end(
        &self,
        session: Uuid,
        outcome: SessionOutcome,
    ) -> Result<(), StoreError> {
        let changed = self.conn().execute(
            "UPDATE session_history SET ended_at = ?2, outcome = ?3 WHERE id = ?1 AND ended_at IS NULL",
            params![session.as_bytes().as_slice(), now()?, outcome as i64],
        )?;
        if changed == 0 { Err(StoreError::NotFound(session)) } else { Ok(()) }
    }

    /// Reads one device-local session, including an ended state when present.
    pub fn session(&self, session: Uuid) -> Result<Option<SessionEntry>, StoreError> {
        let conn = self.conn();
        Ok(conn
            .query_row(
            "SELECT id, profile, kind, started_at, ended_at, outcome FROM session_history WHERE id = ?1",
            params![session.as_bytes().as_slice()],
            decode_session,
        )
        .optional()?)
    }

    /// Forgets one ended session and its saved terminal contents.
    ///
    /// Active sessions are retained until their owner records an outcome. This
    /// prevents a cleanup action from making a live session disappear from
    /// device-local state while a transport still owns it.
    pub fn forget_session(&self, session: Uuid) -> Result<(), StoreError> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let ended = tx
            .query_row(
                "SELECT ended_at FROM session_history WHERE id = ?1",
                params![session.as_bytes().as_slice()],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?;
        match ended {
            None => Err(StoreError::NotFound(session)),
            Some(None) => Err(StoreError::SessionActive(session)),
            Some(Some(_)) => {
                tx.execute(
                    "DELETE FROM scrollback WHERE session = ?1",
                    params![session.as_bytes().as_slice()],
                )?;
                tx.execute(
                    "DELETE FROM session_history WHERE id = ?1",
                    params![session.as_bytes().as_slice()],
                )?;
                tx.commit()?;
                Ok(())
            }
        }
    }

    /// The most recent sessions, newest first.
    pub fn recent_sessions(&self, limit: usize) -> Result<Vec<SessionEntry>, StoreError> {
        let conn = self.conn();
        let mut statement = conn.prepare_cached(
            "SELECT id, profile, kind, started_at, ended_at, outcome FROM session_history
             ORDER BY started_at DESC, id DESC LIMIT ?1",
        )?;
        statement
            .query_map(params![limit as i64], decode_session)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Keeps a session's serialized terminal contents, for restoring it after
    /// a reconnect or restart.
    pub fn save_scrollback(
        &self,
        session: Uuid,
        snapshot: &TerminalSnapshot,
    ) -> Result<(), SavedOutputError> {
        let data = snapshot.encode()?;
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|_| SavedOutputError::Storage)?;
        let terminal: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM session_history WHERE id = ?1 AND kind = 1)",
                params![session.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| SavedOutputError::Storage)?;
        if !terminal {
            return Err(SavedOutputError::Unavailable);
        }
        tx.execute(
            "INSERT INTO scrollback (session, data, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (session) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
            params![session.as_bytes().as_slice(), data, tx.query_row(
                "SELECT max(?1, coalesce(max(updated_at), 0) + 1) FROM scrollback",
                params![now().map_err(|_| SavedOutputError::Storage)?], |row| row.get::<_, i64>(0),
            ).map_err(|_| SavedOutputError::Storage)?],
        ).map_err(|_| SavedOutputError::Storage)?;
        loop {
            let size: i64 = tx
                .query_row("SELECT coalesce(sum(length(data)), 0) FROM scrollback", [], |row| {
                    row.get(0)
                })
                .map_err(|_| SavedOutputError::Storage)?;
            if size <= MAX_SAVED_OUTPUT_BYTES as i64 {
                break;
            }
            tx.execute("DELETE FROM scrollback WHERE session IN (SELECT session FROM scrollback ORDER BY updated_at, session LIMIT 1)", [])
                .map_err(|_| SavedOutputError::Storage)?;
        }
        tx.commit().map_err(|_| SavedOutputError::Storage)?;
        Ok(())
    }

    /// A session's saved terminal contents.
    pub fn scrollback(&self, session: Uuid) -> Result<Option<TerminalSnapshot>, SavedOutputError> {
        let bytes: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT s.data FROM scrollback s JOIN session_history h ON h.id = s.session WHERE s.session = ?1 AND h.kind = 1 AND length(s.data) <= ?2",
                params![session.as_bytes().as_slice(), MAX_SNAPSHOT_BYTES as i64],
                |row| row.get(0),
            )
            .optional().map_err(|_| SavedOutputError::Storage)?;
        bytes.map(|bytes| TerminalSnapshot::decode(&bytes)).transpose()
    }

    /// Whether retention still holds an output snapshot, without reading its content.
    pub fn has_scrollback(&self, session: Uuid) -> Result<bool, StoreError> {
        Ok(self.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM scrollback s JOIN session_history h ON s.session = h.id WHERE s.session = ?1 AND h.kind = 1 AND length(s.data) <= ?2)",
            params![session.as_bytes().as_slice(), MAX_SNAPSHOT_BYTES as i64], |row| row.get(0),
        )?)
    }

    /// Forgets a session's terminal contents.
    pub fn remove_scrollback(&self, session: Uuid) -> Result<(), StoreError> {
        self.conn().execute(
            "DELETE FROM scrollback WHERE session = ?1",
            params![session.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Keeps the state of a window, such as its size and position.
    pub fn save_window_state(&self, window: &str, state: &[u8]) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO window_state (window, state, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (window) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at",
            params![window, state, now()?],
        )?;
        Ok(())
    }

    /// The saved state of a window.
    pub fn window_state(&self, window: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .conn()
            .query_row("SELECT state FROM window_state WHERE window = ?1", params![window], |row| {
                row.get(0)
            })
            .optional()?)
    }
}

fn decode_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionEntry> {
    let id = row.get::<_, Vec<u8>>(0)?;
    let profile = row.get::<_, Vec<u8>>(1)?;
    let kind = row.get::<_, i64>(2)?;
    let started_at = row.get::<_, i64>(3)?;
    let ended_at = row.get::<_, Option<i64>>(4)?;
    let outcome = row.get::<_, Option<i64>>(5)?;
    Ok(SessionEntry {
        id: uuid_from(&id).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?,
        profile: uuid_from(&profile).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?,
        kind: match kind {
            1 => SessionKind::Terminal,
            2 => SessionKind::Files,
            _ => SessionKind::Forward,
        },
        started_at: started_at as u64,
        ended_at: ended_at.map(|t| t as u64),
        outcome: outcome
            .map(|o| if o == 1 { SessionOutcome::Closed } else { SessionOutcome::Failed }),
    })
}
