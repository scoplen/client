// SPDX-License-Identifier: Apache-2.0

//! Bounded, device-local rendered terminal checkpoints. Contents never enter diagnostics.

use serde::{Deserialize, Serialize};
use specta::Type;

/// Maximum encoded snapshot size, including dimensions and format metadata.
pub const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;
/// Maximum total encrypted-store snapshot payload size.
pub const MAX_SAVED_OUTPUT_BYTES: usize = 64 * MAX_SNAPSHOT_BYTES;

/// Rendered terminal state, rather than an unbounded SSH transport log.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalSnapshot {
    /// Current local format. Unreleased legacy transport logs are not restored.
    pub version: u8,
    /// Grid width at serialization.
    pub columns: u16,
    /// Grid height at serialization.
    pub rows: u16,
    /// Serialized xterm state and retained scrollback.
    pub data: String,
}

impl std::fmt::Debug for TerminalSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalSnapshot")
            .field("columns", &self.columns)
            .field("rows", &self.rows)
            .field("data", &"[redacted]")
            .finish()
    }
}

/// A safe, local output failure. No terminal content is included.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub enum SavedOutputError {
    /// The snapshot is too large or has invalid format/grid metadata.
    #[error("saved terminal output has invalid dimensions or exceeds 1 MiB")]
    InvalidSnapshot,
    /// A newer attempt, different store or closed owner invalidated the checkpoint.
    #[error("the terminal checkpoint no longer belongs to this session")]
    StaleCheckpoint,
    /// Retention or forgetting removed the entry or it is not a terminal.
    #[error("saved terminal output is no longer available")]
    Unavailable,
    /// Local storage could not be read or written.
    #[error("saved terminal output could not be read or written")]
    Storage,
}

impl TerminalSnapshot {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, SavedOutputError> {
        if self.version != 1
            || !(1..=1000).contains(&self.columns)
            || !(1..=1000).contains(&self.rows)
            || self.data.len() > MAX_SNAPSHOT_BYTES
        {
            return Err(SavedOutputError::InvalidSnapshot);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| SavedOutputError::InvalidSnapshot)?;
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(SavedOutputError::InvalidSnapshot);
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, SavedOutputError> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(SavedOutputError::InvalidSnapshot);
        }
        let snapshot: Self =
            serde_json::from_slice(bytes).map_err(|_| SavedOutputError::InvalidSnapshot)?;
        snapshot.encode()?;
        Ok(snapshot)
    }
}
