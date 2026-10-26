// SPDX-License-Identifier: Apache-2.0

//! Display-only plans for explicitly directed current-directory synchronization.

use serde::Serialize;
use specta::Type;

use crate::session_transfers::SessionTransferDirection;

/// Content comparison of one source file with its destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum SessionDirectorySyncChange {
    /// The destination does not exist.
    Create,
    /// Complete contents differ.
    Changed,
    /// Complete contents match and will be skipped.
    Same,
}

/// One bounded filename and its comparison result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionDirectorySyncEntry {
    /// Safe source basename; never used to reconstruct a target.
    pub name: String,
    /// Planned action or genuine content equality.
    pub change: SessionDirectorySyncChange,
    /// Decimal source length.
    pub source_size_bytes: String,
    /// Decimal destination length, or absence.
    pub target_size_bytes: Option<String>,
}

/// A read-only observation whose native resources remain in Rust.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionDirectorySyncPlan {
    /// One process-local comparison identity.
    pub plan_id: String,
    /// Owning logical terminal.
    pub session_id: String,
    /// Original authenticated transport.
    pub transport_id: String,
    /// Explicit source-to-destination direction.
    pub direction: SessionTransferDirection,
    /// Safe captured remote directory display.
    pub remote_name: String,
    /// Safe selected local directory basename.
    pub local_name: String,
    /// At most sixteen ordinary source files.
    pub entries: Vec<SessionDirectorySyncEntry>,
    /// Source subdirectories deliberately excluded from this shallow profile.
    pub excluded_directories: u32,
}

/// Fixed operational categories without native paths, contents or digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub enum SessionDirectorySyncIssue {
    /// The captured session, transport or plan is unavailable.
    #[error("this directory comparison is unavailable")]
    Unavailable,
    /// An existing ordinary directory is required.
    #[error("choose an existing ordinary directory")]
    InvalidSelection,
    /// Links, special sources or non-file destinations are unsupported.
    #[error("this directory contains an unsupported entry")]
    UnsupportedEntry,
    /// A name cannot map losslessly or conflicts with another destination.
    #[error("a filename cannot be used at the destination")]
    UnsupportedName,
    /// The source-file count or complete directory listing exceeded its bound.
    #[error("this directory exceeds the file or listing limit")]
    TooManyFiles,
    /// Complete hashing exceeded its per-file or total byte bound.
    #[error("this comparison exceeds its limits")]
    TooLarge,
    /// The absolute comparison or an existing request deadline expired.
    #[error("the directory comparison timed out")]
    Timeout,
    /// The comparison was explicitly cancelled.
    #[error("the directory comparison was cancelled")]
    Cancelled,
    /// A compared file or source filename set changed.
    #[error("the directory changed; compare it again")]
    FileChanged,
    /// The complete batch cannot currently enter the existing queue.
    #[error("the file-transfer queue is busy or full")]
    QueueFull,
    /// A local file operation failed.
    #[error("the local directory could not be read")]
    LocalIo,
    /// The SSH server refused an operation.
    #[error("the server refused the directory comparison")]
    RemoteDenied,
    /// The comparison could not complete.
    #[error("the directory comparison failed")]
    Failed,
}

/// Native folder selection either produced a complete plan or was cancelled.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SessionDirectorySyncPrepareResult {
    /// Ready for explicit review; no file has been written.
    Prepared {
        /// Complete bounded observation.
        plan: SessionDirectorySyncPlan,
    },
    /// The native folder picker was closed.
    Cancelled,
}

/// One admitted execution remains owned by the existing transfer queue.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionDirectorySyncItem {
    /// Stable queue item.
    pub item_id: String,
    /// Exact initial execution.
    pub execution_id: String,
}

/// Explicit Apply either queued its complete changes or had nothing to write.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SessionDirectorySyncApplyResult {
    /// The existing queue owns progress and per-file results.
    Queued {
        /// Captured queue lifetime.
        queue_id: String,
        /// Initial FIFO admission order.
        items: Vec<SessionDirectorySyncItem>,
    },
    /// Every source was Same or there were no ordinary source files.
    Unchanged,
}
