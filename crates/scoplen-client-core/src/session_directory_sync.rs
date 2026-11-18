// SPDX-License-Identifier: Apache-2.0

//! Display-only plans and results for explicitly directed recursive synchronization.

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

/// A corresponding directory is either present or explicitly planned for creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum SessionDirectorySyncDirectoryChange {
    /// This ordinary directory must be created.
    Create,
    /// This ordinary directory already exists.
    Existing,
}

/// One bounded relative display name and its comparison result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SessionDirectorySyncEntry {
    /// One ordinary source file.
    File {
        /// Safe relative name, never used to reconstruct a path.
        name: String,
        /// Planned action or genuine complete-content equality.
        change: SessionDirectorySyncChange,
        /// Decimal source length.
        source_size_bytes: String,
        /// Decimal destination length, or absence.
        target_size_bytes: Option<String>,
    },
    /// An ordinary directory, including the existing root displayed as a dot.
    Directory {
        /// Safe relative name, never used to reconstruct a path.
        name: String,
        /// Whether explicit creation is required.
        change: SessionDirectorySyncDirectoryChange,
    },
}

/// Complete counts for one bounded recursive comparison.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionDirectorySyncSummary {
    /// Missing ordinary files.
    pub files_create: u32,
    /// Existing ordinary files with different contents.
    pub files_changed: u32,
    /// Files whose complete contents match.
    pub files_same: u32,
    /// Missing directories, including empty children.
    pub directories_create: u32,
    /// Existing ordinary directories, including the root.
    pub directories_existing: u32,
    /// Source bytes requiring transfer, as unsigned decimal text.
    pub transfer_size_bytes: String,
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
    /// Complete bounded file and directory rows, including the existing root.
    pub entries: Vec<SessionDirectorySyncEntry>,
    /// Complete counts of planned actions.
    pub summary: SessionDirectorySyncSummary,
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
    /// The complete tree exceeds its entry count.
    #[error("this directory contains too many entries")]
    TooManyEntries,
    /// The complete tree exceeds its depth bound.
    #[error("this directory is nested too deeply")]
    TooDeep,
    /// Retained comparison metadata exceeds its bound.
    #[error("this directory contains too much filename metadata")]
    TooMuchMetadata,
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
    /// Cleanup of the current owned staging file could not be confirmed.
    #[error("temporary file cleanup could not be confirmed")]
    CleanupIncomplete,
    /// A dispatched mutation or publication has an unknown result.
    #[error("the destination result is unknown; review it before trying again")]
    PublicationUnknown,
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

/// Explicit Apply either queued its complete changes or had nothing to write.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SessionDirectorySyncApplyResult {
    /// The existing queue owns progress and per-file results.
    Queued {
        /// Captured queue lifetime.
        queue_id: String,
        /// One stable queue item for the complete reviewed tree.
        item_id: String,
        /// Exact initial execution.
        execution_id: String,
    },
    /// Every source file was Same and every directory was Existing.
    Unchanged,
}

/// Phase of an admitted synchronization job.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum SessionDirectorySyncPhase {
    /// Creating directories or transferring ordinary files.
    Copying,
    /// Verifying and publishing the current ordinary file.
    Finalizing,
}

/// Incremental results remain meaningful when the destination root already existed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionDirectorySyncProgress {
    /// Current child phase, which never implies whole-job completion.
    pub phase: SessionDirectorySyncPhase,
    /// Planned Create and Changed files.
    pub files_total: u32,
    /// Planned directory creations.
    pub directories_total: u32,
    /// Confirmed new file publications.
    pub files_created: u32,
    /// Confirmed replacement publications.
    pub files_updated: u32,
    /// Same files verified by successful Apply.
    pub files_skipped: u32,
    /// Confirmed directory creations.
    pub directories_created: u32,
    /// Safe bounded relative name of the current row.
    pub current_name: Option<String>,
    /// Safe bounded relative name where execution first stopped.
    pub failed_name: Option<String>,
    /// Fixed localized failure category.
    pub issue: Option<SessionDirectorySyncIssue>,
}
