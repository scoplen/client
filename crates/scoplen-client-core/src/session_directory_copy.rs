// SPDX-License-Identifier: Apache-2.0

//! Review and progress for a single explicitly directed directory copy.

use serde::Serialize;
use specta::Type;

use crate::session_transfers::SessionTransferDirection;

/// Fixed operational categories; native paths and peer errors remain in Rust.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub enum SessionDirectoryCopyIssue {
    /// The original session, account or transport is no longer current.
    #[error("this directory copy is unavailable")]
    Unavailable,
    /// Choose an existing ordinary source directory or destination parent.
    #[error("choose an existing ordinary directory")]
    InvalidSelection,
    /// The prepared native selection expired.
    #[error("choose the directory again")]
    SelectionExpired,
    /// Links, reparse points and special entries cannot be copied.
    #[error("the source contains an unsupported entry")]
    UnsupportedEntry,
    /// A name is invalid, cannot map losslessly or collides at the destination.
    #[error("a name cannot be used at the destination")]
    UnsupportedName,
    /// A new root is required; existing destinations are never adopted.
    #[error("the destination root already exists; choose a new name")]
    DestinationExists,
    /// The source contains more than the bounded entry count.
    #[error("the source contains too many entries")]
    TooManyEntries,
    /// The source exceeds the maximum directory depth.
    #[error("the source is nested too deeply")]
    TooDeep,
    /// The retained tree metadata exceeds its bound.
    #[error("the source contains too much filename metadata")]
    TooMuchMetadata,
    /// Enumeration or an existing request deadline expired.
    #[error("the directory copy timed out")]
    Timeout,
    /// Explicit cancellation settled before the next publication.
    #[error("the directory copy was cancelled")]
    Cancelled,
    /// A source stopped matching the admitted ordinary file.
    #[error("the source changed during the directory copy")]
    SourceChanged,
    /// The destination stopped matching the admitted new target.
    #[error("the destination changed during the directory copy")]
    TargetChanged,
    /// There is no outstanding transfer slot available.
    #[error("the file-transfer queue is full")]
    QueueFull,
    /// Another native selection or confirmation still owns the dialog permit.
    #[error("finish the current file selection or confirmation first")]
    NativeDialogBusy,
    /// A native filesystem operation failed.
    #[error("the local directory operation failed")]
    LocalIo,
    /// The peer explicitly rejected an operation.
    #[error("the SSH server refused the directory operation")]
    RemoteDenied,
    /// Cleanup of the current owned staging file could not be confirmed.
    #[error("temporary file cleanup could not be confirmed")]
    CleanupIncomplete,
    /// A dispatched mkdir or file publication has an unknown result.
    #[error("the destination result is unknown; review it before trying again")]
    PublicationUnknown,
    /// The copy could not complete.
    #[error("the directory copy failed")]
    Failed,
}

/// Native paths stay with the prepared Rust owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionDirectoryCopySelection {
    /// Single-use, short-lived selection identity.
    pub selection_id: String,
    /// Original logical terminal.
    pub session_id: String,
    /// Original authenticated SSH transport.
    pub transport_id: String,
    /// Explicit source-to-destination direction.
    pub direction: SessionTransferDirection,
    /// Safe bounded source basename.
    pub source_name: String,
    /// Safe bounded destination-parent basename.
    pub destination_parent_name: String,
    /// Lossless valid source basename, when available.
    pub default_root_name: Option<String>,
}

/// Selection does not scan or create a destination.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SessionDirectoryCopyPrepareResult {
    /// Ready for explicit review of the new destination root.
    Prepared {
        /// Bounded display-only selection.
        selection: SessionDirectoryCopySelection,
    },
    /// The native folder picker was closed.
    Cancelled,
}

/// Phase within one queue-owned recursive copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum SessionDirectoryCopyPhase {
    /// Complete source enumeration precedes root creation.
    Scanning,
    /// Creating directories or copying ordinary file contents.
    Copying,
    /// Verifying and publishing the current ordinary file.
    Finalizing,
}

/// Aggregate tree progress for one stable queue item and execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionDirectoryCopyProgress {
    /// Current tree phase; a phase alone never implies success.
    pub phase: SessionDirectoryCopyPhase,
    /// Complete source-file count, after enumeration.
    pub files_total: Option<u32>,
    /// Complete directory count including the source root, after enumeration.
    pub directories_total: Option<u32>,
    /// Files with confirmed publication.
    pub files_completed: u32,
    /// Directories with confirmed successful creation.
    pub directories_created: u32,
    /// Safe bounded relative display name for the current entry.
    pub current_name: Option<String>,
    /// The new root's creation was acknowledged.
    pub root_created: bool,
    /// The root may exist, but its creation acknowledgement was lost.
    pub root_creation_unknown: bool,
    /// Specific directory-copy failure, when present.
    pub issue: Option<SessionDirectoryCopyIssue>,
}

impl Default for SessionDirectoryCopyProgress {
    fn default() -> Self {
        Self {
            phase: SessionDirectoryCopyPhase::Scanning,
            files_total: None,
            directories_total: None,
            files_completed: 0,
            directories_created: 0,
            current_name: None,
            root_created: false,
            root_creation_unknown: false,
            issue: None,
        }
    }
}
