// SPDX-License-Identifier: Apache-2.0

//! Display-only state of a user-selected local working copy.

use serde::Serialize;
use specta::Type;

/// One stage of the explicit local-editor workflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum SessionEditorState {
    /// Selecting or safely downloading the local copy.
    Preparing,
    /// An explicit text-editor launch is pending.
    Opening,
    /// The saved local copy has no detected changes.
    Watching,
    /// Local changes need an explicit upload.
    ChangesDetected,
    /// An explicit upload is waiting in the existing queue.
    Queued,
    /// An explicit upload is executing or awaiting confirmation.
    Uploading,
    /// The latest upload was acknowledged.
    Uploaded,
    /// The copy or its original transport cannot currently be used.
    Unavailable,
    /// Publication needs manual inspection and queue acknowledgement.
    Unknown,
}

/// Fixed operational categories without paths, contents or native errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub enum SessionEditorIssue {
    /// Stop the current editor registration before selecting another copy.
    #[error("this terminal already has a local working copy")]
    AlreadyEditing,
    /// The captured editor, session or transport is unavailable.
    #[error("the local-editor operation is unavailable")]
    Unavailable,
    /// An ordinary local file or destination is required.
    #[error("choose an ordinary local file or destination")]
    InvalidSelection,
    /// The complete file must satisfy the UTF-8 text policy.
    #[error("the working copy is not supported UTF-8 text")]
    NotText,
    /// The complete file exceeds 262,144 bytes.
    #[error("the working copy exceeds the text editing limit")]
    TooLarge,
    /// A local file operation failed.
    #[error("the local working copy could not be accessed")]
    LocalIo,
    /// The saved copy remains available for another explicit launch.
    #[error("the text editor could not be opened")]
    EditorLaunchFailed,
    /// Transfer capacity or the native selection permit is occupied.
    #[error("the file-transfer queue is busy or full")]
    QueueFull,
    /// The transfer failed with a known result.
    #[error("the working-copy transfer failed")]
    TransferFailed,
    /// The reviewed destination changed.
    #[error("the reviewed file destination changed")]
    TargetChanged,
    /// Inspect the remote file and acknowledge the existing transfer reminder.
    #[error("the file publication result is unknown")]
    PublicationUnknown,
}

/// The existing queue row associated with this copy's latest transfer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionEditorTransfer {
    /// Owning queue lifetime.
    pub queue_id: String,
    /// Stable transfer identity.
    pub item_id: String,
    /// Exact execution identity.
    pub execution_id: String,
}

/// A bounded observation; native paths and file contents remain in Rust.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct SessionEditorSnapshot {
    /// Logical terminal owning the working copy.
    pub session_id: String,
    /// Opaque working-copy registration.
    pub editor_id: String,
    /// The original authenticated transport, including after it ends.
    pub transport_id: String,
    /// Safe display of the complete original remote path.
    pub remote_name: String,
    /// Bounded selected local basename, once selected.
    pub local_name: Option<String>,
    /// Current workflow state.
    pub state: SessionEditorState,
    /// Fixed localized operational category.
    pub issue: Option<SessionEditorIssue>,
    /// The retained copy is saved and no transfer or launch is pending.
    pub can_open: bool,
    /// Progress and transfer actions remain on the existing queue row.
    pub transfer: Option<SessionEditorTransfer>,
}

/// Native selection either started one working copy or was cancelled.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum SessionEditorStartResult {
    /// Rust owns the pending download independently of Files visibility.
    Started {
        /// Opaque working-copy registration.
        editor_id: String,
    },
    /// The native save picker was closed without selecting a destination.
    Cancelled,
}
