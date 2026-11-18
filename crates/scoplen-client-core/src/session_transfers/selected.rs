// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::session_files::directory_copy::DirectoryCopy;
use crate::session_files::{DownloadCheckpoint, UploadCheckpoint, UploadSource};

use super::{DownloadDestination, SessionTransferIssue, SessionTransferReview};

pub(crate) type ReplaceConfirmation = Box<
    dyn FnOnce(
            SessionTransferReview,
        ) -> Pin<Box<dyn Future<Output = Result<bool, SessionTransferIssue>> + Send>>
        + Send,
>;

pub(crate) type RepeatedConfirmation = Arc<
    dyn Fn(
            SessionTransferReview,
        ) -> Pin<Box<dyn Future<Output = Result<bool, SessionTransferIssue>> + Send>>
        + Send
        + Sync,
>;

/// Selected handles, paths and native interaction callbacks are never IPC data.
pub(crate) enum SelectedTransfer {
    Directory(DirectoryCopy),
    DirectorySync {
        plan: Box<crate::session_files::directory_sync::ComparedDirectory>,
        confirm: RepeatedConfirmation,
    },
    Upload {
        source: UploadSource,
        directory: Vec<u8>,
        target: Vec<u8>,
        confirm: ReplaceConfirmation,
        editor: Option<uuid::Uuid>,
    },
    Download {
        remote_path: Vec<u8>,
        destination: Box<DownloadDestination>,
        confirm: ReplaceConfirmation,
        editor: Option<uuid::Uuid>,
    },
    ResumeDownload(Box<DownloadCheckpoint>),
    ResumeUpload(Box<UploadCheckpoint>),
}
