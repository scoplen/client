// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::pin::Pin;

use crate::session_files::{DownloadCheckpoint, UploadSource};

use super::{DownloadDestination, SessionTransferIssue, SessionTransferReview};

pub(crate) type ReplaceConfirmation = Box<
    dyn FnOnce(
            SessionTransferReview,
        ) -> Pin<Box<dyn Future<Output = Result<bool, SessionTransferIssue>> + Send>>
        + Send,
>;

/// Selected handles, paths and native interaction callbacks are never IPC data.
pub(crate) enum SelectedTransfer {
    Upload {
        source: UploadSource,
        directory: Vec<u8>,
        confirm: ReplaceConfirmation,
    },
    Download {
        remote_path: Vec<u8>,
        destination: DownloadDestination,
        confirm: ReplaceConfirmation,
    },
    ResumeDownload(Box<DownloadCheckpoint>),
}
