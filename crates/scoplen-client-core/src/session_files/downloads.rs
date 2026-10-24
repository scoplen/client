// SPDX-License-Identifier: Apache-2.0

use std::pin::Pin;
use std::task::{Context, Poll};

use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWrite};

use crate::session_transfers::DownloadDestination;

use super::*;

const SEGMENT_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum DownloadControl {
    Run,
    Pause,
    Cancel,
}

pub(crate) enum DownloadInput {
    New { remote_path: Vec<u8>, destination: DownloadDestination },
    Resume(Box<DownloadCheckpoint>),
}

pub(crate) enum DownloadPreparation {
    New {
        session: Box<SftpSession>,
        handle: Vec<u8>,
        attributes: SftpAttributes,
        destination: DownloadDestination,
    },
    Resume(Box<DownloadCheckpoint>),
}

pub(crate) enum DownloadExecution {
    Paused(Box<DownloadCheckpoint>),
    Ready { prepared: PreparedDownload, destination: DownloadDestination },
    Published { result: SessionDownloadResult, staging_may_remain: bool },
    Failed { error: FileAccessError, staging_may_remain: bool },
}

/// The queue owns this capability while paused; no pathname is sufficient to resume it.
pub(crate) struct DownloadCheckpoint {
    session: SftpSession,
    handle: Vec<u8>,
    attributes: SftpAttributes,
    temporary: TemporaryDownload,
    partial_baseline: Option<DownloadDestination>,
    destination: DownloadDestination,
    digest: Sha256,
    offset: u64,
    total: u64,
}

async fn controlled<T>(
    control: &mut watch::Receiver<DownloadControl>,
    work: impl Future<Output = Result<T, FileAccessError>>,
) -> Result<T, FileAccessError> {
    tokio::pin!(work);
    loop {
        if *control.borrow() == DownloadControl::Cancel {
            return Err(FileAccessError::Cancelled);
        }
        tokio::select! {
            biased;
            result = &mut work => return result,
            changed = control.changed() => {
                if changed.is_err() { return Err(FileAccessError::Cancelled); }
            }
        }
    }
}

struct HashWriter<'a> {
    file: &'a mut File,
    digest: &'a mut Sha256,
}

impl AsyncWrite for HashWriter<'_> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut *self.file).poll_write(cx, bytes) {
            Poll::Ready(Ok(count)) => {
                self.digest.update(&bytes[..count]);
                Poll::Ready(Ok(count))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.file).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.file).poll_shutdown(cx)
    }
}

#[derive(Default)]
struct HashSink(Sha256);

impl AsyncWrite for HashSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.update(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl DownloadCheckpoint {
    async fn check_source(&mut self) -> Result<(), FileAccessError> {
        let request = self.session.client_mut().fstat(self.handle.clone())?;
        match response(&mut self.session, request).await? {
            SftpPacket::Attrs { mut attrs, .. } => {
                // Reading the retained handle may legitimately update access time.
                attrs.access_time = self.attributes.access_time;
                if attrs == self.attributes { Ok(()) } else { Err(FileAccessError::FileChanged) }
            }
            _ => Err(FileAccessError::UnexpectedResponse),
        }
    }

    async fn check_partial(&self) -> Result<(), FileAccessError> {
        check_partial_identity(&self.temporary.path, &self.temporary.identity)?;
        let baseline = self.partial_baseline.as_ref().ok_or(FileAccessError::FileChanged)?;
        baseline.check().await.map_err(|_| FileAccessError::FileChanged)?;
        let file = self.temporary.file.as_ref().ok_or(FileAccessError::FileChanged)?;
        if file.metadata().await?.len() != self.offset {
            return Err(FileAccessError::FileChanged);
        }
        Ok(())
    }

    async fn validate(&mut self) -> Result<(), FileAccessError> {
        self.destination.check().await.map_err(|_| FileAccessError::Conflict)?;
        self.check_source().await?;
        self.check_partial().await?;
        let expected = self.digest.clone().finalize();
        let file = self.temporary.file.as_mut().ok_or(FileAccessError::FileChanged)?;
        file.seek(std::io::SeekFrom::Start(0)).await?;
        let mut local = Sha256::new();
        let mut left = self.offset;
        let mut buffer = vec![0_u8; READ_CHUNK as usize].into_boxed_slice();
        while left > 0 {
            let count = usize::try_from(left.min(buffer.len() as u64)).expect("bounded read");
            file.read_exact(&mut buffer[..count]).await?;
            local.update(&buffer[..count]);
            left -= count as u64;
        }
        if local.finalize() != expected {
            return Err(FileAccessError::FileChanged);
        }
        let mut remote = HashSink::default();
        let started = Instant::now();
        let last = AtomicU64::new(0);
        let transfer = self.session.download_to(
            &self.handle,
            0,
            Some(self.offset),
            READ_CHUNK,
            SFTP_PIPELINE,
            &mut remote,
            |_| {
                last.store(
                    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
            },
        );
        let copied =
            transfer_with_stall_limit(transfer, started, &last, DOWNLOAD_STALL_TIMEOUT).await?;
        if copied != self.offset || remote.0.finalize() != expected {
            return Err(FileAccessError::FileChanged);
        }
        self.check_source().await?;
        self.check_partial().await?;
        self.temporary
            .file
            .as_mut()
            .expect("retained partial")
            .seek(std::io::SeekFrom::Start(self.offset))
            .await?;
        Ok(())
    }

    /// Explicit cleanup settles before the caller releases this item's capacity.
    pub(crate) async fn discard(mut self) -> bool {
        self.temporary.committed = true;
        if let Some(file) = self.temporary.file.take() {
            drop(file.into_std().await);
        }
        remove_owned_partial(&self.temporary.path, &self.temporary.identity)
    }
}

pub(crate) async fn prepare_download(
    connection: &SshConnection,
    input: DownloadInput,
) -> Result<DownloadPreparation, FileAccessError> {
    match input {
        DownloadInput::Resume(checkpoint) => Ok(DownloadPreparation::Resume(checkpoint)),
        DownloadInput::New { remote_path, destination } => {
            validate_path(&remote_path)?;
            let mut session = tokio::time::timeout(
                SFTP_STEP_TIMEOUT,
                SftpSession::open(connection.authenticated_connection()?, SFTP_PIPELINE),
            )
            .await
            .map_err(|_| FileAccessError::Timeout)??;
            let request = session.client_mut().open(remote_path, 1, SftpAttributes::default())?;
            let handle = match response(&mut session, request).await? {
                SftpPacket::Handle { handle, .. } => handle,
                _ => return Err(FileAccessError::UnexpectedResponse),
            };
            let request = session.client_mut().fstat(handle.clone())?;
            let attributes = match response(&mut session, request).await? {
                SftpPacket::Attrs { attrs, .. } => attrs,
                _ => return Err(FileAccessError::UnexpectedResponse),
            };
            if kind(&attributes) != RemoteFileKind::File {
                return Err(FileAccessError::NotRegularFile);
            }
            attributes.size.ok_or(FileAccessError::MissingFileSize)?;
            Ok(DownloadPreparation::New {
                session: Box::new(session),
                handle,
                attributes,
                destination,
            })
        }
    }
}

pub(crate) async fn continue_download<P>(
    prepared: DownloadPreparation,
    control: watch::Receiver<DownloadControl>,
    progress: P,
) -> DownloadExecution
where
    P: FnMut(FileTransferProgress),
{
    continue_download_with(prepared, control, progress, CreatedDownload::create).await
}

async fn continue_download_with<P, C>(
    prepared: DownloadPreparation,
    mut control: watch::Receiver<DownloadControl>,
    mut progress: P,
    create: C,
) -> DownloadExecution
where
    P: FnMut(FileTransferProgress),
    C: FnOnce(PathBuf) -> Result<CreatedDownload, std::io::Error> + Send + 'static,
{
    let (mut checkpoint, resuming) = match prepared {
        DownloadPreparation::Resume(checkpoint) => (*checkpoint, true),
        DownloadPreparation::New { session, handle, attributes, destination } => {
            // Local creation belongs to this task so transport teardown cannot
            // release the queue slot before the creation guard settles cleanup.
            let temporary = match temporary_download_owned_with(destination.path(), create).await {
                Ok(temporary) => temporary,
                Err((error, staging_may_remain)) => {
                    return DownloadExecution::Failed { error, staging_may_remain };
                }
            };
            let total = attributes.size.expect("prepared regular source has a size");
            (
                DownloadCheckpoint {
                    session: *session,
                    handle,
                    attributes,
                    temporary,
                    partial_baseline: None,
                    destination,
                    digest: Sha256::new(),
                    offset: 0,
                    total,
                },
                false,
            )
        }
    };
    let mut reporter = TransferReporter::new(&mut progress);
    let result = async {
        if resuming {
            controlled(&mut control, checkpoint.validate()).await?;
        }
        loop {
            if *control.borrow() == DownloadControl::Cancel {
                return Err(FileAccessError::Cancelled);
            }
            if *control.borrow() == DownloadControl::Pause
                && checkpoint.offset > 0
                && checkpoint.offset < checkpoint.total
            {
                controlled(&mut control, async {
                    checkpoint
                        .temporary
                        .file
                        .as_mut()
                        .expect("retained partial")
                        .sync_all()
                        .await
                        .map_err(FileAccessError::LocalIo)
                })
                .await?;
                checkpoint.check_source().await?;
                check_partial_identity(&checkpoint.temporary.path, &checkpoint.temporary.identity)?;
                if checkpoint
                    .temporary
                    .file
                    .as_ref()
                    .expect("retained partial")
                    .metadata()
                    .await?
                    .len()
                    != checkpoint.offset
                {
                    return Err(FileAccessError::FileChanged);
                }
                checkpoint.partial_baseline = Some(
                    DownloadDestination::capture(checkpoint.temporary.path.clone())
                        .await
                        .map_err(|_| FileAccessError::FileChanged)?,
                );
                reporter.checkpoint(checkpoint.offset, checkpoint.total);
                return Ok(true);
            }
            if checkpoint.offset == checkpoint.total {
                break;
            }
            let end = checkpoint.offset.saturating_add(SEGMENT_BYTES).min(checkpoint.total);
            let started = Instant::now();
            let last = AtomicU64::new(0);
            let mut writer = HashWriter {
                file: checkpoint.temporary.file.as_mut().expect("retained partial"),
                digest: &mut checkpoint.digest,
            };
            let transfer = checkpoint.session.download_to(
                &checkpoint.handle,
                checkpoint.offset,
                Some(end),
                READ_CHUNK,
                SFTP_PIPELINE,
                &mut writer,
                |update| {
                    last.store(
                        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        Ordering::Relaxed,
                    );
                    reporter.transferring(SftpTransferProgress {
                        offset: update.offset,
                        transferred: update.offset,
                        total: Some(checkpoint.total),
                    });
                },
            );
            let count = controlled(
                &mut control,
                transfer_with_stall_limit(transfer, started, &last, DOWNLOAD_STALL_TIMEOUT),
            )
            .await?;
            if count != end - checkpoint.offset {
                return Err(FileAccessError::FileChanged);
            }
            checkpoint.offset = end;
        }
        reporter.finalizing(checkpoint.offset, checkpoint.total);
        checkpoint.check_source().await?;
        close_handle(&mut checkpoint.session, checkpoint.handle.clone()).await?;
        checkpoint.temporary.file.as_mut().expect("retained partial").sync_all().await?;
        Ok::<_, FileAccessError>(false)
    }
    .await;
    match result {
        Ok(true) => DownloadExecution::Paused(Box::new(checkpoint)),
        Ok(false) => {
            checkpoint.temporary.file.take();
            DownloadExecution::Ready {
                prepared: PreparedDownload {
                    temporary: checkpoint.temporary,
                    destination: checkpoint.destination.path().to_path_buf(),
                },
                destination: checkpoint.destination,
            }
        }
        Err(error) => {
            let clean = checkpoint.discard().await;
            DownloadExecution::Failed { error, staging_may_remain: !clean }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
impl DownloadCheckpoint {
    pub(crate) fn test_partial_path(&self) -> &Path {
        &self.temporary.path
    }
}
