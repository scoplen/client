// SPDX-License-Identifier: Apache-2.0

use std::pin::Pin;
use std::task::{Context, Poll};

use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncSeekExt as _, AsyncWrite, ReadBuf};

use super::*;

const SEGMENT_BYTES: u64 = 1024 * 1024;

pub(crate) enum UploadInput {
    New {
        source: Box<UploadSource>,
        directory: Vec<u8>,
        target: Vec<u8>,
        preflight: UploadPreflight,
    },
    Resume(Box<UploadCheckpoint>),
}

pub(crate) enum UploadExecution {
    Paused(Box<UploadCheckpoint>),
    Published,
    Failed { error: FileAccessError, staging_may_remain: bool },
}

/// A live queue capability; paths and digests never leave Rust.
pub(crate) struct UploadCheckpoint {
    session: SftpSession,
    write_handle: Vec<u8>,
    read_handle: Option<Vec<u8>>,
    source: UploadSource,
    staging: Vec<u8>,
    baseline: SftpAttributes,
    target: Vec<u8>,
    preflight: UploadPreflight,
    digest: Sha256,
    offset: u64,
    cleanup_allowed: bool,
}

struct UploadCleanup {
    path: Vec<u8>,
    baseline: SftpAttributes,
}

async fn cleanup_checked(connection: &SshConnection, owned: UploadCleanup) -> bool {
    let cleanup = async {
        let mut session =
            SftpSession::open(connection.authenticated_connection()?, SFTP_PIPELINE).await?;
        let current = inspect_target(&mut session, &owned.path).await?;
        let Some(current) = current else { return Ok(()) };
        if !same_attributes(current, &owned.baseline) {
            return Err(FileAccessError::FileChanged);
        }
        let request = session.client_mut().remove(owned.path)?;
        match response(&mut session, request).await {
            Ok(SftpPacket::Status { code: 0, .. }) | Err(FileAccessError::RemoteStatus(2)) => {
                Ok(())
            }
            Ok(_) => Err(FileAccessError::UnexpectedResponse),
            Err(error) => Err(error),
        }
    };
    matches!(tokio::time::timeout(CLEANUP_TIMEOUT, cleanup).await, Ok(Ok(())))
}

struct HashReader<'a> {
    file: &'a mut File,
    digest: &'a mut Sha256,
}

impl AsyncRead for HashReader<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        match Pin::new(&mut *self.file).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                self.digest.update(&buffer.filled()[before..]);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
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

fn same_attributes(mut current: SftpAttributes, baseline: &SftpAttributes) -> bool {
    current.access_time = baseline.access_time;
    current == *baseline
}

async fn attributes(
    session: &mut SftpSession,
    handle: &[u8],
) -> Result<SftpAttributes, FileAccessError> {
    let request = session.client_mut().fstat(handle.to_vec())?;
    match response(session, request).await? {
        SftpPacket::Attrs { attrs, .. } => Ok(attrs),
        _ => Err(FileAccessError::UnexpectedResponse),
    }
}

async fn admit_read_handle(
    session: &mut SftpSession,
    staging: &[u8],
    baseline: &SftpAttributes,
) -> Result<Option<Vec<u8>>, FileAccessError> {
    let request = session.client_mut().open(staging.to_vec(), 1, SftpAttributes::default())?;
    let handle = match response(session, request).await {
        Ok(SftpPacket::Handle { handle, .. }) => handle,
        Err(FileAccessError::RemoteStatus(_)) => return Ok(None),
        Ok(_) => return Err(FileAccessError::UnexpectedResponse),
        Err(error) => return Err(error),
    };
    let admission = async {
        if !same_attributes(attributes(session, &handle).await?, baseline) {
            return Err(FileAccessError::UnsafeStaging);
        }
        let request = session.client_mut().read(handle.clone(), 0, 1)?;
        match response(session, request).await {
            Err(FileAccessError::RemoteStatus(1)) => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(FileAccessError::UnsafeStaging),
        }
    }
    .await;
    match admission {
        Ok(()) => Ok(Some(handle)),
        Err(FileAccessError::RemoteStatus(_)) => {
            close_handle(session, handle).await?;
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

impl UploadCheckpoint {
    async fn capture_write_baseline(&mut self) -> Result<(), FileAccessError> {
        let current = attributes(&mut self.session, &self.write_handle).await?;
        if kind(&current) != RemoteFileKind::File
            || current.size != Some(self.offset)
            || current.permissions != self.baseline.permissions
            || current.uid_gid != self.baseline.uid_gid
        {
            self.cleanup_allowed = false;
            return Err(FileAccessError::FileChanged);
        }
        self.baseline = current;
        Ok(())
    }

    async fn check_staging(&mut self) -> Result<(), FileAccessError> {
        let write = attributes(&mut self.session, &self.write_handle).await?;
        let valid = kind(&write) == RemoteFileKind::File
            && write.size == Some(self.offset)
            && write.permissions.is_some_and(|mode| mode & 0o077 == 0)
            && same_attributes(write.clone(), &self.baseline);
        if !valid {
            self.cleanup_allowed = false;
            return Err(FileAccessError::FileChanged);
        }
        if let Some(handle) = &self.read_handle {
            let path = inspect_target(&mut self.session, &self.staging).await?;
            if !path.is_some_and(|path| same_attributes(path, &write))
                || !same_attributes(attributes(&mut self.session, handle).await?, &write)
            {
                self.cleanup_allowed = false;
                return Err(FileAccessError::FileChanged);
            }
        }
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), FileAccessError> {
        if supports_extension(&self.session, b"fsync@openssh.com") {
            let request = self.session.client_mut().fsync(self.write_handle.clone())?;
            match response(&mut self.session, request).await? {
                SftpPacket::Status { code: 0, .. } => {}
                _ => return Err(FileAccessError::UnexpectedResponse),
            }
        }
        Ok(())
    }

    async fn validate(&mut self) -> Result<(), FileAccessError> {
        self.source.check_current().await?;
        let target = inspect_target(&mut self.session, &self.target).await?;
        unchanged_target(&self.preflight, target)?;
        self.check_staging().await?;
        let expected = self.digest.clone().finalize();
        self.source.file.seek(std::io::SeekFrom::Start(0)).await?;
        let mut local = Sha256::new();
        let mut left = self.offset;
        let mut buffer = vec![0_u8; READ_CHUNK as usize].into_boxed_slice();
        while left > 0 {
            let count = usize::try_from(left.min(buffer.len() as u64)).expect("bounded read");
            self.source.file.read_exact(&mut buffer[..count]).await?;
            local.update(&buffer[..count]);
            left -= count as u64;
        }
        if local.finalize() != expected {
            return Err(FileAccessError::SourceChanged);
        }
        let mut remote = HashSink::default();
        let started = Instant::now();
        let last = AtomicU64::new(0);
        let transfer = self.session.download_to(
            self.read_handle.as_ref().ok_or(FileAccessError::UnsafeStaging)?,
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
        let count =
            transfer_with_stall_limit(transfer, started, &last, UPLOAD_STALL_TIMEOUT).await?;
        if count != self.offset || remote.0.finalize() != expected {
            self.cleanup_allowed = false;
            return Err(FileAccessError::FileChanged);
        }
        self.source.check_current().await?;
        self.check_staging().await?;
        self.source.file.seek(std::io::SeekFrom::Start(self.offset)).await?;
        Ok(())
    }

    /// A paused checkpoint has no pending exchange; cleanup uses its original channel.
    pub(crate) async fn discard(mut self) -> bool {
        if !self.cleanup_allowed {
            return false;
        }
        let cleanup = async {
            self.check_staging().await?;
            if let Some(handle) = self.read_handle.take() {
                close_handle(&mut self.session, handle).await?;
            }
            close_handle(&mut self.session, self.write_handle.clone()).await?;
            let request = self.session.client_mut().remove(self.staging.clone())?;
            match response(&mut self.session, request).await {
                Ok(SftpPacket::Status { code: 0, .. }) | Err(FileAccessError::RemoteStatus(2)) => {
                    Ok(())
                }
                Ok(_) => Err(FileAccessError::UnexpectedResponse),
                Err(error) => Err(error),
            }
        };
        matches!(tokio::time::timeout(CLEANUP_TIMEOUT, cleanup).await, Ok(Ok(())))
    }
}

async fn prepare(
    connection: &SshConnection,
    input: UploadInput,
    state: &UploadState,
    owned: &mut Option<UploadCleanup>,
) -> Result<(UploadCheckpoint, bool), FileAccessError> {
    let UploadInput::New { source, directory, target, preflight } = input else {
        unreachable!("resume ownership is retained before preparation")
    };
    source.check_current().await?;
    let mut session = tokio::time::timeout(
        SFTP_STEP_TIMEOUT,
        SftpSession::open(connection.authenticated_connection()?, SFTP_PIPELINE),
    )
    .await
    .map_err(|_| FileAccessError::Timeout)??;
    if preflight.target_attributes.is_some()
        && !supports_extension(&session, b"posix-rename@openssh.com")
    {
        return Err(FileAccessError::ReplacementUnsupported);
    }
    let current = inspect_target(&mut session, &target).await?;
    unchanged_target(&preflight, current)?;
    let staging =
        child_path(&directory, format!(".scoplen-upload-{}.part", Uuid::now_v7()).as_bytes())?;
    let request = session.client_mut().open(
        staging.clone(),
        EXCLUSIVE_WRITE_OPEN,
        SftpAttributes { permissions: Some(0o600), ..SftpAttributes::default() },
    )?;
    state.staging_may_remain.store(true, Ordering::SeqCst);
    let mut path = None;
    let write_handle =
        confirm_staging_open(response(&mut session, request).await, staging, &mut path, state)?;
    let baseline = attributes(&mut session, &write_handle).await?;
    if kind(&baseline) != RemoteFileKind::File
        || baseline.size != Some(0)
        || !baseline.permissions.is_some_and(|mode| mode & 0o077 == 0)
    {
        return Err(FileAccessError::UnsafeStaging);
    }
    let staging = path.expect("confirmed owned staging");
    *owned = Some(UploadCleanup { path: staging.clone(), baseline: baseline.clone() });
    let mut read_handle = match admit_read_handle(&mut session, &staging, &baseline).await {
        Ok(handle) => handle,
        Err(error @ FileAccessError::UnsafeStaging) => {
            *owned = None;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    if read_handle.is_some() {
        match inspect_target(&mut session, &staging).await {
            Ok(Some(current)) if same_attributes(current.clone(), &baseline) => {}
            Err(FileAccessError::RemoteStatus(_)) => {
                close_handle(&mut session, read_handle.take().expect("admitted read handle"))
                    .await?;
            }
            Ok(_) => {
                *owned = None;
                return Err(FileAccessError::UnsafeStaging);
            }
            Err(error) => return Err(error),
        }
    }
    Ok((
        UploadCheckpoint {
            session,
            write_handle,
            read_handle,
            source: *source,
            staging,
            baseline,
            target,
            preflight,
            digest: Sha256::new(),
            offset: 0,
            cleanup_allowed: true,
        },
        false,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn transfer_upload<P, A, C>(
    connection: &SshConnection,
    input: UploadInput,
    mut control: watch::Receiver<TransferControl>,
    state: Arc<UploadState>,
    mut progress: P,
    admit_pause: A,
    authorize_publish: C,
) -> UploadExecution
where
    P: FnMut(FileTransferProgress),
    A: FnOnce(),
    C: FnOnce() -> Result<(), FileAccessError>,
{
    let mut owned = None;
    // Resume already owns remote resources even when cancellation wins before work starts.
    let preparation = match input {
        UploadInput::Resume(checkpoint) => {
            state.staging_may_remain.store(true, Ordering::SeqCst);
            Ok((*checkpoint, true))
        }
        input => {
            transfer_controlled(&mut control, prepare(connection, input, &state, &mut owned)).await
        }
    };
    let (mut checkpoint, resuming) = match preparation {
        Ok(prepared) => prepared,
        Err(error) => {
            if let Some(owned) = owned
                && cleanup_checked(connection, owned).await
            {
                state.staging_may_remain.store(false, Ordering::SeqCst);
            }
            return UploadExecution::Failed {
                error,
                staging_may_remain: state.staging_may_remain.load(Ordering::SeqCst),
            };
        }
    };
    if checkpoint.read_handle.is_some() {
        admit_pause();
    }
    let mut reporter = TransferReporter::new(&mut progress);
    let result = async {
        if resuming {
            transfer_controlled(&mut control, checkpoint.validate()).await?;
        }
        loop {
            if *control.borrow() == TransferControl::Cancel || control.has_changed().is_err() {
                return Err(FileAccessError::Cancelled);
            }
            if *control.borrow() == TransferControl::Pause
                && checkpoint.read_handle.is_some()
                && checkpoint.offset > 0
                && checkpoint.offset < checkpoint.source.size
            {
                transfer_controlled(&mut control, async {
                    checkpoint.sync().await?;
                    checkpoint.check_staging().await?;
                    checkpoint.validate().await
                })
                .await?;
                reporter.checkpoint(checkpoint.offset, checkpoint.source.size);
                return Ok(true);
            }
            if checkpoint.offset == checkpoint.source.size {
                break;
            }
            let length = SEGMENT_BYTES.min(checkpoint.source.size - checkpoint.offset);
            let started = Instant::now();
            let last = AtomicU64::new(0);
            let mut reader =
                HashReader { file: &mut checkpoint.source.file, digest: &mut checkpoint.digest };
            let transfer = checkpoint.session.upload_from(
                &checkpoint.write_handle,
                checkpoint.offset,
                length,
                WRITE_CHUNK,
                SFTP_PIPELINE,
                &mut reader,
                |update| {
                    last.store(
                        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                        Ordering::Relaxed,
                    );
                    reporter.transferring(SftpTransferProgress {
                        offset: update.offset,
                        transferred: update.offset,
                        total: Some(checkpoint.source.size),
                    });
                },
            );
            // Both intents settle this bounded helper; dropping it invalidates the channel
            // before its retained write handle can be checked for owned cleanup.
            let count =
                transfer_with_stall_limit(transfer, started, &last, UPLOAD_STALL_TIMEOUT).await?;
            if count != length {
                return Err(FileAccessError::SourceChanged);
            }
            checkpoint.offset += length;
            checkpoint.capture_write_baseline().await?;
        }
        reporter.finalizing(checkpoint.offset, checkpoint.source.size);
        transfer_controlled(&mut control, async {
            checkpoint.source.check_current().await?;
            checkpoint.sync().await?;
            checkpoint.check_staging().await?;
            if let Some(handle) = checkpoint.read_handle.take() {
                close_handle(&mut checkpoint.session, handle).await?;
            }
            close_handle(&mut checkpoint.session, checkpoint.write_handle.clone()).await?;
            let current = inspect_target(&mut checkpoint.session, &checkpoint.target).await?;
            unchanged_target(&checkpoint.preflight, current)
        })
        .await?;
        let request = if checkpoint.preflight.target_attributes.is_some() {
            checkpoint
                .session
                .client_mut()
                .posix_rename(checkpoint.staging.clone(), checkpoint.target.clone())?
        } else {
            checkpoint
                .session
                .client_mut()
                .rename(checkpoint.staging.clone(), checkpoint.target.clone())?
        };
        authorize_publish()?;
        tokio::time::timeout(SFTP_STEP_TIMEOUT, checkpoint.session.send_request(&request))
            .await
            .map_err(|_| FileAccessError::PublicationUnknown)?
            .map_err(|_| FileAccessError::PublicationUnknown)?;
        let acknowledgement =
            tokio::time::timeout(SFTP_STEP_TIMEOUT, checkpoint.session.read_response())
                .await
                .map_err(|_| FileAccessError::PublicationUnknown)?
                .map_err(|_| FileAccessError::PublicationUnknown)?;
        match acknowledgement {
            SftpPacket::Status { code: 0, .. } => Ok(false),
            SftpPacket::Status { code, .. } => Err(FileAccessError::RemoteStatus(code)),
            _ => Err(FileAccessError::PublicationUnknown),
        }
    }
    .await;
    match result {
        Ok(true) => UploadExecution::Paused(Box::new(checkpoint)),
        Ok(false) => {
            state.staging_may_remain.store(false, Ordering::SeqCst);
            UploadExecution::Published
        }
        Err(error) => {
            if !matches!(error, FileAccessError::PublicationUnknown)
                && checkpoint.cleanup_allowed
                && cleanup_checked(
                    connection,
                    UploadCleanup { path: checkpoint.staging, baseline: checkpoint.baseline },
                )
                .await
            {
                state.staging_may_remain.store(false, Ordering::SeqCst);
            }
            UploadExecution::Failed {
                error,
                staging_may_remain: state.staging_may_remain.load(Ordering::SeqCst),
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
