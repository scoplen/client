// SPDX-License-Identifier: Apache-2.0

//! Bounded SFTP file access on the authenticated connection of a live terminal.

use std::future::Future;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use scoplen_ssh::{SftpAttributes, SftpChannelError, SftpError, SftpPacket, SftpSession};
use serde::Serialize;
use specta::Type;
use tokio::fs::File;
use uuid::Uuid;

use crate::connection::{SshConnection, SshConnectionError};

const MAX_REMOTE_PATH: usize = 4096;
const MAX_DIRECTORY_ENTRIES: usize = 1024;
const MAX_DIRECTORY_BYTES: usize = 1024 * 1024;
const MAX_DIRECTORY_BATCHES: usize = 256;
const MAX_DISPLAY_CHARS: usize = 128;
const SFTP_PIPELINE: usize = 4;
const READ_CHUNK: u32 = 32 * 1024;
const SFTP_STEP_TIMEOUT: Duration = Duration::from_secs(15);
const DOWNLOAD_STALL_TIMEOUT: Duration = Duration::from_secs(30);
const REGULAR_FILE: u32 = 0o100000;
const DIRECTORY: u32 = 0o040000;
const FILE_TYPE_MASK: u32 = 0o170000;

/// One remote name keeps its original bytes apart from display text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct RemoteFileEntry {
    /// Bounded display text; the original name remains in `path`.
    pub name: String,
    /// Opaque remote bytes used for subsequent file requests.
    pub path: Vec<u8>,
    /// Entry type reported by the remote server.
    pub kind: RemoteFileKind,
    /// Decimal text preserves the full SFTP 64-bit size in JavaScript.
    pub size_bytes: Option<String>,
}

/// File types supported by the first session Files surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum RemoteFileKind {
    /// A regular file eligible for download.
    File,
    /// A directory eligible for browsing.
    Directory,
    /// An unrecognized type, including symbolic links.
    Other,
}

/// One bounded listing from the current authenticated SSH connection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct RemoteDirectory {
    /// Entries safe to render or submit using their opaque paths.
    pub entries: Vec<RemoteFileEntry>,
}

/// Errors at the boundary of one terminal-owned SFTP request.
#[derive(Debug, thiserror::Error)]
pub enum FileAccessError {
    /// The remote path is empty, over limit, or contains a null byte.
    #[error("the selected remote path is invalid or too long")]
    InvalidPath,
    /// The listing exceeded its entry limit.
    #[error("this directory has too many entries to display")]
    TooManyEntries,
    /// The listing exceeded its metadata byte limit.
    #[error("this directory contains too much file metadata to display")]
    TooMuchMetadata,
    /// The remote server did not complete a bounded listing.
    #[error("the remote directory listing did not finish; try again")]
    ListingIncomplete,
    /// The opened handle is not a regular file.
    #[error("the selected remote item is not a regular file")]
    NotRegularFile,
    /// The remote server did not report the opened file's size.
    #[error("the SSH server did not provide a file size for this download")]
    MissingFileSize,
    /// The bytes or size changed during transfer.
    #[error("the remote file changed while it was being downloaded; try again")]
    FileChanged,
    /// The remote server returned a non-success SFTP status.
    #[error("the SSH server refused the file operation (status {0})")]
    RemoteStatus(u32),
    /// The SFTP response type did not match the request.
    #[error("the SSH server returned an unexpected file response")]
    UnexpectedResponse,
    /// The native picker returned a location that cannot hold a file.
    #[error("the selected local destination is invalid")]
    InvalidDestination,
    /// The owning terminal transport ended before local commit.
    #[error("this connection ended before the file could be saved")]
    ConnectionEnded,
    /// An SFTP step or transfer did not progress by its deadline.
    #[error("the SSH file operation stopped responding; try again")]
    Timeout,
    /// A local filesystem step failed.
    #[error("the local file could not be saved: {0}")]
    LocalIo(#[from] std::io::Error),
    /// The authenticated SSH connection was unavailable.
    #[error("{0}")]
    Connection(#[from] SshConnectionError),
    /// SFTP channel or transfer processing failed.
    #[error("the file transfer failed: {0}")]
    Sftp(#[from] SftpChannelError),
    /// The local SFTP request could not be encoded.
    #[error("the SSH file request is invalid: {0}")]
    Request(#[from] SftpError),
}

pub(crate) fn validate_path(path: &[u8]) -> Result<&[u8], FileAccessError> {
    if path.is_empty() || path.len() > MAX_REMOTE_PATH || path.contains(&0) {
        return Err(FileAccessError::InvalidPath);
    }
    Ok(path)
}

fn display_name(name: &[u8]) -> String {
    let text = String::from_utf8_lossy(name);
    let mut chars = text.chars();
    let mut shown = String::new();
    for character in chars.by_ref().take(MAX_DISPLAY_CHARS) {
        shown.push(
            if character.is_control()
                || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                '\u{fffd}'
            } else {
                character
            },
        );
    }
    if chars.next().is_some() {
        shown.push('…');
    }
    shown
}

fn child_path(parent: &[u8], name: &[u8]) -> Result<Vec<u8>, FileAccessError> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') || name.contains(&0)
    {
        return Err(FileAccessError::InvalidPath);
    }
    let mut path = Vec::with_capacity(parent.len() + name.len() + 1);
    path.extend_from_slice(parent);
    if !path.ends_with(b"/") {
        path.push(b'/');
    }
    path.extend_from_slice(name);
    validate_path(&path)?;
    Ok(path)
}

fn kind(attributes: &SftpAttributes) -> RemoteFileKind {
    match attributes.permissions.map(|permissions| permissions & FILE_TYPE_MASK) {
        Some(REGULAR_FILE) => RemoteFileKind::File,
        Some(DIRECTORY) => RemoteFileKind::Directory,
        _ => RemoteFileKind::Other,
    }
}

async fn response(
    session: &mut SftpSession,
    request: SftpPacket,
) -> Result<SftpPacket, FileAccessError> {
    let response = tokio::time::timeout(SFTP_STEP_TIMEOUT, async {
        session.send_request(&request).await?;
        session.read_response().await
    })
    .await
    .map_err(|_| FileAccessError::Timeout)??;
    match response {
        SftpPacket::Status { code, .. } if code != 0 => Err(FileAccessError::RemoteStatus(code)),
        other => Ok(other),
    }
}

async fn close_handle(session: &mut SftpSession, handle: Vec<u8>) -> Result<(), FileAccessError> {
    let request = session.client_mut().close(handle)?;
    match response(session, request).await? {
        SftpPacket::Status { code: 0, .. } => Ok(()),
        _ => Err(FileAccessError::UnexpectedResponse),
    }
}

async fn transfer_with_stall_limit<T>(
    transfer: impl Future<Output = Result<T, SftpChannelError>>,
    started: Instant,
    last_progress: &AtomicU64,
    limit: Duration,
) -> Result<T, FileAccessError> {
    let watchdog = async {
        loop {
            tokio::time::sleep(limit.min(Duration::from_secs(1))).await;
            let elapsed = started.elapsed().as_millis();
            if elapsed.saturating_sub(u128::from(last_progress.load(Ordering::Relaxed)))
                >= limit.as_millis()
            {
                break;
            }
        }
    };
    tokio::select! {
        result = transfer => Ok(result?),
        _ = watchdog => Err(FileAccessError::Timeout),
    }
}

/// List one remote directory through a fresh SFTP channel on the live connection.
pub async fn list_directory(
    connection: &SshConnection,
    path: Vec<u8>,
) -> Result<RemoteDirectory, FileAccessError> {
    validate_path(&path)?;
    let mut session = tokio::time::timeout(
        SFTP_STEP_TIMEOUT,
        SftpSession::open(connection.authenticated_connection()?, SFTP_PIPELINE),
    )
    .await
    .map_err(|_| FileAccessError::Timeout)??;
    let request = session.client_mut().opendir(path.clone())?;
    let handle = match response(&mut session, request).await? {
        SftpPacket::Handle { handle, .. } => handle,
        _ => return Err(FileAccessError::UnexpectedResponse),
    };
    let mut entries = Vec::new();
    let mut metadata_bytes = 0_usize;
    let mut finished = false;
    for _ in 0..MAX_DIRECTORY_BATCHES {
        let request = session.client_mut().readdir(handle.clone())?;
        match response(&mut session, request).await {
            Ok(SftpPacket::Name { entries: batch, .. }) => {
                if entries.len().saturating_add(batch.len()) > MAX_DIRECTORY_ENTRIES {
                    return Err(FileAccessError::TooManyEntries);
                }
                for item in batch {
                    if let Ok(child) = child_path(&path, &item.filename) {
                        let name = display_name(&item.filename);
                        metadata_bytes = metadata_bytes
                            .saturating_add(item.filename.len())
                            .saturating_add(child.len())
                            .saturating_add(name.len())
                            .saturating_add(128);
                        if metadata_bytes > MAX_DIRECTORY_BYTES {
                            return Err(FileAccessError::TooMuchMetadata);
                        }
                        entries.push(RemoteFileEntry {
                            name,
                            path: child,
                            kind: kind(&item.attrs),
                            size_bytes: item.attrs.size.map(|size| size.to_string()),
                        });
                    }
                }
            }
            Err(FileAccessError::RemoteStatus(1)) => {
                finished = true;
                break;
            }
            Ok(_) => return Err(FileAccessError::UnexpectedResponse),
            Err(error) => return Err(error),
        }
    }
    if !finished {
        return Err(FileAccessError::ListingIncomplete);
    }
    close_handle(&mut session, handle).await?;
    entries.sort_by(|left, right| {
        (left.kind != RemoteFileKind::Directory, left.name.to_lowercase())
            .cmp(&(right.kind != RemoteFileKind::Directory, right.name.to_lowercase()))
    });
    Ok(RemoteDirectory { entries })
}

struct TemporaryDownload {
    path: PathBuf,
    file: Option<File>,
    committed: bool,
}

struct CreatedDownload {
    path: PathBuf,
    file: Option<std::fs::File>,
}

impl CreatedDownload {
    fn create(path: PathBuf) -> Result<Self, std::io::Error> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&path)?;
        Ok(Self { path, file: Some(file) })
    }

    fn into_async(mut self) -> TemporaryDownload {
        let file = File::from_std(self.file.take().expect("created file is open"));
        TemporaryDownload { path: self.path.clone(), file: Some(file), committed: false }
    }
}

impl Drop for CreatedDownload {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            drop(file);
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Drop for TemporaryDownload {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let Some(file) = self.file.take() else {
            let _ = std::fs::remove_file(&self.path);
            return;
        };
        match file.try_into_std() {
            Ok(file) => {
                drop(file);
                let _ = std::fs::remove_file(&self.path);
            }
            Err(file) => {
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    let path = self.path.clone();
                    drop(runtime.spawn(async move {
                        drop(file.into_std().await);
                        let _ = tokio::fs::remove_file(path).await;
                    }));
                } else {
                    drop(file);
                    let _ = std::fs::remove_file(&self.path);
                }
            }
        }
    }
}

async fn temporary_download(destination: &Path) -> Result<TemporaryDownload, FileAccessError> {
    temporary_download_with(destination, CreatedDownload::create).await
}

async fn temporary_download_with<F>(
    destination: &Path,
    create: F,
) -> Result<TemporaryDownload, FileAccessError>
where
    F: FnOnce(PathBuf) -> Result<CreatedDownload, std::io::Error> + Send + 'static,
{
    let parent = destination.parent().ok_or(FileAccessError::InvalidDestination)?;
    if destination.file_name().is_none() {
        return Err(FileAccessError::InvalidDestination);
    }
    let parent = parent.to_path_buf();
    let path = parent.join(format!(".scoplen-download-{}.part", Uuid::now_v7()));
    let created = tokio::task::spawn_blocking(move || {
        if !parent.is_dir() {
            return Err(FileAccessError::InvalidDestination);
        }
        create(path).map_err(FileAccessError::LocalIo)
    })
    .await
    .map_err(|_| std::io::Error::other("temporary file creation was interrupted"))??;
    Ok(created.into_async())
}

/// Download an opened regular file into a private temporary file and commit it through the owner.
pub async fn download_file<F, Fut>(
    connection: &SshConnection,
    remote_path: Vec<u8>,
    destination: &Path,
    commit: F,
) -> Result<(), FileAccessError>
where
    F: FnOnce(PathBuf, PathBuf) -> Fut,
    Fut: Future<Output = Result<(), FileAccessError>>,
{
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
    let size = attributes.size.ok_or(FileAccessError::MissingFileSize)?;
    let mut temporary = temporary_download(destination).await?;
    let started = Instant::now();
    let last_progress = AtomicU64::new(0);
    let transfer = session.download_to(
        &handle,
        0,
        Some(size),
        READ_CHUNK,
        SFTP_PIPELINE,
        temporary.file.as_mut().expect("temporary file is open"),
        |_| {
            last_progress.store(
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        },
    );
    let copied =
        transfer_with_stall_limit(transfer, started, &last_progress, DOWNLOAD_STALL_TIMEOUT)
            .await?;
    if copied != size {
        return Err(FileAccessError::FileChanged);
    }
    let request = session.client_mut().fstat(handle.clone())?;
    match response(&mut session, request).await? {
        SftpPacket::Attrs { attrs, .. } if attrs.size == Some(size) => {}
        SftpPacket::Attrs { .. } => return Err(FileAccessError::FileChanged),
        _ => return Err(FileAccessError::UnexpectedResponse),
    }
    close_handle(&mut session, handle).await?;
    temporary.file.as_mut().expect("temporary file is open").sync_all().await?;
    temporary.file.take();
    commit(temporary.path.clone(), destination.to_path_buf()).await?;
    temporary.committed = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_names_keep_bytes_and_bound_display_text() {
        assert_eq!(child_path(b".", b"\xffname").unwrap(), b"./\xffname");
        assert_eq!(display_name(b"\xff\x1bname"), "��name");
        assert!(child_path(b".", b"../escape").is_err());
        assert!(child_path(b".", b"x/y").is_err());
        assert!(validate_path(&[b'a'; MAX_REMOTE_PATH + 1]).is_err());
        assert!(display_name(&[b'a'; MAX_DISPLAY_CHARS + 3]).ends_with('…'));
    }

    #[tokio::test]
    async fn dropped_download_removes_only_its_temporary_file() {
        let folder = tempfile::tempdir().unwrap();
        let destination = folder.path().join("existing.bin");
        std::fs::write(&destination, b"keep original").unwrap();
        let mut temporary = temporary_download(&destination).await.unwrap();
        let temporary_path = temporary.path.clone();
        use tokio::io::AsyncWriteExt as _;
        temporary.file.as_mut().unwrap().write_all(b"partial").await.unwrap();
        drop(temporary);
        tokio::time::timeout(Duration::from_secs(2), async {
            while temporary_path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(std::fs::read(destination).unwrap(), b"keep original");
    }

    #[tokio::test]
    async fn cancelled_creation_cleans_the_file_created_by_the_blocking_worker() {
        let folder = tempfile::tempdir().unwrap();
        let destination = folder.path().join("download.bin");
        let (created, started) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let pending = tokio::spawn(async move {
            temporary_download_with(&destination, move |path| {
                let guard = CreatedDownload::create(path)?;
                created.send(guard.path.clone()).unwrap();
                released.recv().unwrap();
                Ok(guard)
            })
            .await
        });
        let path = started.await.unwrap();
        assert!(path.exists());
        pending.abort();
        assert!(pending.await.is_err());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn stalled_transfer_is_cancelled_at_the_download_deadline() {
        let progress = AtomicU64::new(0);
        let result = transfer_with_stall_limit(
            std::future::pending::<Result<u64, SftpChannelError>>(),
            Instant::now(),
            &progress,
            Duration::from_millis(50),
        )
        .await;
        assert!(matches!(result, Err(FileAccessError::Timeout)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn download_replacement_stays_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let folder = tempfile::tempdir().unwrap();
        let destination = folder.path().join("existing.bin");
        std::fs::write(&destination, b"original").unwrap();
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut temporary = temporary_download(&destination).await.unwrap();
        assert_eq!(std::fs::metadata(&temporary.path).unwrap().permissions().mode() & 0o077, 0);
        temporary.file.take();
        std::fs::rename(&temporary.path, &destination).unwrap();
        temporary.committed = true;
        assert_eq!(std::fs::read(&destination).unwrap(), b"");
        assert_eq!(std::fs::metadata(destination).unwrap().permissions().mode() & 0o077, 0);
    }
}
