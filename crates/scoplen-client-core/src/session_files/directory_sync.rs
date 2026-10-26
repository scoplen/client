// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::ffi::OsString;

use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
use unicode_normalization::UnicodeNormalization as _;

use crate::session_directory_sync::{
    SessionDirectorySyncChange as Change, SessionDirectorySyncEntry,
    SessionDirectorySyncIssue as Issue, SessionDirectorySyncPlan,
};
use crate::session_transfers::{
    DownloadDestination, SessionTransferDirection, SessionTransferIssue,
};

use super::*;

const MAX_FILES: usize = 16;
const MAX_HASH_FILE: u64 = 64 * 1024 * 1024;
const MAX_HASH_TOTAL: u64 = 256 * 1024 * 1024;

pub(crate) struct ComparedFile {
    pub name: Vec<u8>,
    pub remote_path: Vec<u8>,
    pub local: DownloadDestination,
    pub remote: Option<SftpAttributes>,
    pub source: Option<UploadSource>,
    pub change: Change,
    pub size: u64,
    pub target_size: Option<u64>,
}

pub(crate) struct ComparedDirectory {
    pub direction: SessionTransferDirection,
    pub remote_root: Vec<u8>,
    pub local_root: PathBuf,
    source_names: Vec<Vec<u8>>,
    pub rows: Vec<ComparedFile>,
    excluded: u32,
}

impl ComparedDirectory {
    pub(crate) fn snapshot(
        &self,
        session: &str,
        transport: Uuid,
        id: Uuid,
    ) -> SessionDirectorySyncPlan {
        SessionDirectorySyncPlan {
            plan_id: id.to_string(),
            session_id: session.to_owned(),
            transport_id: transport.to_string(),
            direction: self.direction,
            remote_name: display_remote_path(&self.remote_root),
            local_name: display_name(
                self.local_root
                    .file_name()
                    .unwrap_or(OsStr::new("Selected folder"))
                    .to_string_lossy()
                    .as_bytes(),
            ),
            entries: self
                .rows
                .iter()
                .map(|row| SessionDirectorySyncEntry {
                    name: display_name(&row.name),
                    change: row.change,
                    source_size_bytes: row.size.to_string(),
                    target_size_bytes: row.target_size.map(|size| size.to_string()),
                })
                .collect(),
            excluded_directories: self.excluded,
        }
    }

    pub(crate) fn changes(&self) -> usize {
        self.rows.iter().filter(|row| row.change != Change::Same).count()
    }
}

impl From<FileAccessError> for Issue {
    fn from(error: FileAccessError) -> Self {
        match error {
            FileAccessError::TooManyEntries
            | FileAccessError::TooMuchMetadata
            | FileAccessError::ListingIncomplete => Self::TooManyFiles,
            FileAccessError::InvalidPath => Self::UnsupportedName,
            FileAccessError::NotRegularFile
            | FileAccessError::InvalidSource
            | FileAccessError::InvalidDestination => Self::UnsupportedEntry,
            FileAccessError::FileChanged
            | FileAccessError::SourceChanged
            | FileAccessError::Conflict => Self::FileChanged,
            FileAccessError::LocalIo(_) | FileAccessError::LocalSourceIo(_) => Self::LocalIo,
            FileAccessError::Timeout => Self::Timeout,
            FileAccessError::Cancelled => Self::Cancelled,
            FileAccessError::RemoteStatus(_)
            | FileAccessError::Sftp(SftpChannelError::RemoteStatus { .. }) => Self::RemoteDenied,
            FileAccessError::ConnectionEnded | FileAccessError::Connection(_) => Self::Unavailable,
            _ => Self::Failed,
        }
    }
}

impl From<SessionTransferIssue> for Issue {
    fn from(issue: SessionTransferIssue) -> Self {
        match issue {
            SessionTransferIssue::QueueFull | SessionTransferIssue::NativeDialogBusy => {
                Self::QueueFull
            }
            SessionTransferIssue::InvalidSelection | SessionTransferIssue::InvalidPath => {
                Self::InvalidSelection
            }
            SessionTransferIssue::TargetChanged => Self::FileChanged,
            SessionTransferIssue::LocalIo => Self::LocalIo,
            SessionTransferIssue::SessionUnavailable
            | SessionTransferIssue::TransportEnded
            | SessionTransferIssue::StaleItem
            | SessionTransferIssue::InvalidIdentifier => Self::Unavailable,
            _ => Self::Failed,
        }
    }
}

impl From<std::io::Error> for Issue {
    fn from(_: std::io::Error) -> Self {
        Self::LocalIo
    }
}

impl From<SftpError> for Issue {
    fn from(error: SftpError) -> Self {
        FileAccessError::from(error).into()
    }
}

impl From<SftpChannelError> for Issue {
    fn from(error: SftpChannelError) -> Self {
        FileAccessError::from(error).into()
    }
}

impl From<SshConnectionError> for Issue {
    fn from(_: SshConnectionError) -> Self {
        Self::Unavailable
    }
}

async fn local_files(root: &Path) -> Result<(Vec<(Vec<u8>, PathBuf)>, u32), Issue> {
    if !root.is_absolute() || !tokio::fs::metadata(root).await?.is_dir() {
        return Err(Issue::InvalidSelection);
    }
    let mut directory = tokio::fs::read_dir(root).await?;
    let mut files = Vec::new();
    let mut excluded = 0;
    let mut entries = 0;
    let mut bytes = 0_usize;
    while let Some(entry) = directory.next_entry().await? {
        entries += 1;
        bytes =
            bytes.saturating_add(entry.file_name().as_encoded_bytes().len()).saturating_add(128);
        if entries > MAX_DIRECTORY_ENTRIES || bytes > MAX_DIRECTORY_BYTES {
            return Err(Issue::TooManyFiles);
        }
        let metadata = tokio::fs::symlink_metadata(entry.path()).await?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt as _;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(Issue::UnsupportedEntry);
            }
        }
        if metadata.file_type().is_symlink() {
            return Err(Issue::UnsupportedEntry);
        }
        if metadata.is_dir() {
            excluded += 1;
        } else if metadata.is_file() {
            files.push((
                upload_name(&entry.file_name()).map_err(|_| Issue::UnsupportedName)?,
                entry.path(),
            ));
            if files.len() > MAX_FILES {
                return Err(Issue::TooManyFiles);
            }
        } else {
            return Err(Issue::UnsupportedEntry);
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok((files, excluded))
}

async fn remote_files(
    connection: &SshConnection,
    root: &[u8],
) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, u32), Issue> {
    let listing = list_directory_with_policy(connection, root.to_vec(), true).await?;
    let mut files = Vec::new();
    let mut excluded = 0;
    for entry in listing.entries {
        match entry.kind {
            RemoteFileKind::Directory => excluded += 1,
            RemoteFileKind::File => {
                let name = entry
                    .path
                    .rsplit(|byte| *byte == b'/')
                    .next()
                    .ok_or(Issue::UnsupportedName)?
                    .to_vec();
                files.push((name, entry.path));
                if files.len() > MAX_FILES {
                    return Err(Issue::TooManyFiles);
                }
            }
            RemoteFileKind::Other => return Err(Issue::UnsupportedEntry),
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    if files.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(Issue::UnsupportedName);
    }
    Ok((files, excluded))
}

fn native_child(name: &[u8]) -> Result<OsString, Issue> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&0) || name.contains(&b'/')
    {
        return Err(Issue::UnsupportedName);
    }
    #[cfg(unix)]
    let native = {
        use std::os::unix::ffi::OsStringExt as _;
        OsString::from_vec(name.to_vec())
    };
    #[cfg(not(unix))]
    let native = {
        let name = std::str::from_utf8(name).map_err(|_| Issue::UnsupportedName)?;
        if name.chars().any(|ch| ch.is_control() || "<>:\"/\\|?*".contains(ch))
            || name.ends_with(['.', ' '])
        {
            return Err(Issue::UnsupportedName);
        }
        let stem = name.split('.').next().unwrap_or_default().to_ascii_uppercase();
        if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        {
            return Err(Issue::UnsupportedName);
        }
        OsString::from(name)
    };
    let mut components = Path::new(&native).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(Issue::UnsupportedName);
    }
    Ok(native)
}

fn stable_attributes(before: &SftpAttributes, after: &SftpAttributes) -> bool {
    let mut after = after.clone();
    after.access_time = before.access_time;
    &after == before
}

async fn remote_attributes(
    session: &mut SftpSession,
    path: &[u8],
) -> Result<Option<SftpAttributes>, Issue> {
    Ok(inspect_target(session, path).await?)
}

fn ordinary_size(attributes: &SftpAttributes) -> Result<u64, Issue> {
    if kind(attributes) != RemoteFileKind::File {
        return Err(Issue::UnsupportedEntry);
    }
    attributes.size.ok_or(Issue::Failed)
}

async fn local_digest(source: &mut UploadSource) -> Result<[u8; 32], Issue> {
    source.check_current().await?;
    source.file.seek(std::io::SeekFrom::Start(0)).await?;
    let mut digest = Sha256::new();
    let mut left = source.size;
    let mut buffer = vec![0; READ_CHUNK as usize];
    while left > 0 {
        let wanted = left.min(buffer.len() as u64) as usize;
        let count = source.file.read(&mut buffer[..wanted]).await?;
        if count == 0 {
            return Err(Issue::FileChanged);
        }
        digest.update(&buffer[..count]);
        left -= count as u64;
    }
    if source.file.read(&mut buffer[..1]).await? != 0 {
        return Err(Issue::FileChanged);
    }
    source.check_current().await?;
    source.file.seek(std::io::SeekFrom::Start(0)).await?;
    Ok(digest.finalize().into())
}

async fn remote_digest(
    session: &mut SftpSession,
    path: &[u8],
    before: &SftpAttributes,
) -> Result<[u8; 32], Issue> {
    let size = ordinary_size(before)?;
    let request = session.client_mut().open(path.to_vec(), 1, SftpAttributes::default())?;
    let handle = match response(session, request).await? {
        SftpPacket::Handle { handle, .. } => handle,
        _ => return Err(Issue::Failed),
    };
    let request = session.client_mut().fstat(handle.clone())?;
    match response(session, request).await? {
        SftpPacket::Attrs { attrs, .. } if stable_attributes(before, &attrs) => {}
        _ => return Err(Issue::FileChanged),
    }
    let mut sink = downloads::HashSink::default();
    let started = Instant::now();
    let last = AtomicU64::new(0);
    let transfer =
        session.download_to(&handle, 0, Some(size), READ_CHUNK, SFTP_PIPELINE, &mut sink, |_| {
            last.store(
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        });
    let copied =
        transfer_with_stall_limit(transfer, started, &last, DOWNLOAD_STALL_TIMEOUT).await?;
    if copied != size {
        return Err(Issue::FileChanged);
    }
    let request = session.client_mut().read(handle.clone(), size, 1)?;
    if !matches!(response(session, request).await, Err(FileAccessError::RemoteStatus(1))) {
        return Err(Issue::FileChanged);
    }
    let request = session.client_mut().fstat(handle.clone())?;
    match response(session, request).await? {
        SftpPacket::Attrs { attrs, .. } if stable_attributes(before, &attrs) => {}
        _ => return Err(Issue::FileChanged),
    }
    let after = remote_attributes(session, path).await?.ok_or(Issue::FileChanged)?;
    if !stable_attributes(before, &after) {
        return Err(Issue::FileChanged);
    }
    close_handle(session, handle).await?;
    Ok(sink.0.finalize().into())
}

async fn remote_session(connection: &SshConnection, root: &[u8]) -> Result<SftpSession, Issue> {
    validate_path(root)?;
    let mut session = tokio::time::timeout(
        SFTP_STEP_TIMEOUT,
        SftpSession::open(connection.authenticated_connection()?, SFTP_PIPELINE),
    )
    .await
    .map_err(|_| Issue::Timeout)??;
    let root = remote_attributes(&mut session, root).await?.ok_or(Issue::InvalidSelection)?;
    if kind(&root) != RemoteFileKind::Directory {
        return Err(Issue::InvalidSelection);
    }
    Ok(session)
}

pub(crate) async fn compare(
    connection: &SshConnection,
    remote_root: Vec<u8>,
    local_root: PathBuf,
    direction: SessionTransferDirection,
) -> Result<ComparedDirectory, Issue> {
    if !local_root.is_absolute() || !tokio::fs::metadata(&local_root).await?.is_dir() {
        return Err(Issue::InvalidSelection);
    }
    let mut session = remote_session(connection, &remote_root).await?;
    let (files, excluded) = match direction {
        SessionTransferDirection::Upload => {
            let (files, excluded) = local_files(&local_root).await?;
            (
                files
                    .into_iter()
                    .map(|(name, _)| {
                        let path = child_path(&remote_root, &name)?;
                        Ok((name, path))
                    })
                    .collect::<Result<Vec<_>, Issue>>()?,
                excluded,
            )
        }
        SessionTransferDirection::Download => remote_files(connection, &remote_root).await?,
    };
    let source_names = files.iter().map(|(name, _)| name.clone()).collect();
    let mut targets = HashSet::new();
    let mut hashed = 0_u64;
    let mut rows = Vec::with_capacity(files.len());
    for (name, remote_path) in files {
        let local_path = match direction {
            SessionTransferDirection::Upload => {
                #[cfg(unix)]
                let native = {
                    use std::os::unix::ffi::OsStringExt as _;
                    OsString::from_vec(name.clone())
                };
                #[cfg(not(unix))]
                let native =
                    OsString::from(std::str::from_utf8(&name).map_err(|_| Issue::UnsupportedName)?);
                local_root.join(native)
            }
            SessionTransferDirection::Download => {
                let native = native_child(&name)?;
                let key = std::str::from_utf8(&name)
                    .map_err(|_| Issue::UnsupportedName)?
                    .nfd()
                    .flat_map(char::to_uppercase)
                    .nfd()
                    .collect::<String>();
                if !targets.insert(key) {
                    return Err(Issue::UnsupportedName);
                }
                local_root.join(native)
            }
        };
        let local =
            DownloadDestination::capture(local_path.clone()).await.map_err(
                |issue| match issue {
                    SessionTransferIssue::InvalidSelection => Issue::UnsupportedEntry,
                    _ => issue.into(),
                },
            )?;
        let remote = remote_attributes(&mut session, &remote_path).await?;
        let mut source = if direction == SessionTransferDirection::Upload {
            Some(open_upload_source(&local_path).await?)
        } else {
            None
        };
        let size = match direction {
            SessionTransferDirection::Upload => source.as_ref().expect("upload source").size(),
            SessionTransferDirection::Download => {
                ordinary_size(remote.as_ref().ok_or(Issue::FileChanged)?)?
            }
        };
        let target_size = match direction {
            SessionTransferDirection::Upload => remote.as_ref().map(ordinary_size).transpose()?,
            SessionTransferDirection::Download if local.exists() => {
                Some(tokio::fs::symlink_metadata(&local_path).await?.len())
            }
            SessionTransferDirection::Download => None,
        };
        let change = match target_size {
            None => Change::Create,
            Some(target) if target != size => Change::Changed,
            Some(_) => {
                if size > MAX_HASH_FILE
                    || hashed.saturating_add(size.saturating_mul(2)) > MAX_HASH_TOTAL
                {
                    return Err(Issue::TooLarge);
                }
                hashed += size * 2;
                let local_hash = if let Some(source) = source.as_mut() {
                    local_digest(source).await?
                } else {
                    local_digest(&mut open_upload_source(&local_path).await?).await?
                };
                let remote_hash = remote_digest(
                    &mut session,
                    &remote_path,
                    remote.as_ref().ok_or(Issue::FileChanged)?,
                )
                .await?;
                if local_hash == remote_hash { Change::Same } else { Change::Changed }
            }
        };
        local.check().await?;
        rows.push(ComparedFile {
            name,
            remote_path,
            local,
            remote,
            source,
            change,
            size,
            target_size,
        });
    }
    Ok(ComparedDirectory { direction, remote_root, local_root, source_names, rows, excluded })
}

pub(crate) async fn validate(
    connection: &SshConnection,
    plan: &ComparedDirectory,
) -> Result<(), Issue> {
    let current_names = match plan.direction {
        SessionTransferDirection::Upload => local_files(&plan.local_root)
            .await?
            .0
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>(),
        SessionTransferDirection::Download => remote_files(connection, &plan.remote_root)
            .await?
            .0
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>(),
    };
    if current_names != plan.source_names {
        return Err(Issue::FileChanged);
    }
    let mut session = remote_session(connection, &plan.remote_root).await?;
    for row in &plan.rows {
        row.local.check().await?;
        if let Some(source) = &row.source {
            source.check_current().await?;
        }
        let current = remote_attributes(&mut session, &row.remote_path).await?;
        match (&row.remote, current) {
            (None, None) => {}
            (Some(before), Some(after)) if stable_attributes(before, &after) => {}
            _ => return Err(Issue::FileChanged),
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
