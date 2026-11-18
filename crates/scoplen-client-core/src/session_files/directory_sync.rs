// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::Metadata;

use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
use unicode_normalization::UnicodeNormalization as _;

use crate::session_directory_sync::{
    SessionDirectorySyncChange as Change, SessionDirectorySyncDirectoryChange as DirectoryChange,
    SessionDirectorySyncEntry, SessionDirectorySyncIssue as Issue, SessionDirectorySyncPlan,
    SessionDirectorySyncSummary,
};
use crate::session_transfers::{
    DownloadDestination, SessionTransferDirection, SessionTransferIssue,
};

use super::directory_copy::{self, DirectoryCopy, EntryKind, Tree};
use super::*;

pub(crate) mod execute;

const MAX_HASH_FILE: u64 = 64 * 1024 * 1024;
const MAX_HASH_TOTAL: u64 = 256 * 1024 * 1024;

pub(crate) enum RowChange {
    Directory { create: bool },
    File { change: Change, size: u64, target_size: Option<u64> },
}

pub(crate) struct ComparedRow {
    pub local: Option<Metadata>,
    pub remote: Option<SftpAttributes>,
    pub change: RowChange,
}

pub(crate) struct ComparedDirectory {
    pub direction: SessionTransferDirection,
    pub remote_root: Vec<u8>,
    pub local_root: PathBuf,
    pub(super) tree: Tree,
    pub rows: Vec<ComparedRow>,
    pub summary: SessionDirectorySyncSummary,
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
                .enumerate()
                .map(|(index, row)| {
                    let name = if index == 0 { ".".to_owned() } else { self.tree.display(index) };
                    match row.change {
                        RowChange::Directory { create } => SessionDirectorySyncEntry::Directory {
                            name,
                            change: if create {
                                DirectoryChange::Create
                            } else {
                                DirectoryChange::Existing
                            },
                        },
                        RowChange::File { change, size, target_size } => {
                            SessionDirectorySyncEntry::File {
                                name,
                                change,
                                source_size_bytes: size.to_string(),
                                target_size_bytes: target_size.map(|size| size.to_string()),
                            }
                        }
                    }
                })
                .collect(),
            summary: self.summary.clone(),
        }
    }
    pub(crate) fn changes(&self) -> usize {
        self.rows
            .iter()
            .filter(|row| {
                !matches!(
                    row.change,
                    RowChange::Directory { create: false }
                        | RowChange::File { change: Change::Same, .. }
                )
            })
            .count()
    }
}

impl From<crate::session_directory_copy::SessionDirectoryCopyIssue> for Issue {
    fn from(issue: crate::session_directory_copy::SessionDirectoryCopyIssue) -> Self {
        use crate::session_directory_copy::SessionDirectoryCopyIssue as Copy;
        match issue {
            Copy::TooManyEntries => Self::TooManyEntries,
            Copy::TooDeep => Self::TooDeep,
            Copy::TooMuchMetadata => Self::TooMuchMetadata,
            Copy::InvalidSelection => Self::InvalidSelection,
            Copy::UnsupportedName => Self::UnsupportedName,
            Copy::UnsupportedEntry => Self::UnsupportedEntry,
            Copy::SourceChanged | Copy::TargetChanged | Copy::DestinationExists => {
                Self::FileChanged
            }
            Copy::Timeout => Self::Timeout,
            Copy::Cancelled => Self::Cancelled,
            Copy::Unavailable => Self::Unavailable,
            Copy::LocalIo => Self::LocalIo,
            Copy::RemoteDenied => Self::RemoteDenied,
            Copy::CleanupIncomplete => Self::CleanupIncomplete,
            Copy::PublicationUnknown => Self::PublicationUnknown,
            _ => Self::Failed,
        }
    }
}

impl From<FileAccessError> for Issue {
    fn from(error: FileAccessError) -> Self {
        match error {
            FileAccessError::TooManyEntries => Self::TooManyEntries,
            FileAccessError::TooMuchMetadata => Self::TooMuchMetadata,
            FileAccessError::ListingIncomplete => Self::Failed,
            FileAccessError::PublicationUnknown => Self::PublicationUnknown,
            FileAccessError::InvalidPath => Self::UnsupportedName,
            FileAccessError::NotRegularFile
            | FileAccessError::InvalidSource
            | FileAccessError::InvalidDestination
            | FileAccessError::UnsupportedEntry => Self::UnsupportedEntry,
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
            SessionTransferIssue::TargetChanged | SessionTransferIssue::SourceChanged => {
                Self::FileChanged
            }
            SessionTransferIssue::PublicationUnknown => Self::PublicationUnknown,
            SessionTransferIssue::CleanupIncomplete => Self::CleanupIncomplete,
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

pub(super) fn native_child(name: &[u8]) -> Result<OsString, Issue> {
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

pub(super) fn destination_key(name: &[u8]) -> Result<String, Issue> {
    Ok(std::str::from_utf8(name)
        .map_err(|_| Issue::UnsupportedName)?
        .nfd()
        .flat_map(char::to_uppercase)
        .nfd()
        .collect())
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

async fn open_reviewed_source(
    path: &Path,
    before: &Metadata,
    size: u64,
) -> Result<UploadSource, Issue> {
    let source = open_upload_source(path).await?;
    let opened = source.file.metadata().await?;
    if source.size != size || !metadata_same(before, &opened) {
        return Err(Issue::FileChanged);
    }
    Ok(source)
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

fn metadata_same(before: &Metadata, after: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.mode() != after.mode()
        {
            return false;
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if before.file_attributes() != after.file_attributes() {
            return false;
        }
    }
    before.file_type() == after.file_type()
        && before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
        && before.created().ok() == after.created().ok()
        && before.permissions().readonly() == after.permissions().readonly()
}

async fn local_attributes(path: &Path) -> Result<Option<Metadata>, Issue> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(meta) => {
            directory_copy::ordinary_local(&meta)?;
            Ok(Some(meta))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Issue::LocalIo),
    }
}

fn check_budget(bytes: &mut usize, extra: usize) -> Result<(), Issue> {
    *bytes = bytes.saturating_add(extra);
    if *bytes > directory_copy::MAX_METADATA { Err(Issue::TooMuchMetadata) } else { Ok(()) }
}

async fn source_tree(
    connection: &SshConnection,
    local: &Path,
    remote: &[u8],
    direction: SessionTransferDirection,
) -> Result<Tree, Issue> {
    let (_sender, control) = tokio::sync::watch::channel(TransferControl::Run);
    Ok(directory_copy::scan(
        connection,
        &DirectoryCopy {
            local: local.to_path_buf(),
            remote: remote.to_vec(),
            root_name: Vec::new(),
            direction,
        },
        &control,
    )
    .await?)
}

// Only corresponding destination directories are read; target-only subtrees are preserved.
async fn destination_names(plan: &ComparedDirectory) -> Result<(), Issue> {
    if plan.direction != SessionTransferDirection::Download {
        return Ok(());
    }
    for (parent, entry) in plan.tree.entries.iter().enumerate() {
        if !matches!(entry.kind, EntryKind::Directory) || plan.rows[parent].local.is_none() {
            continue;
        }
        let mut budget = plan.tree.metadata;
        let mut wanted = HashMap::new();
        for child in plan.tree.entries.iter().filter(|entry| entry.parent == Some(parent)) {
            let key = destination_key(&child.name)?;
            check_budget(&mut budget, key.len() + child.name.len() + 96)?;
            wanted.insert(key, &child.name);
        }
        let mut names = tokio::fs::read_dir(plan.tree.local_path(&plan.local_root, parent)).await?;
        while let Some(entry) = names.next_entry().await? {
            let native = entry.file_name();
            let Some(text) = native.to_str() else {
                continue;
            };
            let key = destination_key(text.as_bytes())?;
            if wanted.get(&key).is_some_and(|name| name.as_slice() != text.as_bytes()) {
                return Err(Issue::UnsupportedName);
            }
        }
    }
    Ok(())
}

pub(crate) async fn compare(
    connection: &SshConnection,
    remote_root: Vec<u8>,
    local_root: PathBuf,
    direction: SessionTransferDirection,
) -> Result<ComparedDirectory, Issue> {
    let mut session = remote_session(connection, &remote_root).await?;
    let tree = source_tree(connection, &local_root, &remote_root, direction).await?;
    let mut plan = ComparedDirectory {
        direction,
        remote_root,
        local_root,
        tree,
        rows: Vec::new(),
        summary: SessionDirectorySyncSummary::default(),
    };
    let mut budget = plan.tree.metadata;
    let mut hashed = 0u64;
    let mut transfer = 0u64;
    for (index, entry) in plan.tree.entries.iter().enumerate() {
        let local_path = plan.tree.local_path(&plan.local_root, index);
        let remote_path = plan.tree.remote_path(&plan.remote_root, index)?;
        let local = local_attributes(&local_path).await?;
        let remote = remote_attributes(&mut session, &remote_path).await?;
        check_budget(&mut budget, 2 * std::mem::size_of::<ComparedRow>() + 64)?;
        if let Some(attrs) = &remote {
            for ext in &attrs.extended {
                check_budget(
                    &mut budget,
                    ext.name.capacity() + ext.data.capacity() + 2 * std::mem::size_of_val(ext),
                )?;
            }
        }
        let (source_directory, target_directory, source_size, target_size) = match direction {
            SessionTransferDirection::Upload => {
                let src = local.as_ref().ok_or(Issue::FileChanged)?;
                if remote.as_ref().is_some_and(|attrs| kind(attrs) == RemoteFileKind::Other) {
                    return Err(Issue::UnsupportedEntry);
                }
                (
                    src.is_dir(),
                    remote.as_ref().map(|attrs| kind(attrs) == RemoteFileKind::Directory),
                    src.len(),
                    remote.as_ref().and_then(|attrs| attrs.size),
                )
            }
            SessionTransferDirection::Download => {
                let src = remote.as_ref().ok_or(Issue::FileChanged)?;
                if kind(src) == RemoteFileKind::Other {
                    return Err(Issue::UnsupportedEntry);
                }
                (
                    kind(src) == RemoteFileKind::Directory,
                    local.as_ref().map(Metadata::is_dir),
                    src.size.unwrap_or(0),
                    local.as_ref().map(Metadata::len),
                )
            }
        };
        if source_directory != matches!(entry.kind, EntryKind::Directory)
            || target_directory.is_some_and(|is_dir| is_dir != source_directory)
        {
            return Err(Issue::UnsupportedEntry);
        }
        let change = if source_directory {
            let create = target_directory.is_none();
            if create {
                plan.summary.directories_create += 1;
            } else {
                plan.summary.directories_existing += 1;
            }
            RowChange::Directory { create }
        } else {
            if remote.as_ref().is_some_and(|attrs| attrs.size.is_none()) {
                return Err(Issue::Failed);
            }
            let change = match target_directory {
                None => Change::Create,
                Some(_) if target_size != Some(source_size) => Change::Changed,
                Some(_) => {
                    if source_size > MAX_HASH_FILE
                        || hashed.saturating_add(source_size.saturating_mul(2)) > MAX_HASH_TOTAL
                    {
                        return Err(Issue::TooLarge);
                    }
                    hashed += source_size * 2;
                    let mut source = open_reviewed_source(
                        &local_path,
                        local.as_ref().ok_or(Issue::FileChanged)?,
                        source_size,
                    )
                    .await?;
                    let a = local_digest(&mut source).await?;
                    let b = remote_digest(
                        &mut session,
                        &remote_path,
                        remote.as_ref().ok_or(Issue::FileChanged)?,
                    )
                    .await?;
                    if a == b { Change::Same } else { Change::Changed }
                }
            };
            match change {
                Change::Create => plan.summary.files_create += 1,
                Change::Changed => plan.summary.files_changed += 1,
                Change::Same => plan.summary.files_same += 1,
            }
            if change != Change::Same {
                transfer = transfer.checked_add(source_size).ok_or(Issue::TooLarge)?;
            }
            RowChange::File { change, size: source_size, target_size }
        };
        plan.rows.push(ComparedRow { local, remote, change });
        check_row(connection, &mut session, &plan, index).await?;
    }
    plan.tree.metadata = budget;
    plan.summary.transfer_size_bytes = transfer.to_string();
    destination_names(&plan).await?;
    Ok(plan)
}

pub(super) async fn check_row(
    _connection: &SshConnection,
    session: &mut SftpSession,
    plan: &ComparedDirectory,
    index: usize,
) -> Result<(), Issue> {
    let row = &plan.rows[index];
    let current = local_attributes(&plan.tree.local_path(&plan.local_root, index)).await?;
    match (&row.local, &current) {
        (None, None) => {}
        (Some(a), Some(b)) if metadata_same(a, b) => {}
        _ => return Err(Issue::FileChanged),
    }
    let current =
        remote_attributes(session, &plan.tree.remote_path(&plan.remote_root, index)?).await?;
    match (&row.remote, current) {
        (None, None) => {}
        (Some(a), Some(b)) if stable_attributes(a, &b) => {}
        _ => return Err(Issue::FileChanged),
    }
    Ok(())
}

pub(crate) async fn validate(
    connection: &SshConnection,
    plan: &ComparedDirectory,
) -> Result<(), Issue> {
    let current =
        source_tree(connection, &plan.local_root, &plan.remote_root, plan.direction).await?;
    if current.entries.len() != plan.tree.entries.len() {
        return Err(Issue::FileChanged);
    }
    let expected = plan
        .tree
        .entries
        .iter()
        .enumerate()
        .skip(1)
        .map(|(index, entry)| {
            (
                (entry.parent.expect("nonroot entry"), entry.name.as_slice()),
                (index, matches!(entry.kind, EntryKind::Directory)),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut parents = vec![0usize; current.entries.len()];
    for (index, entry) in current.entries.iter().enumerate().skip(1) {
        let parent = parents[entry.parent.expect("nonroot entry")];
        let Some(&(planned, directory)) = expected.get(&(parent, entry.name.as_slice())) else {
            return Err(Issue::FileChanged);
        };
        if directory != matches!(entry.kind, EntryKind::Directory) {
            return Err(Issue::FileChanged);
        }
        parents[index] = planned;
    }
    let mut remote = remote_session(connection, &plan.remote_root).await?;
    for index in 0..plan.rows.len() {
        check_row(connection, &mut remote, plan, index).await?;
    }
    destination_names(plan).await?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
