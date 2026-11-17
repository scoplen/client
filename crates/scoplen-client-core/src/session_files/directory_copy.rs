// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::ffi::OsString;
use std::time::SystemTime;

use crate::session_directory_copy::{
    SessionDirectoryCopyIssue as Issue, SessionDirectoryCopyPhase as Phase,
    SessionDirectoryCopyProgress as Progress,
};
use crate::session_transfers::{DownloadDestination, SessionTransferDirection as Direction};

use super::*;

const MAX_ENTRIES: usize = 10_000;
const MAX_DEPTH: u8 = 32;
const MAX_METADATA: usize = 16 * 1024 * 1024;
const ENUMERATION_TIMEOUT: Duration = Duration::from_secs(300);

/// The original selected native path and captured remote path never cross IPC.
pub(crate) struct DirectoryCopy {
    pub local: PathBuf,
    pub remote: Vec<u8>,
    pub root_name: Vec<u8>,
    pub direction: Direction,
}

pub(crate) struct DirectoryCopyResult {
    pub issue: Option<Issue>,
    pub staging_may_remain: bool,
}

#[derive(Clone)]
pub(crate) struct Callbacks {
    pub progress: Arc<dyn Fn(u64, Option<u64>, Progress) + Send + Sync>,
    pub authorize: Arc<dyn Fn() -> Result<(), FileAccessError> + Send + Sync>,
    pub settled: Arc<dyn Fn() + Send + Sync>,
    pub state: Arc<UploadState>,
}

#[derive(Clone, Copy)]
enum EntryKind {
    Directory,
    File { size: u64, local_modified: Option<SystemTime>, remote_modified: Option<u32> },
}

struct Entry {
    parent: Option<usize>,
    name: Vec<u8>,
    native: OsString,
    kind: EntryKind,
    depth: u8,
}

struct Tree {
    entries: Vec<Entry>,
    bytes: u64,
    files: u32,
    directories: u32,
    metadata: usize,
}

impl Tree {
    fn new(retained_paths: usize) -> Result<Self, Issue> {
        let mut tree = Self {
            entries: Vec::new(),
            bytes: 0,
            files: 0,
            directories: 0,
            metadata: retained_paths,
        };
        tree.push(None, Vec::new(), OsString::new(), EntryKind::Directory, 0)?;
        Ok(tree)
    }

    fn push(
        &mut self,
        parent: Option<usize>,
        name: Vec<u8>,
        native: OsString,
        kind: EntryKind,
        collision_bytes: usize,
    ) -> Result<(), Issue> {
        let depth = match parent {
            Some(parent) => self.entries[parent].depth + 1,
            None => 0,
        };
        if depth > MAX_DEPTH {
            return Err(Issue::TooDeep);
        }
        if self.entries.len() >= MAX_ENTRIES {
            return Err(Issue::TooManyEntries);
        }
        // Include spare manifest capacity, collision bookkeeping and native encoding.
        self.metadata = self
            .metadata
            .saturating_add(2 * std::mem::size_of::<Entry>() + 64)
            .saturating_add(name.capacity())
            .saturating_add(native.as_encoded_bytes().len().saturating_mul(2))
            .saturating_add(collision_bytes);
        if self.metadata > MAX_METADATA {
            return Err(Issue::TooMuchMetadata);
        }
        match kind {
            EntryKind::Directory => self.directories += 1,
            EntryKind::File { size, .. } => {
                self.files += 1;
                self.bytes = self.bytes.checked_add(size).ok_or(Issue::TooMuchMetadata)?;
            }
        }
        self.entries.push(Entry { parent, name, native, kind, depth });
        Ok(())
    }

    fn ancestors(&self, mut index: usize) -> Vec<usize> {
        let mut entries = Vec::with_capacity(usize::from(MAX_DEPTH));
        while let Some(parent) = self.entries[index].parent {
            entries.push(index);
            index = parent;
        }
        entries.reverse();
        entries
    }

    fn remote_path(&self, root: &[u8], index: usize) -> Result<Vec<u8>, Issue> {
        let mut path = root.to_vec();
        for index in self.ancestors(index) {
            path = child_path(&path, &self.entries[index].name).map_err(Issue::from)?;
        }
        Ok(path)
    }

    fn local_path(&self, root: &Path, index: usize) -> PathBuf {
        let mut path = root.to_path_buf();
        for index in self.ancestors(index) {
            path.push(&self.entries[index].native);
        }
        path
    }

    fn display(&self, index: usize) -> String {
        let mut path = Vec::new();
        for index in self.ancestors(index) {
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(&self.entries[index].name);
        }
        display_name(&path)
    }
}

impl From<FileAccessError> for Issue {
    fn from(error: FileAccessError) -> Self {
        match error {
            FileAccessError::InvalidPath => Self::UnsupportedName,
            FileAccessError::InvalidSource
            | FileAccessError::InvalidDestination
            | FileAccessError::NotRegularFile
            | FileAccessError::UnsupportedEntry => Self::UnsupportedEntry,
            FileAccessError::FileChanged | FileAccessError::SourceChanged => Self::SourceChanged,
            FileAccessError::Conflict => Self::TargetChanged,
            FileAccessError::Timeout => Self::Timeout,
            FileAccessError::Cancelled => Self::Cancelled,
            FileAccessError::PublicationUnknown => Self::PublicationUnknown,
            FileAccessError::ConnectionEnded | FileAccessError::Connection(_) => Self::Unavailable,
            FileAccessError::LocalIo(_) | FileAccessError::LocalSourceIo(_) => Self::LocalIo,
            FileAccessError::RemoteStatus(_)
            | FileAccessError::Sftp(SftpChannelError::RemoteStatus { .. }) => Self::RemoteDenied,
            _ => Self::Failed,
        }
    }
}

impl From<std::io::Error> for Issue {
    fn from(_: std::io::Error) -> Self {
        Self::LocalIo
    }
}

pub(crate) fn root_name(name: &str, direction: Direction) -> Result<Vec<u8>, Issue> {
    let bytes = name.as_bytes();
    child_path(b"/", bytes).map_err(|_| Issue::UnsupportedName)?;
    if direction == Direction::Download {
        directory_sync::native_child(bytes).map_err(|_| Issue::UnsupportedName)?;
        directory_sync::destination_key(bytes).map_err(|_| Issue::UnsupportedName)?;
    }
    Ok(bytes.to_vec())
}

pub(crate) async fn local_directory(path: &Path) -> Result<(), Issue> {
    if !path.is_absolute() {
        return Err(Issue::InvalidSelection);
    }
    let metadata = tokio::fs::symlink_metadata(path).await?;
    ordinary_local(&metadata)?;
    if !metadata.is_dir() {
        return Err(Issue::InvalidSelection);
    }
    Ok(())
}

fn ordinary_local(metadata: &std::fs::Metadata) -> Result<(), Issue> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(Issue::UnsupportedEntry);
        }
    }
    if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
        return Err(Issue::UnsupportedEntry);
    }
    Ok(())
}

fn check_cancel(control: &watch::Receiver<TransferControl>) -> Result<(), Issue> {
    if *control.borrow() == TransferControl::Cancel { Err(Issue::Cancelled) } else { Ok(()) }
}

async fn remote_session(connection: &SshConnection) -> Result<SftpSession, Issue> {
    Ok(tokio::time::timeout(
        SFTP_STEP_TIMEOUT,
        SftpSession::open(
            connection.authenticated_connection().map_err(FileAccessError::from)?,
            SFTP_PIPELINE,
        ),
    )
    .await
    .map_err(|_| Issue::Timeout)?
    .map_err(FileAccessError::from)?)
}

async fn remote_directory(session: &mut SftpSession, path: &[u8]) -> Result<(), Issue> {
    let attributes = inspect_target(session, path).await?.ok_or(Issue::InvalidSelection)?;
    if kind(&attributes) != RemoteFileKind::Directory {
        return Err(Issue::UnsupportedEntry);
    }
    Ok(())
}

async fn scan(
    connection: &SshConnection,
    input: &DirectoryCopy,
    control: &watch::Receiver<TransferControl>,
) -> Result<Tree, Issue> {
    local_directory(&input.local).await?;
    validate_path(&input.remote)?;
    let mut session = remote_session(connection).await?;
    remote_directory(&mut session, &input.remote).await?;
    let mut tree = Tree::new(
        input.local.as_os_str().as_encoded_bytes().len().saturating_mul(4)
            + 3 * input.remote.len()
            + 2 * input.root_name.len(),
    )?;
    let mut parent = 0;
    while parent < tree.entries.len() {
        check_cancel(control)?;
        if !matches!(tree.entries[parent].kind, EntryKind::Directory) {
            parent += 1;
            continue;
        }
        let mut names = HashSet::new();
        match input.direction {
            Direction::Upload => {
                let path = tree.local_path(&input.local, parent);
                local_directory(&path).await?;
                let mut directory = tokio::fs::read_dir(path).await?;
                while let Some(entry) = directory.next_entry().await? {
                    check_cancel(control)?;
                    let native = entry.file_name();
                    let name = upload_name(&native).map_err(|_| Issue::UnsupportedName)?;
                    let remote_parent = tree.remote_path(&input.remote, parent)?;
                    child_path(&remote_parent, &name)?;
                    if !names.insert(name.clone()) {
                        return Err(Issue::UnsupportedName);
                    }
                    let metadata = tokio::fs::symlink_metadata(entry.path()).await?;
                    ordinary_local(&metadata)?;
                    let kind = if metadata.is_dir() {
                        EntryKind::Directory
                    } else {
                        EntryKind::File {
                            size: metadata.len(),
                            local_modified: metadata.modified().ok(),
                            remote_modified: None,
                        }
                    };
                    let collision_bytes = name.len();
                    tree.push(Some(parent), name, native, kind, collision_bytes)?;
                }
            }
            Direction::Download => {
                let path = tree.remote_path(&input.remote, parent)?;
                remote_directory(&mut session, &path).await?;
                let request =
                    session.client_mut().opendir(path.clone()).map_err(FileAccessError::from)?;
                let handle = match response(&mut session, request).await? {
                    SftpPacket::Handle { handle, .. } => handle,
                    _ => return Err(Issue::Failed),
                };
                loop {
                    check_cancel(control)?;
                    let request = session
                        .client_mut()
                        .readdir(handle.clone())
                        .map_err(FileAccessError::from)?;
                    match response(&mut session, request).await {
                        Err(FileAccessError::RemoteStatus(1)) => break,
                        Ok(SftpPacket::Name { entries, .. }) => {
                            for entry in entries {
                                check_cancel(control)?;
                                if entry.filename == b"." || entry.filename == b".." {
                                    continue;
                                }
                                let native = directory_sync::native_child(&entry.filename)
                                    .map_err(|_| Issue::UnsupportedName)?;
                                let key = directory_sync::destination_key(&entry.filename)
                                    .map_err(|_| Issue::UnsupportedName)?;
                                let collision_bytes = key.len();
                                if !names.insert(key.into_bytes()) {
                                    return Err(Issue::UnsupportedName);
                                }
                                let child = child_path(&path, &entry.filename)?;
                                let attributes = inspect_target(&mut session, &child)
                                    .await?
                                    .ok_or(Issue::SourceChanged)?;
                                let kind = match kind(&attributes) {
                                    RemoteFileKind::Directory => EntryKind::Directory,
                                    RemoteFileKind::File => EntryKind::File {
                                        size: attributes.size.ok_or(Issue::Failed)?,
                                        local_modified: None,
                                        remote_modified: attributes.modify_time,
                                    },
                                    RemoteFileKind::Other => return Err(Issue::UnsupportedEntry),
                                };
                                tree.push(
                                    Some(parent),
                                    entry.filename,
                                    native,
                                    kind,
                                    collision_bytes,
                                )?;
                            }
                        }
                        Err(error) => return Err(error.into()),
                        _ => return Err(Issue::Failed),
                    }
                }
                close_handle(&mut session, handle).await?;
            }
        }
        parent += 1;
    }
    Ok(tree)
}

struct Reporter {
    callbacks: Callbacks,
    progress: Progress,
    transferred: u64,
    completed_bytes: u64,
    total: Option<u64>,
}

impl Reporter {
    fn emit(&self) {
        (self.callbacks.progress)(self.transferred, self.total, self.progress.clone());
    }
    fn child(&mut self, update: FileTransferProgress) {
        self.transferred = self.completed_bytes.saturating_add(update.transferred);
        self.progress.phase = match update.phase {
            SessionFileTransferPhase::Transferring => Phase::Copying,
            SessionFileTransferPhase::Finalizing => Phase::Finalizing,
        };
        self.emit();
    }
}

async fn create_remote(
    connection: &SshConnection,
    path: Vec<u8>,
    callbacks: &Callbacks,
    dispatched: Option<Box<dyn FnOnce() + Send>>,
) -> Result<(), Issue> {
    let mut session = remote_session(connection).await?;
    if inspect_target(&mut session, &path).await?.is_some() {
        return Err(Issue::DestinationExists);
    }
    let request = session
        .client_mut()
        .mkdir(path, SftpAttributes::default())
        .map_err(FileAccessError::from)?;
    (callbacks.authorize)()?;
    if let Some(dispatched) = dispatched {
        dispatched();
    }
    let result = async {
        tokio::time::timeout(SFTP_STEP_TIMEOUT, session.send_request(&request))
            .await
            .map_err(|_| Issue::PublicationUnknown)?
            .map_err(|_| Issue::PublicationUnknown)?;
        match tokio::time::timeout(SFTP_STEP_TIMEOUT, session.read_response()).await {
            Ok(Ok(SftpPacket::Status { code: 0, .. })) => Ok(()),
            Ok(Ok(SftpPacket::Status { .. })) => Err(Issue::RemoteDenied),
            _ => Err(Issue::PublicationUnknown),
        }
    }
    .await;
    if result != Err(Issue::PublicationUnknown) {
        (callbacks.settled)();
    }
    result
}

async fn create_local(
    path: PathBuf,
    callbacks: Callbacks,
    dispatched: Option<Box<dyn FnOnce() + Send>>,
) -> Result<(), Issue> {
    let authorize = callbacks.authorize.clone();
    let result = tokio::task::spawn_blocking(move || {
        authorize()?;
        if let Some(dispatched) = dispatched {
            dispatched();
        }
        std::fs::create_dir(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Issue::DestinationExists
            } else {
                Issue::LocalIo
            }
        })
    })
    .await
    .map_err(|_| Issue::PublicationUnknown)?;
    (callbacks.settled)();
    result
}

async fn publish_local(
    prepared: PreparedDownload,
    destination: DownloadDestination,
    callbacks: Callbacks,
) -> Result<(), (Issue, bool)> {
    let authorize = callbacks.authorize.clone();
    let result = tokio::task::spawn_blocking(move || {
        let mut prepared = prepared;
        let result = destination
            .check_before_publication()
            .map_err(|_| Issue::TargetChanged)
            .and_then(|()| authorize().map_err(Issue::from))
            .and_then(|()| prepared.commit_retained().map_err(Issue::from));
        let clean = result.is_ok() || prepared.discard();
        result.map_err(|issue| (issue, !clean))
    })
    .await
    .map_err(|_| (Issue::PublicationUnknown, true))?;
    (callbacks.settled)();
    result
}

async fn execute(
    connection: &SshConnection,
    input: DirectoryCopy,
    control: &mut watch::Receiver<TransferControl>,
    reporter: &mut Reporter,
) -> Result<(), (Issue, bool)> {
    let tree = tokio::time::timeout(ENUMERATION_TIMEOUT, scan(connection, &input, control))
        .await
        .map_err(|_| (Issue::Timeout, false))?
        .map_err(|issue| (issue, false))?;
    check_cancel(control).map_err(|issue| (issue, false))?;
    reporter.progress.files_total = Some(tree.files);
    reporter.progress.directories_total = Some(tree.directories);
    reporter.total = Some(tree.bytes);
    reporter.progress.phase = Phase::Copying;
    reporter.emit();
    let (remote_root, local_root) = match input.direction {
        Direction::Upload => (
            child_path(&input.remote, &input.root_name).map_err(|e| (e.into(), false))?,
            input.local.clone(),
        ),
        Direction::Download => (
            input.remote.clone(),
            input.local.join(
                directory_sync::native_child(&input.root_name)
                    .map_err(|_| (Issue::UnsupportedName, false))?,
            ),
        ),
    };
    // Validate all destination paths before creating the new root.
    for index in 0..tree.entries.len() {
        tree.remote_path(&remote_root, index).map_err(|issue| (issue, false))?;
    }
    let mut remote = remote_session(connection).await.map_err(|issue| (issue, false))?;
    for (index, entry) in tree.entries.iter().enumerate() {
        check_cancel(control).map_err(|issue| (issue, false))?;
        reporter.progress.phase = Phase::Copying;
        reporter.progress.current_name =
            Some(if index == 0 { display_name(&input.root_name) } else { tree.display(index) });
        reporter.emit();
        match entry.kind {
            EntryKind::Directory => {
                let dispatched: Option<Box<dyn FnOnce() + Send>> = if index == 0 {
                    let callbacks = reporter.callbacks.clone();
                    let mut progress = reporter.progress.clone();
                    let transferred = reporter.transferred;
                    let total = reporter.total;
                    Some(Box::new(move || {
                        progress.root_creation_unknown = true;
                        (callbacks.progress)(transferred, total, progress);
                    }))
                } else {
                    None
                };
                let result = match input.direction {
                    Direction::Upload => {
                        create_remote(
                            connection,
                            tree.remote_path(&remote_root, index).map_err(|e| (e, false))?,
                            &reporter.callbacks,
                            dispatched,
                        )
                        .await
                    }
                    Direction::Download => {
                        create_local(
                            tree.local_path(&local_root, index),
                            reporter.callbacks.clone(),
                            dispatched,
                        )
                        .await
                    }
                };
                if index == 0 {
                    reporter.progress.root_creation_unknown =
                        result == Err(Issue::PublicationUnknown);
                }
                result.map_err(|issue| (issue, false))?;
                if index == 0 {
                    reporter.progress.root_created = true;
                }
                reporter.progress.directories_created += 1;
                reporter.emit();
            }
            EntryKind::File { size, local_modified, remote_modified } => {
                let local_path = tree.local_path(&local_root, index);
                let remote_path =
                    tree.remote_path(&remote_root, index).map_err(|issue| (issue, false))?;
                reporter.callbacks.state.staging_may_remain.store(true, Ordering::SeqCst);
                match input.direction {
                    Direction::Upload => {
                        let source =
                            open_upload_source(&local_path).await.map_err(|e| (e.into(), false))?;
                        if source.size != size || source.modified != local_modified {
                            return Err((Issue::SourceChanged, false));
                        }
                        let directory =
                            remote_path.rsplitn(2, |b| *b == b'/').nth(1).unwrap_or(b"/").to_vec();
                        let callbacks = reporter.callbacks.clone();
                        let execution = transfer_upload(
                            connection,
                            UploadInput::New {
                                source: Box::new(source),
                                directory,
                                target: remote_path,
                                preflight: UploadPreflight {
                                    target_attributes: None,
                                    replacement_supported: false,
                                },
                            },
                            control.clone(),
                            Arc::new(UploadState::default()),
                            |update| reporter.child(update),
                            || {},
                            move || (callbacks.authorize)(),
                        )
                        .await;
                        match execution {
                            UploadExecution::Published => (reporter.callbacks.settled)(),
                            UploadExecution::Failed { error, staging_may_remain } => {
                                let issue = Issue::from(error);
                                if issue != Issue::PublicationUnknown {
                                    (reporter.callbacks.settled)();
                                }
                                return Err((issue, staging_may_remain));
                            }
                            UploadExecution::Paused(checkpoint) => {
                                return Err((Issue::Failed, !checkpoint.discard().await));
                            }
                        }
                    }
                    Direction::Download => {
                        let attributes = inspect_target(&mut remote, &remote_path)
                            .await
                            .map_err(|e| (e.into(), false))?
                            .ok_or((Issue::SourceChanged, false))?;
                        if kind(&attributes) != RemoteFileKind::File
                            || attributes.size != Some(size)
                            || attributes.modify_time != remote_modified
                        {
                            return Err((Issue::SourceChanged, false));
                        }
                        let destination = DownloadDestination::capture(local_path)
                            .await
                            .map_err(|_| (Issue::LocalIo, false))?;
                        if destination.exists() {
                            return Err((Issue::TargetChanged, false));
                        }
                        let prepared = prepare_download(
                            connection,
                            DownloadInput::New { remote_path, destination, text_only: false },
                        )
                        .await
                        .map_err(|e| (e.into(), false))?;
                        if let downloads::DownloadPreparation::New { attributes, .. } = &prepared
                            && (attributes.size != Some(size)
                                || attributes.modify_time != remote_modified)
                        {
                            return Err((Issue::SourceChanged, false));
                        }
                        match continue_download(prepared, control.clone(), |update| {
                            reporter.child(update)
                        })
                        .await
                        {
                            DownloadExecution::Ready { prepared, destination } => {
                                publish_local(prepared, destination, reporter.callbacks.clone())
                                    .await?
                            }
                            DownloadExecution::Failed { error, staging_may_remain } => {
                                return Err((error.into(), staging_may_remain));
                            }
                            DownloadExecution::Paused(checkpoint) => {
                                return Err((Issue::Failed, !checkpoint.discard().await));
                            }
                            DownloadExecution::Published { .. } => {
                                return Err((Issue::Failed, true));
                            }
                        }
                    }
                }
                reporter.callbacks.state.staging_may_remain.store(false, Ordering::SeqCst);
                reporter.completed_bytes += size;
                reporter.transferred = reporter.completed_bytes;
                reporter.progress.files_completed += 1;
                reporter.progress.phase = Phase::Copying;
                reporter.emit();
            }
        }
    }
    Ok(())
}

pub(crate) async fn copy(
    connection: &SshConnection,
    input: DirectoryCopy,
    mut control: watch::Receiver<TransferControl>,
    callbacks: Callbacks,
) -> DirectoryCopyResult {
    let mut reporter = Reporter {
        callbacks,
        progress: Progress::default(),
        transferred: 0,
        completed_bytes: 0,
        total: None,
    };
    reporter.emit();
    let result = execute(connection, input, &mut control, &mut reporter).await;
    let (issue, staging_may_remain) = match result {
        Ok(()) => (None, false),
        Err((issue, staging)) => (Some(issue), staging),
    };
    reporter.progress.issue = issue;
    reporter.callbacks.state.staging_may_remain.store(staging_may_remain, Ordering::SeqCst);
    reporter.emit();
    DirectoryCopyResult { issue, staging_may_remain }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fault_tests;
