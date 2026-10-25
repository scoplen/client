// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::{MAX_NAME_CHARACTERS, SessionTransferIssue, display_text};

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileFingerprint {
    size: u64,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
    readonly: bool,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    attributes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DestinationBaseline {
    Missing,
    File(FileFingerprint),
}

fn fingerprint(metadata: std::fs::Metadata) -> Result<DestinationBaseline, SessionTransferIssue> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(SessionTransferIssue::InvalidSelection);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(SessionTransferIssue::InvalidSelection);
        }
    }
    Ok(DestinationBaseline::File(FileFingerprint {
        size: metadata.len(),
        modified: metadata.modified().ok(),
        created: metadata.created().ok(),
        readonly: metadata.permissions().readonly(),
        #[cfg(unix)]
        device: {
            use std::os::unix::fs::MetadataExt as _;
            metadata.dev()
        },
        #[cfg(unix)]
        inode: {
            use std::os::unix::fs::MetadataExt as _;
            metadata.ino()
        },
        #[cfg(windows)]
        attributes: {
            use std::os::windows::fs::MetadataExt as _;
            metadata.file_attributes()
        },
    }))
}

fn baseline(
    result: Result<std::fs::Metadata, std::io::Error>,
) -> Result<DestinationBaseline, SessionTransferIssue> {
    match result {
        Ok(metadata) => fingerprint(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(DestinationBaseline::Missing)
        }
        Err(_) => Err(SessionTransferIssue::LocalIo),
    }
}

/// The native destination and its visible metadata stay in the Rust owner.
#[derive(Clone)]
pub(crate) struct DownloadDestination {
    path: PathBuf,
    baseline: DestinationBaseline,
}

impl DownloadDestination {
    pub async fn capture(path: PathBuf) -> Result<Self, SessionTransferIssue> {
        if path.file_name().is_none() || !path.is_absolute() {
            return Err(SessionTransferIssue::InvalidSelection);
        }
        let parent = path.parent().ok_or(SessionTransferIssue::InvalidSelection)?;
        if !tokio::fs::metadata(parent).await.map_err(|_| SessionTransferIssue::LocalIo)?.is_dir() {
            return Err(SessionTransferIssue::InvalidSelection);
        }
        let selected = baseline(tokio::fs::symlink_metadata(&path).await)?;
        Ok(Self { path, baseline: selected })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn display_name(&self) -> String {
        display_text(
            &self.path.file_name().expect("selected destination has a filename").to_string_lossy(),
            MAX_NAME_CHARACTERS,
        )
    }

    pub fn exists(&self) -> bool {
        matches!(self.baseline, DestinationBaseline::File(_))
    }

    pub async fn check(&self) -> Result<(), SessionTransferIssue> {
        self.compare(baseline(tokio::fs::symlink_metadata(&self.path).await))
    }

    /// Called in the blocking publication step immediately before its rename.
    pub fn check_before_publication(&self) -> Result<(), SessionTransferIssue> {
        self.compare(baseline(std::fs::symlink_metadata(&self.path)))
    }

    fn compare(
        &self,
        current: Result<DestinationBaseline, SessionTransferIssue>,
    ) -> Result<(), SessionTransferIssue> {
        match current {
            Ok(current) if current == self.baseline => Ok(()),
            Ok(_) | Err(SessionTransferIssue::InvalidSelection) => {
                Err(SessionTransferIssue::TargetChanged)
            }
            Err(issue) => Err(issue),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_target_is_retained_as_absent_until_publication() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("download.bin");
        let destination = DownloadDestination::capture(path.clone()).await.unwrap();
        assert!(!destination.exists());
        destination.check().await.unwrap();
        destination.check_before_publication().unwrap();
        tokio::fs::write(path, b"new local data").await.unwrap();
        assert_eq!(destination.check().await, Err(SessionTransferIssue::TargetChanged));
        assert_eq!(
            destination.check_before_publication(),
            Err(SessionTransferIssue::TargetChanged)
        );
    }

    #[tokio::test]
    async fn existing_target_changes_or_removal_conflict() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("existing.bin");
        tokio::fs::write(&path, b"original").await.unwrap();
        let destination = DownloadDestination::capture(path.clone()).await.unwrap();
        assert!(destination.exists());
        destination.check().await.unwrap();
        tokio::fs::write(&path, b"changed local content").await.unwrap();
        assert_eq!(destination.check().await, Err(SessionTransferIssue::TargetChanged));
        tokio::fs::remove_file(path).await.unwrap();
        assert_eq!(
            destination.check_before_publication(),
            Err(SessionTransferIssue::TargetChanged)
        );
    }

    #[tokio::test]
    async fn directories_and_non_file_destinations_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            DownloadDestination::capture(directory.path().to_path_buf()).await,
            Err(SessionTransferIssue::InvalidSelection)
        ));
        assert!(matches!(
            DownloadDestination::capture(PathBuf::from("relative.bin")).await,
            Err(SessionTransferIssue::InvalidSelection)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn links_are_never_selected_or_published_through() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.bin");
        let link = directory.path().join("download.bin");
        tokio::fs::write(&target, b"original").await.unwrap();
        let destination = DownloadDestination::capture(link.clone()).await.unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(destination.check().await, Err(SessionTransferIssue::TargetChanged));
        assert!(matches!(
            DownloadDestination::capture(link).await,
            Err(SessionTransferIssue::InvalidSelection)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_replaced_file_has_a_different_native_identity() {
        use std::os::unix::fs::MetadataExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("download.bin");
        let retained = directory.path().join("retained.bin");
        tokio::fs::write(&path, b"same bytes").await.unwrap();
        let destination = DownloadDestination::capture(path.clone()).await.unwrap();
        std::fs::rename(&path, &retained).unwrap();
        tokio::fs::write(&path, b"same bytes").await.unwrap();
        assert_ne!(
            std::fs::metadata(&path).unwrap().ino(),
            std::fs::metadata(retained).unwrap().ino()
        );
        assert_eq!(
            destination.check_before_publication(),
            Err(SessionTransferIssue::TargetChanged)
        );
    }
}
