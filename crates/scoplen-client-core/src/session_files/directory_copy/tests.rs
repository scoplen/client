// SPDX-License-Identifier: Apache-2.0

use std::sync::Mutex;

use super::*;
use crate::session_files::directory_sync::tests::{Entry as RemoteEntry, Peer};

fn input(local: &Path, direction: Direction) -> DirectoryCopy {
    DirectoryCopy {
        local: local.to_path_buf(),
        remote: b"./root".to_vec(),
        root_name: b"new-root".to_vec(),
        direction,
    }
}

#[test]
fn manifest_limits_include_root_depth_names_native_mappings_and_collision_keys() {
    let mut tree = Tree::new(0).unwrap();
    let mut parent = 0;
    for _ in 0..MAX_DEPTH {
        tree.push(Some(parent), b"d".to_vec(), "d".into(), EntryKind::Directory, 1).unwrap();
        parent += 1;
    }
    assert_eq!(
        tree.push(Some(parent), b"x".to_vec(), "x".into(), EntryKind::Directory, 1),
        Err(Issue::TooDeep)
    );
    let mut tree = Tree::new(0).unwrap();
    for index in 1..MAX_ENTRIES {
        tree.push(
            Some(0),
            index.to_string().into_bytes(),
            index.to_string().into(),
            EntryKind::Directory,
            1,
        )
        .unwrap();
    }
    assert_eq!(tree.entries.len(), MAX_ENTRIES);
    assert_eq!(
        tree.push(Some(0), b"x".to_vec(), "x".into(), EntryKind::Directory, 1),
        Err(Issue::TooManyEntries)
    );
    let mut tree = Tree::new(MAX_METADATA - 1024).unwrap();
    assert_eq!(
        tree.push(
            Some(0),
            vec![b'a'; 512],
            OsString::from("b".repeat(512)),
            EntryKind::Directory,
            512
        ),
        Err(Issue::TooMuchMetadata)
    );
}

#[test]
fn manifest_retains_parent_indices_and_builds_only_one_current_path() {
    let mut tree = Tree::new(0).unwrap();
    tree.push(Some(0), b"dir".to_vec(), "dir".into(), EntryKind::Directory, 3).unwrap();
    tree.push(
        Some(1),
        b"file".to_vec(),
        "file".into(),
        EntryKind::File { size: 7, local_modified: None, remote_modified: None },
        4,
    )
    .unwrap();
    assert_eq!(tree.remote_path(b"./root", 2).unwrap(), b"./root/dir/file");
    assert_eq!(
        tree.local_path(Path::new("selected"), 2),
        PathBuf::from("selected").join("dir").join("file")
    );
    assert_eq!(tree.display(2), "dir/file");
    assert_eq!((tree.files, tree.directories, tree.bytes), (1, 2, 7));
}

#[tokio::test]
async fn tree_scan_accepts_more_than_the_browser_listing_limit_without_opening_source_files() {
    let root = tempfile::tempdir().unwrap();
    let names = (0..1100).map(|n| format!("file-{n:04}").into_bytes()).collect::<Vec<_>>();
    let entries = names
        .iter()
        .map(|name| (name.as_slice(), RemoteEntry::file(b"binary\0\xff")))
        .collect::<Vec<_>>();
    let peer = Peer::start(&entries).await;
    let (_sender, control) = watch::channel(TransferControl::Run);
    let tree =
        scan(&peer.connection, &input(root.path(), Direction::Download), &control).await.unwrap();
    assert_eq!(tree.entries.len(), 1101);
    assert_eq!(tree.files, 1100);
    assert_eq!(tree.bytes, 1100 * 8);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn local_scan_counts_all_entries_including_empty_directories_and_files() {
    let root = tempfile::tempdir().unwrap();
    tokio::fs::create_dir(root.path().join("empty")).await.unwrap();
    tokio::fs::create_dir(root.path().join("nested")).await.unwrap();
    for n in 0..20 {
        tokio::fs::write(root.path().join("nested").join(format!("file-{n}")), b"bytes")
            .await
            .unwrap();
    }
    tokio::fs::write(root.path().join("zero"), b"").await.unwrap();
    let peer = Peer::start(&[]).await;
    let (_sender, control) = watch::channel(TransferControl::Run);
    let tree =
        scan(&peer.connection, &input(root.path(), Direction::Upload), &control).await.unwrap();
    assert_eq!((tree.files, tree.directories, tree.bytes), (21, 3, 100));
}

#[tokio::test]
async fn remote_scan_cancellation_stops_before_the_next_entry_in_the_same_batch() {
    let root = tempfile::tempdir().unwrap();
    let names = (0..20).map(|n| format!("file-{n:02}").into_bytes()).collect::<Vec<_>>();
    let entries =
        names.iter().map(|name| (name.as_slice(), RemoteEntry::file(b"x"))).collect::<Vec<_>>();
    let peer = Peer::start(&entries).await;
    let (sender, control) = watch::channel(TransferControl::Run);
    peer.cancel_scan_after(1, sender);
    assert!(matches!(
        scan(&peer.connection, &input(root.path(), Direction::Download), &control).await,
        Err(Issue::Cancelled)
    ));
    assert_eq!(peer.listing_attributes(), 1);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn download_rejects_file_directory_case_and_normalization_collisions_before_any_creation() {
    for (file, directory) in
        [(b"A".as_slice(), b"a".as_slice()), ("\u{e9}".as_bytes(), "e\u{301}".as_bytes())]
    {
        let root = tempfile::tempdir().unwrap();
        let peer =
            Peer::start(&[(file, RemoteEntry::file(b"x")), (directory, RemoteEntry::directory())])
                .await;
        let (_sender, control) = watch::channel(TransferControl::Run);
        let effects = Arc::new(AtomicU64::new(0));
        let effect_count = effects.clone();
        let updates = Arc::new(Mutex::new(Vec::new()));
        let seen = updates.clone();
        let result = copy(
            &peer.connection,
            input(root.path(), Direction::Download),
            control,
            Callbacks {
                progress: Arc::new(move |_, _, progress| seen.lock().unwrap().push(progress)),
                authorize: Arc::new(move || {
                    effect_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }),
                settled: Arc::new(|| {}),
                state: Arc::new(UploadState::default()),
            },
        )
        .await;
        assert_eq!(result.issue, Some(Issue::UnsupportedName));
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        assert!(!updates.lock().unwrap().last().unwrap().root_created);
    }
}

#[tokio::test]
async fn complete_download_preserves_binary_zero_files_and_empty_tree_counts() {
    for count in [0, 24] {
        let root = tempfile::tempdir().unwrap();
        let names = (0..count).map(|n| format!("file-{n:02}").into_bytes()).collect::<Vec<_>>();
        let entries = names
            .iter()
            .map(|name| {
                (
                    name.as_slice(),
                    RemoteEntry::file(if name.ends_with(b"00") { b"" } else { &[0, 255, 7] }),
                )
            })
            .collect::<Vec<_>>();
        let peer = Peer::start(&entries).await;
        let (_sender, control) = watch::channel(TransferControl::Run);
        let updates = Arc::new(Mutex::new(Vec::new()));
        let observed = updates.clone();
        let result = copy(
            &peer.connection,
            input(root.path(), Direction::Download),
            control,
            Callbacks {
                progress: Arc::new(move |bytes, total, progress| {
                    observed.lock().unwrap().push((bytes, total, progress))
                }),
                authorize: Arc::new(|| Ok(())),
                settled: Arc::new(|| {}),
                state: Arc::new(UploadState::default()),
            },
        )
        .await;
        assert_eq!(result.issue, None);
        assert!(!result.staging_may_remain);
        let updates = updates.lock().unwrap();
        let (bytes, total, progress) = updates.last().unwrap();
        let expected = if count == 0 { 0 } else { 23 * 3 };
        assert_eq!((*bytes, *total), (expected, Some(expected)));
        assert_eq!((progress.files_total, progress.files_completed), (Some(count), count));
        assert_eq!((progress.directories_total, progress.directories_created), (Some(1), 1));
        assert!(progress.root_created && !progress.root_creation_unknown);
        assert_eq!(
            std::fs::read_dir(root.path().join("new-root")).unwrap().count(),
            count as usize
        );
        if count > 0 {
            assert_eq!(std::fs::read(root.path().join("new-root/file-00")).unwrap(), b"");
            assert_eq!(std::fs::read(root.path().join("new-root/file-23")).unwrap(), [0, 255, 7]);
            assert!(updates.iter().any(|(_, _, progress)| progress.phase == Phase::Finalizing));
        }
    }
}

#[tokio::test]
async fn cancellation_or_context_refusal_preserves_completed_file_and_cleans_only_current_staging()
{
    for cancel in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let peer = Peer::start(&[
            (b"a", RemoteEntry::file(b"first")),
            (b"b", RemoteEntry::file(b"second")),
            (b"c", RemoteEntry::file(b"third")),
        ])
        .await;
        let (sender, control) = watch::channel(TransferControl::Run);
        let effects = Arc::new(AtomicU64::new(0));
        let authorizations = effects.clone();
        let updates = Arc::new(Mutex::new(Vec::new()));
        let observed = updates.clone();
        let result = copy(
            &peer.connection,
            input(root.path(), Direction::Download),
            control,
            Callbacks {
                progress: Arc::new(move |_, _, progress| {
                    if cancel && progress.files_completed == 1 {
                        sender.send_replace(TransferControl::Cancel);
                    }
                    observed.lock().unwrap().push(progress);
                }),
                authorize: Arc::new(move || {
                    if !cancel && authorizations.fetch_add(1, Ordering::SeqCst) == 2 {
                        return Err(FileAccessError::ConnectionEnded);
                    }
                    Ok(())
                }),
                settled: Arc::new(|| {}),
                state: Arc::new(UploadState::default()),
            },
        )
        .await;
        assert_eq!(result.issue, Some(if cancel { Issue::Cancelled } else { Issue::Unavailable }));
        assert!(!result.staging_may_remain);
        let retained = root.path().join("new-root");
        assert_eq!(std::fs::read(retained.join("a")).unwrap(), b"first");
        assert_eq!(std::fs::read_dir(&retained).unwrap().count(), 1);
        let progress = updates.lock().unwrap().last().unwrap().clone();
        assert_eq!((progress.files_completed, progress.directories_created), (1, 1));
        assert!(progress.root_created);
    }
}

#[test]
fn root_names_are_one_explicit_component_and_use_native_download_rules() {
    for name in ["", ".", "..", "a/b", "a\0b"] {
        assert_eq!(root_name(name, Direction::Upload), Err(Issue::UnsupportedName));
    }
    assert_eq!(root_name("new folder", Direction::Download).unwrap(), b"new folder");
    #[cfg(windows)]
    for name in ["CON", "x.", "x:y", "a\\b"] {
        assert_eq!(root_name(name, Direction::Download), Err(Issue::UnsupportedName));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn local_links_and_special_entries_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let link = root.path().join("link");
    std::os::unix::fs::symlink(root.path(), &link).unwrap();
    assert_eq!(local_directory(&link).await, Err(Issue::UnsupportedEntry));
    let peer = Peer::start(&[]).await;
    let (_sender, control) = watch::channel(TransferControl::Run);
    assert!(matches!(
        scan(&peer.connection, &input(root.path(), Direction::Upload), &control).await,
        Err(Issue::UnsupportedEntry)
    ));
}
