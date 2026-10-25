// SPDX-License-Identifier: Apache-2.0

//! Native file identity checks through the platform crate's public interface.

use std::fs::{self, File};

use scoplen_client_platform::file_identity::same_file;

#[test]
fn duplicated_and_independently_opened_handles_identify_the_same_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("partial");
    fs::write(&path, b"confirmed prefix").unwrap();
    let retained = File::open(&path).unwrap();
    let duplicated = retained.try_clone().unwrap();
    let reopened = File::open(&path).unwrap();
    assert!(same_file(&retained, &retained).unwrap());
    assert!(same_file(&retained, &duplicated).unwrap());
    assert!(same_file(&retained, &reopened).unwrap());
}

#[test]
fn equal_bytes_in_distinct_files_do_not_establish_identity() {
    let directory = tempfile::tempdir().unwrap();
    let left = directory.path().join("left");
    let right = directory.path().join("right");
    fs::write(&left, b"identical bytes").unwrap();
    fs::write(&right, b"identical bytes").unwrap();
    assert!(!same_file(&File::open(left).unwrap(), &File::open(right).unwrap()).unwrap());
}

#[test]
fn path_replacement_does_not_match_the_retained_handle() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("partial");
    let moved = directory.path().join("moved");
    fs::write(&path, b"same bytes").unwrap();
    let retained = File::open(&path).unwrap();
    fs::rename(&path, &moved).unwrap();
    fs::write(&path, b"same bytes").unwrap();
    assert!(!same_file(&retained, &File::open(path).unwrap()).unwrap());
    assert!(same_file(&retained, &File::open(moved).unwrap()).unwrap());
}

#[test]
fn hard_links_share_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("partial");
    let alias = directory.path().join("alias");
    fs::write(&path, b"confirmed prefix").unwrap();
    fs::hard_link(&path, &alias).unwrap();
    assert!(same_file(&File::open(path).unwrap(), &File::open(alias).unwrap()).unwrap());
}

#[test]
fn identity_is_independent_of_content() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("partial");
    fs::write(&path, b"old prefix").unwrap();
    let retained = File::open(&path).unwrap();
    fs::write(&path, b"new prefix").unwrap();
    assert!(same_file(&retained, &File::open(path).unwrap()).unwrap());
}

#[test]
fn nonordinary_handles_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("partial");
    fs::write(&path, b"confirmed prefix").unwrap();
    let regular = File::open(path).unwrap();
    #[cfg(unix)]
    let directory_handle = File::open(directory.path()).unwrap();
    #[cfg(windows)]
    let directory_handle = {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
            .open(directory.path())
            .unwrap()
    };
    assert_eq!(
        same_file(&regular, &directory_handle).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
}
