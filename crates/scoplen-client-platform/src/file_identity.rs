// SPDX-License-Identifier: Apache-2.0

//! Identity checks for retained local file handles.

use std::{fs::File, io};

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;

/// Compare the native identities of two open ordinary files.
///
/// Both handles stay open throughout the check. Unix compares device and inode;
/// Windows compares the volume serial number and complete 128-bit file identifier.
/// Failure to read an identity is an error, never a metadata-based fallback.
///
/// This does not compare content or reopen paths. Callers must separately reject
/// links and reparse points when opening a path, and validate content and length
/// before continuing a retained transfer. Path changes after this check remain
/// possible; it does not provide an atomic path comparison and replacement.
pub fn same_file(left: &File, right: &File) -> io::Result<bool> {
    let left_metadata = left.metadata()?;
    let right_metadata = right.metadata()?;
    if !left_metadata.is_file() || !right_metadata.is_file() {
        return Err(io::ErrorKind::InvalidInput.into());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok(left_metadata.dev() == right_metadata.dev()
            && left_metadata.ino() == right_metadata.ino())
    }
    #[cfg(windows)]
    {
        windows::same_file(left, right)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(io::ErrorKind::Unsupported.into())
    }
}
