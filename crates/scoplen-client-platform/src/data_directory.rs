// SPDX-License-Identifier: Apache-2.0
//! Resolve the desktop's application data root without creating an application window.

use std::path::PathBuf;

/// The operating system's roaming application-data directory, without creating it.
/// Returns `None` on unsupported platforms or when the directory cannot be resolved.
pub fn application_data_root() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        windows::root()
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").filter(|home| !home.is_empty())?;
        Some(PathBuf::from(home).join("Library/Application Support"))
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        None
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use super::*;
    use ::windows::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_RoamingAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath},
    };
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};

    pub(super) fn root() -> Option<PathBuf> {
        // SAFETY: The folder GUID is static, no token is retained, and the returned
        // COM-allocated string is copied before being freed with CoTaskMemFree.
        let folder =
            unsafe { SHGetKnownFolderPath(&FOLDERID_RoamingAppData, KF_FLAG_DEFAULT, None) }
                .ok()?;
        if folder.is_null() {
            return None;
        }
        // SAFETY: A successful SHGetKnownFolderPath returns a valid NUL-terminated
        // UTF-16 allocation. The slice is used only before releasing that allocation.
        let path = unsafe { PathBuf::from(OsString::from_wide(folder.as_wide())) };
        // SAFETY: This is the original allocation returned by SHGetKnownFolderPath;
        // it has not been freed and is no longer borrowed after the copied path above.
        unsafe { CoTaskMemFree(Some(folder.0.cast())) };
        Some(path)
    }
}
