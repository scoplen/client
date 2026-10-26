// SPDX-License-Identifier: Apache-2.0

//! Explicit launch of a fixed platform text editor.

use std::path::Path;

/// Start the platform text editor with one literal local path.
///
/// The file extension never selects a program, and no command shell is involved.
/// A successful launch does not prove that a person saved or closed the document.
pub fn open_text_editor(path: &Path) -> std::io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !path.is_absolute() || !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let root = std::env::var_os("SystemRoot")
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        std::process::Command::new(Path::new(&root).join("System32").join("notepad.exe"))
            .arg(path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("/usr/bin/open")
            .args(["-e", "--"])
            .arg(path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other("text editor launch failed"))
        }
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}
