// SPDX-License-Identifier: Apache-2.0

//! Explicit native text clipboard writes, without exposing platform diagnostics.

/// The operating system did not accept the clipboard write.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the clipboard is unavailable")]
pub struct ClipboardUnavailable;

/// Replace the native clipboard with text after an explicit user action.
pub fn write_text(text: &str) -> Result<(), ClipboardUnavailable> {
    #[cfg(any(windows, target_os = "macos"))]
    {
        arboard::Clipboard::new()
            .and_then(|mut clipboard| clipboard.set_text(text))
            .map_err(|_| ClipboardUnavailable)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = text;
        Err(ClipboardUnavailable)
    }
}
