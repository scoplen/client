// SPDX-License-Identifier: Apache-2.0

//! Complete, bounded text disclosure through a dedicated SFTP channel.

use super::*;

const MAX_PREVIEW_BYTES: usize = 256 * 1024;

/// Transient complete text, never included in session status or diagnostics.
#[derive(Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct RemoteTextPreview {
    /// Literal UTF-8 text; the interface must not interpret markup or escapes.
    pub text: String,
    /// Original byte length, including line endings.
    pub size_bytes: u32,
}

impl std::fmt::Debug for RemoteTextPreview {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteTextPreview")
            .field("size_bytes", &self.size_bytes)
            .finish_non_exhaustive()
    }
}

/// Localized preview refusals contain no remote contents or server-supplied status text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum RemoteTextPreviewIssue {
    /// The entry is not an ordinary remote file.
    NotRegularFile,
    /// The server omitted required ordinary-file metadata.
    MissingMetadata,
    /// The complete file exceeds the preview byte bound.
    TooLarge,
    /// The reported file or EOF changed during reading.
    FileChanged,
    /// UTF-8 or supported text-control validation failed.
    NotText,
    /// A bounded request or complete operation timed out.
    Timeout,
    /// The person cancelled this request.
    Cancelled,
    /// This transport or its file-operation admission is unavailable.
    Unavailable,
    /// The SSH server refused a file request.
    RemoteDenied,
    /// The request could not complete safely.
    Failed,
}

impl From<FileAccessError> for RemoteTextPreviewIssue {
    fn from(error: FileAccessError) -> Self {
        match error {
            FileAccessError::NotRegularFile => Self::NotRegularFile,
            FileAccessError::MissingFileSize => Self::MissingMetadata,
            FileAccessError::PreviewTooLarge => Self::TooLarge,
            FileAccessError::PreviewNotText => Self::NotText,
            FileAccessError::FileChanged => Self::FileChanged,
            FileAccessError::Timeout => Self::Timeout,
            FileAccessError::Cancelled => Self::Cancelled,
            FileAccessError::ConnectionEnded | FileAccessError::Connection(_) => Self::Unavailable,
            FileAccessError::RemoteStatus(_)
            | FileAccessError::Sftp(SftpChannelError::RemoteStatus { .. }) => Self::RemoteDenied,
            _ => Self::Failed,
        }
    }
}

fn admitted_size(attributes: &SftpAttributes) -> Result<usize, FileAccessError> {
    if kind(attributes) != RemoteFileKind::File {
        return Err(FileAccessError::NotRegularFile);
    }
    let size = attributes.size.ok_or(FileAccessError::MissingFileSize)?;
    if size > MAX_PREVIEW_BYTES as u64 {
        return Err(FileAccessError::PreviewTooLarge);
    }
    Ok(size as usize)
}

fn unchanged(before: &SftpAttributes, after: &SftpAttributes) -> Result<(), FileAccessError> {
    if kind(after) != RemoteFileKind::File
        || before.size != after.size
        || before.modify_time != after.modify_time
    {
        return Err(FileAccessError::FileChanged);
    }
    Ok(())
}

fn text(bytes: Vec<u8>) -> Result<RemoteTextPreview, FileAccessError> {
    let size_bytes = u32::try_from(bytes.len()).map_err(|_| FileAccessError::PreviewTooLarge)?;
    if bytes.len() > MAX_PREVIEW_BYTES {
        return Err(FileAccessError::PreviewTooLarge);
    }
    let text = String::from_utf8(bytes).map_err(|_| FileAccessError::PreviewNotText)?;
    if text.chars().any(|character| {
        matches!(character, '\0'..='\u{1f}' | '\u{7f}'..='\u{9f}')
            && !matches!(character, '\t' | '\r' | '\n')
    }) {
        return Err(FileAccessError::PreviewNotText);
    }
    Ok(RemoteTextPreview { text, size_bytes })
}

async fn attributes(
    session: &mut SftpSession,
    request: SftpPacket,
) -> Result<SftpAttributes, FileAccessError> {
    match response(session, request).await? {
        SftpPacket::Attrs { attrs, .. } => Ok(attrs),
        _ => Err(FileAccessError::UnexpectedResponse),
    }
}

pub(crate) async fn preview_file(
    connection: &SshConnection,
    path: Vec<u8>,
) -> Result<RemoteTextPreview, FileAccessError> {
    validate_path(&path)?;
    let mut session = tokio::time::timeout(
        SFTP_STEP_TIMEOUT,
        SftpSession::open(connection.authenticated_connection()?, 1),
    )
    .await
    .map_err(|_| FileAccessError::Timeout)??;
    let request = session.client_mut().lstat(path.clone())?;
    let before = attributes(&mut session, request).await?;
    let size = admitted_size(&before)?;
    let request = session.client_mut().open(path.clone(), 1, SftpAttributes::default())?;
    let handle = match response(&mut session, request).await? {
        SftpPacket::Handle { handle, .. } => handle,
        _ => return Err(FileAccessError::UnexpectedResponse),
    };
    let request = session.client_mut().fstat(handle.clone())?;
    let opened = attributes(&mut session, request).await?;
    unchanged(&before, &opened)?;
    let mut bytes = Vec::with_capacity(size);
    let chunk_size = session.limits().map_or(u64::from(READ_CHUNK), |limits| {
        u64::from(READ_CHUNK)
            .min(limits.max_read_length)
            .min(limits.max_packet_length.saturating_sub(64))
    }) as usize;
    if chunk_size == 0 {
        return Err(FileAccessError::UnexpectedResponse);
    }
    while bytes.len() < size {
        let length = chunk_size.min(size - bytes.len());
        let request =
            session.client_mut().read(handle.clone(), bytes.len() as u64, length as u32)?;
        match response(&mut session, request).await {
            Ok(SftpPacket::Data { data, .. }) if !data.is_empty() && data.len() <= length => {
                bytes.extend_from_slice(&data);
            }
            Err(FileAccessError::RemoteStatus(1)) => return Err(FileAccessError::FileChanged),
            Ok(_) => return Err(FileAccessError::UnexpectedResponse),
            Err(error) => return Err(error),
        }
    }
    let request = session.client_mut().read(handle.clone(), size as u64, 1)?;
    match response(&mut session, request).await {
        Err(FileAccessError::RemoteStatus(1)) => {}
        Ok(SftpPacket::Data { data, .. }) if !data.is_empty() && data.len() == 1 => {
            return Err(FileAccessError::FileChanged);
        }
        Ok(_) => return Err(FileAccessError::UnexpectedResponse),
        Err(error) => return Err(error),
    }
    let request = session.client_mut().fstat(handle.clone())?;
    unchanged(&opened, &attributes(&mut session, request).await?)?;
    let request = session.client_mut().lstat(path)?;
    unchanged(&before, &attributes(&mut session, request).await?)?;
    close_handle(&mut session, handle).await?;
    text(bytes)
}

#[cfg(test)]
mod tests;
