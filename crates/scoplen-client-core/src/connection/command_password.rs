// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, fmt, process::Stdio, time::Duration};

use scoplen_crypto::SecretVec;
use tokio::{io::AsyncReadExt, process::Command};
use zeroize::Zeroizing;

use super::SshConnectionError;

const MAX_PASSWORD: usize = scoplen_model::MAX_TEXT_BYTES;
const MAX_RAW_OUTPUT: usize = MAX_PASSWORD + 2;
const TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct CommandPassword {
    pub program: String,
    pub arguments: Vec<String>,
}

impl fmt::Debug for CommandPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("CommandPassword").finish_non_exhaustive()
    }
}

impl CommandPassword {
    pub fn parse(provider: &BTreeMap<String, String>) -> Result<Self, SshConnectionError> {
        if provider.len() != 3
            || provider.get("type").map(String::as_str) != Some("command")
            || provider.get("field").map(String::as_str) != Some("password")
        {
            return Err(SshConnectionError::InvalidCommandPassword);
        }
        let path = provider.get("path").ok_or(SshConnectionError::InvalidCommandPassword)?;
        let (program, arguments) = super::proxy_command::literal(path)
            .map_err(|_| SshConnectionError::InvalidCommandPassword)?;
        #[cfg(windows)]
        {
            // These extensions make Rust insert a command processor implicitly.
            let file =
                program.rsplit(['\\', '/']).next().unwrap_or("").trim_end_matches(['.', ' ']);
            if file.rsplit_once('.').is_some_and(|(_, extension)| {
                extension.eq_ignore_ascii_case("bat") || extension.eq_ignore_ascii_case("cmd")
            }) {
                return Err(SshConnectionError::InvalidCommandPassword);
            }
        }
        Ok(Self { program, arguments })
    }

    pub async fn password(&self) -> Result<SecretVec, SshConnectionError> {
        let mut command = Command::new(&self.program);
        command
            .args(&self.arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x0800_0000);
        let mut child =
            command.spawn().map_err(|_| SshConnectionError::CommandPasswordUnavailable)?;
        let result = tokio::time::timeout(TIMEOUT, async {
            let stdout = child.stdout.take().ok_or(SshConnectionError::CommandPasswordFailed)?;
            let mut output = Zeroizing::new(Vec::with_capacity(MAX_RAW_OUTPUT + 1));
            stdout
                .take((MAX_RAW_OUTPUT + 1) as u64)
                .read_to_end(&mut output)
                .await
                .map_err(|_| SshConnectionError::CommandPasswordFailed)?;
            if output.len() > MAX_RAW_OUTPUT {
                return Err(SshConnectionError::CommandPasswordTooLarge);
            }
            if !child.wait().await.map_err(|_| SshConnectionError::CommandPasswordFailed)?.success()
            {
                return Err(SshConnectionError::CommandPasswordFailed);
            }
            decode_output(output)
        })
        .await
        .unwrap_or(Err(SshConnectionError::CommandPasswordTimeout));
        if result.is_err() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        result
    }
}

fn decode_output(mut output: Zeroizing<Vec<u8>>) -> Result<SecretVec, SshConnectionError> {
    if output.last() == Some(&b'\n') {
        output.pop();
        if output.last() == Some(&b'\r') {
            output.pop();
        }
    }
    if output.is_empty() {
        return Err(SshConnectionError::CommandPasswordEmpty);
    }
    if output.len() > MAX_PASSWORD {
        return Err(SshConnectionError::CommandPasswordTooLarge);
    }
    Ok(SecretVec::new(std::mem::take(&mut *output)))
}

#[cfg(test)]
mod tests;
