// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, fmt, process::Stdio, time::Duration};

use scoplen_crypto::SecretVec;
use tokio::{io::AsyncReadExt, process::Command};
use zeroize::Zeroizing;

use super::{CredentialMaterial, SshConnectionError};

const MAX_MATERIAL: usize = scoplen_model::MAX_TEXT_BYTES;
const MAX_RAW_OUTPUT: usize = MAX_MATERIAL + 2;
const TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct CommandCredential {
    pub program: String,
    pub arguments: Vec<String>,
    field: CommandField,
}

#[derive(Clone, Copy)]
enum CommandField {
    Password,
    PrivateKey,
}

impl fmt::Debug for CommandCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("CommandCredential").finish_non_exhaustive()
    }
}

impl CommandCredential {
    pub fn parse(provider: &BTreeMap<String, String>) -> Result<Self, SshConnectionError> {
        if provider.len() != 3 || provider.get("type").map(String::as_str) != Some("command") {
            return Err(SshConnectionError::InvalidCommandCredential);
        }
        let field = match provider.get("field").map(String::as_str) {
            Some("password") => CommandField::Password,
            Some("private_key") => CommandField::PrivateKey,
            _ => return Err(SshConnectionError::InvalidCommandCredential),
        };
        let path = provider.get("path").ok_or(SshConnectionError::InvalidCommandCredential)?;
        let (program, arguments) = super::proxy_command::literal(path)
            .map_err(|_| SshConnectionError::InvalidCommandCredential)?;
        #[cfg(windows)]
        {
            // These extensions make Rust insert a command processor implicitly.
            let file =
                program.rsplit(['\\', '/']).next().unwrap_or("").trim_end_matches(['.', ' ']);
            if file.rsplit_once('.').is_some_and(|(_, extension)| {
                extension.eq_ignore_ascii_case("bat") || extension.eq_ignore_ascii_case("cmd")
            }) {
                return Err(SshConnectionError::InvalidCommandCredential);
            }
        }
        Ok(Self { program, arguments, field })
    }

    pub async fn credential(&self) -> Result<CredentialMaterial, SshConnectionError> {
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
            command.spawn().map_err(|_| SshConnectionError::CommandCredentialUnavailable)?;
        let result = tokio::time::timeout(TIMEOUT, async {
            let stdout = child.stdout.take().ok_or(SshConnectionError::CommandCredentialFailed)?;
            let mut output = Zeroizing::new(Vec::with_capacity(MAX_RAW_OUTPUT + 1));
            stdout
                .take((MAX_RAW_OUTPUT + 1) as u64)
                .read_to_end(&mut output)
                .await
                .map_err(|_| SshConnectionError::CommandCredentialFailed)?;
            if output.len() > MAX_RAW_OUTPUT {
                return Err(SshConnectionError::CommandCredentialTooLarge);
            }
            if !child
                .wait()
                .await
                .map_err(|_| SshConnectionError::CommandCredentialFailed)?
                .success()
            {
                return Err(SshConnectionError::CommandCredentialFailed);
            }
            decode_output(output)
        })
        .await
        .unwrap_or(Err(SshConnectionError::CommandCredentialTimeout));
        if result.is_err() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        result.map(|material| match self.field {
            CommandField::Password => CredentialMaterial::Password(material),
            CommandField::PrivateKey => CredentialMaterial::PrivateKey(material),
        })
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
        return Err(SshConnectionError::CommandCredentialEmpty);
    }
    if output.len() > MAX_MATERIAL {
        return Err(SshConnectionError::CommandCredentialTooLarge);
    }
    Ok(SecretVec::new(std::mem::take(&mut *output)))
}

#[cfg(test)]
mod tests;
