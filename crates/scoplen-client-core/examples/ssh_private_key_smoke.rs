// SPDX-License-Identifier: Apache-2.0

//! Disposable OpenSSH check for direct software-key authentication.

use std::{env, fs, sync::Arc};

use scoplen_client_core::connection::{
    ConnectionPlan, ConnectionRoute, CredentialMaterial, HostKeyPresentation, HostKeyTrust,
    SshConnection, SshConnectionError, probe_host_key,
};
use scoplen_crypto::SecretVec;
use scoplen_ssh::{ClientError, HostKey, HostKeyVerificationError};
use uuid::Uuid;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6
        || ![
            "success",
            "wrong-key",
            "wrong-rsa-key",
            "sha1-only",
            "untrusted",
            "invalid",
            "encrypted",
            "unsupported",
        ]
        .contains(&args[1].as_str())
    {
        return Err("usage: ssh_private_key_smoke <success|wrong-key|wrong-rsa-key|sha1-only|untrusted|invalid|encrypted|unsupported> <host> <port> <user> <key-file>".into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(run(&args))
}

async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let plan = ConnectionPlan {
        profile_id: Uuid::nil(),
        host_id: Uuid::nil(),
        address: args[2].clone(),
        port: args[3].parse()?,
        username: args[4].clone(),
        route: ConnectionRoute::Direct,
        credential: CredentialMaterial::PrivateKey(SecretVec::new(fs::read(&args[5])?)),
    };
    let trust = if args[1] == "untrusted" {
        None
    } else {
        let presented = probe_host_key(&plan).await?;
        let trust: HostKeyTrust = Arc::new(move |_: &str, key: &HostKey| {
            if HostKeyPresentation::from_host_key(key) == presented {
                Ok(())
            } else {
                Err(HostKeyVerificationError::Rejected("host key changed after probe".into()))
            }
        });
        Some(trust)
    };

    if args[1] == "untrusted" {
        let error =
            SshConnection::connect(&plan, trust).await.err().ok_or("untrusted host accepted")?;
        if !matches!(error, SshConnectionError::Engine(ClientError::HostKey(_))) {
            return Err(format!("unexpected trust result: {error}").into());
        }
        println!("untrusted host rejected");
        return Ok(());
    }

    let mut connection = SshConnection::connect(&plan, trust).await?;
    if ["invalid", "encrypted", "unsupported"].contains(&args[1].as_str()) {
        let error = connection.authenticate().await.err().ok_or("unusable key accepted")?;
        let expected = match args[1].as_str() {
            "invalid" => matches!(error, SshConnectionError::InvalidPrivateKey),
            "encrypted" => matches!(error, SshConnectionError::EncryptedPrivateKey),
            _ => matches!(error, SshConnectionError::UnsupportedPrivateKey),
        };
        if !expected {
            return Err(format!("unexpected private-key result: {error}").into());
        }
        println!("{} private key rejected", args[1]);
        return Ok(());
    }
    if args[1] == "wrong-key" || args[1] == "wrong-rsa-key" || args[1] == "sha1-only" {
        let error =
            connection.authenticate().await.err().ok_or("rejected authentication accepted")?;
        let rejected = match args[1].as_str() {
            "wrong-rsa-key" => matches!(error, SshConnectionError::RsaAuthenticationRejected),
            "sha1-only" => matches!(error, SshConnectionError::RsaSha2Unavailable),
            _ => matches!(
                error,
                SshConnectionError::Engine(ClientError::AuthenticationRejected { .. })
            ),
        };
        if !rejected {
            return Err(format!("unexpected authentication result: {error}").into());
        }
        println!("{} rejected", args[1]);
        return Ok(());
    }

    connection.authenticate().await?;
    let mut session = connection.open_session().await?;
    let result = session.exec(b"printf scoplen-key-ok", None).await?;
    if result.stdout != b"scoplen-key-ok" || result.exit_status != Some(0) {
        return Err("authenticated command returned unexpected output".into());
    }
    connection.close().await?;
    println!("software private key authenticated and executed command");
    Ok(())
}
