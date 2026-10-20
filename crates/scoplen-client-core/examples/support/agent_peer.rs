// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use russh::{Channel, ChannelId, keys::PrivateKey, server};
use ssh_key::{Algorithm, PublicKey};
use tokio::{net::TcpListener, task::JoinHandle};

/// Disposable protocol peer for Windows runners without a Linux Docker daemon.
pub struct Peer(JoinHandle<()>);

impl Drop for Peer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Handler {
    expected_key: Vec<u8>,
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(if user == "smoke" && key.to_bytes().is_ok_and(|key| key == self.expected_key) {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        command: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if command == b"printf scoplen-agent-ok" {
            session.channel_success(channel)?;
            session.data(channel, b"scoplen-agent-ok".to_vec())?;
            session.exit_status_request(channel, 0)?;
        } else {
            session.channel_failure(channel)?;
            session.exit_status_request(channel, 1)?;
        }
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

pub async fn start(public_key: &str) -> Result<(u16, Peer), Box<dyn std::error::Error>> {
    let expected_key = PublicKey::from_openssh(public_key)?.to_bytes()?;
    let mut config = server::Config::default();
    config.keys.push(PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        Algorithm::Ed25519,
    )?);
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            if let Ok(session) = server::run_stream(
                Arc::clone(&config),
                stream,
                Handler { expected_key: expected_key.clone() },
            )
            .await
            {
                let _ = session.await;
            }
        }
    });
    Ok((port, Peer(task)))
}
