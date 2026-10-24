// SPDX-License-Identifier: Apache-2.0
//! Disposable SSH protocol peer; it does not establish OpenSSH interoperability.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use russh::server;
use tokio::{
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};

use super::HostKeyPresentation;

pub(crate) struct Peer {
    pub port: u16,
    pub key: HostKeyPresentation,
    pub authentications: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Handler(Arc<AtomicUsize>);

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(if user == "trust-fixture" && password == "disposable-trust-password" {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }
}

impl Peer {
    pub async fn start() -> Self {
        let private = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let key = HostKeyPresentation::from_host_key(&scoplen_ssh::HostKey::Raw {
            algorithm: "ssh-ed25519".into(),
            key_blob: private.public_key().to_bytes().unwrap(),
        });
        let mut config = server::Config::default();
        config.keys.push(private);
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let authentications = Arc::new(AtomicUsize::new(0));
        let count = authentications.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let config = config.clone();
                let count = count.clone();
                connections.spawn(async move {
                    if let Ok(session) = server::run_stream(config, stream, Handler(count)).await {
                        let _ = session.await;
                    }
                });
            }
        });
        Self { port, key, authentications, task }
    }
}
