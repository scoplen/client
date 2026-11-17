// SPDX-License-Identifier: Apache-2.0
//! Disposable SSH protocol peer; it does not establish OpenSSH interoperability.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use russh::server;
use tokio::{
    net::TcpListener,
    sync::{Notify, mpsc},
    task::{JoinHandle, JoinSet},
};

use super::HostKeyPresentation;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Authentication {
    Password,
    Forwarding,
    Interactive,
    PasswordThenInteractive,
    KeyThenInteractive,
    UnsupportedAfterInteractive,
}

pub(crate) struct Peer {
    pub port: u16,
    pub key: HostKeyPresentation,
    pub authentications: Arc<AtomicUsize>,
    pub challenges: Arc<AtomicUsize>,
    pub session_channels: Arc<AtomicUsize>,
    pub closed_connections: Arc<AtomicUsize>,
    pub remote: Option<RemoteControl>,
    task: JoinHandle<()>,
}

#[derive(Clone, Copy)]
pub(crate) enum ForwardReply {
    Accept,
    Deny,
    Hold,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RemoteRequest {
    Listen(String, u32),
    Cancel(String, u32),
}

pub(crate) struct RemoteControl {
    pub requests: mpsc::UnboundedReceiver<RemoteRequest>,
    pub connections: mpsc::UnboundedReceiver<server::Handle>,
    pub release: Arc<Notify>,
}

#[derive(Clone)]
struct RemoteHandler {
    listen: ForwardReply,
    cancel: ForwardReply,
    requests: mpsc::UnboundedSender<RemoteRequest>,
    release: Arc<Notify>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Handler {
    authentications: Arc<AtomicUsize>,
    challenges: Arc<AtomicUsize>,
    session_channels: Arc<AtomicUsize>,
    mode: Authentication,
    round: usize,
    factor_accepted: bool,
    remote: Option<RemoteHandler>,
}

fn remaining(method: russh::MethodKind, partial_success: bool) -> server::Auth {
    server::Auth::Reject {
        proceed_with_methods: Some(russh::MethodSet::from(&[method][..])),
        partial_success,
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        self.authentications.fetch_add(1, Ordering::SeqCst);
        Ok(if user == "trust-fixture" && password == "disposable-trust-password" {
            if matches!(self.mode, Authentication::Password | Authentication::Forwarding) {
                server::Auth::Accept
            } else if matches!(
                self.mode,
                Authentication::PasswordThenInteractive
                    | Authentication::UnsupportedAfterInteractive
            ) {
                self.factor_accepted = true;
                remaining(russh::MethodKind::KeyboardInteractive, true)
            } else {
                remaining(russh::MethodKind::KeyboardInteractive, false)
            }
        } else {
            remaining(russh::MethodKind::KeyboardInteractive, false)
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _key: server::VerifiedPublicKey<'_>,
    ) -> Result<server::Auth, Self::Error> {
        self.authentications.fetch_add(1, Ordering::SeqCst);
        self.factor_accepted =
            user == "trust-fixture" && self.mode == Authentication::KeyThenInteractive;
        Ok(remaining(russh::MethodKind::KeyboardInteractive, self.factor_accepted))
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        _user: &str,
        _submethods: &str,
        response: Option<server::Response<'a>>,
    ) -> Result<server::Auth, Self::Error> {
        use std::borrow::Cow;
        self.challenges.fetch_add(1, Ordering::SeqCst);
        if matches!(
            self.mode,
            Authentication::PasswordThenInteractive | Authentication::KeyThenInteractive
        ) && !self.factor_accepted
        {
            return Ok(server::Auth::reject());
        }
        if let Some(response) = response {
            let values = response.map(|value| value.to_vec()).collect::<Vec<_>>();
            let expected = match self.round {
                1 => vec![b"visible".to_vec(), vec![]],
                2 => vec![],
                _ => vec![b"123456".to_vec()],
            };
            if values != expected {
                return Ok(server::Auth::reject());
            }
        }
        let prompts = match self.round {
            0 => vec![(Cow::Borrowed("Account"), true), (Cow::Borrowed("Empty answer"), false)],
            1 => vec![],
            2 => vec![(Cow::Borrowed("OTP"), false)],
            _ => {
                return Ok(if self.mode == Authentication::UnsupportedAfterInteractive {
                    remaining(russh::MethodKind::Password, true)
                } else {
                    server::Auth::Accept
                });
            }
        };
        self.round += 1;
        Ok(server::Auth::Partial {
            name: "<literal server>".into(),
            instructions: "Authenticate this connection".into(),
            prompts: Cow::Owned(prompts),
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: russh::Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.session_channels.fetch_add(1, Ordering::SeqCst);
        reply.accept().await;
        Ok(())
    }

    async fn agent_request(
        &mut self,
        _channel: russh::ChannelId,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(self.mode == Authentication::Forwarding)
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        let Some(remote) = &self.remote else { return Ok(false) };
        remote.requests.send(RemoteRequest::Listen(address.into(), *port)).unwrap();
        if matches!(remote.listen, ForwardReply::Hold) {
            remote.release.notified().await;
        }
        Ok(!matches!(remote.listen, ForwardReply::Deny))
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        let Some(remote) = &self.remote else { return Ok(false) };
        remote.requests.send(RemoteRequest::Cancel(address.into(), port)).unwrap();
        if matches!(remote.cancel, ForwardReply::Hold) {
            remote.release.notified().await;
        }
        Ok(!matches!(remote.cancel, ForwardReply::Deny))
    }

    async fn pty_request(
        &mut self,
        channel: russh::ChannelId,
        _term: &str,
        _columns: u32,
        _rows: u32,
        _width: u32,
        _height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        command: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if command == b"printf scoplen-interactive-ok" {
            session.channel_success(channel)?;
            session.data(channel, b"scoplen-interactive-ok".to_vec())?;
            session.exit_status_request(channel, 0)?;
        } else {
            session.channel_failure(channel)?;
            session.exit_status_request(channel, 1)?;
        }
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: russh::ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"\x1b[32mactual SSH saved-output fixture\x1b[0m\r\n".to_vec())?;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: russh::Channel<server::Msg>,
        host: &str,
        _port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.mode == Authentication::Forwarding && host != "refused.example" {
            reply.accept().await;
        } else {
            reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        bytes: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.mode == Authentication::Forwarding {
            session.data(channel, bytes.to_vec())?;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: russh::ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.mode == Authentication::Forwarding {
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }
}

impl Peer {
    pub async fn start() -> Self {
        Self::with_authentication(Authentication::Password).await
    }

    pub async fn with_authentication(mode: Authentication) -> Self {
        Self::configured(mode, None).await
    }

    pub async fn with_remote_forwarding(listen: ForwardReply, cancel: ForwardReply) -> Self {
        Self::configured(Authentication::Forwarding, Some((listen, cancel))).await
    }

    async fn configured(
        mode: Authentication,
        replies: Option<(ForwardReply, ForwardReply)>,
    ) -> Self {
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
        config.auth_rejection_time = std::time::Duration::ZERO;
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let authentications = Arc::new(AtomicUsize::new(0));
        let challenges = Arc::new(AtomicUsize::new(0));
        let session_channels = Arc::new(AtomicUsize::new(0));
        let closed_connections = Arc::new(AtomicUsize::new(0));
        let channel_count = session_channels.clone();
        let closed_count = closed_connections.clone();
        let challenge_count = challenges.clone();
        let count = authentications.clone();
        let (requests, request_receiver) = mpsc::unbounded_channel();
        let (connection_controls, connection_receiver) = mpsc::unbounded_channel();
        let release = Arc::new(Notify::new());
        let remote_handler = replies.map(|(listen, cancel)| RemoteHandler {
            listen,
            cancel,
            requests,
            release: release.clone(),
        });
        let remote = replies.map(|_| RemoteControl {
            requests: request_receiver,
            connections: connection_receiver,
            release,
        });
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let config = config.clone();
                let count = count.clone();
                let challenges = challenge_count.clone();
                let session_channels = channel_count.clone();
                let closed_connections = closed_count.clone();
                let remote = remote_handler.clone();
                let controls = connection_controls.clone();
                connections.spawn(async move {
                    let handler = Handler {
                        authentications: count,
                        challenges,
                        session_channels,
                        mode,
                        round: 0,
                        factor_accepted: false,
                        remote,
                    };
                    if let Ok(session) = server::run_stream(config, stream, handler).await {
                        let _ = controls.send(session.handle());
                        let _ = session.await;
                    }
                    closed_connections.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        Self {
            port,
            key,
            authentications,
            challenges,
            session_channels,
            closed_connections,
            remote,
            task,
        }
    }
}
