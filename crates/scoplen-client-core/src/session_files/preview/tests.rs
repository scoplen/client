// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Mutex;

use russh::server;
use scoplen_crypto::SecretVec;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::connection::{ConnectionPlan, ConnectionRoute, CredentialMaterial};

use super::*;

struct State {
    bytes: Vec<u8>,
    initial: SftpAttributes,
    opened: Option<SftpAttributes>,
    after: Option<SftpAttributes>,
    metadata_calls: usize,
    short_read: usize,
    read_delay: Duration,
    stall: bool,
    refuse_close: bool,
    probe_reply: u8,
    reads: Vec<(u64, u32)>,
    requests: Vec<&'static str>,
}

struct Peer {
    connection: SshConnection,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Handler {
    state: Arc<Mutex<State>>,
    buffers: HashMap<russh::ChannelId, Vec<u8>>,
}

fn status(id: u32, code: u32) -> SftpPacket {
    SftpPacket::Status {
        id,
        code,
        message: b"private remote status".to_vec(),
        language: Vec::new(),
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _: &str, _: &str) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _: russh::Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: russh::ChannelId,
        name: &str,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        assert_eq!(name, "sftp");
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: russh::ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let buffer = self.buffers.entry(channel).or_default();
        buffer.extend_from_slice(data);
        while buffer.len() >= 4 {
            let length = u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize + 4;
            if buffer.len() < length {
                break;
            }
            let packet = SftpPacket::decode(&buffer.drain(..length).collect::<Vec<_>>()).unwrap();
            let response;
            let read_delay;
            {
                let mut state = self.state.lock().unwrap();
                read_delay = match &packet {
                    SftpPacket::Read { offset, .. }
                        if *offset < state.initial.size.unwrap_or(0) =>
                    {
                        state.read_delay
                    }
                    _ => Duration::ZERO,
                };
                response = match packet {
                    SftpPacket::Init { .. } => {
                        SftpPacket::Version { version: 3, extensions: Vec::new() }
                    }
                    SftpPacket::Lstat { id, .. } | SftpPacket::Fstat { id, .. } => {
                        state.requests.push("metadata");
                        state.metadata_calls += 1;
                        let mut attrs = match state.metadata_calls {
                            1 => state.initial.clone(),
                            2 => state.opened.clone().unwrap_or_else(|| state.initial.clone()),
                            _ => state.after.clone().unwrap_or_else(|| state.initial.clone()),
                        };
                        attrs.access_time = attrs.modify_time.map(|_| state.metadata_calls as u32);
                        SftpPacket::Attrs { id, attrs }
                    }
                    SftpPacket::Open { id, pflags, .. } => {
                        assert_eq!(pflags, 1, "preview can only open for reading");
                        state.requests.push("open");
                        SftpPacket::Handle { id, handle: b"preview-handle".to_vec() }
                    }
                    SftpPacket::Read { id, handle, offset, length } => {
                        assert_eq!(handle, b"preview-handle");
                        state.requests.push("read");
                        state.reads.push((offset, length));
                        if state.stall {
                            continue;
                        }
                        if offset == state.initial.size.unwrap_or(u64::MAX) {
                            match state.probe_reply {
                                1 => {
                                    session.data(
                                        channel,
                                        SftpPacket::Data { id, data: Vec::new() }.encode().unwrap(),
                                    )?;
                                    continue;
                                }
                                2 => {
                                    session.data(
                                        channel,
                                        SftpPacket::Data { id, data: vec![b'x'; 2] }
                                            .encode()
                                            .unwrap(),
                                    )?;
                                    continue;
                                }
                                3 => {
                                    session.data(
                                        channel,
                                        SftpPacket::Attrs { id, attrs: SftpAttributes::default() }
                                            .encode()
                                            .unwrap(),
                                    )?;
                                    continue;
                                }
                                _ => {}
                            }
                        }
                        let start = offset as usize;
                        if start >= state.bytes.len() {
                            status(id, 1)
                        } else {
                            let end = start
                                .saturating_add((length as usize).min(state.short_read))
                                .min(state.bytes.len());
                            SftpPacket::Data { id, data: state.bytes[start..end].to_vec() }
                        }
                    }
                    SftpPacket::Close { id, .. } => {
                        state.requests.push("close");
                        status(id, if state.refuse_close { 4 } else { 0 })
                    }
                    _ => panic!("preview issued a write or unsupported request"),
                };
            }
            if !read_delay.is_zero() {
                tokio::time::sleep(read_delay).await;
            }
            session.data(channel, response.encode().unwrap())?;
        }
        Ok(())
    }
}

impl Peer {
    async fn start(bytes: Vec<u8>) -> Self {
        let initial = SftpAttributes {
            size: Some(bytes.len() as u64),
            permissions: Some(0o100600),
            modify_time: Some(100),
            ..Default::default()
        };
        let state = Arc::new(Mutex::new(State {
            bytes,
            initial,
            opened: None,
            after: None,
            metadata_calls: 0,
            short_read: usize::MAX,
            read_delay: Duration::ZERO,
            stall: false,
            refuse_close: false,
            probe_reply: 0,
            reads: Vec::new(),
            requests: Vec::new(),
        }));
        let private = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let blob = private.public_key().to_bytes().unwrap();
        let mut config = server::Config::default();
        config.keys.push(private);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler = Handler { state: state.clone(), buffers: HashMap::new() };
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server::run_stream(Arc::new(config), stream, handler).await.unwrap().await.unwrap();
        });
        let plan = ConnectionPlan {
            profile_id: Uuid::now_v7(),
            host_id: Uuid::now_v7(),
            address: "127.0.0.1".into(),
            port,
            username: "fixture".into(),
            route: ConnectionRoute::Direct,
            credential: CredentialMaterial::Password(SecretVec::new(b"disposable".to_vec())),
        };
        let mut connection = SshConnection::connect(
            &plan,
            Some(Arc::new(move |_: &str, key: &scoplen_ssh::HostKey| match key {
                scoplen_ssh::HostKey::Raw { key_blob, .. } if *key_blob == blob => Ok(()),
                _ => Err(scoplen_ssh::HostKeyVerificationError::Rejected(
                    "fixture key mismatch".into(),
                )),
            })),
        )
        .await
        .unwrap();
        connection.authenticate().await.unwrap();
        Self { connection, state, task }
    }

    async fn preview(&self) -> Result<RemoteTextPreview, RemoteTextPreviewIssue> {
        preview_file(&self.connection, b"./text.txt".to_vec()).await.map_err(Into::into)
    }
}

#[tokio::test]
async fn complete_utf8_empty_and_exact_cap_text_use_read_only_requests_and_probe_eof() {
    for bytes in [
        "中文 <img src=x>\r\n\tשלום\u{202e}".as_bytes().to_vec(),
        Vec::new(),
        vec![b'x'; MAX_PREVIEW_BYTES],
    ] {
        let peer = Peer::start(bytes.clone()).await;
        peer.state.lock().unwrap().short_read = 4096;
        let result = peer.preview().await.unwrap();
        assert_eq!(result.text.as_bytes(), bytes);
        assert_eq!(result.size_bytes as usize, bytes.len());
        assert!(!format!("{result:?}").contains(&result.text) || result.text.is_empty());
        let state = peer.state.lock().unwrap();
        assert_eq!(state.reads.last(), Some(&(bytes.len() as u64, 1)));
        assert!(state.reads.iter().all(|(_, length)| *length <= READ_CHUNK));
        assert_eq!(state.requests.last(), Some(&"close"));
    }
}

#[tokio::test]
async fn oversized_missing_size_and_nonordinary_files_fail_before_open() {
    for (size, permissions, expected) in [
        (Some(MAX_PREVIEW_BYTES as u64 + 1), Some(0o100600), RemoteTextPreviewIssue::TooLarge),
        (None, Some(0o100600), RemoteTextPreviewIssue::MissingMetadata),
        (Some(0), Some(0o120777), RemoteTextPreviewIssue::NotRegularFile),
        (Some(0), Some(0o040700), RemoteTextPreviewIssue::NotRegularFile),
        (Some(0), Some(0o010600), RemoteTextPreviewIssue::NotRegularFile),
    ] {
        let peer = Peer::start(Vec::new()).await;
        {
            let mut state = peer.state.lock().unwrap();
            state.initial.size = size;
            state.initial.permissions = permissions;
        }
        assert_eq!(peer.preview().await.unwrap_err(), expected);
        assert!(!peer.state.lock().unwrap().requests.contains(&"open"));
    }
}

#[tokio::test]
async fn premature_eof_and_growth_beyond_reported_size_do_not_disclose_partial_text() {
    for reported in [2, 4] {
        let peer = Peer::start(b"abc".to_vec()).await;
        peer.state.lock().unwrap().initial.size = Some(reported);
        assert_eq!(peer.preview().await.unwrap_err(), RemoteTextPreviewIssue::FileChanged);
    }
}

#[tokio::test]
async fn changed_opened_or_final_type_size_and_mtime_fail_without_disclosure() {
    for (opened, size, permissions, modify_time) in [
        (true, Some(3), Some(0o120777), Some(100)),
        (false, Some(4), Some(0o100600), Some(100)),
        (false, Some(3), Some(0o100600), Some(101)),
        (false, Some(3), Some(0o100600), None),
    ] {
        let peer = Peer::start(b"abc".to_vec()).await;
        let attrs = SftpAttributes { size, permissions, modify_time, ..Default::default() };
        if opened {
            peer.state.lock().unwrap().opened = Some(attrs);
        } else {
            peer.state.lock().unwrap().after = Some(attrs);
        }
        assert_eq!(peer.preview().await.unwrap_err(), RemoteTextPreviewIssue::FileChanged);
    }
}

#[test]
fn only_defined_nontext_controls_and_invalid_utf8_are_rejected() {
    for scalar in (0..32).chain(127..160) {
        let character = char::from_u32(scalar).unwrap();
        let result = text(character.to_string().into_bytes());
        assert_eq!(result.is_ok(), matches!(character, '\t' | '\r' | '\n'));
    }
    assert!(matches!(text(vec![0xff]), Err(FileAccessError::PreviewNotText)));
    assert!(matches!(
        text(vec![b'x'; MAX_PREVIEW_BYTES + 1]),
        Err(FileAccessError::PreviewTooLarge)
    ));
}

#[tokio::test]
async fn refusal_during_cleanup_never_returns_text_or_remote_status_message() {
    let peer = Peer::start(b"private file contents".to_vec()).await;
    peer.state.lock().unwrap().refuse_close = true;
    assert_eq!(peer.preview().await.unwrap_err(), RemoteTextPreviewIssue::RemoteDenied);
}

#[tokio::test]
async fn cancelled_stalled_read_drops_only_its_sftp_channel_and_allows_fresh_preview() {
    let peer = Peer::start(b"safe".to_vec()).await;
    peer.state.lock().unwrap().stall = true;
    {
        let pending = peer.preview();
        tokio::pin!(pending);
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                _ = &mut pending => panic!("the stalled read must remain pending"),
                () = async {
                    while peer.state.lock().unwrap().reads.is_empty() { tokio::task::yield_now().await; }
                } => {}
            }
        }).await.unwrap();
    }
    peer.state.lock().unwrap().stall = false;
    assert_eq!(peer.preview().await.unwrap().text, "safe");
}

#[tokio::test]
async fn malformed_eof_probe_replies_are_protocol_failures_rather_than_changed_files() {
    for reply in 1..=3 {
        let peer = Peer::start(b"safe".to_vec()).await;
        peer.state.lock().unwrap().probe_reply = reply;
        assert_eq!(peer.preview().await.unwrap_err(), RemoteTextPreviewIssue::Failed);
    }
}

#[tokio::test]
async fn progressing_short_reads_can_exceed_fifteen_seconds_in_total() {
    let peer = Peer::start(b"safe".to_vec()).await;
    {
        let mut state = peer.state.lock().unwrap();
        state.short_read = 2;
        state.read_delay = Duration::from_secs(8);
    }
    let started = tokio::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(30), peer.preview()).await.unwrap();
    assert_eq!(result.unwrap().text, "safe");
    assert!(started.elapsed() >= Duration::from_secs(16));
    assert_eq!(peer.state.lock().unwrap().reads, [(0, 4), (2, 2), (4, 1)]);
}

#[tokio::test]
async fn a_real_stalled_sftp_read_has_a_fifteen_second_step_deadline() {
    let peer = Peer::start(b"safe".to_vec()).await;
    peer.state.lock().unwrap().stall = true;
    let pending = peer.preview();
    tokio::pin!(pending);
    tokio::select! {
        _ = &mut pending => panic!("the stalled read must remain pending"),
        () = async {
            while peer.state.lock().unwrap().reads.is_empty() { tokio::task::yield_now().await; }
        } => {}
    }
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(15)).await;
    assert_eq!(pending.await.unwrap_err(), RemoteTextPreviewIssue::Timeout);
}
