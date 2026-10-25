// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Mutex;

use russh::server;
use scoplen_crypto::SecretVec;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::connection::{ConnectionPlan, ConnectionRoute, CredentialMaterial};

use super::*;

#[derive(Default)]
struct Remote {
    bytes: Vec<u8>,
    staging: Option<Vec<u8>>,
    target: Option<Vec<u8>>,
    opens: Vec<u32>,
    writes: Vec<(Vec<u8>, u64, usize)>,
    reads: Vec<(Vec<u8>, u64, u32)>,
    closes: Vec<Vec<u8>>,
    removed: usize,
    renamed: usize,
    refuse_reads: bool,
    refuse_read_fstat: bool,
    read_attrs_mismatch: bool,
    replace_admission_path: bool,
    replace_on_cleanup: bool,
    write_channel: Option<russh::ChannelId>,
    refuse_empty_read: bool,
    refuse_staging_path_attributes: bool,
    malformed_admission: bool,
    alias_read_handle: bool,
    replace_path: bool,
    lose_rename_reply: bool,
    refuse_cleanup: bool,
    fsync: bool,
    refuse_fsync: bool,
    fsync_offsets: Vec<u64>,
    pause_on_write: Option<(u64, watch::Sender<TransferControl>)>,
}

fn attrs(size: usize) -> SftpAttributes {
    SftpAttributes {
        size: Some(size as u64),
        permissions: Some(0o100600),
        access_time: Some(100),
        modify_time: Some(100),
        ..Default::default()
    }
}

fn status(id: u32, code: u32) -> SftpPacket {
    SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
}

struct Handler {
    remote: Arc<Mutex<Remote>>,
    buffers: HashMap<russh::ChannelId, Vec<u8>>,
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
            let mut remote = self.remote.lock().unwrap();
            let response = match packet {
                SftpPacket::Init { .. } => SftpPacket::Version {
                    version: 3,
                    extensions: if remote.fsync {
                        vec![scoplen_ssh::SftpExtension::new(b"fsync@openssh.com", b"1").unwrap()]
                    } else {
                        Vec::new()
                    },
                },
                SftpPacket::Open { id, path, pflags, .. } => {
                    remote.opens.push(pflags);
                    if pflags == EXCLUSIVE_WRITE_OPEN {
                        assert!(remote.staging.is_none(), "creation must never be retried");
                        remote.staging = Some(path);
                        remote.write_channel = Some(channel);
                        SftpPacket::Handle { id, handle: b"original-write".to_vec() }
                    } else {
                        assert_eq!(pflags, 1);
                        assert_eq!(remote.staging.as_ref(), Some(&path));
                        if remote.refuse_reads {
                            status(id, 3)
                        } else if remote.malformed_admission {
                            SftpPacket::Attrs { id, attrs: attrs(0) }
                        } else {
                            SftpPacket::Handle { id, handle: b"admitted-read".to_vec() }
                        }
                    }
                }
                SftpPacket::Fstat { id, handle } => {
                    if handle == b"admitted-read" && remote.refuse_read_fstat {
                        status(id, 3)
                    } else {
                        assert!(handle == b"original-write" || handle == b"admitted-read");
                        let mut attributes = attrs(remote.bytes.len());
                        if handle == b"admitted-read" && remote.read_attrs_mismatch {
                            attributes.modify_time = Some(101);
                        }
                        attributes.access_time = Some(100 + remote.reads.len() as u32);
                        SftpPacket::Attrs { id, attrs: attributes }
                    }
                }
                SftpPacket::Lstat { id, path } => {
                    if remote.staging.as_ref() == Some(&path)
                        && remote.refuse_staging_path_attributes
                    {
                        status(id, 3)
                    } else if remote.staging.as_ref() == Some(&path) {
                        let mut attributes = attrs(remote.bytes.len());
                        if remote.replace_path
                            || (remote.replace_admission_path && !remote.reads.is_empty())
                            || (remote.replace_on_cleanup && remote.write_channel != Some(channel))
                        {
                            attributes.modify_time = Some(101);
                        }
                        SftpPacket::Attrs { id, attrs: attributes }
                    } else if let Some(target) = &remote.target {
                        SftpPacket::Attrs { id, attrs: attrs(target.len()) }
                    } else {
                        status(id, 2)
                    }
                }
                SftpPacket::Write { id, handle, offset, data } => {
                    assert_eq!(handle, b"original-write");
                    remote.writes.push((handle, offset, data.len()));
                    if let Some((start, control)) = &remote.pause_on_write
                        && offset >= *start
                    {
                        control.send_replace(TransferControl::Pause);
                    }
                    let start = offset as usize;
                    remote.bytes.resize(start + data.len(), 0);
                    remote.bytes[start..start + data.len()].copy_from_slice(&data);
                    status(id, 0)
                }
                SftpPacket::Read { id, handle, offset, length } => {
                    assert_eq!(handle, b"admitted-read");
                    remote.reads.push((handle, offset, length));
                    if remote.bytes.is_empty() && remote.refuse_empty_read {
                        status(id, 3)
                    } else if offset >= remote.bytes.len() as u64 {
                        status(id, 1)
                    } else {
                        let start = offset as usize;
                        let mut data = remote.bytes
                            [start..(start + length as usize).min(remote.bytes.len())]
                            .to_vec();
                        if remote.alias_read_handle && start == 0 {
                            data[0] ^= 1;
                        }
                        SftpPacket::Data { id, data }
                    }
                }
                SftpPacket::Close { id, handle } => {
                    remote.closes.push(handle);
                    status(id, 0)
                }
                SftpPacket::Extended { id, name, data } => {
                    assert_eq!(name, b"fsync@openssh.com");
                    assert_eq!(&data[4..], b"original-write");
                    let offset = remote.bytes.len() as u64;
                    remote.fsync_offsets.push(offset);
                    status(id, if remote.refuse_fsync { 3 } else { 0 })
                }
                SftpPacket::Remove { id, path } => {
                    assert_eq!(remote.staging.as_ref(), Some(&path));
                    remote.removed += 1;
                    if remote.refuse_cleanup {
                        status(id, 3)
                    } else {
                        remote.staging = None;
                        status(id, 0)
                    }
                }
                SftpPacket::Rename { id, old_path, .. } => {
                    assert_eq!(remote.staging.as_ref(), Some(&old_path));
                    remote.renamed += 1;
                    remote.target = Some(remote.bytes.clone());
                    remote.staging = None;
                    if remote.lose_rename_reply {
                        session.close(channel)?;
                        continue;
                    }
                    status(id, 0)
                }
                other => panic!("unexpected upload request: {other:?}"),
            };
            session.data(channel, response.encode().unwrap())?;
        }
        Ok(())
    }
}

pub(crate) struct Peer {
    pub(crate) connection: SshConnection,
    remote: Arc<Mutex<Remote>>,
    task: JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Peer {
    pub(crate) async fn start() -> Self {
        let remote = Arc::new(Mutex::new(Remote::default()));
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
        let handler = Handler { remote: remote.clone(), buffers: HashMap::new() };
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
                _ => Err(scoplen_ssh::HostKeyVerificationError::Rejected("fixture".into())),
            })),
        )
        .await
        .unwrap();
        connection.authenticate_with_passphrase(None).await.unwrap();
        Self { connection, remote, task }
    }

    pub(crate) async fn run(
        &self,
        input: UploadInput,
        control: watch::Receiver<TransferControl>,
        progress: impl FnMut(FileTransferProgress),
    ) -> UploadExecution {
        transfer_upload(
            &self.connection,
            input,
            control,
            Arc::new(UploadState::default()),
            progress,
            || {},
            || Ok(()),
        )
        .await
    }

    pub(crate) async fn paused(&self, path: &Path) -> Box<UploadCheckpoint> {
        let (_sender, control) = watch::channel(TransferControl::Pause);
        match self.run(input(path).await, control, |_| {}).await {
            UploadExecution::Paused(checkpoint) => checkpoint,
            _ => panic!("expected a real upload checkpoint"),
        }
    }

    pub(crate) fn write_offsets(&self) -> Vec<u64> {
        self.remote.lock().unwrap().writes.iter().map(|(_, offset, _)| *offset).collect()
    }

    pub(crate) fn refuse_cleanup(&self) {
        self.remote.lock().unwrap().refuse_cleanup = true;
    }

    pub(crate) fn staging_exists(&self) -> bool {
        self.remote.lock().unwrap().staging.is_some()
    }
}

pub(crate) async fn input(path: &Path) -> UploadInput {
    let source = open_upload_source(path).await.unwrap();
    UploadInput::New {
        target: source.target(b".").unwrap(),
        source: Box::new(source),
        directory: b".".to_vec(),
        preflight: UploadPreflight { target_attributes: None, replacement_supported: false },
    }
}

pub(crate) fn source(directory: &Path) -> (PathBuf, Vec<u8>) {
    let bytes = (0..(3 * SEGMENT_BYTES + 17).div_ceil(8))
        .flat_map(u64::to_le_bytes)
        .take((3 * SEGMENT_BYTES + 17) as usize)
        .collect::<Vec<_>>();
    let path = directory.join("source.bin");
    std::fs::write(&path, &bytes).unwrap();
    (path, bytes)
}

#[tokio::test]
async fn repeated_pause_resumes_original_handles_at_confirmed_nonzero_offsets() {
    let peer = Peer::start().await;
    let directory = tempfile::tempdir().unwrap();
    let (path, expected) = source(directory.path());
    let mut checkpoint = peer.paused(&path).await;
    assert_eq!(checkpoint.offset, SEGMENT_BYTES);
    assert_eq!(peer.remote.lock().unwrap().opens, [EXCLUSIVE_WRITE_OPEN, 1]);
    let first_writes = peer.write_offsets().len();
    let (sender, control) = watch::channel(TransferControl::Run);
    peer.remote.lock().unwrap().pause_on_write = Some((SEGMENT_BYTES, sender));
    let mut reports = Vec::new();
    checkpoint = match peer
        .run(UploadInput::Resume(checkpoint), control, |update| {
            reports.push(update);
        })
        .await
    {
        UploadExecution::Paused(checkpoint) => checkpoint,
        _ => panic!("expected second checkpoint"),
    };
    assert_eq!(checkpoint.offset, 2 * SEGMENT_BYTES);
    assert_eq!(peer.write_offsets()[first_writes], SEGMENT_BYTES);
    assert!(reports.iter().all(|report| report.transferred >= SEGMENT_BYTES));
    let second_writes = peer.write_offsets().len();
    let (_sender, control) = watch::channel(TransferControl::Run);
    assert!(matches!(
        peer.run(UploadInput::Resume(checkpoint), control, |_| {}).await,
        UploadExecution::Published
    ));
    let remote = peer.remote.lock().unwrap();
    assert_eq!(remote.writes[second_writes].1, 2 * SEGMENT_BYTES);
    assert_eq!(remote.target.as_ref(), Some(&expected));
    assert_eq!(remote.renamed, 1);
    assert_eq!(remote.opens, [EXCLUSIVE_WRITE_OPEN, 1]);
    assert!(remote.reads.iter().any(|(_, offset, length)| *offset == 0 && *length > 1));
}

#[tokio::test]
async fn pause_requires_supported_remote_fsync_to_acknowledge_the_confirmed_segment() {
    for refused in [false, true] {
        let peer = Peer::start().await;
        {
            let mut remote = peer.remote.lock().unwrap();
            remote.fsync = true;
            remote.refuse_fsync = refused;
        }
        let directory = tempfile::tempdir().unwrap();
        let (path, _) = source(directory.path());
        let (_sender, control) = watch::channel(TransferControl::Pause);
        let result = peer.run(input(&path).await, control, |_| {}).await;
        match result {
            UploadExecution::Paused(checkpoint) if !refused => assert!(checkpoint.discard().await),
            UploadExecution::Failed {
                error: FileAccessError::RemoteStatus(3),
                staging_may_remain: false,
            } if refused => {}
            _ => panic!("Pause must wait for a successful fsync"),
        }
        let remote = peer.remote.lock().unwrap();
        assert_eq!(remote.fsync_offsets, [SEGMENT_BYTES]);
        assert_eq!(remote.renamed, 0);
    }
}

#[tokio::test]
async fn each_associated_read_admission_refusal_preserves_ordinary_upload() {
    for refusal in 0..4 {
        let peer = Peer::start().await;
        let directory = tempfile::tempdir().unwrap();
        let (path, bytes) = source(directory.path());
        {
            let mut remote = peer.remote.lock().unwrap();
            remote.refuse_reads = refusal == 0;
            remote.refuse_read_fstat = refusal == 1;
            remote.refuse_empty_read = refusal == 2;
            remote.refuse_staging_path_attributes = refusal == 3;
        }
        let (_sender, control) = watch::channel(TransferControl::Pause);
        let admitted = AtomicBool::new(false);
        assert!(matches!(
            transfer_upload(
                &peer.connection,
                input(&path).await,
                control,
                Arc::new(UploadState::default()),
                |_| {},
                || {
                    admitted.store(true, Ordering::SeqCst);
                },
                || Ok(()),
            )
            .await,
            UploadExecution::Published
        ));
        assert!(!admitted.load(Ordering::SeqCst));
        let remote = peer.remote.lock().unwrap();
        assert_eq!(remote.target.as_ref(), Some(&bytes));
        assert_eq!(remote.opens, [EXCLUSIVE_WRITE_OPEN, 1]);
        if refusal != 0 {
            assert!(remote.closes.iter().any(|handle| handle == b"admitted-read"));
        }
    }
}

#[tokio::test]
async fn uncertain_read_admission_ends_and_cleans_without_payload_or_creation_retry() {
    let peer = Peer::start().await;
    peer.remote.lock().unwrap().malformed_admission = true;
    let directory = tempfile::tempdir().unwrap();
    let (path, _) = source(directory.path());
    let (_sender, control) = watch::channel(TransferControl::Run);
    assert!(matches!(
        peer.run(input(&path).await, control, |_| {}).await,
        UploadExecution::Failed {
            error: FileAccessError::UnexpectedResponse,
            staging_may_remain: false
        }
    ));
    let remote = peer.remote.lock().unwrap();
    assert!(remote.writes.is_empty());
    assert_eq!(remote.removed, 1);
    assert_eq!(remote.opens, [EXCLUSIVE_WRITE_OPEN, 1]);
}

#[tokio::test]
async fn admission_handle_or_path_mismatch_preserves_the_unowned_path_without_remove() {
    for path_mismatch in [false, true] {
        let peer = Peer::start().await;
        {
            let mut remote = peer.remote.lock().unwrap();
            remote.read_attrs_mismatch = !path_mismatch;
            remote.replace_admission_path = path_mismatch;
        }
        let directory = tempfile::tempdir().unwrap();
        let (path, _) = source(directory.path());
        let (_sender, control) = watch::channel(TransferControl::Run);
        assert!(matches!(
            peer.run(input(&path).await, control, |_| {}).await,
            UploadExecution::Failed {
                error: FileAccessError::UnsafeStaging,
                staging_may_remain: true
            }
        ));
        let remote = peer.remote.lock().unwrap();
        assert!(remote.writes.is_empty());
        assert_eq!(remote.removed, 0);
        assert_eq!(remote.opens, [EXCLUSIVE_WRITE_OPEN, 1]);
    }
}

#[tokio::test]
async fn source_failure_cleanup_rechecks_path_after_original_checkpoint_validation() {
    let peer = Peer::start().await;
    let directory = tempfile::tempdir().unwrap();
    let (path, _) = source(directory.path());
    let checkpoint = peer.paused(&path).await;
    let metadata = std::fs::metadata(&path).unwrap();
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    use std::io::Write as _;
    (&file).write_all(b"changed").unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(metadata.modified().unwrap())).unwrap();
    peer.remote.lock().unwrap().replace_on_cleanup = true;
    let (_sender, control) = watch::channel(TransferControl::Run);
    assert!(matches!(
        peer.run(UploadInput::Resume(checkpoint), control, |_| {}).await,
        UploadExecution::Failed { error: FileAccessError::SourceChanged, staging_may_remain: true }
    ));
    assert_eq!(peer.remote.lock().unwrap().removed, 0);
}

#[tokio::test]
async fn first_pause_checks_staging_prefix_even_when_both_handles_have_matching_attributes() {
    let peer = Peer::start().await;
    peer.remote.lock().unwrap().alias_read_handle = true;
    let directory = tempfile::tempdir().unwrap();
    let (path, _) = source(directory.path());
    let (_sender, control) = watch::channel(TransferControl::Pause);
    assert!(matches!(
        peer.run(input(&path).await, control, |_| {}).await,
        UploadExecution::Failed { error: FileAccessError::FileChanged, staging_may_remain: true }
    ));
    assert_eq!(peer.remote.lock().unwrap().renamed, 0);
}

#[tokio::test]
async fn resume_refuses_changed_source_prefix_preserving_size_and_modification_time() {
    let peer = Peer::start().await;
    let directory = tempfile::tempdir().unwrap();
    let (path, _) = source(directory.path());
    let checkpoint = peer.paused(&path).await;
    let metadata = std::fs::metadata(&path).unwrap();
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    use std::io::Write as _;
    (&file).write_all(b"changed").unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(metadata.modified().unwrap())).unwrap();
    let writes = peer.write_offsets().len();
    let (_sender, control) = watch::channel(TransferControl::Run);
    assert!(matches!(
        peer.run(UploadInput::Resume(checkpoint), control, |_| {}).await,
        UploadExecution::Failed {
            error: FileAccessError::SourceChanged,
            staging_may_remain: false
        }
    ));
    assert_eq!(peer.write_offsets().len(), writes);
}

#[tokio::test]
async fn resume_refuses_staging_prefix_path_or_target_changes_before_any_payload() {
    for change in 0..3 {
        let peer = Peer::start().await;
        let directory = tempfile::tempdir().unwrap();
        let (path, _) = source(directory.path());
        let checkpoint = peer.paused(&path).await;
        let writes = peer.write_offsets().len();
        {
            let mut remote = peer.remote.lock().unwrap();
            match change {
                0 => remote.bytes[0] ^= 1,
                1 => remote.replace_path = true,
                _ => remote.target = Some(b"concurrent destination".to_vec()),
            }
        }
        let (_sender, control) = watch::channel(TransferControl::Run);
        let result = peer.run(UploadInput::Resume(checkpoint), control, |_| {}).await;
        assert!(matches!(result, UploadExecution::Failed { .. }));
        assert_eq!(peer.write_offsets().len(), writes);
        let remote = peer.remote.lock().unwrap();
        assert_eq!(remote.renamed, 0);
        if change < 2 {
            assert_eq!(remote.removed, 0, "a replaced staging path is not ours to remove");
        }
    }
}

#[tokio::test]
async fn retained_source_handle_survives_source_pathname_replacement() {
    let peer = Peer::start().await;
    let directory = tempfile::tempdir().unwrap();
    let (path, expected) = source(directory.path());
    let checkpoint = peer.paused(&path).await;
    std::fs::rename(&path, directory.path().join("retained.bin")).unwrap();
    std::fs::write(&path, b"different pathname contents").unwrap();
    let (_sender, control) = watch::channel(TransferControl::Run);
    assert!(matches!(
        peer.run(UploadInput::Resume(checkpoint), control, |_| {}).await,
        UploadExecution::Published
    ));
    assert_eq!(peer.remote.lock().unwrap().target.as_ref(), Some(&expected));
}

#[tokio::test]
async fn paused_cleanup_and_pre_dispatch_cancel_settle_or_report_retained_staging() {
    for refusal in [false, true] {
        let peer = Peer::start().await;
        let directory = tempfile::tempdir().unwrap();
        let (path, _) = source(directory.path());
        let checkpoint = peer.paused(&path).await;
        peer.remote.lock().unwrap().refuse_cleanup = refusal;
        assert_eq!(checkpoint.discard().await, !refusal);
        assert_eq!(peer.remote.lock().unwrap().removed, 1);
    }
    let peer = Peer::start().await;
    let directory = tempfile::tempdir().unwrap();
    let (path, _) = source(directory.path());
    let checkpoint = peer.paused(&path).await;
    let (_sender, control) = watch::channel(TransferControl::Cancel);
    assert!(matches!(
        peer.run(UploadInput::Resume(checkpoint), control, |_| {}).await,
        UploadExecution::Failed { error: FileAccessError::Cancelled, staging_may_remain: false }
    ));
    assert_eq!(peer.remote.lock().unwrap().removed, 1);
}

#[tokio::test]
async fn lost_publication_reply_stays_unknown_without_cleanup_or_replay() {
    let peer = Peer::start().await;
    peer.remote.lock().unwrap().lose_rename_reply = true;
    let directory = tempfile::tempdir().unwrap();
    let (path, _) = source(directory.path());
    let (_sender, control) = watch::channel(TransferControl::Run);
    assert!(matches!(
        peer.run(input(&path).await, control, |_| {}).await,
        UploadExecution::Failed {
            error: FileAccessError::PublicationUnknown,
            staging_may_remain: true
        }
    ));
    let remote = peer.remote.lock().unwrap();
    assert_eq!(remote.renamed, 1);
    assert_eq!(remote.removed, 0);
}
