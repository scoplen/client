// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;

use russh::server;
use scoplen_crypto::SecretVec;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::connection::{ConnectionPlan, ConnectionRoute, CredentialMaterial};

use super::*;

pub(crate) struct Peer {
    connection: SshConnection,
    bytes: Arc<Mutex<Vec<u8>>>,
    reads: Arc<Mutex<Vec<(u64, u32)>>>,
    refuse_channels: Arc<AtomicBool>,
    refused_channels: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Handler {
    bytes: Arc<Mutex<Vec<u8>>>,
    reads: Arc<Mutex<Vec<(u64, u32)>>>,
    refuse_channels: Arc<AtomicBool>,
    refused_channels: Arc<AtomicUsize>,
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
        if self.refuse_channels.load(Ordering::SeqCst) {
            self.refused_channels.fetch_add(1, Ordering::SeqCst);
            reply.reject(russh::ChannelOpenFailure::ResourceShortage).await;
        } else {
            reply.accept().await;
        }
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
            let response = match packet {
                SftpPacket::Init { .. } => {
                    SftpPacket::Version { version: 3, extensions: Vec::new() }
                }
                SftpPacket::Open { id, .. } => {
                    SftpPacket::Handle { id, handle: b"original-handle".to_vec() }
                }
                SftpPacket::Fstat { id, handle } => {
                    assert_eq!(handle, b"original-handle");
                    SftpPacket::Attrs {
                        id,
                        attrs: SftpAttributes {
                            size: Some(self.bytes.lock().unwrap().len() as u64),
                            permissions: Some(0o100600),
                            access_time: Some(100 + self.reads.lock().unwrap().len() as u32),
                            modify_time: Some(100),
                            ..Default::default()
                        },
                    }
                }
                SftpPacket::Read { id, handle, offset, length } => {
                    assert_eq!(handle, b"original-handle");
                    self.reads.lock().unwrap().push((offset, length));
                    let bytes = self.bytes.lock().unwrap();
                    let start = offset as usize;
                    if start >= bytes.len() {
                        SftpPacket::Status {
                            id,
                            code: 1,
                            message: Vec::new(),
                            language: Vec::new(),
                        }
                    } else {
                        SftpPacket::Data {
                            id,
                            data: bytes[start..(start + length as usize).min(bytes.len())].to_vec(),
                        }
                    }
                }
                SftpPacket::Close { id, .. } => {
                    SftpPacket::Status { id, code: 0, message: Vec::new(), language: Vec::new() }
                }
                other => panic!("unexpected request: {other:?}"),
            };
            session.data(channel, response.encode().unwrap())?;
        }
        Ok(())
    }
}

impl Peer {
    pub(crate) async fn prepare(&self, input: DownloadInput) -> DownloadPreparation {
        prepare_download(&self.connection, input).await.unwrap()
    }

    pub(crate) async fn start() -> Self {
        let bytes = Arc::new(Mutex::new(
            (0..(3 * SEGMENT_BYTES + 17).div_ceil(8))
                .flat_map(u64::to_le_bytes)
                .take((3 * SEGMENT_BYTES + 17) as usize)
                .collect::<Vec<_>>(),
        ));
        let reads = Arc::new(Mutex::new(Vec::new()));
        let refuse_channels = Arc::new(AtomicBool::new(false));
        let refused_channels = Arc::new(AtomicUsize::new(0));
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
        let handler = Handler {
            bytes: bytes.clone(),
            reads: reads.clone(),
            refuse_channels: refuse_channels.clone(),
            refused_channels: refused_channels.clone(),
            buffers: HashMap::new(),
        };
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
            credential: CredentialMaterial::Password(SecretVec::new(
                b"disposable-fixture".to_vec(),
            )),
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
        connection.authenticate_with_passphrase(None).await.unwrap();
        Self { connection, bytes, reads, refuse_channels, refused_channels, task }
    }

    pub(crate) async fn paused(&self, destination: PathBuf) -> Box<DownloadCheckpoint> {
        let input = DownloadInput::New {
            remote_path: b"./source.bin".to_vec(),
            destination: DownloadDestination::capture(destination).await.unwrap(),
        };
        let prepared = prepare_download(&self.connection, input).await.unwrap();
        let (_sender, control) = watch::channel(TransferControl::Pause);
        match continue_download(prepared, control, |_| {}).await {
            DownloadExecution::Paused(checkpoint) => checkpoint,
            _ => panic!("expected a real checkpoint"),
        }
    }
}

pub(crate) async fn blocked_creation(
    prepared: DownloadPreparation,
    control: watch::Receiver<TransferControl>,
    started: tokio::sync::oneshot::Sender<PathBuf>,
    release: std::sync::mpsc::Receiver<()>,
) -> DownloadExecution {
    continue_download_with(
        prepared,
        control,
        |_| {},
        move |path| {
            let created = CreatedDownload::create(path.clone())?;
            started.send(path).unwrap();
            release.recv().unwrap();
            Ok(created)
        },
    )
    .await
}

#[tokio::test]
async fn refused_new_channel_does_not_evict_an_existing_download_checkpoint() {
    let peer = Peer::start().await;
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("saved.bin");
    let checkpoint = peer.paused(destination.clone()).await;
    let partial = checkpoint.temporary.path.clone();
    peer.refuse_channels.store(true, Ordering::SeqCst);
    let later = DownloadInput::New {
        remote_path: b"./later.bin".to_vec(),
        destination: DownloadDestination::capture(directory.path().join("later.bin"))
            .await
            .unwrap(),
    };
    assert!(prepare_download(&peer.connection, later).await.is_err());
    assert_eq!(peer.refused_channels.load(Ordering::SeqCst), 1);
    assert!(partial.exists());
    let (_sender, control) = watch::channel(TransferControl::Run);
    let DownloadExecution::Ready { prepared, .. } =
        continue_download(DownloadPreparation::Resume(checkpoint), control, |_| {}).await
    else {
        panic!("the original channel must remain usable after another channel was refused")
    };
    prepared.commit().unwrap();
    assert_eq!(std::fs::read(destination).unwrap(), *peer.bytes.lock().unwrap());
    assert!(!partial.exists());
    assert_eq!(peer.refused_channels.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn bounded_segments_retain_exact_partial_and_resume_after_prefix_validation() {
    let peer = Peer::start().await;
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("saved.bin");
    let checkpoint = peer.paused(destination.clone()).await;
    assert_eq!(checkpoint.offset, SEGMENT_BYTES);
    assert_eq!(std::fs::metadata(&checkpoint.temporary.path).unwrap().len(), SEGMENT_BYTES);
    assert!(!destination.exists());
    let first = peer.reads.lock().unwrap().clone();
    assert!(first.iter().all(|(offset, count)| offset + u64::from(*count) <= SEGMENT_BYTES));
    peer.reads.lock().unwrap().clear();
    let (_sender, control) = watch::channel(TransferControl::Run);
    let mut progress = Vec::new();
    let result = continue_download(DownloadPreparation::Resume(checkpoint), control, |update| {
        progress.push(update)
    })
    .await;
    let DownloadExecution::Ready { prepared, .. } = result else { panic!("resume failed") };
    prepared.commit().unwrap();
    assert_eq!(std::fs::read(destination).unwrap(), *peer.bytes.lock().unwrap());
    let reads = peer.reads.lock().unwrap();
    let validation_count = usize::try_from(SEGMENT_BYTES / u64::from(READ_CHUNK)).unwrap();
    assert_eq!(reads[0].0, 0);
    assert_eq!(reads[validation_count].0, SEGMENT_BYTES);
    assert!(reads[validation_count..].iter().all(|(offset, _)| *offset >= SEGMENT_BYTES));
    assert!(progress.iter().all(|update| update.transferred >= SEGMENT_BYTES));
    assert!(progress.windows(2).all(|pair| pair[0].transferred <= pair[1].transferred));
}

#[tokio::test]
async fn prefix_mutation_without_metadata_change_conflicts_and_preserves_destination() {
    let peer = Peer::start().await;
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("saved.bin");
    std::fs::write(&destination, b"original destination").unwrap();
    let checkpoint = peer.paused(destination.clone()).await;
    let partial = checkpoint.temporary.path.clone();
    peer.bytes.lock().unwrap()[0] ^= 1;
    let (_sender, control) = watch::channel(TransferControl::Run);
    assert!(matches!(
        continue_download(DownloadPreparation::Resume(checkpoint), control, |_| {}).await,
        DownloadExecution::Failed {
            error: FileAccessError::FileChanged,
            staging_may_remain: false
        }
    ));
    assert!(!partial.exists());
    assert_eq!(std::fs::read(destination).unwrap(), b"original destination");
}

#[tokio::test]
async fn replaced_partial_is_neither_resumed_nor_deleted() {
    let peer = Peer::start().await;
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("saved.bin");
    let checkpoint = peer.paused(destination.clone()).await;
    let partial = checkpoint.temporary.path.clone();
    let retained = directory.path().join("original-partial");
    std::fs::rename(&partial, &retained).unwrap();
    std::fs::copy(&retained, &partial).unwrap();
    let (_sender, control) = watch::channel(TransferControl::Run);
    assert!(matches!(
        continue_download(DownloadPreparation::Resume(checkpoint), control, |_| {}).await,
        DownloadExecution::Failed { error: FileAccessError::FileChanged, staging_may_remain: true }
    ));
    assert!(partial.exists());
    assert!(retained.exists());
    assert!(!destination.exists());
}

#[tokio::test]
async fn local_prefix_mutation_with_restored_timestamp_is_detected_by_digest() {
    let peer = Peer::start().await;
    let directory = tempfile::tempdir().unwrap();
    let checkpoint = peer.paused(directory.path().join("saved.bin")).await;
    let partial = checkpoint.temporary.path.clone();
    let file = std::fs::OpenOptions::new().write(true).open(&partial).unwrap();
    let times = file.metadata().unwrap();
    std::io::Write::write_all(&mut &file, b"changed").unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(times.modified().unwrap())).unwrap();
    let (_sender, control) = watch::channel(TransferControl::Run);
    assert!(matches!(
        continue_download(DownloadPreparation::Resume(checkpoint), control, |_| {}).await,
        DownloadExecution::Failed {
            error: FileAccessError::FileChanged,
            staging_may_remain: false
        }
    ));
    assert!(!partial.exists());
    assert!(
        peer.reads
            .lock()
            .unwrap()
            .iter()
            .all(|(offset, count)| offset + u64::from(*count) <= SEGMENT_BYTES)
    );
}

#[tokio::test]
async fn changed_source_size_and_changed_destination_fail_before_any_continuation() {
    let peer = Peer::start().await;
    let directory = tempfile::tempdir().unwrap();
    for source_changed in [true, false] {
        let destination =
            directory.path().join(if source_changed { "source.bin" } else { "target.bin" });
        let checkpoint = peer.paused(destination.clone()).await;
        let partial = checkpoint.temporary.path.clone();
        peer.reads.lock().unwrap().clear();
        if source_changed {
            peer.bytes.lock().unwrap().push(1);
        } else {
            std::fs::write(&destination, b"new local data").unwrap();
        }
        let (_sender, control) = watch::channel(TransferControl::Run);
        let result =
            continue_download(DownloadPreparation::Resume(checkpoint), control, |_| {}).await;
        assert!(matches!(
            result,
            DownloadExecution::Failed {
                error: FileAccessError::FileChanged | FileAccessError::Conflict,
                staging_may_remain: false
            }
        ));
        assert!(peer.reads.lock().unwrap().is_empty());
        assert!(!partial.exists());
        if !source_changed {
            assert_eq!(std::fs::read(destination).unwrap(), b"new local data");
        }
    }
}

#[tokio::test]
async fn repeated_pause_advances_the_original_partial_and_cancel_settles_its_cleanup() {
    let peer = Peer::start().await;
    let directory = tempfile::tempdir().unwrap();
    let checkpoint = peer.paused(directory.path().join("saved.bin")).await;
    let path = checkpoint.temporary.path.clone();
    let (sender, control) = watch::channel(TransferControl::Run);
    let result = continue_download(DownloadPreparation::Resume(checkpoint), control, |update| {
        if update.transferred >= SEGMENT_BYTES {
            sender.send_replace(TransferControl::Pause);
        }
    })
    .await;
    let DownloadExecution::Paused(checkpoint) = result else { panic!("second checkpoint missing") };
    assert_eq!(checkpoint.offset, 2 * SEGMENT_BYTES);
    assert_eq!(checkpoint.temporary.path, path);
    let (_sender, control) = watch::channel(TransferControl::Cancel);
    assert!(matches!(
        continue_download(DownloadPreparation::Resume(checkpoint), control, |_| {}).await,
        DownloadExecution::Failed { error: FileAccessError::Cancelled, staging_may_remain: false }
    ));
    assert!(!path.exists());
}

#[tokio::test]
async fn pause_never_drops_an_inflight_exchange_but_cancel_preempts_it() {
    let (sender, mut control) = watch::channel(TransferControl::Run);
    let task = tokio::spawn(async move {
        transfer_controlled(&mut control, std::future::pending::<Result<(), FileAccessError>>())
            .await
    });
    sender.send_replace(TransferControl::Pause);
    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    sender.send_replace(TransferControl::Cancel);
    assert!(matches!(task.await.unwrap(), Err(FileAccessError::Cancelled)));
}
