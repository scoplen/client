// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use russh::server;
use scoplen_crypto::SecretVec;
use scoplen_ssh::SftpNameEntry;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::connection::{ConnectionPlan, ConnectionRoute, CredentialMaterial};

use super::*;

#[derive(Clone, Copy)]
enum Fault {
    IncompleteListing,
    EmptyListing,
    DelayedListing,
    ChangedSecondSource,
    LostMkdirAck(usize),
    LostSecondRenameAck,
    RefuseSecondWrite,
}

struct Node {
    bytes: Option<Vec<u8>>,
    modified: u32,
}

impl Node {
    fn attrs(&self) -> SftpAttributes {
        match &self.bytes {
            Some(bytes) => SftpAttributes {
                size: Some(bytes.len() as u64),
                permissions: Some(0o100600),
                access_time: Some(100),
                modify_time: Some(self.modified),
                ..Default::default()
            },
            None => SftpAttributes { permissions: Some(0o040700), ..Default::default() },
        }
    }
}

struct State {
    fault: Fault,
    delayed_listings: usize,
    nodes: BTreeMap<Vec<u8>, Node>,
    lstats: BTreeMap<Vec<u8>, usize>,
    opened_sources: Vec<Vec<u8>>,
    created_staging: Vec<Vec<u8>>,
    mkdirs: Vec<Vec<u8>>,
    renames: Vec<Vec<u8>>,
    removes: Vec<Vec<u8>>,
}

impl State {
    fn new(fault: Fault) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(b"./root".to_vec(), Node { bytes: None, modified: 100 });
        if matches!(fault, Fault::IncompleteListing | Fault::ChangedSecondSource) {
            for (name, bytes) in [(b"a", b"first"), (b"b", b"next!"), (b"c", b"third")] {
                let mut path = b"./root/".to_vec();
                path.extend_from_slice(name);
                nodes.insert(path, Node { bytes: Some(bytes.to_vec()), modified: 100 });
            }
        }
        Self {
            fault,
            delayed_listings: 0,
            nodes,
            lstats: BTreeMap::new(),
            opened_sources: Vec::new(),
            created_staging: Vec::new(),
            mkdirs: Vec::new(),
            renames: Vec::new(),
            removes: Vec::new(),
        }
    }
}

fn status(id: u32, code: u32) -> SftpPacket {
    SftpPacket::Status { id, code, message: Vec::new(), language: Vec::new() }
}

struct Handler {
    state: Arc<Mutex<State>>,
    buffers: HashMap<russh::ChannelId, Vec<u8>>,
    listed: HashMap<russh::ChannelId, bool>,
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
        bytes: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let buffer = self.buffers.entry(channel).or_default();
        buffer.extend_from_slice(bytes);
        while buffer.len() >= 4 {
            let length = u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize + 4;
            if buffer.len() < length {
                break;
            }
            let packet = SftpPacket::decode(&buffer.drain(..length).collect::<Vec<_>>()).unwrap();
            if let SftpPacket::Readdir { id, .. } = &packet {
                let delayed = {
                    let mut state = self.state.lock().unwrap();
                    if matches!(state.fault, Fault::DelayedListing) {
                        state.delayed_listings += 1;
                        let name = format!("entry-{}", state.delayed_listings).into_bytes();
                        let node = Node { bytes: Some(Vec::new()), modified: 100 };
                        let attrs = node.attrs();
                        let mut path = b"./root/".to_vec();
                        path.extend_from_slice(&name);
                        state.nodes.insert(path, node);
                        Some(SftpNameEntry { filename: name, longname: Vec::new(), attrs })
                    } else {
                        None
                    }
                };
                if let Some(entry) = delayed {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    session.data(
                        channel,
                        SftpPacket::Name { id: *id, entries: vec![entry] }.encode().unwrap(),
                    )?;
                    continue;
                }
            }
            let mut state = self.state.lock().unwrap();
            let response = match packet {
                SftpPacket::Init { .. } => {
                    SftpPacket::Version { version: 3, extensions: Vec::new() }
                }
                SftpPacket::Lstat { id, path } => {
                    let count = state.lstats.entry(path.clone()).or_default();
                    *count += 1;
                    let changed = *count == 2
                        && path == b"./root/b"
                        && matches!(state.fault, Fault::ChangedSecondSource);
                    if changed {
                        state.nodes.get_mut(&path).unwrap().modified += 1;
                    }
                    match state.nodes.get(&path) {
                        Some(node) => SftpPacket::Attrs { id, attrs: node.attrs() },
                        None => status(id, 2),
                    }
                }
                SftpPacket::Opendir { id, path } => {
                    assert_eq!(path, b"./root");
                    SftpPacket::Handle { id, handle: path }
                }
                SftpPacket::Readdir { id, .. } => {
                    let listed = self.listed.entry(channel).or_default();
                    if *listed {
                        if matches!(state.fault, Fault::IncompleteListing) {
                            session.close(channel)?;
                            continue;
                        }
                        status(id, 1)
                    } else {
                        *listed = true;
                        let entries = state
                            .nodes
                            .iter()
                            .filter_map(|(path, node)| {
                                let name = path.strip_prefix(b"./root/")?;
                                Some(SftpNameEntry {
                                    filename: name.to_vec(),
                                    longname: Vec::new(),
                                    attrs: node.attrs(),
                                })
                            })
                            .collect();
                        SftpPacket::Name { id, entries }
                    }
                }
                SftpPacket::Mkdir { id, path, .. } => {
                    assert!(!state.nodes.contains_key(&path), "mkdir must not be replayed");
                    state.mkdirs.push(path.clone());
                    state.nodes.insert(path, Node { bytes: None, modified: 100 });
                    if matches!(state.fault, Fault::LostMkdirAck(attempt) if attempt == state.mkdirs.len())
                    {
                        session.close(channel)?;
                        continue;
                    }
                    status(id, 0)
                }
                SftpPacket::Open { id, path, pflags, .. } => {
                    if pflags == EXCLUSIVE_WRITE_OPEN {
                        assert!(!state.nodes.contains_key(&path), "staging must not be replayed");
                        state.created_staging.push(path.clone());
                        state
                            .nodes
                            .insert(path.clone(), Node { bytes: Some(Vec::new()), modified: 100 });
                        SftpPacket::Handle { id, handle: path }
                    } else {
                        assert_eq!(pflags, 1);
                        if state.created_staging.contains(&path) {
                            status(id, 3)
                        } else {
                            assert!(state.nodes.contains_key(&path));
                            state.opened_sources.push(path.clone());
                            SftpPacket::Handle { id, handle: path }
                        }
                    }
                }
                SftpPacket::Fstat { id, handle } => {
                    SftpPacket::Attrs { id, attrs: state.nodes.get(&handle).unwrap().attrs() }
                }
                SftpPacket::Read { id, handle, offset, length } => {
                    let bytes = state.nodes.get(&handle).unwrap().bytes.as_ref().unwrap();
                    let start = offset as usize;
                    if start >= bytes.len() {
                        status(id, 1)
                    } else {
                        let end = (start + length as usize).min(bytes.len());
                        SftpPacket::Data { id, data: bytes[start..end].to_vec() }
                    }
                }
                SftpPacket::Write { id, handle, offset, data } => {
                    if matches!(state.fault, Fault::RefuseSecondWrite)
                        && state.created_staging.len() == 2
                    {
                        status(id, 3)
                    } else {
                        let bytes = state.nodes.get_mut(&handle).unwrap().bytes.as_mut().unwrap();
                        let start = offset as usize;
                        bytes.resize(start + data.len(), 0);
                        bytes[start..start + data.len()].copy_from_slice(&data);
                        status(id, 0)
                    }
                }
                SftpPacket::Rename { id, old_path, new_path } => {
                    assert!(state.created_staging.contains(&old_path));
                    assert!(!state.nodes.contains_key(&new_path));
                    let node = state.nodes.remove(&old_path).expect("owned staging exists");
                    state.nodes.insert(new_path.clone(), node);
                    state.renames.push(new_path);
                    if matches!(state.fault, Fault::LostSecondRenameAck) && state.renames.len() == 2
                    {
                        session.close(channel)?;
                        continue;
                    }
                    status(id, 0)
                }
                SftpPacket::Remove { id, path } => {
                    assert!(state.created_staging.contains(&path), "cleanup owns only its staging");
                    state.nodes.remove(&path).expect("owned staging remains");
                    state.removes.push(path);
                    status(id, 0)
                }
                SftpPacket::Close { id, .. } => status(id, 0),
                other => panic!("unexpected directory-copy request: {other:?}"),
            };
            session.data(channel, response.encode().unwrap())?;
        }
        Ok(())
    }
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

impl Peer {
    async fn start(fault: Fault) -> Self {
        let state = Arc::new(Mutex::new(State::new(fault)));
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
        let handler =
            Handler { state: state.clone(), buffers: HashMap::new(), listed: HashMap::new() };
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
        connection.authenticate().await.unwrap();
        Self { connection, state, task }
    }

    async fn run(
        &self,
        local: &Path,
        direction: Direction,
    ) -> (DirectoryCopyResult, u64, Option<u64>, Progress) {
        let observed = Arc::new(Mutex::new((0, None, Progress::default())));
        let updates = observed.clone();
        let (_sender, control) = watch::channel(TransferControl::Run);
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            copy(
                &self.connection,
                DirectoryCopy {
                    local: local.to_path_buf(),
                    remote: b"./root".to_vec(),
                    root_name: b"copy".to_vec(),
                    direction,
                },
                control,
                Callbacks {
                    progress: Arc::new(move |bytes, total, progress| {
                        *updates.lock().unwrap() = (bytes, total, progress);
                    }),
                    authorize: Arc::new(|| Ok(())),
                    settled: Arc::new(|| {}),
                    state: Arc::new(UploadState::default()),
                },
            ),
        )
        .await
        .expect("faulted copy must settle without awaiting the enumeration deadline");
        let (bytes, total, progress) = observed.lock().unwrap().clone();
        (result, bytes, total, progress)
    }
}

#[tokio::test]
async fn incomplete_remote_listing_never_creates_destination_root() {
    let root = tempfile::tempdir().unwrap();
    let peer = Peer::start(Fault::IncompleteListing).await;
    let (result, bytes, total, progress) = peer.run(root.path(), Direction::Download).await;
    assert!(matches!(result.issue, Some(Issue::Failed | Issue::Unavailable)));
    assert!(!result.staging_may_remain);
    assert_eq!((bytes, total, progress.files_total), (0, None, None));
    assert!(!progress.root_created && !progress.root_creation_unknown);
    assert_eq!((progress.files_completed, progress.directories_created), (0, 0));
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    assert!(peer.state.lock().unwrap().opened_sources.is_empty());
}

#[tokio::test]
async fn empty_remote_name_packet_never_creates_destination_root() {
    let root = tempfile::tempdir().unwrap();
    let peer = Peer::start(Fault::EmptyListing).await;
    let (result, bytes, total, progress) = peer.run(root.path(), Direction::Download).await;
    assert_eq!(result.issue, Some(Issue::Failed));
    assert!(!result.staging_may_remain);
    assert_eq!((bytes, total, progress.files_total), (0, None, None));
    assert!(!progress.root_created && !progress.root_creation_unknown);
    assert_eq!((progress.files_completed, progress.directories_created), (0, 0));
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    assert!(peer.state.lock().unwrap().opened_sources.is_empty());
}

#[tokio::test]
async fn absolute_enumeration_deadline_stops_responsive_listing_before_root_creation() {
    let root = tempfile::tempdir().unwrap();
    let peer = Peer::start(Fault::DelayedListing).await;
    let (_sender, control) = watch::channel(TransferControl::Run);
    let observed = Arc::new(Mutex::new(Progress::default()));
    let updates = observed.clone();
    let copy = copy(
        &peer.connection,
        DirectoryCopy {
            local: root.path().to_path_buf(),
            remote: b"./root".to_vec(),
            root_name: b"copy".to_vec(),
            direction: Direction::Download,
        },
        control,
        Callbacks {
            progress: Arc::new(move |_, _, progress| *updates.lock().unwrap() = progress),
            authorize: Arc::new(|| panic!("enumeration must not authorize any effect")),
            settled: Arc::new(|| panic!("enumeration has no dispatched effect")),
            state: Arc::new(UploadState::default()),
        },
    );
    tokio::pin!(copy);
    tokio::time::pause();
    for batch in 1..=30 {
        let wall_deadline = std::time::Instant::now() + Duration::from_secs(5);
        while peer.state.lock().unwrap().delayed_listings < batch {
            assert!(
                std::time::Instant::now() < wall_deadline,
                "listing batch {batch} did not progress"
            );
            tokio::select! {
                _ = &mut copy => panic!("responsive requests must not hit a per-step timeout"),
                _ = tokio::task::yield_now() => {},
            }
        }
        // Cross the timer wheel's rounding tick while staying below each request deadline.
        tokio::time::advance(Duration::from_millis(10_010)).await;
    }
    let result = copy.await;
    assert_eq!(result.issue, Some(Issue::Timeout));
    assert!(!result.staging_may_remain);
    let progress = observed.lock().unwrap();
    assert_eq!((progress.files_total, progress.directories_total), (None, None));
    assert_eq!((progress.files_completed, progress.directories_created), (0, 0));
    assert!(!progress.root_created && !progress.root_creation_unknown);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    assert!(peer.state.lock().unwrap().opened_sources.is_empty());
}

#[tokio::test]
async fn changed_source_stops_after_exact_confirmed_partial_download() {
    let root = tempfile::tempdir().unwrap();
    let peer = Peer::start(Fault::ChangedSecondSource).await;
    let (result, bytes, total, progress) = peer.run(root.path(), Direction::Download).await;
    assert_eq!(result.issue, Some(Issue::SourceChanged));
    assert!(!result.staging_may_remain);
    assert_eq!((bytes, total), (5, Some(15)));
    assert_eq!((progress.files_total, progress.files_completed), (Some(3), 1));
    assert_eq!((progress.directories_created, progress.root_created), (1, true));
    assert_eq!(std::fs::read(root.path().join("copy/a")).unwrap(), b"first");
    assert_eq!(std::fs::read_dir(root.path().join("copy")).unwrap().count(), 1);
    assert_eq!(peer.state.lock().unwrap().opened_sources, [b"./root/a".to_vec()]);
}

#[tokio::test]
async fn lost_actual_mkdir_ack_stops_without_replay_or_claiming_creation() {
    for attempt in [1, 2] {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("one")).unwrap();
        std::fs::create_dir(root.path().join("two")).unwrap();
        let peer = Peer::start(Fault::LostMkdirAck(attempt)).await;
        let (result, bytes, total, progress) = peer.run(root.path(), Direction::Upload).await;
        assert_eq!(result.issue, Some(Issue::PublicationUnknown));
        assert!(!result.staging_may_remain);
        assert_eq!((bytes, total), (0, Some(0)));
        assert_eq!((progress.files_completed, progress.directories_total), (0, Some(3)));
        assert_eq!(progress.directories_created, (attempt - 1) as u32);
        assert_eq!(progress.root_created, attempt == 2);
        assert_eq!(progress.root_creation_unknown, attempt == 1);
        let state = peer.state.lock().unwrap();
        assert_eq!(state.mkdirs.len(), attempt);
        assert!(state.created_staging.is_empty() && state.renames.is_empty());
        assert!(state.removes.is_empty());
        assert!(state.nodes.contains_key(b"./root/copy".as_slice()));
    }
}

#[tokio::test]
async fn lost_child_rename_ack_keeps_confirmed_counts_and_never_cleans_or_replays() {
    let root = tempfile::tempdir().unwrap();
    for name in ["a", "b", "c"] {
        std::fs::write(root.path().join(name), b"bytes").unwrap();
    }
    let peer = Peer::start(Fault::LostSecondRenameAck).await;
    let (result, bytes, total, progress) = peer.run(root.path(), Direction::Upload).await;
    assert_eq!(result.issue, Some(Issue::PublicationUnknown));
    assert!(result.staging_may_remain);
    assert_eq!((bytes, total), (10, Some(15)));
    assert_eq!((progress.files_total, progress.files_completed), (Some(3), 1));
    assert_eq!((progress.directories_created, progress.root_created), (1, true));
    assert!(!progress.root_creation_unknown);
    let state = peer.state.lock().unwrap();
    assert_eq!(state.renames.len(), 2);
    assert_eq!(state.created_staging.len(), 2);
    assert!(state.removes.is_empty());
    for path in &state.renames {
        assert_eq!(state.nodes.get(path).unwrap().bytes.as_deref(), Some(b"bytes".as_slice()));
    }
}

#[tokio::test]
async fn refused_child_write_cleans_only_owned_staging_and_retains_completed_file() {
    let root = tempfile::tempdir().unwrap();
    for name in ["a", "b", "c"] {
        std::fs::write(root.path().join(name), b"bytes").unwrap();
    }
    let peer = Peer::start(Fault::RefuseSecondWrite).await;
    let (result, _, total, progress) = peer.run(root.path(), Direction::Upload).await;
    assert_eq!(result.issue, Some(Issue::RemoteDenied));
    assert!(!result.staging_may_remain);
    assert_eq!(total, Some(15));
    assert_eq!((progress.files_total, progress.files_completed), (Some(3), 1));
    assert_eq!((progress.directories_created, progress.root_created), (1, true));
    let state = peer.state.lock().unwrap();
    assert_eq!(state.renames.len(), 1);
    assert_eq!(state.created_staging.len(), 2);
    assert_eq!(state.removes, [state.created_staging[1].clone()]);
    assert_eq!(state.nodes.len(), 3, "only parent, created root and completed file remain");
    assert_eq!(
        state.nodes.get(&state.renames[0]).unwrap().bytes.as_deref(),
        Some(b"bytes".as_slice())
    );
}
