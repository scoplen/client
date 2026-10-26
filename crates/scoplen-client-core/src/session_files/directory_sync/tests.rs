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

#[derive(Clone)]
struct Entry {
    bytes: Vec<u8>,
    attrs: SftpAttributes,
}

impl Entry {
    fn file(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            attrs: SftpAttributes {
                size: Some(bytes.len() as u64),
                permissions: Some(0o100600),
                access_time: Some(100),
                modify_time: Some(100),
                ..Default::default()
            },
        }
    }

    fn directory() -> Self {
        Self {
            bytes: Vec::new(),
            attrs: SftpAttributes { permissions: Some(0o040700), ..Default::default() },
        }
    }
}

#[derive(Default)]
struct State {
    entries: BTreeMap<Vec<u8>, Entry>,
    reads: Vec<(Vec<u8>, u64, u32)>,
    listing: Option<Vec<Vec<u8>>>,
    incomplete: bool,
    refuse_listing: bool,
    grow_on_read: bool,
    stall: bool,
    zero_filled: bool,
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
    listed: HashMap<russh::ChannelId, usize>,
}

fn status(id: u32, code: u32) -> SftpPacket {
    SftpPacket::Status { id, code, message: b"private status".to_vec(), language: Vec::new() }
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
        loop {
            if buffer.len() < 4 {
                break;
            }
            let length = u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize;
            if buffer.len() < length + 4 {
                break;
            }
            let packet = SftpPacket::decode(&buffer[..length + 4]).unwrap();
            buffer.drain(..length + 4);
            let response = {
                let mut state = self.state.lock().unwrap();
                match packet {
                    SftpPacket::Init { .. } => {
                        SftpPacket::Version { version: 3, extensions: Vec::new() }
                    }
                    SftpPacket::Opendir { id, path } => {
                        assert_eq!(path, b"./root");
                        SftpPacket::Handle { id, handle: b"directory".to_vec() }
                    }
                    SftpPacket::Readdir { id, .. } => {
                        if state.refuse_listing {
                            status(id, 3)
                        } else {
                            let names = state
                                .listing
                                .clone()
                                .unwrap_or_else(|| state.entries.keys().cloned().collect());
                            let offset = self.listed.entry(channel).or_default();
                            if *offset >= names.len() && !state.incomplete {
                                status(id, 1)
                            } else {
                                let end = (*offset + MAX_DIRECTORY_ENTRIES).min(names.len());
                                let entries = names[*offset..end]
                                    .iter()
                                    .map(|filename| {
                                        let attrs = state
                                            .entries
                                            .get(filename)
                                            .map(|entry| entry.attrs.clone())
                                            .unwrap_or_default();
                                        SftpNameEntry {
                                            filename: filename.clone(),
                                            longname: Vec::new(),
                                            attrs,
                                        }
                                    })
                                    .collect();
                                *offset = end;
                                SftpPacket::Name { id, entries }
                            }
                        }
                    }
                    SftpPacket::Lstat { id, path } | SftpPacket::Fstat { id, handle: path } => {
                        if path == b"./root" {
                            SftpPacket::Attrs { id, attrs: Entry::directory().attrs }
                        } else if let Some(entry) =
                            state.entries.get(path.strip_prefix(b"./root/").unwrap_or(&path))
                        {
                            let mut attrs = entry.attrs.clone();
                            attrs.access_time = Some(state.reads.len() as u32);
                            SftpPacket::Attrs { id, attrs }
                        } else {
                            status(id, 2)
                        }
                    }
                    SftpPacket::Open { id, path, pflags, .. } => {
                        assert_eq!(pflags, 1, "comparison must only open for reading");
                        SftpPacket::Handle { id, handle: path }
                    }
                    SftpPacket::Read { id, handle, offset, length } => {
                        state.reads.push((handle.clone(), offset, length));
                        if state.stall {
                            continue;
                        }
                        let entry = state
                            .entries
                            .get(handle.strip_prefix(b"./root/").unwrap_or(&handle))
                            .unwrap();
                        let start = offset as usize;
                        if state.zero_filled && offset < entry.attrs.size.unwrap_or(0) {
                            SftpPacket::Data {
                                id,
                                data: vec![
                                    0;
                                    u64::from(length).min(entry.attrs.size.unwrap() - offset)
                                        as usize
                                ],
                            }
                        } else if start >= entry.bytes.len() {
                            if state.grow_on_read {
                                SftpPacket::Data { id, data: vec![b'x'] }
                            } else {
                                status(id, 1)
                            }
                        } else {
                            let end = (start + length as usize).min(entry.bytes.len());
                            SftpPacket::Data { id, data: entry.bytes[start..end].to_vec() }
                        }
                    }
                    SftpPacket::Close { id, .. } => status(id, 0),
                    _ => panic!("directory comparison issued a write or unsupported request"),
                }
            };
            session.data(channel, response.encode().unwrap())?;
        }
        Ok(())
    }
}

impl Peer {
    async fn start(entries: &[(&[u8], Entry)]) -> Self {
        let state = Arc::new(Mutex::new(State {
            entries: entries.iter().map(|(name, entry)| (name.to_vec(), entry.clone())).collect(),
            ..Default::default()
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

    async fn compare(
        &self,
        root: &Path,
        direction: SessionTransferDirection,
    ) -> Result<ComparedDirectory, Issue> {
        compare(&self.connection, b"./root".to_vec(), root.to_path_buf(), direction).await
    }
}

pub(crate) async fn upload_plan(root: &Path) -> ComparedDirectory {
    Peer::start(&[]).await.compare(root, SessionTransferDirection::Upload).await.unwrap()
}

#[tokio::test]
async fn complete_binary_and_empty_comparison_distinguishes_all_actions_without_writes() {
    for direction in [SessionTransferDirection::Upload, SessionTransferDirection::Download] {
        let root = tempfile::tempdir().unwrap();
        let entries: &[(&[u8], Entry)] = &[
            (b"same.bin", Entry::file(&[0, 255, 3])),
            (b"empty", Entry::file(b"")),
            (b"different-size", Entry::file(b"longer")),
            (b"different-bytes", Entry::file(b"abc")),
            (b"remote-only", Entry::file(b"remote")),
            (b"subdirectory", Entry::directory()),
        ];
        for (name, bytes) in [
            ("same.bin", &[0, 255, 3][..]),
            ("empty", b""),
            ("different-size", b"x"),
            ("different-bytes", b"def"),
            ("local-only", b"local"),
        ] {
            tokio::fs::write(root.path().join(name), bytes).await.unwrap();
        }
        tokio::fs::create_dir(root.path().join("subdirectory")).await.unwrap();
        let peer = Peer::start(entries).await;
        let plan = peer.compare(root.path(), direction).await.unwrap();
        assert_eq!(plan.excluded, 1);
        let actions: BTreeMap<_, _> =
            plan.rows.iter().map(|row| (row.name.clone(), row.change)).collect();
        assert_eq!(actions.get(&b"same.bin"[..]), Some(&Change::Same));
        assert_eq!(actions.get(&b"empty"[..]), Some(&Change::Same));
        assert_eq!(actions.get(&b"different-size"[..]), Some(&Change::Changed));
        assert_eq!(actions.get(&b"different-bytes"[..]), Some(&Change::Changed));
        let (source_only, target_only) = match direction {
            SessionTransferDirection::Upload => (&b"local-only"[..], &b"remote-only"[..]),
            SessionTransferDirection::Download => (&b"remote-only"[..], &b"local-only"[..]),
        };
        assert_eq!(actions.get(source_only), Some(&Change::Create));
        assert!(!actions.contains_key(target_only));
        let before = peer.state.lock().unwrap().reads.len();
        validate(&peer.connection, &plan).await.unwrap();
        assert_eq!(peer.state.lock().unwrap().reads.len(), before, "Apply must not rehash");
        let snapshot =
            serde_json::to_string(&plan.snapshot("terminal", Uuid::now_v7(), Uuid::now_v7()))
                .unwrap();
        assert!(!snapshot.contains(&root.path().to_string_lossy().replace('\\', "\\\\")));
        assert_eq!(tokio::fs::read(root.path().join("different-size")).await.unwrap(), b"x");
        assert_eq!(local_files(root.path()).await.unwrap().0.len(), 5);
        assert!(
            peer.state.lock().unwrap().reads.iter().all(|(_, _, length)| *length <= READ_CHUNK)
        );
    }
}

#[tokio::test]
async fn source_membership_and_all_same_row_metadata_changes_require_comparison_again() {
    for direction in [SessionTransferDirection::Upload, SessionTransferDirection::Download] {
        for remote_change in [false, true] {
            let root = tempfile::tempdir().unwrap();
            tokio::fs::write(root.path().join("same"), b"same").await.unwrap();
            let peer = Peer::start(&[(b"same", Entry::file(b"same"))]).await;
            let plan = peer.compare(root.path(), direction).await.unwrap();
            if remote_change {
                peer.state
                    .lock()
                    .unwrap()
                    .entries
                    .get_mut(&b"same"[..])
                    .unwrap()
                    .attrs
                    .modify_time = Some(101);
            } else {
                tokio::fs::write(root.path().join("same"), b"changed").await.unwrap();
            }
            assert_eq!(validate(&peer.connection, &plan).await, Err(Issue::FileChanged));
        }
        let root = tempfile::tempdir().unwrap();
        let peer = Peer::start(&[]).await;
        let plan = peer.compare(root.path(), direction).await.unwrap();
        match direction {
            SessionTransferDirection::Upload => {
                tokio::fs::write(root.path().join("added"), b"x").await.unwrap();
            }
            SessionTransferDirection::Download => {
                peer.state.lock().unwrap().entries.insert(b"added".to_vec(), Entry::file(b"x"));
            }
        }
        assert_eq!(validate(&peer.connection, &plan).await, Err(Issue::FileChanged));
    }
}

#[tokio::test]
async fn oversized_incomplete_duplicate_and_invalid_source_listings_refuse_complete_plan() {
    let root = tempfile::tempdir().unwrap();
    let peer = Peer::start(&[(b"file", Entry::file(b"x"))]).await;
    for (names, issue) in [
        (vec![b"file".to_vec(); 17], Issue::TooManyFiles),
        (vec![b"file".to_vec(); MAX_DIRECTORY_ENTRIES + 1], Issue::TooManyFiles),
        (vec![b"file".to_vec(); 2], Issue::UnsupportedName),
        (vec![b"../escape".to_vec()], Issue::UnsupportedName),
    ] {
        peer.state.lock().unwrap().listing = Some(names);
        assert_eq!(
            peer.compare(root.path(), SessionTransferDirection::Download).await.err(),
            Some(issue)
        );
    }
    {
        let mut state = peer.state.lock().unwrap();
        state.listing = Some(Vec::new());
        state.incomplete = true;
    }
    assert_eq!(
        peer.compare(root.path(), SessionTransferDirection::Download).await.err(),
        Some(Issue::TooManyFiles)
    );
    assert!(peer.state.lock().unwrap().reads.is_empty());
}

#[tokio::test]
async fn source_links_special_entries_and_nonordinary_targets_are_refused() {
    for permissions in [0o120777, 0o010600] {
        let root = tempfile::tempdir().unwrap();
        let mut entry = Entry::file(b"x");
        entry.attrs.permissions = Some(permissions);
        let peer = Peer::start(&[(b"file", entry)]).await;
        assert_eq!(
            peer.compare(root.path(), SessionTransferDirection::Download).await.err(),
            Some(Issue::UnsupportedEntry)
        );
        tokio::fs::write(root.path().join("file"), b"x").await.unwrap();
        assert_eq!(
            peer.compare(root.path(), SessionTransferDirection::Upload).await.err(),
            Some(Issue::UnsupportedEntry)
        );
    }
    let root = tempfile::tempdir().unwrap();
    tokio::fs::create_dir(root.path().join("file")).await.unwrap();
    let peer = Peer::start(&[(b"file", Entry::file(b"x"))]).await;
    assert_eq!(
        peer.compare(root.path(), SessionTransferDirection::Download).await.err(),
        Some(Issue::UnsupportedEntry)
    );
}

#[tokio::test]
async fn colliding_download_names_never_create_partial_targets() {
    for (first, second) in [
        ("A", "a"),
        ("\u{00c4}.txt", "\u{00e4}.txt"),
        ("\u{00e9}.txt", "e\u{0301}.txt"),
        ("\u{0390}", "\u{0399}\u{0308}\u{0301}"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let peer = Peer::start(&[
            (first.as_bytes(), Entry::file(b"a")),
            (second.as_bytes(), Entry::file(b"b")),
        ])
        .await;
        assert_eq!(
            peer.compare(root.path(), SessionTransferDirection::Download).await.err(),
            Some(Issue::UnsupportedName)
        );
        assert!(
            tokio::fs::read_dir(root.path()).await.unwrap().next_entry().await.unwrap().is_none()
        );
    }
    let root = tempfile::tempdir().unwrap();
    let peer = Peer::start(&[(b"invalid-\xff", Entry::file(b"a"))]).await;
    assert_eq!(
        peer.compare(root.path(), SessionTransferDirection::Download).await.err(),
        Some(Issue::UnsupportedName)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn local_source_links_are_refused_without_following_them() {
    let root = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(root.path().join("missing"), root.path().join("link")).unwrap();
    assert_eq!(local_files(root.path()).await.err(), Some(Issue::UnsupportedEntry));
}

#[tokio::test]
async fn ordinary_file_count_and_complete_hash_bound_refuse_without_data_reads() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..17 {
        tokio::fs::write(root.path().join(format!("{index}")), b"x").await.unwrap();
    }
    assert_eq!(local_files(root.path()).await.err(), Some(Issue::TooManyFiles));
    let root = tempfile::tempdir().unwrap();
    let file = tokio::fs::File::create(root.path().join("large")).await.unwrap();
    file.set_len(MAX_HASH_FILE + 1).await.unwrap();
    drop(file);
    let mut remote = Entry::file(b"");
    remote.attrs.size = Some(MAX_HASH_FILE + 1);
    let peer = Peer::start(&[(b"large", remote)]).await;
    assert_eq!(
        peer.compare(root.path(), SessionTransferDirection::Upload).await.err(),
        Some(Issue::TooLarge)
    );
    assert!(peer.state.lock().unwrap().reads.is_empty());
}

#[tokio::test]
async fn complete_hash_budget_counts_both_endpoints_and_refuses_before_the_next_file() {
    let root = tempfile::tempdir().unwrap();
    let mut entry = Entry::file(b"");
    entry.attrs.size = Some(MAX_HASH_FILE);
    let peer = Peer::start(&[(b"a", entry.clone()), (b"b", entry.clone()), (b"c", entry)]).await;
    peer.state.lock().unwrap().zero_filled = true;
    for name in ["a", "b", "c"] {
        let file = tokio::fs::File::create(root.path().join(name)).await.unwrap();
        file.set_len(MAX_HASH_FILE).await.unwrap();
    }
    assert_eq!(
        peer.compare(root.path(), SessionTransferDirection::Upload).await.err(),
        Some(Issue::TooLarge)
    );
    let state = peer.state.lock().unwrap();
    assert!(
        state.reads.iter().any(|(path, offset, _)| path == b"./root/b" && *offset == MAX_HASH_FILE)
    );
    assert!(state.reads.iter().all(|(path, _, _)| path != b"./root/c"));
}

#[tokio::test]
async fn cancelling_a_stalled_comparison_releases_its_channel_for_a_fresh_comparison() {
    let root = tempfile::tempdir().unwrap();
    tokio::fs::write(root.path().join("file"), b"safe").await.unwrap();
    let peer = Peer::start(&[(b"file", Entry::file(b"safe"))]).await;
    peer.state.lock().unwrap().stall = true;
    {
        let pending = peer.compare(root.path(), SessionTransferDirection::Upload);
        tokio::pin!(pending);
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::select! {
                _ = &mut pending => panic!("stalled comparison must remain pending"),
                () = async { while peer.state.lock().unwrap().reads.is_empty() { tokio::task::yield_now().await; } } => {},
            }
        }).await.unwrap();
    }
    peer.state.lock().unwrap().stall = false;
    let plan = peer.compare(root.path(), SessionTransferDirection::Upload).await.unwrap();
    assert_eq!(plan.rows[0].change, Change::Same);
    assert_eq!(tokio::fs::read(root.path().join("file")).await.unwrap(), b"safe");
}

#[tokio::test]
async fn remote_eof_growth_and_listing_refusal_never_return_a_partial_plan() {
    let root = tempfile::tempdir().unwrap();
    tokio::fs::write(root.path().join("file"), b"abc").await.unwrap();
    let peer = Peer::start(&[(b"file", Entry::file(b"abc"))]).await;
    peer.state.lock().unwrap().grow_on_read = true;
    assert_eq!(
        peer.compare(root.path(), SessionTransferDirection::Upload).await.err(),
        Some(Issue::FileChanged)
    );
    peer.state.lock().unwrap().refuse_listing = true;
    assert_eq!(
        peer.compare(root.path(), SessionTransferDirection::Download).await.err(),
        Some(Issue::RemoteDenied)
    );
}

#[test]
fn native_names_require_one_lossless_child() {
    for name in [&b""[..], b".", b"..", b"a/b", b"a\0b"] {
        assert!(native_child(name).is_err());
    }
    assert_eq!(native_child(b"ordinary.txt").unwrap(), OsString::from("ordinary.txt"));
    #[cfg(windows)]
    for name in [&b"CON.txt"[..], b"a\\b", b"bad:", b"trail.", b"trail ", b"LPT9.log", b"\xff"] {
        assert!(native_child(name).is_err());
    }
}
