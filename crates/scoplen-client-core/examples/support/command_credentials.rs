// SPDX-License-Identifier: Apache-2.0

use scoplen_client_core::{
    repository::{
        AccessProfile, AccessProfileChange, Credential, CredentialBinding, CredentialChange,
        CredentialKind, Edit, Host, HostChange, Repository,
    },
    session_files::{SessionDownloadStatus, SessionUploadStatus},
    session_manager::{SessionEvent, SessionManager},
    store::Store,
};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::TcpStream as BlockingStream,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
};
use uuid::Uuid;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const LITERALS: [&str; 8] = ["%h", "%p", "%r", "%%", "$HOME", "|", ">", ""];

pub(super) fn helper(args: &[String]) -> Result<()> {
    if args.len() != 15 || args[7..] != LITERALS {
        return Err("literal helper arguments changed".into());
    }
    let mut lease = BlockingStream::connect(("127.0.0.1", args[4].parse()?))?;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args[5])?
        .write_all(format!("{}\n", args[6]).as_bytes())?;
    lease.write_all(format!("{}\n", args[6]).as_bytes())?;
    if std::io::stdin().read(&mut [0])? != 0 {
        return Err("provider stdin was not null".into());
    }
    let password = Zeroizing::new(fs::read(&args[3])?);
    let mut stdout = std::io::stdout().lock();
    match args[2].as_str() {
        "empty" => {}
        "oversize" => stdout.write_all(&vec![b'x'; 17000])?,
        "wrong" => stdout.write_all(b"wrong-disposable-password")?,
        "stall" => std::thread::sleep(Duration::from_secs(60)),
        mode => {
            stdout.write_all(&password)?;
            if mode == "lf" {
                stdout.write_all(b"\n")?;
            }
            if mode == "crlf" {
                stdout.write_all(b"\r\n")?;
            }
            stdout.flush()?;
            if mode == "exit" {
                std::process::exit(7);
            }
            if mode == "no-exit" {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
    }
    stdout.flush()?;
    std::io::stderr().write_all(&vec![b'x'; 65536])?;
    drop(lease);
    Ok(())
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

pub(super) fn provider(
    executable: &Path,
    mode: &str,
    password: &Path,
    lease: u16,
    marker: &Path,
    label: &str,
    field: &str,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut arguments = vec![
        "helper".into(),
        mode.into(),
        password.to_str().unwrap().into(),
        lease.to_string(),
        marker.to_str().unwrap().into(),
        label.into(),
    ];
    arguments.extend(LITERALS.map(str::to_owned));
    let path = std::iter::once(quote(executable.to_str().unwrap()))
        .chain(arguments.iter().map(|value| quote(value)))
        .collect::<Vec<_>>()
        .join(" ");
    (
        BTreeMap::from([
            ("type".into(), "command".into()),
            ("path".into(), path),
            ("field".into(), field.into()),
        ]),
        arguments,
    )
}

pub(super) fn login(
    store: &Store,
    port: u16,
    provider: BTreeMap<String, String>,
    label: &str,
) -> Result<(Uuid, Uuid)> {
    let host = Repository::<Host>::new(store).create(HostChange {
        name: Some(label.into()),
        address: Some("127.0.0.1".into()),
        port: Edit::Set(port),
        ..Default::default()
    })?;
    let credential = Repository::<Credential>::new(store).create(CredentialChange {
        kind: Some(CredentialKind::ExternalProvider),
        binding: Some(CredentialBinding::None),
        provider: provider.into_iter().map(|(key, value)| (key, Some(value))).collect(),
        ..Default::default()
    })?;
    let profile = Repository::<AccessProfile>::new(store).create(AccessProfileChange {
        host: Some(host.meta.id),
        username: Some("smoke".into()),
        credential: Edit::Set(credential.meta.id),
        ..Default::default()
    })?;
    Ok((profile.meta.id, credential.meta.id))
}

pub(super) struct Relay {
    task: JoinHandle<()>,
    open: Arc<AtomicUsize>,
    pub(super) port: u16,
    pub(super) accepted: Arc<AtomicUsize>,
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Relay {
    pub(super) async fn start(destination: u16) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let open = Arc::new(AtomicUsize::new(0));
        let count = open.clone();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepts = accepted.clone();
        let task = tokio::spawn(async move {
            let mut peers = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut client, _)) = accepted else { break; };
                        accepts.fetch_add(1, Ordering::SeqCst);
                        let count = count.clone();
                        peers.spawn(async move {
                            let Ok(mut upstream) = TcpStream::connect(("127.0.0.1", destination)).await else { return; };
                            count.fetch_add(1, Ordering::SeqCst);
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                            count.fetch_sub(1, Ordering::SeqCst);
                        });
                    },
                    _ = peers.join_next(), if !peers.is_empty() => {},
                }
            }
        });
        Ok(Self { task, open, port, accepted })
    }
    pub(super) async fn idle(&self) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.open.load(Ordering::SeqCst) != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "retained SSH chain was not released".into())
    }
}

pub(super) async fn leases(listener: &TcpListener, labels: &[&str]) -> Result<Vec<TcpStream>> {
    let mut result = Vec::new();
    for label in labels {
        let (mut stream, _) =
            tokio::time::timeout(Duration::from_secs(10), listener.accept()).await??;
        let mut actual = vec![0; label.len() + 1];
        stream.read_exact(&mut actual).await?;
        assert_eq!(actual, format!("{label}\n").as_bytes());
        result.push(stream);
    }
    Ok(result)
}

pub(super) async fn released(mut streams: Vec<TcpStream>) -> Result<()> {
    for stream in &mut streams {
        let result = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut [0])).await?;
        assert!(
            matches!(result, Ok(0))
                || result.is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionReset),
            "owned helper retained its independent lease"
        );
    }
    Ok(())
}

pub(super) async fn ready(events: &mut mpsc::UnboundedReceiver<SessionEvent>) -> Result<String> {
    loop {
        match events.recv().await.ok_or("session events ended")? {
            SessionEvent::Ready { transport_id } => return Ok(transport_id),
            SessionEvent::Failed { error, .. } => return Err(error.into()),
            _ => {}
        }
    }
}

pub(super) async fn files(
    manager: &SessionManager,
    transport: &str,
    directory: &Path,
) -> Result<()> {
    let source = directory.join(format!("provider-{}.bin", Uuid::now_v7()));
    let expected: Vec<u8> = (0..=255).cycle().take(8192).collect();
    fs::write(&source, &expected)?;
    manager.list_files("terminal", transport, &Uuid::now_v7().to_string(), b".".to_vec()).await?;
    let upload = manager
        .upload_file_with_picker(
            "terminal",
            transport,
            &Uuid::now_v7().to_string(),
            b".".to_vec(),
            || async { Ok(Some(source.clone())) },
            |_| async { Err("fresh fixture must not overwrite".into()) },
            |_| {},
        )
        .await?;
    assert_eq!(upload.status, SessionUploadStatus::Saved);
    let remote = manager
        .list_files("terminal", transport, &Uuid::now_v7().to_string(), b".".to_vec())
        .await?
        .entries
        .into_iter()
        .find(|entry| entry.name == source.file_name().unwrap().to_str().unwrap())
        .ok_or("uploaded file missing")?
        .path;
    let destination = directory.join("download.bin");
    let download = manager
        .download_file_with_picker(
            "terminal",
            transport,
            &Uuid::now_v7().to_string(),
            remote,
            || async { Ok(Some(destination.clone())) },
            |_| {},
        )
        .await?;
    assert_eq!(download.status, SessionDownloadStatus::Saved);
    assert_eq!(fs::read(destination)?, expected);
    Ok(())
}
