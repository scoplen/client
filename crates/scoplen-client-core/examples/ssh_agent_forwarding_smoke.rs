// SPDX-License-Identifier: Apache-2.0

//! Ordinary saved Login, terminal/SFTP/tunnels and real OpenSSH second-hop agent use.

use std::{path::Path, sync::Arc, time::Duration};

use scoplen_client_core::{
    connection::{
        SessionTarget,
        preparation::{PreparationEvent, PreparationResponse},
    },
    forward_manager::ForwardPhase,
    personal_server::PersonalServer,
    repository::{
        AccessProfile, AccessProfileChange, Credential, CredentialBinding, CredentialChange,
        CredentialKind, Edit, Forward, ForwardChange, ForwardKind, Host, HostChange, Repository,
    },
    session_files::{SessionDownloadStatus, SessionUploadStatus},
    session_manager::{SessionEvent, SessionManager},
    store::Store,
};
use scoplen_crypto::{LocalDatabaseKey, SecretVec};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use uuid::Uuid;

mod support {
    pub mod forwarded_agent;
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const SECOND_HOP: &str = "ssh -n -p 2223 -o BatchMode=yes -o PasswordAuthentication=no -o PreferredAuthentications=publickey -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/tmp/scoplen-agent-known-hosts -i /tmp/scoplen-agent-selected.pub smoke@127.0.0.1 'printf %s%s second- hop-ok'";
const SCOPE_CONTROL: &str = r#"python3 - <<'PY'
import base64, os, socket, struct
selected = base64.b64decode(open('/tmp/scoplen-agent-selected.pub').read().split()[1])
other = base64.b64decode(open('/tmp/scoplen-agent-other.pub').read().split()[1])
def string(value): return struct.pack('>I', len(value)) + value
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as agent:
    agent.settimeout(5)
    agent.connect(os.environ['SSH_AUTH_SOCK'])
    reader = agent.makefile('rb')
    def exchange(request):
        agent.sendall(string(request))
        header = reader.read(4)
        if len(header) != 4: raise RuntimeError('truncated response header')
        size = struct.unpack('>I', header)[0]
        if size > 262144: raise RuntimeError('oversized response')
        response = reader.read(size)
        if len(response) != size: raise RuntimeError('truncated response')
        return response
    identities = exchange(b'\x0b')
    expected = b'\x0c' + struct.pack('>I', 1) + string(selected) + string(b'')
    if identities != expected: raise RuntimeError('forwarded identities were not exact')
    for forbidden in [b'\x13', b'\x1b' + string(b'query'), b'\x0d' + string(other) + string(b'unselected') + struct.pack('>I', 0)]:
        if exchange(forbidden) != b'\x05': raise RuntimeError('forbidden request was accepted')
        if exchange(b'\x0b') != expected: raise RuntimeError('refusal damaged identity queries')
PY"#;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err("usage: ssh_agent_forwarding_smoke <host> <port> <selected-private-key> <other-private-key>".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(run(&args)))
}

async fn ready(events: &mut mpsc::UnboundedReceiver<SessionEvent>) -> Result<String> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match events.recv().await.ok_or("terminal events ended")? {
                SessionEvent::Ready { transport_id } => return Ok(transport_id),
                SessionEvent::Failed { error, .. } => return Err(error.into()),
                SessionEvent::Closed => return Err("terminal closed before ready".into()),
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| "terminal did not become ready")?
}

async fn reconnect(
    sessions: &SessionManager,
    events: &mut mpsc::UnboundedReceiver<SessionEvent>,
) -> Result<String> {
    sessions.stop("terminal")?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await.ok_or("terminal events ended")? {
                SessionEvent::Closed => return Ok::<(), Box<dyn std::error::Error>>(()),
                SessionEvent::Failed { error, .. } => return Err(error.into()),
                _ => {}
            }
        }
    })
    .await??;
    sessions.retry("terminal")?;
    ready(events).await
}

async fn command(
    sessions: &SessionManager,
    transport: &str,
    output: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    command: &str,
    token: &str,
    expected_status: u32,
) -> Result<Vec<u8>> {
    sessions.input("terminal", transport, format!("{command}\nscoplen_status=$?; printf '\\n%s%s=%s\\n' SCOPLEN- {token} \"$scoplen_status\"\n").into_bytes())?;
    let marker = format!("SCOPLEN-{token}=");
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut received = Vec::new();
        loop {
            received.extend(output.recv().await.ok_or("terminal output ended")?);
            if let Some(start) =
                received.windows(marker.len()).position(|bytes| bytes == marker.as_bytes())
            {
                let status = &received[start + marker.len()..];
                if let Some(end) = status.iter().position(|byte| *byte == b'\n') {
                    let actual: u32 = std::str::from_utf8(&status[..end])?.trim().parse()?;
                    if actual != expected_status {
                        return Err(format!(
                            "terminal command {token} returned {actual}, expected {expected_status}"
                        )
                        .into());
                    }
                    return Ok(received);
                }
            }
            if received.len() > 262_144 {
                return Err("bounded fixture output exceeded".into());
            }
        }
    })
    .await
    .map_err(|_| format!("terminal command {token} timed out"))?
}

async fn files(sessions: &SessionManager, transport: &str, directory: &Path) -> Result<()> {
    let source = directory.join(format!("binary-{}.bin", Uuid::now_v7()));
    let expected: Vec<u8> = (0..=255).cycle().take(8192).collect();
    std::fs::write(&source, &expected)?;
    sessions.list_files("terminal", transport, &Uuid::now_v7().to_string(), b".".to_vec()).await?;
    let uploaded = sessions
        .upload_file_with_picker(
            "terminal",
            transport,
            &Uuid::now_v7().to_string(),
            b".".to_vec(),
            || async { Ok(Some(source.clone())) },
            |_| async { Err("fresh fixture target cannot require overwrite".into()) },
            |_| {},
        )
        .await?;
    assert_eq!(uploaded.status, SessionUploadStatus::Saved);
    let name = source.file_name().unwrap().to_str().unwrap();
    let listed = sessions
        .list_files("terminal", transport, &Uuid::now_v7().to_string(), b".".to_vec())
        .await?;
    let remote = listed
        .entries
        .into_iter()
        .find(|entry| entry.name == name)
        .ok_or("uploaded file missing")?
        .path;
    let destination = directory.join(format!("download-{}.bin", Uuid::now_v7()));
    let downloaded = sessions
        .download_file_with_picker(
            "terminal",
            transport,
            &Uuid::now_v7().to_string(),
            remote,
            || async { Ok(Some(destination.clone())) },
            |_| {},
        )
        .await?;
    assert_eq!(downloaded.status, SessionDownloadStatus::Saved);
    assert_eq!(std::fs::read(destination)?, expected);
    Ok(())
}

async fn tunnel(port: u16, dynamic: bool) -> Result<()> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    if dynamic {
        stream.write_all(&[5, 1, 0]).await?;
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).await?;
        assert_eq!(reply, [5, 0]);
        let mut request = vec![5, 1, 0, 3, 9];
        request.extend_from_slice(b"localhost");
        request.extend_from_slice(&2300u16.to_be_bytes());
        stream.write_all(&request).await?;
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await?;
        assert_eq!(&reply[..3], &[5, 0, 0]);
        let size = match reply[3] {
            1 => 4,
            4 => 16,
            _ => return Err("invalid SOCKS reply".into()),
        };
        stream.read_exact(&mut vec![0; size + 2]).await?;
    }
    let expected: Vec<u8> = (0..=255).cycle().take(8192).collect();
    stream.write_all(&expected).await?;
    let mut received = vec![0; expected.len()];
    stream.read_exact(&mut received).await?;
    assert_eq!(received, expected);
    Ok(())
}

async fn run(args: &[String]) -> Result<()> {
    let agent =
        support::forwarded_agent::SourceAgent::start(Path::new(&args[3]), Path::new(&args[4]))
            .await?;
    let private = SecretVec::new(std::fs::read(&args[3])?);
    let public =
        ssh_key::PrivateKey::from_openssh(private.as_bytes())?.public_key().to_openssh()?;
    let directory = tempfile::tempdir()?;
    let store = Arc::new(Store::open(
        &directory.path().join("local.db"),
        &LocalDatabaseKey::new([41; 32]),
    )?);
    let host = Repository::<Host>::new(&store).create(HostChange {
        name: Some("Forwarded agent target".into()),
        address: Some(args[1].clone()),
        port: Edit::Set(args[2].parse()?),
        ..Default::default()
    })?;
    let credential = Repository::<Credential>::new(&store).create(CredentialChange {
        kind: Some(CredentialKind::Agent),
        binding: Some(CredentialBinding::None),
        public_key: Edit::Set(public),
        ..Default::default()
    })?;
    let profile = Repository::<AccessProfile>::new(&store).create(AccessProfileChange {
        host: Some(host.meta.id),
        username: Some("smoke".into()),
        credential: Edit::Set(credential.meta.id),
        ..Default::default()
    })?;
    let mut ports = Vec::new();
    let mut forwards = Vec::new();
    for kind in [ForwardKind::Local, ForwardKind::Dynamic] {
        let port = TcpListener::bind("127.0.0.1:0").await?.local_addr()?.port();
        let forward = Repository::<Forward>::new(&store).create(ForwardChange {
            name: Some(format!("Concurrent {kind:?}")),
            kind: Some(kind),
            bind_address: Edit::Set("127.0.0.1".into()),
            bind_port: Edit::Set(port),
            target_host: if kind == ForwardKind::Local {
                Edit::Set("127.0.0.1".into())
            } else {
                Edit::Clear
            },
            target_port: if kind == ForwardKind::Local { Edit::Set(2300) } else { Edit::Clear },
            profile: Edit::Set(profile.meta.id),
        })?;
        ports.push(port);
        forwards.push(forward.meta.id);
    }
    Repository::<AccessProfile>::new(&store).update(
        profile.meta.id,
        AccessProfileChange {
            forwards: forwards.into_iter().map(|id| (id, true)).collect(),
            ..Default::default()
        },
    )?;
    let target = SessionTarget::Personal { profile_id: profile.meta.id.to_string() };
    let personal = PersonalServer::default();
    let sessions = SessionManager::default();
    sessions.reserve("terminal", true)?;
    let (send, mut events) = mpsc::unbounded_channel();
    let (bytes, mut output) = mpsc::unbounded_channel();
    let terminal = Box::pin(sessions.run_target(
        "terminal",
        &target,
        &personal,
        None,
        true,
        store.clone(),
        |event| {
            if let SessionEvent::Preparation { transport_id, event } = &event
                && let PreparationEvent::Trust { prompt_id, .. } = event.as_ref()
            {
                sessions.respond(
                    "terminal",
                    transport_id,
                    prompt_id,
                    PreparationResponse::AcceptHostKey,
                )?;
            }
            send.send(event).map_err(|_| "terminal event receiver ended".into())
        },
        |_, data| bytes.send(data).map_err(|_| "terminal output receiver ended".into()),
        |_, _| {},
    ));
    let exercise = Box::pin(async {
        let result = async {
            let first = ready(&mut events).await?;
            command(
                &sessions,
                &first,
                &mut output,
                "test -z \"${SSH_AUTH_SOCK-}\"",
                "DEFAULT-OFF",
                0,
            )
            .await?;
            Repository::<AccessProfile>::new(&store).update(
                profile.meta.id,
                AccessProfileChange { agent_forwarding: Some(true), ..Default::default() },
            )?;
            command(
                &sessions,
                &first,
                &mut output,
                "test -z \"${SSH_AUTH_SOCK-}\"",
                "UNCHANGED-OFF",
                0,
            )
            .await?;
            println!("default-off and immutable live selection passed");
            let second = reconnect(&sessions, &mut events).await?;
            assert_ne!(first, second);
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let attached = sessions.forward_list(&store, "terminal", &second)?;
                    if attached.len() == 2
                        && attached.iter().all(|entry| {
                            entry
                                .run
                                .as_ref()
                                .is_some_and(|run| run.phase == ForwardPhase::Listening)
                        })
                    {
                        return Ok::<(), Box<dyn std::error::Error>>(());
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await??;
            let (ssh, files, local, dynamic) = tokio::join!(
                command(&sessions, &second, &mut output, SECOND_HOP, "SECOND-HOP", 0),
                Box::pin(files(&sessions, &second, directory.path())),
                tunnel(ports[0], false),
                tunnel(ports[1], true),
            );
            assert!(ssh?.windows(b"second-hop-ok".len()).any(|bytes| bytes == b"second-hop-ok"));
            files?;
            local?;
            dynamic?;
            println!("second-hop SSH with concurrent SFTP and Local/Dynamic traffic passed");
            let before = agent.signatures();
            command(&sessions, &second, &mut output, SCOPE_CONTROL, "SCOPE", 0).await?;
            assert_eq!(agent.signatures(), before);
            agent.assert_scoped();
            println!("exact identity and forbidden-request controls passed");
            agent.refuse(true);
            command(&sessions, &second, &mut output, SECOND_HOP, "REFUSED", 255).await?;
            agent.refuse(false);
            command(&sessions, &second, &mut output, SECOND_HOP, "AFTER-REFUSAL", 0).await?;
            println!("source refusal recovery passed");
            Repository::<AccessProfile>::new(&store).update(
                profile.meta.id,
                AccessProfileChange { agent_forwarding: Some(false), ..Default::default() },
            )?;
            command(&sessions, &second, &mut output, SECOND_HOP, "UNCHANGED-ON", 0).await?;
            let third = reconnect(&sessions, &mut events).await?;
            assert_ne!(third, second);
            command(
                &sessions,
                &third,
                &mut output,
                "test -z \"${SSH_AUTH_SOCK-}\"",
                "RECONNECT-OFF",
                0,
            )
            .await?;
            println!("saved-off reconnect passed");
            Repository::<AccessProfile>::new(&store).update(
                profile.meta.id,
                AccessProfileChange { agent_forwarding: Some(true), ..Default::default() },
            )?;
            let fourth = reconnect(&sessions, &mut events).await?;
            assert_ne!(fourth, third);
            agent.stall();
            let before = agent.signatures();
            sessions.input("terminal", &fourth, format!("{SECOND_HOP}\n").into_bytes())?;
            tokio::time::timeout(Duration::from_secs(5), agent.requested_after(before)).await?;
            sessions.close_all()?;
            tokio::time::timeout(Duration::from_secs(3), agent.held_request_closed()).await?;
            assert!(sessions.input("terminal", &fourth, b"late input".to_vec()).is_err());
            agent.assert_scoped();
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        sessions.close_all()?;
        result
    });
    let (terminal, exercise) =
        tokio::time::timeout(Duration::from_secs(120), async { tokio::join!(terminal, exercise) })
            .await?;
    terminal?;
    exercise?;
    println!(
        "saved default-off/exact-Agent forwarding, real second-hop SSH, concurrent shell/binary SFTP/Local/Dynamic, scoped refusals and reconnect/cancellation passed"
    );
    Ok(())
}
