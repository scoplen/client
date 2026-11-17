// SPDX-License-Identifier: Apache-2.0

//! Explicit mixed Workspace restoration against owned disposable OpenSSH peers.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scoplen_client_core::connection::preparation::{PreparationEvent, PreparationResponse};
use scoplen_client_core::forward_manager::{
    ForwardDefinition, ForwardIssue, ForwardManager, ForwardPhase, ForwardSnapshot,
    ForwardStartIntent,
};
use scoplen_client_core::inventory::{Inventory, NewHost, SignIn};
use scoplen_client_core::repository::{
    AccessProfile, AccessProfileChange, Edit, Forward, ForwardChange, ForwardKind, Repository,
    Route, RouteChange, RouteChoice, RouteKind,
};
use scoplen_client_core::session_files::{SessionDownloadStatus, SessionUploadStatus};
use scoplen_client_core::session_manager::{SessionEvent, SessionManager};
use scoplen_client_core::store::Store;
use scoplen_client_core::workspaces::{
    WorkspaceFilesInput, WorkspaceForwardInput, WorkspaceInput, WorkspaceSplitDirection,
    WorkspaceTabInput, WorkspaceTerminal, WorkspaceTree, WorkspaceTreeInput, Workspaces,
};
use scoplen_crypto::LocalDatabaseKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use uuid::Uuid;

type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

struct Tunnel {
    id: String,
    events: mpsc::UnboundedReceiver<ForwardSnapshot>,
}

impl Tunnel {
    fn start(
        manager: &ForwardManager,
        store: Arc<Store>,
        intent: ForwardStartIntent,
    ) -> Result<Self> {
        let (send, events) = mpsc::unbounded_channel();
        let run = manager.start(store, intent, move |snapshot| {
            let _ = send.send(snapshot);
        })?;
        assert_eq!(run.phase, ForwardPhase::Preparing);
        Ok(Self { id: run.run_id, events })
    }

    async fn ready(
        &mut self,
        manager: &ForwardManager,
        store: &Arc<Store>,
    ) -> Result<BTreeSet<u32>> {
        tokio::time::timeout(Duration::from_secs(38), async {
            let mut prompts = BTreeSet::new();
            let mut trusted = BTreeSet::new();
            while let Some(state) = self.events.recv().await {
                if let Some(event) = state.preparation {
                    match event {
                        PreparationEvent::Trust { prompt_id, context, .. } => {
                            if prompts.insert(prompt_id.clone()) {
                                trusted.insert(context.position);
                                manager.respond(
                                    store,
                                    &self.id,
                                    &prompt_id,
                                    PreparationResponse::AcceptHostKey,
                                )?;
                            }
                        }
                        PreparationEvent::Progress { .. } | PreparationEvent::Verified { .. } => {}
                        _ => return Err("password tunnel requested unexpected input".into()),
                    }
                }
                match state.phase {
                    ForwardPhase::Listening => return Ok(trusted),
                    ForwardPhase::Failed | ForwardPhase::Stopped => {
                        return Err(format!(
                            "workspace tunnel failed before listening: {:?}",
                            state.last_issue
                        )
                        .into());
                    }
                    _ => {}
                }
            }
            Err("workspace tunnel events ended before listening".into())
        })
        .await?
    }

    async fn counters(
        &self,
        manager: &ForwardManager,
        store: &Arc<Store>,
        count: usize,
    ) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let state = manager.snapshot(store, &self.id)?;
                if state.active_connections == 0
                    && state.uploaded_bytes == count.to_string()
                    && state.downloaded_bytes == count.to_string()
                {
                    assert_eq!(state.phase, ForwardPhase::Listening);
                    assert_eq!(state.rejected_connections, "0");
                    return Ok::<_, Box<dyn std::error::Error>>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?
    }
}

async fn unused_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0").await?.local_addr()?.port())
}

async fn traffic(port: u16, socks: bool) -> Result<usize> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
        if socks {
            stream.write_all(&[5, 1, 0]).await?;
            let mut selected = [0; 2];
            stream.read_exact(&mut selected).await?;
            assert_eq!(selected, [5, 0]);
            let mut request = vec![5, 1, 0, 3, 9];
            request.extend_from_slice(b"localhost");
            request.extend_from_slice(&2300u16.to_be_bytes());
            stream.write_all(&request).await?;
            let mut reply = [0; 4];
            stream.read_exact(&mut reply).await?;
            assert_eq!(&reply[..3], &[5, 0, 0]);
            let length = match reply[3] {
                1 => 4,
                4 => 16,
                3 => usize::from(stream.read_u8().await?),
                _ => return Err("unexpected SOCKS address kind".into()),
            };
            stream.read_exact(&mut vec![0; length + 2]).await?;
        }
        let payload: Vec<_> = (0..8192).map(|i| (i % 256) as u8).collect();
        stream.write_all(&payload).await?;
        let mut echoed = vec![0; payload.len()];
        stream.read_exact(&mut echoed).await?;
        assert_eq!(echoed, payload);
        stream.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error>>(payload.len())
    })
    .await?
}

struct Pane {
    terminal: WorkspaceTerminal,
    events: mpsc::UnboundedReceiver<SessionEvent>,
    output: Arc<Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<Result<(), String>>,
}

impl Pane {
    fn start(
        manager: Arc<SessionManager>,
        store: Arc<Store>,
        terminal: WorkspaceTerminal,
    ) -> Result<Self, String> {
        manager.reserve(&terminal.session_id, true)?;
        let (send, events) = mpsc::unbounded_channel();
        let output = Arc::new(Mutex::new(Vec::<u8>::new()));
        let bytes = output.clone();
        let current = terminal.clone();
        let task = tokio::spawn(async move {
            manager
                .run(
                    &current.session_id,
                    &current.profile_id,
                    None,
                    true,
                    store,
                    |event| send.send(event).map_err(|_| "fixture event receiver closed".into()),
                    |_, chunk| {
                        let mut output = bytes.lock().unwrap();
                        if output.len() + chunk.len() > 65_536 {
                            return Err("fixture output exceeded its bound".into());
                        }
                        output.extend_from_slice(&chunk);
                        Ok(())
                    },
                    |_, _| {},
                )
                .await
        });
        Ok(Self { terminal, events, output, task })
    }

    async fn ready(
        &mut self,
        manager: &SessionManager,
    ) -> Result<String, Box<dyn std::error::Error>> {
        tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(event) = self.events.recv().await {
                match event {
                    SessionEvent::Ready { transport_id } => return Ok(transport_id),
                    SessionEvent::Preparation { transport_id, event } => match *event {
                        PreparationEvent::Trust { prompt_id, .. } => manager.respond(
                            &self.terminal.session_id,
                            &transport_id,
                            &prompt_id,
                            PreparationResponse::AcceptHostKey,
                        )?,
                        PreparationEvent::CommandExecution { .. }
                        | PreparationEvent::Passphrase { .. }
                        | PreparationEvent::KeyboardInteractive { .. } => {
                            return Err("password fixture requested unexpected input".to_owned());
                        }
                        PreparationEvent::Progress { .. } | PreparationEvent::Verified { .. } => {}
                    },
                    SessionEvent::Failed { .. }
                    | SessionEvent::Closed
                    | SessionEvent::Retrying { .. } => {
                        return Err("ordinary workspace connection failed".to_owned());
                    }
                    SessionEvent::Starting { automatic, .. } => {
                        if automatic {
                            return Err("fixture must not reconnect automatically".to_owned());
                        }
                    }
                    SessionEvent::Forwards { .. } => {}
                }
            }
            Err("fixture connection ended before ready".to_owned())
        })
        .await?
        .map_err(Into::into)
    }

    fn marker_count(&self, marker: &str) -> usize {
        let output = self.output.lock().unwrap();
        output.windows(marker.len()).filter(|part| *part == marker.as_bytes()).count()
    }

    async fn files(&self, manager: &SessionManager, transport: &str, local: &Path) -> Result<()> {
        let directory = self.terminal.files.as_ref().ok_or("open Files intent missing")?;
        let initial = manager.transfer_queue_snapshot(&self.terminal.session_id)?;
        assert!(initial.items.is_empty() && initial.recent.is_empty());
        manager
            .list_files(
                &self.terminal.session_id,
                transport,
                &Uuid::now_v7().to_string(),
                directory.path.clone(),
            )
            .await?;
        let source = local.join(format!("workspace-{}.bin", Uuid::now_v7()));
        let expected: Vec<u8> = (0..=255).cycle().take(8192).collect();
        std::fs::write(&source, &expected)?;
        let upload = manager
            .upload_file_with_picker(
                &self.terminal.session_id,
                transport,
                &Uuid::now_v7().to_string(),
                directory.path.clone(),
                || async { Ok(Some(source.clone())) },
                |_| async { Err("fresh fixture must not overwrite".into()) },
                |_| {},
            )
            .await?;
        assert_eq!(upload.status, SessionUploadStatus::Saved);
        let entry = manager
            .list_files(
                &self.terminal.session_id,
                transport,
                &Uuid::now_v7().to_string(),
                directory.path.clone(),
            )
            .await?
            .entries
            .into_iter()
            .find(|entry| entry.name == source.file_name().unwrap().to_str().unwrap())
            .ok_or("restored Files upload missing")?;
        assert!(entry.path.starts_with(&directory.path));
        let destination = local.join(format!("download-{}.bin", Uuid::now_v7()));
        let download = manager
            .download_file_with_picker(
                &self.terminal.session_id,
                transport,
                &Uuid::now_v7().to_string(),
                entry.path,
                || async { Ok(Some(destination.clone())) },
                |_| {},
            )
            .await?;
        assert_eq!(download.status, SessionDownloadStatus::Saved);
        assert_eq!(std::fs::read(destination)?, expected);
        Ok(())
    }

    async fn refused(&mut self, manager: &SessionManager, trust: bool) -> Result<()> {
        let transport = tokio::time::timeout(Duration::from_secs(30), async {
            let mut current = None;
            let mut reviewed = false;
            let mut finished = false;
            while let Some(event) = self.events.recv().await {
                match event {
                    SessionEvent::Starting { transport_id, automatic } => {
                        assert!(!automatic);
                        current = Some(transport_id);
                    }
                    SessionEvent::Preparation { transport_id, event } => {
                        if let PreparationEvent::Trust { prompt_id, .. } = *event {
                            reviewed = true;
                            if trust {
                                manager.stop(&self.terminal.session_id)?;
                            } else {
                                manager.respond(
                                    &self.terminal.session_id,
                                    &transport_id,
                                    &prompt_id,
                                    PreparationResponse::AcceptHostKey,
                                )?;
                            }
                        }
                    }
                    SessionEvent::Failed { exhausted, .. } if !trust => {
                        assert!(!exhausted);
                        finished = true;
                        break;
                    }
                    SessionEvent::Closed if trust => {
                        finished = true;
                        break;
                    }
                    SessionEvent::Ready { .. } | SessionEvent::Retrying { .. } => {
                        return Err("refused Workspace must not become ready or retry".to_owned());
                    }
                    _ => {}
                }
            }
            if !finished {
                return Err("negative Workspace events ended before refusal".to_owned());
            }
            if !reviewed {
                return Err("negative Workspace must review its independent Host".to_owned());
            }
            current.ok_or("negative Workspace did not begin preparation".to_owned())
        })
        .await??;
        assert!(
            manager
                .list_files(
                    &self.terminal.session_id,
                    &transport,
                    &Uuid::now_v7().to_string(),
                    self.terminal.files.as_ref().unwrap().path.clone()
                )
                .await
                .is_err()
        );
        Ok(())
    }

    async fn marker(
        &self,
        manager: &SessionManager,
        transport: &str,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        manager.input(
            &self.terminal.session_id,
            transport,
            format!("printf '\\123COPLEN-WORKSPACE:%s\\n' '{name}'\r").into_bytes(),
        )?;
        let marker = format!("SCOPLEN-WORKSPACE:{name}\r\n");
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.marker_count(&marker) == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        assert_eq!(self.marker_count(&marker), 1);
        Ok(())
    }

    async fn close(self, manager: &SessionManager) -> Result<(), Box<dyn std::error::Error>> {
        manager.close(&self.terminal.session_id)?;
        tokio::time::timeout(Duration::from_secs(10), self.task).await???;
        Ok(())
    }

    async fn grid(
        &self,
        manager: &SessionManager,
        transport: &str,
        name: &str,
        rows: u32,
        columns: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        manager.input(
            &self.terminal.session_id,
            transport,
            format!("printf '\\123COPLEN-GRID:{name}:'; stty size\r").into_bytes(),
        )?;
        let marker = format!("SCOPLEN-GRID:{name}:{rows} {columns}\r\n");
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.marker_count(&marker) == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        assert_eq!(self.marker_count(&marker), 1);
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: ssh_workspace_smoke <host> <terminal-port> <password-file> <tunnel-port> <remote-published-port>".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Box::pin(run(&args)))
}

async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let scratch = tempfile::tempdir()?;
    let path = scratch.path().join("workspace.db");
    let key = LocalDatabaseKey::new([7; 32]);
    let store = Arc::new(Store::open(&path, &key)?);
    let host = Inventory::new(store.clone()).add_host(NewHost {
        name: Some("Disposable workspace fixture".into()),
        address: args[1].clone(),
        port: Some(args[2].parse()?),
        username: "smoke".into(),
        sign_in: SignIn::Password { password: std::fs::read_to_string(&args[3])? },
    })?;
    let profile_id = host.logins[0].id.clone();
    let jump = Inventory::new(store.clone()).add_host(NewHost {
        name: Some("Workspace Jump".into()),
        address: args[1].clone(),
        port: Some(args[4].parse()?),
        username: "smoke".into(),
        sign_in: SignIn::Password { password: std::fs::read_to_string(&args[3])? },
    })?;
    let target = Inventory::new(store.clone()).add_host(NewHost {
        name: Some("Workspace tunnel target".into()),
        address: "127.0.0.1".into(),
        port: Some(2223),
        username: "smoke".into(),
        sign_in: SignIn::Password { password: std::fs::read_to_string(&args[3])? },
    })?;
    let route = Repository::<Route>::new(&store).create(RouteChange {
        name: Some("Workspace Jump route".into()),
        kind: Some(RouteKind::Jump { hops: vec![Uuid::parse_str(&jump.logins[0].id)?] }),
    })?;
    let files_jump = Inventory::new(store.clone()).add_host(NewHost {
        name: Some("Workspace Files Jump".into()),
        address: "127.0.0.1".into(),
        port: Some(2224),
        username: "smoke".into(),
        sign_in: SignIn::Password { password: std::fs::read_to_string(&args[3])? },
    })?;
    Repository::<AccessProfile>::new(&store).update(
        Uuid::parse_str(&files_jump.logins[0].id)?,
        AccessProfileChange {
            route: Some(RouteChoice::Route(route.meta.id)),
            ..Default::default()
        },
    )?;
    let tunnel_profile = Uuid::parse_str(&target.logins[0].id)?;
    Repository::<AccessProfile>::new(&store).update(
        tunnel_profile,
        AccessProfileChange {
            route: Some(RouteChoice::Route(route.meta.id)),
            ..Default::default()
        },
    )?;
    let direct_tunnel = Inventory::new(store.clone()).add_host(NewHost {
        name: Some("Workspace direct tunnel".into()),
        address: args[1].clone(),
        port: Some(args[4].parse()?),
        username: "smoke".into(),
        sign_in: SignIn::Password { password: std::fs::read_to_string(&args[3])? },
    })?;
    let local_port = unused_port().await?;
    let dynamic_port = unused_port().await?;
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let echo_port = echo.local_addr()?.port();
    let echo_task = tokio::spawn(async move {
        while let Ok((stream, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.into_split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    let mut selected = Vec::new();
    for (kind, port) in [
        (ForwardKind::Local, local_port),
        (ForwardKind::Remote, 2302),
        (ForwardKind::Dynamic, dynamic_port),
    ] {
        let forward = Repository::<Forward>::new(&store).create(ForwardChange {
            name: Some(format!("Workspace {kind:?}")),
            kind: Some(kind),
            bind_address: Edit::Set(
                if kind == ForwardKind::Remote { "0.0.0.0" } else { "127.0.0.1" }.into(),
            ),
            bind_port: Edit::Set(port),
            target_host: if kind == ForwardKind::Dynamic {
                Edit::Clear
            } else {
                Edit::Set("127.0.0.1".into())
            },
            target_port: if kind == ForwardKind::Dynamic {
                Edit::Clear
            } else {
                Edit::Set(if kind == ForwardKind::Remote { echo_port } else { 2300 })
            },
            profile: Edit::Clear,
        })?;
        selected.push(WorkspaceForwardInput {
            forward_id: forward.meta.id.to_string(),
            profile_id: tunnel_profile.to_string(),
        });
    }
    let terminal = |id: &str| WorkspaceTerminal {
        session_id: id.into(),
        profile_id: profile_id.clone(),
        label: "Workspace fixture".into(),
        files: None,
    };
    let manager = Arc::new(SessionManager::default());
    let mut first = Pane::start(manager.clone(), store.clone(), terminal("first-pane"))?;
    let first_transport = first.ready(&manager).await?;
    first.marker(&manager, &first_transport, "first").await?;
    let mut second = Pane::start(manager.clone(), store.clone(), terminal("second-pane"))?;
    let second_transport = second.ready(&manager).await?;
    second.marker(&manager, &second_transport, "second").await?;
    assert_eq!(first.marker_count("SCOPLEN-WORKSPACE:second\r\n"), 0);
    assert_eq!(second.marker_count("SCOPLEN-WORKSPACE:first\r\n"), 0);
    manager.resize("first-pane", &first_transport, 100, 30)?;
    manager.resize("second-pane", &second_transport, 60, 18)?;
    first.grid(&manager, &first_transport, "first", 30, 100).await?;
    second.grid(&manager, &second_transport, "second", 18, 60).await?;
    manager.resize("first-pane", &first_transport, 80, 20)?;
    first.grid(&manager, &first_transport, "first-resized", 20, 80).await?;
    second.grid(&manager, &second_transport, "second-unchanged", 18, 60).await?;
    let workspaces = Workspaces::new(store.clone());
    let directory = b"/tmp/scoplen-workspace-files/nested".to_vec();
    let mut opaque = b"/tmp/scoplen-workspace-files/".to_vec();
    opaque.push(255);
    let saved = workspaces.create(WorkspaceInput {
        name: "Terminals and selected tunnels".into(),
        tabs: vec![
            WorkspaceTabInput {
                tree: WorkspaceTreeInput::Split {
                    direction: WorkspaceSplitDirection::Horizontal,
                    first: Box::new(WorkspaceTreeInput::Terminal {
                        profile_id: profile_id.clone(),
                        files: WorkspaceFilesInput::Open { path: directory.clone() },
                    }),
                    second: Box::new(WorkspaceTreeInput::Terminal {
                        profile_id: files_jump.logins[0].id.clone(),
                        files: WorkspaceFilesInput::Open { path: opaque.clone() },
                    }),
                },
                focused: 1,
            },
            WorkspaceTabInput {
                tree: WorkspaceTreeInput::Terminal {
                    profile_id: profile_id.clone(),
                    files: WorkspaceFilesInput::Closed,
                },
                focused: 0,
            },
            WorkspaceTabInput {
                tree: WorkspaceTreeInput::Terminal {
                    profile_id: profile_id.clone(),
                    files: WorkspaceFilesInput::Open {
                        path: b"/tmp/scoplen-workspace-files/removed".to_vec(),
                    },
                },
                focused: 0,
            },
            WorkspaceTabInput {
                tree: WorkspaceTreeInput::Terminal {
                    profile_id: files_jump.logins[0].id.clone(),
                    files: WorkspaceFilesInput::Open {
                        path: b"/tmp/scoplen-workspace-files/denied".to_vec(),
                    },
                },
                focused: 0,
            },
        ],
        active: Some(0),
        forwards: selected,
    })?;
    first.close(&manager).await?;
    second.marker(&manager, &second_transport, "surviving").await?;
    second.close(&manager).await?;
    drop(workspaces);
    drop(store);
    let reopened = Arc::new(Store::open(&path, &key)?);
    let forward_manager = ForwardManager::default();
    let workspaces = Workspaces::new(reopened.clone());
    assert_eq!(workspaces.list()?.len(), 1);
    assert!(forward_manager.list(&reopened)?.is_empty());
    let saved_bytes = reopened.get(Uuid::parse_str(&saved.id)?)?.unwrap().encode()?;
    let opened = workspaces.open(&saved.id)?;
    assert!(forward_manager.list(&reopened)?.is_empty());
    assert_eq!(opened.forwards.len(), 3);
    let mut unrelated = Pane::start(manager.clone(), reopened.clone(), terminal("unrelated-pane"))?;
    let unrelated_transport = unrelated.ready(&manager).await?;
    let unrelated_queue = manager.transfer_queue_snapshot(&unrelated.terminal.session_id)?;
    let mut temporary = Tunnel::start(
        &forward_manager,
        reopened.clone(),
        ForwardStartIntent::Temporary {
            profile_id: direct_tunnel.logins[0].id.clone(),
            definition: ForwardDefinition::Dynamic {
                name: "Pre-existing temporary run".into(),
                bind_address: "127.0.0.1".into(),
                bind_port: unused_port().await?,
            },
        },
    )?;
    temporary.ready(&forward_manager, &reopened).await?;
    let mut runs = Vec::new();
    for forward in &opened.forwards {
        let intent = ForwardStartIntent::Saved {
            forward_id: forward.forward_id.clone(),
            profile_id: forward.profile_id.clone(),
        };
        let mut run = Tunnel::start(&forward_manager, reopened.clone(), intent.clone())?;
        let trusted = run.ready(&forward_manager, &reopened).await?;
        if runs.is_empty() {
            assert_eq!(trusted, BTreeSet::from([1, 2]));
        }
        assert_eq!(
            forward_manager.start(reopened.clone(), intent, |_| {}),
            Err(ForwardIssue::AlreadyRunning)
        );
        runs.push(run);
    }
    let local_bytes = traffic(local_port, false).await?;
    let remote_bytes = traffic(args[5].parse()?, false).await?;
    let dynamic_bytes = traffic(dynamic_port, true).await?;
    for (run, count) in runs.iter().zip([local_bytes, remote_bytes, dynamic_bytes]) {
        run.counters(&forward_manager, &reopened, count).await?;
    }
    assert_eq!(forward_manager.snapshot(&reopened, &temporary.id)?.phase, ForwardPhase::Listening);
    unrelated.marker(&manager, &unrelated_transport, "existing-during-restore").await?;
    assert_eq!(reopened.list(scoplen_model::ObjectType::FORWARD)?.len(), 3);
    assert_eq!(reopened.get(Uuid::parse_str(&saved.id)?)?.unwrap().encode()?, saved_bytes);
    assert_eq!(opened.active, Some(0));
    let WorkspaceTree::Split { direction, first, second } = &opened.tabs[0].tree else {
        return Err("saved split was not restored".into());
    };
    assert_eq!(*direction, WorkspaceSplitDirection::Horizontal);
    let WorkspaceTree::Terminal { terminal: one } = first.as_ref() else {
        return Err("first pane missing".into());
    };
    let WorkspaceTree::Terminal { terminal: two } = second.as_ref() else {
        return Err("second pane missing".into());
    };
    assert_eq!(opened.tabs[0].focused_session_id, two.session_id);
    assert_ne!(one.session_id, two.session_id);
    assert!(
        [one, two]
            .iter()
            .all(|pane| pane.session_id != "first-pane" && pane.session_id != "second-pane")
    );
    let mut one = Pane::start(manager.clone(), reopened.clone(), one.clone())?;
    let mut two = Pane::start(manager.clone(), reopened.clone(), two.clone())?;
    let one_transport = one.ready(&manager).await?;
    let two_transport = two.ready(&manager).await?;
    assert_eq!(one.terminal.files.as_ref().unwrap().path, directory);
    assert_eq!(two.terminal.files.as_ref().unwrap().path, opaque);
    one.files(&manager, &one_transport, scratch.path()).await?;
    two.files(&manager, &two_transport, scratch.path()).await?;
    for (index, tab) in opened.tabs[1..].iter().enumerate() {
        let WorkspaceTree::Terminal { terminal } = &tab.tree else {
            return Err("extra terminal missing".into());
        };
        let mut pane = Pane::start(manager.clone(), reopened.clone(), terminal.clone())?;
        let transport = pane.ready(&manager).await?;
        let queue = manager.transfer_queue_snapshot(&pane.terminal.session_id)?;
        assert!(queue.items.is_empty() && queue.recent.is_empty());
        assert_ne!(queue.queue_id, unrelated_queue.queue_id);
        if index == 0 {
            assert!(pane.terminal.files.is_none());
        } else {
            assert!(
                manager
                    .list_files(
                        &pane.terminal.session_id,
                        &transport,
                        &Uuid::now_v7().to_string(),
                        pane.terminal.files.as_ref().unwrap().path.clone()
                    )
                    .await
                    .is_err()
            );
            pane.marker(&manager, &transport, "directory-failure-keeps-shell").await?;
        }
        pane.close(&manager).await?;
    }
    assert_eq!(manager.transfer_queue_snapshot(&unrelated.terminal.session_id)?, unrelated_queue);
    assert_eq!(one.marker_count("SCOPLEN-WORKSPACE:first\r\n"), 0);
    assert_eq!(two.marker_count("SCOPLEN-WORKSPACE:second\r\n"), 0);
    one.marker(&manager, &one_transport, "reopened-first").await?;
    two.marker(&manager, &two_transport, "reopened-second").await?;
    one.close(&manager).await?;
    two.close(&manager).await?;
    for refuse_trust in [true, false] {
        let host = Inventory::new(reopened.clone()).add_host(NewHost {
            name: Some(
                if refuse_trust {
                    "Refused Workspace trust"
                } else {
                    "Denied Workspace authentication"
                }
                .into(),
            ),
            address: args[1].clone(),
            port: Some(args[2].parse()?),
            username: "smoke".into(),
            sign_in: SignIn::Password { password: "wrong-disposable-password".into() },
        })?;
        let denied = workspaces.create(WorkspaceInput {
            name: "Negative Files restoration".into(),
            tabs: vec![WorkspaceTabInput {
                tree: WorkspaceTreeInput::Terminal {
                    profile_id: host.logins[0].id.clone(),
                    files: WorkspaceFilesInput::Open { path: directory.clone() },
                },
                focused: 0,
            }],
            active: Some(0),
            forwards: vec![],
        })?;
        let projection = workspaces.open(&denied.id)?;
        let WorkspaceTree::Terminal { terminal } = &projection.tabs[0].tree else { unreachable!() };
        let mut pane = Pane::start(manager.clone(), reopened.clone(), terminal.clone())?;
        pane.refused(&manager, refuse_trust).await?;
        pane.close(&manager).await?;
    }
    forward_manager.stop_all().await?;
    for run in runs.iter().chain(std::iter::once(&temporary)) {
        assert_eq!(forward_manager.snapshot(&reopened, &run.id)?.phase, ForwardPhase::Stopped);
    }
    assert!(TcpStream::connect(("127.0.0.1", local_port)).await.is_err());
    assert!(TcpStream::connect(("127.0.0.1", dynamic_port)).await.is_err());
    unrelated.marker(&manager, &unrelated_transport, "existing-after-stop").await?;
    unrelated.close(&manager).await?;
    echo_task.abort();
    let _ = echo_task.await;
    println!(
        "Real OpenSSH Workspace restored Direct/Jump opaque Files directories, binary transfers and fresh queues; closed panels, failed directories and trust/authentication refusals preserved ordinary terminals and selected Local/Remote/Dynamic tunnel results."
    );
    Ok(())
}
