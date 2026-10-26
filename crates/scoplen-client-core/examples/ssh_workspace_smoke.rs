// SPDX-License-Identifier: Apache-2.0

//! Independent ordinary SSH panes and explicit saved split restoration through public facades.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use scoplen_client_core::connection::preparation::{PreparationEvent, PreparationResponse};
use scoplen_client_core::inventory::{Inventory, NewHost, SignIn};
use scoplen_client_core::session_manager::{SessionEvent, SessionManager};
use scoplen_client_core::store::Store;
use scoplen_client_core::workspaces::{
    WorkspaceInput, WorkspaceSplitDirection, WorkspaceTabInput, WorkspaceTerminal, WorkspaceTree,
    WorkspaceTreeInput, Workspaces,
};
use scoplen_crypto::LocalDatabaseKey;
use tokio::sync::mpsc;

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
                        PreparationEvent::Passphrase { .. }
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
    if args.len() != 4 {
        return Err("usage: ssh_workspace_smoke <host> <port> <password-file>".into());
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(run(&args))
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
    let terminal = |id: &str| WorkspaceTerminal {
        session_id: id.into(),
        profile_id: profile_id.clone(),
        label: "Workspace fixture".into(),
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
    let saved = workspaces.create(WorkspaceInput {
        name: "Two terminals".into(),
        tabs: vec![WorkspaceTabInput {
            tree: WorkspaceTreeInput::Split {
                direction: WorkspaceSplitDirection::Horizontal,
                first: Box::new(WorkspaceTreeInput::Terminal { profile_id: profile_id.clone() }),
                second: Box::new(WorkspaceTreeInput::Terminal { profile_id }),
            },
            focused: 1,
        }],
        active: Some(0),
    })?;
    first.close(&manager).await?;
    second.marker(&manager, &second_transport, "surviving").await?;
    second.close(&manager).await?;
    drop(workspaces);
    drop(store);
    let reopened = Arc::new(Store::open(&path, &key)?);
    let opened = Workspaces::new(reopened.clone()).open(&saved.id)?;
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
    let mut two = Pane::start(manager.clone(), reopened, two.clone())?;
    let one_transport = one.ready(&manager).await?;
    let two_transport = two.ready(&manager).await?;
    assert_eq!(one.marker_count("SCOPLEN-WORKSPACE:first\r\n"), 0);
    assert_eq!(two.marker_count("SCOPLEN-WORKSPACE:second\r\n"), 0);
    one.marker(&manager, &one_transport, "reopened-first").await?;
    two.marker(&manager, &two_transport, "reopened-second").await?;
    one.close(&manager).await?;
    two.close(&manager).await?;
    println!(
        "Real OpenSSH split panes kept independent output, resize and close; explicit saved reopen created fresh ordinary shells without replay."
    );
    Ok(())
}
