// SPDX-License-Identifier: Apache-2.0

//! Save, prepare and send a command through the public facades to real OpenSSH.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use scoplen_client_core::connection::preparation::{PreparationEvent, PreparationResponse};
use scoplen_client_core::inventory::{Inventory, NewHost, SignIn};
use scoplen_client_core::session_manager::{SessionEvent, SessionManager};
use scoplen_client_core::snippets::{
    SnippetInput, SnippetVariableInput, SnippetVariableKind, Snippets,
};
use scoplen_client_core::store::Store;
use scoplen_crypto::LocalDatabaseKey;
use tokio::sync::mpsc;

struct Terminal {
    id: &'static str,
    events: mpsc::UnboundedReceiver<SessionEvent>,
    output: Arc<Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<Result<(), String>>,
}

impl Terminal {
    fn start(
        manager: SessionManager,
        store: Arc<Store>,
        id: &'static str,
        profile_id: String,
    ) -> Result<Self, String> {
        manager.reserve(id, true)?;
        let (sender, events) = mpsc::unbounded_channel();
        let output = Arc::new(Mutex::new(Vec::<u8>::new()));
        let bytes = output.clone();
        let task = tokio::spawn(async move {
            manager
                .run(
                    id,
                    &profile_id,
                    None,
                    true,
                    store,
                    |event| {
                        if matches!(
                            &event,
                            SessionEvent::Starting { automatic: true, .. }
                                | SessionEvent::Retrying { .. }
                                | SessionEvent::Failed { .. }
                        ) {
                            return Err(
                                "selected-terminal fixture must not reconnect or replay".into()
                            );
                        }
                        sender.send(event).map_err(|_| "fixture event receiver closed".into())
                    },
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
        Ok(Self { id, events, output, task })
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
                            self.id,
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
                        return Err("selected-terminal fixture connection failed".to_owned());
                    }
                    SessionEvent::Starting { .. } => {}
                }
            }
            Err("fixture connection ended before ready".to_owned())
        })
        .await?
        .map_err(Into::into)
    }

    fn marker_count(&self, marker: &[u8]) -> usize {
        let output = self.output.lock().unwrap();
        output.windows(marker.len()).filter(|part| *part == marker).count()
    }

    async fn wait_marker(&self, marker: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.marker_count(marker) == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        assert_eq!(self.marker_count(marker), 1);
        Ok(())
    }

    async fn close(self, manager: &SessionManager) -> Result<(), Box<dyn std::error::Error>> {
        manager.close(self.id)?;
        tokio::time::timeout(Duration::from_secs(10), self.task).await???;
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: ssh_snippet_smoke <host> <port> <password-file>".into());
    }
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(run(&args))
}

async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let scratch = tempfile::tempdir()?;
    let store =
        Arc::new(Store::open(&scratch.path().join("local.db"), &LocalDatabaseKey::new([7; 32]))?);
    let host = Inventory::new(store.clone()).add_host(NewHost {
        name: Some("Disposable snippet fixture".into()),
        address: args[1].clone(),
        port: Some(args[2].parse()?),
        username: "smoke".into(),
        sign_in: SignIn::Password { password: std::fs::read_to_string(&args[3])? },
    })?;
    let snippets = Snippets::new(store.clone());
    let definition = SnippetInput {
        name: "Typed command".into(),
        // The echo contains the escape, so only executed output can contain the marker.
        template: "printf '\\123COPLEN-SNIPPET:%s:%s:%s\\n' '{{label}}' {{count}} '{{mode}}'; exit"
            .into(),
        variables: vec![
            SnippetVariableInput {
                name: "label".into(),
                kind: SnippetVariableKind::Text,
                default: Some("ready".into()),
                choices: Vec::new(),
            },
            SnippetVariableInput {
                name: "count".into(),
                kind: SnippetVariableKind::Integer,
                default: Some("-7".into()),
                choices: Vec::new(),
            },
            SnippetVariableInput {
                name: "mode".into(),
                kind: SnippetVariableKind::Choice,
                default: Some("blue".into()),
                choices: vec!["blue".into(), "green".into()],
            },
        ],
        tags: vec!["acceptance".into()],
        folder: None,
    };
    let saved = snippets.create(definition.clone())?;
    assert_eq!(snippets.list()?.as_slice(), std::slice::from_ref(&saved));
    let prepared = snippets.prepare(&saved.id, BTreeMap::new())?;
    assert_eq!(
        prepared.command,
        "printf '\\123COPLEN-SNIPPET:%s:%s:%s\\n' 'ready' -7 'blue'; exit"
    );
    let input = format!("{}\r", prepared.command).into_bytes();
    let manager = SessionManager::default();
    manager.reserve("snippet-terminal", true)?;
    let transport = Mutex::new(None::<String>);
    let output = Mutex::new(Vec::<u8>::new());
    let closed = std::sync::atomic::AtomicBool::new(false);
    tokio::time::timeout(
        Duration::from_secs(40),
        manager.run(
            "snippet-terminal",
            &host.logins[0].id,
            None,
            true,
            store.clone(),
            |event| {
                match event {
                    SessionEvent::Starting { automatic, .. } => {
                        if automatic {
                            return Err("fixture does not accept an automatic replay".into());
                        }
                    }
                    SessionEvent::Preparation { transport_id, event } => match *event {
                        PreparationEvent::Trust { prompt_id, .. } => manager.respond(
                            "snippet-terminal",
                            &transport_id,
                            &prompt_id,
                            PreparationResponse::AcceptHostKey,
                        )?,
                        PreparationEvent::Passphrase { .. }
                        | PreparationEvent::KeyboardInteractive { .. } => {
                            return Err("password fixture requested an unexpected input".into());
                        }
                        PreparationEvent::Progress { .. } | PreparationEvent::Verified { .. } => {}
                    },
                    SessionEvent::Ready { transport_id } => {
                        if transport.lock().unwrap().replace(transport_id.clone()).is_some() {
                            return Err("snippet must be sent exactly once".into());
                        }
                        manager.input("snippet-terminal", &transport_id, input.clone())?;
                    }
                    SessionEvent::Retrying { .. } | SessionEvent::Failed { .. } => {
                        return Err("disposable snippet connection failed".into());
                    }
                    SessionEvent::Closed => {
                        closed.store(true, std::sync::atomic::Ordering::SeqCst);
                        manager.close("snippet-terminal")?;
                    }
                }
                Ok(())
            },
            |_, bytes| {
                let mut output = output.lock().unwrap();
                if output.len() + bytes.len() > 65_536 {
                    return Err("fixture output exceeded its bound".into());
                }
                output.extend_from_slice(&bytes);
                Ok(())
            },
            |_, _| {},
        ),
    )
    .await??;
    assert!(closed.load(std::sync::atomic::Ordering::SeqCst));
    let marker = b"SCOPLEN-SNIPPET:ready:-7:blue\r\n";
    assert_eq!(
        output.lock().unwrap().windows(marker.len()).filter(|part| *part == marker).count(),
        1
    );
    let transport = transport.into_inner().unwrap().expect("one ready transport");
    assert!(manager.input("snippet-terminal", &transport, input).is_err());
    println!(
        "Real OpenSSH saved/typed/prepared snippet produced its exact marker once; ended transport refused old input."
    );

    let mut definition = definition;
    definition.name = "Selected terminals".into();
    definition.template = definition.template.strip_suffix("; exit").unwrap().to_owned();
    let selected = snippets.create(definition)?;
    let prepared = snippets.prepare(&selected.id, BTreeMap::new())?;
    selected_terminals(manager, store, &host.logins[0].id, &prepared.command).await?;
    Ok(())
}

async fn selected_terminals(
    manager: SessionManager,
    store: Arc<Store>,
    profile_id: &str,
    command: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let input = format!("{command}\r").into_bytes();
    let marker = b"SCOPLEN-SNIPPET:ready:-7:blue\r\n";
    let barrier = b"SCOPLEN-REPLACEMENT-READY\r\n";
    let mut terminals = Vec::new();
    let result = async {
        let mut targets = Vec::new();
        for id in ["selected-first", "selected-replaced", "selected-other-tab"] {
            terminals.push(Terminal::start(
                manager.clone(),
                store.clone(),
                id,
                profile_id.to_owned(),
            )?);
            let terminal = terminals.last_mut().unwrap();
            let transport = terminal.ready(&manager).await?;
            assert_eq!(terminal.marker_count(marker), 0);
            targets.push((id, transport));
        }
        assert_ne!(targets[0].1, targets[1].1);
        assert_ne!(targets[1].1, targets[2].1);
        terminals.remove(1).close(&manager).await?;
        terminals.push(Terminal::start(
            manager.clone(),
            store.clone(),
            targets[1].0,
            profile_id.to_owned(),
        )?);
        let replacement = terminals.last_mut().unwrap().ready(&manager).await?;
        assert_ne!(replacement, targets[1].1);

        // These are the captured pairs, not a lookup of each logical session's new transport.
        let outcomes: Vec<_> = targets
            .iter()
            .map(|(id, transport)| manager.input(id, transport, input.clone()).is_ok())
            .collect();
        assert_eq!(outcomes, [true, false, true]);
        terminals[0].wait_marker(marker).await?;
        terminals[1].wait_marker(marker).await?;

        // A later command is an output barrier for the replacement, not a replay of the snippet.
        manager.input(
            targets[1].0,
            &replacement,
            b"printf '\\123COPLEN-REPLACEMENT-READY\\n'\r".to_vec(),
        )?;
        terminals[2].wait_marker(barrier).await?;
        assert_eq!(terminals[2].marker_count(marker), 0);
        assert_eq!(terminals[0].marker_count(marker), 1);
        assert_eq!(terminals[1].marker_count(marker), 1);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let mut cleanup = Ok(());
    for terminal in terminals {
        if let Err(error) = terminal.close(&manager).await {
            cleanup = Err(error);
        }
    }
    result?;
    cleanup?;
    println!(
        "Real OpenSSH selected-session input reached each surviving same-Login transport once; the captured stale transport was refused and its replacement received no replay."
    );
    Ok(())
}
