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
    let saved = snippets.create(SnippetInput {
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
    })?;
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
            store,
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
    let output = output.lock().unwrap();
    let marker = b"SCOPLEN-SNIPPET:ready:-7:blue\r\n";
    assert_eq!(output.windows(marker.len()).filter(|part| *part == marker).count(), 1);
    let transport = transport.into_inner().unwrap().expect("one ready transport");
    assert!(manager.input("snippet-terminal", &transport, input).is_err());
    println!(
        "Real OpenSSH saved/typed/prepared snippet produced its exact marker once; ended transport refused old input."
    );
    Ok(())
}
