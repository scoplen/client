// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::connection::{
    command_credential::CommandCredential,
    resolve_connection_plan,
    test_peer::{Authentication, Peer},
};
use crate::repository::{
    AccessProfileChange, Credential, CredentialBinding, CredentialChange, CredentialKind,
    HostChange,
};
use scoplen_crypto::LocalDatabaseKey;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

pub(super) fn login(store: &Store, port: u16, path: String, explicit: bool) -> (Uuid, Uuid) {
    let host = Repository::<Host>::new(store)
        .create(HostChange {
            name: Some("External password target".into()),
            address: Some("127.0.0.1".into()),
            port: Edit::Set(port),
            ..Default::default()
        })
        .unwrap();
    let credential = Repository::<Credential>::new(store)
        .create(CredentialChange {
            kind: Some(CredentialKind::ExternalProvider),
            binding: Some(CredentialBinding::None),
            provider: BTreeMap::from([
                ("type".into(), Some("command".into())),
                ("path".into(), Some(path)),
                ("field".into(), Some("password".into())),
            ]),
            ..Default::default()
        })
        .unwrap();
    let profile = Repository::<AccessProfile>::new(store)
        .create(AccessProfileChange {
            host: Some(host.meta.id),
            username: Some("trust-fixture".into()),
            credential: if explicit { Edit::Set(credential.meta.id) } else { Edit::Keep },
            ..Default::default()
        })
        .unwrap();
    (profile.meta.id, credential.meta.id)
}

#[tokio::test]
async fn command_password_requires_explicit_selection_then_retained_trust_and_exact_approval() {
    for decline in ["trust", "command", "factor-refused", "factor-unsupported", "none"] {
        let peer = Peer::with_authentication(if decline == "factor-unsupported" {
            Authentication::UnsupportedAfterInteractive
        } else {
            Authentication::PasswordThenInteractive
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let store =
            Store::open(&dir.path().join("local.db"), &LocalDatabaseKey::new([7; 32])).unwrap();
        let marker = dir.path().join("called");
        let script = dir.path().join(if cfg!(windows) { "helper.ps1" } else { "helper.sh" });
        std::fs::write(&script, if cfg!(windows) {
            "[IO.File]::AppendAllText($args[0], '+'); [Console]::Out.Write('disposable-trust-password')"
        } else {
            "printf + >> \"$1\"; printf disposable-trust-password"
        }).unwrap();
        let path = if cfg!(windows) {
            format!(
                "powershell.exe -NoProfile -NonInteractive -File \"{}\" \"{}\"",
                script.display(),
                marker.display()
            )
        } else {
            format!("/bin/sh \"{}\" \"{}\"", script.display(), marker.display())
        };
        let (implicit, _) = login(&store, peer.port, path.clone(), false);
        assert!(resolve_connection_plan(&store, implicit).is_err());
        let (profile, credential) = login(&store, peer.port, path, true);
        let plan = resolve_connection_plan(&store, profile).unwrap();
        assert!(matches!(plan.credential, CredentialMaterial::External { .. }));
        super::super::probe_host_key(&plan).await.unwrap();
        assert!(!marker.exists(), "local resolution/probe executed the helper");
        assert_eq!(peer.authentications.load(Ordering::SeqCst), 0);
        let CredentialMaterial::External { provider } = &plan.credential else { unreachable!() };
        let command = CommandCredential::parse(provider).unwrap();
        let control = PreparationControl::default();
        let verified = AtomicBool::new(false);
        let approvals = AtomicUsize::new(0);
        let rounds = AtomicUsize::new(0);
        let events = Mutex::new(Vec::new());
        let result = prepare_connection(&store, profile, &control, |event| {
            events.lock().unwrap().push(format!("{event:?}"));
            match event {
                PreparationEvent::Trust { prompt_id, .. } => {
                    assert!(!marker.exists());
                    if decline == "trust" {
                        control.cancel();
                    } else {
                        control.respond(&prompt_id, PreparationResponse::AcceptHostKey)?;
                    }
                }
                PreparationEvent::Verified { .. } => {
                    verified.store(true, Ordering::SeqCst);
                }
                PreparationEvent::CommandExecution { prompt_id, program, arguments, context } => {
                    assert!(verified.load(Ordering::SeqCst));
                    assert_eq!(context.profile_id, profile.to_string());
                    assert_eq!(program, command.program);
                    assert_eq!(arguments, command.arguments);
                    assert!(!marker.exists());
                    approvals.fetch_add(1, Ordering::SeqCst);
                    if decline == "command" {
                        control.cancel();
                    } else {
                        control.respond(&prompt_id, PreparationResponse::AcceptCommand)?;
                    }
                }
                PreparationEvent::KeyboardInteractive { prompt_id, .. } => {
                    let answers = match rounds.fetch_add(1, Ordering::SeqCst) {
                        0 => vec![b"visible".to_vec(), vec![]],
                        1 => vec![],
                        _ if decline == "factor-refused" => vec![b"wrong-answer".to_vec()],
                        _ => vec![b"123456".to_vec()],
                    };
                    control
                        .respond(&prompt_id, PreparationResponse::keyboard_interactive(answers)?)?;
                }
                _ => {}
            }
            Ok(())
        })
        .await;
        if decline == "none" {
            let connection = result.unwrap();
            let mut session = connection.open_session().await.unwrap();
            assert_eq!(
                session.exec(b"printf scoplen-interactive-ok", None).await.unwrap().stdout,
                b"scoplen-interactive-ok"
            );
            connection.close().await.unwrap();
            assert_eq!(std::fs::read(&marker).unwrap(), b"+");
            assert_eq!(peer.authentications.load(Ordering::SeqCst), 1);
            assert_eq!(rounds.load(Ordering::SeqCst), 3);
        } else if decline.starts_with("factor-") {
            assert!(matches!(
                result,
                Err(PreparationError::Connection(
                    SshConnectionError::CommandCredentialAuthenticationRejected
                ))
            ));
            assert_eq!(std::fs::read(&marker).unwrap(), b"+");
            assert_eq!(peer.authentications.load(Ordering::SeqCst), 1);
            assert_eq!(rounds.load(Ordering::SeqCst), 3);
        } else {
            assert_eq!(result.err().unwrap().to_string(), "connection was cancelled");
            assert!(!marker.exists());
            assert_eq!(peer.authentications.load(Ordering::SeqCst), 0);
        }
        assert_eq!(approvals.load(Ordering::SeqCst), usize::from(decline != "trust"));
        assert!(crate::repository::credential_secret(&store, credential).unwrap().is_none());
        assert!(store.device_credential(credential).unwrap().is_none());
        assert!(
            !Repository::<Credential>::new(&store).get(credential).unwrap().unwrap().has_secret
        );
        assert!(!events.lock().unwrap().join("\n").contains("disposable-trust-password"));
    }
}

#[tokio::test]
async fn malformed_provider_fails_before_events_or_network() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("local.db"), &LocalDatabaseKey::new([7; 32])).unwrap();
    let (profile, credential) = login(&store, 9, "must-not-execute".into(), true);
    Repository::<Credential>::new(&store)
        .update(
            credential,
            CredentialChange {
                provider: BTreeMap::from([("unknown".into(), Some("value".into()))]),
                ..Default::default()
            },
        )
        .unwrap();
    let result = prepare_connection(&store, profile, &PreparationControl::default(), |_| {
        panic!("invalid descriptor reached connection preparation")
    })
    .await;
    assert!(result.err().unwrap().to_string().contains("external credential is invalid"));
}
