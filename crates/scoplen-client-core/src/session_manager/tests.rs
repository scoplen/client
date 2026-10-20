// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::inventory::{NewHost, SignIn};
use scoplen_crypto::LocalDatabaseKey;
use std::sync::atomic::{AtomicUsize, Ordering};

fn store() -> (tempfile::TempDir, Arc<Store>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("local.db"), &LocalDatabaseKey::new([7; 32])).unwrap();
    (dir, Arc::new(store))
}

#[test]
fn only_ready_sessions_receive_five_exponential_retries() {
    let mut budget = RetryBudget::default();
    assert_eq!(budget.next(), None, "initial failure must not loop");
    budget.ended(Some(Duration::ZERO));
    for delay in RETRY_DELAYS {
        assert_eq!(budget.next(), Some(delay));
        budget.ended(Some(Duration::ZERO));
    }
    assert_eq!(budget.next(), None, "brief readiness must not reset exhaustion");
    budget.ended(Some(Duration::from_secs(29)));
    assert_eq!(budget.next(), None);
    budget.ended(Some(Duration::from_secs(30)));
    assert_eq!(budget.next(), Some(1));
}

#[test]
fn only_typed_network_causes_qualify_for_automatic_reconnect() {
    use scoplen_ssh::{ProxyOperation, ProxyProtocol};
    assert!(retryable_connection(&SshConnectionError::Engine(ClientError::NetworkLost)));
    for kind in [ErrorKind::ConnectionReset, ErrorKind::ConnectionRefused, ErrorKind::TimedOut] {
        assert!(retryable_connection(&SshConnectionError::Engine(ClientError::Transport(
            std::io::Error::from(kind),
        ))));
    }
    for error in [
        SshConnectionError::InvalidPrivateKey,
        SshConnectionError::AgentCancelled,
        SshConnectionError::InvalidUsername,
        SshConnectionError::OutputTooLarge { limit: 1 },
        SshConnectionError::Engine(ClientError::Protocol),
        SshConnectionError::Engine(ClientError::Channel),
        SshConnectionError::Engine(ClientError::ConnectionClosed),
        SshConnectionError::Engine(ClientError::AuthenticationRejected {
            partial_success: false,
            remaining_methods: vec![],
        }),
        SshConnectionError::Engine(ClientError::Transport(std::io::Error::from(
            ErrorKind::InvalidData,
        ))),
    ] {
        assert!(!retryable_connection(&error), "{error}");
    }
    assert!(retryable_connection(&SshConnectionError::Engine(ClientError::Proxy(
        ProxyError::Io {
            protocol: ProxyProtocol::HttpConnect,
            operation: ProxyOperation::Read,
            kind: ErrorKind::TimedOut
        }
        .into(),
    ))));
    assert!(!retryable_connection(&SshConnectionError::Engine(ClientError::Proxy(
        ProxyError::AuthenticationRejected { protocol: ProxyProtocol::Socks5, code: 1 }.into(),
    ))));
}

#[test]
fn closing_an_unclaimed_reservation_prevents_any_attempt() {
    let manager = SessionManager::default();
    assert!(manager.reserve("", true).is_err());
    manager.reserve("logical", true).unwrap();
    assert!(manager.reserve("logical", true).is_err());
    manager.close("logical").unwrap();
    assert!(manager.sessions.lock().unwrap().is_empty());
    assert!(manager.retry("logical").is_err());
    manager.reserve("logical", true).unwrap();
}

#[test]
fn failed_send_keeps_output_and_half_close_before_confirmed_network_loss() {
    let mut terminal = false;
    let mut output = Vec::new();
    for event in [
        ChannelEvent::Data(b"before".to_vec()),
        ChannelEvent::Success,
        ChannelEvent::Eof,
        ChannelEvent::ExtendedData {
            data_type: scoplen_ssh::ExtendedDataType::Stderr,
            data: b"after".to_vec(),
        },
    ] {
        match send_failure_event(Ok(Some(event)), &mut terminal) {
            SendFailureEvent::Output(bytes) => output.extend(bytes),
            SendFailureEvent::Continue => {}
            other => panic!("must drain queued output before deciding: {other:?}"),
        }
    }
    assert_eq!(output, b"beforeafter");
    assert!(!terminal, "EOF only closes one direction");
    assert_eq!(
        send_failure_event(
            Err(SshConnectionError::Engine(ClientError::NetworkLost)),
            &mut terminal
        ),
        SendFailureEvent::NetworkLost
    );
}

#[test]
fn failed_send_keeps_terminal_priority_and_preserves_tail_output() {
    for event in [
        ChannelEvent::ExitStatus(0),
        ChannelEvent::ExitSignal {
            signal: "TERM".into(),
            core_dumped: false,
            error_message: String::new(),
            language_tag: String::new(),
        },
        ChannelEvent::OpenFailure { code: 1, reason: String::new() },
    ] {
        let mut terminal = false;
        assert_eq!(send_failure_event(Ok(Some(event)), &mut terminal), SendFailureEvent::Continue);
        assert!(terminal);
        assert_eq!(
            send_failure_event(Ok(Some(ChannelEvent::Data(b"tail".to_vec()))), &mut terminal),
            SendFailureEvent::Output(b"tail".to_vec())
        );
        assert_eq!(
            send_failure_event(
                Err(SshConnectionError::Engine(ClientError::NetworkLost)),
                &mut terminal
            ),
            SendFailureEvent::Complete
        );
        assert_eq!(send_failure_event(Ok(None), &mut terminal), SendFailureEvent::Complete);
    }
    assert_eq!(
        send_failure_event(Ok(Some(ChannelEvent::Close)), &mut false),
        SendFailureEvent::Complete
    );
}

#[test]
fn failed_send_keeps_unknown_none_and_other_errors_nonretryable() {
    for event in [
        Ok(None),
        Err(SshConnectionError::Engine(ClientError::Protocol)),
        Err(SshConnectionError::Engine(ClientError::Channel)),
        Err(SshConnectionError::OutputTooLarge { limit: 1 }),
    ] {
        assert_eq!(send_failure_event(event, &mut false), SendFailureEvent::Original);
    }
}
#[tokio::test]
async fn pending_stop_fail_and_close_win_before_automatic_or_manual_attempt_registration() {
    for previous in [Intent::None, Intent::Retry] {
        for pending in [Intent::Stop, Intent::Fail, Intent::Close] {
            let manager = Arc::new(SessionManager::default());
            manager.reserve("logical", true).unwrap();
            let mut intents = {
                let mut sessions = manager.sessions.lock().unwrap();
                let entry = sessions.get_mut("logical").unwrap();
                entry.phase =
                    if previous == Intent::Retry { Phase::Ended } else { Phase::Retrying };
                entry.receiver.take().unwrap()
            };
            if previous == Intent::Retry {
                manager.retry("logical").unwrap();
            }
            intents.borrow_and_update();
            let (reached, at_registration) = tokio::sync::oneshot::channel();
            let (resume, gate) = tokio::sync::oneshot::channel();
            let attempt = tokio::spawn({
                let manager = manager.clone();
                async move {
                    reached.send(()).unwrap();
                    gate.await.unwrap();
                    let (sender, _) = mpsc::channel(COMMAND_QUEUE);
                    manager.register_attempt(
                        "logical",
                        Uuid::now_v7(),
                        &PreparationControl::default(),
                        sender,
                        &mut intents,
                    )
                }
            });
            at_registration.await.unwrap();
            manager.intent("logical", pending).unwrap();
            resume.send(()).unwrap();
            assert_eq!(attempt.await.unwrap().unwrap(), pending);
            let sessions = manager.sessions.lock().unwrap();
            let entry = sessions.get("logical").unwrap();
            assert!(entry.active.is_none(), "{pending:?} must prevent transport registration");
            assert_eq!(*entry.intent.borrow(), pending, "pending intent must not be cleared");
        }
    }
}

#[tokio::test]
async fn stop_before_the_reserved_owner_starts_waits_for_manual_retry_without_dialing() {
    let (_dir, store) = store();
    let manager = SessionManager::default();
    manager.reserve("logical", true).unwrap();
    manager.stop("logical").unwrap();
    let starts = AtomicUsize::new(0);
    let closed = AtomicUsize::new(0);
    manager
        .run(
            "logical",
            "invalid-profile",
            None,
            true,
            store,
            |event| {
                match event {
                    SessionEvent::Closed => {
                        assert_eq!(starts.load(Ordering::SeqCst), 0);
                        closed.fetch_add(1, Ordering::SeqCst);
                        manager.retry("logical").unwrap();
                    }
                    SessionEvent::Starting { automatic, .. } => {
                        assert!(!automatic);
                        starts.fetch_add(1, Ordering::SeqCst);
                    }
                    SessionEvent::Failed { .. } => manager.close("logical").unwrap(),
                    _ => panic!("stopped reservation must not connect automatically"),
                }
                Ok(())
            },
            |_, _| panic!("no transport"),
            |_, _| {},
        )
        .await
        .unwrap();
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(closed.load(Ordering::SeqCst), 1);
}

#[test]
fn input_is_bounded_and_old_transport_input_cannot_reach_the_replacement() {
    let manager = SessionManager::default();
    manager.reserve("logical", true).unwrap();
    let old = Uuid::now_v7();
    let (sender, mut receiver) = mpsc::channel(COMMAND_QUEUE);
    manager.sessions.lock().unwrap().get_mut("logical").unwrap().active = Some(ActiveAttempt {
        id: old,
        control: PreparationControl::default(),
        sender,
        ready: false,
    });
    assert!(manager.input("logical", &old.to_string(), vec![1]).is_err());
    manager.sessions.lock().unwrap().get_mut("logical").unwrap().active.as_mut().unwrap().ready =
        true;
    manager.input("logical", &old.to_string(), vec![1]).unwrap();
    assert_eq!(receiver.try_recv(), Ok(TransportCommand::Input(vec![1])));
    assert!(manager.input("logical", &old.to_string(), vec![0; MAX_SSH_INPUT + 1]).is_err());
    for _ in 0..COMMAND_QUEUE {
        manager.input("logical", &old.to_string(), vec![1]).unwrap();
    }
    assert!(manager.input("logical", &old.to_string(), vec![1]).is_err());
    manager.phase("logical", Phase::Ended).unwrap();
    let replacement = Uuid::now_v7();
    let (sender, mut new_receiver) = mpsc::channel(COMMAND_QUEUE);
    manager.sessions.lock().unwrap().get_mut("logical").unwrap().active = Some(ActiveAttempt {
        id: replacement,
        control: PreparationControl::default(),
        sender,
        ready: true,
    });
    assert!(manager.input("logical", &old.to_string(), vec![2]).is_err());
    assert!(new_receiver.try_recv().is_err());
    manager.input("logical", &replacement.to_string(), vec![3]).unwrap();
    assert_eq!(new_receiver.try_recv(), Ok(TransportCommand::Input(vec![3])));
}

#[tokio::test]
async fn failed_initial_attempt_waits_for_manual_intent_and_keeps_the_logical_id() {
    let (_dir, store) = store();
    let manager = SessionManager::default();
    manager.reserve("logical", true).unwrap();
    let starts = Mutex::new(Vec::new());
    let failures = AtomicUsize::new(0);
    manager
        .run(
            "logical",
            "invalid-profile",
            None,
            true,
            store,
            |event| {
                match event {
                    SessionEvent::Starting { transport_id, automatic } => {
                        assert!(!automatic);
                        starts.lock().unwrap().push(transport_id);
                    }
                    SessionEvent::Failed { exhausted, .. } => {
                        assert!(!exhausted);
                        if failures.fetch_add(1, Ordering::SeqCst) == 0 {
                            manager.retry("logical").unwrap();
                        } else {
                            manager.close("logical").unwrap();
                        }
                    }
                    _ => panic!("invalid initial attempt must not reconnect automatically"),
                }
                Ok(())
            },
            |_, _| panic!("no transport"),
            |_, _| {},
        )
        .await
        .unwrap();
    let starts = starts.lock().unwrap();
    assert_eq!(starts.len(), 2);
    assert_ne!(starts[0], starts[1]);
    assert!(manager.sessions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn repeated_stop_and_fail_keep_the_ended_session_available_for_manual_retry() {
    let (_dir, store) = store();
    let manager = SessionManager::default();
    manager.reserve("logical", true).unwrap();
    let starts = AtomicUsize::new(0);
    let failures = AtomicUsize::new(0);
    let closed = AtomicUsize::new(0);
    manager
        .run(
            "logical",
            "invalid-profile",
            None,
            true,
            store,
            |event| {
                match event {
                    SessionEvent::Starting { automatic, .. } => {
                        assert!(!automatic);
                        starts.fetch_add(1, Ordering::SeqCst);
                    }
                    SessionEvent::Failed { .. } => match failures.fetch_add(1, Ordering::SeqCst) {
                        0 => manager.fail("logical").unwrap(),
                        1 => manager.stop("logical").unwrap(),
                        2 => manager.close("logical").unwrap(),
                        _ => panic!("only the explicit manual intent may start a new attempt"),
                    },
                    SessionEvent::Closed => {
                        closed.fetch_add(1, Ordering::SeqCst);
                        manager.retry("logical").unwrap();
                    }
                    _ => panic!("no automatic or network activity expected"),
                }
                Ok(())
            },
            |_, _| panic!("invalid profile has no transport"),
            |_, _| {},
        )
        .await
        .unwrap();
    assert_eq!(starts.load(Ordering::SeqCst), 2);
    assert_eq!(failures.load(Ordering::SeqCst), 3);
    assert_eq!(closed.load(Ordering::SeqCst), 1);
    assert!(manager.sessions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn stop_during_initial_preparation_keeps_manual_retry_and_closes_each_recent() {
    let (_dir, store) = store();
    let inventory = Inventory::new(store.clone());
    let host = inventory
        .add_host(NewHost {
            name: None,
            address: "127.0.0.1".into(),
            port: Some(1),
            username: "fixture".into(),
            sign_in: SignIn::Password { password: "fixture-password".into() },
        })
        .unwrap();
    let manager = SessionManager::default();
    manager.reserve("logical", true).unwrap();
    let attempts = AtomicUsize::new(0);
    manager
        .run(
            "logical",
            &host.logins[0].id,
            None,
            true,
            store.clone(),
            |event| {
                match event {
                    SessionEvent::Preparation { .. } => {
                        if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                            manager.stop("logical").unwrap();
                        } else {
                            manager.close("logical").unwrap();
                        }
                    }
                    SessionEvent::Closed => manager.retry("logical").unwrap(),
                    SessionEvent::Starting { .. } => {}
                    _ => panic!("cancelled preparation must not dial or fail"),
                }
                Ok(())
            },
            |_, _| panic!("cancelled before network"),
            |_, _| {},
        )
        .await
        .unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    let recents = store.recent_sessions(10).unwrap();
    assert_eq!(recents.len(), 2);
    assert!(recents.iter().all(|entry| entry.ended_at.is_some()));
}

#[tokio::test]
async fn aborting_the_owner_removes_its_session_and_closes_pending_prompts() {
    let (_dir, store) = store();
    let manager = Arc::new(SessionManager::default());
    manager.reserve("logical", true).unwrap();
    let (failed, received) = tokio::sync::oneshot::channel();
    let failed = Mutex::new(Some(failed));
    let task = tokio::spawn({
        let manager = manager.clone();
        async move {
            manager
                .run(
                    "logical",
                    "invalid",
                    None,
                    true,
                    store,
                    |event| {
                        if matches!(event, SessionEvent::Failed { .. }) {
                            let _ = failed.lock().unwrap().take().unwrap().send(());
                        }
                        Ok(())
                    },
                    |_, _| Ok(()),
                    |_, _| {},
                )
                .await
        }
    });
    received.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(manager.sessions.lock().unwrap().is_empty());
}

#[tokio::test]
async fn exec_mode_finishes_after_one_attempt_without_automatic_or_manual_wait() {
    let (_dir, store) = store();
    let manager = SessionManager::default();
    manager.reserve("exec", false).unwrap();
    let failures = AtomicUsize::new(0);
    let result = manager
        .run(
            "exec",
            "invalid",
            Some("true"),
            false,
            store,
            |event| {
                if let SessionEvent::Failed { exhausted, .. } = event {
                    assert!(!exhausted);
                    failures.fetch_add(1, Ordering::SeqCst);
                }
                Ok(())
            },
            |_, _| Ok(()),
            |_, _| {},
        )
        .await;
    assert!(result.is_err());
    assert_eq!(failures.load(Ordering::SeqCst), 1);
    assert!(manager.sessions.lock().unwrap().is_empty());
}
