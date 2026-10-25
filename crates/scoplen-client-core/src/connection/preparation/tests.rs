// SPDX-License-Identifier: Apache-2.0

use super::super::evaluate_host_key;
use super::*;
use crate::repository::{
    AccessProfileChange, Credential, CredentialBinding, CredentialChange, CredentialKind,
    HostChange, Route, RouteChange, RouteChoice, RouteKind,
};
use scoplen_crypto::LocalDatabaseKey;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn challenge_request(prompts: Vec<(&str, bool)>) -> KeyboardInteractiveInfoRequest {
    KeyboardInteractiveInfoRequest::new(
        b"<server request>".to_vec(),
        b"literal instructions".to_vec(),
        Vec::new(),
        prompts
            .into_iter()
            .map(|(text, echo)| {
                scoplen_ssh::KeyboardInteractivePrompt::new(text.as_bytes(), echo).unwrap()
            })
            .collect(),
    )
    .unwrap()
}

fn peer_login(store: &Store, port: u16, kind: CredentialKind, secret: Option<Vec<u8>>) -> Uuid {
    let id = login(store, "interactive target");
    let profile = Repository::<AccessProfile>::new(store).get(id).unwrap().unwrap();
    Repository::<Host>::new(store)
        .update(profile.host, HostChange { port: Edit::Set(port), ..Default::default() })
        .unwrap();
    Repository::<AccessProfile>::new(store)
        .update(
            id,
            AccessProfileChange { username: Some("trust-fixture".into()), ..Default::default() },
        )
        .unwrap();
    Repository::<Credential>::new(store)
        .update(
            profile.credential.unwrap(),
            CredentialChange {
                kind: Some(kind),
                binding: Some(if kind == CredentialKind::KeyboardInteractive {
                    CredentialBinding::None
                } else {
                    CredentialBinding::Shared
                }),
                secret: secret.map(|value| Edit::Set(SecretVec::new(value))).unwrap_or(Edit::Clear),
                ..Default::default()
            },
        )
        .unwrap();
    id
}

#[tokio::test]
async fn saved_interactive_and_accepted_password_or_software_key_complete_ordered_rounds() {
    use super::super::test_peer::{Authentication, Peer};
    for mode in [
        Authentication::Interactive,
        Authentication::PasswordThenInteractive,
        Authentication::KeyThenInteractive,
    ] {
        for algorithm in [ssh_key::Algorithm::Ed25519, ssh_key::Algorithm::Rsa { hash: None }] {
            if mode != Authentication::KeyThenInteractive
                && algorithm != ssh_key::Algorithm::Ed25519
            {
                continue;
            }
            let peer = Peer::with_authentication(mode).await;
            let (_dir, store) = store();
            let (kind, secret) = match mode {
                Authentication::KeyThenInteractive => {
                    let key = ssh_key::PrivateKey::random(
                        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                        algorithm,
                    )
                    .unwrap();
                    (
                        CredentialKind::PrivateKey,
                        Some(key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes().to_vec()),
                    )
                }
                Authentication::PasswordThenInteractive => {
                    (CredentialKind::Password, Some(b"disposable-trust-password".to_vec()))
                }
                _ => (CredentialKind::KeyboardInteractive, None),
            };
            let profile = peer_login(&store, peer.port, kind, secret);
            let rounds = AtomicUsize::new(0);
            for _attempt in 0..2 {
                let control = PreparationControl::default();
                let result = tokio::time::timeout(
                    Duration::from_secs(30),
                    prepare_connection(&store, profile, &control, |event| {
                        match event {
                            PreparationEvent::Trust { prompt_id, .. } => {
                                control.respond(&prompt_id, PreparationResponse::AcceptHostKey)?
                            }
                            PreparationEvent::KeyboardInteractive {
                                prompt_id,
                                context,
                                prompts,
                                ..
                            } => {
                                assert_eq!(context.profile_id, profile.to_string());
                                assert!(context.target);
                                assert_eq!(context.port, peer.port);
                                let round = rounds.fetch_add(1, Ordering::SeqCst) % 3;
                                let answers = match round {
                                    0 => vec![b"visible".to_vec(), vec![]],
                                    1 => vec![],
                                    _ => vec![b"123456".to_vec()],
                                };
                                assert_eq!(prompts.len(), answers.len());
                                control.respond(
                                    &prompt_id,
                                    PreparationResponse::keyboard_interactive(answers).unwrap(),
                                )?;
                            }
                            _ => {}
                        }
                        Ok(())
                    }),
                )
                .await
                .unwrap();
                let connection = result.unwrap();
                assert_eq!(connection.state(), super::super::ConnectionState::Open);
                let mut session = connection.open_session().await.unwrap();
                let result = session.exec(b"printf scoplen-interactive-ok", None).await.unwrap();
                assert_eq!(result.stdout, b"scoplen-interactive-ok");
                assert_eq!(result.exit_status, Some(0));
                connection.close().await.unwrap();
            }
            assert_eq!(rounds.load(Ordering::SeqCst), 6);
        }
    }
}

#[tokio::test]
async fn ordinary_rejection_never_falls_back_and_unsupported_next_factor_fails() {
    use super::super::test_peer::{Authentication, Peer};
    for unsupported in [false, true] {
        let peer = Peer::with_authentication(if unsupported {
            Authentication::UnsupportedAfterInteractive
        } else {
            Authentication::PasswordThenInteractive
        })
        .await;
        let (_dir, store) = store();
        let profile = peer_login(
            &store,
            peer.port,
            if unsupported {
                CredentialKind::KeyboardInteractive
            } else {
                CredentialKind::Password
            },
            (!unsupported).then(|| b"wrong-password".to_vec()),
        );
        let control = PreparationControl::default();
        let rounds = AtomicUsize::new(0);
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            prepare_connection(&store, profile, &control, |event| {
                match event {
                    PreparationEvent::Trust { prompt_id, .. } => {
                        control.respond(&prompt_id, PreparationResponse::AcceptHostKey)?
                    }
                    PreparationEvent::KeyboardInteractive { prompt_id, .. } => {
                        let round = rounds.fetch_add(1, Ordering::SeqCst);
                        let answers = match round {
                            0 => vec![b"visible".to_vec(), vec![]],
                            1 => vec![],
                            _ => vec![b"123456".to_vec()],
                        };
                        control.respond(
                            &prompt_id,
                            PreparationResponse::keyboard_interactive(answers).unwrap(),
                        )?;
                    }
                    _ => {}
                }
                Ok(())
            }),
        )
        .await
        .unwrap();
        if unsupported {
            assert!(matches!(
                result,
                Err(PreparationError::Connection(
                    SshConnectionError::UnsupportedAuthenticationFactor
                ))
            ));
        } else {
            assert!(matches!(
                result,
                Err(PreparationError::Connection(SshConnectionError::Engine(
                    ClientError::AuthenticationRejected { partial_success: false, .. }
                )))
            ));
            assert_eq!(rounds.load(Ordering::SeqCst), 0);
            assert_eq!(peer.challenges.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn pending_interactive_allows_another_terminal_and_cancellation_fences_late_answers() {
    use super::super::test_peer::{Authentication, Peer};
    let peer = Peer::with_authentication(Authentication::Interactive).await;
    let ordinary = Peer::start().await;
    let (_dir, store) = store();
    let profile = peer_login(&store, peer.port, CredentialKind::KeyboardInteractive, None);
    let other = peer_login(
        &store,
        ordinary.port,
        CredentialKind::Password,
        Some(b"disposable-trust-password".to_vec()),
    );
    let control = PreparationControl::default();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let prepare = prepare_connection(&store, profile, &control, |event| {
        match event {
            PreparationEvent::Trust { prompt_id, .. } => {
                control.respond(&prompt_id, PreparationResponse::AcceptHostKey)?
            }
            PreparationEvent::KeyboardInteractive { prompt_id, .. } => tx.send(prompt_id).unwrap(),
            _ => {}
        }
        Ok(())
    });
    let concurrent = async {
        let prompt = rx.recv().await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let second = PreparationControl::default();
        let connected = prepare_connection(&store, other, &second, |event| {
            if let PreparationEvent::Trust { prompt_id, .. } = event {
                second.respond(&prompt_id, PreparationResponse::AcceptHostKey)?;
            }
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(connected.state(), super::super::ConnectionState::Open);
        connected.close().await.unwrap();
        control.cancel();
        assert!(
            control
                .respond(
                    &prompt,
                    PreparationResponse::keyboard_interactive(vec![b"late".to_vec(), vec![]])
                        .unwrap()
                )
                .is_err()
        );
    };
    let (result, ()) =
        tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(prepare, concurrent) })
            .await
            .unwrap();
    assert!(result.is_err());
    assert!(control.state.lock().unwrap().pending.is_none());
}

#[test]
fn saved_interactive_jump_descriptors_resolve_at_their_own_positions() {
    let (_dir, store) = store();
    let target = peer_login(&store, 2222, CredentialKind::KeyboardInteractive, None);
    let hop = peer_login(&store, 2223, CredentialKind::KeyboardInteractive, None);
    route(&store, target, RouteKind::Jump { hops: vec![hop] });
    let steps = resolve_steps(&store, target).unwrap();
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].context.profile_id, hop.to_string());
    assert_eq!(steps[0].context.position, 1);
    assert!(!steps[0].context.target);
    assert_eq!(steps[1].context.profile_id, target.to_string());
    assert!(steps[1].context.target);
    assert!(steps.iter().all(|step| matches!(
        step.plan.credential,
        super::super::CredentialMaterial::KeyboardInteractive
    )));
}

#[tokio::test]
async fn interactive_rounds_require_exact_ordered_one_use_answers_including_empty_rounds() {
    let control = PreparationControl::default();
    let (_dir, store) = store();
    let profile = login(&store, "hop");
    let context = resolve_steps(&store, profile).unwrap().remove(0).context;
    let ids = Mutex::new(Vec::<String>::new());
    for prompts in [vec![("Name", true), ("OTP", false)], vec![]] {
        let count = prompts.len();
        let answers = control
            .challenge(
                challenge_request(prompts),
                context.clone(),
                Instant::now() + AUTHENTICATION_TIMEOUT,
                &|event| {
                    let PreparationEvent::KeyboardInteractive {
                        prompt_id,
                        prompts,
                        context: actual,
                        name,
                        ..
                    } = event
                    else {
                        panic!("unexpected prompt")
                    };
                    assert_eq!(actual, context);
                    assert_eq!(name, "<server request>");
                    assert_eq!(prompts.len(), count);
                    if count == 2 {
                        assert!(prompts[0].echo);
                        assert!(!prompts[1].echo);
                    }
                    assert!(
                        control.respond(&prompt_id, PreparationResponse::AcceptHostKey).is_err()
                    );
                    assert!(
                        control
                            .respond(
                                &prompt_id,
                                PreparationResponse::keyboard_interactive(vec![vec![]; count + 1])
                                    .unwrap()
                            )
                            .is_err()
                    );
                    for id in ids.lock().unwrap().iter() {
                        assert!(
                            control
                                .respond(
                                    id,
                                    PreparationResponse::keyboard_interactive(vec![vec![]; count])
                                        .unwrap()
                                )
                                .is_err()
                        );
                    }
                    control.respond(
                        &prompt_id,
                        PreparationResponse::keyboard_interactive(vec![vec![]; count]).unwrap(),
                    )?;
                    assert!(
                        control
                            .respond(
                                &prompt_id,
                                PreparationResponse::keyboard_interactive(vec![vec![]; count])
                                    .unwrap()
                            )
                            .is_err()
                    );
                    ids.lock().unwrap().push(prompt_id);
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert_eq!(answers.responses().len(), count);
        assert!(answers.responses().iter().all(|answer| answer.as_bytes().is_empty()));
        assert!(control.state.lock().unwrap().pending.is_none());
    }
}

#[tokio::test(start_paused = true)]
async fn interactive_admission_rejects_exact_deadline_and_total_authentication_budget() {
    for budget in [CHALLENGE_TIMEOUT, Duration::from_secs(7)] {
        let control = PreparationControl::default();
        let (_dir, store) = store();
        let profile = login(&store, "target");
        let context = resolve_steps(&store, profile).unwrap().remove(0).context;
        let deadline = Instant::now() + budget;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let emit = |event| tx.send(event).map_err(|_| "closed".into());
        let challenge =
            control.challenge(challenge_request(vec![("OTP", false)]), context, deadline, &emit);
        let late = async {
            let PreparationEvent::KeyboardInteractive { prompt_id, .. } = rx.recv().await.unwrap()
            else {
                panic!("unexpected prompt")
            };
            tokio::time::advance(budget).await;
            let error = control
                .respond(
                    &prompt_id,
                    PreparationResponse::keyboard_interactive(vec![b"deadline-secret".to_vec()])
                        .unwrap(),
                )
                .unwrap_err();
            assert!(!error.contains("deadline-secret"));
        };
        let (result, ()) = tokio::join!(challenge, late);
        assert!(result.is_err());
        assert!(control.state.lock().unwrap().pending.is_none());
    }
}

#[tokio::test]
async fn public_preparation_keeps_one_budget_across_passphrase_retry_partial_success_and_rounds() {
    use super::super::test_peer::{Authentication, Peer};
    async fn advance_to(started: Instant, seconds: u64) {
        tokio::time::advance(
            (started + Duration::from_secs(seconds)).duration_since(Instant::now()),
        )
        .await;
    }

    let peer = Peer::with_authentication(Authentication::KeyThenInteractive).await;
    let (_dir, store) = store();
    let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
    let private = ssh_key::PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519).unwrap();
    let private = private.encrypt(&mut rng, b"disposable-passphrase").unwrap();
    let profile = peer_login(
        &store,
        peer.port,
        CredentialKind::PrivateKey,
        Some(private.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes().to_vec()),
    );
    let control = PreparationControl::default();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let started = Mutex::new(None);
    let finished = AtomicBool::new(false);
    let preparation = async {
        let result = prepare_connection(&store, profile, &control, |event| {
            if matches!(event, PreparationEvent::Verified { .. }) {
                tokio::time::pause();
                *started.lock().unwrap() = Some(Instant::now());
            }
            tx.send(event).map_err(|_| "test receiver closed".into())
        })
        .await;
        finished.store(true, Ordering::SeqCst);
        result
    };
    let wall_deadline = std::time::Instant::now() + Duration::from_secs(20);
    let answers = async {
        let mut passphrases = 0;
        let mut rounds = 0;
        let mut accepted_factor_timer_released = false;
        loop {
            // Keep the executor runnable while the local protocol peer handles
            // real sockets, so paused time advances only at the explicit steps.
            let event = loop {
                assert!(
                    !finished.load(Ordering::SeqCst),
                    "preparation ended before the expected prompt"
                );
                assert!(
                    std::time::Instant::now() < wall_deadline,
                    "protocol peer did not deliver the expected prompt after {passphrases} passphrases and {rounds} rounds ({} authentications, {} challenges)",
                    peer.authentications.load(Ordering::SeqCst),
                    peer.challenges.load(Ordering::SeqCst)
                );
                if passphrases == 2
                    && !accepted_factor_timer_released
                    && peer.authentications.load(Ordering::SeqCst) == 1
                {
                    // Russh gates its partial-success reply on a zero-duration
                    // rejection timer, which still needs one paused-clock tick.
                    tokio::time::advance(Duration::from_millis(1)).await;
                    accepted_factor_timer_released = true;
                }
                tokio::select! { biased;
                    event = rx.recv() => break event.expect("preparation ended before the expected prompt"),
                    _ = tokio::task::yield_now() => {}
                }
            };
            match event {
                PreparationEvent::Trust { prompt_id, .. } => {
                    control.respond(&prompt_id, PreparationResponse::AcceptHostKey).unwrap();
                }
                PreparationEvent::Passphrase { prompt_id, incorrect, .. } => {
                    let began = started.lock().unwrap().unwrap();
                    let (at, answer) = if passphrases == 0 {
                        assert!(!incorrect);
                        (180, b"wrong-passphrase".as_slice())
                    } else {
                        assert!(incorrect);
                        (240, b"disposable-passphrase".as_slice())
                    };
                    advance_to(began, at).await;
                    control
                        .respond(
                            &prompt_id,
                            PreparationResponse::Passphrase(SecretVec::new(answer.to_vec())),
                        )
                        .unwrap();
                    passphrases += 1;
                }
                PreparationEvent::KeyboardInteractive { prompt_id, prompts, .. } => {
                    let began = started.lock().unwrap().unwrap();
                    assert_eq!(passphrases, 2);
                    assert_eq!(peer.authentications.load(Ordering::SeqCst), 1);
                    let answer = match rounds {
                        0 => vec![b"visible".to_vec(), vec![]],
                        1 => vec![],
                        2 => {
                            assert_eq!(prompts.len(), 1);
                            advance_to(began, 299).await;
                            assert_eq!(
                                started.lock().unwrap().unwrap().elapsed(),
                                Duration::from_secs(299)
                            );
                            assert!(control.state.lock().unwrap().pending.is_some());
                            advance_to(began, 300).await;
                            let error = control
                                .respond(
                                    &prompt_id,
                                    PreparationResponse::keyboard_interactive(vec![
                                        b"late-disposable".to_vec(),
                                    ])
                                    .unwrap(),
                                )
                                .unwrap_err();
                            assert!(!error.contains("late-disposable"));
                            break;
                        }
                        _ => panic!("unexpected additional authentication round"),
                    };
                    assert_eq!(prompts.len(), answer.len());
                    advance_to(began, 260 + 20 * rounds).await;
                    control
                        .respond(
                            &prompt_id,
                            PreparationResponse::keyboard_interactive(answer).unwrap(),
                        )
                        .unwrap();
                    rounds += 1;
                }
                _ => {}
            }
        }
        assert_eq!(rounds, 2);
        assert_eq!(started.lock().unwrap().unwrap().elapsed(), AUTHENTICATION_TIMEOUT);
        while !finished.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < wall_deadline,
                "timed-out preparation did not close"
            );
            tokio::task::yield_now().await;
        }
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(330), async {
        tokio::join!(preparation, answers)
    })
    .await
    .expect("preparation did not release the timed-out connection");
    tokio::time::resume();
    assert!(result.is_err());
    assert!(control.state.lock().unwrap().pending.is_none());
    assert_eq!(peer.session_channels.load(Ordering::SeqCst), 0);
    while peer.closed_connections.load(Ordering::SeqCst) == 0 {
        assert!(
            std::time::Instant::now() < wall_deadline,
            "failed preparation retained its connection"
        );
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn interactive_cancellation_and_event_failure_clear_pending_state() {
    let (_dir, store) = store();
    let profile = login(&store, "target");
    let context = resolve_steps(&store, profile).unwrap().remove(0).context;
    for cancel in [true, false] {
        let control = PreparationControl::default();
        let result = control
            .challenge(
                challenge_request(vec![("OTP", false)]),
                context.clone(),
                Instant::now() + AUTHENTICATION_TIMEOUT,
                &|event| {
                    if cancel {
                        let PreparationEvent::KeyboardInteractive { prompt_id, .. } = event else {
                            unreachable!()
                        };
                        control.cancel();
                        assert!(
                            control
                                .respond(
                                    &prompt_id,
                                    PreparationResponse::keyboard_interactive(vec![
                                        b"late".to_vec()
                                    ])
                                    .unwrap()
                                )
                                .is_err()
                        );
                        Ok(())
                    } else {
                        Err("renderer unavailable".into())
                    }
                },
            )
            .await;
        assert!(result.is_err());
        assert!(control.state.lock().unwrap().pending.is_none());
    }
}

#[test]
fn interactive_answer_bounds_are_checked_before_dispatch_and_debug_redacts_answers() {
    assert!(PreparationResponse::keyboard_interactive(vec![vec![]; 65]).is_err());
    assert!(PreparationResponse::keyboard_interactive(vec![vec![0; 65537]]).is_err());
    assert!(PreparationResponse::keyboard_interactive(vec![vec![0; 65536]; 4]).is_err());
    let response =
        PreparationResponse::keyboard_interactive(vec![b"private-answer".to_vec()]).unwrap();
    assert!(!format!("{response:?}").contains("private-answer"));
}

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("local.db"), &LocalDatabaseKey::new([7; 32])).unwrap();
    (dir, store)
}

fn login(store: &Store, label: &str) -> Uuid {
    let host = Repository::<Host>::new(store)
        .create(HostChange {
            name: Some(label.into()),
            address: Some("127.0.0.1".into()),
            ..Default::default()
        })
        .unwrap();
    let credential = Repository::<Credential>::new(store)
        .create(CredentialChange {
            kind: Some(CredentialKind::Password),
            binding: Some(CredentialBinding::Shared),
            secret: Edit::Set(SecretVec::new(b"disposable-fixture-password".to_vec())),
            ..Default::default()
        })
        .unwrap();
    Repository::<AccessProfile>::new(store)
        .create(AccessProfileChange {
            host: Some(host.meta.id),
            username: Some("fixture".into()),
            credential: Edit::Set(credential.meta.id),
            ..Default::default()
        })
        .unwrap()
        .meta
        .id
}

fn route(store: &Store, profile: Uuid, kind: RouteKind) -> Uuid {
    let route = Repository::<Route>::new(store)
        .create(RouteChange { name: Some("fixture".into()), kind: Some(kind) })
        .unwrap();
    Repository::<AccessProfile>::new(store)
        .update(
            profile,
            AccessProfileChange {
                route: Some(RouteChoice::Route(route.meta.id)),
                ..Default::default()
            },
        )
        .unwrap();
    route.meta.id
}

fn raw_key(byte: u8) -> HostKey {
    HostKey::Raw { algorithm: "ssh-ed25519".into(), key_blob: vec![byte; 32] }
}

#[test]
fn initial_presentation_is_pinned_during_review_and_all_rekeys() {
    let verifier = PresentedKey::default();
    verifier.verify("fixture", &raw_key(1)).unwrap();
    verifier.verify("fixture", &raw_key(1)).unwrap();
    assert!(verifier.verify("fixture", &raw_key(2)).is_err());
    assert_eq!(
        verifier.0.lock().unwrap().as_ref().unwrap(),
        &HostKeyPresentation::from_host_key(&raw_key(1))
    );
}

#[test]
fn explicit_chain_preserves_order_and_has_no_small_fixed_hop_cap() {
    let (_dir, store) = store();
    let target = login(&store, "target");
    let hops = (0..40).map(|i| login(&store, &format!("hop-{i}"))).collect::<Vec<_>>();
    route(&store, target, RouteKind::Jump { hops: hops.clone() });
    let steps = resolve_steps(&store, target).unwrap();
    assert_eq!(steps.len(), 41);
    assert_eq!(steps[..40].iter().map(|s| s.plan.profile_id).collect::<Vec<_>>(), hops);
    assert!(steps.iter().all(|s| s.plan.route == ConnectionRoute::Direct));
    assert_eq!(steps[0].context.host, "hop-0");
    assert!(!steps[0].context.target);
    assert!(steps.last().unwrap().context.target);
    assert_eq!(steps.last().unwrap().context.position, 41);
}

#[tokio::test]
async fn invalid_chains_fail_before_network_or_agent_access() {
    for invalid in [
        "empty",
        "duplicate-login",
        "duplicate-host",
        "target",
        "missing-login",
        "missing-host",
        "missing-credential",
        "missing-route",
        "nested",
        "proxy",
        "command",
        "unsupported-credential",
        "invalid-agent",
    ] {
        let (_dir, store) = store();
        let target = login(&store, "target");
        let first = login(&store, "first");
        let second = login(&store, "second");
        let mut hops = vec![first, second];
        match invalid {
            "empty" => hops.clear(),
            "duplicate-login" => hops.push(first),
            "duplicate-host" => {
                let host =
                    Repository::<AccessProfile>::new(&store).get(first).unwrap().unwrap().host;
                Repository::<AccessProfile>::new(&store)
                    .update(second, AccessProfileChange { host: Some(host), ..Default::default() })
                    .unwrap();
            }
            "target" => hops.push(target),
            "missing-login" => store.delete(second).unwrap(),
            "missing-host" => {
                let profile =
                    Repository::<AccessProfile>::new(&store).get(second).unwrap().unwrap();
                store.delete(profile.host).unwrap();
            }
            "missing-credential" => {
                let profile =
                    Repository::<AccessProfile>::new(&store).get(second).unwrap().unwrap();
                store.delete(profile.credential.unwrap()).unwrap();
            }
            "missing-route" => {
                let id = route(&store, second, RouteKind::Jump { hops: vec![first] });
                store.delete(id).unwrap();
            }
            "nested" => {
                route(&store, second, RouteKind::Jump { hops: vec![target] });
            }
            "proxy" => {
                route(
                    &store,
                    second,
                    RouteKind::Socks5 {
                        proxy: "127.0.0.1:9".into(),
                        credential: None,
                        username: None,
                    },
                );
            }
            "command" => {
                route(&store, second, RouteKind::Command { command: "must-not-execute".into() });
            }
            kind => {
                let credential = Repository::<Credential>::new(&store)
                    .create(CredentialChange {
                        kind: Some(if kind == "invalid-agent" {
                            CredentialKind::Agent
                        } else {
                            CredentialKind::ExternalProvider
                        }),
                        binding: Some(CredentialBinding::None),
                        ..Default::default()
                    })
                    .unwrap();
                Repository::<AccessProfile>::new(&store)
                    .update(
                        second,
                        AccessProfileChange {
                            credential: Edit::Set(credential.meta.id),
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
        }
        route(&store, target, RouteKind::Jump { hops });
        let effects = AtomicUsize::new(0);
        let result = prepare_connection(&store, target, &PreparationControl::default(), |_| {
            effects.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .await;
        assert!(result.is_err(), "{invalid}");
        assert_eq!(effects.load(Ordering::SeqCst), 0, "{invalid} reached connection preparation");
    }
}

#[tokio::test]
async fn oversized_username_without_command_substitution_fails_before_any_side_effect() {
    let (_dir, store) = store();
    let target = login(&store, "target");
    route(&store, target, RouteKind::Command { command: "must-not-execute %h %p".into() });
    Repository::<AccessProfile>::new(&store)
        .update(
            target,
            AccessProfileChange { username: Some("x".repeat(4097)), ..Default::default() },
        )
        .unwrap();
    let events = AtomicUsize::new(0);
    let result = prepare_connection(&store, target, &PreparationControl::default(), |_| {
        events.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
    .await;
    assert_eq!(result.err().unwrap().to_string(), SshConnectionError::InvalidUsername.to_string());
    assert_eq!(events.load(Ordering::SeqCst), 0);
    assert!(Repository::<TrustRecord>::new(&store).list().unwrap().is_empty());

    let mut plan = resolve_connection_plan(&store, target).unwrap();
    for username in [String::new(), "bad\0user".into(), "\u{1f980}".repeat(1025)] {
        plan.username = username;
        assert!(matches!(
            SshConnection::connect(&plan, None).await,
            Err(SshConnectionError::InvalidUsername)
        ));
        assert!(matches!(
            super::super::probe_host_key(&plan).await,
            Err(SshConnectionError::InvalidUsername)
        ));
    }
    plan.username = "\u{1f980}".repeat(1024);
    assert!(transport_route(&plan).is_ok());
}

#[tokio::test]
async fn progress_callback_can_cancel_before_any_network_operation() {
    let (_dir, store) = store();
    let target = login(&store, "target");
    let control = PreparationControl::default();
    let events = AtomicUsize::new(0);
    let result = prepare_connection(&store, target, &control, |_| {
        events.fetch_add(1, Ordering::SeqCst);
        control.cancel();
        Ok(())
    })
    .await;
    assert_eq!(result.err().unwrap().to_string(), "connection was cancelled");
    assert_eq!(events.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn prompts_reject_wrong_kind_stale_duplicate_and_cross_attempt_responses() {
    let control = PreparationControl::default();
    let other = PreparationControl::default();
    let response = control
        .prompt(
            PromptKind::Trust,
            |id| PreparationEvent::Trust {
                context: context(),
                prompt_id: id,
                host_key: PreparationHostKey {
                    algorithm: "fixture".into(),
                    key: "public".into(),
                    fingerprint: "SHA256:fixture".into(),
                    changed: false,
                    review: None,
                    previous_source: None,
                },
            },
            &|event| {
                let PreparationEvent::Trust { prompt_id, .. } = event else { unreachable!() };
                assert!(control.respond("old", PreparationResponse::AcceptHostKey).is_err());
                assert!(other.respond(&prompt_id, PreparationResponse::AcceptHostKey).is_err());
                assert!(
                    control
                        .respond(
                            &prompt_id,
                            PreparationResponse::Passphrase(SecretVec::new(vec![1]))
                        )
                        .is_err()
                );
                control.respond(&prompt_id, PreparationResponse::AcceptHostKey).unwrap();
                assert!(control.respond(&prompt_id, PreparationResponse::AcceptHostKey).is_err());
                Ok(())
            },
        )
        .await
        .unwrap();
    assert!(matches!(response, PreparationResponse::AcceptHostKey));
}

fn context() -> PreparationContext {
    PreparationContext {
        profile_id: "login".into(),
        host_id: "host".into(),
        login: "fixture".into(),
        host: "fixture".into(),
        username: "fixture".into(),
        address: "127.0.0.1".into(),
        port: 22,
        position: 1,
        total: 1,
        target: true,
    }
}

#[tokio::test]
async fn cancel_after_acceptance_blocks_trust_write_and_any_late_response() {
    let (_dir, store) = store();
    let control = PreparationControl::default();
    let result = control
        .prompt(
            PromptKind::Trust,
            |id| PreparationEvent::Trust {
                context: context(),
                prompt_id: id,
                host_key: PreparationHostKey {
                    algorithm: "fixture".into(),
                    key: "public".into(),
                    fingerprint: "SHA256:fixture".into(),
                    changed: false,
                    review: None,
                    previous_source: None,
                },
            },
            &|event| {
                let PreparationEvent::Trust { prompt_id, .. } = event else { unreachable!() };
                control.respond(&prompt_id, PreparationResponse::AcceptHostKey).unwrap();
                control.cancel();
                assert!(control.respond(&prompt_id, PreparationResponse::AcceptHostKey).is_err());
                Ok(())
            },
        )
        .await;
    assert!(result.is_err());
    assert!(
        control
            .active(|| accept_key(
                &store,
                Uuid::now_v7(),
                &HostKeyPresentation::from_host_key(&raw_key(1))
            ))
            .is_err()
    );
    assert!(Repository::<TrustRecord>::new(&store).list().unwrap().is_empty());
}

#[test]
fn trust_rotation_is_atomic_and_only_trusts_the_selected_host_key() {
    let (_dir, store) = store();
    let host = Uuid::now_v7();
    let first = HostKeyPresentation::from_host_key(&raw_key(1));
    let second = HostKeyPresentation::from_host_key(&raw_key(2));
    accept_key(&store, host, &first).unwrap();
    accept_key(&store, host, &second).unwrap();
    let records = Repository::<TrustRecord>::new(&store).list().unwrap();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| record.accepted_by_device == Some(store.device_id())));
    assert!(records.iter().all(|record| record.accepted_by_account.is_none()));
    assert_eq!(records.iter().filter(|r| !r.revoked).count(), 1);
    assert_eq!(
        evaluate_host_key(host, &first.key, &first.fingerprint, &records),
        HostKeyStatus::Changed
    );
    assert_eq!(
        evaluate_host_key(host, &second.key, &second.fingerprint, &records),
        HostKeyStatus::Trusted
    );
    assert_eq!(
        evaluate_host_key(Uuid::now_v7(), &second.key, &second.fingerprint, &records),
        HostKeyStatus::New
    );
}

#[test]
fn concurrent_acceptance_leaves_only_one_active_raw_key() {
    let (_dir, store) = store();
    let host = Uuid::now_v7();
    let barrier = std::sync::Barrier::new(9);
    std::thread::scope(|scope| {
        for byte in 1..=8 {
            let store = &store;
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                accept_key(store, host, &HostKeyPresentation::from_host_key(&raw_key(byte)))
                    .unwrap();
            });
        }
        barrier.wait();
    });
    let records = Repository::<TrustRecord>::new(&store).list().unwrap();
    assert_eq!(records.len(), 8);
    assert_eq!(records.iter().filter(|r| !r.revoked && !r.ca).count(), 1);
}

#[test]
fn failed_rotation_rolls_back_revocation_and_preserves_ca_and_other_hosts() {
    let (_dir, store) = store();
    let store = Arc::new(store);
    let host = Uuid::now_v7();
    let other = Uuid::now_v7();
    let first = HostKeyPresentation::from_host_key(&raw_key(1));
    accept_key(&store, host, &first).unwrap();
    accept_key(&store, other, &first).unwrap();
    let ca = Repository::<TrustRecord>::new(&store)
        .create(TrustRecordChange {
            host: Edit::Set(host),
            key: Edit::Set(first.key.clone()),
            ca: Some(true),
            ..Default::default()
        })
        .unwrap();
    let before = store.list(TrustRecord::TYPE).unwrap();
    let notifications = Arc::new(AtomicUsize::new(0));
    let count = notifications.clone();
    let _subscription = store.subscribe(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
    });
    let mut invalid = HostKeyPresentation::from_host_key(&raw_key(2));
    invalid.key = "x".repeat(scoplen_model::MAX_TEXT_BYTES + 1);
    assert!(accept_key(&store, host, &invalid).is_err());
    assert_eq!(store.list(TrustRecord::TYPE).unwrap(), before);
    assert_eq!(notifications.load(Ordering::SeqCst), 0);
    accept_key(&store, host, &HostKeyPresentation::from_host_key(&raw_key(2))).unwrap();
    assert!(!Repository::<TrustRecord>::new(&store).get(ca.meta.id).unwrap().unwrap().revoked);
    let records = Repository::<TrustRecord>::new(&store).list().unwrap();
    assert_eq!(records.iter().filter(|r| r.host == Some(host) && !r.revoked && !r.ca).count(), 1);
    assert_eq!(
        evaluate_host_key(other, &first.key, &first.fingerprint, &records),
        HostKeyStatus::Trusted
    );
}
