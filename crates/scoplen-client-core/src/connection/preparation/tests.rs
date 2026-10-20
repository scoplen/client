// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::repository::{
    AccessProfileChange, Credential, CredentialBinding, CredentialChange, CredentialKind,
    HostChange, Route, RouteChange, RouteChoice, RouteKind,
};
use scoplen_crypto::LocalDatabaseKey;
use std::sync::atomic::{AtomicUsize, Ordering};

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
    assert_eq!(result.err().unwrap(), "connection was cancelled");
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
