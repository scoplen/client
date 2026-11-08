// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use scoplen_crypto::LocalDatabaseKey;
use scoplen_model::{FieldEntry, Hlc};

use super::*;
use crate::connection::{
    SessionTarget,
    preparation::{
        PreparationControl, PreparationEvent, PreparationResponse,
        prepare_resolved_target_connection, resolve_target_preparation_plan,
    },
};
use crate::inventory::{Inventory, RecentSessionOutcome};
use crate::repository::{AccessProfileChange, Change, HostChange, Repository, RouteChange};
use crate::store::team_assets::TeamAssetPublication;

fn object<R: Record>(id: Uuid, change: R::Change, device: Uuid) -> Object {
    let mut object = Object::new(id, R::TYPE, 1).unwrap();
    for (path, value) in change.into_writes().unwrap() {
        if value == scoplen_model::cbor::Value::Null {
            continue;
        }
        object.insert(path, FieldEntry::new(value, Hlc::at(1).unwrap(), device).unwrap()).unwrap();
    }
    object
}

struct Fixture {
    store: Arc<Store>,
    personal: PersonalServer,
    source: TeamSshSource,
    host: Uuid,
    profile: Uuid,
    objects: Vec<Object>,
    publication: TeamAssetPublication,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            Store::open(&dir.path().join("teams.db"), &LocalDatabaseKey::new([37; 32])).unwrap(),
        );
        crate::personal_server::tests::fixture_profile(&store, "https://team.example.test", true);
        store.save_personal_tokens(&[1], &[2], u64::MAX, u64::MAX).unwrap();
        let identity = store.personal_record().unwrap().unwrap();
        let source = TeamSshSource {
            origin: identity.origin.clone(),
            account_id: identity.account_id.to_string(),
            organization_id: Uuid::now_v7().to_string(),
            device_id: store.device_id().to_string(),
        };
        let host = Uuid::now_v7();
        let profile = Uuid::now_v7();
        let objects = vec![
            object::<Host>(
                host,
                HostChange {
                    name: Some("Team host".into()),
                    address: Some("team.example.test".into()),
                    ..Default::default()
                },
                store.device_id(),
            ),
            object::<AccessProfile>(
                profile,
                AccessProfileChange {
                    host: Some(host),
                    username: Some("team-user".into()),
                    ..Default::default()
                },
                store.device_id(),
            ),
        ];
        let publication = TeamAssetPublication {
            organization: Uuid::parse_str(&source.organization_id).unwrap(),
            generation: store
                .begin_team_asset_pull(&identity, Uuid::parse_str(&source.organization_id).unwrap())
                .unwrap(),
            vault: Uuid::now_v7(),
            revision: 1,
            cursor: 1,
        };
        store.publish_team_assets(&identity, &publication, &objects).unwrap();
        Self {
            store,
            personal: PersonalServer::default(),
            source,
            host,
            profile,
            objects,
            publication,
            _dir: dir,
        }
    }

    fn target(&self) -> SessionTarget {
        SessionTarget::Organization {
            source: self.source.clone(),
            profile_id: self.profile.to_string(),
        }
    }

    fn publish(&mut self) {
        let identity = self.store.personal_record().unwrap().unwrap();
        self.publication.generation =
            self.store.begin_team_asset_pull(&identity, self.publication.organization).unwrap();
        self.publication.revision += 1;
        self.store.publish_team_assets(&identity, &self.publication, &self.objects).unwrap();
    }
}

#[test]
fn identical_personal_ids_never_supply_a_missing_team_host_or_route() {
    let mut fixture = Fixture::new();
    fixture
        .store
        .create_batch(vec![crate::store::NewObject {
            id: fixture.host,
            object_type: Host::TYPE,
            fields: HostChange {
                name: Some("Personal host".into()),
                address: Some("personal.example.test".into()),
                ..Default::default()
            }
            .into_writes()
            .unwrap(),
        }])
        .unwrap();
    let plan =
        resolve_target_preparation_plan(&fixture.store, &fixture.personal, &fixture.target())
            .unwrap();
    assert_eq!(plan.target_context().address, "team.example.test");
    assert_eq!(plan.target_context().source, Some(fixture.source.clone()));
    fixture.objects.retain(|object| object.id != fixture.host);
    fixture.publish();
    assert!(
        resolve_target_preparation_plan(&fixture.store, &fixture.personal, &fixture.target())
            .is_err()
    );
    let route = Uuid::now_v7();
    fixture
        .store
        .create_batch(vec![crate::store::NewObject {
            id: route,
            object_type: Route::TYPE,
            fields: RouteChange {
                name: Some("Personal route".into()),
                kind: Some(RouteKind::Command { command: "personal-only-helper".into() }),
            }
            .into_writes()
            .unwrap(),
        }])
        .unwrap();
    fixture.objects = vec![
        object::<Host>(
            fixture.host,
            HostChange {
                name: Some("Team host".into()),
                address: Some("team.example.test".into()),
                ..Default::default()
            },
            fixture.store.device_id(),
        ),
        object::<AccessProfile>(
            fixture.profile,
            AccessProfileChange {
                host: Some(fixture.host),
                username: Some("team-user".into()),
                route: Some(RouteChoice::Route(route)),
                ..Default::default()
            },
            fixture.store.device_id(),
        ),
    ];
    fixture.publish();
    assert!(
        resolve_target_preparation_plan(&fixture.store, &fixture.personal, &fixture.target())
            .is_err()
    );
    let mut foreign = fixture.target();
    if let SessionTarget::Organization { source, .. } = &mut foreign {
        source.device_id = Uuid::now_v7().to_string();
    }
    assert!(resolve_target_preparation_plan(&fixture.store, &fixture.personal, &foreign).is_err());
}

#[test]
fn team_jumps_require_every_visible_same_source_login_and_host() {
    let mut fixture = Fixture::new();
    let jump_host = Uuid::now_v7();
    let jump_profile = Uuid::now_v7();
    let route = Uuid::now_v7();
    fixture.objects.push(object::<Host>(
        jump_host,
        HostChange {
            name: Some("Jump".into()),
            address: Some("jump.example.test".into()),
            ..Default::default()
        },
        fixture.store.device_id(),
    ));
    fixture.objects.push(object::<AccessProfile>(
        jump_profile,
        AccessProfileChange {
            host: Some(jump_host),
            username: Some("jump-user".into()),
            ..Default::default()
        },
        fixture.store.device_id(),
    ));
    fixture.objects.push(object::<Route>(
        route,
        RouteChange {
            name: Some("Team jump".into()),
            kind: Some(RouteKind::Jump { hops: vec![jump_profile] }),
        },
        fixture.store.device_id(),
    ));
    fixture.objects.retain(|object| object.id != fixture.profile);
    fixture.objects.push(object::<AccessProfile>(
        fixture.profile,
        AccessProfileChange {
            host: Some(fixture.host),
            username: Some("team-user".into()),
            route: Some(RouteChoice::Route(route)),
            ..Default::default()
        },
        fixture.store.device_id(),
    ));
    fixture.publish();
    let snapshot =
        TeamConnectionSnapshot::load(&fixture.store, &fixture.personal, &fixture.source).unwrap();
    let plans = snapshot.plans(fixture.profile).unwrap();
    assert_eq!(plans.len(), 2);
    assert_eq!(plans[0].0.username, "jump-user");
    assert_eq!(plans[1].0.username, "team-user");
    assert!(
        plans.iter().all(|plan| plan.0.credential == CredentialMaterial::OrganizationCertificate)
    );
    fixture.objects.retain(|object| object.id != jump_host);
    fixture.publish();
    assert!(
        resolve_target_preparation_plan(&fixture.store, &fixture.personal, &fixture.target())
            .is_err()
    );
}

#[test]
fn sidecar_history_and_host_trust_never_resolve_through_personal_ids() {
    let fixture = Fixture::new();
    let snapshot =
        TeamConnectionSnapshot::load(&fixture.store, &fixture.personal, &fixture.source).unwrap();
    let history = fixture
        .store
        .record_team_session_start(
            &fixture.source,
            snapshot.authority,
            fixture.host,
            fixture.profile,
        )
        .unwrap();
    fixture
        .store
        .create_batch(vec![crate::store::NewObject {
            id: fixture.host,
            object_type: Host::TYPE,
            fields: HostChange {
                name: Some("Personal collision".into()),
                address: Some("personal.example.test".into()),
                ..Default::default()
            }
            .into_writes()
            .unwrap(),
        }])
        .unwrap();
    fixture
        .store
        .create_batch(vec![crate::store::NewObject {
            id: fixture.profile,
            object_type: AccessProfile::TYPE,
            fields: AccessProfileChange {
                host: Some(fixture.host),
                username: Some("personal-user".into()),
                ..Default::default()
            }
            .into_writes()
            .unwrap(),
        }])
        .unwrap();
    let inventory = Inventory::new(fixture.store.clone());
    inventory.close_session(history.to_string(), RecentSessionOutcome::Closed).unwrap();
    let recent = inventory.recent_sessions().unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].host_name, "Team host");
    assert_eq!(recent[0].target, fixture.target());
    assert_eq!(inventory.reconnect_session(history.to_string()).unwrap().target, fixture.target());
    fixture
        .store
        .save_scrollback(
            history,
            &crate::terminal_output::TerminalSnapshot {
                version: 1,
                columns: 80,
                rows: 24,
                data: "team output".into(),
            },
        )
        .unwrap();
    assert_eq!(
        inventory.saved_terminal_output(history.to_string()).unwrap().target.target,
        fixture.target()
    );
    let fingerprint = format!("SHA256:{}", "a".repeat(43));
    fixture
        .store
        .accept_team_host_key(&fixture.source, fixture.host, "ssh-ed25519 fixture", &fingerprint)
        .unwrap();
    assert!(Repository::<TrustRecord>::new(&fixture.store).list().unwrap().is_empty());
    let mut other = fixture.source.clone();
    other.organization_id = Uuid::now_v7().to_string();
    assert!(fixture.store.team_host_trust(&other, fixture.host).unwrap().is_none());
    let identity = fixture.store.personal_record().unwrap().unwrap();
    fixture
        .store
        .invalidate_team_assets(
            &identity,
            snapshot.source.owner(&fixture.store).unwrap().organization,
            None,
        )
        .unwrap();
    assert!(inventory.recent_sessions().unwrap().is_empty());
    assert!(inventory.reconnect_session(history.to_string()).is_err());
    assert!(inventory.saved_terminal_output(history.to_string()).is_err());
    assert!(Repository::<Host>::new(&fixture.store).get(fixture.host).unwrap().is_some());
}

#[test]
fn ordinary_failed_pulls_preserve_exact_authority_and_other_team_invalidation_isolated() {
    let fixture = Fixture::new();
    let snapshot =
        TeamConnectionSnapshot::load(&fixture.store, &fixture.personal, &fixture.source).unwrap();
    let identity = fixture.store.personal_record().unwrap().unwrap();
    let organization = Uuid::parse_str(&fixture.source.organization_id).unwrap();
    let pull = fixture.store.begin_team_asset_pull(&identity, organization).unwrap();
    fixture.store.finish_team_asset_pull(&identity, organization, pull, 4, false).unwrap();
    snapshot.current(&fixture.store, &fixture.personal).unwrap();
    let offline =
        TeamConnectionSnapshot::load(&fixture.store, &fixture.personal, &fixture.source).unwrap();
    assert_eq!(offline.authority, snapshot.authority);
    assert_eq!(offline.plan(fixture.profile).unwrap().0.address, "team.example.test");
    let mut other = fixture.source.clone();
    let other_organization = Uuid::now_v7();
    other.organization_id = other_organization.to_string();
    fixture
        .store
        .publish_team_assets(
            &identity,
            &TeamAssetPublication {
                organization: other_organization,
                generation: fixture
                    .store
                    .begin_team_asset_pull(&identity, other_organization)
                    .unwrap(),
                vault: Uuid::now_v7(),
                revision: 1,
                cursor: 1,
            },
            &fixture.objects,
        )
        .unwrap();
    let other = TeamConnectionSnapshot::load(&fixture.store, &fixture.personal, &other).unwrap();
    fixture.store.invalidate_team_assets(&identity, organization, None).unwrap();
    assert!(snapshot.current(&fixture.store, &fixture.personal).is_err());
    other.current(&fixture.store, &fixture.personal).unwrap();
}

#[tokio::test]
async fn organization_command_requires_exact_attempt_approval_before_spawn() {
    let mut fixture = Fixture::new();
    let route = Uuid::now_v7();
    fixture.objects.push(object::<Route>(
        route,
        RouteChange {
            name: Some("Team command".into()),
            kind: Some(RouteKind::Command {
                command: "scoplen-nonexistent-fixture-helper --host=%h ''".into(),
            }),
        },
        fixture.store.device_id(),
    ));
    fixture.objects.retain(|object| object.id != fixture.profile);
    fixture.objects.push(object::<AccessProfile>(
        fixture.profile,
        AccessProfileChange {
            host: Some(fixture.host),
            username: Some("team-user".into()),
            route: Some(RouteChoice::Route(route)),
            ..Default::default()
        },
        fixture.store.device_id(),
    ));
    fixture.publish();
    let control = PreparationControl::default();
    let events = Mutex::new(Vec::new());
    let plan =
        resolve_target_preparation_plan(&fixture.store, &fixture.personal, &fixture.target())
            .unwrap();
    let result = prepare_resolved_target_connection(
        &fixture.store,
        &fixture.personal,
        plan,
        &control,
        |event| {
            match &event {
                PreparationEvent::CommandExecution { context, prompt_id, program, arguments } => {
                    assert_eq!(context.source, Some(fixture.source.clone()));
                    assert_eq!(program, "scoplen-nonexistent-fixture-helper");
                    assert_eq!(arguments, &["--host=team.example.test", ""]);
                    assert!(
                        control.respond(prompt_id, PreparationResponse::AcceptHostKey).is_err()
                    );
                    control.cancel();
                    assert!(
                        control.respond(prompt_id, PreparationResponse::AcceptCommand).is_err()
                    );
                }
                _ => panic!("a cancelled command must not connect or authenticate"),
            }
            events.lock().unwrap().push(event);
            Ok(())
        },
    )
    .await;
    assert!(result.is_err());
    assert_eq!(events.lock().unwrap().len(), 1);
    let control = PreparationControl::default();
    let approved = std::sync::atomic::AtomicBool::new(false);
    let connections = std::sync::atomic::AtomicUsize::new(0);
    let plan =
        resolve_target_preparation_plan(&fixture.store, &fixture.personal, &fixture.target())
            .unwrap();
    let result = prepare_resolved_target_connection(
        &fixture.store,
        &fixture.personal,
        plan,
        &control,
        |event| {
            match event {
                PreparationEvent::CommandExecution { prompt_id, .. } => {
                    assert!(
                        control
                            .respond("another-attempt", PreparationResponse::AcceptCommand)
                            .is_err()
                    );
                    control.respond(&prompt_id, PreparationResponse::AcceptCommand)?;
                    approved.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                PreparationEvent::Progress { .. } => {
                    assert!(approved.load(std::sync::atomic::Ordering::SeqCst));
                    connections.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                _ => panic!("the nonexistent helper must not reach SSH authentication"),
            }
            Ok(())
        },
    )
    .await;
    assert!(result.is_err());
    assert!(approved.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(connections.load(std::sync::atomic::Ordering::SeqCst), 1);
}
