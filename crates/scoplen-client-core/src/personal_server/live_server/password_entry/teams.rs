// SPDX-License-Identifier: Apache-2.0
//! Actual public HTTPS creation/discovery with independent Devices and Account isolation.

use scoplen_api::organization::{MAX_ORGANIZATION_RESOURCE_BYTES, OrganizationResource};
use scoplen_crypto::{DpopProof, DpopTarget, DpopToken};

use super::*;

pub(super) async fn verify_pair(
    first_manager: &PersonalServer,
    first_store: &Arc<Store>,
    second_manager: &PersonalServer,
    second_store: &Arc<Store>,
) -> Vec<TeamSummary> {
    for (manager, store) in [(first_manager, first_store), (second_manager, second_store)] {
        assert!(
            manager
                .teams_page(store.clone(), None)
                .await
                .expect("initial discovery")
                .teams
                .is_empty()
        );
    }
    let before = record(first_store).expect("immutable Personal identity");
    let keys = first_manager
        .load_sync_bootstrap(first_store)
        .expect("verified original keys")
        .expect("installed bootstrap");
    let prepared = first_manager
        .prepare_team_creation(first_store, "First Device team".into())
        .expect("retain the first creation");
    let confirmed = first_manager
        .submit_team_creation(first_store.clone(), &prepared.operation_id)
        .await
        .expect("create through public HTTPS");
    assert_eq!(confirmed.phase, TeamCreationPhase::Confirmed);
    let first_team = confirmed.organization.expect("confirmed team projection");
    assert_eq!(first_team.roles, ["owner"]);
    assert_eq!(
        second_manager.team(second_store.clone(), &first_team.id).await.unwrap(),
        first_team
    );
    let captured = first_manager
        .team_settings(first_store.clone(), &first_team.id)
        .await
        .expect("capture the current public Resource and ETag");
    let stale = second_manager.team_settings(second_store.clone(), &first_team.id).await.unwrap();
    assert_eq!(stale, captured);
    let saved = first_manager
        .update_team_name(
            first_store.clone(),
            &first_team.id,
            &captured.etag,
            "Renamed team".into(),
        )
        .await
        .expect("one public HTTPS conditional name update");
    assert_ne!(saved.etag, captured.etag);
    assert_eq!(saved.team.id, first_team.id);
    assert_eq!(saved.team.name, "Renamed team");
    assert_eq!(
        second_manager
            .update_team_name(
                second_store.clone(),
                &first_team.id,
                &stale.etag,
                "Stale edit".into()
            )
            .await,
        Err(crate::personal_server::TeamFailure::SettingsConflict.into())
    );
    assert_eq!(
        first_manager
            .update_team_name(
                first_store.clone(),
                &first_team.id,
                &saved.etag,
                saved.team.name.clone()
            )
            .await
            .unwrap(),
        saved
    );
    assert_eq!(
        second_manager.team_settings(second_store.clone(), &first_team.id).await.unwrap(),
        saved
    );
    let first_team = saved.team;
    first_manager
        .discard_team_creation(first_store, &prepared.operation_id)
        .expect("explicitly close the confirmed local operation");

    let second_team = send_without_local_confirmation(second_manager, second_store).await;
    let mut expected = vec![first_team, second_team];
    expected.sort_by(|left, right| left.id.cmp(&right.id));
    for (manager, store) in [(first_manager, first_store), (second_manager, second_store)] {
        let page = manager.teams_page(store.clone(), None).await.expect("same Account discovery");
        assert_eq!(page.teams, expected);
        assert!(page.next_cursor.is_none());
        for team in &expected {
            assert_eq!(manager.team(store.clone(), &team.id).await.unwrap(), *team);
        }
    }
    let after = record(first_store).expect("unchanged Personal identity");
    assert_eq!(after.account_id, before.account_id);
    assert_eq!(after.personal_vault_id, before.personal_vault_id);
    assert_eq!(after.private_material.as_bytes(), before.private_material.as_bytes());
    let verified = first_manager
        .bootstrap_sync(first_store.clone())
        .await
        .expect("Personal keys after team creation");
    assert_eq!(verified.personal_vault_key().as_bytes(), keys.personal_vault_key().as_bytes());
    expected
}

async fn send_without_local_confirmation(
    manager: &PersonalServer,
    store: &Arc<Store>,
) -> TeamSummary {
    let prepared = manager
        .prepare_team_creation(store, "Second Device team".into())
        .expect("retain the second Device's exact request");
    let identity = record(store).expect("current independent Device");
    let pending =
        store.team_creation(&identity).expect("retained request").expect("prepared request");
    let access = store.personal_access_token(now().unwrap()).unwrap().expect("real access token");
    let token = std::str::from_utf8(access.as_bytes()).unwrap();
    let proof = proof(&identity, token, "POST", "/api/v1/orgs");
    assert!(
        store
            .dispatch_team_creation(
                &identity,
                &pending,
                &access,
                scoplen_model::system_time_millis().unwrap()
            )
            .expect("durable original dispatch before public request")
    );
    let response = manager
        .transport
        .as_ref()
        .unwrap()
        .team_create(
            &identity.origin,
            pending.payload.as_bytes(),
            pending.operation_id,
            token,
            &proof,
        )
        .await
        .expect("actual public HTTPS response");
    assert_eq!(response.status, 201);
    let resource = OrganizationResource::from_http_json(
        response.body.as_bytes(),
        response.etag.as_deref(),
        response.cache_control.as_deref(),
        response.pragma.as_deref(),
    )
    .expect("complete shared Resource");
    resource.validate_for_account(identity.account_id).expect("same Account");
    // Withhold the successful response from the local reducer, as after interrupted delivery.
    let unknown = manager.pending_team_creation(store).unwrap().unwrap();
    assert_eq!(unknown.phase, TeamCreationPhase::Unknown);
    assert_eq!(unknown.operation_id, prepared.operation_id);
    TeamSummary {
        id: resource.id.to_string(),
        name: resource.name,
        roles: resource.membership.roles,
    }
}

pub(super) async fn verify_reopened(
    manager: &PersonalServer,
    store: &Arc<Store>,
    expected: &[TeamSummary],
) {
    let offline = PersonalServer::default();
    let retained = offline
        .pending_team_creation(store)
        .expect("reopened local pending")
        .expect("unknown retained");
    assert_eq!(retained.phase, TeamCreationPhase::Unknown);
    let before = record(store).unwrap();
    let original = store.team_creation(&before).unwrap().unwrap();
    let confirmed = manager
        .submit_team_creation(store.clone(), &retained.operation_id)
        .await
        .expect("explicit exact replay through the restarted Account");
    assert_eq!(confirmed.phase, TeamCreationPhase::Confirmed);
    assert_eq!(confirmed.retry_until, retained.retry_until);
    assert!(expected.contains(confirmed.organization.as_ref().unwrap()));
    let after = store.team_creation(&record(store).unwrap()).unwrap().unwrap();
    assert_eq!(after.operation_id, original.operation_id);
    assert_eq!(after.payload.as_bytes(), original.payload.as_bytes());
    assert_eq!(after.first_attempt_ms, original.first_attempt_ms);
    let discovered = manager.teams_page(store.clone(), None).await.expect("discovery after replay");
    assert_eq!(discovered.teams, expected);
    assert!(discovered.next_cursor.is_none());
    manager
        .discard_team_creation(store, &retained.operation_id)
        .expect("explicitly close confirmed replay");
}

pub(super) async fn verify_isolation(
    first_manager: &PersonalServer,
    first_store: &Arc<Store>,
    other_manager: &PersonalServer,
    other_store: &Arc<Store>,
    original_teams: &[TeamSummary],
) {
    assert!(
        other_manager
            .teams_page(other_store.clone(), None)
            .await
            .expect("foreign Account discovery")
            .teams
            .is_empty()
    );
    let prepared = other_manager
        .prepare_team_creation(other_store, "Independent Account team".into())
        .unwrap();
    let team = other_manager
        .submit_team_creation(other_store.clone(), &prepared.operation_id)
        .await
        .expect("independent Account creates its own team")
        .organization
        .unwrap();
    assert_eq!(
        other_manager.teams_page(other_store.clone(), None).await.unwrap().teams,
        vec![team.clone()]
    );
    assert_eq!(
        first_manager.teams_page(first_store.clone(), None).await.unwrap().teams,
        original_teams
    );
    for (manager, store, foreign) in [
        (other_manager, other_store, original_teams[0].id.as_str()),
        (first_manager, first_store, team.id.as_str()),
    ] {
        let absent =
            unavailable_team(manager, store, &scoplen_model::new_uuid_v7().unwrap().to_string())
                .await;
        let denied = unavailable_team(manager, store, foreign).await;
        assert_eq!(denied.problem_type, absent.problem_type);
        assert_eq!(denied.title, absent.title);
        assert_eq!(denied.detail, absent.detail);
        assert_eq!(
            manager.update_team_name(store.clone(), foreign, "\"foreign\"", "Refused".into()).await,
            Err(crate::personal_server::TeamFailure::TeamNotFound.into())
        );
    }
}

async fn unavailable_team(
    manager: &PersonalServer,
    store: &Arc<Store>,
    id: &str,
) -> scoplen_api::ProblemDetails {
    let identity = record(store).unwrap();
    let access = store.personal_access_token(now().unwrap()).unwrap().expect("current real token");
    let token = std::str::from_utf8(access.as_bytes()).unwrap();
    let path = format!("/api/v1/orgs/{id}");
    let proof = proof(&identity, token, "GET", &path);
    let response = manager
        .transport
        .as_ref()
        .unwrap()
        .team_get(&identity.origin, &path, token, &proof, MAX_ORGANIZATION_RESOURCE_BYTES)
        .await
        .expect("actual inaccessible team request");
    assert_eq!(response.status, 404);
    assert!(response.problem_json);
    let problem = scoplen_api::ProblemDetails::from_json(response.body.as_bytes(), 4096).unwrap();
    assert_eq!(problem.status, 404);
    assert_eq!(problem.code.as_str(), "organization.not_found");
    assert!(!problem.changed && !problem.retryable);
    problem
}

fn proof(
    identity: &crate::store::personal::PersonalRecord,
    token: &str,
    method: &str,
    path: &str,
) -> DpopProof {
    let secrets = identity::Secrets::parse(&identity.private_material).unwrap();
    let signing = P256SigningKey::from_bytes(secrets.signing()).unwrap();
    DpopProof::sign(
        &signing,
        &signing.public_key_sec1(),
        &DpopTarget::new(method, &identity.origin, path).unwrap(),
        DpopToken::Protected(token),
        now().unwrap(),
        None,
    )
    .unwrap()
}
