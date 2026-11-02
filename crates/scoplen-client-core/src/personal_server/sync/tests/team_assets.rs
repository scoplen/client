// SPDX-License-Identifier: Apache-2.0
//! Public team view consumption through actual TLS/H2 and independent shared wire codecs.

use scoplen_api::{
    ErrorCode, ProblemDetails,
    sync::{SyncChange, SyncOrganizationAckResponse, SyncOrganizationViewResponse},
};
use scoplen_model::{FieldEntry, FieldPath, Hlc, Object, ObjectType, cbor::Value};

use super::*;
use crate::personal_server::{TeamAssetsPhase, TeamError, TeamFailure};

fn id() -> uuid::Uuid {
    scoplen_model::new_uuid_v7().unwrap()
}

fn host(name: &str) -> Object {
    let mut object = Object::new(id(), ObjectType::HOST, 1).unwrap();
    let origin = id();
    for (field, value) in [(1, name), (2, "host.example")] {
        object
            .insert(
                FieldPath::Field(field),
                FieldEntry::new(Value::Text(value.into()), Hlc::at(1).unwrap(), origin).unwrap(),
            )
            .unwrap();
    }
    object
}

fn session(peer: &Peer, organization: uuid::Uuid, vault: uuid::Uuid, revision: u64) {
    let response = {
        let state = peer.state.lock().unwrap();
        SyncSessionResponse::from_cbor(&state.replies["/sync/v1/session"].body).unwrap()
    };
    let mut response = response;
    response.vaults.retain(|item| item.kind != VaultKind::Organization);
    response.vaults.push(SessionVault {
        id: vault,
        kind: VaultKind::Organization,
        seq: 50,
        key_epoch: 1,
        rotation_pending: false,
        organization: Some(OrganizationVaultContext { organization, view_revision: revision }),
    });
    peer.reply("/sync/v1/session", Reply::cbor(response.to_cbor().unwrap()));
}

fn page(
    peer: &Peer,
    organization: uuid::Uuid,
    vault: uuid::Uuid,
    revision: u64,
    objects: &[Object],
) {
    peer.reply(
        &format!("/sync/v1/vaults/{vault}/view"),
        Reply::cbor(
            SyncOrganizationViewResponse {
                organization,
                vault,
                view_revision: revision,
                objects: objects
                    .iter()
                    .enumerate()
                    .map(|(index, object)| SyncChange {
                        object_id: object.id,
                        seq: index as u64 + 1,
                        payload: object.encode().unwrap(),
                        tombstone: false,
                        signer_device_id: None,
                    })
                    .collect(),
                next_cursor: 50,
                more: false,
            }
            .to_cbor()
            .unwrap(),
        ),
    );
    peer.reply(
        &format!("/sync/v1/vaults/{vault}/ack"),
        Reply::cbor(
            SyncOrganizationAckResponse { cursor: 50, view_revision: revision }.to_cbor().unwrap(),
        ),
    );
}

#[tokio::test]
async fn complete_team_view_withdraws_absent_assets_and_never_enters_personal_objects() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let (organization, vault) = (id(), id());
    let (first, second) = (host("First team asset"), host("Second team asset"));
    session(&peer, organization, vault, 1);
    page(&peer, organization, vault, 1, &[first.clone(), second.clone()]);
    let view = manager.refresh_team_assets(store.clone(), &organization.to_string()).await.unwrap();
    assert_eq!(view.phase, TeamAssetsPhase::Ready);
    assert!(view.acknowledged);
    assert_eq!(view.assets.len(), 2);
    assert_eq!(view.organization_id, organization.to_string());
    assert_eq!(view.origin, peer.origin);
    assert!(store.get(first.id).unwrap().is_none());
    assert!(store.get(second.id).unwrap().is_none());
    session(&peer, organization, vault, u64::MAX);
    page(&peer, organization, vault, u64::MAX, &[second]);
    let view = manager.refresh_team_assets(store.clone(), &organization.to_string()).await.unwrap();
    assert_eq!(view.assets.len(), 1);
    assert_eq!(view.assets[0].name.as_deref(), Some("Second team asset"));
    assert_eq!(view.revision.as_deref(), Some("18446744073709551615"));
    let paths = peer.state.lock().unwrap().paths.clone();
    assert!(!paths.iter().any(|path| path.ends_with("/keys")
        || path.ends_with("/changes")
        || path.ends_with("/snapshot")));
    peer.assert_healthy();
}

#[tokio::test]
async fn changed_view_or_membership_loss_cannot_publish_an_empty_or_previous_active_view() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let (organization, vault) = (id(), id());
    session(&peer, organization, vault, 1);
    page(&peer, organization, vault, 1, &[host("Retained")]);
    manager.refresh_team_assets(store.clone(), &organization.to_string()).await.unwrap();
    for (status, code, retryable, phase) in [
        (409, "sync.view_changed", true, TeamAssetsPhase::Stale),
        (404, "sync.object_not_found", false, TeamAssetsPhase::Unavailable),
    ] {
        peer.reply(
            &format!("/sync/v1/vaults/{vault}/view"),
            Reply {
                status,
                content_type: "application/problem+cbor",
                body: ProblemDetails::new(
                    ErrorCode::new(code).unwrap(),
                    status,
                    "Unavailable",
                    "Fixture",
                    "/fixture",
                    false,
                    retryable,
                )
                .unwrap()
                .to_cbor()
                .unwrap(),
                ..Reply::cbor(vec![])
            },
        );
        assert!(
            manager.refresh_team_assets(store.clone(), &organization.to_string()).await.is_err()
        );
        let view = manager.team_assets(&store, &organization.to_string()).unwrap();
        assert_eq!(view.phase, phase);
        assert!(view.assets.is_empty());
    }
    peer.assert_healthy();
}

#[tokio::test]
async fn foreign_response_and_late_obsolete_pull_never_replace_the_new_owner() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = Arc::new(peer.prepare(&store).await);
    let (organization, vault) = (id(), id());
    session(&peer, organization, vault, 1);
    page(&peer, id(), vault, 1, &[host("Foreign")]);
    assert!(matches!(
        manager.refresh_team_assets(store.clone(), &organization.to_string()).await,
        Err(TeamError::Team(TeamFailure::InvalidTeamResponse))
    ));
    page(&peer, organization, vault, 1, &[host("Old reply")]);
    let reached = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    peer.state.lock().unwrap().pause =
        Some((format!("/sync/v1/vaults/{vault}/view"), reached.clone(), resume.clone()));
    let work = {
        let manager = manager.clone();
        let store = store.clone();
        tokio::spawn(
            async move { manager.refresh_team_assets(store, &organization.to_string()).await },
        )
    };
    reached.notified().await;
    page(&peer, organization, vault, 1, &[host("New reply")]);
    let newest =
        manager.refresh_team_assets(store.clone(), &organization.to_string()).await.unwrap();
    assert_eq!(newest.assets[0].name.as_deref(), Some("New reply"));
    resume.notify_one();
    assert!(work.await.unwrap().is_err());
    let view = manager.team_assets(&store, &organization.to_string()).unwrap();
    assert_eq!(view.phase, TeamAssetsPhase::Ready);
    assert_eq!(view.assets[0].name.as_deref(), Some("New reply"));
    peer.assert_healthy();
}

#[tokio::test]
async fn unconfirmed_ack_retains_complete_publication_and_reopen_requires_revalidation() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let (organization, vault) = (id(), id());
    session(&peer, organization, vault, 1);
    page(&peer, organization, vault, 1, &[host("Team asset")]);
    peer.reply(&format!("/sync/v1/vaults/{vault}/ack"), Reply::cbor(vec![0xff]));
    assert!(matches!(
        manager.refresh_team_assets(store.clone(), &organization.to_string()).await,
        Err(TeamError::Team(TeamFailure::AssetsAcknowledgementUnknown))
    ));
    let view = manager.team_assets(&store, &organization.to_string()).unwrap();
    assert_eq!(view.phase, TeamAssetsPhase::Ready);
    assert!(!view.acknowledged);
    assert_eq!(view.assets.len(), 1);
    drop(store);
    let reopened = local(&dir);
    let view = manager.team_assets(&reopened, &organization.to_string()).unwrap();
    assert_eq!(view.phase, TeamAssetsPhase::Stale);
    assert!(view.assets.is_empty());
    for (status, code, expected) in [
        (401, "auth.authentication_required", PersonalServerError::AuthenticationRequired),
        (403, "policy.denied", PersonalServerError::PermissionDenied),
    ] {
        peer.reply(
            &format!("/sync/v1/vaults/{vault}/ack"),
            Reply {
                status,
                content_type: "application/problem+cbor",
                body: ProblemDetails::new(
                    ErrorCode::new(code).unwrap(),
                    status,
                    "Denied",
                    "Fixture",
                    "/fixture",
                    false,
                    false,
                )
                .unwrap()
                .to_cbor()
                .unwrap(),
                ..Reply::cbor(vec![])
            },
        );
        assert_eq!(
            manager.refresh_team_assets(reopened.clone(), &organization.to_string()).await,
            Err(TeamError::Personal(expected))
        );
        let denied = manager.team_assets(&reopened, &organization.to_string()).unwrap();
        assert_eq!(denied.phase, TeamAssetsPhase::Failed);
        assert!(denied.assets.is_empty());
        assert!(reopened.personal_access_token(now().unwrap()).unwrap().is_some());
    }
    peer.assert_healthy();
}

#[tokio::test]
async fn multiple_pages_publish_only_after_the_final_valid_page() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = Arc::new(peer.prepare(&store).await);
    let (organization, vault) = (id(), id());
    let first = host("First page");
    let second = host("Final page");
    session(&peer, organization, vault, 1);
    page(&peer, organization, vault, 1, &[]);
    let make_page = |object: &Object, seq, more| {
        Reply::cbor(
            SyncOrganizationViewResponse {
                organization,
                vault,
                view_revision: 1,
                objects: vec![SyncChange {
                    object_id: object.id,
                    seq,
                    payload: object.encode().unwrap(),
                    tombstone: false,
                    signer_device_id: None,
                }],
                next_cursor: if more { seq } else { 50 },
                more,
            }
            .to_cbor()
            .unwrap(),
        )
    };
    let path = format!("/sync/v1/vaults/{vault}/view");
    peer.state
        .lock()
        .unwrap()
        .view_pages
        .insert(path.clone(), [make_page(&first, 1, true), make_page(&second, 2, false)].into());
    let reached = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    peer.state.lock().unwrap().pause =
        Some((format!("{path}?revision=1&after=1&limit=16"), reached.clone(), resume.clone()));
    let work = {
        let manager = manager.clone();
        let store = store.clone();
        tokio::spawn(
            async move { manager.refresh_team_assets(store, &organization.to_string()).await },
        )
    };
    reached.notified().await;
    let staged = manager.team_assets(&store, &organization.to_string()).unwrap();
    assert_eq!(staged.phase, TeamAssetsPhase::Updating);
    assert!(staged.assets.is_empty());
    assert!(!peer.state.lock().unwrap().paths.iter().any(|path| path.ends_with("/ack")));
    resume.notify_one();
    let final_view = work.await.unwrap().unwrap();
    assert_eq!(final_view.assets.len(), 2);
    assert!(final_view.acknowledged);
    assert!(store.get(first.id).unwrap().is_none());
    assert!(store.get(second.id).unwrap().is_none());
    peer.assert_healthy();
}

#[tokio::test]
async fn an_invalid_final_page_never_replaces_a_complete_view_or_another_teams_cache() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let (organization, vault, other, other_vault) = (id(), id(), id(), id());
    let original = host("Original team asset");
    session(&peer, organization, vault, 1);
    page(&peer, organization, vault, 1, std::slice::from_ref(&original));
    manager.refresh_team_assets(store.clone(), &organization.to_string()).await.unwrap();
    session(&peer, other, other_vault, 1);
    page(&peer, other, other_vault, 1, &[host("Other team asset")]);
    manager.refresh_team_assets(store.clone(), &other.to_string()).await.unwrap();

    session(&peer, organization, vault, 2);
    let staged = host("Partial replacement");
    let path = format!("/sync/v1/vaults/{vault}/view");
    let first = SyncOrganizationViewResponse {
        organization,
        vault,
        view_revision: 2,
        objects: vec![SyncChange {
            object_id: staged.id,
            seq: 1,
            payload: staged.encode().unwrap(),
            tombstone: false,
            signer_device_id: None,
        }],
        next_cursor: 1,
        more: true,
    }
    .to_cbor()
    .unwrap();
    let final_page = SyncOrganizationViewResponse {
        organization: other,
        vault,
        view_revision: 2,
        objects: vec![],
        next_cursor: 50,
        more: false,
    }
    .to_cbor()
    .unwrap();
    peer.state
        .lock()
        .unwrap()
        .view_pages
        .insert(path, [Reply::cbor(first), Reply::cbor(final_page)].into());
    let acknowledgements =
        || peer.state.lock().unwrap().paths.iter().filter(|path| path.ends_with("/ack")).count();
    let before = acknowledgements();
    assert!(matches!(
        manager.refresh_team_assets(store.clone(), &organization.to_string()).await,
        Err(TeamError::Team(TeamFailure::InvalidTeamResponse))
    ));
    let failed = manager.team_assets(&store, &organization.to_string()).unwrap();
    assert_eq!(failed.phase, TeamAssetsPhase::Failed);
    assert!(failed.assets.is_empty());
    assert_eq!(acknowledgements(), before);
    assert!(store.get(staged.id).unwrap().is_none());
    let other_view = manager.team_assets(&store, &other.to_string()).unwrap();
    assert_eq!(other_view.phase, TeamAssetsPhase::Ready);
    assert_eq!(other_view.assets[0].name.as_deref(), Some("Other team asset"));

    page(&peer, organization, vault, 2, &[]);
    let empty =
        manager.refresh_team_assets(store.clone(), &organization.to_string()).await.unwrap();
    assert_eq!(empty.phase, TeamAssetsPhase::Ready);
    assert!(empty.assets.is_empty());
    assert!(empty.acknowledged);
    peer.assert_healthy();
}

#[tokio::test]
async fn independent_background_owner_polls_unchanged_team_views_and_team_hints_do_not_write_personal()
 {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = Arc::new(peer.prepare(&store).await);
    {
        let mut state = peer.state.lock().unwrap();
        state.inventory = Some(InventoryPeer::default());
        state.notification = Some(notification::NotificationPeer::default());
    }
    manager.bootstrap_sync(store.clone()).await.unwrap();
    let (organization, vault) = (id(), id());
    session(&peer, organization, vault, 1);
    page(&peer, organization, vault, 1, &[host("Initial team view")]);
    manager.refresh_team_assets(store.clone(), &organization.to_string()).await.unwrap();
    let running = notification::start_shared(manager.clone(), store.clone());
    let views =
        || peer.state.lock().unwrap().paths.iter().filter(|path| path.ends_with("/view")).count();
    notification::wait(|| {
        views() >= 2
            && running.runtime.status()
                == crate::personal_server::PersonalBackgroundStatus::Connected
    })
    .await;
    tokio::time::sleep(Duration::from_millis(350)).await;
    let baseline = views();
    page(&peer, organization, vault, 1, &[host("Same revision fresh reevaluation")]);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::time::resume();
    notification::wait(|| views() > baseline).await;
    notification::wait(|| {
        manager
            .team_assets(&store, &organization.to_string())
            .unwrap()
            .assets
            .first()
            .is_some_and(|asset| asset.name.as_deref() == Some("Same revision fresh reevaluation"))
    })
    .await;
    let personal_writes = peer.state.lock().unwrap().inventory.as_ref().unwrap().writes;
    page(&peer, organization, vault, 1, &[host("Hint refresh")]);
    notification::team_hint(
        &peer,
        scoplen_api::sync::SyncNotification::OrganizationViewChanged {
            organization,
            vault,
            view_revision: 1,
        },
    );
    notification::wait(|| {
        manager
            .team_assets(&store, &organization.to_string())
            .unwrap()
            .assets
            .first()
            .is_some_and(|asset| asset.name.as_deref() == Some("Hint refresh"))
    })
    .await;
    assert_eq!(peer.state.lock().unwrap().inventory.as_ref().unwrap().writes, personal_writes);
    running.runtime.set_store(None);
    tokio::time::sleep(Duration::from_millis(350)).await;
    let detached = views();
    store.invalidate_team_assets(&record(&store).unwrap(), organization, None).unwrap();
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert_eq!(views(), detached);
    peer.assert_healthy();
}
