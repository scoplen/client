// SPDX-License-Identifier: Apache-2.0
//! Fresh team authoring and permission withdrawal through the public HTTPS client surface.

use std::collections::BTreeSet;

use crate::personal_server::{
    TeamAssetsPhase, TeamAssetsView, TeamAuthoringCollection as Collection,
    TeamAuthoringCreatePhase, TeamAuthoringData as Data, TeamAuthoringResourceView, TeamError,
    TeamFailure, TeamGroupFields, TeamHostFields, TeamLoginFields, TeamOperationKind,
    TeamPolicyFields, TeamRouteReference, TeamSimplePermission, TeamSimpleRuleInput,
    TeamSimpleRuleResource,
};

use super::*;

pub(super) async fn create_team(
    manager: &PersonalServer,
    store: &Arc<Store>,
    name: &str,
) -> TeamSummary {
    let prepared = manager.prepare_team_creation(store, name.into()).expect("retain team creation");
    let confirmed = manager
        .submit_team_creation(store.clone(), &prepared.operation_id)
        .await
        .expect("create a real team through HTTPS");
    manager
        .discard_team_creation(store, &prepared.operation_id)
        .expect("dismiss confirmed team creation");
    confirmed.organization.expect("verified new team")
}

pub(super) async fn join_team(
    owner: &PersonalServer,
    owner_store: &Arc<Store>,
    member: &PersonalServer,
    member_store: &Arc<Store>,
    organization: &str,
    username: &str,
) {
    let prepared = owner
        .prepare_team_invitation(owner_store, organization, username.into(), vec!["member".into()])
        .expect("prepare a named invitation");
    let invitation = owner
        .submit_team_operation(
            owner_store.clone(),
            TeamOperationKind::Invitation,
            &prepared.operation_id,
        )
        .await
        .expect("issue the named invitation through HTTPS");
    let link = invitation.link.as_deref().expect("public invitation locator");
    let preview = member
        .preview_team_invitation(member_store.clone(), link)
        .await
        .expect("preview as the designated Account");
    let password = owner
        .team_invitation_password(owner_store, &invitation.operation_id)
        .expect("read the separate invitation password explicitly");
    let acceptance = member
        .prepare_team_acceptance(member_store.clone(), link, &preview.etag, password)
        .await
        .expect("retain the designated Account acceptance");
    member
        .submit_team_operation(
            member_store.clone(),
            TeamOperationKind::Acceptance,
            &acceptance.operation_id,
        )
        .await
        .expect("join through the public acceptance API");
    member
        .discard_team_operation(
            member_store,
            TeamOperationKind::Acceptance,
            &acceptance.operation_id,
        )
        .expect("dismiss confirmed acceptance");
    owner
        .discard_team_operation(
            owner_store,
            TeamOperationKind::Invitation,
            &invitation.operation_id,
        )
        .expect("dismiss confirmed invitation");
}

pub(super) async fn create_resource(
    manager: &PersonalServer,
    store: &Arc<Store>,
    organization: &str,
    data: Data,
) -> TeamAuthoringResourceView {
    let prepared = manager
        .prepare_team_authoring(store, organization, data)
        .expect("retain the original typed resource create");
    let confirmed = manager
        .submit_team_authoring(store.clone(), organization, &prepared.operation_id)
        .await
        .expect("create the actual resource through HTTPS");
    assert_eq!(confirmed.phase, TeamAuthoringCreatePhase::Confirmed);
    manager
        .discard_team_authoring(store, organization, &prepared.operation_id)
        .expect("dismiss the original confirmed create");
    let collection = match confirmed.data {
        Data::Host(_) => Collection::Host,
        Data::Login(_) => Collection::Login,
        Data::Group(_) => Collection::Group,
        Data::Policy(_) => Collection::Policy,
        _ => panic!("this acceptance creates only Hosts, Logins, Groups and Policies"),
    };
    manager
        .team_authoring_resource(store.clone(), organization, collection, &prepared.resource_id)
        .await
        .expect("capture the actual persisted resource and strong ETag")
}

fn host_fields(name: &str) -> Data {
    Data::Host(TeamHostFields {
        name: Some(name.into()),
        address: "inventory.example.test".into(),
        ..Default::default()
    })
}

fn rule(
    manager: &PersonalServer,
    store: &Store,
    organization: &str,
    group: &str,
    permission: TeamSimplePermission,
    resources: Vec<TeamSimpleRuleResource>,
) -> Data {
    let remote_user =
        matches!(permission, TeamSimplePermission::Connect).then(|| "operator".into());
    let preview = manager
        .preview_team_simple_rule(
            store,
            organization,
            TeamSimpleRuleInput {
                membership_id: None,
                group_id: Some(group.into()),
                permission,
                resources,
                remote_user,
            },
        )
        .expect("preview the shared ordinary rule generator");
    Data::Policy(TeamPolicyFields {
        name: "Selected team access".into(),
        source: preview.source,
        enabled: true,
    })
}

fn selected(collection: Collection, id: &str) -> TeamSimpleRuleResource {
    TeamSimpleRuleResource { collection, id: id.into() }
}

async fn member_view(
    manager: &PersonalServer,
    store: &Arc<Store>,
    organization: &str,
    expected: &[(&str, &str)],
) -> TeamAssetsView {
    let view = manager
        .refresh_team_assets(store.clone(), organization)
        .await
        .expect("refresh and acknowledge a complete current team view");
    assert_eq!(view.organization_id, organization);
    assert_eq!(view.phase, TeamAssetsPhase::Ready);
    assert!(view.acknowledged && view.revision.is_some() && view.vault_id.is_some());
    let actual: BTreeSet<_> =
        view.assets.iter().map(|asset| (asset.id.as_str(), asset.kind.as_str())).collect();
    assert_eq!(actual, expected.iter().copied().collect());
    view
}

async fn roundtrip(deployment: PasswordDeployment, directory: &Path) {
    let ca = bounded_file(&deployment.ca_certificate, 65_536);
    let owner_device = Device::new(&directory.join("owner"));
    let member_device = Device::new(&directory.join("member"));
    let owner = manager(&ca);
    let member = manager(&ca);
    let suffix = scoplen_model::new_uuid_v7().expect("fresh disposable usernames");
    let owner_name = format!("inventory-owner-{suffix}");
    let member_name = format!("inventory-member-{suffix}");
    let owner_lease = register(
        &owner_device,
        &owner,
        &deployment.origin,
        &owner_name,
        SecretVec::new(b"Disposable inventory owner password".to_vec()),
        &directory.join("owner-recovery.txt"),
    )
    .await;
    let member_lease = register(
        &member_device,
        &member,
        &deployment.origin,
        &member_name,
        SecretVec::new(b"Disposable inventory member password".to_vec()),
        &directory.join("member-recovery.txt"),
    )
    .await;
    assert_ne!(
        owner_lease.account().unwrap().account_id,
        member_lease.account().unwrap().account_id,
    );
    let owner_store = owner_device.store(&owner_lease);
    let member_store = member_device.store(&member_lease);
    let personal = PersonalInventorySettings::default();
    let owner_host = host(&owner_store, "Owner Personal Host");
    let member_host = host(&member_store, "Member Personal Host");
    for (manager, store, object) in
        [(&owner, &owner_store, &owner_host), (&member, &member_store, &member_host)]
    {
        let preview =
            personal.preview(store, vec![object.id.to_string()]).expect("review Personal upload");
        personal
            .synchronize(manager, store.clone(), preview.token)
            .await
            .expect("publish encrypted Personal Host");
    }
    let owner_host =
        owner_store.get(owner_host.id).unwrap().expect("published owner Personal Host");
    let member_host =
        member_store.get(member_host.id).unwrap().expect("published member Personal Host");
    let owner_personal = serde_json::to_value(personal.status(&owner_store).unwrap()).unwrap();
    let member_personal = serde_json::to_value(personal.status(&member_store).unwrap()).unwrap();

    let team = create_team(&owner, &owner_store, "Inventory acceptance").await;
    let foreign = create_team(&owner, &owner_store, "Independent inventory boundary").await;
    join_team(&owner, &owner_store, &member, &member_store, &team.id, &member_name).await;
    let membership =
        member.team_settings(member_store.clone(), &team.id).await.expect("current own membership");
    member_view(&member, &member_store, &team.id, &[]).await;

    let destination =
        create_resource(&owner, &owner_store, &team.id, host_fields("Permitted Host")).await;
    let hidden =
        create_resource(&owner, &owner_store, &team.id, host_fields("Unselected Host")).await;
    let login = create_resource(
        &owner,
        &owner_store,
        &team.id,
        Data::Login(TeamLoginFields {
            host: destination.id.clone(),
            name: Some("Operator Login".into()),
            username: "operator".into(),
            route: Some(TeamRouteReference::Direct(0)),
            terminal_profile: None,
            startup_command: None,
            agent_forwarding: None,
        }),
    )
    .await;
    let group = create_resource(
        &owner,
        &owner_store,
        &team.id,
        Data::Group(TeamGroupFields {
            name: "Inventory operators".into(),
            members: vec![membership.membership_id.clone()],
        }),
    )
    .await;
    let view_policy = create_resource(
        &owner,
        &owner_store,
        &team.id,
        rule(
            &owner,
            &owner_store,
            &team.id,
            &group.id,
            TeamSimplePermission::View,
            vec![
                selected(Collection::Host, &destination.id),
                selected(Collection::Login, &login.id),
            ],
        ),
    )
    .await;
    let connect_policy = create_resource(
        &owner,
        &owner_store,
        &team.id,
        rule(
            &owner,
            &owner_store,
            &team.id,
            &group.id,
            TeamSimplePermission::Connect,
            vec![selected(Collection::Host, &destination.id)],
        ),
    )
    .await;
    let visible = [(destination.id.as_str(), "Host"), (login.id.as_str(), "AccessProfile")];
    let view = member_view(&member, &member_store, &team.id, &visible).await;
    assert!(view.assets.iter().all(|asset| asset.id != hidden.id));
    assert!(
        view.assets
            .iter()
            .any(|asset| asset.id == destination.id
                && asset.name.as_deref() == Some("Permitted Host"))
    );
    assert!(matches!(
        member
            .update_team_authoring(
                member_store.clone(),
                &team.id,
                &destination.id,
                &destination.etag,
                host_fields("Member edit")
            )
            .await,
        Err(TeamError::Personal(PersonalServerError::PermissionDenied)),
    ));
    assert!(matches!(
        owner
            .team_authoring_resource(
                owner_store.clone(),
                &foreign.id,
                Collection::Host,
                &destination.id
            )
            .await,
        Err(TeamError::Team(TeamFailure::TeamNotFound)),
    ));
    assert!(matches!(
        member
            .team_authoring_resource(
                member_store.clone(),
                &foreign.id,
                Collection::Host,
                &destination.id
            )
            .await,
        Err(TeamError::Team(TeamFailure::TeamNotFound)),
    ));

    let updated = owner
        .update_team_authoring(
            owner_store.clone(),
            &team.id,
            &destination.id,
            &destination.etag,
            host_fields("Updated permitted Host"),
        )
        .await
        .expect("replace the actual Host using its captured ETag");
    assert_ne!(updated.etag, destination.etag);
    assert!(matches!(
        owner
            .update_team_authoring(
                owner_store.clone(),
                &team.id,
                &destination.id,
                &destination.etag,
                host_fields("Stale replacement")
            )
            .await,
        Err(TeamError::Team(TeamFailure::AuthoringConflict)),
    ));
    let view = member_view(&member, &member_store, &team.id, &visible).await;
    assert!(view.assets.iter().any(|asset| asset.id == destination.id
        && asset.name.as_deref() == Some("Updated permitted Host")));

    let empty_group = owner
        .update_team_authoring(
            owner_store.clone(),
            &team.id,
            &group.id,
            &group.etag,
            Data::Group(TeamGroupFields { name: "Inventory operators".into(), members: vec![] }),
        )
        .await
        .expect("remove the member from the local access group");
    member_view(&member, &member_store, &team.id, &[]).await;
    owner
        .update_team_authoring(
            owner_store.clone(),
            &team.id,
            &group.id,
            &empty_group.etag,
            Data::Group(TeamGroupFields {
                name: "Inventory operators".into(),
                members: vec![membership.membership_id],
            }),
        )
        .await
        .expect("restore the reviewed group membership");
    member_view(&member, &member_store, &team.id, &visible).await;
    owner
        .delete_team_authoring(
            owner_store.clone(),
            &team.id,
            Collection::Policy,
            &view_policy.id,
            &view_policy.etag,
        )
        .await
        .expect("delete only the view grant through its captured ETag");
    member_view(&member, &member_store, &team.id, &[]).await;
    let retained = owner
        .team_authoring_resource(
            owner_store.clone(),
            &team.id,
            Collection::Policy,
            &connect_policy.id,
        )
        .await
        .expect("the independent connect rule remains persisted");
    assert!(matches!(retained.data, Data::Policy(TeamPolicyFields { enabled: true, .. })));

    for (manager, store, original, before) in [
        (&owner, &owner_store, &owner_host, &owner_personal),
        (&member, &member_store, &member_host, &member_personal),
    ] {
        assert_eq!(serde_json::to_value(personal.status(store).unwrap()).unwrap(), *before);
        assert_eq!(store.get(original.id).unwrap().as_ref(), Some(original));
        assert!(store.get(destination.id.parse().unwrap()).unwrap().is_none());
        assert!(store.get(login.id.parse().unwrap()).unwrap().is_none());
        assert_eq!(
            store.list(ObjectType::HOST).unwrap().as_slice(),
            std::slice::from_ref(original)
        );
        assert!(manager.load_sync_bootstrap(store).unwrap().is_some());
    }
}

#[tokio::test]
async fn live_team_inventory_authoring_and_access_withdrawal() {
    let artifact = std::env::var_os("SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT")
        .expect("set a private disposable HTTPS descriptor");
    let bytes = Zeroizing::new(bounded_file(Path::new(&artifact), 8_192));
    let deployment: PasswordDeployment =
        serde_json::from_slice(&bytes).expect("valid private descriptor");
    assert!(deployment.disposable, "use a disposable deployment");
    assert!(
        deployment
            .origin
            .strip_prefix("https://localhost:")
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|port| port != 0),
        "live mutations require loopback HTTPS",
    );
    let directory = OwnedDirectory::new();
    roundtrip(deployment, directory.path()).await;
    directory.close();
}
