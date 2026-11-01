// SPDX-License-Identifier: Apache-2.0
//! Named membership lifecycle through public HTTPS using fresh independently registered Accounts.

use crate::personal_server::{TeamFailure, TeamOperationKind, TeamOperationView};
use scoplen_crypto::{DpopProof, DpopTarget, DpopToken};

use super::*;

async fn create_team(manager: &PersonalServer, store: &Arc<Store>, name: &str) -> TeamSummary {
    let operation = manager.prepare_team_creation(store, name.into()).expect("retain creation");
    let result = manager
        .submit_team_creation(store.clone(), &operation.operation_id)
        .await
        .expect("create through public HTTPS");
    manager
        .discard_team_creation(store, &operation.operation_id)
        .expect("dismiss confirmed creation");
    result.organization.expect("verified created team")
}

async fn invite(
    manager: &PersonalServer,
    store: &Arc<Store>,
    organization: &str,
    username: &str,
) -> TeamOperationView {
    let operation = manager
        .prepare_team_invitation(store, organization, username.into(), vec!["member".into()])
        .expect("protect original named invitation");
    let confirmed = manager
        .submit_team_operation(
            store.clone(),
            TeamOperationKind::Invitation,
            &operation.operation_id,
        )
        .await
        .expect("issue named invitation through public HTTPS");
    assert_eq!(confirmed.phase, TeamCreationPhase::Confirmed);
    confirmed
}

async fn prepare_acceptance(
    manager: &PersonalServer,
    store: &Arc<Store>,
    issuer: &PersonalServer,
    issuer_store: &Arc<Store>,
    invitation: &TeamOperationView,
) -> TeamOperationView {
    let link = invitation.link.as_deref().expect("public locator");
    let preview = manager
        .preview_team_invitation(store.clone(), link)
        .await
        .expect("authorized named recipient preview");
    assert_eq!(preview.organization_id, invitation.organization_id);
    let password = issuer
        .team_invitation_password(issuer_store, &invitation.operation_id)
        .expect("explicit local password read");
    manager
        .prepare_team_acceptance(store.clone(), link, &preview.etag, password)
        .await
        .expect("protect original acceptance")
}

/// Discard only the delivered success projection, modelling loss before local confirmation.
async fn send_without_confirmation(
    manager: &PersonalServer,
    store: &Arc<Store>,
    operation: &TeamOperationView,
) {
    let identity = record(store).expect("captured real Account");
    let kind = match operation.kind {
        TeamOperationKind::Invitation => 0,
        TeamOperationKind::Acceptance => 1,
        TeamOperationKind::Dissolution => 2,
    };
    let pending =
        store.team_operation(&identity, kind).unwrap().expect("protected original operation");
    let access =
        store.personal_access_token(now().unwrap()).unwrap().expect("current real Device token");
    let token = std::str::from_utf8(access.as_bytes()).unwrap();
    let path = match operation.kind {
        TeamOperationKind::Invitation => {
            format!("/api/v1/orgs/{}/invitations", pending.organization_id)
        }
        TeamOperationKind::Acceptance => format!(
            "/api/v1/orgs/{}/invitations/{}/accept",
            pending.organization_id,
            pending.invitation_id.unwrap()
        ),
        TeamOperationKind::Dissolution => {
            format!("/api/v1/orgs/{}/dissolve", pending.organization_id)
        }
    };
    let secrets = identity::Secrets::parse(&identity.private_material).unwrap();
    let signing = P256SigningKey::from_bytes(secrets.signing()).unwrap();
    let proof = DpopProof::sign(
        &signing,
        &signing.public_key_sec1(),
        &DpopTarget::new("POST", &identity.origin, &path).unwrap(),
        DpopToken::Protected(token),
        now().unwrap(),
        None,
    )
    .unwrap();
    assert!(
        store
            .dispatch_team_operation(
                &identity,
                &pending,
                &access,
                scoplen_model::system_time_millis().unwrap()
            )
            .unwrap()
    );
    let response = manager
        .transport
        .as_ref()
        .unwrap()
        .team_exchange(
            &identity.origin,
            &path,
            reqwest::Method::POST,
            Some(pending.payload.as_bytes()),
            token,
            &proof,
            Some(pending.operation_id),
            pending.etag.as_deref(),
            4096,
        )
        .await
        .expect("real public HTTPS mutation");
    assert_eq!(
        response.status,
        if operation.kind == TeamOperationKind::Invitation { 201 } else { 200 }
    );
    assert_eq!(
        manager
            .pending_team_operations(store)
            .unwrap()
            .into_iter()
            .find(|view| view.operation_id == operation.operation_id)
            .unwrap()
            .phase,
        TeamCreationPhase::Unknown
    );
}

async fn roundtrip(deployment: PasswordDeployment, directory: &Path) {
    let ca = bounded_file(&deployment.ca_certificate, 65_536);
    let owner_device = Device::new(&directory.join("owner"));
    let recipient_device = Device::new(&directory.join("recipient"));
    let owner = manager(&ca);
    let recipient = manager(&ca);
    let suffix = scoplen_model::new_uuid_v7().unwrap();
    let owner_name = format!("team-owner-{suffix}");
    let recipient_name = format!("team-recipient-{suffix}");
    let owner_lease = register(
        &owner_device,
        &owner,
        &deployment.origin,
        &owner_name,
        SecretVec::new(b"Disposable team owner password".to_vec()),
        &directory.join("owner-recovery.txt"),
    )
    .await;
    let recipient_lease = register(
        &recipient_device,
        &recipient,
        &deployment.origin,
        &recipient_name,
        SecretVec::new(b"Disposable team recipient password".to_vec()),
        &directory.join("recipient-recovery.txt"),
    )
    .await;
    let owner_store = owner_device.store(&owner_lease);
    let recipient_store = recipient_device.store(&recipient_lease);
    let owner_identity = record(&owner_store).unwrap();
    let recipient_identity = record(&recipient_store).unwrap();
    let owner_keys = owner.load_sync_bootstrap(&owner_store).unwrap().unwrap();
    let recipient_keys = recipient.load_sync_bootstrap(&recipient_store).unwrap().unwrap();
    let team = create_team(&owner, &owner_store, "Membership lifecycle").await;
    let other = create_team(&owner, &owner_store, "Owner independent team").await;
    let personal_team =
        create_team(&recipient, &recipient_store, "Recipient independent team").await;

    let invitation = owner
        .prepare_team_invitation(
            &owner_store,
            &team.id,
            recipient_name.clone(),
            vec!["member".into()],
        )
        .unwrap();
    send_without_confirmation(&owner, &owner_store, &invitation).await;
    let invitation = owner
        .submit_team_operation(
            owner_store.clone(),
            TeamOperationKind::Invitation,
            &invitation.operation_id,
        )
        .await
        .expect("confirm same original invitation");
    let acceptance =
        prepare_acceptance(&recipient, &recipient_store, &owner, &owner_store, &invitation).await;
    recipient
        .submit_team_operation(
            recipient_store.clone(),
            TeamOperationKind::Acceptance,
            &acceptance.operation_id,
        )
        .await
        .expect("accept as fixed Account");
    recipient
        .discard_team_operation(
            &recipient_store,
            TeamOperationKind::Acceptance,
            &acceptance.operation_id,
        )
        .unwrap();
    owner
        .discard_team_operation(
            &owner_store,
            TeamOperationKind::Invitation,
            &invitation.operation_id,
        )
        .unwrap();
    assert_eq!(recipient.teams_page(recipient_store.clone(), None).await.unwrap().teams.len(), 2);
    assert_eq!(
        recipient.team_members(recipient_store.clone(), &team.id, None).await,
        Err(PersonalServerError::PermissionDenied.into())
    );
    let members = owner.team_members(owner_store.clone(), &team.id, None).await.unwrap();
    let member =
        members.items.into_iter().find(|member| member.username == recipient_name).unwrap();
    assert_eq!(
        owner
            .update_team_member(
                owner_store.clone(),
                &other.id,
                &member.id,
                &member.etag,
                vec!["member".into()],
                "active"
            )
            .await,
        Err(TeamFailure::TeamNotFound.into())
    );
    let suspended = owner
        .update_team_member(
            owner_store.clone(),
            &team.id,
            &member.id,
            &member.etag,
            vec!["approver".into(), "member".into()],
            "suspended",
        )
        .await
        .expect("suspend through current Cedar authority");
    assert_eq!(
        owner.remove_team_member(owner_store.clone(), &team.id, &member.id, &member.etag).await,
        Err(TeamFailure::MembershipConflict.into())
    );
    assert!(
        recipient
            .teams_page(recipient_store.clone(), None)
            .await
            .unwrap()
            .teams
            .iter()
            .all(|value| value.id != team.id)
    );
    owner
        .update_team_member(
            owner_store.clone(),
            &team.id,
            &member.id,
            &suspended.etag,
            vec!["member".into()],
            "active",
        )
        .await
        .expect("restore suspended member through reviewed update");
    let settings = recipient.team_settings(recipient_store.clone(), &team.id).await.unwrap();
    recipient
        .remove_team_member(
            recipient_store.clone(),
            &team.id,
            &settings.membership_id,
            &settings.etag,
        )
        .await
        .expect("active self-leave through captured own projection");

    let invitation = invite(&owner, &owner_store, &team.id, &recipient_name).await;
    let acceptance =
        prepare_acceptance(&recipient, &recipient_store, &owner, &owner_store, &invitation).await;
    send_without_confirmation(&recipient, &recipient_store, &acceptance).await;
    let members = owner.team_members(owner_store.clone(), &team.id, None).await.unwrap();
    let member =
        members.items.into_iter().find(|member| member.username == recipient_name).unwrap();
    owner
        .remove_team_member(owner_store.clone(), &team.id, &member.id, &member.etag)
        .await
        .expect("remove before recipient can confirm historical receipt");
    recipient
        .submit_team_operation(
            recipient_store.clone(),
            TeamOperationKind::Acceptance,
            &acceptance.operation_id,
        )
        .await
        .expect("historical receipt after removal");
    assert!(
        recipient
            .teams_page(recipient_store.clone(), None)
            .await
            .unwrap()
            .teams
            .iter()
            .all(|value| value.id != team.id)
    );
    recipient
        .discard_team_operation(
            &recipient_store,
            TeamOperationKind::Acceptance,
            &acceptance.operation_id,
        )
        .unwrap();
    owner
        .discard_team_operation(
            &owner_store,
            TeamOperationKind::Invitation,
            &invitation.operation_id,
        )
        .unwrap();

    let revoked = invite(&owner, &owner_store, &team.id, &recipient_name).await;
    let invitations = owner.team_invitations(owner_store.clone(), &team.id, None).await.unwrap();
    let item = invitations
        .items
        .into_iter()
        .find(|item| Some(&item.id) == revoked.invitation_id.as_ref())
        .unwrap();
    owner
        .revoke_team_invitation(owner_store.clone(), &team.id, &item.id, &item.etag)
        .await
        .expect("revoke reviewed pending invitation");
    owner
        .discard_team_operation(&owner_store, TeamOperationKind::Invitation, &revoked.operation_id)
        .unwrap();
    assert_eq!(
        recipient
            .preview_team_invitation(recipient_store.clone(), revoked.link.as_deref().unwrap())
            .await
            .unwrap()
            .status,
        "revoked"
    );
    let invitation = invite(&owner, &owner_store, &team.id, &recipient_name).await;
    let acceptance =
        prepare_acceptance(&recipient, &recipient_store, &owner, &owner_store, &invitation).await;
    recipient
        .submit_team_operation(
            recipient_store.clone(),
            TeamOperationKind::Acceptance,
            &acceptance.operation_id,
        )
        .await
        .unwrap();
    let settings = owner.team_settings(owner_store.clone(), &team.id).await.unwrap();
    let dissolution =
        owner.prepare_team_dissolution(&owner_store, &team.id, &settings.etag).unwrap();
    send_without_confirmation(&owner, &owner_store, &dissolution).await;
    owner
        .submit_team_operation(
            owner_store.clone(),
            TeamOperationKind::Dissolution,
            &dissolution.operation_id,
        )
        .await
        .expect("confirm dissolution after active Owner was revoked");
    assert_eq!(owner.teams_page(owner_store.clone(), None).await.unwrap().teams, [other]);
    assert_eq!(
        recipient.teams_page(recipient_store.clone(), None).await.unwrap().teams,
        [personal_team]
    );
    assert!(record(&owner_store).unwrap().private_material == owner_identity.private_material);
    assert!(
        record(&recipient_store).unwrap().private_material == recipient_identity.private_material
    );
    assert!(
        owner.load_sync_bootstrap(&owner_store).unwrap().unwrap().personal_vault_key().as_bytes()
            == owner_keys.personal_vault_key().as_bytes()
    );
    assert!(
        recipient
            .load_sync_bootstrap(&recipient_store)
            .unwrap()
            .unwrap()
            .personal_vault_key()
            .as_bytes()
            == recipient_keys.personal_vault_key().as_bytes()
    );
}

#[tokio::test]
async fn live_named_team_membership_lifecycle() {
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
        "live mutations require loopback HTTPS"
    );
    let directory = OwnedDirectory::new();
    roundtrip(deployment, directory.path()).await;
    directory.close();
}
