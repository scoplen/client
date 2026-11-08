// SPDX-License-Identifier: Apache-2.0
//! Consume a real browser-authored team through the native Device and SSH surfaces.

use crate::{
    connection::SessionTarget,
    personal_server::{
        TeamAuthoringCollection as Collection, TeamAuthoringData as Data, TeamRouteReference,
        TeamSshOperationKind, TeamSshSource,
    },
};

use super::{
    team_ssh::{SshFixture, terminal_and_files},
    *,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserTeamDeployment {
    disposable: bool,
    origin: String,
    ca_certificate: PathBuf,
    organization_id: String,
    host_id: String,
    profile_id: String,
    owner_username: String,
    owner_password_file: PathBuf,
    member_username: String,
    member_password_file: PathBuf,
}

async fn roundtrip(deployment: BrowserTeamDeployment, ssh: SshFixture, directory: &Path) {
    let ca = bounded_file(&deployment.ca_certificate, 65_536);
    let owner_device = Device::new(&directory.join("owner"));
    let member_device = Device::new(&directory.join("member"));
    let owner = manager(&ca);
    let member = manager(&ca);
    let owner_lease = sign_in(
        &owner_device,
        &owner,
        &deployment.origin,
        &deployment.owner_username,
        SecretVec::new(bounded_file(&deployment.owner_password_file, 4096)),
    )
    .await;
    let member_lease = sign_in(
        &member_device,
        &member,
        &deployment.origin,
        &deployment.member_username,
        SecretVec::new(bounded_file(&deployment.member_password_file, 4096)),
    )
    .await;
    let owner_store = owner_device.store(&owner_lease);
    let member_store = member_device.store(&member_lease);
    assert_ne!(record(&owner_store).unwrap().account_id, record(&member_store).unwrap().account_id);

    let host = owner
        .team_authoring_resource(
            owner_store.clone(),
            &deployment.organization_id,
            Collection::Host,
            &deployment.host_id,
        )
        .await
        .unwrap();
    let Data::Host(host) = host.data else { panic!("expected the browser-authored Host") };
    assert_eq!(host.address, "127.0.0.1");
    assert_eq!(host.port, Some(ssh.port));
    assert_eq!(host.default_profile.as_deref(), Some(deployment.profile_id.as_str()));
    let profile = owner
        .team_authoring_resource(
            owner_store.clone(),
            &deployment.organization_id,
            Collection::Login,
            &deployment.profile_id,
        )
        .await
        .unwrap();
    let Data::Login(profile) = profile.data else { panic!("expected the browser-authored Login") };
    assert_eq!(profile.host, deployment.host_id);
    assert_eq!(profile.username, "smoke");
    assert!(matches!(profile.route, Some(TeamRouteReference::Direct(0))));

    owner.refresh_team_assets(owner_store.clone(), &deployment.organization_id).await.unwrap();
    let visible = member
        .refresh_team_assets(member_store.clone(), &deployment.organization_id)
        .await
        .unwrap();
    assert!(visible.acknowledged);
    assert!(visible.assets.iter().any(|asset| asset.id == deployment.host_id));
    assert!(visible.assets.iter().any(|asset| asset.id == deployment.profile_id));
    let source = |store: &Store| TeamSshSource {
        origin: deployment.origin.clone(),
        account_id: record(store).unwrap().account_id.to_string(),
        organization_id: deployment.organization_id.clone(),
        device_id: store.device_id().to_string(),
    };
    let owner_source = source(&owner_store);
    if owner.team_user_ca(owner_store.clone(), &owner_source).await.unwrap().is_none() {
        let prepared = owner.prepare_team_user_ca(&owner_store, &owner_source).unwrap();
        owner
            .confirm_team_ssh_operation(
                owner_store.clone(),
                &owner_source,
                TeamSshOperationKind::UserCa,
                &prepared.operation_id,
            )
            .await
            .unwrap();
        owner
            .discard_team_ssh_operation(
                &owner_store,
                &owner_source,
                TeamSshOperationKind::UserCa,
                &prepared.operation_id,
            )
            .unwrap();
    }
    let trust = owner.team_user_ca(owner_store.clone(), &owner_source).await.unwrap().unwrap();
    let setup =
        trust.setups.iter().find(|setup| setup.profile_id == deployment.profile_id).unwrap();
    assert_eq!(setup.host_id, deployment.host_id);
    assert_eq!(setup.remote_user, "smoke");
    assert_eq!(
        setup.principal,
        format!("spl:{}:h:{}:smoke", deployment.organization_id, deployment.host_id)
    );
    ssh.install(&trust.public_key, &setup.principal).await;
    let target = SessionTarget::Organization {
        source: source(&member_store),
        profile_id: deployment.profile_id,
    };
    terminal_and_files(&member, member_store, &target, directory).await;
}

#[tokio::test]
async fn live_browser_authored_team_ssh_and_sftp() {
    let artifact = std::env::var_os("SCOPLEN_LIVE_BROWSER_TEAM_DEPLOYMENT")
        .expect("provide the private browser-authored team descriptor");
    let deployment: BrowserTeamDeployment =
        serde_json::from_slice(&bounded_file(Path::new(&artifact), 8192)).unwrap();
    assert!(deployment.disposable);
    assert!(
        deployment.ca_certificate.is_absolute()
            && deployment.owner_password_file.is_absolute()
            && deployment.member_password_file.is_absolute()
    );
    assert!(
        deployment
            .origin
            .strip_prefix("https://localhost:")
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|port| port != 0)
    );
    let artifact = std::env::var_os("SCOPLEN_LIVE_TEAM_SSH_FIXTURE")
        .expect("provide the owned OpenSSH fixture descriptor");
    let ssh: SshFixture =
        serde_json::from_slice(&bounded_file(Path::new(&artifact), 8192)).unwrap();
    let directory = OwnedDirectory::new();
    roundtrip(deployment, ssh, directory.path()).await;
    directory.close();
}
