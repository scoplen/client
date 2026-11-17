// SPDX-License-Identifier: Apache-2.0
//! Independent cold-Store consumption of an existing Host Grant through real SSH/SFTP.

use crate::{
    connection::SessionTarget,
    personal_server::{
        TeamAuthoringCollection as Collection, TeamAuthoringData as Data, TeamCreationPhase,
        TeamRouteReference, TeamSshError, TeamSshOperationKind, TeamSshSource,
    },
};

use super::{
    team_ssh::{SshFixture, terminal_and_files},
    *,
};

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedOutcome {
    SshSftp,
    IssuanceDenied,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantTeamDeployment {
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
    expected_outcome: ExpectedOutcome,
    #[serde(deserialize_with = "required_cutoff")]
    certificate_not_after: Option<u64>,
}

fn required_cutoff<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    let cutoff = Option::<u64>::deserialize(deserializer)?;
    if cutoff.is_some_and(|value| value > 253_402_300_799) {
        return Err(serde::de::Error::custom("certificate cutoff exceeds the UTC second limit"));
    }
    Ok(cutoff)
}

async fn consume(deployment: GrantTeamDeployment, ssh: SshFixture, directory: &Path) {
    ssh.verify().await;
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
        .expect("read the existing prepared Host");
    let Data::Host(host) = host.data else { panic!("expected the prepared Host") };
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
        .expect("read the existing prepared Login");
    let Data::Login(profile) = profile.data else { panic!("expected the prepared Login") };
    assert_eq!(profile.host, deployment.host_id);
    assert_eq!(profile.username, "smoke");
    assert!(matches!(profile.route, Some(TeamRouteReference::Direct(0))));

    owner.refresh_team_assets(owner_store.clone(), &deployment.organization_id).await.unwrap();
    let visible = member
        .refresh_team_assets(member_store.clone(), &deployment.organization_id)
        .await
        .expect("the prepared member can view the Host without implicit connect authority");
    assert!(visible.acknowledged);
    assert!(visible.assets.iter().any(|asset| asset.id == deployment.host_id));
    assert!(visible.assets.iter().any(|asset| asset.id == deployment.profile_id));
    let source = |store: &Store| TeamSshSource {
        origin: deployment.origin.clone(),
        account_id: record(store).unwrap().account_id.to_string(),
        organization_id: deployment.organization_id.clone(),
        device_id: store.device_id().to_string(),
    };
    let trust = owner
        .team_user_ca(owner_store.clone(), &source(&owner_store))
        .await
        .expect("read the existing authenticated user CA")
        .expect("the fixture must provision its user CA before client consumption");
    let setup = trust
        .setups
        .iter()
        .find(|setup| setup.profile_id == deployment.profile_id)
        .expect("the existing CA setup names the prepared Login");
    assert_eq!(setup.host_id, deployment.host_id);
    assert_eq!(setup.remote_user, "smoke");
    assert_eq!(
        setup.principal,
        format!("spl:{}:h:{}:smoke", deployment.organization_id, deployment.host_id)
    );
    let member_source = source(&member_store);
    let member_trust = member
        .team_user_ca(member_store.clone(), &member_source)
        .await
        .expect("the prepared member can read the authenticated user CA")
        .expect("the prepared member reads the existing user CA");
    assert_eq!(member_trust.id, trust.id);
    assert_eq!(member_trust.public_key, trust.public_key);
    match deployment.expected_outcome {
        ExpectedOutcome::IssuanceDenied => {
            assert!(member.team_ssh_operations(&member_store, &member_source).unwrap().is_empty());
            assert!(matches!(
                member
                    .team_ssh_certificate(
                        member_store.clone(),
                        &member_source,
                        deployment.host_id.parse().unwrap(),
                        "smoke",
                    )
                    .await,
                Err(TeamSshError::Personal(PersonalServerError::PermissionDenied)),
            ));
            let operations = member.team_ssh_operations(&member_store, &member_source).unwrap();
            let [attempt] = operations.as_slice() else {
                panic!("the denied certificate request must retain its exact original operation")
            };
            assert_eq!(attempt.kind, TeamSshOperationKind::Certificate);
            assert_eq!(attempt.source, member_source);
            assert_eq!(attempt.host_id.as_deref(), Some(deployment.host_id.as_str()));
            assert_eq!(attempt.remote_user.as_deref(), Some("smoke"));
            assert_eq!(attempt.phase, TeamCreationPhase::Prepared);
            assert!(
                attempt.retry_until.is_some(),
                "the certificate POST must have been dispatched"
            );
        }
        ExpectedOutcome::SshSftp => {
            ssh.install(&trust.public_key, &setup.principal).await;
            let target = SessionTarget::Organization {
                source: member_source.clone(),
                profile_id: deployment.profile_id,
            };
            terminal_and_files(&member, member_store.clone(), &target, directory).await;
            let cached = member
                .team_ssh_certificate(
                    member_store,
                    &member_source,
                    deployment.host_id.parse().unwrap(),
                    "smoke",
                )
                .await
                .expect("inspect the certificate obtained by the real terminal");
            assert!(cached.cached, "the terminal must have obtained the inspected certificate");
            assert!(
                cached.certificate.certificate().valid_before()
                    <= deployment.certificate_not_after.unwrap(),
                "the signed certificate must expire no later than its effective Host Grant",
            );
        }
    }
}

#[tokio::test]
async fn live_host_grant_ssh_and_sftp() {
    let artifact = std::env::var_os("SCOPLEN_LIVE_HOST_GRANT_DEPLOYMENT")
        .expect("provide the private Host Grant consumer descriptor");
    let deployment: GrantTeamDeployment =
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
    match deployment.expected_outcome {
        ExpectedOutcome::SshSftp => assert!(deployment.certificate_not_after.is_some()),
        ExpectedOutcome::IssuanceDenied => assert!(deployment.certificate_not_after.is_none()),
    }
    let artifact = std::env::var_os("SCOPLEN_LIVE_TEAM_SSH_FIXTURE")
        .expect("provide the owned OpenSSH fixture descriptor");
    let ssh: SshFixture =
        serde_json::from_slice(&bounded_file(Path::new(&artifact), 8192)).unwrap();
    let directory = OwnedDirectory::new();
    consume(deployment, ssh, directory.path()).await;
    directory.close();
}

#[test]
fn grant_handoff_requires_exact_fields_and_a_bounded_explicit_cutoff() {
    let original = serde_json::json!({
        "disposable": true,
        "origin": "https://localhost:8443",
        "ca_certificate": "/fixture/ca.pem",
        "organization_id": "01900000-0000-7000-8000-000000000001",
        "host_id": "01900000-0000-7000-8000-000000000002",
        "profile_id": "01900000-0000-7000-8000-000000000003",
        "owner_username": "fixture-owner",
        "owner_password_file": "/fixture/owner-password",
        "member_username": "fixture-member",
        "member_password_file": "/fixture/member-password",
        "expected_outcome": "issuance_denied",
        "certificate_not_after": null,
    });
    assert!(serde_json::from_value::<GrantTeamDeployment>(original.clone()).is_ok());
    let mut absent = original.clone();
    absent.as_object_mut().unwrap().remove("certificate_not_after");
    assert!(serde_json::from_value::<GrantTeamDeployment>(absent).is_err());
    let mut extended = original.clone();
    extended["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<GrantTeamDeployment>(extended).is_err());
    for invalid in [
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!(253_402_300_800_u64),
        serde_json::json!("253402300799"),
    ] {
        let mut descriptor = original.clone();
        descriptor["certificate_not_after"] = invalid;
        assert!(serde_json::from_value::<GrantTeamDeployment>(descriptor).is_err());
    }
    let mut allowed = original;
    allowed["expected_outcome"] = serde_json::json!("ssh_sftp");
    allowed["certificate_not_after"] = serde_json::json!(253_402_300_799_u64);
    assert!(serde_json::from_value::<GrantTeamDeployment>(allowed).is_ok());
}
