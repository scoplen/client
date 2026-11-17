// SPDX-License-Identifier: Apache-2.0
//! Native-authored CSV/OpenSSH batches, real member view/ACK and actual SSH/SFTP.

use super::{
    team_inventory::{create_resource, create_team, join_team},
    team_ssh::{SshFixture, provision_user_ca, terminal_and_files},
    *,
};
use crate::{
    connection::SessionTarget,
    personal_server::{
        TeamAuthoringCollection as Collection, TeamAuthoringData as Data, TeamImportCandidate,
        TeamImportError, TeamImportPhase, TeamImportSource, TeamPolicyFields, TeamRouteReference,
        TeamSimplePermission, TeamSimpleRuleInput, TeamSimpleRuleResource, TeamSshSource,
    },
};

async fn roundtrip(deployment: PasswordDeployment, ssh: SshFixture, directory: &Path) {
    ssh.verify().await;
    let ca = bounded_file(&deployment.ca_certificate, 65_536);
    let owner_device = Device::new(&directory.join("owner"));
    let member_device = Device::new(&directory.join("member"));
    let mut owner = manager(&ca);
    let member = manager(&ca);
    let suffix = scoplen_model::new_uuid_v7().unwrap();
    let mut owner_lease = register(
        &owner_device,
        &owner,
        &deployment.origin,
        &format!("import-owner-{suffix}"),
        SecretVec::new(b"Disposable import owner password".to_vec()),
        &directory.join("owner-recovery.txt"),
    )
    .await;
    let member_name = format!("import-member-{suffix}");
    let member_lease = register(
        &member_device,
        &member,
        &deployment.origin,
        &member_name,
        SecretVec::new(b"Disposable import member password".to_vec()),
        &directory.join("member-recovery.txt"),
    )
    .await;
    let owner_profile = owner_lease.account().unwrap().id;
    let mut owner_store = owner_device.store(&owner_lease);
    let member_store = member_device.store(&member_lease);
    let personal = host(&member_store, "Independent Personal Host");
    let team = create_team(&owner, &owner_store, "Native CSV and OpenSSH import acceptance").await;
    join_team(&owner, &owner_store, &member, &member_store, &team.id, &member_name).await;
    let membership = member.team_settings(member_store.clone(), &team.id).await.unwrap();
    let mut rows = Vec::new();
    for source in [TeamImportSource::Csv, TeamImportSource::OpenSsh] {
        let (name, text) = match source {
            TeamImportSource::Csv => (
                "Native CSV",
                format!(
                    "name,address,port,username,login_name\nNative CSV,127.0.0.1,{},smoke,CSV default\nNot selected,unselected.example,22,ops,\n",
                    ssh.port
                ),
            ),
            TeamImportSource::OpenSsh => (
                "native-openssh",
                format!(
                    "Host native-openssh\n HostName 127.0.0.1\n User smoke\n Port {}\nHost blocked\n User smoke\n ProxyCommand must-not-run\n",
                    ssh.port
                ),
            ),
        };
        let path = directory.join(format!("{name}.source"));
        std::fs::write(&path, text).unwrap();
        let preview = owner
            .preview_team_inventory_import_file(&owner_store, &team.id, source, &path)
            .expect("native read and published parser");
        assert_eq!(preview.candidates.len(), 2);
        if source == TeamImportSource::OpenSsh {
            assert!(matches!(
                preview.candidates[1],
                TeamImportCandidate::Blocked { ordinal: 2, .. }
            ));
        }
        let reviewed = owner
            .prepare_team_inventory_import(&owner_store, &team.id, &preview.preview_id, vec![1])
            .expect("explicit Ready subset");
        assert_eq!(reviewed.rows.len(), 1);
        assert_eq!(reviewed.rows[0].fields.name, name);
        assert!(rows.iter().all(|row: &crate::personal_server::TeamImportRow| row.host_id
            != reviewed.rows[0].host_id
            && row.login_id != reviewed.rows[0].login_id));
        owner
            .transport
            .as_ref()
            .unwrap()
            .discard_next_import_reply
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            matches!(
                owner
                    .submit_team_inventory_import(
                        owner_store.clone(),
                        &team.id,
                        &reviewed.operation_id
                    )
                    .await,
                Err(TeamImportError::Unknown)
            ),
            "test-only discard follows a complete real HTTPS 201"
        );
        assert!(
            !owner
                .transport
                .as_ref()
                .unwrap()
                .discard_next_import_reply
                .load(std::sync::atomic::Ordering::SeqCst)
        );
        assert_eq!(
            owner.pending_team_inventory_import(&owner_store, &team.id).unwrap().unwrap().phase,
            TeamImportPhase::Unknown
        );
        drop(owner_store);
        drop(owner_lease);
        drop(owner);
        owner_device.profiles.open_local().expect("close the Account runtime and store");
        owner_lease = owner_device
            .profiles
            .open(owner_profile, local_passphrase())
            .expect("reopen original Account with a new runtime owner");
        owner_store = owner_device.store(&owner_lease);
        owner = manager(&ca);
        let retained =
            owner.pending_team_inventory_import(&owner_store, &team.id).unwrap().unwrap();
        assert_eq!(retained.phase, TeamImportPhase::Unknown);
        assert_eq!(retained.operation_id, reviewed.operation_id);
        assert_eq!(retained.rows[0].host_id, reviewed.rows[0].host_id);
        assert_eq!(retained.rows[0].login_id, reviewed.rows[0].login_id);
        assert_eq!(retained.rows[0].fields, reviewed.rows[0].fields);
        let confirmed = owner
            .submit_team_inventory_import(owner_store.clone(), &team.id, &reviewed.operation_id)
            .await
            .expect("explicitly confirm original key/body against the production receipt");
        assert_eq!(confirmed.phase, TeamImportPhase::Confirmed);
        let row = confirmed.rows.into_iter().next().unwrap();
        let host = owner
            .team_authoring_resource(owner_store.clone(), &team.id, Collection::Host, &row.host_id)
            .await
            .unwrap();
        let Data::Host(host) = host.data else { panic!("imported Host") };
        assert_eq!(host.address, "127.0.0.1");
        assert_eq!(host.port, Some(ssh.port));
        assert_eq!(host.default_profile.as_deref(), Some(row.login_id.as_str()));
        let login = owner
            .team_authoring_resource(
                owner_store.clone(),
                &team.id,
                Collection::Login,
                &row.login_id,
            )
            .await
            .unwrap();
        let Data::Login(login) = login.data else { panic!("imported default Login") };
        assert_eq!(login.host, row.host_id);
        assert_eq!(login.username, "smoke");
        assert!(matches!(login.route, Some(TeamRouteReference::Direct(0))));
        let review = owner
            .review_team_inventory_import(owner_store.clone(), &team.id, &reviewed.operation_id)
            .await
            .unwrap();
        assert!(review.error.is_none());
        let inventory = review.inventory.unwrap();
        assert!(inventory.acknowledged);
        assert_eq!(
            inventory
                .assets
                .iter()
                .filter(|asset| matches!(asset.kind.as_str(), "Host" | "AccessProfile"))
                .count(),
            (rows.len() + 1) * 2,
            "full view contains only selected Host/default-Login pairs"
        );
        assert!(inventory.assets.iter().all(|asset| asset.name.as_deref() != Some("Not selected")
            && asset.address.as_deref() != Some("unselected.example")));
        assert_eq!(review.pending.phase, TeamImportPhase::Confirmed);
        owner
            .discard_team_inventory_import(&owner_store, &team.id, &reviewed.operation_id)
            .unwrap();
        rows.push(row);
    }
    let hidden = member.refresh_team_assets(member_store.clone(), &team.id).await.unwrap();
    assert!(hidden.acknowledged && hidden.assets.is_empty(), "import grants no member visibility");
    let mut policies = Vec::new();
    for permission in [TeamSimplePermission::View, TeamSimplePermission::Connect] {
        let resources = rows
            .iter()
            .flat_map(|row| {
                let mut resources = vec![TeamSimpleRuleResource {
                    collection: Collection::Host,
                    id: row.host_id.clone(),
                }];
                if matches!(permission, TeamSimplePermission::View) {
                    resources.push(TeamSimpleRuleResource {
                        collection: Collection::Login,
                        id: row.login_id.clone(),
                    });
                }
                resources
            })
            .collect();
        let rule = owner
            .preview_team_simple_rule(
                &owner_store,
                &team.id,
                TeamSimpleRuleInput {
                    membership_id: Some(membership.membership_id.clone()),
                    group_id: None,
                    permission,
                    resources,
                    remote_user: matches!(permission, TeamSimplePermission::Connect)
                        .then(|| "smoke".into()),
                },
            )
            .unwrap();
        policies.push(
            create_resource(
                &owner,
                &owner_store,
                &team.id,
                Data::Policy(TeamPolicyFields {
                    name: "Explicit native import acceptance access".into(),
                    source: rule.source,
                    enabled: true,
                }),
            )
            .await,
        );
    }
    owner.refresh_team_assets(owner_store.clone(), &team.id).await.unwrap();
    let visible = member.refresh_team_assets(member_store.clone(), &team.id).await.unwrap();
    assert!(visible.acknowledged);
    for row in &rows {
        assert!(visible.assets.iter().any(|asset| asset.id == row.host_id));
        assert!(visible.assets.iter().any(|asset| asset.id == row.login_id));
    }
    let source = |store: &Store| TeamSshSource {
        origin: deployment.origin.clone(),
        account_id: record(store).unwrap().account_id.to_string(),
        device_id: store.device_id().to_string(),
        organization_id: team.id.clone(),
    };
    let trust = provision_user_ca(&owner, &owner_store, &source(&owner_store)).await;
    for row in &rows {
        let setup = trust.setups.iter().find(|setup| setup.profile_id == row.login_id).unwrap();
        assert_eq!(setup.host_id, row.host_id);
        assert_eq!(setup.principal, format!("spl:{}:h:{}:smoke", team.id, row.host_id));
        ssh.install(&trust.public_key, &setup.principal).await;
        let target = SessionTarget::Organization {
            source: source(&member_store),
            profile_id: row.login_id.clone(),
        };
        terminal_and_files(&member, member_store.clone(), &target, directory).await;
    }
    for policy in policies {
        owner
            .delete_team_authoring(
                owner_store.clone(),
                &team.id,
                Collection::Policy,
                &policy.id,
                &policy.etag,
            )
            .await
            .unwrap();
    }
    let withdrawn = member.refresh_team_assets(member_store.clone(), &team.id).await.unwrap();
    assert!(withdrawn.acknowledged && withdrawn.assets.is_empty());
    for row in rows {
        assert!(
            member
                .team_ssh_certificate(
                    member_store.clone(),
                    &source(&member_store),
                    row.host_id.parse().unwrap(),
                    "smoke"
                )
                .await
                .is_err()
        );
        assert!(member_store.get(row.host_id.parse().unwrap()).unwrap().is_none());
    }
    assert_eq!(member_store.get(personal.id).unwrap().as_ref(), Some(&personal));
}

#[tokio::test]
async fn live_native_team_inventory_import_ssh_and_sftp() {
    let artifact = std::env::var_os("SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT")
        .expect("provide a disposable HTTPS descriptor");
    let deployment: PasswordDeployment =
        serde_json::from_slice(&bounded_file(Path::new(&artifact), 8192)).unwrap();
    assert!(
        deployment.disposable
            && deployment
                .origin
                .strip_prefix("https://localhost:")
                .and_then(|port| port.parse::<u16>().ok())
                .is_some_and(|port| port != 0)
    );
    let artifact = std::env::var_os("SCOPLEN_LIVE_TEAM_SSH_FIXTURE")
        .expect("provide an owned OpenSSH fixture descriptor");
    let ssh: SshFixture =
        serde_json::from_slice(&bounded_file(Path::new(&artifact), 8192)).unwrap();
    let directory = OwnedDirectory::new();
    roundtrip(deployment, ssh, directory.path()).await;
    directory.close();
}
