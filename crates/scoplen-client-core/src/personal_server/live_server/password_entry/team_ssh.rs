// SPDX-License-Identifier: Apache-2.0
//! Public team enrollment, CA setup and real terminal-owned SSH/SFTP acceptance.

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::{process::Command, sync::mpsc};

use crate::{
    connection::{
        SessionTarget,
        preparation::{PreparationContext, PreparationEvent, PreparationResponse},
    },
    inventory::Inventory,
    personal_server::{
        TeamAuthoringCollection as Collection, TeamAuthoringData as Data, TeamHostFields,
        TeamLoginFields, TeamPolicyFields, TeamRouteReference, TeamSimplePermission,
        TeamSimpleRuleInput, TeamSimpleRuleResource, TeamSshError, TeamSshFailure,
        TeamSshOperationKind, TeamSshSource, TeamUserCaView,
    },
    session_files::{
        RemoteFileKind, SessionDownloadStatus, SessionFileMutationStatus, SessionUploadStatus,
    },
    session_manager::{SessionEvent, SessionManager},
};

use super::{
    team_inventory::{create_resource, create_team, join_team},
    *,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SshFixture {
    disposable: bool,
    pub(super) container: String,
    owner: String,
    pub(super) port: u16,
}

impl SshFixture {
    pub(super) async fn docker(&self, arguments: &[&str]) -> Vec<u8> {
        let output = tokio::time::timeout(
            Duration::from_secs(20),
            Command::new("docker").args(arguments).kill_on_drop(true).output(),
        )
        .await
        .expect("owned Docker operation exceeded its deadline")
        .expect("run the owned OpenSSH fixture command");
        assert!(output.status.success(), "owned OpenSSH fixture command failed");
        output.stdout
    }

    pub(super) async fn verify(&self) {
        assert!(self.disposable && self.port != 0);
        assert!(self.container.starts_with("scoplen-team-ssh-"));
        assert!(uuid::Uuid::parse_str(&self.owner).is_ok());
        let label = self
            .docker(&[
                "inspect",
                "--format",
                "{{index .Config.Labels \"com.scoplen.fixture\"}}",
                &self.container,
            ])
            .await;
        assert_eq!(String::from_utf8(label).unwrap().trim(), self.owner);
        let binding = self.docker(&["port", &self.container, "2222/tcp"]).await;
        assert_eq!(String::from_utf8(binding).unwrap().trim(), format!("127.0.0.1:{}", self.port));
    }

    pub(super) async fn install(&self, ca: &str, principal: &str) {
        self.verify().await;
        let setup = r#"set -eu
home=$(getent passwd smoke | cut -d: -f6)
test -n "$home"
test -f /config/sshd/sshd_config
mkdir -p "$home/.ssh"
printf '%s\n' "$1" > /etc/ssh/scoplen_user_ca_keys
printf '%s\n' "$2" > "$home/.ssh/scoplen_principals"
chown -R "smoke:$(id -gn smoke)" "$home/.ssh"
chmod 700 "$home/.ssh"
chmod 600 "$home/.ssh/scoplen_principals"
sed -i '/^[[:space:]]*TrustedUserCAKeys[[:space:]]/d; /^[[:space:]]*AuthorizedPrincipalsFile[[:space:]]/d; /^[[:space:]]*AuthorizedKeysFile[[:space:]]/d; /^[[:space:]]*PasswordAuthentication[[:space:]]/d; /^[[:space:]]*KbdInteractiveAuthentication[[:space:]]/d' /config/sshd/sshd_config
printf '\nTrustedUserCAKeys /etc/ssh/scoplen_user_ca_keys\nAuthorizedPrincipalsFile .ssh/scoplen_principals\nAuthorizedKeysFile none\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' >> /config/sshd/sshd_config
/usr/sbin/sshd.pam -t -f /config/sshd/sshd_config
effective=$(/usr/sbin/sshd.pam -T -f /config/sshd/sshd_config)
# sshd omits a disabled AuthorizedKeysFile list from its effective output.
if printf '%s\n' "$effective" | grep -q '^authorizedkeysfile '; then exit 1; fi
printf '%s\n' "$effective" | grep -Fx 'pubkeyauthentication yes'
printf '%s\n' "$effective" | grep -Fx 'trustedusercakeys /etc/ssh/scoplen_user_ca_keys'
printf '%s\n' "$effective" | grep -Fx 'authorizedprincipalsfile .ssh/scoplen_principals'
printf '%s\n' "$effective" | grep -Fx 'passwordauthentication no'
printf '%s\n' "$effective" | grep -Fx 'kbdinteractiveauthentication no'
pkill -HUP -o sshd
"#;
        self.docker(&["exec", &self.container, "sh", "-c", setup, "sh", ca, principal]).await;
    }
}

async fn wait_for_output(output: &mut mpsc::UnboundedReceiver<Vec<u8>>, marker: &[u8]) {
    let mut received = Vec::new();
    loop {
        received.extend(output.recv().await.expect("live shell output remains available"));
        assert!(received.len() <= 65_536, "unexpected disposable shell output volume");
        if received.windows(marker.len()).any(|window| window == marker) {
            return;
        }
    }
}

pub(super) async fn terminal_and_files(
    personal: &PersonalServer,
    store: Arc<Store>,
    target: &SessionTarget,
    directory: &Path,
) {
    terminal_and_files_with_trust(personal, store, target, directory, 1).await;
}

pub(super) async fn terminal_and_files_with_trust(
    personal: &PersonalServer,
    store: Arc<Store>,
    target: &SessionTarget,
    directory: &Path,
    expected_trust_prompts: usize,
) {
    let account = record(&store).unwrap().account_id;
    let device = store.device_id();
    let recent_before = Inventory::new(store.clone()).recent_sessions().unwrap().len();
    let sessions = SessionManager::default();
    let id = "team-ssh-acceptance";
    sessions.reserve(id, true).unwrap();
    let (ready_tx, mut ready_rx) = mpsc::unbounded_channel();
    let (output_tx, mut output_rx) = mpsc::unbounded_channel();
    let trusts = AtomicUsize::new(0);
    let validate = |context: &PreparationContext| {
        match target {
            SessionTarget::Organization { source, .. } => {
                assert_eq!(context.source.as_ref(), Some(source));
            }
            SessionTarget::Personal { .. } => {
                assert!(context.source.is_none());
                assert_eq!(record(&store).unwrap().account_id, account);
                assert_eq!(store.device_id(), device);
            }
        }
        assert_eq!(context.profile_id, target.profile_id());
    };
    let terminal = sessions.run_target(
        id,
        target,
        personal,
        None,
        true,
        store.clone(),
        |event| {
            match event {
                SessionEvent::Preparation { transport_id, event } => match *event {
                    PreparationEvent::Trust { prompt_id, context, .. } => {
                        validate(&context);
                        trusts.fetch_add(1, Ordering::SeqCst);
                        assert!(trusts.load(Ordering::SeqCst) <= expected_trust_prompts);
                        sessions.respond(
                            id,
                            &transport_id,
                            &prompt_id,
                            PreparationResponse::AcceptHostKey,
                        )?;
                    }
                    PreparationEvent::Verified { context, .. } => validate(&context),
                    _ => {}
                },
                SessionEvent::Ready { transport_id } => {
                    ready_tx.send(transport_id).map_err(|_| "readiness receiver closed")?;
                }
                SessionEvent::Failed { error, .. } => return Err(error),
                _ => {}
            }
            Ok(())
        },
        |_, bytes| output_tx.send(bytes).map_err(|_| "output receiver closed".into()),
        |_, _| {},
    );
    let exercise = async {
        let transport = ready_rx.recv().await.expect("real certificate-authenticated shell");
        sessions.input(id, &transport, b"printf '%s%s\\n' SCOPLEN- TEAM-READY\n".to_vec()).unwrap();
        wait_for_output(&mut output_rx, b"SCOPLEN-TEAM-READY").await;
        sessions.resize(id, &transport, 100, 30).unwrap();
        let original: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let filename = format!("team-upload-{}.bin", uuid::Uuid::now_v7());
        let source = directory.join(&filename);
        std::fs::write(&source, &original).unwrap();
        let uploaded = sessions
            .upload_file_with_picker(
                id,
                &transport,
                &uuid::Uuid::now_v7().to_string(),
                b".".to_vec(),
                || async { Ok(Some(source.clone())) },
                |_| async { Err("a fresh fixture file must not need replacement".into()) },
                |_| {},
            )
            .await
            .expect("upload through the same authenticated team connection");
        assert_eq!(uploaded.status, SessionUploadStatus::Saved);
        assert!(!uploaded.staging_may_remain);
        let listing = sessions
            .list_files(id, &transport, &uuid::Uuid::now_v7().to_string(), b".".to_vec())
            .await
            .expect("browse the same certificate-authenticated SFTP session");
        let remote = listing.entries.iter().find(|entry| entry.name == filename).unwrap();
        assert_eq!(remote.size_bytes.as_deref(), Some("4096"));
        let destination = directory.join(format!("downloaded-{filename}"));
        let downloaded = sessions
            .download_file_with_picker(
                id,
                &transport,
                &uuid::Uuid::now_v7().to_string(),
                remote.path.clone(),
                || async { Ok(Some(destination.clone())) },
                |_| {},
            )
            .await
            .expect("download the actual uploaded binary");
        assert_eq!(downloaded.status, SessionDownloadStatus::Saved);
        assert_eq!(std::fs::read(destination).unwrap(), original);
        let removed = sessions
            .delete_remote_entry_with_confirmation(
                id,
                &transport,
                &uuid::Uuid::now_v7().to_string(),
                b".".to_vec(),
                remote.path.clone(),
                |kind, name| async move {
                    assert_eq!(kind, RemoteFileKind::File);
                    assert_eq!(name, filename);
                    Ok(true)
                },
            )
            .await
            .expect("remove only the captured disposable upload");
        assert_eq!(removed.status, SessionFileMutationStatus::Saved);
        sessions.close(id).unwrap();
    };
    let (terminal, ()) =
        tokio::time::timeout(Duration::from_secs(120), async { tokio::join!(terminal, exercise) })
            .await
            .expect("bounded real team terminal and SFTP journey");
    terminal.expect("close the real team terminal");
    assert_eq!(trusts.load(Ordering::SeqCst), expected_trust_prompts);
    let recent = Inventory::new(store).recent_sessions().unwrap();
    assert_eq!(recent.len(), recent_before + 1);
    assert_eq!(&recent[0].target, target);
    assert!(recent[0].ended_at.is_some());
}

async fn provision_user_ca(
    personal: &PersonalServer,
    store: &Arc<Store>,
    source: &TeamSshSource,
) -> TeamUserCaView {
    assert!(personal.team_user_ca(store.clone(), source).await.unwrap().is_none());
    let prepared = personal.prepare_team_user_ca(store, source).unwrap();
    personal
        .confirm_team_ssh_operation(
            store.clone(),
            source,
            TeamSshOperationKind::UserCa,
            &prepared.operation_id,
        )
        .await
        .unwrap();
    personal
        .discard_team_ssh_operation(
            store,
            source,
            TeamSshOperationKind::UserCa,
            &prepared.operation_id,
        )
        .unwrap();
    personal.team_user_ca(store.clone(), source).await.unwrap().unwrap()
}

async fn roundtrip(deployment: PasswordDeployment, ssh: SshFixture, directory: &Path) {
    let ca = bounded_file(&deployment.ca_certificate, 65_536);
    let owner_device = Device::new(&directory.join("owner"));
    let member_device = Device::new(&directory.join("member"));
    let owner = manager(&ca);
    let member = manager(&ca);
    let suffix = scoplen_model::new_uuid_v7().unwrap();
    let owner_name = format!("ssh-owner-{suffix}");
    let member_name = format!("ssh-member-{suffix}");
    let owner_lease = register(
        &owner_device,
        &owner,
        &deployment.origin,
        &owner_name,
        SecretVec::new(b"Disposable SSH owner password".to_vec()),
        &directory.join("owner-recovery.txt"),
    )
    .await;
    let member_lease = register(
        &member_device,
        &member,
        &deployment.origin,
        &member_name,
        SecretVec::new(b"Disposable SSH member password".to_vec()),
        &directory.join("member-recovery.txt"),
    )
    .await;
    let owner_store = owner_device.store(&owner_lease);
    let member_store = member_device.store(&member_lease);
    let first_member_store = member_store.clone();
    let first_personal_host = host(&first_member_store, "First-device Personal Host");
    let team = create_team(&owner, &owner_store, "Real SSH acceptance").await;
    join_team(&owner, &owner_store, &member, &member_store, &team.id, &member_name).await;
    let membership = member.team_settings(member_store.clone(), &team.id).await.unwrap();
    let destination = create_resource(
        &owner,
        &owner_store,
        &team.id,
        Data::Host(TeamHostFields {
            name: Some("Disposable OpenSSH".into()),
            address: "127.0.0.1".into(),
            port: Some(ssh.port),
            ..Default::default()
        }),
    )
    .await;
    let login = create_resource(
        &owner,
        &owner_store,
        &team.id,
        Data::Login(TeamLoginFields {
            host: destination.id.clone(),
            name: Some("Certificate Login".into()),
            username: "smoke".into(),
            route: Some(TeamRouteReference::Direct(0)),
            terminal_profile: None,
            startup_command: None,
            agent_forwarding: None,
        }),
    )
    .await;
    let mut connect_policy = None;
    for permission in [TeamSimplePermission::View, TeamSimplePermission::Connect] {
        let resources = if matches!(permission, TeamSimplePermission::View) {
            vec![
                TeamSimpleRuleResource { collection: Collection::Host, id: destination.id.clone() },
                TeamSimpleRuleResource { collection: Collection::Login, id: login.id.clone() },
            ]
        } else {
            vec![TeamSimpleRuleResource {
                collection: Collection::Host,
                id: destination.id.clone(),
            }]
        };
        let preview = owner
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
        let policy = create_resource(
            &owner,
            &owner_store,
            &team.id,
            Data::Policy(TeamPolicyFields {
                name: "Explicit SSH acceptance permission".into(),
                source: preview.source,
                enabled: true,
            }),
        )
        .await;
        if matches!(permission, TeamSimplePermission::Connect) {
            connect_policy = Some(policy);
        }
    }
    let second_member_device = Device::new(&directory.join("member-second"));
    let member = manager(&ca);
    let second_member_lease = sign_in(
        &second_member_device,
        &member,
        &deployment.origin,
        &member_name,
        SecretVec::new(b"Disposable SSH member password".to_vec()),
    )
    .await;
    let member_store = second_member_device.store(&second_member_lease);
    assert_eq!(
        record(&member_store).unwrap().account_id,
        record(&first_member_store).unwrap().account_id,
    );
    assert_ne!(member_store.device_id(), first_member_store.device_id());
    let discovered = member.teams_page(member_store.clone(), None).await.unwrap();
    assert_eq!(discovered.teams.len(), 1);
    assert_eq!(discovered.teams[0].id, team.id);
    let personal_host = host(&member_store, "Second-device Personal Host");
    owner.refresh_team_assets(owner_store.clone(), &team.id).await.unwrap();
    member.refresh_team_assets(member_store.clone(), &team.id).await.unwrap();
    let source = |store: &Store| {
        let identity = record(store).unwrap();
        TeamSshSource {
            origin: deployment.origin.clone(),
            account_id: identity.account_id.to_string(),
            organization_id: team.id.clone(),
            device_id: store.device_id().to_string(),
        }
    };
    let owner_source = source(&owner_store);
    let member_source = source(&member_store);
    let trust = provision_user_ca(&owner, &owner_store, &owner_source).await;
    let setup = trust.setups.iter().find(|setup| setup.profile_id == login.id).unwrap();
    assert_eq!(setup.principal, format!("spl:{}:h:{}:smoke", team.id, destination.id));
    ssh.install(&trust.public_key, &setup.principal).await;
    let target =
        SessionTarget::Organization { source: member_source.clone(), profile_id: login.id.clone() };
    terminal_and_files(&member, member_store.clone(), &target, directory).await;
    let cached = member
        .team_ssh_certificate(
            member_store.clone(),
            &member_source,
            destination.id.parse().unwrap(),
            "smoke",
        )
        .await
        .unwrap();
    assert!(cached.cached);
    let owned_team = create_team(&member, &member_store, "Independent certificate Owner").await;
    let owned_host = create_resource(
        &member,
        &member_store,
        &owned_team.id,
        Data::Host(TeamHostFields {
            name: Some("Independent certificate Host".into()),
            address: "127.0.0.1".into(),
            port: Some(ssh.port),
            ..Default::default()
        }),
    )
    .await;
    let owned_login = create_resource(
        &member,
        &member_store,
        &owned_team.id,
        Data::Login(TeamLoginFields {
            host: owned_host.id.clone(),
            name: Some("Independent certificate Login".into()),
            username: "smoke".into(),
            route: Some(TeamRouteReference::Direct(0)),
            terminal_profile: None,
            startup_command: None,
            agent_forwarding: None,
        }),
    )
    .await;
    create_resource(
        &member,
        &member_store,
        &owned_team.id,
        Data::Policy(TeamPolicyFields {
            name: "Permit all within the independent team".into(),
            source: "permit(principal, action, resource);".into(),
            enabled: true,
        }),
    )
    .await;
    member.refresh_team_assets(member_store.clone(), &owned_team.id).await.unwrap();
    let owned_source =
        TeamSshSource { organization_id: owned_team.id.clone(), ..member_source.clone() };
    let owned_trust = provision_user_ca(&member, &member_store, &owned_source).await;
    assert_ne!(owned_trust.public_key, trust.public_key);
    let owned_setup =
        owned_trust.setups.iter().find(|setup| setup.profile_id == owned_login.id).unwrap();
    assert_eq!(owned_setup.host_id, owned_host.id);
    assert_eq!(owned_setup.principal, format!("spl:{}:h:{}:smoke", owned_team.id, owned_host.id));
    ssh.install(&owned_trust.public_key, &owned_setup.principal).await;
    let owned_target =
        SessionTarget::Organization { source: owned_source.clone(), profile_id: owned_login.id };
    terminal_and_files(&member, member_store.clone(), &owned_target, directory).await;
    let owned_cached = member
        .team_ssh_certificate(
            member_store.clone(),
            &owned_source,
            owned_host.id.parse().unwrap(),
            "smoke",
        )
        .await
        .expect("the independent team has a real usable certificate after normal Host-key review");
    assert!(owned_cached.cached);
    let owned_ca =
        ssh_key::PublicKey::from_openssh(&owned_trust.public_key).unwrap().to_bytes().unwrap();
    assert_eq!(owned_cached.certificate.certificate().ca_public_key_blob(), owned_ca.as_slice());
    assert_eq!(
        owned_cached.certificate.certificate().principals(),
        std::slice::from_ref(&owned_setup.principal)
    );
    assert_ne!(
        owned_cached.certificate.certificate().ca_public_key_blob(),
        cached.certificate.certificate().ca_public_key_blob()
    );
    cached.current(&member_store).expect("independent team setup preserves the Member certificate");
    assert!(matches!(
        member
            .team_ssh_certificate(
                member_store.clone(),
                &owned_source,
                destination.id.parse().unwrap(),
                "smoke"
            )
            .await,
        Err(TeamSshError::Ssh(TeamSshFailure::ViewRequired)),
    ));
    let connect = connect_policy.unwrap();
    owner
        .delete_team_authoring(
            owner_store.clone(),
            &team.id,
            Collection::Policy,
            &connect.id,
            &connect.etag,
        )
        .await
        .unwrap();
    member.refresh_team_assets(member_store.clone(), &team.id).await.unwrap();
    assert_eq!(
        cached.current(&member_store),
        Err(TeamSshError::Ssh(TeamSshFailure::AuthorityChanged))
    );
    assert!(matches!(
        member
            .team_ssh_certificate(
                member_store.clone(),
                &member_source,
                destination.id.parse().unwrap(),
                "smoke"
            )
            .await,
        Err(TeamSshError::Personal(PersonalServerError::PermissionDenied)),
    ));
    owned_cached.current(&member_store).expect("the independent Owner certificate remains current");
    assert!(
        member
            .team_ssh_certificate(
                member_store.clone(),
                &owned_source,
                owned_host.id.parse().unwrap(),
                "smoke"
            )
            .await
            .expect("the independent team's original certificate cache remains usable")
            .cached
    );
    terminal_and_files_with_trust(&member, member_store.clone(), &owned_target, directory, 0).await;
    assert_eq!(member_store.get(personal_host.id).unwrap().as_ref(), Some(&personal_host));
    assert_eq!(
        first_member_store.get(first_personal_host.id).unwrap().as_ref(),
        Some(&first_personal_host),
    );
    assert!(member_store.get(destination.id.parse().unwrap()).unwrap().is_none());
    assert!(member_store.get(owned_host.id.parse().unwrap()).unwrap().is_none());
}

#[tokio::test]
async fn live_team_ssh_and_sftp() {
    let artifact = std::env::var_os("SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT")
        .expect("provide a disposable HTTPS descriptor");
    let deployment: PasswordDeployment =
        serde_json::from_slice(&bounded_file(Path::new(&artifact), 8192)).unwrap();
    assert!(deployment.disposable);
    assert!(
        deployment
            .origin
            .strip_prefix("https://localhost:")
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|port| port != 0)
    );
    let artifact = std::env::var_os("SCOPLEN_LIVE_TEAM_SSH_FIXTURE")
        .expect("use scripts/test-live-team-ssh.ps1");
    let ssh: SshFixture =
        serde_json::from_slice(&bounded_file(Path::new(&artifact), 8192)).unwrap();
    let directory = OwnedDirectory::new();
    roundtrip(deployment, ssh, directory.path()).await;
    directory.close();
}
