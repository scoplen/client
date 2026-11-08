// SPDX-License-Identifier: Apache-2.0
//! Password-admitted Devices use a reviewed, synchronized generated key through real SSH/SFTP.

use crate::{
    connection::SessionTarget,
    inventory::{Inventory, NewHost, SignIn},
    personal_inventory::PersonalInventoryCategory,
    repository::{Repository, TrustRecord},
};

use super::{
    team_ssh::{SshFixture, terminal_and_files_with_trust},
    *,
};

async fn install_public_key(ssh: &SshFixture, public_key: &str) {
    ssh.verify().await;
    assert!(public_key.starts_with("ssh-ed25519 "));
    assert!(!public_key.contains(['\r', '\n']));
    let setup = r#"set -eu
home=$(getent passwd smoke | cut -d: -f6)
test -n "$home"
test -f /config/sshd/sshd_config
mkdir -p "$home/.ssh"
printf '%s\n' "$1" > "$home/.ssh/scoplen_personal_authorized_keys"
chown "smoke:$(id -gn smoke)" "$home/.ssh" "$home/.ssh/scoplen_personal_authorized_keys"
chmod 700 "$home/.ssh"
chmod 600 "$home/.ssh/scoplen_personal_authorized_keys"
sed -i '/^[[:space:]]*TrustedUserCAKeys[[:space:]]/d; /^[[:space:]]*AuthorizedPrincipalsFile[[:space:]]/d; /^[[:space:]]*AuthorizedKeysFile[[:space:]]/d; /^[[:space:]]*PasswordAuthentication[[:space:]]/d; /^[[:space:]]*KbdInteractiveAuthentication[[:space:]]/d' /config/sshd/sshd_config
printf '\nAuthorizedKeysFile .ssh/scoplen_personal_authorized_keys\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' >> /config/sshd/sshd_config
/usr/sbin/sshd.pam -t -f /config/sshd/sshd_config
effective=$(/usr/sbin/sshd.pam -T -f /config/sshd/sshd_config)
printf '%s\n' "$effective" | grep -Fx 'pubkeyauthentication yes'
printf '%s\n' "$effective" | grep -Fx 'authorizedkeysfile .ssh/scoplen_personal_authorized_keys'
printf '%s\n' "$effective" | grep -Fx 'trustedusercakeys none'
printf '%s\n' "$effective" | grep -Fx 'passwordauthentication no'
printf '%s\n' "$effective" | grep -Fx 'kbdinteractiveauthentication no'
pkill -HUP -o sshd
"#;
    ssh.docker(&["exec", &ssh.container, "sh", "-c", setup, "sh", public_key]).await;
}

async fn roundtrip(deployment: PasswordDeployment, ssh: SshFixture, directory: &Path) {
    let ca = bounded_file(&deployment.ca_certificate, 65_536);
    let first = Device::new(&directory.join("first"));
    let first_manager = manager(&ca);
    let suffix = uuid::Uuid::now_v7();
    let username = format!("personal-key-{}", suffix.simple());
    let password = SecretVec::new(format!("Disposable Personal SSH {suffix}").into_bytes());
    let first_lease = register(
        &first,
        &first_manager,
        &deployment.origin,
        &username,
        password.clone(),
        &directory.join("recovery.txt"),
    )
    .await;
    let first_profile = first_lease.account().unwrap().clone();
    let first_store = first.store(&first_lease);
    let details = Inventory::new(first_store.clone())
        .add_host(NewHost {
            name: Some("Synchronized generated-key SSH".into()),
            address: "127.0.0.1".into(),
            port: Some(ssh.port),
            username: "smoke".into(),
            sign_in: SignIn::GenerateKey,
        })
        .expect("generate and save the ordinary Host, Login and shared software Credential");
    let host: uuid::Uuid = details.summary.id.parse().unwrap();
    let profile = details.logins[0].id.clone();
    let credential = details.logins[0].credential.as_ref().unwrap();
    let credential_id: uuid::Uuid = credential.id.parse().unwrap();
    let public_key = credential.public_key.as_deref().expect("generated public key projection");
    install_public_key(&ssh, public_key).await;
    let target = SessionTarget::Personal { profile_id: profile };
    terminal_and_files_with_trust(&first_manager, first_store.clone(), &target, directory, 1).await;
    let trust = Repository::<TrustRecord>::new(&first_store)
        .list()
        .unwrap()
        .into_iter()
        .find(|trust| trust.host == Some(host))
        .expect("ordinary host-key confirmation persists its source");
    assert_eq!(trust.accepted_by_device, Some(first_profile.device_id));
    assert_eq!(trust.accepted_by_account, Some(first_profile.account_id));
    let ids = [host, target.profile_id().parse().unwrap(), credential_id, trust.meta.id];
    let originals = ids.map(|id| first_store.get(id).unwrap().unwrap());
    let settings = PersonalInventorySettings::default();
    let before = settings.status(&first_store).unwrap();
    assert!(before.objects.iter().all(|object| !object.personal && !object.dirty));
    let incomplete = settings.preview(&first_store, vec![target.profile_id().into()]).unwrap();
    assert!(incomplete.token.is_none() && !incomplete.missing.is_empty());
    let preview = settings
        .preview(&first_store, ids.map(|id| id.to_string()).to_vec())
        .expect("explicitly review the exact Host, Login, Credential and ordinary trust");
    assert!(preview.missing.is_empty());
    assert_eq!(preview.objects.len(), 4);
    let secret = preview.objects.iter().find(|object| object.id == credential.id).unwrap();
    assert_eq!(secret.category, PersonalInventoryCategory::Credential);
    assert!(secret.shared_secret, "upload consent must disclose the generated private key");
    assert_eq!(preview.objects.iter().filter(|object| object.shared_secret).count(), 1);
    let result = settings
        .synchronize(&first_manager, first_store.clone(), preview.token)
        .await
        .expect("explicit consent uploads the signed encrypted objects");
    assert_eq!(result.uploaded, 4);
    drop(first_store);
    drop(first_lease);
    drop(first);
    drop(first_manager);

    let second = Device::new(&directory.join("second"));
    let second_manager = manager(&ca);
    let second_lease =
        sign_in(&second, &second_manager, &deployment.origin, &username, password).await;
    let second_profile = second_lease.account().unwrap().clone();
    assert_eq!(second_profile.account_id, first_profile.account_id);
    assert_eq!(second_profile.personal_vault_id, first_profile.personal_vault_id);
    assert_ne!(second_profile.device_id, first_profile.device_id);
    let second_store = second.store(&second_lease);
    let runtime = &second.runtime;
    let owner = runtime.run(&second_manager);
    tokio::pin!(owner);
    let scenario = async {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let progress = settings.status(&second_store).unwrap();
                if originals
                    .iter()
                    .all(|object| second_store.get(object.id).unwrap().as_ref() == Some(object))
                    && progress.pending == 0
                    && progress.applied_cursor != "0"
                    && progress.applied_cursor == progress.acknowledged_cursor
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("password installation starts background download without Verify keys or Sync now");
        let downloaded =
            Inventory::new(second_store.clone()).host(details.summary.id.clone()).unwrap().unwrap();
        assert_eq!(
            downloaded.logins[0].credential.as_ref().unwrap().public_key.as_deref(),
            Some(public_key)
        );
        terminal_and_files_with_trust(&second_manager, second_store.clone(), &target, directory, 0)
            .await;
        runtime.shutdown();
    };
    tokio::select! {
        _ = &mut owner => panic!("background owner ended before explicit shutdown"),
        () = scenario => {},
    }
    tokio::time::timeout(Duration::from_secs(5), owner).await.expect("background owner stops");
    drop(second_store);
    drop(second_lease);
    second.profiles.open_local().unwrap();
    let reopened = second.profiles.open(second_profile.id, local_passphrase()).unwrap();
    let reopened_store = second.store(&reopened);
    let offline = PersonalServer::default();
    assert!(offline.load_sync_bootstrap(&reopened_store).unwrap().is_some());
    for original in &originals {
        assert!(reopened_store.get(original.id).unwrap().as_ref() == Some(original));
    }
    terminal_and_files_with_trust(&offline, reopened_store, &target, directory, 0).await;
}

#[tokio::test]
async fn live_password_device_generated_key_sync_ssh_and_sftp() {
    let artifact = std::env::var_os("SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT")
        .expect("provide the private disposable HTTPS descriptor");
    let deployment: PasswordDeployment =
        serde_json::from_slice(&bounded_file(Path::new(&artifact), 8192)).unwrap();
    assert!(deployment.disposable && deployment.ca_certificate.is_absolute());
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
