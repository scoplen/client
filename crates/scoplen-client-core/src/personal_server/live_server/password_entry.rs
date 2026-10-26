// SPDX-License-Identifier: Apache-2.0
//! Fresh registration and independent password sign-in against an external disposable server.

use crate::{
    local_data::{LocalData, Status},
    profiles::{AccountProfiles, ProfileLease},
};

use super::*;

mod isolation;
mod teams;

const LOCAL_PASSPHRASE: &str = "Disposable local data passphrase";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordDeployment {
    disposable: bool,
    origin: String,
    ca_certificate: PathBuf,
}

struct OwnedDirectory(Option<tempfile::TempDir>);

impl OwnedDirectory {
    fn new() -> Self {
        Self(Some(
            tempfile::Builder::new()
                .prefix("scoplen-password-live-")
                .tempdir()
                .expect("create independent disposable client stores"),
        ))
    }

    fn path(&self) -> &Path {
        self.0.as_ref().expect("owned directory remains available").path()
    }

    fn close(mut self) {
        self.0
            .take()
            .expect("owned successful fixture")
            .close()
            .expect("remove successful fixture");
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        if let Some(directory) = self.0.take() {
            // Failed public integration retains its encrypted stores and exact pending state.
            let _ = directory.keep();
        }
    }
}

struct Device {
    local: Arc<LocalData>,
    profiles: AccountProfiles,
}

impl Device {
    fn new(directory: &Path) -> Self {
        let local = Arc::new(LocalData::start(directory, None).expect("independent Local store"));
        assert!(matches!(local.create(LOCAL_PASSPHRASE), Ok(Status::Open { .. })));
        let profiles = AccountProfiles::with_keystores(
            local.clone(),
            Arc::new(PersonalSyncRuntime::default()),
            Arc::new(|_| None),
        )
        .expect("independent passphrase-protected Account catalog");
        Self { local, profiles }
    }

    fn store(&self, lease: &ProfileLease) -> Arc<Store> {
        self.profiles.with_current_store(lease, Arc::clone).expect("current captured namespace")
    }
}

fn local_passphrase() -> Option<SecretVec> {
    Some(SecretVec::new(LOCAL_PASSPHRASE.as_bytes().to_vec()))
}

fn host(store: &Store, name: &str) -> scoplen_model::Object {
    store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text(name.into())),
                (FieldPath::Field(2), Value::Text("host.example.com".into())),
            ],
        })
        .expect("write an ordinary local Host")
}

fn manager(ca: &[u8]) -> PersonalServer {
    PersonalServer { operation: Mutex::new(()), transport: Ok(trusted_transport(ca)) }
}

async fn register(
    device: &Device,
    manager: &PersonalServer,
    origin: &str,
    username: &str,
    password: SecretVec,
    recovery_path: &Path,
) -> ProfileLease {
    let source = device.profiles.current().expect("initial Local context");
    let store = device.store(&source);
    let prepared = manager
        .prepare_registration(&device.local, &store, origin, username, "First device", password)
        .expect("prepare real password registration");
    manager
        .save_registration_recovery(&device.local, &store, prepared.operation_id, recovery_path)
        .expect("save the generated recovery key to an owned private file");
    manager
        .confirm_registration_recovery(&device.local, &store, prepared.operation_id)
        .expect("explicitly confirm recovery custody");
    let committed = manager
        .exchange_registration(
            &device.local,
            store,
            prepared.operation_id,
            RegistrationAction::Submit,
            &RegistrationCancellation::default(),
        )
        .await
        .expect("create a fresh Account through public registration HTTP");
    assert_eq!(committed.phase, RegistrationPhase::Committed);
    manager
        .install_registration_profile(
            &device.profiles,
            &source,
            prepared.operation_id,
            local_passphrase(),
            &RegistrationCancellation::default(),
        )
        .await
        .expect("authenticate and install the original Device through public APIs")
}

async fn sign_in(
    device: &Device,
    manager: &PersonalServer,
    origin: &str,
    username: &str,
    password: SecretVec,
) -> ProfileLease {
    let source = device.profiles.current().expect("independent Local context");
    assert_eq!(
        manager
            .begin_password_login(
                &device.profiles,
                &source,
                origin,
                username,
                "Second device",
                SecretVec::new(b"Incorrect disposable account password".to_vec()),
                &RegistrationCancellation::default(),
            )
            .await
            .expect_err("wrong password must fail through the public server"),
        PasswordLoginError::AuthenticationDenied,
    );
    assert!(device.profiles.list().expect("unchanged Local catalog").is_empty());
    // The first admitted denial carries the contract's one-second cooldown.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let ready = manager
        .begin_password_login(
            &device.profiles,
            &source,
            origin,
            username,
            "Second device",
            password,
            &RegistrationCancellation::default(),
        )
        .await
        .expect("recover the existing Account using only its username and password");
    assert_eq!(ready.phase, PasswordLoginPhase::Ready);
    let committed = manager
        .exchange_password_login(
            &device.profiles,
            &source,
            ready.operation_id,
            RegistrationAction::Submit,
            &RegistrationCancellation::default(),
        )
        .await
        .expect("admit a fresh Device through public HTTP");
    assert_eq!(committed.phase, PasswordLoginPhase::Committed);
    manager
        .install_password_login_profile(
            &device.profiles,
            &source,
            ready.operation_id,
            local_passphrase(),
            &RegistrationCancellation::default(),
        )
        .await
        .expect("authenticate and install the independently admitted Device")
}

async fn roundtrip(deployment: PasswordDeployment, directory: &Path) {
    let ca = bounded_file(&deployment.ca_certificate, 65_536);
    let first = Device::new(&directory.join("first"));
    let second = Device::new(&directory.join("second"));
    let first_manager = manager(&ca);
    let second_manager = manager(&ca);
    let first_root = first.local.store().expect("first Local store");
    let second_root = second.local.store().expect("second Local store");
    let first_local = host(&first_root, "First device Local-only Host");
    let second_local = host(&second_root, "Second device Local-only Host");
    let suffix = scoplen_model::new_uuid_v7().expect("unique disposable identity");
    let username = format!("live-{}", suffix.simple());
    let password = SecretVec::new(format!("Disposable Account {suffix}").into_bytes());
    let first_lease = register(
        &first,
        &first_manager,
        &deployment.origin,
        &username,
        password.clone(),
        &directory.join("recovery.txt"),
    )
    .await;
    let first_profile = first_lease.account().expect("installed Account metadata").clone();
    let first_store = first.store(&first_lease);
    assert!(first_store.get(first_local.id).expect("separate Account namespace").is_none());
    let shared = host(&first_store, "Host created before second-device sign-in");
    let settings = PersonalInventorySettings::default();
    let preview =
        settings.preview(&first_store, vec![shared.id.to_string()]).expect("review upload");
    assert!(preview.missing.is_empty() && preview.token.is_some());
    let uploaded = settings
        .synchronize(&first_manager, first_store.clone(), preview.token)
        .await
        .expect("publish the original Device's signed encrypted Host");
    assert_eq!(uploaded.uploaded, 1);

    let second_lease =
        sign_in(&second, &second_manager, &deployment.origin, &username, password).await;
    let second_profile = second_lease.account().expect("second Account metadata").clone();
    assert_eq!(second_profile.account_id, first_profile.account_id);
    assert_eq!(second_profile.personal_vault_id, first_profile.personal_vault_id);
    assert_ne!(second_profile.device_id, first_profile.device_id);
    let second_store = second.store(&second_lease);
    assert!(second_store.get(second_local.id).expect("separate Account namespace").is_none());
    let created_teams =
        teams::verify_pair(&first_manager, &first_store, &second_manager, &second_store).await;
    let original = rotate_live_session(
        &first_manager,
        &first_store,
        "rotate the original registration Device session",
        2,
    )
    .await;
    let restored = rotate_live_session(
        &second_manager,
        &second_store,
        "rotate the independently admitted Device session",
        2,
    )
    .await;
    assert_eq!(original.account_id, restored.account_id);
    assert_eq!(original.devices.len(), 2);
    assert_eq!(restored.devices.len(), 2);
    settings
        .synchronize(&second_manager, second_store.clone(), None)
        .await
        .expect("independent Device downloads and decrypts existing Host data");
    assert_eq!(
        second_store.get(shared.id).expect("decrypted synchronized Host"),
        Some(shared.clone())
    );
    let edited = second_store
        .write(LocalWrite {
            id: Some(shared.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("Host edited on second device".into()))],
        })
        .expect("edit the downloaded Host through the ordinary local intent");
    settings
        .synchronize(&second_manager, second_store.clone(), None)
        .await
        .expect("upload the second Device's signed edit");
    settings
        .synchronize(&first_manager, first_store.clone(), None)
        .await
        .expect("original Device verifies and decrypts the second Device's edit");
    assert_eq!(
        first_store.get(shared.id).expect("bidirectional synchronized Host"),
        Some(edited.clone())
    );
    let foreign_host = isolation::verify(
        &deployment,
        directory,
        &ca,
        &first_manager,
        &first_store,
        &edited,
        &created_teams,
    )
    .await;
    settings
        .synchronize(&second_manager, second_store.clone(), None)
        .await
        .expect("the other original Account Device remains usable after foreign reads");
    for store in [&first_store, &second_store] {
        let progress = settings.status(store).expect("durable synchronized progress");
        assert_eq!(progress.pending, 0);
        assert_eq!(progress.applied_cursor, progress.acknowledged_cursor);
        assert_ne!(progress.applied_cursor, "0");
        assert!(store.get(first_local.id).expect("Local remains separate").is_none());
        assert!(store.get(second_local.id).expect("Local remains separate").is_none());
        assert!(store.get(foreign_host.id).expect("foreign Account Host stays separate").is_none());
        assert_eq!(
            store.get(shared.id).expect("own Account Host stays intact"),
            Some(edited.clone())
        );
    }
    assert_eq!(first_root.get(first_local.id).expect("original Local Host"), Some(first_local));
    assert_eq!(second_root.get(second_local.id).expect("original Local Host"), Some(second_local));
    drop(second_lease);
    drop(second_store);
    second.profiles.open_local().expect("return to the preserved Local store");
    let reopened =
        second.profiles.open(second_profile.id, local_passphrase()).expect("reopen Account");
    let reopened_store = second.store(&reopened);
    let offline = PersonalServer::default();
    assert!(offline.load_sync_bootstrap(&reopened_store).expect("offline verified keys").is_some());
    assert_eq!(reopened_store.get(shared.id).expect("offline reopened Host"), Some(edited));
    teams::verify_reopened(&second_manager, &reopened_store, &created_teams).await;
}

#[tokio::test]
async fn live_password_registration_and_independent_device_sync() {
    let artifact = std::env::var_os("SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT")
        .expect("set SCOPLEN_LIVE_ACCOUNT_DEPLOYMENT to a private disposable HTTPS descriptor");
    let bytes = Zeroizing::new(bounded_file(Path::new(&artifact), 8_192));
    let deployment: PasswordDeployment =
        serde_json::from_slice(&bytes).expect("valid private descriptor");
    assert!(deployment.disposable, "use an independent disposable deployment");
    assert!(
        deployment
            .origin
            .strip_prefix("https://localhost:")
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|port| port != 0),
        "this live mutation check requires loopback HTTPS",
    );
    let directory = OwnedDirectory::new();
    roundtrip(deployment, directory.path()).await;
    directory.close();
}
