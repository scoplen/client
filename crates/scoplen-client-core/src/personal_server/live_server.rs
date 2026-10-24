// SPDX-License-Identifier: Apache-2.0
//! Explicit opt-in checks against a disposable deployment, without server source dependencies.

use std::{io::Read as _, path::PathBuf, time::Duration};

use rustls::pki_types::pem::PemObject as _;
use scoplen_crypto::SymmetricKey;
use scoplen_model::{FieldPath, ObjectType, cbor::Value};
use serde::Deserialize;

use super::*;
use crate::{personal_inventory::PersonalInventorySettings, store::LocalWrite};

mod history;
mod pairing;
mod three_device;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Deployment {
    disposable: bool,
    origin: String,
    invitation_url: String,
    ca_certificate: PathBuf,
}

fn bounded_file(path: &Path, limit: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .expect("open private test artifact")
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .expect("read private test artifact");
    assert!(bytes.len() as u64 <= limit, "test artifact exceeds its bound");
    bytes
}

fn trusted_transport(ca: &[u8]) -> Transport {
    let certificate = reqwest::Certificate::from_pem(ca).expect("test CA certificate");
    let mut transport = Transport::fixture(certificate, Duration::from_secs(15));
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from_pem_slice(ca).expect("notification CA"))
        .expect("trusted notification CA");
    let mut tls = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    transport.notification_tls = Arc::new(tls);
    transport
}

async fn rotate_live_session(
    manager: &PersonalServer,
    store: &Arc<Store>,
    context: &'static str,
) -> PersonalAccountSnapshot {
    let mut before = record(store).expect("retained authenticated identity");
    let access = store
        .personal_access_token(now().expect("current time"))
        .expect("load real access credential")
        .expect("usable real access credential");
    // Expire only the local cache. The server clock, signed JWT and refresh credential
    // remain real, so the next explicit operation exercises production token rotation.
    before.access_expires_at = Some(0);
    store
        .set_personal_session_metadata_for_test(&before)
        .expect("conservatively expire the cached access lifetime");
    let account = manager.query_account(store.clone()).await.unwrap_or_else(|error| {
        let scheduled = record(store).is_ok_and(|identity| identity.refresh_retry_at.is_some());
        panic!("{context}: {error:?}; local refresh retry is scheduled: {scheduled}")
    });
    assert_eq!(account.account_id, before.account_id.to_string());
    assert_eq!(account.email, None);
    assert_eq!(account.devices.len(), 1);
    assert_eq!(account.devices[0].id, store.device_id().to_string());
    assert_eq!(account.devices[0].name, "Live integration device");
    assert!(account.devices[0].current);
    let after = record(store).expect("durable rotated session");
    assert_eq!(after.account_id, before.account_id);
    assert_eq!(after.personal_vault_id, before.personal_vault_id);
    assert_eq!(after.auth_scope, before.auth_scope);
    assert!(after.auth_generation > before.auth_generation);
    assert!(after.refresh_available);
    assert!(after.refresh_expires_at.expect("rotated family deadline") > now().unwrap());
    assert!(
        after.refresh_expires_at.unwrap()
            <= before.refresh_expires_at.expect("original family deadline")
    );
    let rotated = store
        .personal_access_token(now().unwrap())
        .expect("read rotated access credential")
        .expect("usable rotated access credential");
    assert!(rotated.as_bytes() != access.as_bytes(), "the access credential must rotate");
    account
}

#[tokio::test]
async fn live_personal_enrollment_and_inventory_roundtrip() {
    let artifact = std::env::var_os("SCOPLEN_LIVE_PERSONAL_DEPLOYMENT").expect(
        "set SCOPLEN_LIVE_PERSONAL_DEPLOYMENT to a private disposable-deployment JSON file",
    );
    let bytes = Zeroizing::new(bounded_file(Path::new(&artifact), 8_192));
    let mut deployment: Deployment =
        serde_json::from_slice(&bytes).expect("valid private deployment descriptor");
    assert!(deployment.disposable, "this check consumes an invitation on a disposable server");
    assert!(
        deployment
            .origin
            .strip_prefix("https://localhost:")
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|port| port != 0),
        "the live check is restricted to a loopback HTTPS deployment"
    );
    let ca = bounded_file(&deployment.ca_certificate, 65_536);
    let manager = Arc::new(PersonalServer {
        operation: Mutex::new(()),
        transport: Ok(trusted_transport(&ca)),
        pairing: Default::default(),
    });
    let directory = tempfile::tempdir().expect("private local store directory");
    let path = directory.path().join("personal.sqlite");
    let key = SymmetricKey::new([27; 32]);
    let store = Arc::new(Store::open(&path, &key).expect("encrypted local store"));
    let invitation = Zeroizing::new(std::mem::take(&mut deployment.invitation_url));
    let ready = manager
        .prepare(store.clone(), invitation, "Live integration device".into())
        .await
        .expect("prepare real first-device key hierarchy");
    assert_eq!(ready.origin.as_deref(), Some(deployment.origin.as_str()));
    assert_eq!(ready.phase, PersonalServerPhase::RecoveryRequired);
    manager
        .save_recovery_key(store.clone(), directory.path().join("recovery.txt"))
        .await
        .expect("export native recovery file");
    manager.confirm_recovery_key(store.clone()).await.expect("confirm recovery export");
    let authenticated = manager
        .submit(store.clone())
        .await
        .expect("enroll through public HTTPS and authenticate with retained device identity");
    assert_eq!(authenticated.phase, PersonalServerPhase::Authenticated);
    let bootstrap = manager
        .bootstrap_sync(store.clone())
        .await
        .expect("verify server K-4 bundle and unwrap the real account and Personal keys");
    assert_eq!(bootstrap.session().vaults.len(), 1);
    let account =
        rotate_live_session(&manager, &store, "rotate the initial native session before transfer")
            .await;

    let object = store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text("Live Personal host".into())),
                (FieldPath::Field(2), Value::Text("host.example.com".into())),
            ],
        })
        .expect("write local host");
    let settings = PersonalInventorySettings::default();
    let preview = settings.preview(&store, vec![object.id.to_string()]).expect("review selection");
    assert!(preview.missing.is_empty());
    assert!(preview.token.is_some());
    let transferred = settings
        .synchronize(&manager, store.clone(), preview.token)
        .await
        .expect("upload signed ciphertext, pull it back and acknowledge");
    assert_eq!(transferred.uploaded, 1);
    assert!(transferred.downloaded >= 1);
    let saved = settings.status(&store).expect("durable public progress");
    assert_eq!(saved.pending, 0);
    assert_eq!(saved.applied_cursor, saved.acknowledged_cursor);
    assert_ne!(saved.applied_cursor, "0");
    assert_eq!(store.get(object.id).expect("stored host"), Some(object.clone()));

    let runtime = Arc::new(PersonalSyncRuntime::default());
    runtime.set_store(Some(store.clone()));
    let owner = runtime.clone();
    let server = manager.clone();
    let background = tokio::spawn(async move { owner.run(&server).await });
    tokio::time::timeout(Duration::from_secs(15), async {
        while runtime.status() != PersonalBackgroundStatus::Connected {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("real TLS 1.3/H2 D-75 context/auth/ready without Settings");
    store
        .write(LocalWrite {
            id: Some(object.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("Edited live Personal host".into()))],
        })
        .expect("edit adopted host");
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let current = settings.status(&store).expect("background progress");
            if current.pending == 0
                && current.applied_cursor != saved.applied_cursor
                && current.applied_cursor == current.acknowledged_cursor
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("adopted local edit uploads and acknowledges without Settings");
    let before_refresh = record(&store).unwrap();
    let mut expired = record(&store).unwrap();
    expired.access_expires_at = Some(0);
    store.set_personal_session_metadata_for_test(&expired).unwrap();
    store.personal_changed();
    tokio::time::timeout(Duration::from_secs(15), async {
        while record(&store).unwrap().auth_generation <= before_refresh.auth_generation
            || runtime.status() != PersonalBackgroundStatus::Connected
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("notification reconnect rotates real credentials");
    assert!(record(&store).unwrap().refresh_expires_at <= before_refresh.refresh_expires_at);
    runtime.shutdown();
    tokio::time::timeout(Duration::from_secs(5), background)
        .await
        .expect("background shutdown")
        .unwrap();
    let saved = settings.status(&store).expect("second committed progress");
    assert_eq!(saved.pending, 0);
    assert_eq!(saved.applied_cursor, saved.acknowledged_cursor);

    drop(store);
    let reopened = Arc::new(Store::open(&path, &key).expect("reopen encrypted local store"));
    let offline = PersonalServer::default();
    assert!(offline.load_sync_bootstrap(&reopened).expect("offline key revalidation").is_some());
    assert_eq!(
        offline.account_snapshot(&reopened).expect("offline signed account revalidation"),
        Some(account)
    );
    rotate_live_session(
        &manager,
        &reopened,
        "rotate the native session after encrypted-store reopen",
    )
    .await;
    assert_eq!(
        settings.status(&reopened).expect("offline durable progress").applied_cursor,
        saved.applied_cursor
    );
    assert_eq!(
        settings
            .restore(&offline, &reopened, vec![object.id.to_string()])
            .expect("restore original copy without a network request"),
        1
    );
    assert_eq!(reopened.list(ObjectType::HOST).expect("local host copies").len(), 2);
    let (paired, unshared) =
        pairing::verify(&deployment, &manager, reopened.clone(), object.id).await;
    let paired_host = reopened.get(object.id).expect("original-device synchronized host");
    let historical_copy = history::verify(&manager, reopened.clone(), &object).await;
    let (paired_account, converged, cursor) =
        three_device::verify(&deployment, &manager, reopened.clone(), paired).await;
    drop(reopened);
    let reopened = Store::open(&path, &key).expect("reopen original paired-account device");
    assert!(
        offline.load_sync_bootstrap(&reopened).expect("original-device offline keys").is_some()
    );
    assert_eq!(
        offline.account_snapshot(&reopened).expect("original-device offline account"),
        Some(paired_account)
    );
    assert_eq!(reopened.get(object.id).expect("original-device offline host"), paired_host);
    assert_eq!(
        reopened.get(unshared.id).expect("original-device offline local-only host"),
        Some(unshared)
    );
    assert_eq!(
        reopened.get(historical_copy.id).expect("offline historical copy"),
        Some(historical_copy)
    );
    for expected in converged {
        assert_eq!(
            reopened.get(expected.id).expect("original-device offline convergence"),
            Some(expected)
        );
    }
    let progress = settings.status(&reopened).expect("original-device offline converged progress");
    assert_eq!(progress.pending, 0);
    assert_eq!(progress.applied_cursor, cursor);
    assert_eq!(progress.acknowledged_cursor, cursor);
}
