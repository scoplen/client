// SPDX-License-Identifier: Apache-2.0
//! Explicit opt-in checks against a disposable deployment, without server source dependencies.

use std::{io::Read as _, path::PathBuf, time::Duration};

use scoplen_crypto::SymmetricKey;
use scoplen_model::{FieldPath, ObjectType, cbor::Value};
use serde::Deserialize;

use super::*;
use crate::{personal_inventory::PersonalInventorySettings, store::LocalWrite};

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

async fn rotate_live_session(
    manager: &PersonalServer,
    store: &Arc<Store>,
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
    let account = manager
        .query_account(store.clone())
        .await
        .expect("rotate the real native session before an explicit account query");
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
    let certificate = reqwest::Certificate::from_pem(&ca).expect("test CA certificate");
    let manager = PersonalServer {
        operation: Mutex::new(()),
        transport: Ok(Transport::fixture(certificate, Duration::from_secs(15))),
    };
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
    let account = rotate_live_session(&manager, &store).await;

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

    store
        .write(LocalWrite {
            id: Some(object.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text("Edited live Personal host".into()))],
        })
        .expect("edit adopted host");
    let second = settings
        .synchronize(&manager, store.clone(), None)
        .await
        .expect("incremental update through existing adoption");
    assert_eq!(second.uploaded, 1);
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
    rotate_live_session(&manager, &reopened).await;
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
}
