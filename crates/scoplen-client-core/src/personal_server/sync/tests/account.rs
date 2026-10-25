// SPDX-License-Identifier: Apache-2.0
//! Real TLS peer exercises the public Personal account API and its offline read model.

use super::*;
use scoplen_api::{account_devices::AccountDeviceStatements, account_profile::AccountProfile};

pub(super) fn json(body: Vec<u8>) -> Reply {
    Reply {
        content_type: "application/json",
        headers: vec![("cache-control", "no-store".into()), ("pragma", "no-cache".into())],
        ..Reply::cbor(body)
    }
}

pub(super) fn install(peer: &Peer, store: &Store) -> AccountDeviceStatements {
    let pending = record(store).unwrap();
    let key = Ed25519SigningKey::from_bytes(
        identity::Secrets::parse(&pending.private_material).unwrap().account_signing(),
    )
    .unwrap();
    let current = crate::personal_server::retained::RetainedAccount::load(store, &pending)
        .unwrap()
        .certificate;
    let other = issue(
        store,
        &key,
        scoplen_model::new_uuid_v7().unwrap(),
        pending.account_id,
        "办公室的 Mac",
        "macos",
    );
    let revoked_id = scoplen_model::new_uuid_v7().unwrap();
    let revoked = issue(store, &key, revoked_id, pending.account_id, "Old device", "windows");
    let mut certificates =
        vec![current.encode().unwrap(), other.encode().unwrap(), revoked.encode().unwrap()];
    certificates.sort();
    let mut revocations = vec![
        RevocationStatement::issue(&key, revoked_id, 1, "Retired".into())
            .unwrap()
            .encode()
            .unwrap(),
        RevocationStatement::issue(
            &key,
            scoplen_model::new_uuid_v7().unwrap(),
            2,
            "Not in certificate set".into(),
        )
        .unwrap()
        .encode()
        .unwrap(),
    ];
    revocations.sort();
    let statements =
        AccountDeviceStatements::new(pending.account_id, certificates, revocations).unwrap();
    let profile = AccountProfile::new(
        pending.account_id,
        "\"one\"",
        "2026-10-23T00:00:00Z",
        "2026-10-23T00:00:00Z",
        None,
    )
    .unwrap();
    let mut reply = json(profile.to_json().unwrap());
    reply.headers.push(("etag", profile.etag));
    peer.reply("/api/v1/accounts/me", reply);
    peer.reply("/api/v1/accounts/me/devices", json(statements.to_json().unwrap()));
    statements
}

fn issue(
    store: &Store,
    key: &Ed25519SigningKey,
    id: uuid::Uuid,
    account: uuid::Uuid,
    name: &str,
    platform: &str,
) -> DeviceCertificate {
    let pending = record(store).unwrap();
    let secrets = identity::Secrets::parse(&pending.private_material).unwrap();
    DeviceCertificate::issue(
        key,
        id,
        account,
        P256SigningKey::from_bytes(secrets.signing()).unwrap().public_key_sec1(),
        DeviceKemKeyPair::from_private_bytes(secrets.device_kem()).unwrap().public_key().to_vec(),
        name.into(),
        platform.into(),
        1,
    )
    .unwrap()
}

#[tokio::test]
async fn explicit_query_verifies_signed_devices_and_survives_offline_restart() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store);
    assert!(manager.account_snapshot(&store).unwrap().is_none());
    assert!(peer.state.lock().unwrap().paths.is_empty());
    let result = manager.query_account(store.clone()).await.unwrap();
    assert_eq!(result.account_id, record(&store).unwrap().account_id.to_string());
    assert!(result.email.is_none());
    assert_eq!(result.devices.len(), 2);
    assert!(result.devices.windows(2).all(|devices| devices[0].id < devices[1].id));
    let current = result.devices.iter().find(|device| device.current).unwrap();
    assert_eq!(current.id, store.device_id().to_string());
    assert_eq!(current.name, "Desktop");
    assert_eq!(current.platform, std::env::consts::OS);
    assert!(
        result
            .devices
            .iter()
            .any(|device| device.name == "办公室的 Mac" && device.platform == "macos")
    );
    assert_eq!(peer.state.lock().unwrap().proofs.len(), 2);
    {
        let _operation = manager.operation.try_lock().unwrap();
        assert_eq!(manager.account_snapshot(&store).unwrap(), Some(result.clone()));
    }
    assert_eq!(
        peer.state.lock().unwrap().paths.as_slice(),
        ["/.well-known/jwks.json", "/api/v1/accounts/me", "/api/v1/accounts/me/devices"]
    );
    assert!(!format!("{result:?}").contains("Desktop"));
    let encoded = serde_json::to_string(&result).unwrap();
    assert!(
        !encoded.contains("certificate")
            && !encoded.contains("token")
            && !encoded.contains("private")
    );
    store.clear_personal_tokens().unwrap();
    peer.assert_healthy();
    drop(peer);
    drop(store);
    let store = local(&dir);
    assert_eq!(PersonalServer::default().account_snapshot(&store).unwrap(), Some(result));
}

#[tokio::test]
async fn invalid_whole_sets_never_replace_the_previous_verified_snapshot() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let base = install(&peer, &store);
    let original = manager.query_account(store.clone()).await.unwrap();
    let pending = record(&store).unwrap();
    let key = Ed25519SigningKey::from_bytes(
        identity::Secrets::parse(&pending.private_material).unwrap().account_signing(),
    )
    .unwrap();
    for case in 0..10 {
        let mut statements = base.clone();
        match case {
            0 => statements.account_id = scoplen_model::new_uuid_v7().unwrap(),
            1 => statements.certificates.push(
                issue(
                    &store,
                    &key,
                    scoplen_model::new_uuid_v7().unwrap(),
                    scoplen_model::new_uuid_v7().unwrap(),
                    "Foreign",
                    "macos",
                )
                .encode()
                .unwrap(),
            ),
            2 => {
                let mut certificate =
                    DeviceCertificate::decode(&statements.certificates[0]).unwrap();
                certificate.signature[0] ^= 1;
                statements.certificates[0] = certificate.encode().unwrap();
            }
            3 => statements.certificates.push(
                issue(
                    &store,
                    &key,
                    store.device_id(),
                    pending.account_id,
                    "Duplicate identity",
                    "windows",
                )
                .encode()
                .unwrap(),
            ),
            4 => statements.certificates.retain(|bytes| {
                DeviceCertificate::decode(bytes).unwrap().device_id != store.device_id()
            }),
            5 => {
                statements.certificates.retain(|bytes| {
                    DeviceCertificate::decode(bytes).unwrap().device_id != store.device_id()
                });
                statements.certificates.push(
                    issue(
                        &store,
                        &key,
                        store.device_id(),
                        pending.account_id,
                        "Replaced certificate",
                        "windows",
                    )
                    .encode()
                    .unwrap(),
                );
            }
            6 => {
                let revocation = RevocationStatement::decode(&statements.revocations[0]).unwrap();
                statements.revocations.push(
                    RevocationStatement::issue(
                        &key,
                        revocation.device_id,
                        9,
                        "Duplicate identity".into(),
                    )
                    .unwrap()
                    .encode()
                    .unwrap(),
                );
            }
            7 => {
                let mut revocation =
                    RevocationStatement::decode(&statements.revocations[0]).unwrap();
                revocation.signature[0] ^= 1;
                statements.revocations[0] = revocation.encode().unwrap();
            }
            8 => statements.revocations.push(
                RevocationStatement::issue(
                    &key,
                    store.device_id(),
                    9,
                    "Current device revoked".into(),
                )
                .unwrap()
                .encode()
                .unwrap(),
            ),
            _ => statements.certificates.push(vec![1]),
        }
        statements.certificates.sort();
        statements.revocations.sort();
        peer.reply("/api/v1/accounts/me/devices", json(statements.to_json().unwrap()));
        assert_eq!(
            manager.query_account(store.clone()).await,
            Err(PersonalServerError::InvalidAccountResponse),
            "case {case}"
        );
        assert_eq!(
            manager.account_snapshot(&store).unwrap(),
            Some(original.clone()),
            "case {case}"
        );
    }
    peer.assert_healthy();
}

#[tokio::test]
async fn profile_metadata_and_transport_failures_keep_the_entire_cached_pair() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store);
    let original = manager.query_account(store.clone()).await.unwrap();
    let base = peer.state.lock().unwrap().replies["/api/v1/accounts/me"].clone();
    for case in 0..8 {
        let mut reply = base.clone();
        match case {
            0 => {
                let mut profile = AccountProfile::from_json(&reply.body).unwrap();
                profile.id = scoplen_model::new_uuid_v7().unwrap();
                reply.body = profile.to_json().unwrap();
            }
            1 => reply.headers.retain(|(name, _)| *name != "etag"),
            2 => reply.headers.retain(|(name, _)| *name != "pragma"),
            3 => reply.headers.push(("age", "1".into())),
            4 => reply.headers.push(("cache-control", "no-store".into())),
            5 => reply.body = vec![b' '; 4097],
            6 => reply.content_type = "text/html",
            _ => reply.status = 302,
        }
        peer.reply("/api/v1/accounts/me", reply);
        assert_eq!(
            manager.query_account(store.clone()).await,
            Err(PersonalServerError::InvalidAccountResponse),
            "case {case}"
        );
        assert_eq!(manager.account_snapshot(&store).unwrap(), Some(original.clone()));
    }
    peer.assert_healthy();
}

#[tokio::test]
async fn session_scope_and_denial_never_grant_device_access_and_keep_offline_state() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store);
    let original = manager.query_account(store.clone()).await.unwrap();
    peer.install_token(&store, |claims| claims.scope = "keys:read".into(), None);
    assert_eq!(
        manager.query_account(store.clone()).await,
        Err(PersonalServerError::AuthenticationRequired)
    );
    peer.install_token(&store, |claims| claims.scope = "keys:read".into(), None);
    let mut identity = record(&store).unwrap();
    identity.auth_scope = Some("keys:read".into());
    store.set_personal_session_metadata_for_test(&identity).unwrap();
    let before = peer.state.lock().unwrap().paths.len();
    assert_eq!(
        manager.query_account(store.clone()).await,
        Err(PersonalServerError::PermissionDenied)
    );
    assert_eq!(peer.state.lock().unwrap().paths.len(), before + 1);
    peer.install_token(&store, |_| {}, None);
    peer.reply(
        "/api/v1/accounts/me/devices",
        Reply { status: 403, content_type: "application/problem+json", ..json(vec![]) },
    );
    assert_eq!(
        manager.query_account(store.clone()).await,
        Err(PersonalServerError::PermissionDenied)
    );
    assert!(store.personal_access_token(now().unwrap()).unwrap().is_some());
    assert_eq!(manager.account_snapshot(&store).unwrap(), Some(original.clone()));
    peer.reply(
        "/api/v1/accounts/me/devices",
        Reply { status: 401, content_type: "application/problem+json", ..json(vec![]) },
    );
    assert_eq!(
        manager.query_account(store.clone()).await,
        Err(PersonalServerError::AuthenticationRequired)
    );
    assert!(store.personal_access_token(now().unwrap()).unwrap().is_none());
    assert_eq!(manager.account_snapshot(&store).unwrap(), Some(original));
    peer.assert_healthy();
}

#[tokio::test]
async fn stale_authentication_cannot_publish_an_older_snapshot() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    install(&peer, &store);
    let original = manager.query_account(store.clone()).await.unwrap();
    let identity = record(&store).unwrap();
    let access = store.personal_access_token(now().unwrap()).unwrap().unwrap();
    let snapshot = store.personal_account_snapshot(&identity).unwrap().unwrap();
    store.clear_personal_tokens().unwrap();
    assert!(
        !store
            .save_personal_account_snapshot(
                &identity,
                &access,
                &snapshot,
                Some(snapshot.devices.as_bytes()),
                now().unwrap()
            )
            .unwrap()
    );
    assert_eq!(manager.account_snapshot(&store).unwrap(), Some(original));
}

#[tokio::test]
async fn offline_reads_reverify_artifacts_and_bound_the_local_query_time() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir);
    let manager = peer.prepare(&store).await;
    let base = install(&peer, &store);
    manager.query_account(store.clone()).await.unwrap();
    let identity = record(&store).unwrap();
    let access = store.personal_access_token(now().unwrap()).unwrap().unwrap();
    let requests = peer.state.lock().unwrap().paths.len();
    for invalid_time in [false, true] {
        let mut snapshot = store.personal_account_snapshot(&identity).unwrap().unwrap();
        let expected = snapshot.devices.as_bytes().to_vec();
        if invalid_time {
            snapshot.devices = SecretVec::new(base.to_json().unwrap());
            snapshot.queried_at = 253_402_300_800_000;
        } else {
            let mut statements = base.clone();
            let mut certificate = DeviceCertificate::decode(&statements.certificates[0]).unwrap();
            certificate.signature[0] ^= 1;
            statements.certificates[0] = certificate.encode().unwrap();
            statements.certificates.sort();
            snapshot.devices = SecretVec::new(statements.to_json().unwrap());
        }
        assert!(
            store
                .save_personal_account_snapshot(
                    &identity,
                    &access,
                    &snapshot,
                    Some(&expected),
                    now().unwrap()
                )
                .unwrap()
        );
        assert_eq!(
            manager.account_snapshot(&store).unwrap_err(),
            PersonalServerError::InvalidAccountResponse
        );
    }
    assert_eq!(peer.state.lock().unwrap().paths.len(), requests);
}
