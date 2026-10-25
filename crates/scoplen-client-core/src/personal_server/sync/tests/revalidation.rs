// SPDX-License-Identifier: Apache-2.0
//! Current authority uses real signed auth and bounded TLS 1.3/H2 bootstrap, never old entry.

use rusqlite::params;
use scoplen_api::account_devices::AccountDeviceStatements;

use super::*;
use crate::personal_server::identity::Secrets;
use crate::{local_data::LocalData, personal_server::PersonalServerPhase, testing::MemoryKeystore};

fn profile(dir: &tempfile::TempDir) -> LocalData {
    let key = MemoryKeystore::default();
    let mut slot = vec![1];
    slot.extend_from_slice(&[27; 32]);
    *key.0.lock().unwrap() = Some(slot);
    LocalData::start(dir.path(), Some(Box::new(key))).unwrap()
}

fn database(dir: &tempfile::TempDir) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(dir.path().join("local.db")).unwrap();
    conn.pragma_update(None, "key", format!("x'{}'", "1b".repeat(32))).unwrap();
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn
}

async fn raw(peer: &Peer, local: &LocalData, dir: &tempfile::TempDir) -> PersonalServer {
    let store = local.store().unwrap();
    let manager = peer.prepare_profile(&store, false).await;
    database(dir)
        .execute(
            "UPDATE personal_server SET access_token=NULL, refresh_token=NULL,
        access_expires_at=NULL, refresh_expires_at=NULL, auth_scope=NULL, session_established=0,
        enrollment_request=X'ff'",
            [],
        )
        .unwrap();
    refresh::install_revalidation(peer, &store, refresh::Mode::Success);
    manager
}

fn unchanged(conn: &rusqlite::Connection, before: &[u8]) {
    let (admissions, sessions, snapshots, private, archive): (i64, i64, i64, Vec<u8>, Vec<u8>) =
        conn.query_row(
            "SELECT (SELECT count(*) FROM personal_admission), session_established,
            (SELECT count(*) FROM personal_sync), private_material, enrollment_request
         FROM personal_server",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap();
    assert_eq!((admissions, sessions, snapshots), (0, 0, 0));
    assert_eq!(private, before);
    assert_eq!(archive, [255]);
    let tokens: bool = conn.query_row("SELECT access_token IS NULL AND refresh_token IS NULL AND auth_scope IS NULL FROM personal_server", [], |r| r.get(0)).unwrap();
    assert!(tokens, "unverified credentials escaped the transient Rust operation");
}

#[tokio::test]
async fn explicit_revalidation_keeps_credentials_transient_then_installs_all_state_and_reopens_offline()
 {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let local = profile(&dir);
    let store = local.store().unwrap();
    let manager = raw(&peer, &local, &dir).await;
    let before = store.personal_record().unwrap().unwrap();
    assert_eq!(manager.status(&store).unwrap().phase, PersonalServerPhase::RevalidationRequired);
    assert!(peer.state.lock().unwrap().paths.is_empty());
    let reached = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    peer.state.lock().unwrap().pause =
        Some(("/sync/v1/keys".into(), reached.clone(), resume.clone()));
    let status = {
        let result = manager.revalidate_retained_device(&local, local.store().unwrap());
        tokio::pin!(result);
        tokio::select! {
            _ = &mut result => panic!("bootstrap finished before peer release"),
            _ = reached.notified() => {}
        }
        unchanged(&database(&dir), before.private_material.as_bytes());
        resume.notify_one();
        result.await.unwrap()
    };
    assert_eq!(status.phase, PersonalServerPhase::Authenticated);
    assert!(manager.load_sync_bootstrap(&store).unwrap().is_some());
    assert!(store.personal_access_token(now().unwrap()).unwrap().is_some());
    let after = store.personal_record().unwrap().unwrap();
    assert_eq!(after.private_material.as_bytes(), before.private_material.as_bytes());
    let archive: Vec<u8> = database(&dir)
        .query_row("SELECT enrollment_request FROM personal_server", [], |row| row.get(0))
        .unwrap();
    assert_eq!(archive, [255]);
    assert!(after.auth_generation > before.auth_generation);
    {
        let state = peer.state.lock().unwrap();
        assert_eq!(state.proofs.len(), 3);
        assert_eq!(
            state.paths,
            [
                "/api/v1/auth/challenge",
                "/api/v1/auth/device",
                "/.well-known/jwks.json",
                "/sync/v1/session",
                "/sync/v1/keys",
                &format!("/sync/v1/vaults/{}/keys", before.personal_vault_id)
            ]
        );
    }
    peer.assert_healthy();
    assert_eq!(
        manager.revalidate_retained_device(&local, local.store().unwrap()).await.unwrap_err(),
        PersonalServerError::Busy
    );
    drop(store);
    drop(local);
    drop(peer);
    let reopened = profile(&dir);
    let restored =
        PersonalServer::default().load_sync_bootstrap(&reopened.store().unwrap()).unwrap();
    assert!(restored.is_some());
}

#[tokio::test]
async fn invalid_authentication_claims_never_fetch_bootstrap_or_install_credentials() {
    for mode in [
        refresh::Mode::ForeignAccount,
        refresh::Mode::ForeignDevice,
        refresh::Mode::ForeignKey,
        refresh::Mode::ForeignIssuer,
        refresh::Mode::InvalidSignature,
        refresh::Mode::ExpiredAccess,
        refresh::Mode::MissingScope,
    ] {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let local = profile(&dir);
        let store = local.store().unwrap();
        let manager = raw(&peer, &local, &dir).await;
        let before = store.personal_record().unwrap().unwrap();
        refresh::install_revalidation(&peer, &store, mode);
        assert_eq!(
            manager.revalidate_retained_device(&local, local.store().unwrap()).await.unwrap_err(),
            PersonalServerError::InvalidResponse
        );
        unchanged(&database(&dir), before.private_material.as_bytes());
        assert!(!peer.state.lock().unwrap().paths.iter().any(|path| path.starts_with("/sync/")));
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn substituted_keys_certificates_revocation_vaults_and_epochs_never_gain_authority() {
    for fault in 0..16 {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let local = profile(&dir);
        let store = local.store().unwrap();
        let manager = raw(&peer, &local, &dir).await;
        let mut before = store.personal_record().unwrap().unwrap();
        let observed = store.personal_changes();
        let generation = *observed.borrow();
        let mut bundle = SyncAccountKeyBundle::from_cbor(
            &peer.state.lock().unwrap().replies["/sync/v1/keys"].body,
        )
        .unwrap();
        let signing = Ed25519SigningKey::from_bytes(
            Secrets::parse(&before.private_material).unwrap().account_signing(),
        )
        .unwrap();
        match fault {
            0 => bundle.wrapped_ark[90] ^= 1,
            1 => bundle.account_signing_key[40] ^= 1,
            2 => bundle.account_kem_key[40] ^= 1,
            3 => bundle.recovery_blob[40] ^= 1,
            4 => {
                let mut cert = DeviceCertificate::decode(&bundle.certificates[0]).unwrap();
                cert.signature[0] ^= 1;
                bundle.certificates[0] = cert.encode().unwrap();
            }
            5 => {
                bundle.revocations = vec![
                    RevocationStatement::issue(&signing, store.device_id(), 1, "revoked".into())
                        .unwrap()
                        .encode()
                        .unwrap(),
                ]
            }
            6 => bundle.certificates.clear(),
            7 => {
                let mut cert = DeviceCertificate::decode(&bundle.certificates[0]).unwrap();
                cert.account_id = scoplen_model::new_uuid_v7().unwrap();
                bundle.certificates[0] = cert.encode().unwrap();
            }
            8 => {
                let path = format!("/sync/v1/vaults/{}/keys", before.personal_vault_id);
                let mut wraps = SyncVaultKeysResponse::from_cbor(
                    &peer.state.lock().unwrap().replies[&path].body,
                )
                .unwrap();
                wraps.keys[0].wrapped_vault_key[40] ^= 1;
                peer.reply(&path, Reply::cbor(wraps.to_cbor().unwrap()));
            }
            9..=11 => {
                let mut session = SyncSessionResponse::from_cbor(
                    &peer.state.lock().unwrap().replies["/sync/v1/session"].body,
                )
                .unwrap();
                if fault == 9 {
                    session.vaults[0].id = scoplen_model::new_uuid_v7().unwrap();
                }
                if fault == 10 {
                    session.vaults[0].key_epoch = 2;
                }
                if fault == 11 {
                    session.vaults[0].rotation_pending = true;
                }
                peer.reply("/sync/v1/session", Reply::cbor(session.to_cbor().unwrap()));
            }
            12..=15 => {
                let mut material = Zeroizing::new(before.private_material.as_bytes().to_vec());
                material[[65, 97, 129, 161][fault - 12]] ^= 1;
                database(&dir)
                    .execute("UPDATE personal_server SET private_material=?1", [&*material])
                    .unwrap();
                before.private_material = SecretVec::new(material.to_vec());
            }
            _ => unreachable!(),
        }
        peer.reply("/sync/v1/keys", Reply::cbor(bundle.to_cbor().unwrap()));
        assert_eq!(
            manager.revalidate_retained_device(&local, local.store().unwrap()).await.unwrap_err(),
            PersonalServerError::AdmissionUnverified,
            "fault {fault}"
        );
        unchanged(&database(&dir), before.private_material.as_bytes());
        assert_eq!(*observed.borrow(), generation, "failure woke the background owner");
        peer.assert_healthy();
    }
}

fn saved_bootstrap(peer: &Peer, conn: &rusqlite::Connection, vault: uuid::Uuid) {
    let state = peer.state.lock().unwrap();
    conn.execute("INSERT INTO personal_sync (singleton,generation,session,account_keys,vault_keys) VALUES(1,1,?1,?2,?3)",
        params![state.replies["/sync/v1/session"].body, state.replies["/sync/v1/keys"].body,
            state.replies[&format!("/sync/v1/vaults/{vault}/keys")].body]).unwrap();
}

#[tokio::test]
async fn retained_non_recovery_device_accepts_newer_membership_with_all_old_evidence() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let local = profile(&dir);
    let store = local.store().unwrap();
    let manager = raw(&peer, &local, &dir).await;
    let original = store.personal_record().unwrap().unwrap();
    let mut material = Zeroizing::new(original.private_material.as_bytes()[..193].to_vec());
    material[0] = 2;
    let conn = database(&dir);
    conn.execute(
        "UPDATE personal_server SET private_material=?1, enrollment_request=zeroblob(1048577)",
        params![&*material],
    )
    .unwrap();
    let mut bundle =
        SyncAccountKeyBundle::from_cbor(&peer.state.lock().unwrap().replies["/sync/v1/keys"].body)
            .unwrap();
    let signing = Ed25519SigningKey::from_bytes(
        Secrets::parse(&original.private_material).unwrap().account_signing(),
    )
    .unwrap();
    bundle.revision = 3;
    bundle.revocations = vec![
        RevocationStatement::issue(
            &signing,
            scoplen_model::new_uuid_v7().unwrap(),
            1,
            "known".into(),
        )
        .unwrap()
        .encode()
        .unwrap(),
    ];
    peer.reply("/sync/v1/keys", Reply::cbor(bundle.to_cbor().unwrap()));
    saved_bootstrap(&peer, &conn, original.personal_vault_id);
    bundle.revision = 4;
    peer.reply("/sync/v1/keys", Reply::cbor(bundle.to_cbor().unwrap()));
    assert_eq!(manager.status(&store).unwrap().phase, PersonalServerPhase::RevalidationRequired);
    assert_eq!(
        manager.revalidate_retained_device(&local, local.store().unwrap()).await.unwrap().phase,
        PersonalServerPhase::Authenticated
    );
    assert!(manager.load_sync_bootstrap(&store).unwrap().is_some());
    let preserved: i64 = conn
        .query_row("SELECT length(enrollment_request) FROM personal_server", [], |r| r.get(0))
        .unwrap();
    assert_eq!(preserved, 1_048_577);
    let retained = store.personal_record().unwrap().unwrap();
    assert_eq!(retained.private_material.as_bytes(), &*material);
    assert_eq!(
        SyncAccountKeyBundle::from_cbor(
            store.personal_sync_record().unwrap().unwrap().account_keys.as_bytes()
        )
        .unwrap()
        .revision,
        4
    );
    peer.assert_healthy();
}

#[tokio::test]
async fn missing_profile_and_bounded_transport_failures_do_not_install_or_send_entry_requests() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let local = profile(&dir);
    assert_eq!(
        peer.manager()
            .revalidate_retained_device(&local, local.store().unwrap())
            .await
            .unwrap_err(),
        PersonalServerError::NotConfigured
    );
    assert!(peer.state.lock().unwrap().paths.is_empty());
    let store = local.store().unwrap();
    let manager = raw(&peer, &local, &dir).await;
    let before = store.personal_record().unwrap().unwrap();
    let reopened = profile(&dir);
    assert_eq!(
        manager.revalidate_retained_device(&reopened, store.clone()).await.unwrap_err(),
        PersonalServerError::Busy
    );
    assert!(peer.state.lock().unwrap().paths.is_empty());
    for fault in 0..4 {
        let reply = match fault {
            0 => Reply { status: 403, ..Reply::cbor(vec![]) },
            1 => Reply {
                status: 302,
                headers: vec![("location", "https://foreign.example".into())],
                ..Reply::cbor(vec![])
            },
            2 => Reply::cbor(vec![0; 4 * 1024 * 1024 + 1]),
            _ => Reply::cbor(vec![255]),
        };
        peer.reply("/sync/v1/keys", reply);
        assert!(
            manager.revalidate_retained_device(&local, local.store().unwrap()).await.is_err(),
            "fault {fault}"
        );
        unchanged(&database(&dir), before.private_material.as_bytes());
    }
    assert!(!peer.state.lock().unwrap().paths.iter().any(|path| path.contains("enroll")
        || path.contains("pair")
        || path.contains("accounts/register")));
    peer.assert_healthy();
}

#[tokio::test]
async fn revalidation_preserves_known_certificates_revocations_revisions_and_epoch_evidence() {
    for fault in 0..5 {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let local = profile(&dir);
        let store = local.store().unwrap();
        let manager = raw(&peer, &local, &dir).await;
        let identity = store.personal_record().unwrap().unwrap();
        let conn = database(&dir);
        let original = peer.state.lock().unwrap().replies["/sync/v1/keys"].clone();
        let mut bundle = SyncAccountKeyBundle::from_cbor(&original.body).unwrap();
        bundle.revision = 3;
        peer.reply("/sync/v1/keys", Reply::cbor(bundle.to_cbor().unwrap()));
        saved_bootstrap(&peer, &conn, identity.personal_vault_id);
        let signing = Ed25519SigningKey::from_bytes(
            Secrets::parse(&identity.private_material).unwrap().account_signing(),
        )
        .unwrap();
        if fault <= 1 {
            let mut cert = DeviceCertificate::decode(&bundle.certificates[0]).unwrap();
            if fault == 0 {
                cert.device_id = scoplen_model::new_uuid_v7().unwrap();
            } else {
                cert.display_name = "different signed metadata".into();
            }
            cert = DeviceCertificate::issue(
                &signing,
                cert.device_id,
                cert.account_id,
                cert.signing_public_key,
                cert.kem_public_key,
                cert.display_name,
                cert.platform,
                cert.created_at,
            )
            .unwrap();
            let statements = AccountDeviceStatements {
                account_id: identity.account_id,
                certificates: vec![cert.encode().unwrap()],
                revocations: vec![],
            };
            let profile = scoplen_api::account_profile::AccountProfile {
                id: identity.account_id,
                etag: "\"fixture\"".into(),
                created_at: "2026-10-23T00:00:00Z".into(),
                updated_at: "2026-10-23T00:00:00Z".into(),
                email: None,
            };
            conn.execute("INSERT INTO personal_account_snapshot(singleton,origin,account_id,queried_at,profile,devices) VALUES(1,?1,?2,1,?3,?4)",
                params![identity.origin,identity.account_id.as_bytes().as_slice(),profile.to_json().unwrap(),statements.to_json().unwrap()]).unwrap();
        } else if fault == 2 {
            let revocation = RevocationStatement::issue(
                &signing,
                scoplen_model::new_uuid_v7().unwrap(),
                1,
                "known revoked".into(),
            )
            .unwrap();
            bundle.revocations = vec![revocation.encode().unwrap()];
            conn.execute("UPDATE personal_sync SET account_keys=?1", [bundle.to_cbor().unwrap()])
                .unwrap();
        } else if fault == 3 {
            bundle.revision = 2;
            peer.reply("/sync/v1/keys", Reply::cbor(bundle.to_cbor().unwrap()));
        } else {
            let path = format!("/sync/v1/vaults/{}/keys", identity.personal_vault_id);
            let mut wraps =
                SyncVaultKeysResponse::from_cbor(&peer.state.lock().unwrap().replies[&path].body)
                    .unwrap();
            let secrets = Secrets::parse(&identity.private_material).unwrap();
            wraps.keys[0].wrapped_vault_key = PersonalVaultKeyWrap::seal(
                identity.account_id,
                identity.personal_vault_id,
                1,
                &SymmetricKey::new(secrets.ark().try_into().unwrap()),
                &SymmetricKey::new(secrets.vault().try_into().unwrap()),
            )
            .unwrap()
            .encode()
            .to_vec();
            peer.reply(&path, Reply::cbor(wraps.to_cbor().unwrap()));
        }
        let prior = store.personal_sync_record().unwrap().unwrap();
        assert!(
            manager.revalidate_retained_device(&local, local.store().unwrap()).await.is_err(),
            "fault {fault}"
        );
        assert!(store.personal_admission(&identity).unwrap().is_none());
        let after = store.personal_sync_record().unwrap().unwrap();
        assert_eq!(after.account_keys.as_bytes(), prior.account_keys.as_bytes());
        assert_eq!(after.vault_keys.as_bytes(), prior.vault_keys.as_bytes());
        assert_eq!(after.generation, prior.generation);
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn late_auth_generation_and_transaction_failure_preserve_original_profile() {
    for fault in 0..3 {
        let peer = Peer::new().await;
        let dir = tempfile::tempdir().unwrap();
        let local = profile(&dir);
        let store = local.store().unwrap();
        let manager = raw(&peer, &local, &dir).await;
        let before = store.personal_record().unwrap().unwrap();
        let conn = database(&dir);
        if fault == 0 {
            let reached = Arc::new(tokio::sync::Notify::new());
            let resume = Arc::new(tokio::sync::Notify::new());
            let path = format!("/sync/v1/vaults/{}/keys", before.personal_vault_id);
            peer.state.lock().unwrap().pause = Some((path, reached.clone(), resume.clone()));
            let result = manager.revalidate_retained_device(&local, local.store().unwrap());
            tokio::pin!(result);
            tokio::select! { _ = &mut result => panic!("unexpected completion"), _ = reached.notified() => {} }
            conn.execute("UPDATE personal_server SET auth_generation=auth_generation+1", [])
                .unwrap();
            resume.notify_one();
            assert_eq!(result.await.unwrap_err(), PersonalServerError::Busy);
        } else {
            conn.execute_batch(if fault == 1 {
                "CREATE TRIGGER fail_session BEFORE UPDATE OF access_token ON personal_server BEGIN SELECT RAISE(ABORT,'fixture'); END;"
            } else {
                "CREATE TRIGGER fail_bootstrap BEFORE INSERT ON personal_sync BEGIN SELECT RAISE(ABORT,'fixture'); END;"
            }).unwrap();
            assert_eq!(
                manager
                    .revalidate_retained_device(&local, local.store().unwrap())
                    .await
                    .unwrap_err(),
                PersonalServerError::Storage
            );
        }
        unchanged(&conn, before.private_material.as_bytes());
        peer.assert_healthy();
    }
}

#[tokio::test]
async fn new_revocation_evidence_during_bootstrap_cannot_be_erased_by_the_install() {
    let peer = Peer::new().await;
    let dir = tempfile::tempdir().unwrap();
    let local = profile(&dir);
    let store = local.store().unwrap();
    let manager = raw(&peer, &local, &dir).await;
    let identity = store.personal_record().unwrap().unwrap();
    let signing = Ed25519SigningKey::from_bytes(
        Secrets::parse(&identity.private_material).unwrap().account_signing(),
    )
    .unwrap();
    let bundle =
        SyncAccountKeyBundle::from_cbor(&peer.state.lock().unwrap().replies["/sync/v1/keys"].body)
            .unwrap();
    let statements = AccountDeviceStatements {
        account_id: identity.account_id,
        certificates: bundle.certificates,
        revocations: vec![
            RevocationStatement::issue(&signing, store.device_id(), 1, "known revoked".into())
                .unwrap()
                .encode()
                .unwrap(),
        ],
    };
    let profile = scoplen_api::account_profile::AccountProfile::new(
        identity.account_id,
        "\"fixture\"",
        "2026-10-23T00:00:00Z",
        "2026-10-23T00:00:00Z",
        None,
    )
    .unwrap();
    let reached = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    peer.state.lock().unwrap().pause = Some((
        format!("/sync/v1/vaults/{}/keys", identity.personal_vault_id),
        reached.clone(),
        resume.clone(),
    ));
    let result = manager.revalidate_retained_device(&local, store.clone());
    tokio::pin!(result);
    tokio::select! { _ = &mut result => panic!("unexpected completion"), _ = reached.notified() => {} }
    let conn = database(&dir);
    conn.execute("INSERT INTO personal_account_snapshot(singleton,origin,account_id,queried_at,profile,devices) VALUES(1,?1,?2,1,?3,?4)",
        params![identity.origin,identity.account_id.as_bytes().as_slice(),profile.to_json().unwrap(),statements.to_json().unwrap()]).unwrap();
    resume.notify_one();
    assert_eq!(result.await.unwrap_err(), PersonalServerError::Busy);
    unchanged(&conn, identity.private_material.as_bytes());
    assert_eq!(
        store.personal_account_snapshot(&identity).unwrap().unwrap().devices.as_bytes(),
        statements.to_json().unwrap()
    );
    peer.assert_healthy();
}
