// SPDX-License-Identifier: Apache-2.0
//! Neutral admission and archived data stay independent of retired wire formats.

use super::*;

fn admission_count(dir: &tempfile::TempDir) -> i64 {
    database(dir).query_row("SELECT count(*) FROM personal_admission", [], |r| r.get(0)).unwrap()
}

#[test]
fn neutral_anchors_reopen_offline_without_reading_or_changing_archived_entry_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let fixture = fixture_profile(&local, "https://example.test", true);
    let anchors = local.personal_admission(&fixture.record).unwrap().unwrap();
    assert!(anchors.len() < 4096);
    let conn = database(&dir);
    conn.execute(
        "UPDATE personal_server SET enrollment_request=X'00ff', paired_handoff=X'cafe'",
        [],
    )
    .unwrap();
    let before: i64 = conn.pragma_query_value(None, "data_version", |r| r.get(0)).unwrap();
    let manager = PersonalServer::default();
    assert_eq!(manager.status(&local).unwrap().phase, PersonalServerPhase::AuthenticationRequired);
    assert_eq!(
        conn.pragma_query_value(None, "data_version", |r| r.get::<_, i64>(0)).unwrap(),
        before
    );
    drop(local);
    let reopened = store(&dir);
    assert_eq!(
        manager.status(&reopened).unwrap().phase,
        PersonalServerPhase::AuthenticationRequired
    );
    let record = reopened.personal_record().unwrap().unwrap();
    assert_eq!(record.private_material.as_bytes(), fixture.record.private_material.as_bytes());
    assert_eq!(
        reopened.personal_admission(&record).unwrap().unwrap().as_bytes(),
        anchors.as_bytes()
    );
    let archives: (Vec<u8>, Vec<u8>) = conn
        .query_row("SELECT enrollment_request,paired_handoff FROM personal_server", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(archives, (vec![0, 255], vec![202, 254]));
    assert_eq!(admission_count(&dir), 1);
}

#[test]
fn saved_v1_anchors_without_a_wrap_digest_still_reopen_offline() {
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let fixture = fixture_profile(&local, "https://example.test", false);
    let (_, anchors) =
        retained::RetainedAccount::from_snapshot(&local, &fixture.record, &fixture.snapshot)
            .unwrap();
    let mut saved: serde_json::Value = serde_json::from_slice(anchors.as_bytes()).unwrap();
    assert_eq!(saved["version"], 1);
    saved["vault_wraps"] = serde_json::Value::Null;
    local.insert_personal_admission(&fixture.record, &serde_json::to_vec(&saved).unwrap()).unwrap();
    drop(local);
    let reopened = store(&dir);
    assert_eq!(
        PersonalServer::default().status(&reopened).unwrap().phase,
        PersonalServerPhase::AuthenticationRequired
    );
    let record = reopened.personal_record().unwrap().unwrap();
    assert!(retained::RetainedAccount::load(&reopened, &record).unwrap().vault_wraps.is_none());
    assert_eq!(record.private_material.as_bytes(), fixture.record.private_material.as_bytes());
}

#[tokio::test]
async fn historical_session_flags_and_unbounded_archives_cannot_install_admission_or_send_auth() {
    let server = Fixture::new().await;
    for oversized in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let local = store(&dir);
        let fixture = fixture_profile(&local, &server.origin, false);
        let conn = database(&dir);
        conn.pragma_update(None, "ignore_check_constraints", "ON").unwrap();
        let sizes = if oversized { (1_048_577, 4_456_409) } else { (1, 1) };
        conn.execute(
            "UPDATE personal_server SET enrollment_request=zeroblob(?1),
            paired_handoff=zeroblob(?2), enrollment_attempted=1, session_established=1,
            recovery_saved=1, recovery_confirmed=1",
            rusqlite::params![sizes.0, sizes.1],
        )
        .unwrap();
        let version: i64 = conn.pragma_query_value(None, "data_version", |r| r.get(0)).unwrap();
        let manager = server.manager();
        assert_eq!(
            manager.status(&local).unwrap().phase,
            PersonalServerPhase::RevalidationRequired
        );
        assert_eq!(
            manager.authenticate(local.clone()).await,
            Err(PersonalServerError::RetiredEntry)
        );
        assert_eq!(admission_count(&dir), 0);
        assert_eq!(
            local.personal_record().unwrap().unwrap().private_material.as_bytes(),
            fixture.record.private_material.as_bytes()
        );
        let after: (i64, i64) = conn
            .query_row(
                "SELECT length(enrollment_request),length(paired_handoff) FROM personal_server",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(after, (i64::from(sizes.0), i64::from(sizes.1)));
        assert_eq!(
            conn.pragma_query_value(None, "data_version", |r| r.get::<_, i64>(0)).unwrap(),
            version
        );
    }
    assert_eq!(server.state.challenges.load(Ordering::SeqCst), 0);
    assert_eq!(server.state.device_exchanges.load(Ordering::SeqCst), 0);
}

#[test]
fn invalid_retained_keys_and_invalid_neutral_anchors_fail_closed() {
    for fault in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let local = store(&dir);
        let fixture = fixture_profile(&local, "https://example.test", false);
        let conn = database(&dir);
        conn.execute("UPDATE personal_server SET enrollment_request=X'ff'", []).unwrap();
        match fault {
            0 => {
                conn.execute("UPDATE device_key_pair SET signing=?1", [vec![3; 32]]).unwrap();
            }
            1 => {
                conn.execute("UPDATE personal_server SET private_material=zeroblob(226)", [])
                    .unwrap();
            }
            _ => {
                local.insert_personal_admission(&fixture.record, b"invalid anchors").unwrap();
            }
        }
        let version: i64 = conn.pragma_query_value(None, "data_version", |r| r.get(0)).unwrap();
        assert_eq!(
            PersonalServer::default().status(&local).unwrap_err(),
            PersonalServerError::AdmissionUnverified
        );
        assert_eq!(admission_count(&dir), i64::from(fault == 2));
        assert_eq!(
            conn.pragma_query_value(None, "data_version", |r| r.get::<_, i64>(0)).unwrap(),
            version
        );
        let archive: Vec<u8> = conn
            .query_row("SELECT enrollment_request FROM personal_server", [], |r| r.get(0))
            .unwrap();
        assert_eq!(archive, [255]);
    }
}

#[test]
fn an_orphaned_archived_entry_reports_retirement_without_decoding_its_payload() {
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    let conn = database(&dir);
    conn.pragma_update(None, "ignore_check_constraints", "ON").unwrap();
    conn.execute(
        "INSERT INTO personal_pairing (singleton,generation,side,origin,pairing_id,
        expires_at,local_expires_at,attempt_started,phase,transcript,certificate)
        VALUES (1,1,2,'https://example.test',randomblob(16),1,1,1,'completed',
        zeroblob(8388609),zeroblob(65537))",
        [],
    )
    .unwrap();
    let version: i64 = conn.pragma_query_value(None, "data_version", |r| r.get(0)).unwrap();
    assert_eq!(
        PersonalServer::default().status(&local).unwrap().phase,
        PersonalServerPhase::RetiredEntry
    );
    assert_eq!(admission_count(&dir), 0);
    assert_eq!(
        conn.pragma_query_value(None, "data_version", |r| r.get::<_, i64>(0)).unwrap(),
        version
    );
}

#[test]
fn admitted_account_origin_vault_device_and_secret_ownership_are_immutable() {
    let dir = tempfile::tempdir().unwrap();
    let local = store(&dir);
    fixture_profile(&local, "https://example.test", true);
    PersonalServer::default().status(&local).unwrap();
    let conn = database(&dir);
    for statement in [
        "UPDATE personal_server SET origin='https://other.test'",
        "UPDATE personal_server SET account_id=randomblob(16)",
        "UPDATE personal_server SET personal_vault_id=randomblob(16)",
        "UPDATE personal_server SET private_material=randomblob(225)",
        "DELETE FROM personal_server",
        "DELETE FROM device",
        "DELETE FROM device_key_pair",
        "UPDATE device SET device_id=randomblob(16)",
        "UPDATE device_key_pair SET signing=randomblob(32)",
        "UPDATE device_key_pair SET kem=randomblob(32)",
        "UPDATE personal_admission SET anchors=X'ff'",
        "DELETE FROM personal_admission",
        "INSERT OR REPLACE INTO personal_admission SELECT * FROM personal_admission",
        "INSERT OR REPLACE INTO personal_server SELECT * FROM personal_server",
        "INSERT OR REPLACE INTO device SELECT singleton,randomblob(16),clock,created_at FROM device",
        "INSERT OR REPLACE INTO device_key_pair SELECT singleton,randomblob(32),kem,created_at FROM device_key_pair",
    ] {
        assert!(conn.execute(statement, []).is_err(), "{statement}");
    }
    let mut foreign = local.personal_record().unwrap().unwrap();
    foreign.origin = "https://other.test".into();
    assert!(local.begin_personal_authentication(&foreign).is_err());
    assert!(local.claim_personal_refresh(&foreign, 0).is_err());
}
