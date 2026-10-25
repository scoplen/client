// SPDX-License-Identifier: Apache-2.0
//! Public Rust preparation surface with real D-127 work and independently opened artifacts.

use std::sync::{Mutex, MutexGuard};

use scoplen_crypto::SecretBytes;

use super::*;
use crate::testing::MemoryKeystore;

static SERIAL: Mutex<()> = Mutex::new(());
const PASSWORD: &[u8] = b"a real account password";

struct Fixture {
    server: PersonalServer,
    local: LocalData,
    store: Arc<Store>,
    keys: MemoryKeystore,
    status: RegistrationStatus,
    _serial: MutexGuard<'static, ()>,
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let keys = MemoryKeystore::default();
        let local = LocalData::start(dir.path(), Some(Box::new(keys.clone()))).unwrap();
        let store = local.store().unwrap();
        let server = PersonalServer::default();
        let status = server
            .prepare_registration(
                &local,
                &store,
                "https://account.example",
                "alice",
                "Desktop",
                SecretVec::new(PASSWORD.to_vec()),
            )
            .unwrap();
        Self { server, local, store, keys, status, _serial: serial, dir }
    }

    fn database(&self) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(self.dir.path().join("local.db")).unwrap();
        let slot = self.keys.0.lock().unwrap();
        let slot = slot.as_ref().unwrap();
        assert_eq!(slot[0], 1);
        let hex = Zeroizing::new(slot[1..].iter().map(|b| format!("{b:02x}")).collect::<String>());
        let pragma = Zeroizing::new(format!("x'{}'", hex.as_str()));
        conn.pragma_update(None, "key", pragma.as_str()).unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        conn
    }

    fn ready(&self) {
        self.server
            .save_registration_recovery(
                &self.local,
                &self.store,
                self.status.operation_id,
                &self.dir.path().join("recovery.txt"),
            )
            .unwrap();
        assert_eq!(
            self.server
                .confirm_registration_recovery(&self.local, &self.store, self.status.operation_id)
                .unwrap()
                .phase,
            RegistrationPhase::Ready
        );
    }

    fn request(&self, n: u8) -> AccountRegistrationRequest {
        let requested = self
            .server
            .registration_challenge(&self.local, &self.store, self.status.operation_id)
            .unwrap();
        self.server.registration_request(&self.local, &self.store, &requested, fresh(n)).unwrap()
    }

    fn confirmation(&self) -> AccountCommittedConfirmation {
        let record = self.store.pending_registration().unwrap().unwrap();
        AccountCommittedConfirmation {
            kind: AccountRequestKind::Register,
            operation_id: self.status.operation_id,
            request_digest: signature_input(&record)
                .unwrap()
                .request_digest(&record.account_signature),
            account_id: self.status.account_id,
            personal_vault_id: self.status.personal_vault_id,
            device_id: self.status.device_id,
            admitted_key_revision: 1,
        }
    }
}

fn fresh(n: u8) -> AccountRequestChallengeResponse {
    AccountRequestChallengeResponse {
        attempt_id: SecretBytes::new([n; 32]),
        nonce: SecretBytes::new([n + 1; 32]),
        expires_at_ms: now_ms().unwrap() + 120_000,
    }
}

#[test]
fn public_preparation_uses_real_password_derivation_and_opens_every_original_wrapper() {
    let f = Fixture::new();
    assert_eq!(f.status.phase, RegistrationPhase::RecoveryRequired);
    assert_ne!(f.status.device_id, f.store.device_id());
    let record = f.store.pending_registration().unwrap().unwrap();
    let p = AccountRegistrationPayload::from_cbor(record.payload.as_bytes()).unwrap();
    let bundle = SyncAccountKeyBundleUpdate::from_cbor(&p.key_bundle).unwrap();
    let context = PasswordKdfContext::new(&p.origin, &p.username, 1, &p.password_salt).unwrap();
    let derived = context.derive(SecretVec::new(PASSWORD.to_vec())).unwrap();
    assert_eq!(derived.verifier().as_bytes(), &p.verifier);
    let context = PasswordBootstrapContext::new(
        context,
        p.account_id,
        p.personal_vault_id,
        &p.account_signing_public_key,
        &p.account_kem_public_key,
        1,
    )
    .unwrap();
    let opened = derived
        .open_bootstrap(
            &context,
            &PasswordArkWrap::decode(&p.password_ark).unwrap(),
            &AccountSigningKeyWrap::decode(&bundle.account_signing_key).unwrap(),
            &AccountKemKeyWrap::decode(&bundle.account_kem_key).unwrap(),
        )
        .unwrap();
    let secrets = Secrets::parse(&record.private_material).unwrap();
    assert_eq!(opened.ark().as_bytes(), secrets.ark());
    assert_eq!(opened.keys().signing.public_key(), p.account_signing_public_key);
    assert_eq!(opened.keys().kem.public_key(), p.account_kem_public_key);
    let recovery = RecoveryKey::from_bytes(secrets.recovery().unwrap()).unwrap();
    assert_eq!(
        RecoveryBlob::decode(&bundle.recovery_blob).unwrap().open(&recovery, p.account_id).unwrap(),
        *opened.ark()
    );
    let device = DeviceKemKeyPair::from_private_bytes(secrets.device_kem()).unwrap();
    assert_eq!(
        DeviceArkWrap::decode(&bundle.device_wraps[0].wrapped_ark)
            .unwrap()
            .open(p.account_id, p.device_id, &device)
            .unwrap(),
        *opened.ark()
    );
    assert_eq!(
        PersonalVaultKeyWrap::decode(&p.personal_wrapped_key)
            .unwrap()
            .open(p.account_id, p.personal_vault_id, 1, opened.ark())
            .unwrap()
            .as_bytes(),
        secrets.vault()
    );
    assert!(
        context
            .derive_and_open(
                SecretVec::new(b"a different account password".to_vec()),
                &p.password_ark,
                &bundle.account_signing_key,
                &bundle.account_kem_key
            )
            .is_err()
    );
    assert_eq!(format!("{record:?}"), "RegistrationRecord([REDACTED])");
    assert!(f.store.personal_record().unwrap().is_none());
    assert!(f.store.device_key_pair().unwrap().is_none());
    assert!(f.store.personal_sync_record().unwrap().is_none());
    assert!(f.server.load_sync_bootstrap(&f.store).unwrap().is_none());
}

#[test]
fn recovery_save_is_create_new_and_confirmation_requires_a_completed_export() {
    let f = Fixture::new();
    assert_eq!(
        f.server.confirm_registration_recovery(&f.local, &f.store, f.status.operation_id),
        Err(RegistrationError::RecoveryRequired)
    );
    assert_eq!(
        f.server.registration_challenge(&f.local, &f.store, f.status.operation_id),
        Err(RegistrationError::RecoveryRequired)
    );
    let path = f.dir.path().join("occupied.txt");
    std::fs::write(&path, b"user-owned").unwrap();
    assert_eq!(
        f.server.save_registration_recovery(&f.local, &f.store, f.status.operation_id, &path),
        Err(RegistrationError::RecoverySave)
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"user-owned");
    assert!(!f.server.registration_status(&f.local, &f.store).unwrap().unwrap().recovery_saved);
    f.ready();
    let contents =
        Zeroizing::new(std::fs::read_to_string(f.dir.path().join("recovery.txt")).unwrap());
    let displayed = contents.lines().find(|line| line.starts_with("SPL1-")).unwrap();
    let key = RecoveryKey::parse_display(displayed).unwrap();
    let retained = f.store.pending_registration().unwrap().unwrap();
    assert_eq!(
        key.as_bytes(),
        Secrets::parse(&retained.private_material).unwrap().recovery().unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(f.dir.path().join("recovery.txt")).unwrap().permissions().mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn a_failed_saved_marker_keeps_recovery_unconfirmed_and_does_not_overwrite_the_export() {
    let f = Fixture::new();
    let db = f.database();
    db.execute_batch("CREATE TRIGGER fail_save BEFORE UPDATE ON personal_registration BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    let path = f.dir.path().join("flushed.txt");
    assert_eq!(
        f.server.save_registration_recovery(&f.local, &f.store, f.status.operation_id, &path),
        Err(RegistrationError::Storage)
    );
    assert!(path.is_file());
    let record = f.store.pending_registration().unwrap().unwrap();
    assert!(!record.recovery_saved);
    assert!(!record.recovery_confirmed);
    db.execute_batch("DROP TRIGGER fail_save").unwrap();
    assert_eq!(
        f.server.save_registration_recovery(&f.local, &f.store, f.status.operation_id, &path),
        Err(RegistrationError::RecoverySave)
    );
    f.ready();
}

#[test]
fn request_handoff_is_durable_unknown_and_restart_uses_fresh_confirm_with_identical_business_bytes()
{
    let f = Fixture::new();
    f.ready();
    let first = f.request(1);
    assert_eq!(first.intent, AccountRequestIntent::Submit);
    let reopened = LocalData::start(f.dir.path(), Some(Box::new(f.keys.clone()))).unwrap();
    let reopened_store = reopened.store().unwrap();
    assert_eq!(
        f.server.registration_status(&reopened, &reopened_store).unwrap().unwrap().phase,
        RegistrationPhase::OutcomeUnknown
    );
    let requested =
        f.server.registration_challenge(&reopened, &reopened_store, f.status.operation_id).unwrap();
    assert_eq!(requested.intent, AccountRequestIntent::Confirm);
    let second =
        f.server.registration_request(&reopened, &reopened_store, &requested, fresh(3)).unwrap();
    assert_eq!(first.payload, second.payload);
    assert_eq!(first.account_signature, second.account_signature);
    assert_ne!(first.device_proof, second.device_proof);
    assert_eq!(
        first.verify_proof(&f.status.origin).unwrap(),
        second.verify_proof(&f.status.origin).unwrap()
    );
    let mut stale_submit = requested;
    stale_submit.intent = AccountRequestIntent::Submit;
    assert_eq!(
        f.server.registration_request(&reopened, &reopened_store, &stale_submit, fresh(5)),
        Err(RegistrationError::InvalidResponse)
    );
    assert_eq!(
        f.server.cancel_registration(&reopened, &reopened_store, f.status.operation_id),
        Err(RegistrationError::OutcomeUnknown)
    );
    assert!(
        f.server
            .record_registration_confirmation(
                &reopened,
                &reopened_store,
                f.status.operation_id,
                b"{}"
            )
            .is_err()
    );
    assert_eq!(
        f.server
            .registration_challenge(&reopened, &reopened_store, f.status.operation_id)
            .unwrap()
            .intent,
        AccountRequestIntent::Confirm
    );
    assert!(reopened_store.personal_record().unwrap().is_none());
    assert!(reopened_store.personal_access_token(0).unwrap().is_none());
}

#[test]
fn exact_confirmation_binds_every_field_and_grants_only_historical_outcome() {
    let f = Fixture::new();
    f.ready();
    f.request(7);
    for field in 0..7 {
        let mut result = f.confirmation();
        match field {
            0 => result.kind = AccountRequestKind::Admit,
            1 => result.operation_id = scoplen_model::new_uuid_v7().unwrap(),
            2 => result.request_digest[0] ^= 1,
            3 => result.account_id = scoplen_model::new_uuid_v7().unwrap(),
            4 => result.personal_vault_id = scoplen_model::new_uuid_v7().unwrap(),
            5 => result.device_id = scoplen_model::new_uuid_v7().unwrap(),
            _ => result.admitted_key_revision = 2,
        }
        assert_eq!(
            f.server.record_registration_confirmation(
                &f.local,
                &f.store,
                f.status.operation_id,
                &result.to_json().unwrap()
            ),
            Err(RegistrationError::InvalidResponse)
        );
    }
    let response = f.confirmation().to_json().unwrap();
    assert_eq!(
        f.server
            .record_registration_confirmation(&f.local, &f.store, f.status.operation_id, &response)
            .unwrap()
            .phase,
        RegistrationPhase::Committed
    );
    assert_eq!(
        f.server
            .record_registration_confirmation(&f.local, &f.store, f.status.operation_id, &response)
            .unwrap()
            .phase,
        RegistrationPhase::Committed
    );
    assert!(f.store.personal_record().unwrap().is_none());
    assert!(f.store.device_key_pair().unwrap().is_none());
    assert!(f.store.personal_sync_record().unwrap().is_none());
    assert_eq!(
        f.server.status(&f.store).unwrap().phase,
        super::super::PersonalServerPhase::NotConfigured
    );
    assert_eq!(
        f.database()
            .query_row("SELECT count(*) FROM personal_admission", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    let reopened = LocalData::start(f.dir.path(), Some(Box::new(f.keys.clone()))).unwrap();
    assert_eq!(
        f.server.registration_status(&reopened, &reopened.store().unwrap()).unwrap().unwrap().phase,
        RegistrationPhase::Committed
    );
}

#[test]
fn profile_generation_and_operation_id_fence_all_late_actions() {
    let f = Fixture::new();
    let other = LocalData::start(f.dir.path(), Some(Box::new(f.keys.clone()))).unwrap();
    assert_eq!(
        f.server.registration_status(&other, &f.store),
        Err(RegistrationError::ContextChanged)
    );
    let path = f.dir.path().join("late.txt");
    assert_eq!(
        f.server.save_registration_recovery(&other, &f.store, f.status.operation_id, &path),
        Err(RegistrationError::ContextChanged)
    );
    assert!(!path.exists());
    assert_eq!(
        f.server.save_registration_recovery(
            &f.local,
            &f.store,
            scoplen_model::new_uuid_v7().unwrap(),
            &path
        ),
        Err(RegistrationError::NotPrepared)
    );
    assert!(!path.exists());
    f.server.cancel_registration(&f.local, &f.store, f.status.operation_id).unwrap();
    assert!(f.server.registration_status(&f.local, &f.store).unwrap().is_none());
    assert!(
        f.server.confirm_registration_recovery(&f.local, &f.store, f.status.operation_id).is_err()
    );
}

#[test]
fn failed_dispatch_marker_returns_no_request_and_cannot_change_existing_identity_bytes() {
    let f = Fixture::new();
    f.ready();
    let db = f.database();
    db.execute_batch("CREATE TRIGGER fail_dispatch BEFORE UPDATE ON personal_registration BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    let requested =
        f.server.registration_challenge(&f.local, &f.store, f.status.operation_id).unwrap();
    let mut expired = fresh(8);
    expired.expires_at_ms = 1;
    assert_eq!(
        f.server.registration_request(&f.local, &f.store, &requested, expired),
        Err(RegistrationError::InvalidResponse)
    );
    assert_eq!(
        f.server.registration_request(&f.local, &f.store, &requested, fresh(8)),
        Err(RegistrationError::Storage)
    );
    assert_eq!(
        f.server.registration_status(&f.local, &f.store).unwrap().unwrap().phase,
        RegistrationPhase::Ready
    );
    db.execute_batch("DROP TRIGGER fail_dispatch").unwrap();
    for sql in [
        "UPDATE personal_registration SET payload=X'01'",
        "UPDATE personal_registration SET private_material=zeroblob(225)",
        "INSERT OR REPLACE INTO personal_registration SELECT * FROM personal_registration",
    ] {
        assert!(db.execute(sql, []).is_err());
    }
    f.request(9);
    for sql in [
        "DELETE FROM personal_registration",
        "UPDATE personal_registration SET phase=0",
        "UPDATE personal_registration SET recovery_confirmed=0",
    ] {
        assert!(db.execute(sql, []).is_err());
    }
}

#[test]
fn publicly_valid_but_inconsistent_wrappers_fail_before_any_request_or_recovery_export() {
    let f = Fixture::new();
    let db = f.database();
    db.execute_batch("DROP TRIGGER personal_registration_immutable").unwrap();
    let original = f.store.pending_registration().unwrap().unwrap();
    let p = AccountRegistrationPayload::from_cbor(original.payload.as_bytes()).unwrap();
    let s = Secrets::parse(&original.private_material).unwrap();
    let root = Ed25519SigningKey::from_bytes(s.account_signing()).unwrap();
    let other_ark = generate_symmetric_key().unwrap();
    let kem = DeviceKemKeyPair::from_private_bytes(s.device_kem()).unwrap();
    let account_kem = AccountKemKeyPair::from_private_bytes(s.account_kem()).unwrap();
    let recovery = RecoveryKey::from_bytes(s.recovery().unwrap()).unwrap();
    for field in 0..5 {
        let mut changed = p.clone();
        let mut bundle = SyncAccountKeyBundleUpdate::from_cbor(&p.key_bundle).unwrap();
        match field {
            0 => {
                bundle.device_wraps[0].wrapped_ark =
                    DeviceArkWrap::seal(p.account_id, p.device_id, kem.public_key(), &other_ark)
                        .unwrap()
                        .encode()
                        .to_vec()
            }
            1 => {
                bundle.recovery_blob = RecoveryBlob::wrap(&recovery, p.account_id, &other_ark)
                    .unwrap()
                    .encode()
                    .unwrap()
            }
            2 => {
                bundle.account_signing_key =
                    AccountSigningKeyWrap::seal(p.account_id, &other_ark, &root)
                        .unwrap()
                        .encode()
                        .to_vec()
            }
            3 => {
                bundle.account_kem_key =
                    AccountKemKeyWrap::seal(p.account_id, &other_ark, &account_kem)
                        .unwrap()
                        .encode()
                        .to_vec()
            }
            _ => {
                changed.personal_wrapped_key = PersonalVaultKeyWrap::seal(
                    p.account_id,
                    p.personal_vault_id,
                    1,
                    &other_ark,
                    &generate_symmetric_key().unwrap(),
                )
                .unwrap()
                .encode()
            }
        }
        bundle.signature = root.sign(&bundle.signature_input().unwrap()).to_vec();
        changed.key_bundle = bundle.to_cbor().unwrap();
        let payload = SecretVec::new(changed.to_cbor().unwrap());
        let signature =
            AccountRequestSignatureInput::new(AccountRequestKind::Register, payload.as_bytes())
                .unwrap()
                .sign(&root);
        db.execute(
            "UPDATE personal_registration SET payload=?1,account_signature=?2",
            rusqlite::params![payload.as_bytes(), signature.as_slice()],
        )
        .unwrap();
        assert_eq!(
            f.server.registration_status(&f.local, &f.store),
            Err(RegistrationError::Identity)
        );
        let path = f.dir.path().join(format!("invalid-{field}.txt"));
        assert_eq!(
            f.server.save_registration_recovery(&f.local, &f.store, p.operation_id, &path),
            Err(RegistrationError::Identity)
        );
        assert!(!path.exists());
    }
}

#[test]
fn existing_admitted_or_archived_material_is_preserved_before_password_work() {
    let f = Fixture::new();
    f.server.cancel_registration(&f.local, &f.store, f.status.operation_id).unwrap();
    let profile = super::super::tests::fixture_profile(&f.store, "https://retained.example", true);
    let db = f.database();
    db.execute("UPDATE personal_server SET enrollment_request=zeroblob(1048577)", []).unwrap();
    let before = f.store.personal_record().unwrap().unwrap();
    assert_eq!(
        f.server.prepare_registration(
            &f.local,
            &f.store,
            "https://account.example",
            "bob",
            "New",
            SecretVec::new(PASSWORD.to_vec())
        ),
        Err(RegistrationError::ExistingProfile)
    );
    assert_eq!(
        f.store.personal_record().unwrap().unwrap().private_material,
        before.private_material
    );
    assert_eq!(f.store.personal_record().unwrap().unwrap().account_id, profile.record.account_id);
    assert_eq!(
        db.query_row("SELECT length(enrollment_request) FROM personal_server", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1_048_577
    );
    assert!(f.server.registration_status(&f.local, &f.store).unwrap().is_none());
}

#[test]
fn failed_initial_transaction_leaves_no_partial_pending_identity() {
    let f = Fixture::new();
    f.server.cancel_registration(&f.local, &f.store, f.status.operation_id).unwrap();
    let db = f.database();
    db.execute_batch("CREATE TRIGGER fail_prepare BEFORE INSERT ON personal_registration BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    let original_device = f.store.device_id();
    assert_eq!(
        f.server.prepare_registration(
            &f.local,
            &f.store,
            "https://account.example",
            "bob",
            "New",
            SecretVec::new(PASSWORD.to_vec())
        ),
        Err(RegistrationError::Storage)
    );
    assert!(f.server.registration_status(&f.local, &f.store).unwrap().is_none());
    assert_eq!(f.store.device_id(), original_device);
    assert!(f.store.device_key_pair().unwrap().is_none());
}

#[test]
fn invalid_inputs_and_process_wide_kdf_admission_never_persist_state() {
    let f = Fixture::new();
    f.server.cancel_registration(&f.local, &f.store, f.status.operation_id).unwrap();
    for (origin, username, password) in [
        ("http://account.example", "alice", PASSWORD),
        ("https://account.example", "Alice", PASSWORD),
        ("https://account.example", "alice", b"short".as_slice()),
    ] {
        assert_eq!(
            f.server.prepare_registration(
                &f.local,
                &f.store,
                origin,
                username,
                "Desktop",
                SecretVec::new(password.to_vec())
            ),
            Err(RegistrationError::InvalidInput)
        );
        assert!(f.server.registration_status(&f.local, &f.store).unwrap().is_none());
    }
    let _gate = PASSWORD_DERIVATION.lock().unwrap();
    assert_eq!(
        PersonalServer::default().prepare_registration(
            &f.local,
            &f.store,
            "https://account.example",
            "alice",
            "Desktop",
            SecretVec::new(PASSWORD.to_vec())
        ),
        Err(RegistrationError::Busy)
    );
}

#[test]
fn oversized_or_corrupt_local_records_fail_closed_without_loading_or_replacing_them() {
    let f = Fixture::new();
    let db = f.database();
    db.execute_batch(
        "DROP TRIGGER personal_registration_immutable; DROP TRIGGER personal_registration_monotonic; PRAGMA ignore_check_constraints=ON;",
    )
    .unwrap();
    for (field, size) in [
        ("payload", 262_145),
        ("private_material", 226),
        ("account_signature", 65),
        ("confirmation", 1025),
    ] {
        let before = f.store.pending_registration().unwrap().unwrap();
        db.execute(&format!("UPDATE personal_registration SET {field}=zeroblob(?1)"), [size])
            .unwrap();
        assert_eq!(
            f.server.registration_status(&f.local, &f.store),
            Err(RegistrationError::Storage)
        );
        db.execute("UPDATE personal_registration SET payload=?1,private_material=?2,account_signature=?3,confirmation=NULL",
            rusqlite::params![before.payload.as_bytes(), before.private_material.as_bytes(),before.account_signature.as_slice()]).unwrap();
    }
    let record = f.store.pending_registration().unwrap().unwrap();
    let mut broken = Zeroizing::new(record.private_material.as_bytes().to_vec());
    broken[65] ^= 1;
    db.execute("UPDATE personal_registration SET private_material=?1", [broken.as_slice()])
        .unwrap();
    assert_eq!(f.server.registration_status(&f.local, &f.store), Err(RegistrationError::Identity));
}
