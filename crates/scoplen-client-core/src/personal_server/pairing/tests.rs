// SPDX-License-Identifier: Apache-2.0

use scoplen_api::sync::SyncVaultKey;
use scoplen_crypto::generate_account_keys;

use super::*;

fn fixture() -> (tempfile::TempDir, Store, PairingRecord, PairingHandoff, Ed25519SigningKey) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("pairing.db"), &SymmetricKey::new([31; 32])).unwrap();
    let keys = generate_device_keys().unwrap();
    let device = PairingDeviceRecord {
        origin: "https://sync.example".into(),
        device_name: "New desktop".into(),
        signing: SecretVec::new(keys.signing.private_key_bytes().as_bytes().to_vec()),
        kem: SecretVec::new(keys.kem.private_key_bytes().as_bytes().to_vec()),
        created_at: 12345,
    };
    assert!(store.insert_pairing_device(&device).unwrap());
    let pending = PairingRecord {
        generation: 0,
        side: 2,
        origin: device.origin.clone(),
        pairing_id: scoplen_model::new_uuid_v7().unwrap(),
        peer_id: Some(scoplen_model::new_uuid_v7().unwrap()),
        expires_at: now().unwrap() + 1000,
        local_expires_at: now().unwrap() + 300,
        attempt_started: false,
        phase: "exchanging".into(),
        capability: Some(SecretVec::new(vec![43; 32])),
        transcript: encoded_transcript(&[]).unwrap(),
        certificate: None,
        key_update: None,
        handoff: None,
        acceptance: None,
        approval_request: None,
    };
    assert!(store.save_pairing(None, &pending).unwrap());
    let pending = store.pairing_record().unwrap().unwrap();
    assert!(store.claim_pairing_attempt(&pending).unwrap());
    let pending = store.pairing_record().unwrap().unwrap();
    let account = generate_account_keys().unwrap();
    let account_id = scoplen_model::new_uuid_v7().unwrap();
    let personal_vault_id = scoplen_model::new_uuid_v7().unwrap();
    let ark = SymmetricKey::new([66; 32]);
    let certificate = DeviceCertificate::issue(
        &account.signing,
        store.device_id(),
        account_id,
        keys.signing.public_key_sec1(),
        keys.kem.public_key().to_vec(),
        device.device_name,
        std::env::consts::OS.into(),
        device.created_at,
    )
    .unwrap();
    let keys = SyncVaultKeysResponse {
        keys: [1, 2]
            .into_iter()
            .map(|epoch| SyncVaultKey {
                epoch,
                wrapped_vault_key: PersonalVaultKeyWrap::seal(
                    account_id,
                    personal_vault_id,
                    epoch as u32,
                    &ark,
                    &SymmetricKey::new([epoch as u8; 32]),
                )
                .unwrap()
                .encode()
                .to_vec(),
            })
            .collect(),
    };
    let mut handoff = PairingHandoff {
        context: crypto_context(&store, &pending).unwrap(),
        account_id,
        personal_vault_id,
        account_signing_public_key: account.signing.public_key(),
        account_kem_public_key: account.kem.public_key().try_into().unwrap(),
        device_certificate: certificate.encode().unwrap(),
        revision: 12,
        key_bundle_update_hash: [7; 32],
        key_anchor: [0; 32],
        wrapped_ark: DeviceArkWrap::seal(
            account_id,
            store.device_id(),
            &certificate.kem_public_key,
            &ark,
        )
        .unwrap()
        .encode()
        .to_vec(),
        account_signing_key: AccountSigningKeyWrap::seal(account_id, &ark, &account.signing)
            .unwrap()
            .encode()
            .to_vec(),
        account_kem_key: AccountKemKeyWrap::seal(account_id, &ark, &account.kem)
            .unwrap()
            .encode()
            .to_vec(),
        recovery_blob: vec![8],
        personal_vault_keys: keys.to_cbor().unwrap(),
    };
    handoff.key_anchor = pairing_key_anchor(handoff.projection()).unwrap();
    let handoff = PairingHandoff::decode(handoff.encode().unwrap().as_bytes()).unwrap();
    (dir, store, pending, handoff, account.signing)
}

#[test]
fn every_personal_epoch_opens_before_identity_and_no_recovery_key_is_invented() {
    let (_dir, store, pending, mut handoff, _account) = fixture();
    let (identity, _) = accepted_identity(&store, &pending, &handoff).unwrap();
    let secrets = identity::Secrets::parse(&identity.private_material).unwrap();
    assert_eq!(secrets.vault(), &[2; 32]);
    assert!(secrets.recovery().is_none());
    assert!(identity.enrollment_request.is_none());
    assert!(!identity.enrollment_attempted);
    assert!(identity.paired_handoff.is_some());
    let mut keys = SyncVaultKeysResponse::from_cbor(&handoff.personal_vault_keys).unwrap();
    keys.keys[0].wrapped_vault_key[40] ^= 1;
    handoff.personal_vault_keys = keys.to_cbor().unwrap();
    let decoded = PairingHandoff::decode(handoff.encode().unwrap().as_bytes()).unwrap();
    assert!(matches!(
        accepted_identity(&store, &pending, &decoded),
        Err(PairingError::InvalidResponse)
    ));
    assert!(store.personal_record().unwrap().is_none());
}

#[test]
fn authenticated_certificate_claims_and_account_roots_must_match_retained_keys() {
    let (_dir, store, pending, mut handoff, account) = fixture();
    let original = handoff.encode().unwrap();
    for claim in 0..4 {
        let mut cert = DeviceCertificate::decode(&handoff.device_certificate).unwrap();
        match claim {
            0 => cert.display_name = "Changed name".into(),
            1 => cert.platform = "Changed platform".into(),
            2 => cert.created_at += 1,
            _ => cert.kem_public_key = generate_device_keys().unwrap().kem.public_key().to_vec(),
        }
        cert = DeviceCertificate::issue(
            &account,
            cert.device_id,
            cert.account_id,
            cert.signing_public_key,
            cert.kem_public_key,
            cert.display_name,
            cert.platform,
            cert.created_at,
        )
        .unwrap();
        handoff.device_certificate = cert.encode().unwrap();
        let decoded = PairingHandoff::decode(handoff.encode().unwrap().as_bytes()).unwrap();
        assert!(matches!(
            accepted_identity(&store, &pending, &decoded),
            Err(PairingError::InvalidResponse)
        ));
        handoff = PairingHandoff::decode(original.as_bytes()).unwrap();
    }
    handoff.account_kem_public_key =
        generate_account_keys().unwrap().kem.public_key().try_into().unwrap();
    let decoded = PairingHandoff::decode(handoff.encode().unwrap().as_bytes()).unwrap();
    assert!(matches!(
        accepted_identity(&store, &pending, &decoded),
        Err(PairingError::InvalidResponse)
    ));
    assert!(store.personal_record().unwrap().is_none());
}

#[test]
fn server_expiry_never_extends_local_monotonic_ceiling() {
    let started = Instant::now();
    let deadline = bounded_deadline(started, now().unwrap() + 10000).unwrap();
    assert!(deadline <= started + Duration::from_secs(300));
    assert_eq!(
        bounded_deadline(started, now().unwrap().saturating_sub(1)),
        Err(PairingError::Expired)
    );
}
