// SPDX-License-Identifier: Apache-2.0
//! Bounded, offline read conversion of already confirmed historical identities.

use scoplen_api::{
    personal_enrollment::PersonalEnrollmentRequest,
    sync::{SyncVaultKey, SyncVaultKeysResponse},
};
use scoplen_crypto::{
    AccountKemKeyPair, AccountKemKeyWrap, AccountSigningKeyWrap, DeviceArkWrap, DeviceCertificate,
    DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey, PairingApplicationContext, PairingContext,
    PairingHandoff, PairingKeyProjection, PersonalEnrollmentArtifacts, PersonalEnrollmentContext,
    PersonalVaultKeyWrap, RecoveryBlob, RecoveryKey, SecretVec, SymmetricKey, ed25519_verify,
    pairing_key_anchor,
};
use zeroize::Zeroize as _;

use super::super::{identity::Secrets, storage};
use super::{
    Anchors, PersonalServerError, RetainedAccount, artifacts_anchor, digest, projection_anchor,
    vault_key_anchor,
};
use crate::store::{
    Store,
    personal::{PairingRecord, PersonalRecord},
};

struct LegacyAccount {
    pub signing_public: [u8; 32],
    pub kem_public: [u8; 32],
    pub certificate: DeviceCertificate,
    pub revision: u64,
    pub anchor: [u8; 32],
    pub account_signing_key: Vec<u8>,
    pub account_kem_key: Vec<u8>,
    pub recovery_blob: Vec<u8>,
    pub vault_keys: SyncVaultKeysResponse,
    pub invitation: bool,
    pub wrapped_ark: Vec<u8>,
}

fn invalid(_: impl std::fmt::Debug) -> PersonalServerError {
    PersonalServerError::AdmissionUnverified
}

impl LegacyAccount {
    pub fn load(store: &Store, identity: &PersonalRecord) -> Result<Self, PersonalServerError> {
        if identity.enrollment_request.as_ref().is_some_and(|v| {
            v.len() > scoplen_api::personal_enrollment::MAX_PERSONAL_ENROLLMENT_REQUEST_BYTES
        }) || identity.paired_handoff.as_ref().is_some_and(|v| v.len() > 4_456_408)
        {
            return Err(PersonalServerError::AdmissionUnverified);
        }
        let value = match (&identity.enrollment_request, &identity.paired_handoff) {
            (Some(encoded), None) => {
                let mut enrollment =
                    PersonalEnrollmentRequest::from_json(encoded.as_bytes()).map_err(invalid)?;
                if enrollment.account_id != identity.account_id
                    || enrollment.personal_vault_id != identity.personal_vault_id
                {
                    return Err(PersonalServerError::AdmissionUnverified);
                }
                let proof = PersonalEnrollmentContext::new(
                    &identity.origin,
                    &enrollment.invitation_token,
                    enrollment.account_id,
                    enrollment.personal_vault_id,
                    PersonalEnrollmentArtifacts {
                        account_signing_public_key: &enrollment.account_signing_public_key,
                        account_kem_public_key: &enrollment.account_kem_public_key,
                        key_bundle_update: &enrollment
                            .key_bundle_update
                            .to_cbor()
                            .map_err(invalid)?,
                        device_certificate: &enrollment
                            .device_certificate
                            .encode()
                            .map_err(invalid)?,
                        wrapped_personal_vault_key: &enrollment.wrapped_personal_vault_key,
                    },
                )
                .map_err(invalid)?;
                enrollment.invitation_token.zeroize();
                proof
                    .verify(
                        &enrollment.device_certificate.signing_public_key,
                        &enrollment.device_signature,
                    )
                    .map_err(invalid)?;
                ed25519_verify(
                    &enrollment.account_signing_public_key,
                    &enrollment.key_bundle_update.signature_input().map_err(invalid)?,
                    &enrollment.key_bundle_update.signature,
                )
                .map_err(invalid)?;
                let bundle = enrollment.key_bundle_update;
                let own = bundle
                    .device_wraps
                    .iter()
                    .find(|wrap| wrap.device_id == store.device_id())
                    .ok_or(PersonalServerError::AdmissionUnverified)?;
                let wrapped_ark = own.wrapped_ark.clone();
                Self {
                    signing_public: enrollment.account_signing_public_key,
                    kem_public: enrollment.account_kem_public_key,
                    certificate: enrollment.device_certificate,
                    revision: bundle.revision,
                    anchor: pairing_key_anchor(PairingKeyProjection {
                        revision: bundle.revision,
                        wrapped_ark: &own.wrapped_ark,
                        account_signing_key: &bundle.account_signing_key,
                        account_kem_key: &bundle.account_kem_key,
                        recovery_blob: &bundle.recovery_blob,
                    })
                    .map_err(invalid)?,
                    account_signing_key: bundle.account_signing_key,
                    account_kem_key: bundle.account_kem_key,
                    recovery_blob: bundle.recovery_blob,
                    vault_keys: SyncVaultKeysResponse {
                        keys: vec![SyncVaultKey {
                            epoch: 1,
                            wrapped_vault_key: enrollment.wrapped_personal_vault_key,
                        }],
                    },
                    invitation: true,
                    wrapped_ark,
                }
            }
            (None, Some(encoded)) => {
                let handoff = PairingHandoff::decode(encoded.as_bytes()).map_err(invalid)?;
                if handoff.context.origin() != identity.origin
                    || handoff.context.pairing().responder_device_id() != store.device_id()
                    || handoff.account_id != identity.account_id
                    || handoff.personal_vault_id != identity.personal_vault_id
                    || identity.enrollment_attempted
                {
                    return Err(PersonalServerError::AdmissionUnverified);
                }
                Self {
                    signing_public: handoff.account_signing_public_key,
                    kem_public: handoff.account_kem_public_key,
                    certificate: DeviceCertificate::decode(&handoff.device_certificate)
                        .map_err(invalid)?,
                    revision: handoff.revision,
                    anchor: handoff.key_anchor,
                    account_signing_key: handoff.account_signing_key,
                    account_kem_key: handoff.account_kem_key,
                    recovery_blob: handoff.recovery_blob,
                    vault_keys: SyncVaultKeysResponse::from_cbor(&handoff.personal_vault_keys)
                        .map_err(invalid)?,
                    invitation: false,
                    wrapped_ark: handoff.wrapped_ark,
                }
            }
            _ => return Err(PersonalServerError::AdmissionUnverified),
        };
        let secrets = Secrets::parse(&identity.private_material).map_err(invalid)?;
        let signing = P256SigningKey::from_bytes(secrets.signing()).map_err(invalid)?;
        let kem = DeviceKemKeyPair::from_private_bytes(secrets.device_kem()).map_err(invalid)?;
        let device = store
            .device_key_pair()
            .map_err(invalid)?
            .ok_or(PersonalServerError::AdmissionUnverified)?;
        if value.certificate.device_id != store.device_id()
            || value.certificate.account_id != identity.account_id
            || value.certificate.signing_public_key != signing.public_key_sec1()
            || value.certificate.kem_public_key != kem.public_key()
            || device.signing.as_bytes() != secrets.signing()
            || device.kem.as_bytes() != secrets.device_kem()
            || Ed25519SigningKey::from_bytes(secrets.account_signing())
                .map_err(invalid)?
                .public_key()
                != value.signing_public
            || AccountKemKeyPair::from_private_bytes(secrets.account_kem())
                .map_err(invalid)?
                .public_key()
                != value.kem_public
            || value.invitation != secrets.recovery().is_some()
        {
            return Err(PersonalServerError::AdmissionUnverified);
        }
        value.certificate.verify(&value.signing_public).map_err(invalid)?;
        Ok(value)
    }

    pub fn open_vault_keys(
        &self,
        identity: &PersonalRecord,
        ark: &SymmetricKey,
    ) -> Result<std::collections::BTreeMap<u32, SymmetricKey>, PersonalServerError> {
        self.vault_keys
            .keys
            .iter()
            .map(|key| {
                let epoch = u32::try_from(key.epoch).map_err(invalid)?;
                let opened = PersonalVaultKeyWrap::decode(&key.wrapped_vault_key)
                    .map_err(invalid)?
                    .open(identity.account_id, identity.personal_vault_id, epoch, ark)
                    .map_err(invalid)?;
                Ok((epoch, opened))
            })
            .collect()
    }
}

pub(super) fn convert(
    store: &Store,
    identity: &PersonalRecord,
) -> Result<SecretVec, PersonalServerError> {
    let snapshot = store.personal_sync_record().map_err(storage)?;
    let completed = completed_pairing(store, identity)?;
    if !identity.session_established && snapshot.is_none() && completed.is_none() {
        return Err(PersonalServerError::RetiredEntry);
    }
    let legacy = LegacyAccount::load(store, identity)
        .map_err(|_| PersonalServerError::AdmissionUnverified)?;
    if pairing_key_anchor(PairingKeyProjection {
        revision: legacy.revision,
        wrapped_ark: &legacy.wrapped_ark,
        account_signing_key: &legacy.account_signing_key,
        account_kem_key: &legacy.account_kem_key,
        recovery_blob: &legacy.recovery_blob,
    })
    .map_err(invalid)?
        != legacy.anchor
    {
        return Err(PersonalServerError::AdmissionUnverified);
    }
    let secrets = Secrets::parse(&identity.private_material).map_err(invalid)?;
    let kem = DeviceKemKeyPair::from_private_bytes(secrets.device_kem()).map_err(invalid)?;
    let ark = DeviceArkWrap::decode(&legacy.wrapped_ark)
        .map_err(invalid)?
        .open(identity.account_id, store.device_id(), &kem)
        .map_err(invalid)?;
    let signing = AccountSigningKeyWrap::decode(&legacy.account_signing_key)
        .map_err(invalid)?
        .open(identity.account_id, &ark, &legacy.signing_public)
        .map_err(invalid)?;
    let account_kem = AccountKemKeyWrap::decode(&legacy.account_kem_key)
        .map_err(invalid)?
        .open(identity.account_id, &ark, &legacy.kem_public)
        .map_err(invalid)?;
    let keys = legacy.open_vault_keys(identity, &ark)?;
    let (current_epoch, current) =
        keys.last_key_value().ok_or(PersonalServerError::AdmissionUnverified)?;
    if ark.as_bytes() != secrets.ark()
        || signing.private_key_bytes().as_bytes() != secrets.account_signing()
        || account_kem.private_key_bytes().as_bytes() != secrets.account_kem()
        || current.as_bytes() != secrets.vault()
    {
        return Err(PersonalServerError::AdmissionUnverified);
    }
    if let Some(recovery) = secrets.recovery() {
        let recovery = RecoveryKey::from_bytes(recovery).map_err(invalid)?;
        if RecoveryBlob::decode(&legacy.recovery_blob)
            .map_err(invalid)?
            .open(&recovery, identity.account_id)
            .map_err(invalid)?
            != ark
        {
            return Err(PersonalServerError::AdmissionUnverified);
        }
    }
    let anchors = Anchors {
        version: 1,
        signing_public: legacy.signing_public,
        kem_public: legacy.kem_public,
        certificate: legacy.certificate.encode().map_err(invalid)?,
        revision: legacy.revision,
        projection: projection_anchor(
            legacy.revision,
            &legacy.wrapped_ark,
            &legacy.account_signing_key,
            &legacy.account_kem_key,
            &legacy.recovery_blob,
        ),
        artifacts: artifacts_anchor(
            &legacy.account_signing_key,
            &legacy.account_kem_key,
            &legacy.recovery_blob,
        ),
        vault_keys: vault_key_anchor(&keys),
        vault_wraps: if legacy.invitation {
            Some(digest(
                b"scoplen-client-personal-wraps-v1",
                &[&legacy.vault_keys.to_cbor().map_err(invalid)?],
            ))
        } else {
            None
        },
        current_epoch: *current_epoch,
    };
    let encoded = SecretVec::new(serde_json::to_vec(&anchors).map_err(invalid)?);
    let retained = RetainedAccount::from_anchors(anchors)?;
    retained.verify_identity(store, identity)?;
    if let Some(snapshot) = &snapshot {
        super::super::sync::validate_against(store, identity, snapshot, None, &retained, false)
            .map_err(|_| PersonalServerError::AdmissionUnverified)?;
    }
    if !store
        .save_personal_admission(
            identity,
            encoded.as_bytes(),
            snapshot.as_ref(),
            completed.as_ref(),
        )
        .map_err(storage)?
    {
        return store
            .personal_admission(identity)
            .map_err(storage)?
            .ok_or(PersonalServerError::Busy);
    }
    Ok(encoded)
}

fn completed_pairing(
    store: &Store,
    identity: &PersonalRecord,
) -> Result<Option<PairingRecord>, PersonalServerError> {
    let Some(encoded) = &identity.paired_handoff else { return Ok(None) };
    if encoded.len() > 4_456_408 {
        return Err(PersonalServerError::AdmissionUnverified);
    }
    let Some(checkpoint) = store.pairing_record().map_err(storage)? else { return Ok(None) };
    if checkpoint.side != 2
        || checkpoint.phase != "completed"
        || checkpoint.origin != identity.origin
    {
        return Ok(None);
    }
    let handoff = PairingHandoff::decode(encoded.as_bytes()).map_err(invalid)?;
    let context = PairingApplicationContext::new(
        &checkpoint.origin,
        PairingContext::new(
            checkpoint.pairing_id,
            checkpoint.peer_id.ok_or(PersonalServerError::AdmissionUnverified)?,
            store.device_id(),
        )
        .map_err(invalid)?,
    )
    .map_err(invalid)?;
    Ok((handoff.context == context
        && checkpoint
            .certificate
            .as_ref()
            .is_some_and(|cert| cert.as_bytes() == handoff.device_certificate))
    .then_some(checkpoint))
}
