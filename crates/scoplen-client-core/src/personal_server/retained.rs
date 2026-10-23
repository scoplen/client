// SPDX-License-Identifier: Apache-2.0
//! One retained account trust boundary for invitation and authenticated pairing provenance.

use scoplen_api::{
    personal_enrollment::PersonalEnrollmentRequest,
    sync::{SyncVaultKey, SyncVaultKeysResponse},
};
use scoplen_crypto::{
    AccountKemKeyPair, DeviceCertificate, DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey,
    PairingHandoff, PairingKeyProjection, PersonalVaultKeyWrap, SymmetricKey, ed25519_verify,
    pairing_key_anchor,
};
use zeroize::Zeroize as _;

use super::{PersonalServerError, identity::Secrets};
use crate::store::{Store, personal::PersonalRecord};

pub(super) struct RetainedAccount {
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
}

fn invalid(_: impl std::fmt::Debug) -> PersonalServerError {
    PersonalServerError::Identity
}

impl RetainedAccount {
    pub fn load(store: &Store, identity: &PersonalRecord) -> Result<Self, PersonalServerError> {
        let value = match (&identity.enrollment_request, &identity.paired_handoff) {
            (Some(encoded), None) => {
                let mut enrollment =
                    PersonalEnrollmentRequest::from_json(encoded.as_bytes()).map_err(invalid)?;
                enrollment.invitation_token.zeroize();
                if enrollment.account_id != identity.account_id
                    || enrollment.personal_vault_id != identity.personal_vault_id
                {
                    return Err(PersonalServerError::Identity);
                }
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
                    .ok_or(PersonalServerError::Identity)?;
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
                    return Err(PersonalServerError::Identity);
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
                }
            }
            _ => return Err(PersonalServerError::Identity),
        };
        let secrets = Secrets::parse(&identity.private_material)?;
        let signing = P256SigningKey::from_bytes(secrets.signing()).map_err(invalid)?;
        let kem = DeviceKemKeyPair::from_private_bytes(secrets.device_kem()).map_err(invalid)?;
        let device =
            store.device_key_pair().map_err(invalid)?.ok_or(PersonalServerError::Identity)?;
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
            return Err(PersonalServerError::Identity);
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
