// SPDX-License-Identifier: Apache-2.0
//! Neutral local admission anchors. Historical ceremony formats are read only during conversion.

use std::collections::BTreeMap;

use scoplen_crypto::{
    AccountKemKeyPair, DeviceCertificate, DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey,
    SymmetricKey, validate_server_origin,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{PersonalServerError, identity::Secrets, storage};
use crate::store::{Store, personal::PersonalRecord};

mod legacy;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchors {
    version: u8,
    signing_public: [u8; 32],
    kem_public: [u8; 32],
    certificate: Vec<u8>,
    revision: u64,
    projection: [u8; 32],
    artifacts: [u8; 32],
    vault_keys: [u8; 32],
    vault_wraps: Option<[u8; 32]>,
    current_epoch: u32,
}

pub(super) struct RetainedAccount {
    pub signing_public: [u8; 32],
    pub kem_public: [u8; 32],
    pub certificate: DeviceCertificate,
    pub revision: u64,
    pub anchor: [u8; 32],
    pub artifacts: [u8; 32],
    pub vault_keys: [u8; 32],
    pub vault_wraps: Option<[u8; 32]>,
    pub current_epoch: u32,
}

impl RetainedAccount {
    pub fn load(store: &Store, identity: &PersonalRecord) -> Result<Self, PersonalServerError> {
        let encoded = match store.personal_admission(identity).map_err(storage)? {
            Some(encoded) => encoded,
            None => legacy::convert(store, identity)?,
        };
        if encoded.len() > 524_288 {
            return Err(PersonalServerError::AdmissionUnverified);
        }
        let anchors: Anchors = serde_json::from_slice(encoded.as_bytes())
            .map_err(|_| PersonalServerError::AdmissionUnverified)?;
        if anchors.version != 1
            || anchors.revision == 0
            || anchors.current_epoch == 0
            || anchors.certificate.is_empty()
            || anchors.certificate.len() > 65_536
        {
            return Err(PersonalServerError::AdmissionUnverified);
        }
        let value = Self::from_anchors(anchors)?;
        value.verify_identity(store, identity)?;
        Ok(value)
    }

    fn from_anchors(value: Anchors) -> Result<Self, PersonalServerError> {
        Ok(Self {
            signing_public: value.signing_public,
            kem_public: value.kem_public,
            certificate: DeviceCertificate::decode(&value.certificate)
                .map_err(|_| PersonalServerError::AdmissionUnverified)?,
            revision: value.revision,
            anchor: value.projection,
            artifacts: value.artifacts,
            vault_keys: value.vault_keys,
            vault_wraps: value.vault_wraps,
            current_epoch: value.current_epoch,
        })
    }

    fn verify_identity(
        &self,
        store: &Store,
        identity: &PersonalRecord,
    ) -> Result<(), PersonalServerError> {
        validate_server_origin(&identity.origin).map_err(invalid)?;
        let secrets = Secrets::parse(&identity.private_material).map_err(invalid)?;
        let signing = P256SigningKey::from_bytes(secrets.signing()).map_err(invalid)?;
        let kem = DeviceKemKeyPair::from_private_bytes(secrets.device_kem()).map_err(invalid)?;
        let device = store
            .device_key_pair()
            .map_err(storage)?
            .ok_or(PersonalServerError::AdmissionUnverified)?;
        if self.certificate.account_id != identity.account_id
            || self.certificate.device_id != store.device_id()
            || self.certificate.signing_public_key != signing.public_key_sec1()
            || self.certificate.kem_public_key != kem.public_key()
            || device.signing.as_bytes() != secrets.signing()
            || device.kem.as_bytes() != secrets.device_kem()
            || Ed25519SigningKey::from_bytes(secrets.account_signing())
                .map_err(invalid)?
                .public_key()
                != self.signing_public
            || AccountKemKeyPair::from_private_bytes(secrets.account_kem())
                .map_err(invalid)?
                .public_key()
                != self.kem_public
        {
            return Err(PersonalServerError::AdmissionUnverified);
        }
        self.certificate.verify(&self.signing_public).map_err(invalid)
    }
}

fn invalid(_: impl std::fmt::Debug) -> PersonalServerError {
    PersonalServerError::AdmissionUnverified
}

// These digests are encrypted, device-local anchors, never shared protocol inputs.
pub(super) fn digest(label: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(label);
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

pub(super) fn projection_anchor(
    revision: u64,
    wrapped_ark: &[u8],
    signing: &[u8],
    kem: &[u8],
    recovery: &[u8],
) -> [u8; 32] {
    digest(
        b"scoplen-client-key-projection-v1",
        &[&revision.to_be_bytes(), wrapped_ark, signing, kem, recovery],
    )
}

pub(super) fn artifacts_anchor(signing: &[u8], kem: &[u8], recovery: &[u8]) -> [u8; 32] {
    digest(b"scoplen-client-key-artifacts-v1", &[signing, kem, recovery])
}

pub(super) fn vault_key_anchor(keys: &BTreeMap<u32, SymmetricKey>) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"scoplen-client-personal-epochs-v1");
    for (epoch, key) in keys {
        hash.update(epoch.to_be_bytes());
        hash.update(key.as_bytes());
    }
    hash.finalize().into()
}
