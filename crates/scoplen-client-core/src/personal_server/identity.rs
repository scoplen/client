// SPDX-License-Identifier: Apache-2.0
//! Shared K-2 artifacts and a device-local SQLCipher serialization of secret keys.

use scoplen_api::{
    personal_enrollment::PersonalEnrollmentRequest,
    sync::{SyncAccountDeviceWrap, SyncAccountKeyBundleUpdate},
};
use scoplen_crypto::{
    AccountKemKeyWrap, AccountSigningKeyWrap, DeviceArkWrap, DeviceCertificate, P256SigningKey,
    PersonalEnrollmentArtifacts, PersonalEnrollmentContext, PersonalVaultKeyWrap, RecoveryBlob,
    RecoveryKey, SecretVec, generate_account_keys, generate_device_keys, generate_symmetric_key,
};
use zeroize::{Zeroize as _, Zeroizing};

use super::{Invitation, PersonalServerError};
use crate::store::{Store, personal::PersonalRecord};

pub(super) struct Secrets<'a>(&'a [u8]);

impl<'a> Secrets<'a> {
    pub fn parse(material: &'a SecretVec) -> Result<Self, PersonalServerError> {
        if !matches!((material.as_bytes().first(), material.len()), (Some(1), 225) | (Some(2), 193))
        {
            return Err(PersonalServerError::Identity);
        }
        Ok(Self(material.as_bytes()))
    }

    pub fn signing(&self) -> &[u8] {
        &self.0[1..33]
    }
    pub fn device_kem(&self) -> &[u8] {
        &self.0[33..65]
    }
    pub fn ark(&self) -> &[u8] {
        &self.0[65..97]
    }
    pub fn account_signing(&self) -> &[u8] {
        &self.0[97..129]
    }
    pub fn account_kem(&self) -> &[u8] {
        &self.0[129..161]
    }
    pub fn vault(&self) -> &[u8] {
        &self.0[161..193]
    }
    pub fn recovery(&self) -> Option<&[u8]> {
        self.0.get(193..225)
    }
}

fn invalid(_: impl std::fmt::Debug) -> PersonalServerError {
    PersonalServerError::Identity
}

pub(super) fn replace_invitation(
    store: &Store,
    pending: &PersonalRecord,
    invitation: Invitation,
) -> Result<SecretVec, PersonalServerError> {
    let encoded = pending.enrollment_request.as_ref().ok_or(PersonalServerError::Identity)?;
    let mut request = PersonalEnrollmentRequest::from_json(encoded.as_bytes()).map_err(invalid)?;
    let result = (|| {
        let secrets = Secrets::parse(&pending.private_material)?;
        let signing = P256SigningKey::from_bytes(secrets.signing()).map_err(invalid)?;
        if request.account_id != pending.account_id
            || request.personal_vault_id != pending.personal_vault_id
            || request.device_certificate.device_id != store.device_id()
            || request.device_certificate.signing_public_key != signing.public_key_sec1()
        {
            return Err(PersonalServerError::Identity);
        }
        request.invitation_token.copy_from_slice(invitation.token.as_bytes());
        request.device_signature = PersonalEnrollmentContext::new(
            &pending.origin,
            &request.invitation_token,
            request.account_id,
            request.personal_vault_id,
            PersonalEnrollmentArtifacts {
                account_signing_public_key: &request.account_signing_public_key,
                account_kem_public_key: &request.account_kem_public_key,
                key_bundle_update: &request.key_bundle_update.to_cbor().map_err(invalid)?,
                device_certificate: &request.device_certificate.encode().map_err(invalid)?,
                wrapped_personal_vault_key: &request.wrapped_personal_vault_key,
            },
        )
        .map_err(invalid)?
        .sign(&signing)
        .map_err(invalid)?;
        request.to_json().map(SecretVec::new).map_err(invalid)
    })();
    request.invitation_token.zeroize();
    result
}

pub(super) fn prepare(
    store: &Store,
    invitation: Invitation,
    device_name: String,
) -> Result<PersonalRecord, PersonalServerError> {
    let account_id = scoplen_model::new_uuid_v7().map_err(invalid)?;
    let personal_vault_id = scoplen_model::new_uuid_v7().map_err(invalid)?;
    let device = generate_device_keys().map_err(invalid)?;
    let account = generate_account_keys().map_err(invalid)?;
    let ark = generate_symmetric_key().map_err(invalid)?;
    let vault_key = generate_symmetric_key().map_err(invalid)?;
    let recovery = RecoveryKey::generate().map_err(invalid)?;
    let device_id = store.device_id();
    let certificate = DeviceCertificate::issue(
        &account.signing,
        device_id,
        account_id,
        device.signing.public_key_sec1(),
        device.kem.public_key().to_vec(),
        device_name.clone(),
        std::env::consts::OS.to_owned(),
        scoplen_model::system_time_millis().map_err(invalid)?,
    )
    .map_err(invalid)?;
    let mut bundle = SyncAccountKeyBundleUpdate {
        revision: 1,
        device_wraps: vec![SyncAccountDeviceWrap {
            device_id,
            wrapped_ark: DeviceArkWrap::seal(account_id, device_id, device.kem.public_key(), &ark)
                .map_err(invalid)?
                .encode()
                .to_vec(),
        }],
        account_signing_key: AccountSigningKeyWrap::seal(account_id, &ark, &account.signing)
            .map_err(invalid)?
            .encode()
            .to_vec(),
        account_kem_key: AccountKemKeyWrap::seal(account_id, &ark, &account.kem)
            .map_err(invalid)?
            .encode()
            .to_vec(),
        recovery_blob: RecoveryBlob::wrap(&recovery, account_id, &ark)
            .map_err(invalid)?
            .encode()
            .map_err(invalid)?,
        signature: vec![0; 64],
    };
    bundle.signature = account.signing.sign(&bundle.signature_input().map_err(invalid)?).to_vec();
    let wrapped_vault =
        PersonalVaultKeyWrap::seal(account_id, personal_vault_id, 1, &ark, &vault_key)
            .map_err(invalid)?
            .encode()
            .to_vec();
    let signing_public = account.signing.public_key();
    let kem_public: [u8; 32] = account.kem.public_key().try_into().map_err(invalid)?;
    let invitation_token =
        Zeroizing::new(<[u8; 32]>::try_from(invitation.token.as_bytes()).map_err(invalid)?);
    let proof = PersonalEnrollmentContext::new(
        &invitation.origin,
        &invitation_token,
        account_id,
        personal_vault_id,
        PersonalEnrollmentArtifacts {
            account_signing_public_key: &signing_public,
            account_kem_public_key: &kem_public,
            key_bundle_update: &bundle.to_cbor().map_err(invalid)?,
            device_certificate: &certificate.encode().map_err(invalid)?,
            wrapped_personal_vault_key: &wrapped_vault,
        },
    )
    .map_err(invalid)?
    .sign(&device.signing)
    .map_err(invalid)?;
    let mut request = PersonalEnrollmentRequest {
        invitation_token: *invitation_token,
        account_id,
        personal_vault_id,
        account_signing_public_key: signing_public,
        account_kem_public_key: kem_public,
        key_bundle_update: bundle,
        device_certificate: certificate,
        wrapped_personal_vault_key: wrapped_vault,
        device_signature: proof,
    };
    let encoded = request.to_json();
    request.invitation_token.zeroize();
    let encoded = SecretVec::new(encoded.map_err(invalid)?);
    // This is local persistence only, not a cryptographic artifact or a wire format.
    // Its version and fixed fields keep every temporary key in a zeroizing buffer.
    let mut material = Zeroizing::new(Vec::with_capacity(225));
    material.push(1);
    material.extend_from_slice(device.signing.private_key_bytes().as_bytes());
    material.extend_from_slice(device.kem.private_key_bytes().as_bytes());
    material.extend_from_slice(ark.as_bytes());
    material.extend_from_slice(account.signing.private_key_bytes().as_bytes());
    material.extend_from_slice(account.kem.private_key_bytes().as_bytes());
    material.extend_from_slice(vault_key.as_bytes());
    material.extend_from_slice(recovery.as_bytes());
    Ok(PersonalRecord {
        origin: invitation.origin,
        account_id,
        personal_vault_id,
        device_name,
        private_material: SecretVec::new(material.to_vec()),
        enrollment_request: Some(encoded),
        paired_handoff: None,
        recovery_saved: false,
        recovery_confirmed: false,
        enrollment_attempted: false,
        access_expires_at: None,
        refresh_expires_at: None,
        auth_generation: 0,
        auth_scope: None,
        refresh_available: false,
        session_established: false,
        refresh_retry_at: None,
    })
}
