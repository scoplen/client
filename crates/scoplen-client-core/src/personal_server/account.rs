// SPDX-License-Identifier: Apache-2.0
//! Explicit account reads with complete signed-device verification and offline persistence.

use std::{fmt, sync::Arc};

use scoplen_api::{
    account_devices::{AccountDeviceStatements, MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES},
    account_profile::{AccountProfile, MAX_ACCOUNT_PROFILE_BYTES},
    auth::DeviceAccessOperation,
    personal_enrollment::PersonalEnrollmentRequest,
};
use scoplen_crypto::{
    DeviceAccessToken, DeviceCertificate, DeviceKemKeyPair, DpopProof, DpopTarget, DpopToken,
    Ed25519SigningKey, P256SigningKey, RevocationStatement, dpop_jwk_thumbprint,
    verify_device_list,
};
use serde::Serialize;
use specta::Type;
use zeroize::Zeroize as _;

use super::{
    PersonalServer, PersonalServerError, identity, now, record, storage, trusted_token_keys,
};
use crate::store::{
    Store,
    personal::{PersonalAccountRecord, PersonalRecord},
};

/// Public signed claims only; no certificate or key material crosses IPC.
#[derive(Clone, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PersonalAccountDevice {
    /// Stable signed identity.
    pub id: String,
    /// Display name signed by the account, not a hardware attestation.
    pub name: String,
    /// Platform text signed by the account, not server-observed activity.
    pub platform: String,
    /// The certificate exactly matches this device's retained enrollment certificate.
    pub current: bool,
}

/// The last complete manual query, retained offline independently of authentication expiry.
#[derive(Clone, Eq, PartialEq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PersonalAccountSnapshot {
    /// The verified session's account, bound to both responses.
    pub account_id: String,
    /// The identity service's optional email; absence is not replaced by a synthetic address.
    pub email: Option<String>,
    /// Device-local query completion time in Unix milliseconds, encoded without precision loss.
    pub queried_at: String,
    /// Active certificates after verifying the entire statement set and applying revocations.
    pub devices: Vec<PersonalAccountDevice>,
}

impl fmt::Debug for PersonalAccountSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersonalAccountSnapshot")
            .field("devices", &self.devices.len())
            .finish_non_exhaustive()
    }
}

impl PersonalServer {
    /// Reverify the saved statement set locally. Opening settings never requests the server.
    pub fn account_snapshot(
        &self,
        store: &Store,
    ) -> Result<Option<PersonalAccountSnapshot>, PersonalServerError> {
        let pending = record(store)?;
        let Some(snapshot) = store.personal_account_snapshot(&pending).map_err(storage)? else {
            return Ok(None);
        };
        validate(store, &pending, &snapshot).map(Some)
    }

    /// Query both public resources explicitly, replacing local state only after full verification.
    pub async fn query_account(
        &self,
        store: Arc<Store>,
    ) -> Result<PersonalAccountSnapshot, PersonalServerError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        self.refresh_for_operation(&store).await?;
        let pending = record(&store)?;
        let access = store
            .personal_access_token(now()?)
            .map_err(storage)?
            .ok_or(PersonalServerError::AuthenticationRequired)?;
        let token = std::str::from_utf8(access.as_bytes())
            .map_err(|_| PersonalServerError::AuthenticationRequired)?;
        let secrets = identity::Secrets::parse(&pending.private_material)?;
        let signing = P256SigningKey::from_bytes(secrets.signing()).map_err(invalid)?;
        let transport = self.transport.as_ref().map_err(|error| *error)?;
        let trusted = trusted_token_keys(transport, &pending.origin).await?;
        let current_time = now()?;
        let verified = DeviceAccessToken::parse(token)
            .and_then(|token| token.verify(&trusted, current_time))
            .map_err(|_| PersonalServerError::AuthenticationRequired);
        let verified = match verified {
            Ok(verified) => verified,
            Err(error) => {
                store.invalidate_personal_session(&pending, &access).map_err(storage)?;
                return Err(error);
            }
        };
        let claims = verified.claims();
        if claims.sub != pending.account_id
            || claims.did != store.device_id()
            || !claims.org.is_empty()
            || pending.auth_scope.as_deref() != Some(claims.scope.as_str())
            || claims.cnf_jkt != dpop_jwk_thumbprint(&signing.public_key_sec1()).map_err(invalid)?
        {
            store.invalidate_personal_session(&pending, &access).map_err(storage)?;
            return Err(PersonalServerError::AuthenticationRequired);
        }
        for operation in
            [DeviceAccessOperation::AccountProfileRead, DeviceAccessOperation::AccountDevicesRead]
        {
            if !operation.required_scope().is_present_in(&claims.scope) {
                return Err(PersonalServerError::PermissionDenied);
            }
        }
        let mut bodies = Vec::with_capacity(2);
        for (path, limit) in [
            ("/api/v1/accounts/me", MAX_ACCOUNT_PROFILE_BYTES),
            ("/api/v1/accounts/me/devices", MAX_ACCOUNT_DEVICE_STATEMENTS_BYTES),
        ] {
            if verified.expires_at() <= now()?
                || !store.personal_session_current(&pending, &access, now()?).map_err(storage)?
            {
                return Err(PersonalServerError::AuthenticationRequired);
            }
            let target = DpopTarget::new("GET", &pending.origin, path).map_err(invalid)?;
            let proof = DpopProof::sign(
                &signing,
                &signing.public_key_sec1(),
                &target,
                DpopToken::Protected(token),
                now()?,
                None,
            )
            .map_err(invalid)?;
            let response = transport
                .account_get(&pending.origin, path, token, &proof, limit)
                .await
                .map_err(|error| match error {
                    PersonalServerError::InvalidResponse => {
                        PersonalServerError::InvalidAccountResponse
                    }
                    other => other,
                })?;
            match response.status {
                200 if path.ends_with("/devices") => {
                    AccountDeviceStatements::from_http_json(
                        response.body.as_bytes(),
                        response.cache_control.as_deref(),
                        response.pragma.as_deref(),
                    )
                    .map_err(invalid)?;
                }
                200 => {
                    AccountProfile::from_http_json(
                        response.body.as_bytes(),
                        response.etag.as_deref(),
                        response.cache_control.as_deref(),
                        response.pragma.as_deref(),
                    )
                    .map_err(invalid)?;
                }
                401 => {
                    store.invalidate_personal_session(&pending, &access).map_err(storage)?;
                    return Err(PersonalServerError::AuthenticationRequired);
                }
                403 => return Err(PersonalServerError::PermissionDenied),
                _ => return Err(PersonalServerError::InvalidAccountResponse),
            }
            bodies.push(response.body);
        }
        let mut bodies = bodies.into_iter();
        let snapshot = PersonalAccountRecord {
            queried_at: scoplen_model::system_time_millis().map_err(invalid)?,
            profile: bodies.next().ok_or(PersonalServerError::InvalidAccountResponse)?,
            devices: bodies.next().ok_or(PersonalServerError::InvalidAccountResponse)?,
        };
        let expires_at = verified.expires_at();
        tokio::task::spawn_blocking(move || {
            let result = validate(&store, &pending, &snapshot)?;
            if expires_at <= now()?
                || !store
                    .save_personal_account_snapshot(&pending, &access, &snapshot, now()?)
                    .map_err(storage)?
            {
                return Err(PersonalServerError::AuthenticationRequired);
            }
            Ok(result)
        })
        .await
        .map_err(|_| PersonalServerError::Storage)?
    }
}

fn invalid(_: impl fmt::Debug) -> PersonalServerError {
    PersonalServerError::InvalidAccountResponse
}

fn validate(
    store: &Store,
    identity: &PersonalRecord,
    snapshot: &PersonalAccountRecord,
) -> Result<PersonalAccountSnapshot, PersonalServerError> {
    if snapshot.queried_at > 253_402_300_799_999 {
        return Err(PersonalServerError::InvalidAccountResponse);
    }
    let profile = AccountProfile::from_json(snapshot.profile.as_bytes()).map_err(invalid)?;
    let statements =
        AccountDeviceStatements::from_json(snapshot.devices.as_bytes()).map_err(invalid)?;
    if profile.id != identity.account_id || statements.account_id != identity.account_id {
        return Err(PersonalServerError::InvalidAccountResponse);
    }
    let secrets = identity::Secrets::parse(&identity.private_material)?;
    let account_key =
        Ed25519SigningKey::from_bytes(secrets.account_signing()).map_err(invalid)?.public_key();
    let mut enrollment = PersonalEnrollmentRequest::from_json(
        identity.enrollment_request.as_ref().ok_or(PersonalServerError::Identity)?.as_bytes(),
    )
    .map_err(invalid)?;
    enrollment.invitation_token.zeroize();
    let current = &enrollment.device_certificate;
    let signing = P256SigningKey::from_bytes(secrets.signing()).map_err(invalid)?;
    let kem = DeviceKemKeyPair::from_private_bytes(secrets.device_kem()).map_err(invalid)?;
    let device_keys =
        store.device_key_pair().map_err(storage)?.ok_or(PersonalServerError::Identity)?;
    if enrollment.account_id != identity.account_id
        || enrollment.account_signing_public_key != account_key
        || current.account_id != identity.account_id
        || current.device_id != store.device_id()
        || current.signing_public_key != signing.public_key_sec1()
        || current.kem_public_key != kem.public_key()
        || device_keys.signing.as_bytes() != secrets.signing()
        || device_keys.kem.as_bytes() != secrets.device_kem()
    {
        return Err(PersonalServerError::Identity);
    }
    current.verify(&account_key).map_err(invalid)?;
    let certificates = statements
        .certificates
        .iter()
        .map(|bytes| DeviceCertificate::decode(bytes).map_err(invalid))
        .collect::<Result<Vec<_>, _>>()?;
    if certificates.iter().any(|certificate| certificate.account_id != identity.account_id) {
        return Err(PersonalServerError::InvalidAccountResponse);
    }
    let revocations = statements
        .revocations
        .iter()
        .map(|bytes| RevocationStatement::decode(bytes).map_err(invalid))
        .collect::<Result<Vec<_>, _>>()?;
    let active = verify_device_list(&certificates, &revocations, &account_key).map_err(invalid)?;
    if !active.iter().any(|certificate| certificate == current) {
        return Err(PersonalServerError::InvalidAccountResponse);
    }
    Ok(PersonalAccountSnapshot {
        account_id: profile.id.to_string(),
        email: profile.email,
        queried_at: snapshot.queried_at.to_string(),
        devices: active
            .into_iter()
            .map(|certificate| PersonalAccountDevice {
                current: certificate == *current,
                id: certificate.device_id.to_string(),
                name: certificate.display_name,
                platform: certificate.platform,
            })
            .collect(),
    })
}
