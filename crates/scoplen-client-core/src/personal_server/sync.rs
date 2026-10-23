// SPDX-License-Identifier: Apache-2.0
//! First-device K-4 bootstrap. No inventory is uploaded or moved by this operation.

use std::sync::Arc;

use scoplen_api::{
    personal_enrollment::PersonalEnrollmentRequest,
    sync::{
        SyncAccountKeyBundle, SyncSessionRequest, SyncSessionResponse, SyncVaultKeysResponse,
        VaultKind,
    },
};
use scoplen_crypto::{
    AccountKemKeyWrap, AccountSigningKeyWrap, DeviceAccessToken, DeviceArkWrap, DeviceCertificate,
    DeviceKemKeyPair, DpopProof, DpopTarget, DpopToken, P256SigningKey, PersonalVaultKeyWrap,
    RecoveryBlob, RecoveryKey, RevocationStatement, SecretVec, SymmetricKey, dpop_jwk_thumbprint,
    ed25519_verify, verify_device_list,
};
use zeroize::Zeroize as _;

use super::{
    PersonalServer, PersonalServerError, identity, now, record, storage, trusted_token_keys,
};
use crate::store::{
    Store,
    personal::{PersonalRecord, PersonalSyncRecord},
};

const BODY_LIMIT: usize = 4 * 1024 * 1024;

mod inventory;
pub use inventory::{PersonalInventoryIntent, PersonalInventoryProgress};

/// Failures preserve both retained identity and the previous verified bootstrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PersonalSyncError {
    /// A local or bounded HTTPS operation failed.
    #[error(transparent)]
    Personal(#[from] PersonalServerError),
    /// Device authentication must be renewed before sync can access the server.
    #[error("Authenticate this device again before connecting Personal sync.")]
    AuthenticationRequired,
    /// A response did not match the retained account, device, or cryptographic material.
    #[error("The Personal sync response was invalid. The existing keys were retained.")]
    InvalidResponse,
    /// This first-device path cannot accept rotated account or vault keys.
    #[error(
        "This account or vault requires key rotation support. The existing keys were retained."
    )]
    RotationRequired,
    /// A write conflict has no current object because the server already purged it.
    #[error("Personal sync needs full reconciliation. Local changes were retained.")]
    ReconciliationRequired,
    /// A write may have committed; a later cycle must pull before writing again.
    #[error("The server may have saved these changes. Synchronize again to check their result.")]
    WriteOutcomeUnknown,
    /// Objects are durable locally, but their server acknowledgement is unconfirmed.
    #[error(
        "Changes are saved on this device. Synchronize again to confirm the server acknowledgement."
    )]
    AcknowledgementUnknown,
    /// Concurrent changes exceeded this cycle's bounded conflict retries.
    #[error("Personal sync is receiving concurrent changes. Synchronize again.")]
    ConcurrentChanges,
    /// The wall clock or server Date is unsuitable for a safe object write.
    #[error("Check this device's clock and the server's Date header before synchronizing changes.")]
    Clock,
    /// Selected local objects require a complete, explicit dependency selection.
    #[error("Review the selected objects and their referenced local objects before synchronizing.")]
    Selection,
    /// One bounded request cannot carry this object or response safely.
    #[error("The inventory exceeds this client's synchronization limits. Local data was retained.")]
    ResourceLimit,
    /// A trust record has no verified same-user provenance for automatic replication.
    #[error("Confirm the source of these host keys before synchronizing their trust records.")]
    TrustReviewRequired,
}

/// Verified session metadata and an unwrapped Personal key, kept entirely inside Rust.
/// This is not an IPC type; callers must never serialize its secret material.
pub struct PersonalSyncBootstrap {
    session: SyncSessionResponse,
    personal_vault_key: SymmetricKey,
    active_devices: Vec<DeviceCertificate>,
}

struct SyncContext {
    store: Arc<Store>,
    bootstrap: PersonalSyncBootstrap,
    identity: PersonalRecord,
    access: SecretVec,
    signing: P256SigningKey,
    expires_at: u64,
    device_id: uuid::Uuid,
}

impl PersonalSyncBootstrap {
    /// The complete validated session metadata, including unknown future vault kinds.
    pub fn session(&self) -> &SyncSessionResponse {
        &self.session
    }

    /// The verified epoch-1 key for the retained Personal vault.
    pub fn personal_vault_key(&self) -> &SymmetricKey {
        &self.personal_vault_key
    }
}

impl PersonalServer {
    /// Connect the retained first device to K-4 and atomically save its verified bootstrap.
    /// Every protected request has a fresh proof and uses TLS 1.3 and HTTP/2.
    /// Existing local objects remain local; no inventory write is performed.
    pub async fn bootstrap_sync(
        &self,
        store: Arc<Store>,
    ) -> Result<PersonalSyncBootstrap, PersonalSyncError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        Ok(self.bootstrap_inner(&store, false).await?.bootstrap)
    }

    async fn bootstrap_inner(
        &self,
        store: &Arc<Store>,
        write: bool,
    ) -> Result<SyncContext, PersonalSyncError> {
        self.refresh_for_operation(store).await.map_err(|error| match error {
            PersonalServerError::AuthenticationRequired => {
                PersonalSyncError::AuthenticationRequired
            }
            _ => error.into(),
        })?;
        let pending = record(store)?;
        let previous = store.personal_sync_record().map_err(storage)?;
        let access = store
            .personal_access_token(now()?)
            .map_err(storage)?
            .ok_or(PersonalSyncError::AuthenticationRequired)?;
        let token = std::str::from_utf8(access.as_bytes())
            .map_err(|_| PersonalSyncError::AuthenticationRequired)?;
        let secrets = identity::Secrets::parse(&pending.private_material)?;
        let signing = P256SigningKey::from_bytes(secrets.signing()).map_err(invalid)?;
        let transport = self.transport.as_ref().map_err(|error| *error)?;
        let trusted = trusted_token_keys(transport, &pending.origin).await?;
        let current_time = now()?;
        let verified = match DeviceAccessToken::parse(token)
            .and_then(|token| token.verify(&trusted, current_time))
        {
            Ok(verified) => verified,
            Err(_) => {
                store.invalidate_personal_session(&pending, &access).map_err(storage)?;
                return Err(PersonalSyncError::AuthenticationRequired);
            }
        };
        let claims = verified.claims();
        if claims.sub != pending.account_id
            || claims.did != store.device_id()
            || claims.cnf_jkt != dpop_jwk_thumbprint(&signing.public_key_sec1()).map_err(invalid)?
        {
            store.invalidate_personal_session(&pending, &access).map_err(storage)?;
            return Err(PersonalSyncError::AuthenticationRequired);
        }
        if !["keys:read", "sync:read"]
            .iter()
            .all(|required| claims.scope.split(' ').any(|scope| scope == *required))
            || write && !claims.scope.split(' ').any(|scope| scope == "sync:write")
        {
            return Err(PersonalServerError::PermissionDenied.into());
        }
        let request = SyncSessionRequest {
            client_version: env!("CARGO_PKG_VERSION").into(),
            model_version: scoplen_model::CURRENT_SCHEMA_VERSION,
            device_id: store.device_id(),
        }
        .to_cbor()
        .map_err(invalid)?;
        let vault_path = format!("/sync/v1/vaults/{}/keys", pending.personal_vault_id);
        let mut bodies = Vec::with_capacity(3);
        for (path, body) in [
            ("/sync/v1/session", Some(request.as_slice())),
            ("/sync/v1/keys", None),
            (vault_path.as_str(), None),
        ] {
            if verified.expires_at() <= now()?
                || !store.personal_session_current(&pending, &access, now()?).map_err(storage)?
            {
                return Err(PersonalSyncError::AuthenticationRequired);
            }
            let target =
                DpopTarget::new(if body.is_some() { "POST" } else { "GET" }, &pending.origin, path)
                    .map_err(invalid)?;
            let proof = DpopProof::sign(
                &signing,
                &signing.public_key_sec1(),
                &target,
                DpopToken::Protected(token),
                now()?,
                None,
            )
            .map_err(invalid)?;
            let response =
                transport.protected(&pending.origin, path, body, token, &proof, BODY_LIMIT).await?;
            match response.status {
                200 => bodies.push(response.body),
                401 | 403 => {
                    store.invalidate_personal_session(&pending, &access).map_err(storage)?;
                    return Err(PersonalSyncError::AuthenticationRequired);
                }
                _ => return Err(PersonalSyncError::InvalidResponse),
            }
        }
        let mut bodies = bodies.into_iter();
        let snapshot = PersonalSyncRecord {
            generation: 0,
            session: bodies.next().ok_or(PersonalSyncError::InvalidResponse)?,
            account_keys: bodies.next().ok_or(PersonalSyncError::InvalidResponse)?,
            vault_keys: bodies.next().ok_or(PersonalSyncError::InvalidResponse)?,
        };
        let bootstrap = validate(store, &pending, &snapshot)?;
        if verified.expires_at() <= now()? {
            return Err(PersonalSyncError::AuthenticationRequired);
        }
        if !store
            .save_personal_sync(
                &pending,
                &access,
                previous.as_ref().map(|row| row.generation),
                &snapshot,
                now()?,
            )
            .map_err(storage)?
        {
            return Err(PersonalServerError::Storage.into());
        }
        let expires_at = verified.expires_at();
        Ok(SyncContext {
            store: store.clone(),
            bootstrap,
            identity: pending,
            access,
            signing,
            expires_at,
            device_id: store.device_id(),
        })
    }

    /// Restore and cryptographically revalidate the encrypted bootstrap without network I/O.
    /// An expired access token does not remove offline access to already verified keys.
    pub fn load_sync_bootstrap(
        &self,
        store: &Store,
    ) -> Result<Option<PersonalSyncBootstrap>, PersonalSyncError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let Some(snapshot) = store.personal_sync_record().map_err(storage)? else {
            return Ok(None);
        };
        validate(store, &record(store)?, &snapshot).map(Some)
    }
}

fn invalid(_: impl std::fmt::Debug) -> PersonalSyncError {
    PersonalSyncError::InvalidResponse
}

fn validate(
    store: &Store,
    pending: &PersonalRecord,
    snapshot: &PersonalSyncRecord,
) -> Result<PersonalSyncBootstrap, PersonalSyncError> {
    let secrets = identity::Secrets::parse(&pending.private_material)?;
    let device = store.device_key_pair().map_err(storage)?.ok_or(PersonalServerError::Identity)?;
    if device.signing.as_bytes() != secrets.signing()
        || device.kem.as_bytes() != secrets.device_kem()
    {
        return Err(PersonalServerError::Identity.into());
    }
    let mut enrollment = PersonalEnrollmentRequest::from_json(
        pending.enrollment_request.as_ref().ok_or(PersonalServerError::Identity)?.as_bytes(),
    )
    .map_err(invalid)?;
    enrollment.invitation_token.zeroize();
    if enrollment.account_id != pending.account_id
        || enrollment.personal_vault_id != pending.personal_vault_id
        || enrollment.device_certificate.device_id != store.device_id()
    {
        return Err(PersonalServerError::Identity.into());
    }
    enrollment
        .device_certificate
        .verify(&enrollment.account_signing_public_key)
        .map_err(invalid)?;
    ed25519_verify(
        &enrollment.account_signing_public_key,
        &enrollment.key_bundle_update.signature_input().map_err(invalid)?,
        &enrollment.key_bundle_update.signature,
    )
    .map_err(invalid)?;
    let session =
        SyncSessionResponse::from_cbor_with_body_limit(snapshot.session.as_bytes(), BODY_LIMIT)
            .map_err(invalid)?;
    let vault = session
        .vaults
        .iter()
        .find(|vault| vault.id == pending.personal_vault_id)
        .ok_or(PersonalSyncError::InvalidResponse)?;
    if vault.kind != VaultKind::Personal {
        return Err(PersonalSyncError::InvalidResponse);
    }
    let bundle =
        SyncAccountKeyBundle::from_cbor(snapshot.account_keys.as_bytes()).map_err(invalid)?;
    let vault_keys =
        SyncVaultKeysResponse::from_cbor(snapshot.vault_keys.as_bytes()).map_err(invalid)?;
    if bundle.revision != 1
        || vault.key_epoch != 1
        || vault.rotation_pending
        || vault_keys.keys.iter().any(|key| key.epoch != 1)
    {
        return Err(PersonalSyncError::RotationRequired);
    }
    let certificates = bundle
        .certificates
        .iter()
        .map(|bytes| DeviceCertificate::decode(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)?;
    let revocations = bundle
        .revocations
        .iter()
        .map(|bytes| RevocationStatement::decode(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)?;
    if certificates.iter().any(|certificate| certificate.account_id != pending.account_id) {
        return Err(PersonalSyncError::InvalidResponse);
    }
    let active =
        verify_device_list(&certificates, &revocations, &enrollment.account_signing_public_key)
            .map_err(invalid)?;
    let certificate = active
        .iter()
        .find(|certificate| certificate.device_id == store.device_id())
        .ok_or(PersonalSyncError::InvalidResponse)?;
    let signing = P256SigningKey::from_bytes(secrets.signing()).map_err(invalid)?;
    let kem = DeviceKemKeyPair::from_private_bytes(secrets.device_kem()).map_err(invalid)?;
    if certificate != &enrollment.device_certificate
        || certificate.signing_public_key != signing.public_key_sec1()
        || certificate.kem_public_key != kem.public_key()
    {
        return Err(PersonalSyncError::InvalidResponse);
    }
    let ark = DeviceArkWrap::decode(&bundle.wrapped_ark)
        .map_err(invalid)?
        .open(pending.account_id, store.device_id(), &kem)
        .map_err(invalid)?;
    let account_signing = AccountSigningKeyWrap::decode(&bundle.account_signing_key)
        .map_err(invalid)?
        .open(pending.account_id, &ark, &enrollment.account_signing_public_key)
        .map_err(invalid)?;
    let account_kem = AccountKemKeyWrap::decode(&bundle.account_kem_key)
        .map_err(invalid)?
        .open(pending.account_id, &ark, &enrollment.account_kem_public_key)
        .map_err(invalid)?;
    let recovery = RecoveryKey::from_bytes(secrets.recovery()).map_err(invalid)?;
    let recovered = RecoveryBlob::decode(&bundle.recovery_blob)
        .map_err(invalid)?
        .open(&recovery, pending.account_id)
        .map_err(invalid)?;
    let key = vault_keys.keys.first().ok_or(PersonalSyncError::InvalidResponse)?;
    let personal_vault_key = PersonalVaultKeyWrap::decode(&key.wrapped_vault_key)
        .map_err(invalid)?
        .open(pending.account_id, pending.personal_vault_id, 1, &ark)
        .map_err(invalid)?;
    if ark.as_bytes() != secrets.ark()
        || recovered != ark
        || account_signing.private_key_bytes().as_bytes() != secrets.account_signing()
        || account_kem.private_key_bytes().as_bytes() != secrets.account_kem()
        || personal_vault_key.as_bytes() != secrets.vault()
    {
        return Err(PersonalSyncError::InvalidResponse);
    }
    Ok(PersonalSyncBootstrap { session, personal_vault_key, active_devices: active })
}

#[cfg(test)]
mod tests;
