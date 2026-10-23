// SPDX-License-Identifier: Apache-2.0
//! Retained-device K-4 bootstrap. No inventory is uploaded or moved by this operation.

use std::{collections::BTreeMap, sync::Arc};

use scoplen_api::sync::{
    SyncAccountKeyBundle, SyncSessionRequest, SyncSessionResponse, SyncVaultKeysResponse, VaultKind,
};
use scoplen_crypto::{
    AccountKemKeyWrap, AccountSigningKeyWrap, DeviceAccessToken, DeviceArkWrap, DeviceCertificate,
    DeviceKemKeyPair, DpopProof, DpopTarget, DpopToken, P256SigningKey, PairingKeyProjection,
    PersonalVaultKeyWrap, RecoveryBlob, RecoveryKey, RevocationStatement, SecretVec, SymmetricKey,
    dpop_jwk_thumbprint, pairing_key_anchor, verify_device_list,
};

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
    /// The retained-device path cannot accept rotated account or vault keys.
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
    personal_epoch: u32,
    personal_keys: BTreeMap<u32, SymmetricKey>,
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
    account_keys: SecretVec,
    vault_keys: SecretVec,
}

pub(super) struct PairingSource {
    pub identity: PersonalRecord,
    pub certificates: Vec<DeviceCertificate>,
    pub bundle: SyncAccountKeyBundle,
    pub vault_keys: SyncVaultKeysResponse,
}

impl PersonalSyncBootstrap {
    /// The complete validated session metadata, including unknown future vault kinds.
    pub fn session(&self) -> &SyncSessionResponse {
        &self.session
    }

    /// The verified current-epoch key for the retained Personal vault.
    pub fn personal_vault_key(&self) -> &SymmetricKey {
        &self.personal_vault_key
    }
}

impl PersonalServer {
    pub(super) async fn pairing_source(
        &self,
        store: &Arc<Store>,
    ) -> Result<PairingSource, PersonalSyncError> {
        let context = self.bootstrap_inner(store, false).await?;
        Ok(PairingSource {
            identity: context.identity,
            certificates: context.bootstrap.active_devices,
            bundle: SyncAccountKeyBundle::from_cbor(context.account_keys.as_bytes())
                .map_err(invalid)?,
            vault_keys: SyncVaultKeysResponse::from_cbor(context.vault_keys.as_bytes())
                .map_err(invalid)?,
        })
    }
    /// Connect the retained device to K-4 and atomically save its verified bootstrap.
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
        let bootstrap = validate(store, &pending, &snapshot, previous.as_ref())?;
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
            account_keys: snapshot.account_keys,
            vault_keys: snapshot.vault_keys,
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
        validate(store, &record(store)?, &snapshot, None).map(Some)
    }
}

fn invalid(_: impl std::fmt::Debug) -> PersonalSyncError {
    PersonalSyncError::InvalidResponse
}

fn validate(
    store: &Store,
    pending: &PersonalRecord,
    snapshot: &PersonalSyncRecord,
    previous: Option<&PersonalSyncRecord>,
) -> Result<PersonalSyncBootstrap, PersonalSyncError> {
    let secrets = identity::Secrets::parse(&pending.private_material)?;
    let device = store.device_key_pair().map_err(storage)?.ok_or(PersonalServerError::Identity)?;
    if device.signing.as_bytes() != secrets.signing()
        || device.kem.as_bytes() != secrets.device_kem()
    {
        return Err(PersonalServerError::Identity.into());
    }
    let retained = super::retained::RetainedAccount::load(store, pending)?;
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
    if vault.rotation_pending
        || vault_keys.keys.last().map(|key| key.epoch) != Some(vault.key_epoch)
        || vault_keys.keys.iter().map(|key| key.epoch).ne(retained
            .vault_keys
            .keys
            .iter()
            .map(|key| key.epoch))
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
    let active = verify_device_list(&certificates, &revocations, &retained.signing_public)
        .map_err(invalid)?;
    let certificate = active
        .iter()
        .find(|certificate| certificate.device_id == store.device_id())
        .ok_or(PersonalSyncError::InvalidResponse)?;
    let signing = P256SigningKey::from_bytes(secrets.signing()).map_err(invalid)?;
    let kem = DeviceKemKeyPair::from_private_bytes(secrets.device_kem()).map_err(invalid)?;
    if certificate != &retained.certificate
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
        .open(pending.account_id, &ark, &retained.signing_public)
        .map_err(invalid)?;
    let account_kem = AccountKemKeyWrap::decode(&bundle.account_kem_key)
        .map_err(invalid)?
        .open(pending.account_id, &ark, &retained.kem_public)
        .map_err(invalid)?;
    if let Some(recovery) = secrets.recovery() {
        let recovery = RecoveryKey::from_bytes(recovery).map_err(invalid)?;
        if RecoveryBlob::decode(&bundle.recovery_blob)
            .map_err(invalid)?
            .open(&recovery, pending.account_id)
            .map_err(invalid)?
            != ark
        {
            return Err(PersonalSyncError::InvalidResponse);
        }
    }
    let initial_keys = retained.open_vault_keys(pending, &ark)?;
    let personal_keys = vault_keys
        .keys
        .iter()
        .map(|key| {
            let epoch = u32::try_from(key.epoch).map_err(invalid)?;
            let opened = PersonalVaultKeyWrap::decode(&key.wrapped_vault_key)
                .map_err(invalid)?
                .open(pending.account_id, pending.personal_vault_id, epoch, &ark)
                .map_err(invalid)?;
            if initial_keys.get(&epoch) != Some(&opened) {
                return Err(PersonalSyncError::InvalidResponse);
            }
            Ok((epoch, opened))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let personal_epoch = u32::try_from(vault.key_epoch).map_err(invalid)?;
    let personal_vault_key =
        personal_keys.get(&personal_epoch).ok_or(PersonalSyncError::InvalidResponse)?.clone();
    if ark.as_bytes() != secrets.ark()
        || account_signing.private_key_bytes().as_bytes() != secrets.account_signing()
        || account_kem.private_key_bytes().as_bytes() != secrets.account_kem()
        || personal_vault_key.as_bytes() != secrets.vault()
    {
        return Err(PersonalSyncError::InvalidResponse);
    }
    // Membership updates do not authorize account or vault key rotation.
    if bundle.account_signing_key != retained.account_signing_key
        || bundle.account_kem_key != retained.account_kem_key
        || bundle.recovery_blob != retained.recovery_blob
        || retained.invitation && vault_keys != retained.vault_keys
    {
        return Err(PersonalSyncError::RotationRequired);
    }
    let anchor = pairing_key_anchor(PairingKeyProjection {
        revision: bundle.revision,
        wrapped_ark: &bundle.wrapped_ark,
        account_signing_key: &bundle.account_signing_key,
        account_kem_key: &bundle.account_kem_key,
        recovery_blob: &bundle.recovery_blob,
    })
    .map_err(invalid)?;
    if bundle.revision < retained.revision
        || bundle.revision == retained.revision && anchor != retained.anchor
    {
        return Err(PersonalSyncError::InvalidResponse);
    }
    if let Some(previous) = previous {
        let retained =
            SyncAccountKeyBundle::from_cbor(previous.account_keys.as_bytes()).map_err(invalid)?;
        // Statements can change independently of a bundle revision. Only the key projection
        // is immutable at a retained revision; every statement above is still verified.
        if bundle.revision < retained.revision
            || bundle.revision == retained.revision
                && (bundle.wrapped_ark != retained.wrapped_ark
                    || bundle.account_signing_key != retained.account_signing_key
                    || bundle.account_kem_key != retained.account_kem_key
                    || bundle.recovery_blob != retained.recovery_blob)
        {
            return Err(PersonalSyncError::InvalidResponse);
        }
    }
    Ok(PersonalSyncBootstrap {
        session,
        personal_vault_key,
        personal_epoch,
        personal_keys,
        active_devices: active,
    })
}

#[cfg(test)]
mod tests;
