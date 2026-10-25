// SPDX-License-Identifier: Apache-2.0
//! Explicit current-device authority recovery, independent of historical entry codecs.

use std::sync::Arc;

use scoplen_api::sync::{SyncAccountKeyBundle, SyncSessionRequest};
use scoplen_crypto::{
    AccountKemKeyPair, DeviceCertificate, DeviceKemKeyPair, DpopProof, DpopTarget, DpopToken,
    Ed25519SigningKey, P256SigningKey, RevocationStatement, validate_server_origin,
};

use super::{
    PersonalServer, PersonalServerError, PersonalServerStatus, authentication_tokens,
    identity::Secrets, now, retained::RetainedAccount, status, storage, sync,
    trust::PersonalTrustDevices,
};
use crate::{
    local_data::LocalData,
    store::{
        Store,
        personal::{PersonalRecord, PersonalSyncRecord},
    },
};

pub(super) fn verify_material(
    store: &Store,
    identity: &PersonalRecord,
) -> Result<(), PersonalServerError> {
    validate_server_origin(&identity.origin).map_err(invalid)?;
    let secrets = Secrets::parse(&identity.private_material).map_err(invalid)?;
    P256SigningKey::from_bytes(secrets.signing()).map_err(invalid)?;
    DeviceKemKeyPair::from_private_bytes(secrets.device_kem()).map_err(invalid)?;
    Ed25519SigningKey::from_bytes(secrets.account_signing()).map_err(invalid)?;
    AccountKemKeyPair::from_private_bytes(secrets.account_kem()).map_err(invalid)?;
    let device = store
        .device_key_pair()
        .map_err(storage)?
        .ok_or(PersonalServerError::AdmissionUnverified)?;
    if device.signing.as_bytes() != secrets.signing()
        || device.kem.as_bytes() != secrets.device_kem()
    {
        return Err(PersonalServerError::AdmissionUnverified);
    }
    Ok(())
}

fn invalid(_: impl std::fmt::Debug) -> PersonalServerError {
    PersonalServerError::AdmissionUnverified
}

fn current(
    local: &LocalData,
    store: &Arc<Store>,
    identity: &PersonalRecord,
) -> Result<(), PersonalServerError> {
    local
        .with_current_store(store, || current_identity(store, identity))
        .ok_or(PersonalServerError::Busy)?
}

impl PersonalServer {
    /// Revalidate only the pre-D-128 personal_server profile's retained keys. D-128 pending
    /// operations are separate and must never be installed or confirmed through this path.
    pub async fn revalidate_retained_device(
        &self,
        local: &LocalData,
        store: Arc<Store>,
    ) -> Result<PersonalServerStatus, PersonalServerError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = local
            .with_current_store(&store, || store.personal_record())
            .ok_or(PersonalServerError::Busy)?
            .map_err(storage)?
            .ok_or(PersonalServerError::NotConfigured)?;
        current(local, &store, &identity)?;
        local
            .with_current_store(&store, || verify_material(&store, &identity))
            .ok_or(PersonalServerError::Busy)??;
        let previous = store.personal_sync_record().map_err(storage)?;
        let account = store.personal_account_snapshot(&identity).map_err(storage)?;
        let transport = self.transport.as_ref().map_err(|error| *error)?;
        let tokens = authentication_tokens(&store, &identity, transport, || {
            current(local, &store, &identity)
        })
        .await?
        .ok_or(PersonalServerError::Authentication)?;
        let token = std::str::from_utf8(tokens.access.as_bytes()).map_err(invalid)?;
        let request = SyncSessionRequest {
            client_version: env!("CARGO_PKG_VERSION").into(),
            model_version: scoplen_model::CURRENT_SCHEMA_VERSION,
            device_id: store.device_id(),
        }
        .to_cbor()
        .map_err(invalid)?;
        let vault_path = format!("/sync/v1/vaults/{}/keys", identity.personal_vault_id);
        let mut bodies = Vec::with_capacity(3);
        for (path, body) in [
            ("/sync/v1/session", Some(request.as_slice())),
            ("/sync/v1/keys", None),
            (vault_path.as_str(), None),
        ] {
            current(local, &store, &identity)?;
            if tokens.access_expires_at <= now()? {
                return Err(PersonalServerError::AuthenticationRequired);
            }
            let proof = local
                .with_current_store(&store, || {
                    let secrets = Secrets::parse(&identity.private_material)?;
                    let signing = P256SigningKey::from_bytes(secrets.signing()).map_err(invalid)?;
                    let target = DpopTarget::new(
                        if body.is_some() { "POST" } else { "GET" },
                        &identity.origin,
                        path,
                    )
                    .map_err(invalid)?;
                    DpopProof::sign(
                        &signing,
                        &signing.public_key_sec1(),
                        &target,
                        DpopToken::Protected(token),
                        now()?,
                        None,
                    )
                    .map_err(invalid)
                })
                .ok_or(PersonalServerError::Busy)??;
            let response = transport
                .protected(&identity.origin, path, body, token, &proof, 4 * 1024 * 1024)
                .await?;
            current(local, &store, &identity)?;
            match response.status {
                200 => bodies.push(response.body),
                401 | 403 => return Err(PersonalServerError::Authentication),
                _ => return Err(PersonalServerError::InvalidResponse),
            }
        }
        let mut bodies = bodies.into_iter();
        let snapshot = PersonalSyncRecord {
            generation: 0,
            session: bodies.next().ok_or(PersonalServerError::InvalidResponse)?,
            account_keys: bodies.next().ok_or(PersonalServerError::InvalidResponse)?,
            vault_keys: bodies.next().ok_or(PersonalServerError::InvalidResponse)?,
        };
        local
            .with_current_store(&store, || {
                current_identity(&store, &identity)?;
                let (retained, anchors) = RetainedAccount::from_snapshot(
                    &store,
                    &identity,
                    previous.as_ref().unwrap_or(&snapshot),
                )?;
                if let Some(previous) = &previous {
                    sync::validate_against(&store, &identity, previous, None, &retained, false)
                        .map_err(invalid)?;
                }
                let known = PersonalTrustDevices::from_snapshots(
                    identity.account_id,
                    retained.certificate.clone(),
                    &retained.signing_public,
                    previous.as_ref(),
                    account.as_ref(),
                )?;
                preserve_statements(&snapshot, &known)?;
                sync::validate_against(
                    &store,
                    &identity,
                    &snapshot,
                    previous.as_ref(),
                    &retained,
                    false,
                )
                .map_err(invalid)?;
                if tokens.access_expires_at <= now()?
                    || !store
                        .finish_personal_revalidation(
                            &identity,
                            anchors.as_bytes(),
                            &tokens,
                            &snapshot,
                            previous.as_ref(),
                            account.as_ref(),
                        )
                        .map_err(storage)?
                {
                    return Err(PersonalServerError::Busy);
                }
                status(&store)
            })
            .ok_or(PersonalServerError::Busy)?
    }
}

fn current_identity(store: &Store, identity: &PersonalRecord) -> Result<(), PersonalServerError> {
    if store.personal_revalidation_current(identity).map_err(storage)? {
        Ok(())
    } else {
        Err(PersonalServerError::Busy)
    }
}

fn preserve_statements(
    snapshot: &PersonalSyncRecord,
    known: &PersonalTrustDevices,
) -> Result<(), PersonalServerError> {
    let bundle =
        SyncAccountKeyBundle::from_cbor(snapshot.account_keys.as_bytes()).map_err(invalid)?;
    let certificates = bundle
        .certificates
        .iter()
        .map(|bytes| DeviceCertificate::decode(bytes).map_err(invalid))
        .collect::<Result<Vec<_>, _>>()?;
    let revoked = bundle
        .revocations
        .iter()
        .map(|bytes| {
            RevocationStatement::decode(bytes).map(|value| value.device_id).map_err(invalid)
        })
        .collect::<Result<std::collections::HashSet<_>, _>>()?;
    if !known.certificates.values().all(|known| certificates.contains(known))
        || !known.revoked.is_subset(&revoked)
    {
        return Err(PersonalServerError::AdmissionUnverified);
    }
    Ok(())
}
