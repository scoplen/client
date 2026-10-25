// SPDX-License-Identifier: Apache-2.0
//! Exact admission is historical provenance; ordinary Device authentication and K-4 grant use.

use super::*;
use crate::{
    personal_server::{
        PersonalServerError, authentication_tokens, retained::RetainedAccount, sync,
    },
    profiles::{AccountProfile, AccountProfileError, AccountProfiles, ProfileLease},
    store::profiles::{AccountInstallation, ProfileRecord},
};

impl PersonalServer {
    /// Install one exactly confirmed independent Device admission into its own encrypted Account store, then
    /// select it and start the supplied profile catalog's Personal background owner. The optional
    /// local passphrase unlocks existing protection or creates it when no platform keystore is
    /// available; an unlocked keystore-backed profile keeps its existing protection. It is never
    /// an Account password. Call this
    /// Rust operation off the interface thread because factory/key/SQL work is synchronous.
    ///
    /// No Local objects are copied, adopted or uploaded. A failed or cancelled installation
    /// retains the exact keys and reservation for explicit retry. The original pending identity
    /// is archived only after the independent store has durably installed verified current state.
    ///
    /// # Errors
    /// Requires a current Local lease and exact positive historical confirmation; rejects
    /// conflicting files/identity, cancelled or stale work, current Device authentication denial,
    /// unsupported root/epoch transitions, malformed bootstrap and failed durable transactions.
    pub async fn install_password_login_profile(
        &self,
        profiles: &AccountProfiles,
        source: &ProfileLease,
        operation_id: Uuid,
        local_passphrase: Option<SecretVec>,
        cancellation: &RegistrationCancellation,
    ) -> Result<ProfileLease, AccountProfileError> {
        let _operation = self.operation.try_lock().map_err(|_| AccountProfileError::Busy)?;
        let mut changes = profiles.changes();
        let mut root_changes = profiles.local.context_changes();
        let (pending, existing) = profiles.root_password_login_record(source, operation_id)?;
        let (provenance, data, material) = {
            let _active = cancellation.guard().map_err(|_| AccountProfileError::Cancelled)?;
            if let Some(pending) = &pending {
                let payload = profiles.with_current_store(source, |_| verify(pending))??;
                if payload.operation_id != operation_id {
                    return Err(AccountProfileError::NotFound);
                }
                if pending.entry.phase != 2 {
                    return Err(AccountProfileError::ConfirmationRequired);
                }
                let candidate = ProfileRecord {
                    profile: AccountProfile {
                        id: scoplen_model::new_uuid_v7()
                            .map_err(|_| AccountProfileError::Storage)?,
                        origin: payload.origin.clone(),
                        account_id: payload.account_id,
                        personal_vault_id: payload.personal_vault_id,
                        device_id: payload.device_id,
                        operation_id,
                        ready: false,
                    },
                    payload: pending.entry.payload.clone(),
                    signature: pending.entry.account_signature,
                    confirmation: pending
                        .entry
                        .confirmation
                        .clone()
                        .ok_or(AccountProfileError::ConfirmationRequired)?,
                };
                let provenance = profiles.reserve(source, &candidate, &pending.entry)?;
                let data = profiles.with_current_store(source, |_| {
                    profiles.open_candidate(&provenance, local_passphrase)
                })??;
                let target = data.store().ok_or(AccountProfileError::Locked)?;
                let certificate = DeviceCertificate::decode(&payload.device_certificate)
                    .map_err(|_| AccountProfileError::Verification)?;
                profiles
                    .with_current_store(source, |_| {
                        target.initialize_account_profile(
                            &provenance,
                            &pending.entry.private_material,
                            &certificate.display_name,
                        )
                    })?
                    .map_err(|_| AccountProfileError::Storage)?;
                profiles
                    .with_current_store(source, |_| {
                        target.retain_login_bootstrap(&pending.snapshot)
                    })?
                    .map_err(|_| AccountProfileError::Storage)?;
                (provenance, data, pending.entry.private_material.clone())
            } else {
                let provenance = existing
                    .filter(|entry| entry.profile.ready)
                    .ok_or(AccountProfileError::NotFound)?;
                let data = profiles.with_current_store(source, |_| {
                    profiles.open_candidate(&provenance, local_passphrase)
                })??;
                let target = data.store().ok_or(AccountProfileError::Locked)?;
                let identity = target
                    .personal_record()
                    .map_err(|_| AccountProfileError::Storage)?
                    .ok_or(AccountProfileError::Verification)?;
                (provenance, data, identity.private_material)
            }
        };
        let target = data.store().ok_or(AccountProfileError::Locked)?;
        let (identity, previous, admission, retained) = {
            let _active = cancellation.guard().map_err(|_| AccountProfileError::Cancelled)?;
            profiles.with_current_store(source, |_| {
                let historical = RegistrationRecord {
                    payload: provenance.payload.clone(),
                    account_signature: provenance.signature,
                    private_material: material,
                    recovery_saved: false,
                    recovery_confirmed: false,
                    phase: 2,
                    confirmation: Some(provenance.confirmation.clone()),
                    dispatch_generation: 1,
                    unchanged_generation: 0,
                    retry_not_before_ms: 0,
                };
                AccountCommittedConfirmation::from_json(provenance.confirmation.as_bytes())
                    .map_err(|_| AccountProfileError::Verification)?
                    .validate_for_request(
                        AccountRequestKind::Admit,
                        historical.payload.as_bytes(),
                        &historical.account_signature,
                    )
                    .map_err(|_| AccountProfileError::Verification)?;
                let bootstrap = target
                    .login_bootstrap()
                    .map_err(|_| AccountProfileError::Storage)?
                    .ok_or(AccountProfileError::Verification)?;
                let (payload, original) = verify_material(&historical, &bootstrap)?;
                if payload.operation_id != operation_id
                    || payload.origin != provenance.profile.origin
                    || payload.account_id != provenance.profile.account_id
                    || payload.personal_vault_id != provenance.profile.personal_vault_id
                    || payload.device_id != provenance.profile.device_id
                {
                    return Err(AccountProfileError::Verification);
                }
                let identity = target
                    .personal_record()
                    .map_err(|_| AccountProfileError::Storage)?
                    .ok_or(AccountProfileError::Verification)?;
                if identity.private_material != historical.private_material {
                    return Err(AccountProfileError::Verification);
                }
                let previous =
                    target.personal_sync_record().map_err(|_| AccountProfileError::Storage)?;
                let admission = target
                    .personal_admission(&identity)
                    .map_err(|_| AccountProfileError::Storage)?;
                if previous.is_some() != admission.is_some() {
                    return Err(AccountProfileError::Verification);
                }
                let retained = if admission.is_some() {
                    let retained = RetainedAccount::load(&target, &identity)?;
                    sync::validate_against(
                        &target,
                        &identity,
                        previous.as_ref().ok_or(AccountProfileError::Verification)?,
                        None,
                        &original,
                        false,
                    )
                    .map_err(|_| AccountProfileError::Verification)?;
                    retained
                } else {
                    original
                };
                Ok((identity, previous, admission, retained))
            })??
        };
        let current = || {
            let active = cancellation.guard().map_err(|_| PersonalServerError::Busy)?;
            let generation =
                profiles.generation_guard(source).map_err(|_| PersonalServerError::Busy)?;
            if let Some(expected) = &pending
                && source
                    .store
                    .pending_password_login()
                    .map_err(|_| PersonalServerError::Storage)?
                    .as_ref()
                    != Some(expected)
            {
                return Err(PersonalServerError::Busy);
            }
            Ok((active, generation))
        };
        let transport = self.transport.as_ref().map_err(|error| *error)?;
        let exchange = async {
            let tokens = authentication_tokens(&target, &identity, transport, &current)
                .await?
                .ok_or(PersonalServerError::Authentication)?;
            let snapshot =
                sync::fetch_current(&target, &identity, transport, &tokens, &current).await?;
            Ok::<_, PersonalServerError>((tokens, snapshot))
        };
        let (tokens, snapshot) = tokio::select! {
            biased;
            _=cancellation.cancelled()=>return Err(AccountProfileError::Cancelled),
            _=changes.changed()=>return Err(AccountProfileError::ContextChanged),
            _=root_changes.changed()=>return Err(AccountProfileError::ContextChanged),
            result=exchange=>result?,
        };
        let _active = cancellation.guard().map_err(|_| AccountProfileError::Cancelled)?;
        profiles.with_current_store(source, |_| {
            let initial = target
                .login_bootstrap()
                .map_err(|_| AccountProfileError::Storage)?
                .ok_or(AccountProfileError::Verification)?;
            let initial = AccountBootstrapSnapshot::from_cbor(initial.as_bytes())
                .map_err(|_| AccountProfileError::Verification)?;
            let current = scoplen_api::sync::SyncAccountKeyBundle::from_cbor(
                snapshot.account_keys.as_bytes(),
            )
            .map_err(|_| AccountProfileError::Verification)?;
            if !super::super::trust::preserves_revocations(
                &initial.revocations,
                &current.revocations,
            ) {
                return Err(AccountProfileError::Verification);
            }
            sync::validate_against(
                &target,
                &identity,
                &snapshot,
                previous.as_ref(),
                &retained,
                false,
            )
            .map_err(|_| AccountProfileError::Verification)?;
            let (_, anchors) = RetainedAccount::from_snapshot(&target, &identity, &snapshot)?;
            if tokens.access_expires_at <= crate::personal_server::now()?
                || !target
                    .commit_account_installation(AccountInstallation {
                        provenance: &provenance,
                        identity: &identity,
                        anchors: anchors.as_bytes(),
                        tokens: &tokens,
                        snapshot: &snapshot,
                        previous: previous.as_ref(),
                        previous_admission: admission.as_ref(),
                    })
                    .map_err(|_| AccountProfileError::Storage)?
            {
                return Err(AccountProfileError::ContextChanged);
            }
            Ok(())
        })??;
        profiles.finish(source, &provenance, pending.as_ref().map(|p| &p.entry), data)
    }
}
