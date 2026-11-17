// SPDX-License-Identifier: Apache-2.0
//! Existing-Device credential replacement, independent of current session authority.

use scoplen_api::{
    account_admission::{
        AccountBootstrapSnapshot, AccountCommittedConfirmation, AccountDeviceAdmissionPayload,
        AccountEntryOperation, AccountPasswordChangeConfirmation, AccountPasswordChangePayload,
        AccountPasswordLoginRequest, AccountPasswordLoginResponse, AccountPasswordOptionsRequest,
        AccountPasswordOptionsResponse, AccountRegistrationPayload,
    },
    sync::{
        SyncAccountKeyBundle, SyncAccountKeyBundleUpdate, SyncSessionResponse, SyncVaultKey,
        SyncVaultKeysResponse,
    },
};
use scoplen_crypto::{
    AccountKemKeyWrap, AccountRequestKind, AccountRequestSignatureInput, AccountSigningKeyWrap,
    DeviceCertificate, PasswordArkWrap, PasswordBootstrapContext, PasswordKdfContext,
    PasswordSecrets, SecretVec, SymmetricKey, account_bootstrap_digest, account_capability_digest,
    normalize_account_password,
};
use uuid::Uuid;

use super::{
    PasswordLoginError, PersonalServer, RegistrationCancellation, RegistrationError,
    identity::Secrets, password_login::exchange::problem, registration::PASSWORD_DERIVATION,
    retained::RetainedAccount,
};
use crate::{
    profiles::{AccountProfileError, AccountProfiles, ProfileLease},
    store::{
        Store,
        personal::{PasswordChangeRecord, PersonalRecord, PersonalSyncRecord},
    },
};

mod exchange;
#[cfg(test)]
mod tests;

/// Safe next action for the original credential replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordChangePhase {
    /// Exact bytes are saved; explicit Submit remains.
    Ready,
    /// Only a fresh proof confirming the original operation is safe.
    OutcomeUnknown,
    /// A trusted unchanged result permits explicit Retry or discard.
    RetryAvailable,
    /// Never-sent or known unchanged work needs a fresh password login.
    SignInRequired,
    /// Exact historical success, without a claim of current generation or authorization.
    Committed,
}

/// Public metadata only; all password, capability and protected bytes stay in Rust.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordChangeStatus {
    /// Explicit next action.
    pub phase: PasswordChangePhase,
    /// Stable original operation.
    pub operation_id: Uuid,
    /// Original bounded retry deadline.
    pub retry_not_before_ms: Option<u64>,
}

/// Fixed, redacted failures for password replacement and historical recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PasswordChangeError {
    /// Another native operation owns this Account.
    #[error("An Account operation is already running.")]
    Busy,
    /// The captured Account is no longer current.
    #[error("The open Account changed. Reopen its Settings.")]
    ContextChanged,
    /// Password policy or local input failure.
    #[error("Enter valid current and new account passwords.")]
    InvalidInput,
    /// Equal normalized passwords must fail before network or derivation.
    #[error("Choose a new password different from the current password.")]
    SamePassword,
    /// Cryptographic or strict response binding failed.
    #[error("The password change could not be verified. Its original data was retained.")]
    Verification,
    /// An encrypted durable boundary failed.
    #[error("The encrypted local data is unavailable.")]
    Storage,
    /// No matching original operation exists.
    #[error("No matching password change is prepared.")]
    NotPrepared,
    /// A Submit may have committed.
    #[error("The password-change result is unknown. Confirm the original operation.")]
    OutcomeUnknown,
    /// Original capability or current credential snapshot is no longer usable for Submit.
    #[error("Discard the unchanged operation and verify the current password again.")]
    SignInRequired,
    /// Retry is always explicit.
    #[error("Choose Retry for the original unchanged operation.")]
    ExplicitRetryRequired,
    /// The original operation cannot be retried.
    #[error("This operation cannot be retried. Check its original result.")]
    RetryUnavailable,
    /// A bounded server delay has not elapsed.
    #[error("Wait before retrying this original operation.")]
    RetryDeferred,
    /// Cancellation retains any dispatched operation.
    #[error("The password-change exchange stopped. Check its saved state.")]
    Cancelled,
    /// Transport errors cannot establish rollback.
    #[error("The HTTPS exchange did not complete. Check the connection and saved result.")]
    Network,
    /// Server does not implement the published ceremony.
    #[error("This server does not support native password changes.")]
    UnsupportedService,
    /// Common password/capability/proof/receipt denial.
    #[error("The current password or original request could not be verified.")]
    AuthenticationDenied,
    /// Trusted unchanged policy refusal.
    #[error("The server does not permit this password change.")]
    PolicyDenied,
    /// Trusted unchanged transient storage error.
    #[error("The server could not complete this request. Keep its original data and try later.")]
    ServiceUnavailable,
}

impl From<PasswordLoginError> for PasswordChangeError {
    fn from(value: PasswordLoginError) -> Self {
        use PasswordLoginError as E;
        match value {
            E::Busy => Self::Busy,
            E::ContextChanged => Self::ContextChanged,
            E::InvalidInput => Self::InvalidInput,
            E::Storage => Self::Storage,
            E::NotPrepared => Self::NotPrepared,
            E::OutcomeUnknown => Self::OutcomeUnknown,
            E::AdmissionConflict => Self::SignInRequired,
            E::ExplicitRetryRequired => Self::ExplicitRetryRequired,
            E::RetryUnavailable => Self::RetryUnavailable,
            E::RetryDeferred | E::RateLimited { .. } => Self::RetryDeferred,
            E::Cancelled => Self::Cancelled,
            E::Network | E::Timeout => Self::Network,
            E::UnsupportedService => Self::UnsupportedService,
            E::AuthenticationDenied => Self::AuthenticationDenied,
            E::PolicyDenied => Self::PolicyDenied,
            E::ServiceUnavailable => Self::ServiceUnavailable,
            _ => Self::Verification,
        }
    }
}
impl From<RegistrationError> for PasswordChangeError {
    fn from(value: RegistrationError) -> Self {
        PasswordLoginError::from(value).into()
    }
}

impl PersonalServer {
    /// Verify old-password bootstrap against the installed roots, original Device and K-4,
    /// then retain a fresh password wrapper for the same ARK before any business Submit.
    /// Equal normalized passwords cause zero network or KDF work.
    /// # Errors
    /// Rejects stale/Local contexts, invalid/equal passwords, mismatched or stale bootstrap,
    /// authentication/transport failures and unsuccessful durable preparation.
    pub async fn begin_password_change(
        &self,
        profiles: &AccountProfiles,
        source: &ProfileLease,
        old_password: SecretVec,
        new_password: SecretVec,
        cancellation: &RegistrationCancellation,
    ) -> Result<PasswordChangeStatus, PasswordChangeError> {
        let _operation = self.operation.try_lock().map_err(|_| PasswordChangeError::Busy)?;
        let old_password = normalize_account_password(old_password)
            .map_err(|_| PasswordChangeError::InvalidInput)?;
        let new_password = normalize_account_password(new_password)
            .map_err(|_| PasswordChangeError::InvalidInput)?;
        if old_password == new_password {
            return Err(PasswordChangeError::SamePassword);
        }
        let (identity, retained, username, baseline) =
            check(profiles, source, cancellation, || {
                if source.store.pending_password_change().map_err(storage)?.is_some() {
                    return Err(PasswordChangeError::Busy);
                }
                installed(source)
            })?;
        let derivation =
            PASSWORD_DERIVATION.try_acquire().map_err(|_| PasswordChangeError::Busy)?;
        let mut changes = profiles.changes();
        let mut root_changes = profiles.local.context_changes();
        let transport = self.transport.as_ref().map_err(|_| PasswordChangeError::Network)?;
        let options = until_stopped(
            cancellation,
            &mut changes,
            &mut root_changes,
            transport.registration_post(
                &identity.origin,
                AccountEntryOperation::PasswordOptions,
                SecretVec::new(
                    AccountPasswordOptionsRequest { username: username.clone() }
                        .to_json()
                        .map_err(invalid)?,
                ),
            ),
        )
        .await?;
        check(profiles, source, cancellation, || Ok(()))?;
        if options.status != 200 {
            return Err(problem(&options)?.into());
        }
        let options =
            AccountPasswordOptionsResponse::from_json(options.body.as_bytes()).map_err(invalid)?;
        if options.expires_at_ms <= now_ms()? {
            return Err(PasswordChangeError::Verification);
        }
        let kdf = PasswordKdfContext::new(&identity.origin, &username, 1, &options.salt)
            .map_err(invalid)?;
        let derive = tokio::task::spawn_blocking(move || {
            let secrets =
                kdf.derive(old_password).map_err(|_| PasswordChangeError::InvalidInput)?;
            Ok::<_, PasswordChangeError>((secrets, derivation))
        });
        let (secrets, derivation) =
            until_stopped(cancellation, &mut changes, &mut root_changes, async {
                derive.await.map_err(invalid)?
            })
            .await?;
        let body = check(profiles, source, cancellation, || {
            if options.expires_at_ms <= now_ms()? {
                return Err(PasswordChangeError::Verification);
            }
            AccountPasswordLoginRequest {
                attempt_id: options.attempt_id,
                auth_secret: secrets.auth_secret().clone(),
            }
            .to_json()
            .map_err(invalid)
        })?;
        let response = until_stopped(
            cancellation,
            &mut changes,
            &mut root_changes,
            transport.registration_post(
                &identity.origin,
                AccountEntryOperation::PasswordLogin,
                body,
            ),
        )
        .await?;
        check(profiles, source, cancellation, || Ok(()))?;
        if response.status != 200 {
            return Err(problem(&response)?.into());
        }
        let response =
            AccountPasswordLoginResponse::from_json(response.body.as_bytes()).map_err(invalid)?;
        let snapshot =
            AccountBootstrapSnapshot::from_cbor(response.snapshot.as_bytes()).map_err(invalid)?;
        check(profiles, source, cancellation, || {
            validate_snapshot(&source.store, &identity, &retained, &username, baseline, &snapshot)
        })?;
        let device_id = source.store.device_id();
        let prepare = tokio::task::spawn_blocking(move || {
            let _derivation = derivation;
            prepare(response, &secrets, new_password, &identity, device_id, &retained)
        });
        let pending = until_stopped(cancellation, &mut changes, &mut root_changes, async {
            prepare.await.map_err(invalid)?
        })
        .await?;
        check(profiles, source, cancellation, || {
            let payload = verify(source, &pending)?;
            source
                .store
                .observe_credential_generation(payload.credential_generation)
                .map_err(storage)?;
            source.store.insert_password_change(&pending).map_err(storage)?;
            status(&pending)
        })
    }

    /// Read and verify encrypted pending data without a session, password, KDF or network.
    /// # Errors
    /// Rejects stale profiles, unavailable storage and invalid retained bindings.
    pub fn password_change_status(
        &self,
        profiles: &AccountProfiles,
        source: &ProfileLease,
    ) -> Result<Option<PasswordChangeStatus>, PasswordChangeError> {
        account(profiles, source, || {
            let Some(mut r) = source.store.pending_password_change().map_err(storage)? else {
                return Ok(None);
            };
            verify(source, &r)?;
            if r.token.is_some() && r.expires_at_ms <= now_ms()? {
                let original = r.clone();
                r.token = None;
                changed(source.store.update_password_change(&original, &r, None))?;
            }
            status(&r).map(Some)
        })
    }

    /// Discard never-sent/known-unchanged work, or acknowledge an exact historical success.
    /// Unknown work remains durable even after expiry, restart, logout or Device revocation.
    /// # Errors
    /// Rejects busy/stale/unknown operations and failed durable deletion.
    pub fn discard_password_change(
        &self,
        profiles: &AccountProfiles,
        source: &ProfileLease,
        operation: Uuid,
    ) -> Result<(), PasswordChangeError> {
        let _operation = self.operation.try_lock().map_err(|_| PasswordChangeError::Busy)?;
        account(profiles, source, || {
            let r = record(source, operation)?;
            if r.phase == 1 && r.dispatch_generation != r.unchanged_generation {
                return Err(PasswordChangeError::OutcomeUnknown);
            }
            changed(source.store.discard_password_change(&r))
        })
    }
}

fn installed(
    source: &ProfileLease,
) -> Result<(PersonalRecord, RetainedAccount, String, u64), PasswordChangeError> {
    let profile =
        source.account().filter(|p| p.ready).ok_or(PasswordChangeError::ContextChanged)?;
    let provenance = source
        .store
        .account_profile_binding()
        .map_err(storage)?
        .ok_or(PasswordChangeError::Verification)?;
    let identity = source
        .store
        .personal_record()
        .map_err(storage)?
        .ok_or(PasswordChangeError::Verification)?;
    if provenance.profile != *profile
        || profile.origin != identity.origin
        || profile.account_id != identity.account_id
        || profile.personal_vault_id != identity.personal_vault_id
        || profile.device_id != source.store.device_id()
        || !identity.authentication_allowed()
    {
        return Err(PasswordChangeError::Verification);
    }
    let retained = RetainedAccount::load(&source.store, &identity).map_err(invalid)?;
    let (kind, username, generation, origin, account_id, vault_id, device_id, operation) =
        if let Ok(p) = AccountRegistrationPayload::from_cbor(provenance.payload.as_bytes()) {
            if p.account_signing_public_key != retained.signing_public
                || p.account_kem_public_key != retained.kem_public
            {
                return Err(PasswordChangeError::Verification);
            }
            (
                AccountRequestKind::Register,
                p.username,
                1,
                p.origin,
                p.account_id,
                p.personal_vault_id,
                p.device_id,
                p.operation_id,
            )
        } else {
            let p = AccountDeviceAdmissionPayload::from_cbor(provenance.payload.as_bytes())
                .map_err(invalid)?;
            (
                AccountRequestKind::Admit,
                p.username,
                p.credential_generation,
                p.origin,
                p.account_id,
                p.personal_vault_id,
                p.device_id,
                p.operation_id,
            )
        };
    if origin != profile.origin
        || account_id != profile.account_id
        || vault_id != profile.personal_vault_id
        || device_id != profile.device_id
        || operation != profile.operation_id
    {
        return Err(PasswordChangeError::Verification);
    }
    AccountRequestSignatureInput::new(kind, provenance.payload.as_bytes())
        .map_err(invalid)?
        .verify(&retained.signing_public, &provenance.signature)
        .map_err(invalid)?;
    AccountCommittedConfirmation::from_json(provenance.confirmation.as_bytes())
        .map_err(invalid)?
        .validate_for_request(kind, provenance.payload.as_bytes(), &provenance.signature)
        .map_err(invalid)?;
    Ok((identity, retained, username, generation))
}

fn validate_snapshot(
    store: &Store,
    identity: &PersonalRecord,
    retained: &RetainedAccount,
    username: &str,
    baseline: u64,
    s: &AccountBootstrapSnapshot,
) -> Result<(), PasswordChangeError> {
    s.validate_admission_state().map_err(invalid)?;
    let floor =
        store.credential_generation_floor().map_err(storage)?.unwrap_or(baseline).max(baseline);
    if s.origin != identity.origin
        || s.username != username
        || s.account_id != identity.account_id
        || s.personal_vault_id != identity.personal_vault_id
        || s.account_signing_public_key != retained.signing_public
        || s.account_kem_public_key != retained.kem_public
        || s.credential_generation < floor
    {
        return Err(PasswordChangeError::Verification);
    }
    let previous =
        store.personal_sync_record().map_err(storage)?.ok_or(PasswordChangeError::Verification)?;
    let mut session = SyncSessionResponse::from_cbor_with_body_limit(
        previous.session.as_bytes(),
        4 * 1024 * 1024,
    )
    .map_err(invalid)?;
    session.vaults.retain(|v| v.id == s.personal_vault_id);
    let vault = session.vaults.first_mut().ok_or(PasswordChangeError::Verification)?;
    vault.key_epoch = u64::from(s.personal.current_epoch);
    vault.rotation_pending = s.personal.rotation_pending;
    let bundle = SyncAccountKeyBundleUpdate::from_cbor(&s.key_bundle).map_err(invalid)?;
    let own = bundle
        .device_wraps
        .iter()
        .find(|w| w.device_id == store.device_id())
        .ok_or(PasswordChangeError::Verification)?;
    let projected = PersonalSyncRecord {
        generation: previous.generation,
        session: SecretVec::new(session.to_cbor().map_err(invalid)?),
        account_keys: SecretVec::new(
            SyncAccountKeyBundle {
                revision: bundle.revision,
                wrapped_ark: own.wrapped_ark.clone(),
                account_signing_key: bundle.account_signing_key,
                account_kem_key: bundle.account_kem_key,
                recovery_blob: bundle.recovery_blob,
                certificates: s.certificates.clone(),
                revocations: s.revocations.clone(),
            }
            .to_cbor()
            .map_err(invalid)?,
        ),
        vault_keys: SecretVec::new(
            SyncVaultKeysResponse {
                keys: s
                    .personal
                    .epochs
                    .iter()
                    .map(|e| SyncVaultKey {
                        epoch: u64::from(e.epoch),
                        wrapped_vault_key: e.wrapped_key.to_vec(),
                    })
                    .collect(),
            }
            .to_cbor()
            .map_err(invalid)?,
        ),
    };
    super::sync::validate_against(store, identity, &projected, Some(&previous), retained, true)
        .map_err(invalid)?;
    Ok(())
}

fn prepare(
    response: AccountPasswordLoginResponse,
    old: &PasswordSecrets,
    new_password: SecretVec,
    identity: &PersonalRecord,
    device_id: Uuid,
    retained: &RetainedAccount,
) -> Result<PasswordChangeRecord, PasswordChangeError> {
    if response.expires_at_ms <= now_ms()? {
        return Err(PasswordChangeError::SignInRequired);
    }
    let s = AccountBootstrapSnapshot::from_cbor(response.snapshot.as_bytes()).map_err(invalid)?;
    if s.origin != old.context().origin()
        || s.username != old.context().username()
        || &s.password_salt != old.context().salt()
    {
        return Err(PasswordChangeError::Verification);
    }
    let bundle = SyncAccountKeyBundleUpdate::from_cbor(&s.key_bundle).map_err(invalid)?;
    let context = PasswordBootstrapContext::new(
        old.context().clone(),
        s.account_id,
        s.personal_vault_id,
        &s.account_signing_public_key,
        &s.account_kem_public_key,
        s.credential_generation,
    )
    .map_err(invalid)?;
    let signing_wrap =
        AccountSigningKeyWrap::decode(&bundle.account_signing_key).map_err(invalid)?;
    let kem_wrap = AccountKemKeyWrap::decode(&bundle.account_kem_key).map_err(invalid)?;
    let opened = old
        .open_bootstrap(
            &context,
            &PasswordArkWrap::decode(&s.password_ark).map_err(invalid)?,
            &signing_wrap,
            &kem_wrap,
        )
        .map_err(invalid)?;
    let local = Secrets::parse(&identity.private_material).map_err(invalid)?;
    let expected_ark =
        SymmetricKey::from_slice(local.ark()).ok_or(PasswordChangeError::Verification)?;
    let expected_signing = SymmetricKey::from_slice(local.account_signing())
        .ok_or(PasswordChangeError::Verification)?;
    let expected_kem =
        SymmetricKey::from_slice(local.account_kem()).ok_or(PasswordChangeError::Verification)?;
    if *opened.ark() != expected_ark
        || opened.keys().signing.private_key_bytes() != expected_signing
        || opened.keys().kem.private_key_bytes() != expected_kem
    {
        return Err(PasswordChangeError::Verification);
    }
    let generation =
        s.credential_generation.checked_add(1).ok_or(PasswordChangeError::Verification)?;
    let new = PasswordSecrets::create(&s.origin, &s.username, new_password)
        .map_err(|_| PasswordChangeError::InvalidInput)?;
    let context = PasswordBootstrapContext::new(
        new.context().clone(),
        s.account_id,
        s.personal_vault_id,
        &s.account_signing_public_key,
        &s.account_kem_public_key,
        generation,
    )
    .map_err(invalid)?;
    let wrapper = PasswordArkWrap::seal(&new, &context, opened.ark()).map_err(invalid)?;
    if new.open_bootstrap(&context, &wrapper, &signing_wrap, &kem_wrap).map_err(invalid)?.ark()
        != opened.ark()
    {
        return Err(PasswordChangeError::Verification);
    }
    let p = AccountPasswordChangePayload {
        operation_id: scoplen_model::new_uuid_v7().map_err(invalid)?,
        origin: s.origin.clone(),
        username: s.username.clone(),
        account_id: s.account_id,
        personal_vault_id: s.personal_vault_id,
        device_id,
        credential_generation: s.credential_generation,
        new_credential_generation: generation,
        snapshot_digest: account_bootstrap_digest(response.snapshot.as_bytes()),
        capability_digest: account_capability_digest(response.admission_token.as_bytes()),
        password_salt: *new.context().salt(),
        verifier: *new.verifier().as_bytes(),
        password_ark: wrapper.encode(),
    };
    p.validate_for_snapshot(&s, response.snapshot.as_bytes(), response.admission_token.as_bytes())
        .map_err(invalid)?;
    let payload = SecretVec::new(p.to_cbor().map_err(invalid)?);
    let signature =
        AccountRequestSignatureInput::new(AccountRequestKind::PasswordChange, payload.as_bytes())
            .map_err(invalid)?
            .sign(&opened.keys().signing);
    Ok(PasswordChangeRecord {
        payload,
        account_signature: signature,
        snapshot: response.snapshot,
        signing_public: retained.signing_public,
        kem_public: retained.kem_public,
        certificate: retained.certificate.encode().map_err(invalid)?,
        token: Some(response.admission_token),
        expires_at_ms: response.expires_at_ms,
        phase: 0,
        confirmation: None,
        dispatch_generation: 0,
        unchanged_generation: 0,
        retry_not_before_ms: 0,
        restart_required: false,
    })
}

fn verify(
    source: &ProfileLease,
    r: &PasswordChangeRecord,
) -> Result<AccountPasswordChangePayload, PasswordChangeError> {
    let (_, retained, username, _) = installed(source)?;
    let p = AccountPasswordChangePayload::from_cbor(r.payload.as_bytes()).map_err(invalid)?;
    let s = AccountBootstrapSnapshot::from_cbor(r.snapshot.as_bytes()).map_err(invalid)?;
    s.validate_admission_state().map_err(invalid)?;
    let profile = source.account().ok_or(PasswordChangeError::ContextChanged)?;
    let cert = DeviceCertificate::decode(&r.certificate).map_err(invalid)?;
    cert.verify(&r.signing_public).map_err(invalid)?;
    if p.origin != profile.origin
        || p.username != username
        || p.account_id != profile.account_id
        || p.personal_vault_id != profile.personal_vault_id
        || p.device_id != profile.device_id
        || r.signing_public != retained.signing_public
        || r.kem_public != retained.kem_public
        || cert != retained.certificate
        || s.origin != p.origin
        || s.username != p.username
        || s.account_id != p.account_id
        || s.personal_vault_id != p.personal_vault_id
        || s.account_signing_public_key != r.signing_public
        || s.account_kem_public_key != r.kem_public
        || s.credential_generation != p.credential_generation
        || account_bootstrap_digest(r.snapshot.as_bytes()) != p.snapshot_digest
        || !(0..=2).contains(&r.phase)
        || r.dispatch_generation < 0
        || r.unchanged_generation < 0
        || r.unchanged_generation > r.dispatch_generation
        || r.retry_not_before_ms < 0
        || r.expires_at_ms == 0
        || (r.phase == 0) != (r.dispatch_generation == 0)
        || (r.phase == 2) != r.confirmation.is_some()
        || (r.phase == 2 && r.token.is_some())
        || (r.token.is_none() && r.phase != 2 && r.expires_at_ms > now_ms()?)
        || (r.restart_required
            && (r.phase == 0 || (r.phase == 1 && r.dispatch_generation != r.unchanged_generation)))
    {
        return Err(PasswordChangeError::Verification);
    }
    if let Some(token) = &r.token {
        p.validate_for_snapshot(&s, r.snapshot.as_bytes(), token.as_bytes()).map_err(invalid)?;
    }
    AccountRequestSignatureInput::new(AccountRequestKind::PasswordChange, r.payload.as_bytes())
        .map_err(invalid)?
        .verify(&r.signing_public, &r.account_signature)
        .map_err(invalid)?;
    if let Some(c) = &r.confirmation {
        AccountPasswordChangeConfirmation::from_json(c.as_bytes())
            .map_err(invalid)?
            .validate_for_request(r.payload.as_bytes(), &r.account_signature)
            .map_err(invalid)?;
    }
    Ok(p)
}
fn status(r: &PasswordChangeRecord) -> Result<PasswordChangeStatus, PasswordChangeError> {
    Ok(PasswordChangeStatus {
        phase: match r.phase {
            0 if r.expires_at_ms <= now_ms()? => PasswordChangePhase::SignInRequired,
            0 => PasswordChangePhase::Ready,
            1 if r.dispatch_generation != r.unchanged_generation => {
                PasswordChangePhase::OutcomeUnknown
            }
            1 if r.restart_required || r.expires_at_ms <= now_ms()? => {
                PasswordChangePhase::SignInRequired
            }
            1 => PasswordChangePhase::RetryAvailable,
            2 => PasswordChangePhase::Committed,
            _ => return Err(PasswordChangeError::Verification),
        },
        operation_id: AccountPasswordChangePayload::from_cbor(r.payload.as_bytes())
            .map_err(invalid)?
            .operation_id,
        retry_not_before_ms: (r.retry_not_before_ms > 0).then_some(r.retry_not_before_ms as u64),
    })
}
fn account<T>(
    profiles: &AccountProfiles,
    source: &ProfileLease,
    operation: impl FnOnce() -> Result<T, PasswordChangeError>,
) -> Result<T, PasswordChangeError> {
    if !source.account().is_some_and(|p| p.ready) {
        return Err(PasswordChangeError::ContextChanged);
    }
    profiles.with_current_store(source, |_| operation()).map_err(|e| match e {
        AccountProfileError::Busy => PasswordChangeError::Busy,
        AccountProfileError::ContextChanged => PasswordChangeError::ContextChanged,
        _ => PasswordChangeError::Storage,
    })?
}
fn check<T>(
    profiles: &AccountProfiles,
    source: &ProfileLease,
    cancellation: &RegistrationCancellation,
    operation: impl FnOnce() -> Result<T, PasswordChangeError>,
) -> Result<T, PasswordChangeError> {
    account(profiles, source, || {
        let _active = cancellation.guard().map_err(PasswordChangeError::from)?;
        operation()
    })
}
fn record(
    source: &ProfileLease,
    operation: Uuid,
) -> Result<PasswordChangeRecord, PasswordChangeError> {
    let r = source
        .store
        .pending_password_change()
        .map_err(storage)?
        .ok_or(PasswordChangeError::NotPrepared)?;
    if verify(source, &r)?.operation_id != operation {
        return Err(PasswordChangeError::NotPrepared);
    }
    Ok(r)
}
async fn until_stopped<T, E: Into<PasswordChangeError>>(
    cancellation: &RegistrationCancellation,
    changes: &mut tokio::sync::watch::Receiver<i64>,
    root_changes: &mut tokio::sync::watch::Receiver<()>,
    operation: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, PasswordChangeError> {
    tokio::select! {biased;
        _=cancellation.cancelled()=>Err(PasswordChangeError::Cancelled),
        _=changes.changed()=>Err(PasswordChangeError::ContextChanged),
        _=root_changes.changed()=>Err(PasswordChangeError::ContextChanged),
        result=operation=>result.map_err(Into::into),
    }
}
fn invalid(_: impl std::fmt::Debug) -> PasswordChangeError {
    PasswordChangeError::Verification
}
fn storage(_: crate::store::StoreError) -> PasswordChangeError {
    PasswordChangeError::Storage
}
fn now_ms() -> Result<u64, PasswordChangeError> {
    scoplen_model::system_time_millis().map_err(invalid)
}
fn changed(result: Result<bool, crate::store::StoreError>) -> Result<(), PasswordChangeError> {
    if result.map_err(storage)? { Ok(()) } else { Err(PasswordChangeError::ContextChanged) }
}
