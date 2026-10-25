// SPDX-License-Identifier: Apache-2.0
//! Independent password sign-in. Bootstrap, capabilities and receipts never grant authority.

use std::collections::BTreeMap;

use scoplen_api::{
    account_admission::{
        AccountBootstrapSnapshot, AccountCommittedConfirmation, AccountDeviceAdmissionPayload,
        AccountEntryOperation, AccountPasswordLoginRequest, AccountPasswordLoginResponse,
        AccountPasswordOptionsRequest, AccountPasswordOptionsResponse,
    },
    sync::{SyncAccountDeviceWrap, SyncAccountKeyBundleUpdate},
};
use scoplen_crypto::{
    AccountKemKeyPair, AccountKemKeyWrap, AccountRequestKind, AccountRequestSignatureInput,
    AccountSigningKeyWrap, DeviceArkWrap, DeviceCertificate, DeviceKemKeyPair, Ed25519SigningKey,
    P256SigningKey, PasswordArkWrap, PasswordBootstrapContext, PasswordKdfContext, PasswordSecrets,
    PersonalVaultKeyWrap, SecretVec, SymmetricKey, account_bootstrap_digest,
    account_capability_digest, generate_device_keys,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    PersonalServer, RegistrationAction, RegistrationCancellation, RegistrationError,
    identity::Secrets,
    registration::PASSWORD_DERIVATION,
    retained::{self, RetainedAccount},
};
use crate::{
    profiles::{AccountProfileError, AccountProfiles, ProfileLease},
    store::{
        Store,
        personal::{PasswordLoginRecord, RegistrationRecord},
    },
};

mod exchange;
mod install;

/// Historical admission state. Only a separately authenticated, verified installation is usable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordLoginPhase {
    /// Verified immutable business bytes have never been handed to the network.
    Ready,
    /// The original admission may have committed; only fresh exact confirmation is safe.
    OutcomeUnknown,
    /// A complete trusted response proves the latest Submit unchanged; retry is explicit.
    RetryAvailable,
    /// The original Submit is known unchanged or never sent, but requires fresh password login.
    SignInRequired,
    /// Exact historical receipt verified. Ordinary Device authentication is still required.
    Committed,
}

/// Safe native metadata; no password, capability, proof or encrypted/decrypted payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordLoginStatus {
    /// Explicit next action for the original operation.
    pub phase: PasswordLoginPhase,
    /// Stable operation to bind callbacks and retries.
    pub operation_id: Uuid,
    /// Exact trusted origin.
    pub origin: String,
    /// Validated canonical username.
    pub username: String,
    /// Existing Account; sign-in never creates a replacement.
    pub account_id: Uuid,
    /// Existing Personal vault.
    pub personal_vault_id: Uuid,
    /// Fresh Device identity, unrelated to the Local writer id.
    pub device_id: Uuid,
    /// Capability expiry applies only to a new Submit, never historical confirmation.
    pub admission_expires_at_ms: u64,
    /// Durable handoff count.
    pub dispatch_generation: u64,
    /// Trusted rate delay, preserved through restart.
    pub retry_not_before_ms: Option<u64>,
}

/// Redacted native failures, with no server text or sensitive input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PasswordLoginError {
    /// Fail-fast bounded work admission.
    #[error("Another account operation is running. Wait for it to finish.")]
    Busy,
    /// Captured Local profile is no longer active.
    #[error("The open profile changed. Reopen the account view before continuing.")]
    ContextChanged,
    /// Existing installed/pending identity cannot be replaced by sign-in.
    #[error(
        "This account or profile already has retained setup. Continue its original operation or open its saved profile."
    )]
    ExistingProfile,
    /// Invalid canonical context, device label or password input.
    #[error("Check the server address, username, account password and device name.")]
    InvalidInput,
    /// Unsupported or internally inconsistent bootstrap.
    #[error(
        "The account identity or encrypted keys could not be verified. Existing data was retained."
    )]
    Verification,
    /// Storage has not durably saved the transition.
    #[error(
        "The encrypted account setup could not be saved. Unlock its original profile and try again."
    )]
    Storage,
    /// No exact retained operation.
    #[error("This sign-in preparation is no longer open.")]
    NotPrepared,
    /// Never reinterpret a missing response as safe rollback.
    #[error(
        "The device admission result is unresolved. Keep its original keys and confirm the exact operation."
    )]
    OutcomeUnknown,
    /// Used/expired/current-state-invalid capability requires a new password login.
    #[error(
        "The sign-in state expired or changed. Keep any unresolved operation and sign in again only after its result is resolved."
    )]
    AdmissionConflict,
    /// Explicit new Submit is allowed only after trusted unchanged response.
    #[error("Review the unchanged result, then explicitly retry this original device admission.")]
    ExplicitRetryRequired,
    /// No trusted latest unchanged result exists.
    #[error("Confirm the original device admission result before starting another attempt.")]
    RetryUnavailable,
    /// Durable backoff remains active.
    #[error("The server asked this sign-in to wait. Try again after its retry time.")]
    RetryDeferred,
    /// Explicit cancellation retains an already prepared operation.
    #[error("Sign-in was cancelled. Any retained operation and keys were preserved.")]
    Cancelled,
    /// Transport errors never imply a business rollback.
    #[error("The HTTPS exchange did not complete. Check the server certificate and connection.")]
    Network,
    /// Bound elapsed network time.
    #[error("Sign-in timed out. Keep its original keys and check any pending result.")]
    Timeout,
    /// No supported frozen route.
    #[error("This server does not support native account sign-in. Contact its operator.")]
    UnsupportedService,
    /// Strict codec or transport metadata failure.
    #[error("The server response did not match this sign-in. Its original data was retained.")]
    InvalidResponse,
    /// Common wrong-password/unknown-user denial.
    #[error("Sign-in could not be verified. Check the account details and try again.")]
    AuthenticationDenied,
    /// Exact trusted unchanged request failure.
    #[error("The server rejected this sign-in request. Its original data was retained.")]
    RequestRejected,
    /// Service policy denial.
    #[error("The server does not permit this sign-in. Contact its operator.")]
    PolicyDenied,
    /// Account lifetime admission capacity.
    #[error("The server cannot admit another device. Contact its operator.")]
    QuotaExceeded,
    /// Exact bounded common authentication delay.
    #[error("The server asked sign-in to wait {retry_after_seconds} seconds.")]
    RateLimited {
        /// Wait in the shared 1..=300-second range.
        retry_after_seconds: u16,
    },
    /// Trusted transient storage error.
    #[error("The server could not complete this request. Keep its original data and try later.")]
    ServiceUnavailable,
}

impl From<RegistrationError> for PasswordLoginError {
    fn from(error: RegistrationError) -> Self {
        match error {
            RegistrationError::Busy => Self::Busy,
            RegistrationError::ContextChanged => Self::ContextChanged,
            RegistrationError::InvalidInput => Self::InvalidInput,
            RegistrationError::Storage => Self::Storage,
            RegistrationError::Cancelled => Self::Cancelled,
            RegistrationError::Timeout => Self::Timeout,
            RegistrationError::Network => Self::Network,
            RegistrationError::UnsupportedService => Self::UnsupportedService,
            RegistrationError::RequestRejected => Self::RequestRejected,
            RegistrationError::PolicyDenied => Self::PolicyDenied,
            RegistrationError::AuthenticationDenied => Self::AuthenticationDenied,
            RegistrationError::QuotaExceeded => Self::QuotaExceeded,
            RegistrationError::RateLimited { retry_after_seconds } => {
                Self::RateLimited { retry_after_seconds }
            }
            RegistrationError::ServiceUnavailable => Self::ServiceUnavailable,
            RegistrationError::OutcomeUnknown => Self::OutcomeUnknown,
            _ => Self::InvalidResponse,
        }
    }
}

impl PersonalServer {
    /// Fetch native password options over verified TLS 1.3/H2, derive once in a bounded Rust
    /// worker, authenticate, open the original ARK/private roots and every retained Personal
    /// epoch, then durably prepare one fresh Device admission. No ordinary tokens are issued.
    /// Password/KEK/AuthSecret are transient; cancelling derivation discards its result.
    ///
    /// # Errors
    /// Rejects concurrent/stale/occupied Local contexts, invalid inputs, password denial,
    /// unsupported/incorrect bootstrap, HTTP failures or a failed durable preparation.
    #[allow(clippy::too_many_arguments)]
    pub async fn begin_password_login(
        &self,
        profiles: &AccountProfiles,
        source: &ProfileLease,
        origin: &str,
        username: &str,
        device_name: &str,
        password: SecretVec,
        cancellation: &RegistrationCancellation,
    ) -> Result<PasswordLoginStatus, PasswordLoginError> {
        let _operation = self.operation.try_lock().map_err(|_| PasswordLoginError::Busy)?;
        PasswordKdfContext::new(origin, username, 1, &[0; 16])
            .map_err(|_| PasswordLoginError::InvalidInput)?;
        if device_name.trim().is_empty()
            || device_name.len() > 128
            || device_name.chars().any(char::is_control)
        {
            return Err(PasswordLoginError::InvalidInput);
        }
        check(profiles, source, cancellation, || {
            if !source.store.registration_available().map_err(storage)? {
                return Err(PasswordLoginError::ExistingProfile);
            }
            Ok(())
        })?;
        let derivation = PASSWORD_DERIVATION.try_acquire().map_err(|_| PasswordLoginError::Busy)?;
        let mut changes = profiles.changes();
        let mut root_changes = profiles.local.context_changes();
        let transport = self.transport.as_ref().map_err(|_| PasswordLoginError::Network)?;
        let options = exchange::until_stopped(
            cancellation,
            &mut changes,
            &mut root_changes,
            transport.registration_post(
                origin,
                AccountEntryOperation::PasswordOptions,
                SecretVec::new(
                    AccountPasswordOptionsRequest { username: username.into() }
                        .to_json()
                        .map_err(invalid)?,
                ),
            ),
        )
        .await?;
        check(profiles, source, cancellation, || Ok(()))?;
        if options.status != 200 {
            return Err(exchange::problem(&options)?);
        }
        let options =
            AccountPasswordOptionsResponse::from_json(options.body.as_bytes()).map_err(invalid)?;
        if options.expires_at_ms <= now_ms()? {
            return Err(PasswordLoginError::InvalidResponse);
        }
        let kdf = PasswordKdfContext::new(origin, username, 1, &options.salt).map_err(invalid)?;
        let derive = tokio::task::spawn_blocking(move || {
            let secrets = kdf.derive(password).map_err(|_| PasswordLoginError::InvalidInput)?;
            Ok::<_, PasswordLoginError>((secrets, derivation))
        });
        let (secrets, derivation) =
            exchange::until_stopped(cancellation, &mut changes, &mut root_changes, async {
                derive.await.map_err(|_| PasswordLoginError::Verification)?
            })
            .await?;
        let request = check(profiles, source, cancellation, || {
            if options.expires_at_ms <= now_ms()? {
                return Err(PasswordLoginError::InvalidResponse);
            }
            AccountPasswordLoginRequest {
                attempt_id: options.attempt_id,
                auth_secret: secrets.auth_secret().clone(),
            }
            .to_json()
            .map_err(invalid)
        })?;
        let response = exchange::until_stopped(
            cancellation,
            &mut changes,
            &mut root_changes,
            transport.registration_post(origin, AccountEntryOperation::PasswordLogin, request),
        )
        .await?;
        check(profiles, source, cancellation, || Ok(()))?;
        if response.status != 200 {
            return Err(exchange::problem(&response)?);
        }
        let device_name = device_name.to_owned();
        let prepare = tokio::task::spawn_blocking(move || {
            let _derivation = derivation;
            let response = AccountPasswordLoginResponse::from_json(response.body.as_bytes())
                .map_err(invalid)?;
            prepare(response, &secrets, &device_name)
        });
        let pending =
            exchange::until_stopped(cancellation, &mut changes, &mut root_changes, async {
                prepare.await.map_err(|_| PasswordLoginError::Verification)?
            })
            .await?;
        check(profiles, source, cancellation, || {
            if !source.store.registration_available().map_err(storage)? {
                return Err(PasswordLoginError::ExistingProfile);
            }
            let payload = verify(&pending)?;
            if source
                .store
                .profile_catalog()
                .map_err(storage)?
                .iter()
                .any(|p| p.origin == payload.origin && p.account_id == payload.account_id)
            {
                return Err(PasswordLoginError::ExistingProfile);
            }
            source.store.insert_password_login(&pending).map_err(storage)?;
            status(&pending)
        })
    }

    /// Reverify encrypted pending material after cancellation or process restart, without
    /// password/network access. It cannot turn a receipt into current Device authority.
    /// # Errors
    /// Rejects stale profiles, malformed retained state or unavailable SQLCipher data.
    pub fn password_login_status(
        &self,
        profiles: &AccountProfiles,
        source: &ProfileLease,
    ) -> Result<Option<PasswordLoginStatus>, PasswordLoginError> {
        local(profiles, source, || {
            source.store.pending_password_login().map_err(storage)?.as_ref().map(status).transpose()
        })
    }

    /// Discard only a never-dispatched or durably proven unchanged admission. An unresolved
    /// mutation remains retained even when its capability expires or the user cancels exchange.
    /// # Errors
    /// Rejects busy/stale/unknown/committed operations and failed durable deletion.
    pub fn cancel_password_login(
        &self,
        profiles: &AccountProfiles,
        source: &ProfileLease,
        operation_id: Uuid,
    ) -> Result<(), PasswordLoginError> {
        let _operation = self.operation.try_lock().map_err(|_| PasswordLoginError::Busy)?;
        local(profiles, source, || {
            let pending = record(&source.store, operation_id)?;
            if pending.entry.phase != 0
                && !(pending.entry.phase == 1
                    && pending.entry.dispatch_generation == pending.entry.unchanged_generation)
            {
                return Err(PasswordLoginError::OutcomeUnknown);
            }
            changed(source.store.cancel_password_login_record(&pending))
        })
    }
}

fn prepare(
    response: AccountPasswordLoginResponse,
    password: &PasswordSecrets,
    device_name: &str,
) -> Result<PasswordLoginRecord, PasswordLoginError> {
    if response.expires_at_ms <= now_ms()? {
        return Err(PasswordLoginError::AdmissionConflict);
    }
    let snapshot =
        AccountBootstrapSnapshot::from_cbor(response.snapshot.as_bytes()).map_err(invalid)?;
    snapshot.validate_admission_state().map_err(invalid)?;
    if snapshot.origin != password.context().origin()
        || snapshot.username != password.context().username()
        || &snapshot.password_salt != password.context().salt()
    {
        return Err(PasswordLoginError::Verification);
    }
    let mut bundle =
        SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).map_err(invalid)?;
    let context = PasswordBootstrapContext::new(
        password.context().clone(),
        snapshot.account_id,
        snapshot.personal_vault_id,
        &snapshot.account_signing_public_key,
        &snapshot.account_kem_public_key,
        snapshot.credential_generation,
    )
    .map_err(invalid)?;
    let opened = password
        .open_bootstrap(
            &context,
            &PasswordArkWrap::decode(&snapshot.password_ark).map_err(invalid)?,
            &AccountSigningKeyWrap::decode(&bundle.account_signing_key).map_err(invalid)?,
            &AccountKemKeyWrap::decode(&bundle.account_kem_key).map_err(invalid)?,
        )
        .map_err(|_| PasswordLoginError::Verification)?;
    let epochs = open_epochs(&snapshot, opened.ark())?;
    let device = generate_device_keys().map_err(invalid)?;
    let device_id = scoplen_model::new_uuid_v7().map_err(invalid)?;
    let operation_id = scoplen_model::new_uuid_v7().map_err(invalid)?;
    let certificate = DeviceCertificate::issue(
        &opened.keys().signing,
        device_id,
        snapshot.account_id,
        device.signing.public_key_sec1(),
        device.kem.public_key().to_vec(),
        device_name.to_owned(),
        std::env::consts::OS.into(),
        now_ms()?,
    )
    .map_err(invalid)?
    .encode()
    .map_err(invalid)?;
    let wrapped =
        DeviceArkWrap::seal(snapshot.account_id, device_id, device.kem.public_key(), opened.ark())
            .map_err(invalid)?;
    if wrapped.open(snapshot.account_id, device_id, &device.kem).map_err(invalid)? != *opened.ark()
    {
        return Err(PasswordLoginError::Verification);
    }
    bundle.revision = bundle.revision.checked_add(1).ok_or(PasswordLoginError::Verification)?;
    bundle
        .device_wraps
        .push(SyncAccountDeviceWrap { device_id, wrapped_ark: wrapped.encode().to_vec() });
    bundle.device_wraps.sort_by_key(|w| w.device_id);
    bundle.signature =
        opened.keys().signing.sign(&bundle.signature_input().map_err(invalid)?).to_vec();
    let payload = AccountDeviceAdmissionPayload {
        operation_id,
        origin: snapshot.origin.clone(),
        username: snapshot.username.clone(),
        account_id: snapshot.account_id,
        personal_vault_id: snapshot.personal_vault_id,
        device_id,
        credential_generation: snapshot.credential_generation,
        snapshot_digest: account_bootstrap_digest(response.snapshot.as_bytes()),
        capability_digest: account_capability_digest(response.admission_token.as_bytes()),
        device_certificate: certificate,
        key_bundle: bundle.to_cbor().map_err(invalid)?,
    };
    payload
        .validate_for_snapshot(
            &snapshot,
            response.snapshot.as_bytes(),
            response.admission_token.as_bytes(),
        )
        .map_err(invalid)?;
    let bytes = SecretVec::new(payload.to_cbor().map_err(invalid)?);
    let signature = AccountRequestSignatureInput::new(AccountRequestKind::Admit, bytes.as_bytes())
        .map_err(invalid)?
        .sign(&opened.keys().signing);
    let mut material = Zeroizing::new(Vec::with_capacity(193));
    material.push(2);
    for bytes in [
        device.signing.private_key_bytes().as_ref(),
        device.kem.private_key_bytes().as_ref(),
        opened.ark().as_ref(),
        opened.keys().signing.private_key_bytes().as_ref(),
        opened.keys().kem.private_key_bytes().as_ref(),
        epochs
            .get(&snapshot.personal.current_epoch)
            .ok_or(PasswordLoginError::Verification)?
            .as_ref(),
    ] {
        material.extend_from_slice(bytes);
    }
    let record = PasswordLoginRecord {
        entry: RegistrationRecord {
            payload: bytes,
            account_signature: signature,
            private_material: SecretVec::new(std::mem::take(&mut *material)),
            recovery_saved: false,
            recovery_confirmed: false,
            phase: 0,
            confirmation: None,
            dispatch_generation: 0,
            unchanged_generation: 0,
            retry_not_before_ms: 0,
        },
        snapshot: response.snapshot,
        token: response.admission_token,
        expires_at_ms: response.expires_at_ms,
        restart_required: false,
    };
    verify(&record)?;
    Ok(record)
}

fn open_epochs(
    snapshot: &AccountBootstrapSnapshot,
    ark: &SymmetricKey,
) -> Result<BTreeMap<u32, SymmetricKey>, PasswordLoginError> {
    snapshot
        .personal
        .epochs
        .iter()
        .map(|e| {
            Ok((
                e.epoch,
                PersonalVaultKeyWrap::decode(&e.wrapped_key)
                    .map_err(invalid)?
                    .open(snapshot.account_id, snapshot.personal_vault_id, e.epoch, ark)
                    .map_err(invalid)?,
            ))
        })
        .collect()
}

fn verify_material(
    entry: &RegistrationRecord,
    raw: &SecretVec,
) -> Result<(AccountDeviceAdmissionPayload, RetainedAccount), PasswordLoginError> {
    let p = AccountDeviceAdmissionPayload::from_cbor(entry.payload.as_bytes()).map_err(invalid)?;
    let snapshot = AccountBootstrapSnapshot::from_cbor(raw.as_bytes()).map_err(invalid)?;
    snapshot.validate_admission_state().map_err(invalid)?;
    if snapshot.origin != p.origin
        || snapshot.username != p.username
        || snapshot.account_id != p.account_id
        || snapshot.personal_vault_id != p.personal_vault_id
        || snapshot.credential_generation != p.credential_generation
        || account_bootstrap_digest(raw.as_bytes()) != p.snapshot_digest
    {
        return Err(PasswordLoginError::Verification);
    }
    let s = Secrets::parse(&entry.private_material).map_err(invalid)?;
    if s.recovery().is_some() {
        return Err(PasswordLoginError::Verification);
    }
    let signing = P256SigningKey::from_bytes(s.signing()).map_err(invalid)?;
    let kem = DeviceKemKeyPair::from_private_bytes(s.device_kem()).map_err(invalid)?;
    let root = Ed25519SigningKey::from_bytes(s.account_signing()).map_err(invalid)?;
    let root_kem = AccountKemKeyPair::from_private_bytes(s.account_kem()).map_err(invalid)?;
    AccountRequestSignatureInput::new(AccountRequestKind::Admit, entry.payload.as_bytes())
        .map_err(invalid)?
        .verify(&snapshot.account_signing_public_key, &entry.account_signature)
        .map_err(invalid)?;
    let certificate = DeviceCertificate::decode(&p.device_certificate).map_err(invalid)?;
    certificate.verify(&snapshot.account_signing_public_key).map_err(invalid)?;
    if root.public_key() != snapshot.account_signing_public_key
        || root_kem.public_key() != snapshot.account_kem_public_key
        || certificate.signing_public_key != signing.public_key_sec1()
        || certificate.kem_public_key != kem.public_key()
    {
        return Err(PasswordLoginError::Verification);
    }
    let ark = SymmetricKey::from_slice(s.ark()).ok_or(PasswordLoginError::Verification)?;
    let bundle = SyncAccountKeyBundleUpdate::from_cbor(&p.key_bundle).map_err(invalid)?;
    scoplen_crypto::ed25519_verify(
        &snapshot.account_signing_public_key,
        &bundle.signature_input().map_err(invalid)?,
        &bundle.signature,
    )
    .map_err(invalid)?;
    let old = SyncAccountKeyBundleUpdate::from_cbor(&snapshot.key_bundle).map_err(invalid)?;
    let own = bundle
        .device_wraps
        .iter()
        .find(|w| w.device_id == p.device_id)
        .ok_or(PasswordLoginError::Verification)?;
    let opened = DeviceArkWrap::decode(&own.wrapped_ark)
        .map_err(invalid)?
        .open(p.account_id, p.device_id, &kem)
        .map_err(invalid)?;
    let expected_signing =
        SymmetricKey::from_slice(s.account_signing()).ok_or(PasswordLoginError::Verification)?;
    let expected_kem =
        SymmetricKey::from_slice(s.account_kem()).ok_or(PasswordLoginError::Verification)?;
    if opened != ark
        || AccountSigningKeyWrap::decode(&bundle.account_signing_key)
            .map_err(invalid)?
            .open(p.account_id, &ark, &snapshot.account_signing_public_key)
            .map_err(invalid)?
            .private_key_bytes()
            != expected_signing
        || AccountKemKeyWrap::decode(&bundle.account_kem_key)
            .map_err(invalid)?
            .open(p.account_id, &ark, &snapshot.account_kem_public_key)
            .map_err(invalid)?
            .private_key_bytes()
            != expected_kem
        || bundle.revision != old.revision.checked_add(1).ok_or(PasswordLoginError::Verification)?
        || bundle.account_signing_key != old.account_signing_key
        || bundle.account_kem_key != old.account_kem_key
        || bundle.recovery_blob != old.recovery_blob
        || bundle.device_wraps.len() != old.device_wraps.len() + 1
        || bundle
            .device_wraps
            .iter()
            .filter(|w| w.device_id != p.device_id)
            .ne(old.device_wraps.iter())
    {
        return Err(PasswordLoginError::Verification);
    }
    let epochs = open_epochs(&snapshot, &ark)?;
    if epochs.get(&snapshot.personal.current_epoch).map(|key| key.as_bytes().as_slice())
        != Some(s.vault())
    {
        return Err(PasswordLoginError::Verification);
    }
    let retained = RetainedAccount {
        signing_public: snapshot.account_signing_public_key,
        kem_public: snapshot.account_kem_public_key,
        certificate,
        revision: bundle.revision,
        anchor: retained::projection_anchor(
            bundle.revision,
            &own.wrapped_ark,
            &bundle.account_signing_key,
            &bundle.account_kem_key,
            &bundle.recovery_blob,
        ),
        artifacts: retained::artifacts_anchor(
            &bundle.account_signing_key,
            &bundle.account_kem_key,
            &bundle.recovery_blob,
        ),
        vault_keys: retained::vault_key_anchor(&epochs),
        vault_wraps: Some(retained::digest(
            b"scoplen-client-personal-wraps-v1",
            &[&scoplen_api::sync::SyncVaultKeysResponse {
                keys: snapshot
                    .personal
                    .epochs
                    .iter()
                    .map(|e| scoplen_api::sync::SyncVaultKey {
                        epoch: u64::from(e.epoch),
                        wrapped_vault_key: e.wrapped_key.to_vec(),
                    })
                    .collect(),
            }
            .to_cbor()
            .map_err(invalid)?],
        )),
        current_epoch: snapshot.personal.current_epoch,
    };
    Ok((p, retained))
}

fn verify(
    record: &PasswordLoginRecord,
) -> Result<AccountDeviceAdmissionPayload, PasswordLoginError> {
    let e = &record.entry;
    if !(0..=2).contains(&e.phase)
        || e.recovery_saved
        || e.recovery_confirmed
        || e.dispatch_generation < 0
        || e.unchanged_generation < 0
        || e.unchanged_generation > e.dispatch_generation
        || e.retry_not_before_ms < 0
        || record.expires_at_ms == 0
        || record.restart_required
            && (e.phase == 0 || (e.phase == 1 && e.dispatch_generation != e.unchanged_generation))
        || (e.phase == 0) != (e.dispatch_generation == 0)
        || (e.phase == 2) != e.confirmation.is_some()
    {
        return Err(PasswordLoginError::Verification);
    }
    let (p, _) = verify_material(e, &record.snapshot)?;
    let snapshot =
        AccountBootstrapSnapshot::from_cbor(record.snapshot.as_bytes()).map_err(invalid)?;
    p.validate_for_snapshot(&snapshot, record.snapshot.as_bytes(), record.token.as_bytes())
        .map_err(invalid)?;
    if let Some(c) = &e.confirmation {
        AccountCommittedConfirmation::from_json(c.as_bytes())
            .map_err(invalid)?
            .validate_for_request(
                AccountRequestKind::Admit,
                e.payload.as_bytes(),
                &e.account_signature,
            )
            .map_err(invalid)?;
    }
    Ok(p)
}

fn status(record: &PasswordLoginRecord) -> Result<PasswordLoginStatus, PasswordLoginError> {
    let p = verify(record)?;
    let e = &record.entry;
    Ok(PasswordLoginStatus {
        phase: match e.phase {
            0 if record.expires_at_ms <= now_ms()? => PasswordLoginPhase::SignInRequired,
            0 => PasswordLoginPhase::Ready,
            1 if e.dispatch_generation == e.unchanged_generation
                && (record.restart_required || record.expires_at_ms <= now_ms()?) =>
            {
                PasswordLoginPhase::SignInRequired
            }
            1 if e.dispatch_generation == e.unchanged_generation => {
                PasswordLoginPhase::RetryAvailable
            }
            1 => PasswordLoginPhase::OutcomeUnknown,
            2 => PasswordLoginPhase::Committed,
            _ => return Err(PasswordLoginError::Verification),
        },
        operation_id: p.operation_id,
        origin: p.origin,
        username: p.username,
        account_id: p.account_id,
        personal_vault_id: p.personal_vault_id,
        device_id: p.device_id,
        admission_expires_at_ms: record.expires_at_ms,
        dispatch_generation: e.dispatch_generation as u64,
        retry_not_before_ms: (e.retry_not_before_ms > 0).then_some(e.retry_not_before_ms as u64),
    })
}
fn local<T>(
    profiles: &AccountProfiles,
    source: &ProfileLease,
    operation: impl FnOnce() -> Result<T, PasswordLoginError>,
) -> Result<T, PasswordLoginError> {
    if source.account().is_some() {
        return Err(PasswordLoginError::ContextChanged);
    }
    profiles.with_current_store(source, |_| operation()).map_err(profile)?
}
fn check<T>(
    profiles: &AccountProfiles,
    source: &ProfileLease,
    cancellation: &RegistrationCancellation,
    operation: impl FnOnce() -> Result<T, PasswordLoginError>,
) -> Result<T, PasswordLoginError> {
    local(profiles, source, || {
        let _active = cancellation.guard().map_err(PasswordLoginError::from)?;
        operation()
    })
}
fn record(store: &Store, operation: Uuid) -> Result<PasswordLoginRecord, PasswordLoginError> {
    let record =
        store.pending_password_login().map_err(storage)?.ok_or(PasswordLoginError::NotPrepared)?;
    if verify(&record)?.operation_id != operation {
        return Err(PasswordLoginError::NotPrepared);
    }
    Ok(record)
}
fn now_ms() -> Result<u64, PasswordLoginError> {
    scoplen_model::system_time_millis().map_err(invalid)
}
fn invalid(_: impl std::fmt::Debug) -> PasswordLoginError {
    PasswordLoginError::Verification
}
fn storage(_: crate::store::StoreError) -> PasswordLoginError {
    PasswordLoginError::Storage
}
fn changed(result: Result<bool, crate::store::StoreError>) -> Result<(), PasswordLoginError> {
    if result.map_err(storage)? { Ok(()) } else { Err(PasswordLoginError::ContextChanged) }
}
fn profile(error: AccountProfileError) -> PasswordLoginError {
    match error {
        AccountProfileError::Busy => PasswordLoginError::Busy,
        AccountProfileError::ContextChanged => PasswordLoginError::ContextChanged,
        _ => PasswordLoginError::Storage,
    }
}

#[cfg(test)]
mod tests;
