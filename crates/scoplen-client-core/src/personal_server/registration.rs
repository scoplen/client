// SPDX-License-Identifier: Apache-2.0
//! Rust-owned registration preparation and HTTPS. No tokens or admitted profile installation.

use std::{fs::OpenOptions, io::Write as _, path::Path, sync::Arc};

use scoplen_api::{
    account_admission::{
        AccountCommittedConfirmation, AccountRegistrationPayload, AccountRegistrationRequest,
        AccountRequestChallengeRequest, AccountRequestChallengeResponse,
    },
    sync::{SyncAccountDeviceWrap, SyncAccountKeyBundleUpdate},
};
use scoplen_crypto::{
    AccountKemKeyPair, AccountKemKeyWrap, AccountRequestIntent, AccountRequestKind,
    AccountRequestProof, AccountRequestSignatureInput, AccountSigningKeyWrap, DeviceArkWrap,
    DeviceCertificate, DeviceKemKeyPair, Ed25519SigningKey, P256SigningKey, PasswordArkWrap,
    PasswordBootstrapContext, PasswordBootstrapError, PasswordKdfContext, PasswordSecrets,
    PersonalVaultKeyWrap, RecoveryBlob, RecoveryKey, SecretVec, SymmetricKey,
    generate_account_keys, generate_device_keys, generate_symmetric_key,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{PersonalServer, identity::Secrets};
use crate::{
    local_data::LocalData,
    store::{Store, personal::RegistrationRecord},
};

mod http;
pub use http::{RegistrationAction, RegistrationCancellation};

// Process-wide, fail-fast admission also covers separate PersonalServer instances. A caller
// runs these synchronous preparation methods on its blocking worker, never on the renderer.
static PASSWORD_DERIVATION: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
static TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Safe local preparation state; even Committed is historical evidence, not current authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationPhase {
    /// Save the generated recovery key and explicitly confirm keeping it safely.
    RecoveryRequired,
    /// Verified exact business bytes are durable and have never been handed to a sender.
    Ready,
    /// The original request may have committed; only exact fresh-proof confirmation is allowed.
    OutcomeUnknown,
    /// A trusted response proves the latest Submit unchanged; another Submit needs explicit Retry.
    RetryAvailable,
    /// Every historical confirmation field matches the original bytes; no Device is installed.
    Committed,
}

/// Public metadata for the captured pending operation. Contains no secret or opaque payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationStatus {
    /// Safe next local action.
    pub phase: RegistrationPhase,
    /// Stable identifier; callbacks must name this operation rather than whichever is open later.
    pub operation_id: Uuid,
    /// Exact trusted canonical HTTPS origin.
    pub origin: String,
    /// Canonical deployment-local username.
    pub username: String,
    /// Newly generated Account identifier.
    pub account_id: Uuid,
    /// Newly generated Personal vault identifier.
    pub personal_vault_id: Uuid,
    /// Independently generated Device id, separate from the local-only store's writer id.
    pub device_id: Uuid,
    /// A create-new recovery file was completely written and flushed before this marker.
    pub recovery_saved: bool,
    /// The user explicitly confirmed keeping the saved key safely.
    pub recovery_confirmed: bool,
    /// Count of durably recorded Submit handoffs; it never decreases or resets.
    pub dispatch_generation: u64,
    /// Earliest time for an explicit retry after a trusted rate response, in Unix milliseconds.
    pub retry_not_before_ms: Option<u64>,
}

/// Input-free preparation failures; never include passwords, filesystem paths, or crypto details.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RegistrationError {
    /// Another operation or password derivation owns the bounded work slot.
    #[error("An account operation is already running. Wait for it to finish.")]
    Busy,
    /// The captured open profile changed or is unavailable.
    #[error("The open local profile changed. Return to its original profile before continuing.")]
    ContextChanged,
    /// Preserve all current and historical Account material rather than replace it.
    #[error(
        "This profile already contains account setup material. Continue its original setup or use its confirmed account."
    )]
    ExistingProfile,
    /// Canonical origin, username, password, or device name is invalid.
    #[error("Check the server address, username, account password, and device name.")]
    InvalidInput,
    /// Local keys, signatures, or artifacts could not be generated or verified.
    #[error("The registration keys could not be prepared or verified. Existing data was retained.")]
    Identity,
    /// SQLCipher could not durably commit the operation.
    #[error(
        "The encrypted local data could not be saved. Unlock its original profile and try again."
    )]
    Storage,
    /// No pending operation matches the captured id.
    #[error("This registration preparation is no longer open.")]
    NotPrepared,
    /// Recovery export and explicit confirmation are mandatory before handing off a request.
    #[error("Save the recovery key and confirm keeping it safely before continuing.")]
    RecoveryRequired,
    /// A file might be partial; no saved marker is granted on error.
    #[error(
        "The recovery key could not be saved. Choose a new file in a private location and try again."
    )]
    RecoverySave,
    /// Never discard, replace, or replay a possibly committed registration.
    #[error(
        "The registration result is unresolved. Keep its original keys and confirm the exact operation."
    )]
    OutcomeUnknown,
    /// The supplied challenge/confirmation does not match the complete retained operation.
    #[error(
        "The response did not match this registration. Its original keys and result were retained."
    )]
    InvalidResponse,
    /// A new Submit requires the separate explicit retry action after a trusted unchanged result.
    #[error("Review this unchanged result, then explicitly retry the original registration.")]
    ExplicitRetryRequired,
    /// The current attempt has no trusted unchanged result and cannot authorize another Submit.
    #[error("This registration cannot be submitted again. Confirm its original result instead.")]
    RetryUnavailable,
    /// The retry delay remains in effect through restart.
    #[error("The server asked this registration to wait. Try again after its retry time.")]
    RetryDeferred,
    /// Cancellation stops this exchange while preserving its original pending identity.
    #[error("The registration exchange was cancelled. Its original keys and result were retained.")]
    Cancelled,
    /// A request or response did not finish within the bounded network deadline.
    #[error("The registration exchange timed out. Keep its original keys and check its result.")]
    Timeout,
    /// A verified HTTPS exchange did not complete; this never proves a handed-off Submit unchanged.
    #[error("The HTTPS exchange did not complete. Check the server certificate and connection.")]
    Network,
    /// The selected service does not expose the D-128 native routes.
    #[error("This server does not support native account registration. Contact its operator.")]
    UnsupportedService,
    /// The exact trusted problem reports a request/media failure without business changes.
    #[error("The server rejected this registration request. Its original keys were retained.")]
    RequestRejected,
    /// New registrations are disabled or the trusted origin is denied.
    #[error("The server does not permit this registration. Contact its operator.")]
    PolicyDenied,
    /// Fresh request possession was denied, without claiming whether an earlier Submit committed.
    #[error("The server could not verify this account request. Its original result was retained.")]
    AuthenticationDenied,
    /// The trusted first Submit reports a username or identifier conflict without partial creation.
    #[error("The server denied this registration. Its original keys and request were retained.")]
    RegistrationDenied,
    /// The deployment cannot admit another registration under its configured capacity.
    #[error("The server cannot accept another registration. Contact its operator.")]
    QuotaExceeded,
    /// A trusted common rate response supplies the bounded delay, without arbitrary server text.
    #[error("The server asked this registration to wait {retry_after_seconds} seconds.")]
    RateLimited {
        /// The shared contract's exact 1..=300 second delay.
        retry_after_seconds: u16,
    },
    /// The trusted response confirms no new business commit; a retry is always explicit.
    #[error("The server could not complete this request. Keep its original keys and try later.")]
    ServiceUnavailable,
}

impl PersonalServer {
    /// Generate and locally open all real D-127/D-108 artifacts, then persist their exact signed
    /// business bytes in SQLCipher. This synchronous method performs the fixed production KDF.
    /// It preserves local objects, the store writer id, archived material and admitted profiles.
    ///
    /// # Errors
    /// Rejects busy work slots, a replaced/occupied profile, invalid inputs, cryptographic
    /// failures or a failed durable transaction. A failure grants no Account authority.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_registration(
        &self,
        local: &LocalData,
        store: &Arc<Store>,
        origin: &str,
        username: &str,
        device_name: &str,
        password: SecretVec,
    ) -> Result<RegistrationStatus, RegistrationError> {
        let _operation = self.operation.try_lock().map_err(|_| RegistrationError::Busy)?;
        let _derivation = PASSWORD_DERIVATION.try_lock().map_err(|_| RegistrationError::Busy)?;
        current(local, store, || {
            if !store.registration_available().map_err(storage)? {
                return Err(RegistrationError::ExistingProfile);
            }
            Ok(())
        })?;
        PasswordKdfContext::new(origin, username, 1, &[0; 16]).map_err(password_error)?;
        if device_name.trim().is_empty()
            || device_name.len() > 128
            || device_name.chars().any(char::is_control)
        {
            return Err(RegistrationError::InvalidInput);
        }
        let record = prepare(origin, username, device_name, password)?;
        current(local, store, || {
            if !store.registration_available().map_err(storage)? {
                return Err(RegistrationError::ExistingProfile);
            }
            store.insert_registration(&record).map_err(storage)?;
            status(&record)
        })
    }

    /// Reverify retained identity and exact signatures without a password or any network call.
    ///
    /// # Errors
    /// Rejects a replaced profile, unavailable storage or inconsistent retained material.
    pub fn registration_status(
        &self,
        local: &LocalData,
        store: &Arc<Store>,
    ) -> Result<Option<RegistrationStatus>, RegistrationError> {
        current(local, store, || {
            store.pending_registration().map_err(storage)?.as_ref().map(status).transpose()
        })
    }

    /// Write only to a new native-selected path; the secret never leaves Rust. Windows inherits
    /// the selected directory's ACL; Unix creates mode 0600. An error may leave an incomplete
    /// file, which is never reported as saved or removed through an unverified path.
    ///
    /// # Errors
    /// Rejects busy/stale operations, attempted registrations, invalid retained keys, file
    /// creation/write/flush failures or failure to commit the saved marker after export.
    pub fn save_registration_recovery(
        &self,
        local: &LocalData,
        store: &Arc<Store>,
        operation_id: Uuid,
        path: &Path,
    ) -> Result<RegistrationStatus, RegistrationError> {
        let _operation = self.operation.try_lock().map_err(|_| RegistrationError::Busy)?;
        current(local, store, || {
            let mut record = record(store, operation_id)?;
            if record.phase != 0 {
                return Err(RegistrationError::OutcomeUnknown);
            }
            let payload = verify(&record)?;
            let secrets = Secrets::parse(&record.private_material).map_err(identity)?;
            let recovery =
                RecoveryKey::from_bytes(secrets.recovery().ok_or(RegistrationError::Identity)?)
                    .map_err(identity)?;
            let display = Zeroizing::new(recovery.encode_display());
            let contents = Zeroizing::new(format!(
                "Scoplen Personal recovery key\nServer: {}\nAccount: {}\n\n{}\n\nKeep this file private and offline. Anyone with this key can recover the account.\n",
                payload.origin,
                payload.account_id,
                display.as_str(),
            ));
            save_file(path, contents.as_bytes())?;
            changed(store.update_registration(&record, true, record.recovery_confirmed, 0, None))?;
            record.recovery_saved = true;
            status(&record)
        })
    }

    /// Record the user's explicit confirmation only after an actual successful flushed export.
    ///
    /// # Errors
    /// Rejects busy/stale operations, attempted registrations, missing successful recovery
    /// export, invalid retained material or failure to durably commit the confirmation.
    pub fn confirm_registration_recovery(
        &self,
        local: &LocalData,
        store: &Arc<Store>,
        operation_id: Uuid,
    ) -> Result<RegistrationStatus, RegistrationError> {
        let _operation = self.operation.try_lock().map_err(|_| RegistrationError::Busy)?;
        current(local, store, || {
            let mut record = record(store, operation_id)?;
            if record.phase != 0 {
                return Err(RegistrationError::OutcomeUnknown);
            }
            if !record.recovery_saved {
                return Err(RegistrationError::RecoveryRequired);
            }
            changed(store.update_registration(&record, true, true, 0, None))?;
            record.recovery_confirmed = true;
            status(&record)
        })
    }

    /// Return only the challenge request's public ids and exact intent. An unknown original
    /// operation always selects Confirm, including after restart, denial or a missing receipt.
    ///
    /// # Errors
    /// Rejects a stale operation/profile, unconfirmed recovery, unreadable storage or
    /// inconsistent retained material. It never substitutes Submit for an unknown outcome.
    pub fn registration_challenge(
        &self,
        local: &LocalData,
        store: &Arc<Store>,
        operation_id: Uuid,
    ) -> Result<AccountRequestChallengeRequest, RegistrationError> {
        current(local, store, || {
            let record = record(store, operation_id)?;
            challenge(&record)
        })
    }

    /// Bind a fresh challenge through the fallible DeviceSigner boundary. Before returning any
    /// Submit request, FULL/IMMEDIATE storage marks its result unknown. Dropping it, cancellation,
    /// a lost reply or process death cannot make it safe to submit again. No HTTP is performed.
    /// The caller must obtain the response over verified TLS from the retained canonical origin.
    ///
    /// # Errors
    /// Rejects busy/stale operations, unconfirmed recovery, mismatched or expired challenges,
    /// invalid keys/proofs, or failure to durably mark Submit unknown before returning it.
    pub fn registration_request(
        &self,
        local: &LocalData,
        store: &Arc<Store>,
        requested: &AccountRequestChallengeRequest,
        response: AccountRequestChallengeResponse,
    ) -> Result<AccountRegistrationRequest, RegistrationError> {
        let _operation = self.operation.try_lock().map_err(|_| RegistrationError::Busy)?;
        current(local, store, || {
            let record = record(store, requested.operation_id)?;
            request_for(store, &record, requested, response, false)
        })
    }

    /// Accept only a bounded exact committed confirmation from the trusted TLS response.
    /// This persists historical outcome only: no admission anchors, tokens, sync, upload consent,
    /// active-profile binding, or device authentication are created by it.
    ///
    /// # Errors
    /// Rejects busy/stale or never-dispatched operations, malformed/inexact confirmations,
    /// inconsistent retained material or failure to commit the historical result.
    pub fn record_registration_confirmation(
        &self,
        local: &LocalData,
        store: &Arc<Store>,
        operation_id: Uuid,
        response: &[u8],
    ) -> Result<RegistrationStatus, RegistrationError> {
        let _operation = self.operation.try_lock().map_err(|_| RegistrationError::Busy)?;
        current(local, store, || {
            let record = record(store, operation_id)?;
            confirm_record(store, record, response)
        })
    }

    /// Cancel only a preparation never handed to a sender. User-owned exported files remain.
    ///
    /// # Errors
    /// Rejects busy/stale operations, any attempted registration, inconsistent retained
    /// material or failure to commit the exact pending-record deletion.
    pub fn cancel_registration(
        &self,
        local: &LocalData,
        store: &Arc<Store>,
        operation_id: Uuid,
    ) -> Result<(), RegistrationError> {
        let _operation = self.operation.try_lock().map_err(|_| RegistrationError::Busy)?;
        current(local, store, || {
            let record = record(store, operation_id)?;
            if record.phase != 0 {
                return Err(RegistrationError::OutcomeUnknown);
            }
            changed(store.cancel_registration(&record))
        })
    }
}

fn confirm_record(
    store: &Store,
    mut record: RegistrationRecord,
    response: &[u8],
) -> Result<RegistrationStatus, RegistrationError> {
    if record.phase == 0 {
        return Err(RegistrationError::InvalidResponse);
    }
    let confirmation = AccountCommittedConfirmation::from_json(response)
        .map_err(|_| RegistrationError::InvalidResponse)?;
    confirmation
        .validate_for_request(
            AccountRequestKind::Register,
            record.payload.as_bytes(),
            &record.account_signature,
        )
        .map_err(|_| RegistrationError::InvalidResponse)?;
    let encoded = SecretVec::new(confirmation.to_json().map_err(identity)?);
    changed(store.update_registration(&record, true, true, 2, Some(encoded.as_bytes())))?;
    record.phase = 2;
    record.confirmation = Some(encoded);
    status(&record)
}

fn current<T>(
    local: &LocalData,
    store: &Arc<Store>,
    operation: impl FnOnce() -> Result<T, RegistrationError>,
) -> Result<T, RegistrationError> {
    local.with_current_store(store, operation).ok_or(RegistrationError::ContextChanged)?
}

fn record(store: &Store, operation: Uuid) -> Result<RegistrationRecord, RegistrationError> {
    let record =
        store.pending_registration().map_err(storage)?.ok_or(RegistrationError::NotPrepared)?;
    if verify(&record)?.operation_id != operation {
        return Err(RegistrationError::NotPrepared);
    }
    Ok(record)
}

fn status(record: &RegistrationRecord) -> Result<RegistrationStatus, RegistrationError> {
    let payload = verify(record)?;
    Ok(RegistrationStatus {
        phase: match record.phase {
            0 if record.recovery_confirmed => RegistrationPhase::Ready,
            0 => RegistrationPhase::RecoveryRequired,
            1 if record.dispatch_generation == record.unchanged_generation => {
                RegistrationPhase::RetryAvailable
            }
            1 => RegistrationPhase::OutcomeUnknown,
            2 => RegistrationPhase::Committed,
            _ => return Err(RegistrationError::Identity),
        },
        operation_id: payload.operation_id,
        origin: payload.origin,
        username: payload.username,
        account_id: payload.account_id,
        personal_vault_id: payload.personal_vault_id,
        device_id: payload.device_id,
        recovery_saved: record.recovery_saved,
        recovery_confirmed: record.recovery_confirmed,
        dispatch_generation: record.dispatch_generation as u64,
        retry_not_before_ms: (record.retry_not_before_ms > 0)
            .then_some(record.retry_not_before_ms as u64),
    })
}

fn challenge(
    record: &RegistrationRecord,
) -> Result<AccountRequestChallengeRequest, RegistrationError> {
    let p = verify(record)?;
    if !record.recovery_confirmed {
        return Err(RegistrationError::RecoveryRequired);
    }
    Ok(AccountRequestChallengeRequest {
        kind: AccountRequestKind::Register,
        intent: if record.phase == 0 {
            AccountRequestIntent::Submit
        } else {
            AccountRequestIntent::Confirm
        },
        operation_id: p.operation_id,
        device_id: p.device_id,
    })
}

fn request_for(
    store: &Store,
    record: &RegistrationRecord,
    requested: &AccountRequestChallengeRequest,
    response: AccountRequestChallengeResponse,
    retry: bool,
) -> Result<AccountRegistrationRequest, RegistrationError> {
    let mut expected = challenge(record)?;
    if retry {
        http::retry_allowed(record)?;
        expected.intent = AccountRequestIntent::Submit;
    }
    if &expected != requested || response.expires_at_ms <= now_ms()? {
        return Err(RegistrationError::InvalidResponse);
    }
    let payload = verify(record)?;
    let secrets = Secrets::parse(&record.private_material).map_err(identity)?;
    let signing = P256SigningKey::from_bytes(secrets.signing()).map_err(identity)?;
    let digest = signature_input(record)?.request_digest(&record.account_signature);
    let proof = AccountRequestProof::new(
        requested.kind,
        requested.intent,
        &payload.origin,
        response.attempt_id.as_bytes(),
        response.nonce.as_bytes(),
        requested.operation_id,
        requested.device_id,
        &digest,
    )
    .map_err(identity)?
    .sign(&signing)
    .map_err(identity)?;
    let request = AccountRegistrationRequest {
        intent: requested.intent,
        payload: record.payload.clone(),
        account_signature: record.account_signature,
        attempt_id: response.attempt_id,
        nonce: response.nonce,
        device_proof: proof,
    };
    request.verify_proof(&payload.origin).map_err(identity)?;
    if requested.intent == AccountRequestIntent::Submit {
        changed(store.update_registration(record, true, true, 1, None))?;
    }
    Ok(request)
}

fn prepare(
    origin: &str,
    username: &str,
    name: &str,
    password: SecretVec,
) -> Result<RegistrationRecord, RegistrationError> {
    let password = PasswordSecrets::create(origin, username, password).map_err(password_error)?;
    let account_id = scoplen_model::new_uuid_v7().map_err(identity)?;
    let vault_id = scoplen_model::new_uuid_v7().map_err(identity)?;
    let device_id = scoplen_model::new_uuid_v7().map_err(identity)?;
    let operation_id = scoplen_model::new_uuid_v7().map_err(identity)?;
    let device = generate_device_keys().map_err(identity)?;
    let account = generate_account_keys().map_err(identity)?;
    let ark = generate_symmetric_key().map_err(identity)?;
    let vault = generate_symmetric_key().map_err(identity)?;
    let recovery = RecoveryKey::generate().map_err(identity)?;
    let kem_public: [u8; 32] = account.kem.public_key().try_into().map_err(identity)?;
    let context = PasswordBootstrapContext::new(
        password.context().clone(),
        account_id,
        vault_id,
        &account.signing.public_key(),
        &kem_public,
        1,
    )
    .map_err(identity)?;
    let password_ark = PasswordArkWrap::seal(&password, &context, &ark).map_err(identity)?;
    let certificate = DeviceCertificate::issue(
        &account.signing,
        device_id,
        account_id,
        device.signing.public_key_sec1(),
        device.kem.public_key().to_vec(),
        name.into(),
        std::env::consts::OS.into(),
        now_ms()?,
    )
    .map_err(identity)?
    .encode()
    .map_err(identity)?;
    let mut bundle = SyncAccountKeyBundleUpdate {
        revision: 1,
        device_wraps: vec![SyncAccountDeviceWrap {
            device_id,
            wrapped_ark: DeviceArkWrap::seal(account_id, device_id, device.kem.public_key(), &ark)
                .map_err(identity)?
                .encode()
                .to_vec(),
        }],
        account_signing_key: AccountSigningKeyWrap::seal(account_id, &ark, &account.signing)
            .map_err(identity)?
            .encode()
            .to_vec(),
        account_kem_key: AccountKemKeyWrap::seal(account_id, &ark, &account.kem)
            .map_err(identity)?
            .encode()
            .to_vec(),
        recovery_blob: RecoveryBlob::wrap(&recovery, account_id, &ark)
            .map_err(identity)?
            .encode()
            .map_err(identity)?,
        signature: vec![0; 64],
    };
    bundle.signature = account.signing.sign(&bundle.signature_input().map_err(identity)?).to_vec();
    let opened = password
        .open_bootstrap(
            &context,
            &password_ark,
            &AccountSigningKeyWrap::decode(&bundle.account_signing_key).map_err(identity)?,
            &AccountKemKeyWrap::decode(&bundle.account_kem_key).map_err(identity)?,
        )
        .map_err(identity)?;
    if opened.ark() != &ark {
        return Err(RegistrationError::Identity);
    }
    let payload = AccountRegistrationPayload {
        operation_id,
        origin: origin.into(),
        username: username.into(),
        account_id,
        personal_vault_id: vault_id,
        device_id,
        account_signing_public_key: account.signing.public_key(),
        account_kem_public_key: kem_public,
        password_salt: *password.context().salt(),
        verifier: *password.verifier().as_bytes(),
        password_ark: password_ark.encode(),
        device_certificate: certificate,
        key_bundle: bundle.to_cbor().map_err(identity)?,
        personal_wrapped_key: PersonalVaultKeyWrap::seal(account_id, vault_id, 1, &ark, &vault)
            .map_err(identity)?
            .encode(),
    };
    let payload = SecretVec::new(payload.to_cbor().map_err(identity)?);
    let account_signature =
        AccountRequestSignatureInput::new(AccountRequestKind::Register, payload.as_bytes())
            .map_err(identity)?
            .sign(&account.signing);
    let mut material = Zeroizing::new(Vec::with_capacity(225));
    material.push(1);
    let device_signing = device.signing.private_key_bytes();
    let device_kem = device.kem.private_key_bytes();
    let account_signing = account.signing.private_key_bytes();
    let account_kem = account.kem.private_key_bytes();
    for bytes in [
        device_signing.as_ref(),
        device_kem.as_ref(),
        ark.as_ref(),
        account_signing.as_ref(),
        account_kem.as_ref(),
        vault.as_ref(),
        recovery.as_ref(),
    ] {
        material.extend_from_slice(bytes);
    }
    let record = RegistrationRecord {
        payload,
        account_signature,
        private_material: SecretVec::new(std::mem::take(&mut *material)),
        recovery_saved: false,
        recovery_confirmed: false,
        phase: 0,
        confirmation: None,
        dispatch_generation: 0,
        unchanged_generation: 0,
        retry_not_before_ms: 0,
    };
    verify(&record)?;
    Ok(record)
}

// Reopening validates exact signed business bytes and every available independent local key.
// The KEK/AuthSecret/password are intentionally not retained. The original password wrap was
// opened above before signing; its immutable bytes remain covered by the Account signature.
fn verify(record: &RegistrationRecord) -> Result<AccountRegistrationPayload, RegistrationError> {
    if record.recovery_confirmed && !record.recovery_saved
        || !(0..=2).contains(&record.phase)
        || record.phase != 0 && !record.recovery_confirmed
        || (record.phase == 2) != record.confirmation.is_some()
        || record.dispatch_generation < 0
        || record.unchanged_generation < 0
        || record.unchanged_generation > record.dispatch_generation
        || record.retry_not_before_ms < 0
        || (record.phase == 0) != (record.dispatch_generation == 0)
    {
        return Err(RegistrationError::Identity);
    }
    let p = AccountRegistrationPayload::from_cbor(record.payload.as_bytes()).map_err(identity)?;
    signature_input(record)?
        .verify(&p.account_signing_public_key, &record.account_signature)
        .map_err(identity)?;
    let s = Secrets::parse(&record.private_material).map_err(identity)?;
    let signing = P256SigningKey::from_bytes(s.signing()).map_err(identity)?;
    let kem = DeviceKemKeyPair::from_private_bytes(s.device_kem()).map_err(identity)?;
    let account_signing = Ed25519SigningKey::from_bytes(s.account_signing()).map_err(identity)?;
    let account_kem = AccountKemKeyPair::from_private_bytes(s.account_kem()).map_err(identity)?;
    let ark = SymmetricKey::new(s.ark().try_into().map_err(identity)?);
    let expected_vault = SymmetricKey::from_slice(s.vault()).ok_or(RegistrationError::Identity)?;
    let expected_signing =
        SymmetricKey::from_slice(s.account_signing()).ok_or(RegistrationError::Identity)?;
    let expected_kem =
        SymmetricKey::from_slice(s.account_kem()).ok_or(RegistrationError::Identity)?;
    let cert = DeviceCertificate::decode(&p.device_certificate).map_err(identity)?;
    let bundle = SyncAccountKeyBundleUpdate::from_cbor(&p.key_bundle).map_err(identity)?;
    let device_ark = DeviceArkWrap::decode(&bundle.device_wraps[0].wrapped_ark)
        .map_err(identity)?
        .open(p.account_id, p.device_id, &kem)
        .map_err(identity)?;
    let recovery = RecoveryKey::from_bytes(s.recovery().ok_or(RegistrationError::Identity)?)
        .map_err(identity)?;
    let recovery_ark = RecoveryBlob::decode(&bundle.recovery_blob)
        .map_err(identity)?
        .open(&recovery, p.account_id)
        .map_err(identity)?;
    let root_signing = AccountSigningKeyWrap::decode(&bundle.account_signing_key)
        .map_err(identity)?
        .open(p.account_id, &ark, &p.account_signing_public_key)
        .map_err(identity)?;
    let root_kem = AccountKemKeyWrap::decode(&bundle.account_kem_key)
        .map_err(identity)?
        .open(p.account_id, &ark, &p.account_kem_public_key)
        .map_err(identity)?;
    let vault = PersonalVaultKeyWrap::decode(&p.personal_wrapped_key)
        .map_err(identity)?
        .open(p.account_id, p.personal_vault_id, 1, &ark)
        .map_err(identity)?;
    if cert.signing_public_key != signing.public_key_sec1()
        || cert.kem_public_key != kem.public_key()
        || p.account_signing_public_key != account_signing.public_key()
        || p.account_kem_public_key != account_kem.public_key()
        || device_ark != ark
        || recovery_ark != ark
        || vault != expected_vault
        || root_signing.private_key_bytes() != expected_signing
        || root_kem.private_key_bytes() != expected_kem
    {
        return Err(RegistrationError::Identity);
    }
    if let Some(confirmation) = &record.confirmation {
        AccountCommittedConfirmation::from_json(confirmation.as_bytes())
            .map_err(identity)?
            .validate_for_request(
                AccountRequestKind::Register,
                record.payload.as_bytes(),
                &record.account_signature,
            )
            .map_err(identity)?;
    }
    Ok(p)
}

fn signature_input(
    record: &RegistrationRecord,
) -> Result<AccountRequestSignatureInput, RegistrationError> {
    AccountRequestSignatureInput::new(AccountRequestKind::Register, record.payload.as_bytes())
        .map_err(identity)
}

fn save_file(path: &Path, contents: &[u8]) -> Result<(), RegistrationError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|_| RegistrationError::RecoverySave)?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|_| RegistrationError::RecoverySave)
}

fn now_ms() -> Result<u64, RegistrationError> {
    scoplen_model::system_time_millis().map_err(identity)
}
fn identity(_: impl std::fmt::Debug) -> RegistrationError {
    RegistrationError::Identity
}
fn storage(_: crate::store::StoreError) -> RegistrationError {
    RegistrationError::Storage
}
fn changed(result: Result<bool, crate::store::StoreError>) -> Result<(), RegistrationError> {
    if result.map_err(storage)? { Ok(()) } else { Err(RegistrationError::ContextChanged) }
}
fn password_error(error: PasswordBootstrapError) -> RegistrationError {
    match error {
        PasswordBootstrapError::InvalidPassword | PasswordBootstrapError::InvalidContext => {
            RegistrationError::InvalidInput
        }
        _ => RegistrationError::Identity,
    }
}

#[cfg(test)]
mod tests;
