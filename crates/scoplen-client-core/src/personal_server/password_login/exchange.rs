// SPDX-License-Identifier: Apache-2.0
//! Fresh request proofs around immutable admission bytes and durable handoff evidence.

use scoplen_api::{
    ProblemDetails,
    account_admission::{
        AccountDeviceAdmissionRequest, AccountRequestChallengeRequest,
        AccountRequestChallengeResponse, MAX_ACCOUNT_ENTRY_PROBLEM_BYTES,
    },
};
use scoplen_crypto::{AccountRequestIntent, AccountRequestProof};
use std::future::Future;
use tokio::sync::watch;

use super::*;
use crate::personal_server::transport::RegistrationResponse;

impl PersonalServer {
    /// Explicitly submit, retry a proven unchanged Submit, or recover only its exact receipt.
    /// Every exchange uses a new challenge/proof. FULL/IMMEDIATE storage records uncertainty
    /// before sending any business request. Cancellation, restart, missing receipts and expired
    /// capabilities cannot silently authorize a second mutation or generate another identity.
    ///
    /// # Errors
    /// Rejects stale/concurrent/ineligible work, expired capabilities, malformed responses,
    /// common password/admission denials, network failures and failed durable transitions.
    pub async fn exchange_password_login(
        &self,
        profiles: &AccountProfiles,
        source: &ProfileLease,
        operation_id: Uuid,
        action: RegistrationAction,
        cancellation: &RegistrationCancellation,
    ) -> Result<PasswordLoginStatus, PasswordLoginError> {
        let _operation = self.operation.try_lock().map_err(|_| PasswordLoginError::Busy)?;
        let original =
            check(profiles, source, cancellation, || record(&source.store, operation_id))?;
        let e = &original.entry;
        let intent = match action {
            RegistrationAction::Submit if e.phase == 0 => AccountRequestIntent::Submit,
            RegistrationAction::Submit => {
                return Err(if e.dispatch_generation == e.unchanged_generation {
                    PasswordLoginError::ExplicitRetryRequired
                } else {
                    PasswordLoginError::OutcomeUnknown
                });
            }
            RegistrationAction::Confirm if e.phase > 0 => AccountRequestIntent::Confirm,
            RegistrationAction::Confirm => return Err(PasswordLoginError::InvalidResponse),
            RegistrationAction::Retry => {
                if original.restart_required {
                    return Err(PasswordLoginError::AdmissionConflict);
                }
                if e.phase != 1 || e.dispatch_generation != e.unchanged_generation {
                    return Err(PasswordLoginError::RetryUnavailable);
                }
                if e.retry_not_before_ms as u64 > now_ms()? {
                    return Err(PasswordLoginError::RetryDeferred);
                }
                AccountRequestIntent::Submit
            }
        };
        if intent == AccountRequestIntent::Submit && original.expires_at_ms <= now_ms()? {
            return Err(PasswordLoginError::AdmissionConflict);
        }
        let payload = verify(&original)?;
        let requested = AccountRequestChallengeRequest {
            kind: AccountRequestKind::Admit,
            intent,
            operation_id,
            device_id: payload.device_id,
        };
        let mut changes = profiles.changes();
        let mut root_changes = profiles.local.context_changes();
        let transport = self.transport.as_ref().map_err(|_| PasswordLoginError::Network)?;
        exact(profiles, source, cancellation, &original, || Ok(()))?;
        let response = until_stopped(
            cancellation,
            &mut changes,
            &mut root_changes,
            transport.registration_post(
                &payload.origin,
                AccountEntryOperation::RequestChallenge,
                SecretVec::new(requested.to_json().map_err(invalid)?),
            ),
        )
        .await?;
        exact(profiles, source, cancellation, &original, || Ok(()))?;
        if response.status != 200 {
            return Err(problem(&response)?);
        }
        let response = AccountRequestChallengeResponse::from_json(response.body.as_bytes())
            .map_err(invalid)?;
        let (body, dispatched) = exact(profiles, source, cancellation, &original, || {
            if response.expires_at_ms <= now_ms()? {
                return Err(PasswordLoginError::InvalidResponse);
            }
            if intent == AccountRequestIntent::Submit && original.expires_at_ms <= now_ms()? {
                return Err(PasswordLoginError::AdmissionConflict);
            }
            let s = Secrets::parse(&e.private_material).map_err(invalid)?;
            let signing = P256SigningKey::from_bytes(s.signing()).map_err(invalid)?;
            let digest =
                AccountRequestSignatureInput::new(AccountRequestKind::Admit, e.payload.as_bytes())
                    .map_err(invalid)?
                    .request_digest(&e.account_signature);
            let proof = AccountRequestProof::new(
                AccountRequestKind::Admit,
                intent,
                &payload.origin,
                response.attempt_id.as_bytes(),
                response.nonce.as_bytes(),
                operation_id,
                payload.device_id,
                &digest,
            )
            .map_err(invalid)?
            .sign(&signing)
            .map_err(invalid)?;
            let request = AccountDeviceAdmissionRequest {
                intent,
                payload: e.payload.clone(),
                account_signature: e.account_signature,
                attempt_id: response.attempt_id,
                nonce: response.nonce,
                device_proof: proof,
                admission_token: (intent == AccountRequestIntent::Submit)
                    .then(|| original.token.clone()),
            };
            let snapshot = AccountBootstrapSnapshot::from_cbor(original.snapshot.as_bytes())
                .map_err(invalid)?;
            request
                .verify_proof(&payload.origin, &snapshot.account_signing_public_key)
                .map_err(invalid)?;
            let body = SecretVec::new(request.to_json().map_err(invalid)?);
            if intent == AccountRequestIntent::Submit {
                changed(source.store.update_password_login(
                    &original,
                    1,
                    None,
                    false,
                    e.retry_not_before_ms,
                    false,
                ))?;
            }
            Ok((body, record(&source.store, operation_id)?))
        })?;
        exact(profiles, source, cancellation, &dispatched, || Ok(()))?;
        let response = until_stopped(
            cancellation,
            &mut changes,
            &mut root_changes,
            transport.registration_post(
                &payload.origin,
                AccountEntryOperation::DeviceAdmission,
                body,
            ),
        )
        .await?;
        exact(profiles, source, cancellation, &dispatched, || Ok(()))?;
        if response.status == if intent == AccountRequestIntent::Submit { 201 } else { 200 } {
            return exact(profiles, source, cancellation, &dispatched, || {
                let c = AccountCommittedConfirmation::from_json(response.body.as_bytes())
                    .map_err(invalid)?;
                c.validate_for_request(
                    AccountRequestKind::Admit,
                    dispatched.entry.payload.as_bytes(),
                    &dispatched.entry.account_signature,
                )
                .map_err(invalid)?;
                let bytes = SecretVec::new(c.to_json().map_err(invalid)?);
                changed(source.store.update_password_login(
                    &dispatched,
                    2,
                    Some(bytes.as_bytes()),
                    false,
                    dispatched.entry.retry_not_before_ms,
                    false,
                ))?;
                status(&record(&source.store, operation_id)?)
            });
        }
        let error = problem(&response)?;
        if intent == AccountRequestIntent::Submit && error != PasswordLoginError::OutcomeUnknown {
            let delay = match error {
                PasswordLoginError::RateLimited { retry_after_seconds } => {
                    u64::from(retry_after_seconds) * 1000
                }
                _ => 0,
            };
            let retry_at = if delay == 0 {
                0
            } else {
                now_ms()?.checked_add(delay).ok_or(PasswordLoginError::InvalidResponse)?
            };
            let retry_at = i64::try_from(retry_at).map_err(invalid)?;
            exact(profiles, source, cancellation, &dispatched, || {
                changed(source.store.update_password_login(
                    &dispatched,
                    1,
                    None,
                    true,
                    retry_at,
                    matches!(
                        error,
                        PasswordLoginError::AdmissionConflict
                            | PasswordLoginError::AuthenticationDenied
                    ),
                ))
            })?;
        }
        Err(error)
    }
}

fn exact<T>(
    profiles: &AccountProfiles,
    source: &ProfileLease,
    cancellation: &RegistrationCancellation,
    expected: &PasswordLoginRecord,
    operation: impl FnOnce() -> Result<T, PasswordLoginError>,
) -> Result<T, PasswordLoginError> {
    check(profiles, source, cancellation, || {
        if source.store.pending_password_login().map_err(storage)?.as_ref() != Some(expected) {
            return Err(PasswordLoginError::ContextChanged);
        }
        operation()
    })
}

pub(super) async fn until_stopped<T, E: Into<PasswordLoginError>>(
    cancellation: &RegistrationCancellation,
    changes: &mut watch::Receiver<i64>,
    root_changes: &mut watch::Receiver<()>,
    operation: impl Future<Output = Result<T, E>>,
) -> Result<T, PasswordLoginError> {
    tokio::select! {biased;
        _=cancellation.cancelled()=>Err(PasswordLoginError::Cancelled),
        _=changes.changed()=>Err(PasswordLoginError::ContextChanged),
        _=root_changes.changed()=>Err(PasswordLoginError::ContextChanged),
        result=operation=>result.map_err(Into::into),
    }
}

pub(super) fn problem(
    response: &RegistrationResponse,
) -> Result<PasswordLoginError, PasswordLoginError> {
    if !response.problem_json {
        return Err(PasswordLoginError::InvalidResponse);
    }
    let p = ProblemDetails::from_json(response.body.as_bytes(), MAX_ACCOUNT_ENTRY_PROBLEM_BYTES)
        .map_err(|_| PasswordLoginError::InvalidResponse)?;
    if p.status != response.status {
        return Err(PasswordLoginError::InvalidResponse);
    }
    Ok(match (p.status, p.code.as_str(), p.changed, p.retryable) {
        (400 | 413 | 415, "auth.invalid_request", false, false) => {
            PasswordLoginError::RequestRejected
        }
        (403, "policy.denied", false, false) => PasswordLoginError::PolicyDenied,
        (401, "auth.authentication_required", false, false) => {
            PasswordLoginError::AuthenticationDenied
        }
        (409, "auth.admission_conflict", false, false) => PasswordLoginError::AdmissionConflict,
        (413, "auth.quota_exceeded", false, false) => PasswordLoginError::QuotaExceeded,
        (429, "auth.rate_limited", false, true) => PasswordLoginError::RateLimited {
            retry_after_seconds: response.retry_after.ok_or(PasswordLoginError::InvalidResponse)?,
        },
        (503, "auth.storage_unavailable", false, true) => PasswordLoginError::ServiceUnavailable,
        (503, "auth.commit_outcome_unknown", true, false) => PasswordLoginError::OutcomeUnknown,
        _ => return Err(PasswordLoginError::InvalidResponse),
    })
}
