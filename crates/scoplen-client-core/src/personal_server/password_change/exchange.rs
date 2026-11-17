// SPDX-License-Identifier: Apache-2.0
//! Fresh existing-Device proof, with durable uncertainty before every business Submit.

use super::*;
use crate::personal_server::RegistrationAction;
use scoplen_api::account_admission::{
    AccountPasswordChangeRequest, AccountRequestChallengeRequest, AccountRequestChallengeResponse,
};
use scoplen_crypto::{AccountRequestIntent, AccountRequestProof, P256SigningKey};

impl PersonalServer {
    /// Submit once, explicitly retry a proven unchanged Submit, or confirm its exact receipt.
    /// Confirm needs only the original installed keys and never a current native session.
    /// # Errors
    /// Rejects stale contexts, ineligible/expired work, strict response failures and failed
    /// durable transitions. Network/cancellation/unknown errors retain original uncertainty.
    pub async fn exchange_password_change(
        &self,
        profiles: &AccountProfiles,
        source: &ProfileLease,
        operation_id: Uuid,
        action: RegistrationAction,
        cancellation: &RegistrationCancellation,
    ) -> Result<PasswordChangeStatus, PasswordChangeError> {
        let _operation = self.operation.try_lock().map_err(|_| PasswordChangeError::Busy)?;
        let original = check(profiles, source, cancellation, || record(source, operation_id))?;
        let intent = match action {
            RegistrationAction::Submit if original.phase == 0 => AccountRequestIntent::Submit,
            RegistrationAction::Submit => {
                return Err(if original.dispatch_generation == original.unchanged_generation {
                    PasswordChangeError::ExplicitRetryRequired
                } else {
                    PasswordChangeError::OutcomeUnknown
                });
            }
            RegistrationAction::Confirm if original.phase > 0 => AccountRequestIntent::Confirm,
            RegistrationAction::Confirm => return Err(PasswordChangeError::RetryUnavailable),
            RegistrationAction::Retry => {
                if original.restart_required {
                    return Err(PasswordChangeError::SignInRequired);
                }
                if original.phase != 1
                    || original.dispatch_generation != original.unchanged_generation
                {
                    return Err(PasswordChangeError::RetryUnavailable);
                }
                if original.retry_not_before_ms as u64 > now_ms()? {
                    return Err(PasswordChangeError::RetryDeferred);
                }
                AccountRequestIntent::Submit
            }
        };
        let p = verify(source, &original)?;
        if intent == AccountRequestIntent::Submit {
            check_submit(&source.store, &original, &p)?;
        }
        let mut changes = profiles.changes();
        let mut root_changes = profiles.local.context_changes();
        let transport = self.transport.as_ref().map_err(|_| PasswordChangeError::Network)?;
        let challenge = AccountRequestChallengeRequest {
            kind: AccountRequestKind::PasswordChange,
            intent,
            operation_id,
            device_id: p.device_id,
        };
        exact(profiles, source, cancellation, &original, || Ok(()))?;
        let response = until_stopped(
            cancellation,
            &mut changes,
            &mut root_changes,
            transport.registration_post(
                &p.origin,
                AccountEntryOperation::RequestChallenge,
                SecretVec::new(challenge.to_json().map_err(invalid)?),
            ),
        )
        .await?;
        exact(profiles, source, cancellation, &original, || Ok(()))?;
        if response.status != 200 {
            return Err(problem(&response)?.into());
        }
        let challenge = AccountRequestChallengeResponse::from_json(response.body.as_bytes())
            .map_err(invalid)?;
        let (body, dispatched) = exact(profiles, source, cancellation, &original, || {
            if challenge.expires_at_ms <= now_ms()? {
                return Err(PasswordChangeError::Verification);
            }
            if intent == AccountRequestIntent::Submit {
                check_submit(&source.store, &original, &p)?;
            }
            let identity = source
                .store
                .personal_record()
                .map_err(storage)?
                .ok_or(PasswordChangeError::Verification)?;
            let secrets = Secrets::parse(&identity.private_material).map_err(invalid)?;
            let signing = P256SigningKey::from_bytes(secrets.signing()).map_err(invalid)?;
            let digest = AccountRequestSignatureInput::new(
                AccountRequestKind::PasswordChange,
                original.payload.as_bytes(),
            )
            .map_err(invalid)?
            .request_digest(&original.account_signature);
            let proof = AccountRequestProof::new(
                AccountRequestKind::PasswordChange,
                intent,
                &p.origin,
                challenge.attempt_id.as_bytes(),
                challenge.nonce.as_bytes(),
                operation_id,
                p.device_id,
                &digest,
            )
            .map_err(invalid)?
            .sign(&signing)
            .map_err(invalid)?;
            let request = AccountPasswordChangeRequest {
                intent,
                payload: original.payload.clone(),
                account_signature: original.account_signature,
                attempt_id: challenge.attempt_id,
                nonce: challenge.nonce,
                device_proof: proof,
                admission_token: if intent == AccountRequestIntent::Submit {
                    original.token.clone()
                } else {
                    None
                },
            };
            let certificate = DeviceCertificate::decode(&original.certificate).map_err(invalid)?;
            request
                .verify_proof(&p.origin, &original.signing_public, &certificate.signing_public_key)
                .map_err(invalid)?;
            let body = SecretVec::new(request.to_json().map_err(invalid)?);
            let mut next = original.clone();
            if intent == AccountRequestIntent::Submit {
                next.phase = 1;
                next.dispatch_generation = next
                    .dispatch_generation
                    .checked_add(1)
                    .ok_or(PasswordChangeError::Verification)?;
                changed(source.store.update_password_change(&original, &next, None))?;
            }
            Ok((body, next))
        })?;
        exact(profiles, source, cancellation, &dispatched, || Ok(()))?;
        let response = until_stopped(
            cancellation,
            &mut changes,
            &mut root_changes,
            transport.registration_post(&p.origin, AccountEntryOperation::PasswordChange, body),
        )
        .await?;
        exact(profiles, source, cancellation, &dispatched, || Ok(()))?;
        if response.status == if intent == AccountRequestIntent::Submit { 201 } else { 200 } {
            return exact(profiles, source, cancellation, &dispatched, || {
                let receipt =
                    AccountPasswordChangeConfirmation::from_json(response.body.as_bytes())
                        .map_err(invalid)?;
                receipt
                    .validate_for_request(
                        dispatched.payload.as_bytes(),
                        &dispatched.account_signature,
                    )
                    .map_err(invalid)?;
                let mut next = dispatched.clone();
                next.phase = 2;
                next.token = None;
                next.confirmation = Some(SecretVec::new(receipt.to_json().map_err(invalid)?));
                changed(source.store.update_password_change(
                    &dispatched,
                    &next,
                    Some(receipt.credential_generation),
                ))?;
                status(&next)
            });
        }
        let error = problem(&response)?;
        if intent == AccountRequestIntent::Submit && error != PasswordLoginError::OutcomeUnknown {
            let mut next = dispatched.clone();
            next.unchanged_generation = next.dispatch_generation;
            next.retry_not_before_ms = match error {
                PasswordLoginError::RateLimited { retry_after_seconds } => i64::try_from(
                    now_ms()?
                        .checked_add(u64::from(retry_after_seconds) * 1000)
                        .ok_or(PasswordChangeError::Verification)?,
                )
                .map_err(invalid)?,
                _ => 0,
            };
            next.restart_required = matches!(
                error,
                PasswordLoginError::AdmissionConflict | PasswordLoginError::AuthenticationDenied
            );
            exact(profiles, source, cancellation, &dispatched, || {
                changed(source.store.update_password_change(&dispatched, &next, None))
            })?;
        }
        Err(error.into())
    }
}

fn check_submit(
    store: &Store,
    r: &PasswordChangeRecord,
    p: &AccountPasswordChangePayload,
) -> Result<(), PasswordChangeError> {
    if r.expires_at_ms <= now_ms()?
        || r.token.is_none()
        || r.restart_required
        || store
            .credential_generation_floor()
            .map_err(storage)?
            .is_some_and(|floor| floor > p.credential_generation)
    {
        return Err(PasswordChangeError::SignInRequired);
    }
    Ok(())
}
fn exact<T>(
    profiles: &AccountProfiles,
    source: &ProfileLease,
    cancellation: &RegistrationCancellation,
    expected: &PasswordChangeRecord,
    operation: impl FnOnce() -> Result<T, PasswordChangeError>,
) -> Result<T, PasswordChangeError> {
    check(profiles, source, cancellation, || {
        if source.store.pending_password_change().map_err(storage)?.as_ref() != Some(expected) {
            return Err(PasswordChangeError::ContextChanged);
        }
        operation()
    })
}
