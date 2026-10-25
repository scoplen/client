// SPDX-License-Identifier: Apache-2.0
//! One explicit native exchange; only exact trusted Submit failures authorize a later retry.

use std::future::Future;

use scoplen_api::{
    ProblemDetails,
    account_admission::{AccountEntryOperation, MAX_ACCOUNT_ENTRY_PROBLEM_BYTES},
};
use tokio::sync::watch;

use super::*;
use crate::personal_server::transport::RegistrationResponse;

/// The user's explicit network action for one captured pending registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationAction {
    /// The original never-dispatched preparation, after recovery save and confirmation.
    Submit,
    /// Historical receipt recovery only; absence never authorizes a new Submit.
    Confirm,
    /// Another fresh Submit after a trusted unchanged result for the latest dispatch.
    Retry,
}

/// Cancellation of one exchange. Cancelling never erases the pending keys or handoff evidence.
#[derive(Clone)]
pub struct RegistrationCancellation {
    cancelled: watch::Sender<bool>,
}

impl Default for RegistrationCancellation {
    fn default() -> Self {
        Self { cancelled: watch::channel(false).0 }
    }
}

impl RegistrationCancellation {
    /// Stop this exchange; if Submit was handed off, its business result remains unresolved.
    pub fn cancel(&self) {
        self.cancelled.send_replace(true);
    }

    fn guard(&self) -> Result<watch::Ref<'_, bool>, RegistrationError> {
        let guard = self.cancelled.borrow();
        if *guard { Err(RegistrationError::Cancelled) } else { Ok(guard) }
    }

    async fn cancelled(&self) {
        let mut receiver = self.cancelled.subscribe();
        let _ = receiver.wait_for(|cancelled| *cancelled).await;
    }
}

impl PersonalServer {
    /// Run one Rust-owned TLS 1.3/H2 challenge and registration/receipt exchange. Every call
    /// needs an explicit action and fresh proof. Success records historical commit only;
    /// Account-store installation, current-device authentication and sync remain separate.
    /// Dropping this future or cancelling after Submit handoff retains OutcomeUnknown.
    ///
    /// # Errors
    /// Rejects busy, stale, unprepared or ineligible operations; cancelled/timed-out network
    /// work; unsupported services; malformed/inexact responses; typed trusted denials; and
    /// failed durable transitions. A Confirm error never proves the original Submit unchanged.
    pub async fn exchange_registration(
        &self,
        local: &LocalData,
        store: Arc<Store>,
        operation_id: Uuid,
        action: RegistrationAction,
        cancellation: &RegistrationCancellation,
    ) -> Result<RegistrationStatus, RegistrationError> {
        let _operation = self.operation.try_lock().map_err(|_| RegistrationError::Busy)?;
        let mut changes = local.context_changes();
        let original = current(local, &store, || {
            let _active = cancellation.guard()?;
            record(&store, operation_id)
        })?;
        let (mut requested, origin) = checked(local, &store, cancellation, &original, || {
            Ok((challenge(&original)?, verify(&original)?.origin))
        })?;
        match action {
            RegistrationAction::Submit if original.phase != 0 => {
                return Err(if original.dispatch_generation == original.unchanged_generation {
                    RegistrationError::ExplicitRetryRequired
                } else {
                    RegistrationError::OutcomeUnknown
                });
            }
            RegistrationAction::Confirm if original.phase == 0 => {
                return Err(RegistrationError::InvalidResponse);
            }
            RegistrationAction::Retry => {
                retry_allowed(&original)?;
                requested.intent = AccountRequestIntent::Submit;
            }
            _ => {}
        }
        let transport = self.transport.as_ref().map_err(|_| RegistrationError::Network)?;
        checked(local, &store, cancellation, &original, || Ok(()))?;
        let response = until_stopped(
            cancellation,
            &mut changes,
            transport.registration_post(
                &origin,
                AccountEntryOperation::RequestChallenge,
                SecretVec::new(requested.to_json().map_err(identity)?),
            ),
        )
        .await?;
        checked(local, &store, cancellation, &original, || Ok(()))?;
        if response.status != 200 {
            return Err(problem(&response)?);
        }
        let response = AccountRequestChallengeResponse::from_http_json(
            response.body.as_bytes(),
            Some("no-store"),
            Some("no-cache"),
        )
        .map_err(|_| RegistrationError::InvalidResponse)?;
        let (body, dispatched) = checked(local, &store, cancellation, &original, || {
            let request = request_for(
                &store,
                &original,
                &requested,
                response,
                action == RegistrationAction::Retry,
            )?;
            Ok((
                SecretVec::new(request.to_json().map_err(identity)?),
                record(&store, operation_id)?,
            ))
        })?;
        checked(local, &store, cancellation, &dispatched, || Ok(()))?;
        let response = until_stopped(
            cancellation,
            &mut changes,
            transport.registration_post(&origin, AccountEntryOperation::Register, body),
        )
        .await?;
        checked(local, &store, cancellation, &dispatched, || Ok(()))?;
        let success_status =
            if requested.intent == AccountRequestIntent::Submit { 201 } else { 200 };
        if response.status == success_status {
            return checked(local, &store, cancellation, &dispatched, || {
                let current = record(&store, operation_id)?;
                confirm_record(&store, current, response.body.as_bytes())
            });
        }
        let error = problem(&response)?;
        if requested.intent == AccountRequestIntent::Submit
            && error != RegistrationError::OutcomeUnknown
        {
            let delay = match error {
                RegistrationError::RateLimited { retry_after_seconds } => {
                    u64::from(retry_after_seconds) * 1_000
                }
                _ => 0,
            };
            let retry_at = if delay == 0 {
                0
            } else {
                now_ms()?.checked_add(delay).ok_or(RegistrationError::InvalidResponse)?
            };
            let retry_at =
                i64::try_from(retry_at).map_err(|_| RegistrationError::InvalidResponse)?;
            checked(local, &store, cancellation, &dispatched, || {
                changed(store.registration_unchanged(&dispatched, retry_at))
            })?;
        }
        Err(error)
    }
}

pub(super) fn retry_allowed(record: &RegistrationRecord) -> Result<(), RegistrationError> {
    if record.phase != 1 || record.dispatch_generation != record.unchanged_generation {
        return Err(RegistrationError::RetryUnavailable);
    }
    if record.retry_not_before_ms as u64 > now_ms()? {
        return Err(RegistrationError::RetryDeferred);
    }
    Ok(())
}

fn checked<T>(
    local: &LocalData,
    store: &Arc<Store>,
    cancellation: &RegistrationCancellation,
    expected: &RegistrationRecord,
    operation: impl FnOnce() -> Result<T, RegistrationError>,
) -> Result<T, RegistrationError> {
    current(local, store, || {
        // The watch read guard linearizes bounded key use and SQL writes with Cancel.
        let _active = cancellation.guard()?;
        let latest = store.pending_registration().map_err(storage)?;
        if latest.as_ref() != Some(expected) {
            return Err(RegistrationError::ContextChanged);
        }
        verify(expected)?;
        operation()
    })
}

async fn until_stopped<T>(
    cancellation: &RegistrationCancellation,
    changes: &mut watch::Receiver<()>,
    operation: impl Future<Output = Result<T, RegistrationError>>,
) -> Result<T, RegistrationError> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(RegistrationError::Cancelled),
        _ = changes.changed() => Err(RegistrationError::ContextChanged),
        result = operation => result,
    }
}

fn problem(response: &RegistrationResponse) -> Result<RegistrationError, RegistrationError> {
    if !response.problem_json {
        return Err(RegistrationError::InvalidResponse);
    }
    let problem =
        ProblemDetails::from_json(response.body.as_bytes(), MAX_ACCOUNT_ENTRY_PROBLEM_BYTES)
            .map_err(|_| RegistrationError::InvalidResponse)?;
    if problem.status != response.status {
        return Err(RegistrationError::InvalidResponse);
    }
    let code = problem.code.as_str();
    match (problem.status, code, problem.changed, problem.retryable) {
        (400 | 413 | 415, "auth.invalid_request", false, false) => {
            Ok(RegistrationError::RequestRejected)
        }
        (403, "policy.denied", false, false) => Ok(RegistrationError::PolicyDenied),
        (401, "auth.authentication_required", false, false) => {
            Ok(RegistrationError::AuthenticationDenied)
        }
        (409, "auth.registration_denied", false, false) => {
            Ok(RegistrationError::RegistrationDenied)
        }
        (413, "auth.quota_exceeded", false, false) => Ok(RegistrationError::QuotaExceeded),
        (429, "auth.rate_limited", false, true) => Ok(RegistrationError::RateLimited {
            retry_after_seconds: response.retry_after.ok_or(RegistrationError::InvalidResponse)?,
        }),
        (503, "auth.storage_unavailable", false, true) => Ok(RegistrationError::ServiceUnavailable),
        (503, "auth.commit_outcome_unknown", true, false) => Ok(RegistrationError::OutcomeUnknown),
        _ => Err(RegistrationError::InvalidResponse),
    }
}

#[cfg(test)]
mod tests;
