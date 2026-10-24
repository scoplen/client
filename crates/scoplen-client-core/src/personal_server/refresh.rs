// SPDX-License-Identifier: Apache-2.0
//! Single-use native refresh shared by explicit operations and the background owner.

use scoplen_api::{
    ProblemDetails,
    auth::{AuthRefreshRequest, AuthTokenResponse, MAX_REFRESH_TOKEN_BYTES},
};
use scoplen_crypto::{
    DeviceAccessToken, DpopProof, DpopTarget, DpopToken, P256SigningKey, SecretVec,
    dpop_jwk_thumbprint,
};
use zeroize::{Zeroize as _, Zeroizing};

use super::{PersonalServer, PersonalServerError, identity, now, storage, trusted_token_keys};
use crate::store::{
    Store,
    personal::{PersonalRecord, PersonalRefreshClaim, PersonalTokens},
};

impl PersonalServer {
    pub(super) async fn refresh_for_operation(
        &self,
        store: &Store,
    ) -> Result<(), PersonalServerError> {
        self.refresh_for_run(store, None).await
    }

    pub(super) async fn refresh_for_run(
        &self,
        store: &Store,
        run: Option<&std::sync::Arc<super::background::Run>>,
    ) -> Result<(), PersonalServerError> {
        super::background::guard(run)?;
        let identity = super::record(store)?;
        let current = now()?;
        if identity.auth_scope.is_some()
            && identity.access_expires_at.is_some_and(|expiry| expiry > current.saturating_add(60))
        {
            return Ok(());
        }
        if identity.refresh_retry_at.is_some_and(|retry| retry > current) {
            return Err(PersonalServerError::RefreshDeferred);
        }
        let secrets = identity::Secrets::parse(&identity.private_material)?;
        let signing = P256SigningKey::from_bytes(secrets.signing())
            .map_err(|_| PersonalServerError::Identity)?;
        let target = DpopTarget::new("POST", &identity.origin, "/api/v1/auth/refresh")
            .map_err(|_| PersonalServerError::Identity)?;
        let transport = self.transport.as_ref().map_err(|error| *error)?;
        let claim = {
            let _active = super::background::guard(run)?;
            store
                .claim_personal_refresh(&identity, current)
                .map_err(storage)?
                .ok_or(PersonalServerError::AuthenticationRequired)?
        };
        // A committed claim survives cancellation and crashes. Only a verified unchanged
        // response, or a confirmed connection failure before sending, may return it to use.
        let refresh = std::str::from_utf8(claim.previous.refresh.as_bytes())
            .map_err(|_| PersonalServerError::AuthenticationRequired)?;
        let mut request = AuthRefreshRequest::new(refresh)
            .map_err(|_| PersonalServerError::AuthenticationRequired)?;
        let body = request.to_json().map(Zeroizing::new);
        request.refresh_token.zeroize();
        let body = body.map_err(|_| PersonalServerError::AuthenticationRequired)?;
        let mut nonce = None;
        for attempt in 0..2 {
            super::background::guard(run)?;
            if now()? >= claim.previous.refresh_expires_at {
                return Err(PersonalServerError::AuthenticationRequired);
            }
            let proof = DpopProof::sign(
                &signing,
                &signing.public_key_sec1(),
                &target,
                DpopToken::Refresh,
                now()?,
                nonce.as_deref(),
            )
            .map_err(|_| PersonalServerError::AuthenticationRequired)?;
            let response = match transport.refresh(&identity.origin, body.as_bytes(), &proof).await
            {
                Ok(response) => response,
                Err(PersonalServerError::ConnectionBeforeRequest) => {
                    let _active = super::background::guard(run)?;
                    restore(store, &identity, &claim, None)?;
                    return Err(PersonalServerError::ConnectionBeforeRequest);
                }
                Err(_) => return Err(PersonalServerError::AuthenticationRequired),
            };
            if !response.refresh_protocol {
                return Err(PersonalServerError::InvalidResponse);
            }
            if response.status == 200 {
                let tokens = AuthTokenResponse::from_json(response.text()?)
                    .map_err(|_| PersonalServerError::InvalidResponse)?;
                let access = Zeroizing::new(tokens.access_token);
                let refresh = Zeroizing::new(tokens.refresh_token);
                if refresh.as_bytes() == claim.previous.refresh.as_bytes()
                    || refresh.is_empty()
                    || refresh.len() > MAX_REFRESH_TOKEN_BYTES
                {
                    return Err(PersonalServerError::InvalidResponse);
                }
                let trusted = trusted_token_keys(transport, &identity.origin).await?;
                let current = now()?;
                let verified = DeviceAccessToken::parse(&access)
                    .and_then(|token| token.verify(&trusted, current))
                    .map_err(|_| PersonalServerError::InvalidResponse)?;
                let claims = verified.claims();
                // JWT issuance and remaining whole seconds need not share a clock sample.
                // Use the lifetime for scheduling without extending the retained ceiling.
                let expiry = claims
                    .iat
                    .saturating_add(tokens.refresh_expires_in)
                    .min(claim.previous.refresh_expires_at);
                if expiry <= current {
                    return Err(PersonalServerError::InvalidResponse);
                }
                if claims.sub != identity.account_id
                    || claims.did != store.device_id()
                    || !claims.org.is_empty()
                    || claims.cnf_jkt
                        != dpop_jwk_thumbprint(&signing.public_key_sec1())
                            .map_err(|_| PersonalServerError::Identity)?
                    || !claims.scope.split(' ').all(|scope| {
                        claim.previous.scope.split(' ').any(|original| original == scope)
                    })
                {
                    return Err(PersonalServerError::InvalidResponse);
                }
                let tokens = PersonalTokens {
                    access: SecretVec::new(access.as_bytes().to_vec()),
                    refresh: SecretVec::new(refresh.as_bytes().to_vec()),
                    access_expires_at: current
                        .saturating_add(tokens.expires_in)
                        .min(verified.expires_at()),
                    refresh_expires_at: expiry,
                    scope: claims.scope.clone(),
                };
                let _active = super::background::guard(run)?;
                if !store
                    .finish_personal_session(&identity, claim.generation, true, &tokens, None)
                    .map_err(storage)?
                {
                    return Err(PersonalServerError::AuthenticationRequired);
                }
                return Ok(());
            }
            let problem = if response.problem_json {
                serde_json::from_slice::<ProblemDetails>(response.body.as_bytes()).ok()
            } else {
                None
            };
            let Some(problem) = problem.filter(|problem| problem.status == response.status) else {
                return Err(PersonalServerError::AuthenticationRequired);
            };
            if !problem.changed && problem.retryable {
                let _active = super::background::guard(run)?;
                match (response.status, problem.code.as_str()) {
                    (400, "auth.use_dpop_nonce") => {
                        if let Some(challenge) = response.nonce {
                            // Validate the exact nonce before allowing any credential reuse.
                            DpopProof::sign(
                                &signing,
                                &signing.public_key_sec1(),
                                &target,
                                DpopToken::Refresh,
                                now()?,
                                Some(&challenge),
                            )
                            .map_err(|_| PersonalServerError::InvalidResponse)?;
                            if attempt == 0 {
                                nonce = Some(challenge);
                                continue;
                            }
                            restore(store, &identity, &claim, None)?;
                            return Err(PersonalServerError::RefreshDeferred);
                        }
                    }
                    (503, "auth.storage_unavailable") => {
                        restore(store, &identity, &claim, None)?;
                        return Err(PersonalServerError::RefreshDeferred);
                    }
                    (429, "auth.rate_limited") => {
                        if let Some(seconds) = response.retry_after {
                            let retry_at = now()?.saturating_add(seconds);
                            restore(store, &identity, &claim, Some(retry_at))?;
                            return Err(PersonalServerError::RefreshDeferred);
                        }
                    }
                    _ => {}
                }
            }
            return Err(PersonalServerError::AuthenticationRequired);
        }
        Err(PersonalServerError::AuthenticationRequired)
    }
}

fn restore(
    store: &Store,
    identity: &PersonalRecord,
    claim: &PersonalRefreshClaim,
    retry_at: Option<u64>,
) -> Result<(), PersonalServerError> {
    if !store
        .finish_personal_session(identity, claim.generation, true, &claim.previous, retry_at)
        .map_err(storage)?
    {
        return Err(PersonalServerError::AuthenticationRequired);
    }
    Ok(())
}
