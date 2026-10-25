// SPDX-License-Identifier: Apache-2.0
//! Native Account JSON exchanges share the bounded TLS 1.3/H2 client without credentials.

use reqwest::header;
use scoplen_api::{
    account_admission::{AccountEntryOperation, MAX_ACCOUNT_ENTRY_PROBLEM_BYTES},
    auth::AuthRateLimitHeaders,
};
use scoplen_crypto::{SecretVec, validate_server_origin};

use super::Transport;
use crate::personal_server::RegistrationError;

pub(in crate::personal_server) struct RegistrationResponse {
    pub status: u16,
    pub body: SecretVec,
    pub problem_json: bool,
    pub retry_after: Option<u16>,
}

impl Transport {
    pub(in crate::personal_server) async fn registration_post(
        &self,
        origin: &str,
        operation: AccountEntryOperation,
        body: SecretVec,
    ) -> Result<RegistrationResponse, RegistrationError> {
        validate_server_origin(origin).map_err(|_| RegistrationError::InvalidInput)?;
        let path = match operation {
            AccountEntryOperation::RequestChallenge => "/api/v1/auth/accounts/requests/challenge",
            AccountEntryOperation::Register => "/api/v1/auth/accounts/register",
            _ => return Err(RegistrationError::InvalidInput),
        };
        let (request_limit, success_limit) = operation.body_limits();
        if body.len() > request_limit {
            return Err(RegistrationError::InvalidInput);
        }
        let mut response = self
            .sync_client
            .post(format!("{origin}{path}"))
            .version(reqwest::Version::HTTP_2)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT_ENCODING, "identity")
            .body(bytes::Bytes::from_owner(body))
            .send()
            .await
            .map_err(network)?;
        if matches!(response.status().as_u16(), 404 | 405 | 501) {
            return Err(RegistrationError::UnsupportedService);
        }
        let single = |name: &str| {
            let mut values = response.headers().get_all(name).iter();
            let value = values.next()?.to_str().ok()?;
            values.next().is_none().then_some(value)
        };
        let content_type = single("content-type");
        let problem_json = matches!(
            content_type,
            Some("application/problem+json" | "application/problem+json; charset=utf-8")
        );
        if response.version() != reqwest::Version::HTTP_2
            || response.status().is_redirection()
            || response.headers().contains_key(header::SET_COOKIE)
            || response.headers().contains_key(header::AGE)
            || single("cache-control") != Some("no-store")
            || single("pragma") != Some("no-cache")
            || response.headers().contains_key(header::CONTENT_ENCODING)
                && single("content-encoding") != Some("identity")
            || response.headers().contains_key(header::CONTENT_LENGTH)
                && single("content-length").is_none()
            || if response.status().is_success() {
                !matches!(
                    content_type,
                    Some("application/json" | "application/json; charset=utf-8")
                )
            } else {
                !problem_json
            }
        {
            return Err(RegistrationError::InvalidResponse);
        }
        let retry_after = if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let text = single("retry-after").ok_or(RegistrationError::InvalidResponse)?;
            let seconds = text.parse::<u16>().map_err(|_| RegistrationError::InvalidResponse)?;
            let profile = AuthRateLimitHeaders::new(seconds)
                .map_err(|_| RegistrationError::InvalidResponse)?;
            if text != seconds.to_string()
                || single("ratelimit") != Some(profile.rate_limit().as_str())
                || single("ratelimit-policy") != Some(profile.rate_limit_policy())
            {
                return Err(RegistrationError::InvalidResponse);
            }
            Some(seconds)
        } else {
            None
        };
        let status = response.status().as_u16();
        let limit = if response.status().is_success() {
            success_limit
        } else {
            MAX_ACCOUNT_ENTRY_PROBLEM_BYTES
        };
        if response.content_length().is_some_and(|length| length > limit as u64) {
            return Err(RegistrationError::InvalidResponse);
        }
        let mut body = zeroize::Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(network)? {
            if chunk.len() > limit.saturating_sub(body.len()) {
                return Err(RegistrationError::InvalidResponse);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(RegistrationResponse {
            status,
            body: SecretVec::new(std::mem::take(&mut *body)),
            problem_json,
            retry_after,
        })
    }
}

fn network(error: reqwest::Error) -> RegistrationError {
    if error.is_timeout() { RegistrationError::Timeout } else { RegistrationError::Network }
}
