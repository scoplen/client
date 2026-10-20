// SPDX-License-Identifier: Apache-2.0
//! Bounded HTTPS with platform trust, no redirects, cookies, proxies, or automatic retries.

use std::time::Duration;

use reqwest::{Client, Method, header};
use scoplen_crypto::{SecretVec, validate_server_origin};

use super::PersonalServerError;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) struct Transport {
    client: Client,
}

pub(super) struct Response {
    pub status: u16,
    pub body: SecretVec,
}

impl Response {
    pub fn text(&self) -> Result<&str, PersonalServerError> {
        std::str::from_utf8(self.body.as_bytes()).map_err(|_| PersonalServerError::InvalidResponse)
    }
}

impl Transport {
    pub fn new() -> Result<Self, PersonalServerError> {
        // All Rustls consumers use the already installed provider, or the existing ring stack.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| PersonalServerError::Network)?;
        Ok(Self { client })
    }

    #[cfg(test)]
    pub fn fixture(certificate: reqwest::Certificate, timeout: Duration) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Self {
            client: Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .tls_certs_merge([certificate])
                .timeout(timeout)
                .build()
                .unwrap(),
        }
    }

    pub async fn post(
        &self,
        origin: &str,
        path: &str,
        body: &[u8],
        limit: usize,
    ) -> Result<Response, PersonalServerError> {
        self.exchange(Method::POST, origin, path, Some(body), limit).await
    }

    pub async fn get(
        &self,
        origin: &str,
        path: &str,
        limit: usize,
    ) -> Result<Response, PersonalServerError> {
        self.exchange(Method::GET, origin, path, None, limit).await
    }

    async fn exchange(
        &self,
        method: Method,
        origin: &str,
        path: &str,
        body: Option<&[u8]>,
        limit: usize,
    ) -> Result<Response, PersonalServerError> {
        validate_server_origin(origin).map_err(|_| PersonalServerError::Invitation)?;
        let mut request = self
            .client
            .request(method, format!("{origin}{path}"))
            .header(header::ACCEPT, "application/json");
        if let Some(body) = body {
            request = request.header(header::CONTENT_TYPE, "application/json").body(body.to_vec());
        }
        let mut response = request.send().await.map_err(|error| {
            if error.is_connect() && !error.is_timeout() {
                PersonalServerError::ConnectionBeforeRequest
            } else {
                PersonalServerError::Network
            }
        })?;
        if response.status().is_redirection() {
            return Err(PersonalServerError::InvalidResponse);
        }
        let status = response.status().as_u16();
        if response.content_length().is_some_and(|length| length > limit as u64) {
            return Err(PersonalServerError::InvalidResponse);
        }
        if response.status().is_success() {
            if !response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| {
                    value.split(',').any(|part| part.trim().eq_ignore_ascii_case("no-store"))
                })
            {
                return Err(PersonalServerError::InvalidResponse);
            }
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .ok_or(PersonalServerError::InvalidResponse)?;
            if content_type != "application/json"
                && content_type != "application/json; charset=utf-8"
            {
                return Err(PersonalServerError::InvalidResponse);
            }
        }
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| PersonalServerError::Network)? {
            if chunk.len() > limit.saturating_sub(bytes.len()) {
                return Err(PersonalServerError::InvalidResponse);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(Response { status, body: SecretVec::new(bytes.to_vec()) })
    }
}
