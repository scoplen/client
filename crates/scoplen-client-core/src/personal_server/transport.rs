// SPDX-License-Identifier: Apache-2.0
//! Bounded HTTPS with platform trust, no redirects, cookies, proxies, or automatic retries.

use std::time::{Duration, Instant, SystemTime};

use reqwest::{Client, Method, header};
use scoplen_api::auth::AuthRateLimitHeaders;
use scoplen_crypto::{DpopProof, SecretVec, validate_server_origin};

use super::PersonalServerError;

mod registration;
mod teams;
pub(super) use registration::RegistrationResponse;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) struct Transport {
    client: Client,
    sync_client: Client,
    pub(super) notification_tls: std::sync::Arc<rustls::ClientConfig>,
}

pub(super) struct Response {
    pub status: u16,
    pub body: SecretVec,
    pub problem_json: bool,
    pub problem_cbor: bool,
    pub date: Option<(SystemTime, Instant)>,
    pub refresh_protocol: bool,
    pub nonce: Option<String>,
    pub retry_after: Option<u64>,
    pub etag: Option<String>,
    pub cache_control: Option<String>,
    pub pragma: Option<String>,
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
        let builder = || {
            Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .tls_version_min(reqwest::tls::Version::TLS_1_3)
                .connect_timeout(Duration::from_secs(5))
                .timeout(REQUEST_TIMEOUT)
        };
        let client = builder().build().map_err(|_| PersonalServerError::Network)?;
        let sync_client =
            builder().http2_prior_knowledge().build().map_err(|_| PersonalServerError::Network)?;
        Ok(Self { client, sync_client, notification_tls: notification_tls()? })
    }

    #[cfg(test)]
    pub fn fixture(certificate: reqwest::Certificate, timeout: Duration) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let builder = || {
            Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .tls_version_min(reqwest::tls::Version::TLS_1_3)
                .tls_certs_merge([certificate.clone()])
                .timeout(timeout)
        };
        Self {
            client: builder().build().unwrap(),
            sync_client: builder().http2_prior_knowledge().build().unwrap(),
            notification_tls: notification_tls().unwrap(),
        }
    }

    pub async fn post(
        &self,
        origin: &str,
        path: &str,
        body: &[u8],
        limit: usize,
    ) -> Result<Response, PersonalServerError> {
        self.exchange(Method::POST, origin, path, Some(body), None, None, limit).await
    }

    pub async fn get(
        &self,
        origin: &str,
        path: &str,
        limit: usize,
    ) -> Result<Response, PersonalServerError> {
        self.exchange(Method::GET, origin, path, None, None, None, limit).await
    }

    pub async fn refresh(
        &self,
        origin: &str,
        body: &[u8],
        proof: &DpopProof,
    ) -> Result<Response, PersonalServerError> {
        self.exchange(
            Method::POST,
            origin,
            "/api/v1/auth/refresh",
            Some(body),
            Some(proof),
            None,
            16_384,
        )
        .await
    }

    pub async fn account_get(
        &self,
        origin: &str,
        path: &str,
        access: &str,
        proof: &DpopProof,
        limit: usize,
    ) -> Result<Response, PersonalServerError> {
        self.exchange(Method::GET, origin, path, None, Some(proof), Some(access), limit).await
    }

    pub async fn protected(
        &self,
        origin: &str,
        path: &str,
        body: Option<&[u8]>,
        access_token: &str,
        proof: &DpopProof,
        limit: usize,
    ) -> Result<Response, PersonalServerError> {
        validate_server_origin(origin).map_err(|_| PersonalServerError::Identity)?;
        let authorization = zeroize::Zeroizing::new(format!("DPoP {access_token}"));
        let mut authorization = header::HeaderValue::from_str(&authorization)
            .map_err(|_| PersonalServerError::Identity)?;
        authorization.set_sensitive(true);
        let mut dpop = header::HeaderValue::from_str(proof.as_str())
            .map_err(|_| PersonalServerError::Identity)?;
        dpop.set_sensitive(true);
        let mut request = self
            .sync_client
            .request(
                if body.is_some() { Method::POST } else { Method::GET },
                format!("{origin}{path}"),
            )
            .version(reqwest::Version::HTTP_2)
            .header(header::AUTHORIZATION, authorization)
            .header("DPoP", dpop)
            .header(header::ACCEPT, "application/cbor")
            .header(header::ACCEPT_ENCODING, "identity");
        if let Some(body) = body {
            request = request.header(header::CONTENT_TYPE, "application/cbor").body(body.to_vec());
        }
        let response = request.send().await.map_err(|_| PersonalServerError::Network)?;
        if response.version() != reqwest::Version::HTTP_2
            || response.status().is_redirection()
            || response.headers().contains_key(header::AGE)
            || response.headers().contains_key(header::CONTENT_ENCODING)
            || response.status().is_success()
                && response.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok())
                    != Some("application/cbor")
        {
            return Err(PersonalServerError::InvalidResponse);
        }
        let status = response.status().as_u16();
        let problem_cbor =
            response.headers().get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok())
                == Some("application/problem+cbor");
        let date = response
            .headers()
            .get(header::DATE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| httpdate::parse_http_date(value).ok())
            .map(|date| (date, Instant::now()));
        let body = read_body(response, limit).await?;
        Ok(Response {
            status,
            body,
            problem_json: false,
            problem_cbor,
            date,
            refresh_protocol: false,
            nonce: None,
            retry_after: None,
            etag: None,
            cache_control: None,
            pragma: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn exchange(
        &self,
        method: Method,
        origin: &str,
        path: &str,
        body: Option<&[u8]>,
        proof: Option<&DpopProof>,
        access: Option<&str>,
        limit: usize,
    ) -> Result<Response, PersonalServerError> {
        validate_server_origin(origin).map_err(|_| PersonalServerError::Identity)?;
        let mut request = self
            .client
            .request(method, format!("{origin}{path}"))
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT_ENCODING, "identity");
        if let Some(access) = access {
            let authorization = zeroize::Zeroizing::new(format!("DPoP {access}"));
            let mut authorization = header::HeaderValue::from_str(&authorization)
                .map_err(|_| PersonalServerError::Identity)?;
            authorization.set_sensitive(true);
            request = request.header(header::AUTHORIZATION, authorization);
        }
        if let Some(proof) = proof {
            let mut header = header::HeaderValue::from_str(proof.as_str())
                .map_err(|_| PersonalServerError::Identity)?;
            header.set_sensitive(true);
            request = request.header("DPoP", header);
        }
        if let Some(body) = body {
            request = request.header(header::CONTENT_TYPE, "application/json").body(body.to_vec());
        }
        let response = request.send().await.map_err(|error| {
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
        let no_store = response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.split(',').any(|part| part.trim().eq_ignore_ascii_case("no-store"))
            });
        let cached = response.headers().contains_key(header::AGE);
        let content_type =
            response.headers().get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok());
        let problem_json = no_store
            && !cached
            && matches!(
                content_type,
                Some("application/problem+json" | "application/problem+json; charset=utf-8")
            );
        let single_header = |name: &str| {
            let mut values = response.headers().get_all(name).iter();
            let first = values.next()?.to_str().ok()?;
            if values.next().is_some() {
                return None;
            }
            Some(first)
        };
        let refresh_protocol = no_store
            && !cached
            && !response.headers().contains_key(header::CONTENT_ENCODING)
            && single_header("content-type").is_some()
            && single_header("cache-control").is_some()
            && single_header("pragma").is_some_and(|value| value.eq_ignore_ascii_case("no-cache"));
        let nonce = single_header("dpop-nonce").map(str::to_owned);
        let etag = single_header("etag").map(str::to_owned);
        let cache_control = single_header("cache-control").map(str::to_owned);
        let pragma = single_header("pragma").map(str::to_owned);
        let retry_after = single_header("retry-after").and_then(|value| {
            let seconds = value.parse::<u16>().ok()?;
            if value != seconds.to_string() {
                return None;
            }
            AuthRateLimitHeaders::new(seconds)
                .ok()
                .map(|headers| u64::from(headers.retry_after_seconds()))
        });
        if response.status().is_success()
            && (!no_store
                || cached
                || response.headers().contains_key(header::CONTENT_ENCODING)
                || single_header("content-type").is_none()
                || !matches!(
                    content_type,
                    Some("application/json" | "application/json; charset=utf-8")
                ))
        {
            return Err(PersonalServerError::InvalidResponse);
        }
        let body = read_body(response, limit).await?;
        Ok(Response {
            status,
            body,
            problem_json,
            problem_cbor: false,
            date: None,
            refresh_protocol,
            nonce,
            retry_after,
            etag,
            cache_control,
            pragma,
        })
    }
}

fn notification_tls() -> Result<std::sync::Arc<rustls::ClientConfig>, PersonalServerError> {
    use rustls_platform_verifier::BuilderVerifierExt as _;
    let mut config =
        rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_platform_verifier()
            .map_err(|_| PersonalServerError::Network)?
            .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(std::sync::Arc::new(config))
}

async fn read_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<SecretVec, PersonalServerError> {
    if response.content_length().is_some_and(|length| length > limit as u64) {
        return Err(PersonalServerError::InvalidResponse);
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| PersonalServerError::Network)? {
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err(PersonalServerError::InvalidResponse);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(SecretVec::new(bytes.to_vec()))
}
