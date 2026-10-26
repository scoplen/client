// SPDX-License-Identifier: Apache-2.0
//! Explicit authenticated team JSON exchanges; no redirect, cookie, or automatic retry.

use reqwest::{Method, header};
use scoplen_api::organization::{MAX_ORGANIZATION_PROBLEM_BYTES, MAX_ORGANIZATION_RESOURCE_BYTES};
use scoplen_crypto::{DpopProof, validate_server_origin};
use uuid::Uuid;

use super::{Response, Transport, read_body};
use crate::personal_server::PersonalServerError;

impl Transport {
    pub(in crate::personal_server) async fn team_get(
        &self,
        origin: &str,
        path: &str,
        access: &str,
        proof: &DpopProof,
        limit: usize,
    ) -> Result<Response, PersonalServerError> {
        self.team_exchange(origin, path, None, access, proof, None, limit).await
    }

    pub(in crate::personal_server) async fn team_create(
        &self,
        origin: &str,
        body: &[u8],
        operation_id: Uuid,
        access: &str,
        proof: &DpopProof,
    ) -> Result<Response, PersonalServerError> {
        self.team_exchange(
            origin,
            "/api/v1/orgs",
            Some(body),
            access,
            proof,
            Some(operation_id),
            MAX_ORGANIZATION_RESOURCE_BYTES,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn team_exchange(
        &self,
        origin: &str,
        path: &str,
        body: Option<&[u8]>,
        access: &str,
        proof: &DpopProof,
        operation_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Response, PersonalServerError> {
        validate_server_origin(origin).map_err(|_| PersonalServerError::Identity)?;
        let authorization = zeroize::Zeroizing::new(format!("DPoP {access}"));
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
            .header(header::ACCEPT, "application/json")
            .header(header::ACCEPT_ENCODING, "identity");
        if let Some(body) = body {
            request = request.header(header::CONTENT_TYPE, "application/json").body(body.to_vec());
        }
        if let Some(operation_id) = operation_id {
            request = request.header("Idempotency-Key", operation_id.to_string());
        }
        let response = request.send().await.map_err(|error| {
            if error.is_connect() && !error.is_timeout() {
                PersonalServerError::ConnectionBeforeRequest
            } else {
                PersonalServerError::Network
            }
        })?;
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
            || response.headers().contains_key(header::CONTENT_ENCODING)
            || single("cache-control") != Some("no-store")
            || single("pragma") != Some("no-cache")
            || single("x-request-id").is_none_or(str::is_empty)
            || if response.status().is_success() {
                !matches!(
                    content_type,
                    Some("application/json" | "application/json; charset=utf-8")
                )
            } else {
                !problem_json
            }
        {
            return Err(PersonalServerError::InvalidResponse);
        }
        let status = response.status().as_u16();
        let etag = single("etag").map(str::to_owned);
        let cache_control = single("cache-control").map(str::to_owned);
        let pragma = single("pragma").map(str::to_owned);
        let limit =
            if response.status().is_success() { limit } else { MAX_ORGANIZATION_PROBLEM_BYTES };
        let body = read_body(response, limit).await?;
        Ok(Response {
            status,
            body,
            etag,
            cache_control,
            pragma,
            problem_json,
            problem_cbor: false,
            date: None,
            refresh_protocol: false,
            nonce: None,
            retry_after: None,
        })
    }
}
