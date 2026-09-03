// SPDX-License-Identifier: GPL-2.0-only

//! Fixed-origin Cloudflare adapter over the shared bounded rustls HTTP transport.

use std::{future::Future, sync::Arc, time::Duration};

use hyper::Method;
use meshspan_contracts::ContractError;
use rustls::ClientConfig;

use crate::{
    CloudflareHttpMethod, CloudflareHttpRequest, CloudflareHttpResponse, CloudflareHttpTransport,
    rustls_http::{RustlsHttpClient, RustlsHttpError, RustlsHttpRequest},
};

const API_PREFIX: &str = "https://api.cloudflare.com/client/v4/";
const CONTENT_TYPE_JSON: &str = "application/json";
const MAXIMUM_TOKEN_BYTES: usize = 2_048;
const MINIMUM_TOKEN_BYTES: usize = 16;
const USER_AGENT_VALUE: &str = "MeshSpan/0.1 Cloudflare-DNS";

/// Direct userspace Cloudflare API transport with an immutable API origin.
pub struct RustlsCloudflareHttpTransport {
    client: RustlsHttpClient,
}

impl RustlsCloudflareHttpTransport {
    /// Creates a fixed-origin transport with finite connection and request deadlines.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive timeouts.
    pub fn new(
        tls: Arc<ClientConfig>,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, ContractError> {
        RustlsHttpClient::new(tls, connect_timeout, request_timeout)
            .map(|client| Self { client })
            .map_err(map_error)
    }

    async fn exchange(
        &self,
        request: &CloudflareHttpRequest,
        bearer_token: &[u8],
    ) -> Result<CloudflareHttpResponse, ContractError> {
        validate_request(request, bearer_token)?;
        let method = match request.method {
            CloudflareHttpMethod::Get => Method::GET,
            CloudflareHttpMethod::Post => Method::POST,
            CloudflareHttpMethod::Delete => Method::DELETE,
        };
        let response = self
            .client
            .send(RustlsHttpRequest {
                method,
                url: &request.url,
                body: &request.body,
                content_type: (!request.body.is_empty()).then_some(CONTENT_TYPE_JSON),
                bearer_token: Some(bearer_token),
                user_agent: USER_AGENT_VALUE,
            })
            .await
            .map_err(map_error)?;
        Ok(CloudflareHttpResponse {
            status: response.status,
            body: response.body,
        })
    }
}

impl CloudflareHttpTransport for RustlsCloudflareHttpTransport {
    fn send(
        &mut self,
        request: &CloudflareHttpRequest,
        bearer_token: &[u8],
    ) -> impl Future<Output = Result<CloudflareHttpResponse, ContractError>> + Send {
        self.exchange(request, bearer_token)
    }
}

fn validate_request(
    request: &CloudflareHttpRequest,
    bearer_token: &[u8],
) -> Result<(), ContractError> {
    if !request.url.starts_with(API_PREFIX)
        || !(MINIMUM_TOKEN_BYTES..=MAXIMUM_TOKEN_BYTES).contains(&bearer_token.len())
        || !bearer_token.is_ascii()
        || bearer_token.iter().any(u8::is_ascii_control)
    {
        return Err(ContractError::InvalidInput);
    }
    match request.method {
        CloudflareHttpMethod::Post if request.body.is_empty() => Err(ContractError::InvalidInput),
        CloudflareHttpMethod::Get | CloudflareHttpMethod::Delete if !request.body.is_empty() => {
            Err(ContractError::InvalidInput)
        }
        CloudflareHttpMethod::Get | CloudflareHttpMethod::Post | CloudflareHttpMethod::Delete => {
            Ok(())
        }
    }
}

const fn map_error(error: RustlsHttpError) -> ContractError {
    match error {
        RustlsHttpError::InvalidRequest => ContractError::InvalidInput,
        RustlsHttpError::Unavailable | RustlsHttpError::Rejected => ContractError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TOKEN: &[u8] = b"test-token-with-enough-entropy";

    #[test]
    fn rejects_non_cloudflare_origins_and_header_injection() {
        let request = CloudflareHttpRequest {
            method: CloudflareHttpMethod::Get,
            url: "https://attacker.invalid/client/v4/zones".to_owned(),
            body: Vec::new(),
        };
        assert_eq!(
            validate_request(&request, VALID_TOKEN),
            Err(ContractError::InvalidInput)
        );

        let request = CloudflareHttpRequest {
            method: CloudflareHttpMethod::Get,
            url: format!("{API_PREFIX}zones"),
            body: Vec::new(),
        };
        assert_eq!(
            validate_request(&request, b"valid-length-token\r\nattack"),
            Err(ContractError::InvalidInput)
        );
    }

    #[test]
    fn enforces_method_body_contract() {
        let mut request = CloudflareHttpRequest {
            method: CloudflareHttpMethod::Post,
            url: format!("{API_PREFIX}zones/id/dns_records"),
            body: Vec::new(),
        };
        assert_eq!(
            validate_request(&request, VALID_TOKEN),
            Err(ContractError::InvalidInput)
        );
        request.body = br#"{"type":"TXT"}"#.to_vec();
        assert_eq!(validate_request(&request, VALID_TOKEN), Ok(()));
        request.method = CloudflareHttpMethod::Delete;
        assert_eq!(
            validate_request(&request, VALID_TOKEN),
            Err(ContractError::InvalidInput)
        );
    }
}
