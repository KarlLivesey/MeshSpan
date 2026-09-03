// SPDX-License-Identifier: GPL-2.0-only

//! Canonical version-one DNS webhook wire contract over a secret-safe HTTP boundary.

use std::future::Future;

use meshspan_contracts::ContractError;
use serde_json::{Map, Value, json};

use crate::{WebhookDnsAction, WebhookDnsApi, WebhookDnsRecord};

const MAXIMUM_BODY_BYTES: usize = 16 * 1_024;

/// Webhook request value which deliberately excludes the protected bearer token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookHttpRequest {
    /// Exact allow-listed endpoint.
    pub url: String,
    /// Canonical version-one JSON body.
    pub body: Vec<u8>,
}

/// Bounded webhook response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookHttpResponse {
    /// HTTP response status.
    pub status: u16,
    /// Complete bounded JSON response body.
    pub body: Vec<u8>,
}

/// Secret-safe HTTPS boundary for an explicitly configured webhook endpoint.
pub trait WebhookHttpTransport {
    /// Sends one request with bearer credentials outside the inspectable request value.
    ///
    /// # Errors
    ///
    /// Returns closed validation, availability, deadline or certificate failures.
    fn send(
        &mut self,
        request: &WebhookHttpRequest,
        bearer_token: &[u8],
    ) -> impl Future<Output = Result<WebhookHttpResponse, ContractError>> + Send;
}

/// Strict version-one DNS webhook adapter.
pub struct WebhookV1Api<T> {
    transport: T,
}

impl<T> WebhookV1Api<T> {
    /// Wraps one authenticated HTTPS transport.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Returns the transport for orderly shutdown or inspection.
    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl<T> WebhookDnsApi for WebhookV1Api<T>
where
    T: WebhookHttpTransport + Send + Sync,
{
    async fn apply(
        &mut self,
        endpoint: &str,
        bearer_token: &[u8],
        action: WebhookDnsAction,
        record: &WebhookDnsRecord<'_>,
    ) -> Result<(), ContractError> {
        let value = std::str::from_utf8(record.value).map_err(|_| ContractError::InvalidInput)?;
        let action = match action {
            WebhookDnsAction::Publish => "publish",
            WebhookDnsAction::Remove => "remove",
        };
        let body = serde_json::to_vec(&json!({
            "action": action,
            "name": record.name,
            "ownership": record.ownership_marker,
            "value": value,
            "version": 1
        }))
        .map_err(|_| ContractError::InternalContract)?;
        let response = self
            .transport
            .send(
                &WebhookHttpRequest {
                    url: endpoint.to_owned(),
                    body,
                },
                bearer_token,
            )
            .await?;
        validate_response(&response, record.ownership_marker)
    }
}

fn validate_response(
    response: &WebhookHttpResponse,
    expected_ownership: &str,
) -> Result<(), ContractError> {
    if response.status == 401 || response.status == 403 {
        return Err(ContractError::Unauthorized);
    }
    if response.status != 200 || response.body.len() > MAXIMUM_BODY_BYTES {
        return Err(ContractError::Unavailable);
    }
    let root = crate::strict_json::from_slice(&response.body)
        .map_err(|_| ContractError::InternalContract)?;
    let object = root.as_object().ok_or(ContractError::InternalContract)?;
    exact_response_fields(object)?;
    if object.get("version").and_then(Value::as_u64) != Some(1)
        || object.get("accepted").and_then(Value::as_bool) != Some(true)
        || object.get("ownership").and_then(Value::as_str) != Some(expected_ownership)
    {
        return Err(ContractError::InternalContract);
    }
    Ok(())
}

fn exact_response_fields(object: &Map<String, Value>) -> Result<(), ContractError> {
    const FIELDS: [&str; 3] = ["accepted", "ownership", "version"];
    if object.len() != FIELDS.len() || !FIELDS.iter().all(|field| object.contains_key(*field)) {
        return Err(ContractError::InternalContract);
    }
    Ok(())
}
