// SPDX-License-Identifier: GPL-2.0-only

//! Strict Cloudflare v4 DNS API adapter over a secret-safe bounded HTTPS transport.

use std::future::Future;

use meshspan_contracts::ContractError;
use serde_json::{Value, json};

use crate::{CloudflareDnsApi, CloudflareTxtRecord};

const API_ORIGIN: &str = "https://api.cloudflare.com/client/v4";
const MAXIMUM_BODY_BYTES: usize = 1024 * 1024;
const MAXIMUM_MATCHES: usize = 2;

/// HTTP methods used by the Cloudflare DNS record adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudflareHttpMethod {
    /// Exact record lookup.
    Get,
    /// Record creation.
    Post,
    /// Exact record deletion.
    Delete,
}

/// Bounded Cloudflare request excluding its protected bearer token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudflareHttpRequest {
    /// HTTP method.
    pub method: CloudflareHttpMethod,
    /// Fixed-origin Cloudflare v4 URL.
    pub url: String,
    /// JSON request body, or empty for GET and DELETE.
    pub body: Vec<u8>,
}

/// Bounded Cloudflare HTTP response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudflareHttpResponse {
    /// HTTP response status.
    pub status: u16,
    /// Complete bounded JSON body.
    pub body: Vec<u8>,
}

/// Secret-safe HTTPS boundary for the fixed Cloudflare API origin.
pub trait CloudflareHttpTransport {
    /// Sends one request with the bearer token supplied outside the inspectable request value.
    ///
    /// # Errors
    ///
    /// Returns closed availability, deadline, certificate or response-bound failures.
    fn send(
        &mut self,
        request: &CloudflareHttpRequest,
        bearer_token: &[u8],
    ) -> impl Future<Output = Result<CloudflareHttpResponse, ContractError>> + Send;
}

/// Strict Cloudflare v4 record adapter using exact filters and ownership markers.
pub struct CloudflareV4Api<T> {
    transport: T,
}

impl<T> CloudflareV4Api<T> {
    /// Wraps one bounded fixed-origin HTTPS transport.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Returns the transport for orderly shutdown or implementation inspection.
    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl<T> CloudflareDnsApi for CloudflareV4Api<T>
where
    T: CloudflareHttpTransport + Send + Sync,
{
    async fn ensure_txt(
        &mut self,
        zone_id: &str,
        api_token: &[u8],
        record: &CloudflareTxtRecord<'_>,
    ) -> Result<(), ContractError> {
        let matches = self.list_owned(zone_id, api_token, record).await?;
        match matches.as_slice() {
            [_] => Ok(()),
            [] => self.create(zone_id, api_token, record).await,
            _ => Err(ContractError::Conflict),
        }
    }

    async fn remove_txt(
        &mut self,
        zone_id: &str,
        api_token: &[u8],
        record: &CloudflareTxtRecord<'_>,
    ) -> Result<(), ContractError> {
        let matches = self.list_owned(zone_id, api_token, record).await?;
        let record_id = match matches.as_slice() {
            [] => return Ok(()),
            [record_id] => record_id,
            _ => return Err(ContractError::Conflict),
        };
        let response = self
            .transport
            .send(
                &CloudflareHttpRequest {
                    method: CloudflareHttpMethod::Delete,
                    url: format!("{API_ORIGIN}/zones/{zone_id}/dns_records/{record_id}"),
                    body: Vec::new(),
                },
                api_token,
            )
            .await?;
        let result = success_result(&response)?;
        let deleted_id = required_text(&result, "id")?;
        if deleted_id != record_id {
            return Err(ContractError::InternalContract);
        }
        Ok(())
    }
}

impl<T> CloudflareV4Api<T>
where
    T: CloudflareHttpTransport + Send,
{
    async fn list_owned(
        &mut self,
        zone_id: &str,
        api_token: &[u8],
        record: &CloudflareTxtRecord<'_>,
    ) -> Result<Vec<String>, ContractError> {
        validate_identifier(zone_id)?;
        let url = list_url(zone_id, record)?;
        let response = self
            .transport
            .send(
                &CloudflareHttpRequest {
                    method: CloudflareHttpMethod::Get,
                    url,
                    body: Vec::new(),
                },
                api_token,
            )
            .await?;
        let root = success_root(&response)?;
        reject_additional_pages(&root)?;
        let records = root
            .get("result")
            .and_then(Value::as_array)
            .ok_or(ContractError::InternalContract)?;
        if records.len() > MAXIMUM_MATCHES {
            return Err(ContractError::Conflict);
        }
        records
            .iter()
            .map(|value| validate_record(value, record))
            .collect()
    }

    async fn create(
        &mut self,
        zone_id: &str,
        api_token: &[u8],
        record: &CloudflareTxtRecord<'_>,
    ) -> Result<(), ContractError> {
        let content = std::str::from_utf8(record.value).map_err(|_| ContractError::InvalidInput)?;
        let body = serde_json::to_vec(&json!({
            "comment": record.ownership_marker,
            "content": content,
            "name": record.name,
            "proxied": false,
            "ttl": record.ttl_seconds,
            "type": "TXT"
        }))
        .map_err(|_| ContractError::InternalContract)?;
        let response = self
            .transport
            .send(
                &CloudflareHttpRequest {
                    method: CloudflareHttpMethod::Post,
                    url: format!("{API_ORIGIN}/zones/{zone_id}/dns_records"),
                    body,
                },
                api_token,
            )
            .await?;
        validate_record(&success_result(&response)?, record)?;
        Ok(())
    }
}

fn list_url(zone_id: &str, record: &CloudflareTxtRecord<'_>) -> Result<String, ContractError> {
    let content = std::str::from_utf8(record.value).map_err(|_| ContractError::InvalidInput)?;
    let mut query = form_urlencoded::Serializer::new(String::new());
    query.append_pair("type", "TXT");
    query.append_pair("name.exact", record.name);
    query.append_pair("content.exact", content);
    query.append_pair("comment.exact", record.ownership_marker);
    query.append_pair("match", "all");
    query.append_pair("per_page", "2");
    Ok(format!(
        "{API_ORIGIN}/zones/{zone_id}/dns_records?{}",
        query.finish()
    ))
}

fn success_root(response: &CloudflareHttpResponse) -> Result<Value, ContractError> {
    if response.status != 200 || response.body.len() > MAXIMUM_BODY_BYTES {
        return Err(ContractError::Unavailable);
    }
    let root = crate::strict_json::from_slice(&response.body)
        .map_err(|_| ContractError::InternalContract)?;
    if root.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(ContractError::Unauthorized);
    }
    Ok(root)
}

fn success_result(response: &CloudflareHttpResponse) -> Result<Value, ContractError> {
    success_root(response)?
        .get("result")
        .cloned()
        .ok_or(ContractError::InternalContract)
}

fn reject_additional_pages(root: &Value) -> Result<(), ContractError> {
    let total_pages = root
        .get("result_info")
        .and_then(|value| value.get("total_pages"))
        .and_then(Value::as_u64)
        .ok_or(ContractError::InternalContract)?;
    if total_pages > 1 {
        return Err(ContractError::Conflict);
    }
    Ok(())
}

fn validate_record(
    value: &Value,
    expected: &CloudflareTxtRecord<'_>,
) -> Result<String, ContractError> {
    let id = required_text(value, "id")?;
    validate_identifier(id)?;
    let content = std::str::from_utf8(expected.value).map_err(|_| ContractError::InvalidInput)?;
    if required_text(value, "type")? != "TXT"
        || required_text(value, "name")? != expected.name
        || required_text(value, "content")? != content
        || required_text(value, "comment")? != expected.ownership_marker
    {
        return Err(ContractError::InternalContract);
    }
    Ok(id.to_owned())
}

fn required_text<'a>(value: &'a Value, field: &str) -> Result<&'a str, ContractError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ContractError::InternalContract)
}

fn validate_identifier(value: &str) -> Result<(), ContractError> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ContractError::InternalContract);
    }
    Ok(())
}
