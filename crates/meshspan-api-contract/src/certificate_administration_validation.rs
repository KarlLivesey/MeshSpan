// SPDX-License-Identifier: GPL-2.0-only

//! Runtime structural validation for hostile certificate-administration messages.

use std::sync::OnceLock;

use schemars::JsonSchema;
use serde_json::Value;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{BoundaryError, ProvisionCertificateRequest, ProvisionCertificateResponse, schema};

static REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Maximum accepted bytes for certificate provisioning, including protected provider settings.
pub const MAX_PROVISION_CERTIFICATE_BYTES: usize = 64 * 1_024;

/// Decodes and structurally validates one hostile certificate-provisioning body.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, schema-invalid or ambiguous input.
pub fn decode_provision_certificate_request(
    bytes: &[u8],
) -> Result<ProvisionCertificateRequest, BoundaryError> {
    if bytes.is_empty() || bytes.len() > MAX_PROVISION_CERTIFICATE_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_PROVISION_CERTIFICATE_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate_request_value(&value)?;
    let request: ProvisionCertificateRequest =
        serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)?;
    request
        .certificate_names
        .iter()
        .all(|name| valid_dns_name(name))
        .then_some(())
        .filter(|()| {
            request
                .certificate_names
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        })
        .map(|()| request)
        .ok_or(BoundaryError::DecodeMismatch)
}

/// Validates the raw JSON-equivalent request.
///
/// # Errors
///
/// Rejects unknown fields, invalid variants and values outside strict bounds.
pub fn validate_provision_certificate_request_value(value: &Value) -> Result<(), BoundaryError> {
    validate_request_value(value)
}

/// Validates and encodes one authoritative provisioning result.
///
/// # Errors
///
/// Refuses to emit a response outside the Rust-authored contract.
pub fn encode_provision_certificate_response(
    response: &ProvisionCertificateResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        response_validator::<ProvisionCertificateResponse>()?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn validate_request_value(value: &Value) -> Result<(), BoundaryError> {
    validate(request_validator::<ProvisionCertificateRequest>()?, value)
}

fn request_validator<T: JsonSchema>() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(REQUEST.get_or_init(|| compile(&schema::request_schema::<T>())))
}

fn response_validator<T: JsonSchema>() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(RESPONSE.get_or_init(|| compile(&schema::response_schema::<T>())))
}

fn valid_dns_name(value: &str) -> bool {
    let name = value.strip_prefix("*.").unwrap_or(value);
    !name.is_empty()
        && value.len() <= 253
        && name.is_ascii()
        && name.contains('.')
        && name.split('.').all(valid_dns_label)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'*')
        })
}

fn valid_dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
