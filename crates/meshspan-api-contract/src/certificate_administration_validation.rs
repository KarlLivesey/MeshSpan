// SPDX-License-Identifier: GPL-2.0-only

//! Runtime structural validation for hostile certificate-administration messages.

use std::sync::OnceLock;

use schemars::JsonSchema;
use serde_json::Value;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, ProvisionCertificateRequest, ProvisionCertificateResponse,
    PublishExternalCertificateRequest, PublishExternalCertificateResponse, schema,
};

static REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static EXTERNAL_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static EXTERNAL_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Maximum accepted bytes for certificate provisioning, including protected provider settings.
pub const MAX_PROVISION_CERTIFICATE_BYTES: usize = 64 * 1_024;
/// Maximum automated external publication body, including one protected private key.
pub const MAX_PUBLISH_EXTERNAL_CERTIFICATE_BYTES: usize = 128 * 1_024;

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

/// Decodes and structurally validates one hostile automated certificate publication.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, schema-invalid or non-canonical input before crypto.
pub fn decode_publish_external_certificate_request(
    bytes: &[u8],
) -> Result<PublishExternalCertificateRequest, BoundaryError> {
    if bytes.is_empty() || bytes.len() > MAX_PUBLISH_EXTERNAL_CERTIFICATE_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_PUBLISH_EXTERNAL_CERTIFICATE_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(external_request_validator()?, &value)?;
    let request: PublishExternalCertificateRequest =
        serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)?;
    if request.generation.value().is_none()
        || !valid_canonical_names(&request.certificate_names)
        || !looks_like_certificate_chain(request.certificate_chain_pem.as_bytes())
    {
        return Err(BoundaryError::DecodeMismatch);
    }
    Ok(request)
}

/// Validates and encodes one secret-free external publication result.
///
/// # Errors
///
/// Refuses to emit a response outside the Rust-authored contract.
pub fn encode_publish_external_certificate_response(
    response: &PublishExternalCertificateResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(external_response_validator()?, &value)?;
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

fn external_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        EXTERNAL_REQUEST.get_or_init(|| {
            compile(&schema::request_schema::<PublishExternalCertificateRequest>())
        }),
    )
}

fn external_response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        EXTERNAL_RESPONSE.get_or_init(|| {
            compile(&schema::response_schema::<PublishExternalCertificateResponse>())
        }),
    )
}

fn valid_canonical_names(names: &[String]) -> bool {
    names.iter().all(|name| valid_dns_name(name)) && names.windows(2).all(|pair| pair[0] < pair[1])
}

fn looks_like_certificate_chain(value: &[u8]) -> bool {
    value.starts_with(b"-----BEGIN CERTIFICATE-----")
        && value
            .windows(b"-----END CERTIFICATE-----".len())
            .any(|candidate| candidate == b"-----END CERTIFICATE-----")
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
