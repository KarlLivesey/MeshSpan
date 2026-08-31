// SPDX-License-Identifier: GPL-2.0-only

//! Bounded current-user API-key request and response validation.

use std::sync::OnceLock;

use serde_json::Value;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{BoundaryError, CreateApiKeyRequest, CreateApiKeyResponse, schema};

/// Maximum accepted body size for one API-key issuance request.
pub const MAX_CREATE_API_KEY_BYTES: usize = 2_048;

static REQUEST_VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RESPONSE_VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Validates and decodes one bounded API-key issuance request.
///
/// # Errors
///
/// Rejects excessive, malformed, schema-invalid or unexpectedly undecodable input.
pub fn decode_create_api_key_request(bytes: &[u8]) -> Result<CreateApiKeyRequest, BoundaryError> {
    if bytes.len() > MAX_CREATE_API_KEY_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_CREATE_API_KEY_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate_create_api_key_request_value(&value)?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

/// Validates raw API-key issuance input.
///
/// # Errors
///
/// Returns bounded structural issues or an invalid authoritative schema.
pub fn validate_create_api_key_request_value(value: &Value) -> Result<(), BoundaryError> {
    validate(request_validator()?, value)
}

/// Validates and encodes one secret-bearing issuance response.
///
/// # Errors
///
/// Returns an encoding or outgoing-contract failure instead of emitting invalid secret material.
pub fn encode_create_api_key_response(
    response: &CreateApiKeyResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_create_api_key_response_value(&value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validates raw API-key issuance output.
///
/// # Errors
///
/// Returns bounded structural issues or an invalid authoritative schema.
pub fn validate_create_api_key_response_value(value: &Value) -> Result<(), BoundaryError> {
    validate(response_validator()?, value)
}

fn request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        REQUEST_VALIDATOR.get_or_init(|| compile(&schema::request_schema::<CreateApiKeyRequest>())),
    )
}

fn response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        RESPONSE_VALIDATOR
            .get_or_init(|| compile(&schema::response_schema::<CreateApiKeyResponse>())),
    )
}
