// SPDX-License-Identifier: GPL-2.0-only

//! Bounded recovery-bundle save-verification request and response validation.

use serde_json::Value;

use crate::schema::{request_schema, response_schema};
use crate::validation::{CompiledValidator, compile, validator_from};
use crate::{BoundaryError, ConfirmRecoveryBundleRequest, ConfirmRecoveryBundleResponse};

/// Maximum accepted save-verification request body.
pub const MAX_CONFIRM_RECOVERY_BUNDLE_BYTES: usize = 512;

/// Validates and decodes one save-verification request without coercion.
///
/// # Errors
///
/// Rejects oversized, malformed, schema-invalid or unexpectedly undecodable input.
pub fn decode_confirm_recovery_bundle_request(
    bytes: &[u8],
) -> Result<ConfirmRecoveryBundleRequest, BoundaryError> {
    if bytes.len() > MAX_CONFIRM_RECOVERY_BUNDLE_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_CONFIRM_RECOVERY_BUNDLE_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate_confirm_recovery_bundle_request_value(&value)?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

/// Validates raw save-verification input against the Rust-authored schema.
///
/// # Errors
///
/// Returns bounded structural issues or an invalid authoritative schema.
pub fn validate_confirm_recovery_bundle_request_value(value: &Value) -> Result<(), BoundaryError> {
    crate::validation::validate(confirm_request_validator()?, value)
}

/// Validates and encodes one committed save-verification response.
///
/// # Errors
///
/// Suppresses a response which disagrees with the Rust-authored contract.
pub fn encode_confirm_recovery_bundle_response(
    response: &ConfirmRecoveryBundleResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    crate::validation::validate(confirm_response_validator()?, &value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn confirm_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    static VALIDATOR: std::sync::OnceLock<Result<CompiledValidator, String>> =
        std::sync::OnceLock::new();
    validator_from(
        VALIDATOR.get_or_init(|| compile(&request_schema::<ConfirmRecoveryBundleRequest>())),
    )
}

fn confirm_response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    static VALIDATOR: std::sync::OnceLock<Result<CompiledValidator, String>> =
        std::sync::OnceLock::new();
    validator_from(
        VALIDATOR.get_or_init(|| compile(&response_schema::<ConfirmRecoveryBundleResponse>())),
    )
}
