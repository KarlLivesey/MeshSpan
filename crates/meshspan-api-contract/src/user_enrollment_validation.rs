// SPDX-License-Identifier: GPL-2.0-only

//! Independent bounded request and receipt validation for invitation authority.

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, IssueUserEnrollmentRequest, IssueUserEnrollmentResponse,
    RedeemUserEnrollmentApiKeyRequest, RevokeUserEnrollmentRequest, RevokeUserEnrollmentResponse,
    schema,
};
use schemars::JsonSchema;
use serde::{Serialize, de::DeserializeOwned};
use std::sync::OnceLock;

/// Maximum encoded invitation mutation or recipient enrollment request.
pub const MAX_USER_ENROLLMENT_REQUEST_BYTES: usize = 2_048;
static ISSUE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static REVOKE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static REDEEM: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static ISSUED: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static REVOKED: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Decodes manager consent without coercion, excess fields or unbounded allocation.
///
/// # Errors
/// Rejects malformed, oversized or structurally invalid input.
pub fn decode_issue_user_enrollment_request(
    bytes: &[u8],
) -> Result<IssueUserEnrollmentRequest, BoundaryError> {
    decode(bytes, &ISSUE)
}
/// Decodes an exact invitation cancellation request.
///
/// # Errors
/// Rejects malformed, oversized or structurally invalid input.
pub fn decode_revoke_user_enrollment_request(
    bytes: &[u8],
) -> Result<RevokeUserEnrollmentRequest, BoundaryError> {
    decode(bytes, &REVOKE)
}
/// Decodes the recipient's secret-bearing ordinary API-key enrollment request.
///
/// # Errors
/// Rejects malformed, oversized, duplicate-scope or structurally invalid input.
pub fn decode_redeem_user_enrollment_api_key_request(
    bytes: &[u8],
) -> Result<RedeemUserEnrollmentApiKeyRequest, BoundaryError> {
    let request: RedeemUserEnrollmentApiKeyRequest = decode(bytes, &REDEEM)?;
    if request.scopes.len() == 2 && request.scopes.first() == request.scopes.get(1) {
        return Err(BoundaryError::DecodeMismatch);
    }
    Ok(request)
}
/// Validates the secret-bearing invitation receipt before transmission.
///
/// # Errors
/// Rejects malformed outgoing authority evidence without exposing the token.
pub fn encode_issue_user_enrollment_response(
    response: &IssueUserEnrollmentResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode(response, &ISSUED)
}
/// Validates the committed cancellation receipt before transmission.
///
/// # Errors
/// Rejects malformed outgoing authority evidence.
pub fn encode_revoke_user_enrollment_response(
    response: &RevokeUserEnrollmentResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode(response, &REVOKED)
}

fn decode<T: JsonSchema + DeserializeOwned>(
    bytes: &[u8],
    validator: &'static OnceLock<Result<CompiledValidator, String>>,
) -> Result<T, BoundaryError> {
    if bytes.len() > MAX_USER_ENROLLMENT_REQUEST_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_USER_ENROLLMENT_REQUEST_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(
        validator_from(validator.get_or_init(|| compile(&schema::request_schema::<T>())))?,
        &value,
    )?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}
fn encode<T: JsonSchema + Serialize>(
    response: &T,
    validator: &'static OnceLock<Result<CompiledValidator, String>>,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(validator.get_or_init(|| compile(&schema::response_schema::<T>())))?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}
