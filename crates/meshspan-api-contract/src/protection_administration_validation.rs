// SPDX-License-Identifier: GPL-2.0-only

//! Runtime structural validation for hostile protection-policy messages.

use std::sync::OnceLock;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    AssignVolumeProtectionPolicyRequest, AssignVolumeProtectionPolicyResponse, BoundaryError,
    CreateProtectionPolicyRequest, CreateProtectionPolicyResponse, ListProtectionPoliciesResponse,
    schema,
};

/// Maximum accepted bytes for one protection-policy mutation.
pub const MAX_PROTECTION_POLICY_MUTATION_BYTES: usize = 64 * 1_024;

static CREATE_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static ASSIGN_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Decodes one bounded immutable-policy creation request without coercion.
///
/// # Errors
///
/// Returns a boundary error for empty, oversized, malformed or schema-invalid input.
pub fn decode_create_protection_policy_request(
    bytes: &[u8],
) -> Result<CreateProtectionPolicyRequest, BoundaryError> {
    decode_request(bytes, create_request_validator()?)
}

/// Decodes one bounded volume-policy assignment request without coercion.
///
/// # Errors
///
/// Returns a boundary error for empty, oversized, malformed or schema-invalid input.
pub fn decode_assign_volume_protection_policy_request(
    bytes: &[u8],
) -> Result<AssignVolumeProtectionPolicyRequest, BoundaryError> {
    decode_request(bytes, assign_request_validator()?)
}

/// Validates and encodes one policy page.
///
/// # Errors
///
/// Returns a boundary error rather than emitting a response outside the generated contract.
pub fn encode_list_protection_policies_response(
    response: &ListProtectionPoliciesResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

/// Validates and encodes one created policy.
///
/// # Errors
///
/// Returns a boundary error rather than emitting a response outside the generated contract.
pub fn encode_create_protection_policy_response(
    response: &CreateProtectionPolicyResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

/// Validates and encodes one volume-policy assignment.
///
/// # Errors
///
/// Returns a boundary error rather than emitting a response outside the generated contract.
pub fn encode_assign_volume_protection_policy_response(
    response: &AssignVolumeProtectionPolicyResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

fn decode_request<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    validator: &CompiledValidator,
) -> Result<T, BoundaryError> {
    if bytes.is_empty() || bytes.len() > MAX_PROTECTION_POLICY_MUTATION_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_PROTECTION_POLICY_MUTATION_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(validator, &value)?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

fn encode_response<T: serde::Serialize + schemars::JsonSchema>(
    response: &T,
) -> Result<Vec<u8>, BoundaryError> {
    let validator =
        compile(&schema::response_schema::<T>()).map_err(BoundaryError::InvalidSchema)?;
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(&validator, &value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn create_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        CREATE_REQUEST
            .get_or_init(|| compile(&schema::request_schema::<CreateProtectionPolicyRequest>())),
    )
}

fn assign_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        ASSIGN_REQUEST.get_or_init(|| {
            compile(&schema::request_schema::<AssignVolumeProtectionPolicyRequest>())
        }),
    )
}
