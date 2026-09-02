// SPDX-License-Identifier: GPL-2.0-only

//! Runtime structural validation for hostile placement-policy messages.

use std::sync::OnceLock;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    AssignVolumePlacementPolicyRequest, AssignVolumePlacementPolicyResponse, BoundaryError,
    CreateAcknowledgementPolicyRequest, CreateAcknowledgementPolicyResponse,
    CreateLocalityPolicyRequest, CreateLocalityPolicyResponse, ListAcknowledgementPoliciesResponse,
    ListLocalityPoliciesResponse, schema,
};

/// Maximum accepted bytes for one locality or acknowledgement policy mutation.
pub const MAX_PLACEMENT_POLICY_MUTATION_BYTES: usize = 128 * 1_024;

static CREATE_LOCALITY: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static CREATE_ACKNOWLEDGEMENT: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static ASSIGN: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Decodes one bounded locality-policy creation request without coercion.
///
/// # Errors
///
/// Rejects empty, oversized, malformed or schema-invalid input.
pub fn decode_create_locality_policy_request(
    bytes: &[u8],
) -> Result<CreateLocalityPolicyRequest, BoundaryError> {
    decode_request(
        bytes,
        validator_from(
            CREATE_LOCALITY
                .get_or_init(|| compile(&schema::request_schema::<CreateLocalityPolicyRequest>())),
        )?,
    )
}

/// Decodes one bounded acknowledgement-policy creation request without coercion.
///
/// # Errors
///
/// Rejects empty, oversized, malformed or schema-invalid input.
pub fn decode_create_acknowledgement_policy_request(
    bytes: &[u8],
) -> Result<CreateAcknowledgementPolicyRequest, BoundaryError> {
    decode_request(
        bytes,
        validator_from(CREATE_ACKNOWLEDGEMENT.get_or_init(|| {
            compile(&schema::request_schema::<CreateAcknowledgementPolicyRequest>())
        }))?,
    )
}

/// Decodes one bounded volume-policy assignment request without coercion.
///
/// # Errors
///
/// Rejects empty, oversized, malformed or schema-invalid input.
pub fn decode_assign_volume_placement_policy_request(
    bytes: &[u8],
) -> Result<AssignVolumePlacementPolicyRequest, BoundaryError> {
    decode_request(
        bytes,
        validator_from(ASSIGN.get_or_init(|| {
            compile(&schema::request_schema::<AssignVolumePlacementPolicyRequest>())
        }))?,
    )
}

/// Validates and encodes one locality-policy page.
///
/// # Errors
///
/// Rejects a response which does not satisfy its generated public schema.
pub fn encode_list_locality_policies_response(
    response: &ListLocalityPoliciesResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

/// Validates and encodes one created locality policy.
///
/// # Errors
///
/// Rejects a response which does not satisfy its generated public schema.
pub fn encode_create_locality_policy_response(
    response: &CreateLocalityPolicyResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

/// Validates and encodes one acknowledgement-policy page.
///
/// # Errors
///
/// Rejects a response which does not satisfy its generated public schema.
pub fn encode_list_acknowledgement_policies_response(
    response: &ListAcknowledgementPoliciesResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

/// Validates and encodes one created acknowledgement policy.
///
/// # Errors
///
/// Rejects a response which does not satisfy its generated public schema.
pub fn encode_create_acknowledgement_policy_response(
    response: &CreateAcknowledgementPolicyResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

/// Validates and encodes one volume placement-policy assignment.
///
/// # Errors
///
/// Rejects a response which does not satisfy its generated public schema.
pub fn encode_assign_volume_placement_policy_response(
    response: &AssignVolumePlacementPolicyResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response)
}

fn decode_request<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    validator: &CompiledValidator,
) -> Result<T, BoundaryError> {
    if bytes.is_empty() || bytes.len() > MAX_PLACEMENT_POLICY_MUTATION_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_PLACEMENT_POLICY_MUTATION_BYTES,
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
