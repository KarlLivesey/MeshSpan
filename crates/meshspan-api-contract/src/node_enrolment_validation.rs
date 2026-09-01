// SPDX-License-Identifier: GPL-2.0-only

//! Bounded join-grant and node-enrolment request/response validation.

use std::sync::OnceLock;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, CreateNodeJoinGrantRequest, CreateNodeJoinGrantResponse, EnrolNodeRequest,
    EnrolNodeResponse, schema,
};

/// Maximum accepted administrator join-grant body.
pub const MAX_CREATE_NODE_JOIN_GRANT_BYTES: usize = 2_048;
/// Maximum accepted anonymous node-enrolment body.
pub const MAX_ENROL_NODE_BYTES: usize = 8_192;

static ISSUE_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static ISSUE_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static ENROL_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static ENROL_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Decodes one structurally valid bounded join-grant request.
///
/// # Errors
///
/// Rejects oversized, malformed or schema-invalid input.
pub fn decode_create_node_join_grant_request(
    bytes: &[u8],
) -> Result<CreateNodeJoinGrantRequest, BoundaryError> {
    decode(bytes, MAX_CREATE_NODE_JOIN_GRANT_BYTES, issue_request()?)
}

/// Encodes one contract-valid secret-bearing join-grant result.
///
/// # Errors
///
/// Rejects a response that cannot be encoded or violates its published schema.
pub fn encode_create_node_join_grant_response(
    response: &CreateNodeJoinGrantResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode(response, issue_response()?)
}

/// Decodes one structurally valid bounded anonymous node-enrolment request.
///
/// # Errors
///
/// Rejects oversized, malformed or schema-invalid input.
pub fn decode_enrol_node_request(bytes: &[u8]) -> Result<EnrolNodeRequest, BoundaryError> {
    decode(bytes, MAX_ENROL_NODE_BYTES, enrol_request()?)
}

/// Encodes one contract-valid anonymous node-enrolment request.
///
/// # Errors
///
/// Rejects a request that cannot be encoded or violates its published schema.
pub fn encode_enrol_node_request(request: &EnrolNodeRequest) -> Result<Vec<u8>, BoundaryError> {
    encode(request, enrol_request()?)
}

/// Encodes one contract-valid node certificate and bootstrap result.
///
/// # Errors
///
/// Rejects a response that cannot be encoded or violates its published schema.
pub fn encode_enrol_node_response(response: &EnrolNodeResponse) -> Result<Vec<u8>, BoundaryError> {
    encode(response, enrol_response()?)
}

/// Decodes one structurally valid bounded node-enrolment response.
///
/// # Errors
///
/// Rejects oversized, malformed or schema-invalid input.
pub fn decode_enrol_node_response(bytes: &[u8]) -> Result<EnrolNodeResponse, BoundaryError> {
    decode(bytes, MAX_ENROL_NODE_BYTES, enrol_response()?)
}

fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    limit: usize,
    validator: &CompiledValidator,
) -> Result<T, BoundaryError> {
    if bytes.len() > limit {
        return Err(BoundaryError::BodyTooLarge { limit });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(validator, &value)?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

fn encode<T: serde::Serialize>(
    response: &T,
    validator: &CompiledValidator,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(validator, &value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn issue_request() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        ISSUE_REQUEST
            .get_or_init(|| compile(&schema::request_schema::<CreateNodeJoinGrantRequest>())),
    )
}

fn issue_response() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        ISSUE_RESPONSE
            .get_or_init(|| compile(&schema::response_schema::<CreateNodeJoinGrantResponse>())),
    )
}

fn enrol_request() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        ENROL_REQUEST.get_or_init(|| compile(&schema::request_schema::<EnrolNodeRequest>())),
    )
}

fn enrol_response() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        ENROL_RESPONSE.get_or_init(|| compile(&schema::response_schema::<EnrolNodeResponse>())),
    )
}
