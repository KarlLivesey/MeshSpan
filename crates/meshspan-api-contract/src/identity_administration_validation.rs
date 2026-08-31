// SPDX-License-Identifier: GPL-2.0-only

//! Runtime structural validation for hostile identity-administration messages.

use std::sync::OnceLock;

use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, CreateGroupRequest, CreatePrincipalResponse, CreateUserRequest,
    ListPrincipalsQuery, ListPrincipalsResponse, schema,
};

/// Maximum accepted bytes for one identity-creation body.
pub const MAX_CREATE_PRINCIPAL_BYTES: usize = 2_048;

static CREATE_USER_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static CREATE_GROUP_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static CREATE_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static LIST_QUERY: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static LIST_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Decodes and structurally validates one hostile user-creation body.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, schema-invalid or ambiguous input.
pub fn decode_create_user_request(bytes: &[u8]) -> Result<CreateUserRequest, BoundaryError> {
    let request: CreateUserRequest = decode_request(
        bytes,
        request_validator::<CreateUserRequest>(&CREATE_USER_REQUEST)?,
    )?;
    request
        .display_name
        .is_domain_candidate()
        .then_some(request)
        .ok_or(BoundaryError::DecodeMismatch)
}

/// Decodes and structurally validates one hostile group-creation body.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, schema-invalid or ambiguous input.
pub fn decode_create_group_request(bytes: &[u8]) -> Result<CreateGroupRequest, BoundaryError> {
    let request: CreateGroupRequest = decode_request(
        bytes,
        request_validator::<CreateGroupRequest>(&CREATE_GROUP_REQUEST)?,
    )?;
    request
        .display_name
        .is_domain_candidate()
        .then_some(request)
        .ok_or(BoundaryError::DecodeMismatch)
}

/// Validates and encodes one authoritative creation response.
///
/// # Errors
///
/// Refuses to emit a response outside the Rust-authored contract.
pub fn encode_create_principal_response(
    response: &CreatePrincipalResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(
        response,
        response_validator::<CreatePrincipalResponse>(&CREATE_RESPONSE)?,
    )
}

/// Validates one decoded identity-list query.
///
/// # Errors
///
/// Rejects structurally invalid bounds or continuation tokens.
pub fn validate_list_principals_query(query: &ListPrincipalsQuery) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(query).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_list_principals_query_value(&value)
}

/// Validates the raw JSON-equivalent identity-list query.
///
/// # Errors
///
/// Rejects structurally invalid fields and values.
pub fn validate_list_principals_query_value(value: &Value) -> Result<(), BoundaryError> {
    validate(
        request_validator::<ListPrincipalsQuery>(&LIST_QUERY)?,
        value,
    )
}

/// Validates and encodes one authoritative identity page.
///
/// # Errors
///
/// Refuses to emit a response outside the Rust-authored contract.
pub fn encode_list_principals_response(
    response: &ListPrincipalsResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(
        response,
        response_validator::<ListPrincipalsResponse>(&LIST_RESPONSE)?,
    )
}

fn decode_request<T: DeserializeOwned>(
    bytes: &[u8],
    validator: &CompiledValidator,
) -> Result<T, BoundaryError> {
    if bytes.is_empty() || bytes.len() > MAX_CREATE_PRINCIPAL_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_CREATE_PRINCIPAL_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(validator, &value)?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

fn encode_response<T: Serialize>(
    response: &T,
    validator: &CompiledValidator,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(validator, &value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn request_validator<T: JsonSchema>(
    cell: &'static OnceLock<Result<CompiledValidator, String>>,
) -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(cell.get_or_init(|| compile(&schema::request_schema::<T>())))
}

fn response_validator<T: JsonSchema>(
    cell: &'static OnceLock<Result<CompiledValidator, String>>,
) -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(cell.get_or_init(|| compile(&schema::response_schema::<T>())))
}
