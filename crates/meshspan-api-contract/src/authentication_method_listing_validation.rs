// SPDX-License-Identifier: GPL-2.0-only

//! Runtime structural validation for hostile authentication-method inventory messages.

use std::sync::OnceLock;

use schemars::JsonSchema;
use serde_json::Value;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, ListAuthenticationMethodsQuery, ListAuthenticationMethodsResponse, schema,
};

static LIST_QUERY: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static LIST_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Validates one decoded authentication-method list query.
///
/// # Errors
///
/// Rejects structurally invalid bounds or continuation tokens.
pub fn validate_list_authentication_methods_query(
    query: &ListAuthenticationMethodsQuery,
) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(query).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_list_authentication_methods_query_value(&value)
}

/// Validates the raw JSON-equivalent authentication-method list query.
///
/// # Errors
///
/// Rejects structurally invalid fields and values.
pub fn validate_list_authentication_methods_query_value(
    value: &Value,
) -> Result<(), BoundaryError> {
    validate(
        request_validator::<ListAuthenticationMethodsQuery>(&LIST_QUERY)?,
        value,
    )
}

/// Validates and encodes one authoritative authentication-method page.
///
/// # Errors
///
/// Refuses to emit a response outside the Rust-authored contract.
pub fn encode_list_authentication_methods_response(
    response: &ListAuthenticationMethodsResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        response_validator::<ListAuthenticationMethodsResponse>(&LIST_RESPONSE)?,
        &value,
    )?;
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
