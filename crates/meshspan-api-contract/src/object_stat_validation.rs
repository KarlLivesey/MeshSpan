// SPDX-License-Identifier: GPL-2.0-only

//! Runtime validation for native object metadata queries.

use std::sync::OnceLock;

use serde_json::Value;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{BoundaryError, DirectoryEntryKind, GetObjectQuery, GetObjectResponse, schema};

static QUERY_VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RESPONSE_VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Validates one decoded object query before authentication-authorised filesystem work.
///
/// # Errors
///
/// Rejects structurally invalid or non-canonical relative paths.
pub fn validate_get_object_query(query: &GetObjectQuery) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(query).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_get_object_query_value(&value)?;
    if !query.path.is_canonical() {
        return Err(BoundaryError::DecodeMismatch);
    }
    Ok(())
}

/// Validates the raw JSON-equivalent object query.
///
/// # Errors
///
/// Returns bounded structural issues or an invalid authoritative schema.
pub fn validate_get_object_query_value(value: &Value) -> Result<(), BoundaryError> {
    validate(query_validator()?, value)
}

/// Validates and encodes one complete object metadata response.
///
/// # Errors
///
/// Refuses schema-invalid or internally inconsistent file/directory metadata.
pub fn encode_get_object_response(response: &GetObjectResponse) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_get_object_response_value(&value)?;
    let file_metadata =
        response.object.file_version_id.is_some() && response.object.logical_length.is_some();
    let consistent = match response.object.kind {
        DirectoryEntryKind::Directory => {
            response.object.file_version_id.is_none() && response.object.logical_length.is_none()
        }
        DirectoryEntryKind::File => file_metadata,
    };
    if !consistent {
        return Err(BoundaryError::EncodeMismatch);
    }
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validates the raw outgoing object metadata response.
///
/// # Errors
///
/// Returns bounded structural issues or an invalid authoritative schema.
pub fn validate_get_object_response_value(value: &Value) -> Result<(), BoundaryError> {
    validate(response_validator()?, value)
}

fn query_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        QUERY_VALIDATOR.get_or_init(|| compile(&schema::request_schema::<GetObjectQuery>())),
    )
}

fn response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        RESPONSE_VALIDATOR.get_or_init(|| compile(&schema::response_schema::<GetObjectResponse>())),
    )
}
