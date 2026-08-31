// SPDX-License-Identifier: GPL-2.0-only

//! Runtime validation for authenticated directory listings.

use std::sync::OnceLock;

use serde_json::Value;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{BoundaryError, DirectoryEntryKind, ListDirectoryQuery, ListDirectoryResponse, schema};

static QUERY_VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RESPONSE_VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Validates one decoded query before authentication-authorised filesystem work.
///
/// # Errors
///
/// Rejects structurally invalid fields or non-canonical relative path components.
pub fn validate_list_directory_query(query: &ListDirectoryQuery) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(query).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_list_directory_query_value(&value)?;
    if query.path.as_ref().is_some_and(|path| !path.is_canonical()) {
        return Err(BoundaryError::DecodeMismatch);
    }
    Ok(())
}

/// Validates the raw JSON-equivalent form of one directory query.
///
/// # Errors
///
/// Returns bounded structural issues or an invalid authoritative schema.
pub fn validate_list_directory_query_value(value: &Value) -> Result<(), BoundaryError> {
    validate(query_validator()?, value)
}

/// Validates and encodes one complete directory page.
///
/// # Errors
///
/// Refuses to emit schema-invalid or internally inconsistent object metadata.
pub fn encode_list_directory_response(
    response: &ListDirectoryResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_list_directory_response_value(&value)?;
    for entry in &response.entries {
        let file_metadata = entry.file_version_id.is_some() && entry.logical_length.is_some();
        let valid = match entry.kind {
            DirectoryEntryKind::Directory => {
                entry.file_version_id.is_none() && entry.logical_length.is_none()
            }
            DirectoryEntryKind::File => file_metadata,
        };
        if !valid {
            return Err(BoundaryError::EncodeMismatch);
        }
    }
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validates the raw JSON form of one outgoing directory page.
///
/// # Errors
///
/// Returns bounded structural issues or an invalid authoritative schema.
pub fn validate_list_directory_response_value(value: &Value) -> Result<(), BoundaryError> {
    validate(response_validator()?, value)
}

fn query_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        QUERY_VALIDATOR.get_or_init(|| compile(&schema::request_schema::<ListDirectoryQuery>())),
    )
}

fn response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        RESPONSE_VALIDATOR
            .get_or_init(|| compile(&schema::response_schema::<ListDirectoryResponse>())),
    )
}
