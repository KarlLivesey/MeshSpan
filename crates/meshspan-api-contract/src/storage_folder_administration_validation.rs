// SPDX-License-Identifier: GPL-2.0-only

//! Runtime structural validation for hostile storage-folder administration messages.

use std::sync::OnceLock;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, ListStorageFoldersQuery, ListStorageFoldersResponse,
    RegisterStorageFolderRequest, RegisterStorageFolderResponse, schema,
};

/// Maximum accepted bytes for one local folder registration.
pub const MAX_REGISTER_STORAGE_FOLDER_BYTES: usize = 32 * 1_024;

static REGISTER_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static REGISTER_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static LIST_QUERY: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static LIST_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Decodes one bounded local folder-registration request without coercion.
///
/// # Errors
///
/// Rejects empty, oversized, malformed or structurally invalid input.
pub fn decode_register_storage_folder_request(
    bytes: &[u8],
) -> Result<RegisterStorageFolderRequest, BoundaryError> {
    if bytes.is_empty() || bytes.len() > MAX_REGISTER_STORAGE_FOLDER_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_REGISTER_STORAGE_FOLDER_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(request_validator()?, &value)?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

/// Validates and encodes one local folder-registration response.
///
/// # Errors
///
/// Suppresses an invalid outgoing response.
pub fn encode_register_storage_folder_response(
    response: &RegisterStorageFolderResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(response, response_validator()?)
}

/// Validates one decoded storage-folder list query.
///
/// # Errors
///
/// Rejects structurally invalid bounds or cursors.
pub fn validate_list_storage_folders_query(
    query: &ListStorageFoldersQuery,
) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(query).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(list_query_validator()?, &value)
}

/// Validates and encodes one local storage-folder page.
///
/// # Errors
///
/// Suppresses invalid or non-monotonically ordered output.
pub fn encode_list_storage_folders_response(
    response: &ListStorageFoldersResponse,
) -> Result<Vec<u8>, BoundaryError> {
    if response
        .folders
        .windows(2)
        .any(|pair| pair[0].target_id >= pair[1].target_id)
    {
        return Err(BoundaryError::EncodeMismatch);
    }
    encode_response(response, list_response_validator()?)
}

fn encode_response<T: serde::Serialize>(
    response: &T,
    validator: &CompiledValidator,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(validator, &value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        REGISTER_REQUEST
            .get_or_init(|| compile(&schema::request_schema::<RegisterStorageFolderRequest>())),
    )
}

fn response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        REGISTER_RESPONSE
            .get_or_init(|| compile(&schema::response_schema::<RegisterStorageFolderResponse>())),
    )
}

fn list_query_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        LIST_QUERY.get_or_init(|| compile(&schema::request_schema::<ListStorageFoldersQuery>())),
    )
}

fn list_response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        LIST_RESPONSE
            .get_or_init(|| compile(&schema::response_schema::<ListStorageFoldersResponse>())),
    )
}
