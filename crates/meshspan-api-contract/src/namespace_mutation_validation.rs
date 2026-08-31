// SPDX-License-Identifier: GPL-2.0-only

//! Runtime structural validation for hostile namespace-mutation messages.

use std::sync::OnceLock;

use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, CreateDirectoryRequest, CreateDirectoryResponse, DeleteObjectRequest,
    DeleteObjectResponse, RenameObjectRequest, RenameObjectResponse, schema,
};

/// Maximum accepted JSON bytes for one namespace mutation.
pub const MAX_NAMESPACE_MUTATION_BYTES: usize = 16 * 1_024;

static CREATE_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static CREATE_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RENAME_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RENAME_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static DELETE_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static DELETE_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Decodes and validates one hostile empty-directory creation body.
///
/// # Errors
///
/// Rejects oversized, malformed, schema-invalid or non-canonical input.
pub fn decode_create_directory_request(
    bytes: &[u8],
) -> Result<CreateDirectoryRequest, BoundaryError> {
    let request: CreateDirectoryRequest = decode_request(
        bytes,
        request_validator::<CreateDirectoryRequest>(&CREATE_REQUEST)?,
    )?;
    request
        .path
        .is_canonical()
        .then_some(request)
        .ok_or(BoundaryError::DecodeMismatch)
}

/// Validates and encodes one authoritative directory-creation receipt.
///
/// # Errors
///
/// Rejects an authoritative response which violates the public contract.
pub fn encode_create_directory_response(
    response: &CreateDirectoryResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(
        response,
        response_validator::<CreateDirectoryResponse>(&CREATE_RESPONSE)?,
    )
}

/// Decodes and validates one hostile same-volume rename body.
///
/// # Errors
///
/// Rejects oversized, malformed, schema-invalid, non-canonical or no-op input.
pub fn decode_rename_object_request(bytes: &[u8]) -> Result<RenameObjectRequest, BoundaryError> {
    let request: RenameObjectRequest = decode_request(
        bytes,
        request_validator::<RenameObjectRequest>(&RENAME_REQUEST)?,
    )?;
    (request.source_path.is_canonical()
        && request.target_path.is_canonical()
        && request.source_path != request.target_path)
        .then_some(request)
        .ok_or(BoundaryError::DecodeMismatch)
}

/// Validates and encodes one authoritative rename receipt.
///
/// # Errors
///
/// Rejects an authoritative response which violates the public contract.
pub fn encode_rename_object_response(
    response: &RenameObjectResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(
        response,
        response_validator::<RenameObjectResponse>(&RENAME_RESPONSE)?,
    )
}

/// Decodes and validates one hostile logical-delete body.
///
/// # Errors
///
/// Rejects oversized, malformed, schema-invalid or non-canonical input.
pub fn decode_delete_object_request(bytes: &[u8]) -> Result<DeleteObjectRequest, BoundaryError> {
    let request: DeleteObjectRequest = decode_request(
        bytes,
        request_validator::<DeleteObjectRequest>(&DELETE_REQUEST)?,
    )?;
    request
        .path
        .is_canonical()
        .then_some(request)
        .ok_or(BoundaryError::DecodeMismatch)
}

/// Validates and encodes one authoritative logical-delete receipt.
///
/// # Errors
///
/// Rejects an authoritative response which violates the public contract.
pub fn encode_delete_object_response(
    response: &DeleteObjectResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(
        response,
        response_validator::<DeleteObjectResponse>(&DELETE_RESPONSE)?,
    )
}

fn decode_request<T: DeserializeOwned>(
    bytes: &[u8],
    validator: &CompiledValidator,
) -> Result<T, BoundaryError> {
    if bytes.is_empty() || bytes.len() > MAX_NAMESPACE_MUTATION_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_NAMESPACE_MUTATION_BYTES,
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
