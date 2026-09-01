// SPDX-License-Identifier: GPL-2.0-only

//! Runtime structural validation for hostile volume-inventory messages.

use std::sync::OnceLock;

use schemars::JsonSchema;
use serde_json::Value;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, CreateVolumeRequest, CreateVolumeResponse, ListVolumesQuery,
    ListVolumesResponse, NamespaceRight, schema,
};

static LIST_QUERY: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static LIST_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static CREATE_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static CREATE_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Maximum accepted bytes for one volume-creation request.
pub const MAX_CREATE_VOLUME_BYTES: usize = 64 * 1_024;

/// Decodes and structurally validates one hostile volume-creation body.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, schema-invalid or ambiguous input.
pub fn decode_create_volume_request(bytes: &[u8]) -> Result<CreateVolumeRequest, BoundaryError> {
    if bytes.is_empty() || bytes.len() > MAX_CREATE_VOLUME_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_CREATE_VOLUME_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(
        request_validator::<CreateVolumeRequest>(&CREATE_REQUEST)?,
        &value,
    )?;
    let request: CreateVolumeRequest =
        serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)?;
    request
        .name
        .is_domain_candidate()
        .then_some(request)
        .ok_or(BoundaryError::DecodeMismatch)
}

/// Validates and encodes one authoritative volume-creation response.
///
/// # Errors
///
/// Refuses to emit a response outside the Rust-authored contract.
pub fn encode_create_volume_response(
    response: &CreateVolumeResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        response_validator::<CreateVolumeResponse>(&CREATE_RESPONSE)?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validates one decoded volume list query.
///
/// # Errors
///
/// Rejects structurally invalid bounds or continuation tokens.
pub fn validate_list_volumes_query(query: &ListVolumesQuery) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(query).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_list_volumes_query_value(&value)
}

/// Validates the raw JSON-equivalent volume list query.
///
/// # Errors
///
/// Rejects structurally invalid fields and values.
pub fn validate_list_volumes_query_value(value: &Value) -> Result<(), BoundaryError> {
    validate(request_validator::<ListVolumesQuery>(&LIST_QUERY)?, value)
}

/// Validates and encodes one authoritative permission-filtered volume page.
///
/// # Errors
///
/// Refuses schema-invalid, unordered or duplicate rights projections.
pub fn encode_list_volumes_response(
    response: &ListVolumesResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        response_validator::<ListVolumesResponse>(&LIST_RESPONSE)?,
        &value,
    )?;
    if response.volumes.iter().any(|volume| {
        !has_browse_rights(&volume.effective_rights)
            || !volume
                .effective_rights
                .windows(2)
                .all(|rights| rights[0] < rights[1])
    }) {
        return Err(BoundaryError::EncodeMismatch);
    }
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

fn has_browse_rights(rights: &[NamespaceRight]) -> bool {
    rights.binary_search(&NamespaceRight::Traverse).is_ok()
        && rights.binary_search(&NamespaceRight::List).is_ok()
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
