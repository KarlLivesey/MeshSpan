// SPDX-License-Identifier: GPL-2.0-only

//! Runtime structural validation for hostile permission-administration messages.

use std::sync::OnceLock;

use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, CreateVolumePermissionGrantRequest, CreateVolumePermissionGrantResponse,
    ListVolumePermissionGrantsQuery, ListVolumePermissionGrantsResponse, NamespaceRight,
    NullableField, RevokePermissionGrantRequest, RevokePermissionGrantResponse, schema,
};

/// Maximum accepted bytes for one permission mutation body.
pub const MAX_PERMISSION_GRANT_MUTATION_BYTES: usize = 8 * 1_024;

static CREATE_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static CREATE_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static REVOKE_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static REVOKE_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static LIST_QUERY: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static LIST_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Decodes and validates one hostile permission grant request.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, duplicated, unordered or incoherent input.
pub fn decode_create_volume_permission_grant_request(
    bytes: &[u8],
) -> Result<CreateVolumePermissionGrantRequest, BoundaryError> {
    let request: CreateVolumePermissionGrantRequest = decode_request(
        bytes,
        request_validator::<CreateVolumePermissionGrantRequest>(&CREATE_REQUEST)?,
    )?;
    validate_rights(&request.rights)?;
    validate_window(&request)?;
    Ok(request)
}

/// Decodes and validates one hostile grant-revocation request.
///
/// # Errors
///
/// Rejects empty, oversized, malformed or blank-reason input.
pub fn decode_revoke_permission_grant_request(
    bytes: &[u8],
) -> Result<RevokePermissionGrantRequest, BoundaryError> {
    let request: RevokePermissionGrantRequest = decode_request(
        bytes,
        request_validator::<RevokePermissionGrantRequest>(&REVOKE_REQUEST)?,
    )?;
    request
        .reason
        .is_domain_candidate()
        .then_some(request)
        .ok_or(BoundaryError::DecodeMismatch)
}

/// Validates one decoded volume-grant query.
///
/// # Errors
///
/// Rejects invalid bounds or continuation tokens.
pub fn validate_list_volume_permission_grants_query(
    query: &ListVolumePermissionGrantsQuery,
) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(query).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        request_validator::<ListVolumePermissionGrantsQuery>(&LIST_QUERY)?,
        &value,
    )
}

/// Validates and encodes one authoritative grant page.
///
/// # Errors
///
/// Refuses output outside the Rust-authored contract or with invalid rights ordering.
pub fn encode_list_volume_permission_grants_response(
    response: &ListVolumePermissionGrantsResponse,
) -> Result<Vec<u8>, BoundaryError> {
    for grant in &response.grants {
        validate_rights(&grant.rights)?;
    }
    encode_response(
        response,
        response_validator::<ListVolumePermissionGrantsResponse>(&LIST_RESPONSE)?,
    )
}

/// Validates and encodes one authoritative grant-creation result.
///
/// # Errors
///
/// Refuses output outside the Rust-authored contract.
pub fn encode_create_volume_permission_grant_response(
    response: &CreateVolumePermissionGrantResponse,
) -> Result<Vec<u8>, BoundaryError> {
    validate_rights(&response.grant.rights)?;
    encode_response(
        response,
        response_validator::<CreateVolumePermissionGrantResponse>(&CREATE_RESPONSE)?,
    )
}

/// Validates and encodes one authoritative grant-revocation result.
///
/// # Errors
///
/// Refuses output outside the Rust-authored contract.
pub fn encode_revoke_permission_grant_response(
    response: &RevokePermissionGrantResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(
        response,
        response_validator::<RevokePermissionGrantResponse>(&REVOKE_RESPONSE)?,
    )
}

fn validate_rights(rights: &[NamespaceRight]) -> Result<(), BoundaryError> {
    if rights.is_empty() || !rights.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(BoundaryError::DecodeMismatch);
    }
    Ok(())
}

fn validate_window(request: &CreateVolumePermissionGrantRequest) -> Result<(), BoundaryError> {
    let from = instant_value(&request.valid_from_epoch_micros);
    let until = instant_value(&request.valid_until_epoch_micros);
    match (from, until) {
        (Some(from), Some(until)) if until <= from => Err(BoundaryError::DecodeMismatch),
        _ => Ok(()),
    }
}

const fn instant_value(value: &NullableField<crate::PermissionGrantInstant>) -> Option<i64> {
    match value {
        NullableField::Value(instant) => Some(instant.epoch_micros()),
        NullableField::Missing | NullableField::Null => None,
    }
}

fn decode_request<T: DeserializeOwned>(
    bytes: &[u8],
    validator: &CompiledValidator,
) -> Result<T, BoundaryError> {
    if bytes.is_empty() || bytes.len() > MAX_PERMISSION_GRANT_MUTATION_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_PERMISSION_GRANT_MUTATION_BYTES,
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
