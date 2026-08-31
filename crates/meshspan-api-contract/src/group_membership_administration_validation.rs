// SPDX-License-Identifier: GPL-2.0-only

//! Runtime structural validation for hostile group-membership messages.

use std::sync::OnceLock;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    AddGroupMemberRequest, AddGroupMemberResponse, BoundaryError, ListGroupMembershipsQuery,
    ListGroupMembershipsResponse, NullableField, RemoveGroupMemberRequest,
    RemoveGroupMemberResponse, schema,
};
use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Maximum accepted bytes for one membership mutation body.
pub const MAX_GROUP_MEMBERSHIP_MUTATION_BYTES: usize = 4_096;

static ADD_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static ADD_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static REMOVE_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static REMOVE_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static LIST_QUERY: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static LIST_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Decodes and validates one hostile direct-membership addition.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, schema-invalid or incoherent input.
pub fn decode_add_group_member_request(
    bytes: &[u8],
) -> Result<AddGroupMemberRequest, BoundaryError> {
    let request = decode_request(
        bytes,
        request_validator::<AddGroupMemberRequest>(&ADD_REQUEST)?,
    )?;
    validate_window(&request)?;
    Ok(request)
}

/// Decodes and validates one hostile direct-membership removal.
///
/// # Errors
///
/// Rejects empty, oversized, malformed, schema-invalid or blank-reason input.
pub fn decode_remove_group_member_request(
    bytes: &[u8],
) -> Result<RemoveGroupMemberRequest, BoundaryError> {
    let request: RemoveGroupMemberRequest = decode_request(
        bytes,
        request_validator::<RemoveGroupMemberRequest>(&REMOVE_REQUEST)?,
    )?;
    request
        .reason
        .is_domain_candidate()
        .then_some(request)
        .ok_or(BoundaryError::DecodeMismatch)
}

/// Validates one decoded direct-membership list query.
///
/// # Errors
///
/// Rejects structurally invalid bounds or continuation tokens.
pub fn validate_list_group_memberships_query(
    query: &ListGroupMembershipsQuery,
) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(query).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        request_validator::<ListGroupMembershipsQuery>(&LIST_QUERY)?,
        &value,
    )
}

/// Validates and encodes one authoritative direct-membership page.
///
/// # Errors
///
/// Refuses to emit output outside the Rust-authored contract.
pub fn encode_list_group_memberships_response(
    response: &ListGroupMembershipsResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(
        response,
        response_validator::<ListGroupMembershipsResponse>(&LIST_RESPONSE)?,
    )
}

/// Validates and encodes one authoritative direct-membership addition result.
///
/// # Errors
///
/// Refuses to emit output outside the Rust-authored contract.
pub fn encode_add_group_member_response(
    response: &AddGroupMemberResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(
        response,
        response_validator::<AddGroupMemberResponse>(&ADD_RESPONSE)?,
    )
}

/// Validates and encodes one authoritative direct-membership removal result.
///
/// # Errors
///
/// Refuses to emit output outside the Rust-authored contract.
pub fn encode_remove_group_member_response(
    response: &RemoveGroupMemberResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_response(
        response,
        response_validator::<RemoveGroupMemberResponse>(&REMOVE_RESPONSE)?,
    )
}

fn validate_window(request: &AddGroupMemberRequest) -> Result<(), BoundaryError> {
    let from = instant_value(&request.valid_from_epoch_micros);
    let until = instant_value(&request.valid_until_epoch_micros);
    match (from, until) {
        (Some(from), Some(until)) if until <= from => Err(BoundaryError::DecodeMismatch),
        _ => Ok(()),
    }
}

const fn instant_value(value: &NullableField<crate::GroupMembershipInstant>) -> Option<i64> {
    match value {
        NullableField::Value(instant) => Some(instant.epoch_micros()),
        NullableField::Missing | NullableField::Null => None,
    }
}

fn decode_request<T: DeserializeOwned>(
    bytes: &[u8],
    validator: &CompiledValidator,
) -> Result<T, BoundaryError> {
    if bytes.is_empty() || bytes.len() > MAX_GROUP_MEMBERSHIP_MUTATION_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_GROUP_MEMBERSHIP_MUTATION_BYTES,
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
