// SPDX-License-Identifier: GPL-2.0-only

//! Runtime validation for hostile storage-drain messages.

use std::sync::OnceLock;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BeginStorageDrainRequest, BeginStorageDrainResponse, BoundaryError, ListStorageDrainsQuery,
    ListStorageDrainsResponse, StorageDrainState, StorageDrainSummary, schema,
};

/// Maximum accepted bytes for one drain-admission request.
pub const MAX_BEGIN_STORAGE_DRAIN_BYTES: usize = 8 * 1_024;

static BEGIN_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static BEGIN_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static LIST_QUERY: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static LIST_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static STATUS_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Decodes one bounded drain request without coercion.
///
/// # Errors
///
/// Rejects empty, oversized, malformed or schema-invalid input.
pub fn decode_begin_storage_drain_request(
    bytes: &[u8],
) -> Result<BeginStorageDrainRequest, BoundaryError> {
    if bytes.is_empty() || bytes.len() > MAX_BEGIN_STORAGE_DRAIN_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_BEGIN_STORAGE_DRAIN_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(
        validator_from(
            BEGIN_REQUEST
                .get_or_init(|| compile(&schema::request_schema::<BeginStorageDrainRequest>())),
        )?,
        &value,
    )?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

/// Validates one decoded inventory query.
///
/// # Errors
///
/// Rejects malformed bounds or cursors.
pub fn validate_list_storage_drains_query(
    query: &ListStorageDrainsQuery,
) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(query).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(
            LIST_QUERY.get_or_init(|| compile(&schema::request_schema::<ListStorageDrainsQuery>())),
        )?,
        &value,
    )
}

/// Validates and encodes one drain-admission result.
///
/// # Errors
///
/// Suppresses contradictory or schema-invalid output.
pub fn encode_begin_storage_drain_response(
    response: &BeginStorageDrainResponse,
) -> Result<Vec<u8>, BoundaryError> {
    validate_summary(&response.drain)?;
    encode(
        response,
        validator_from(
            BEGIN_RESPONSE
                .get_or_init(|| compile(&schema::response_schema::<BeginStorageDrainResponse>())),
        )?,
    )
}

/// Validates and encodes one exact drain status.
///
/// # Errors
///
/// Suppresses contradictory or schema-invalid output.
pub fn encode_storage_drain_summary(
    response: &StorageDrainSummary,
) -> Result<Vec<u8>, BoundaryError> {
    validate_summary(response)?;
    encode(
        response,
        validator_from(
            STATUS_RESPONSE
                .get_or_init(|| compile(&schema::response_schema::<StorageDrainSummary>())),
        )?,
    )
}

/// Validates and encodes one newest-first drain page.
///
/// # Errors
///
/// Suppresses contradictory, misordered or schema-invalid output.
pub fn encode_list_storage_drains_response(
    response: &ListStorageDrainsResponse,
) -> Result<Vec<u8>, BoundaryError> {
    for drain in &response.drains {
        validate_summary(drain)?;
    }
    if response
        .drains
        .windows(2)
        .any(|pair| pair[0].requested_at_epoch_micros < pair[1].requested_at_epoch_micros)
    {
        return Err(BoundaryError::EncodeMismatch);
    }
    encode(
        response,
        validator_from(
            LIST_RESPONSE
                .get_or_init(|| compile(&schema::response_schema::<ListStorageDrainsResponse>())),
        )?,
    )
}

fn validate_summary(value: &StorageDrainSummary) -> Result<(), BoundaryError> {
    let terminal = value.state == StorageDrainState::SafeToDetach;
    if terminal != value.safe_at_epoch_micros.is_some()
        || value
            .safe_at_epoch_micros
            .is_some_and(|safe_at| safe_at < value.requested_at_epoch_micros)
    {
        return Err(BoundaryError::EncodeMismatch);
    }
    Ok(())
}

fn encode<T: serde::Serialize>(
    response: &T,
    validator: &CompiledValidator,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(validator, &value)?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}
