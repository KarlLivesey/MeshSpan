// SPDX-License-Identifier: GPL-2.0-only

//! Runtime trust-boundary validation for native resumable uploads.

use std::sync::OnceLock;

use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    AbortUploadRequest, AbortUploadResponse, BeginUploadRequest, BeginUploadResponse,
    BoundaryError, CommitUploadRequest, CommitUploadResponse, ListUploadRangesQuery,
    ListUploadRangesResponse, UploadState, UploadStatusResponse, WriteUploadRangeResponse, schema,
};

/// Maximum accepted JSON bytes for beginning an upload.
pub const MAX_BEGIN_UPLOAD_BYTES: usize = 16 * 1_024;
/// Maximum accepted JSON bytes for an explicit upload commit.
pub const MAX_COMMIT_UPLOAD_BYTES: usize = 16 * 1_024;
/// Maximum accepted JSON bytes for aborting an upload.
pub const MAX_ABORT_UPLOAD_BYTES: usize = 8 * 1_024;

static BEGIN_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static BEGIN_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static COMMIT_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static COMMIT_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static ABORT_REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static STATUS_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RANGE_QUERY: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RANGE_RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Decodes and validates one hostile begin-upload body.
///
/// # Errors
///
/// Rejects oversized, malformed, schema-invalid or non-canonical input.
pub fn decode_begin_upload_request(bytes: &[u8]) -> Result<BeginUploadRequest, BoundaryError> {
    let request: BeginUploadRequest =
        decode_request(bytes, MAX_BEGIN_UPLOAD_BYTES, begin_request_validator())?;
    if !request.path.is_canonical() {
        return Err(BoundaryError::DecodeMismatch);
    }
    Ok(request)
}

/// Decodes and validates one hostile commit-upload body.
///
/// # Errors
///
/// Rejects oversized, malformed or schema-invalid input.
pub fn decode_commit_upload_request(bytes: &[u8]) -> Result<CommitUploadRequest, BoundaryError> {
    decode_request(bytes, MAX_COMMIT_UPLOAD_BYTES, commit_request_validator())
}

/// Decodes and validates one hostile abort-upload body.
///
/// # Errors
///
/// Rejects oversized, malformed or schema-invalid input.
pub fn decode_abort_upload_request(bytes: &[u8]) -> Result<AbortUploadRequest, BoundaryError> {
    decode_request(bytes, MAX_ABORT_UPLOAD_BYTES, abort_request_validator())
}

/// Validates and encodes a ready upload response.
///
/// # Errors
///
/// Rejects incoherent or schema-invalid authoritative state.
pub fn encode_begin_upload_response(
    response: &BeginUploadResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_status(response, begin_response_validator())
}

/// Validates and encodes a range-write response.
///
/// # Errors
///
/// Rejects incoherent or schema-invalid authoritative state.
pub fn encode_write_upload_range_response(
    response: &WriteUploadRangeResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_status(response, status_response_validator())
}

/// Validates and encodes a status response.
///
/// # Errors
///
/// Rejects incoherent or schema-invalid authoritative state.
pub fn encode_upload_status_response(
    response: &UploadStatusResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode_status(response, status_response_validator())
}

/// Validates one decoded upload-range page query.
///
/// # Errors
///
/// Rejects schema-invalid cursor or page bounds.
pub fn validate_list_upload_ranges_query(
    query: &ListUploadRangesQuery,
) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(query).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(range_query_validator()?, &value)
}

/// Validates and encodes one exact upload-range page.
///
/// # Errors
///
/// Rejects excessive, empty, overlapping, adjacent or schema-invalid ranges.
pub fn encode_list_upload_ranges_response(
    response: &ListUploadRangesResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let valid_ranges = response.ranges.iter().all(|range| range.start < range.end)
        && response
            .ranges
            .windows(2)
            .all(|pair| pair[0].end < pair[1].start);
    if !valid_ranges {
        return Err(BoundaryError::EncodeMismatch);
    }
    encode_response(response, range_response_validator())
}

/// Validates and encodes a complete publication response.
///
/// # Errors
///
/// Rejects non-terminal, incoherent or schema-invalid authoritative state.
pub fn encode_commit_upload_response(
    response: &CommitUploadResponse,
) -> Result<Vec<u8>, BoundaryError> {
    let acknowledgement = &response.acknowledgement;
    let policy_success = acknowledgement.policy_committed
        && !acknowledgement.fallback_applied
        && acknowledgement.configured_consistency == acknowledgement.acknowledged_consistency;
    let explicit_fallback = !acknowledgement.policy_committed
        && acknowledgement.fallback_applied
        && acknowledgement.configured_consistency == crate::AcknowledgementConsistency::Strong
        && acknowledgement.acknowledged_consistency == crate::AcknowledgementConsistency::Eventual;
    let scope_matches = match acknowledgement.acknowledged_consistency {
        crate::AcknowledgementConsistency::Strong => {
            acknowledgement.durability_scope == crate::WriteDurabilityScope::GloballyConverged
        }
        crate::AcknowledgementConsistency::Eventual => {
            acknowledgement.durability_scope != crate::WriteDurabilityScope::GloballyConverged
        }
    };
    if response.upload.state != UploadState::Committed
        || !(policy_success || explicit_fallback)
        || !scope_matches
    {
        return Err(BoundaryError::EncodeMismatch);
    }
    encode_response(response, commit_response_validator())
}

/// Validates and encodes an abort response.
///
/// # Errors
///
/// Rejects non-aborted, incoherent or schema-invalid authoritative state.
pub fn encode_abort_upload_response(
    response: &AbortUploadResponse,
) -> Result<Vec<u8>, BoundaryError> {
    if response.state != UploadState::Aborted {
        return Err(BoundaryError::EncodeMismatch);
    }
    encode_status(response, status_response_validator())
}

fn decode_request<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
    validator: Result<&CompiledValidator, BoundaryError>,
) -> Result<T, BoundaryError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(BoundaryError::BodyTooLarge { limit: maximum });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(validator?, &value)?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

fn encode_status(
    response: &UploadStatusResponse,
    validator: Result<&CompiledValidator, BoundaryError>,
) -> Result<Vec<u8>, BoundaryError> {
    let has_commit =
        response.committed_object_id.is_some() && response.committed_version_id.is_some();
    let coherent_pair =
        response.committed_object_id.is_some() == response.committed_version_id.is_some();
    if !coherent_pair
        || (response.state == UploadState::Committed) != has_commit
        || response.logical_extent > response.maximum_bytes
    {
        return Err(BoundaryError::EncodeMismatch);
    }
    encode_response(response, validator)
}

fn encode_response<T: Serialize>(
    response: &T,
    validator: Result<&CompiledValidator, BoundaryError>,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(validator?, &value)?;
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

fn begin_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    request_validator::<BeginUploadRequest>(&BEGIN_REQUEST)
}

fn begin_response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    response_validator::<BeginUploadResponse>(&BEGIN_RESPONSE)
}

fn commit_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    request_validator::<CommitUploadRequest>(&COMMIT_REQUEST)
}

fn commit_response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    response_validator::<CommitUploadResponse>(&COMMIT_RESPONSE)
}

fn abort_request_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    request_validator::<AbortUploadRequest>(&ABORT_REQUEST)
}

fn status_response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    response_validator::<UploadStatusResponse>(&STATUS_RESPONSE)
}

fn range_query_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    request_validator::<ListUploadRangesQuery>(&RANGE_QUERY)
}

fn range_response_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    response_validator::<ListUploadRangesResponse>(&RANGE_RESPONSE)
}
