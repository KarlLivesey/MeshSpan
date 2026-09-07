// SPDX-License-Identifier: GPL-2.0-only

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{BoundaryError, ManageUpdateRequest, ManageUpdateResponse, UpdatesResponse, schema};
use std::sync::OnceLock;

/// JSON admission bound, including base64 manifest and detached signature.
pub const MAX_MANAGE_UPDATE_BYTES: usize = 24 * 1024;

/// Validate original request bytes without coercion or unknown/duplicate fields.
///
/// # Errors
/// Rejects malformed, excessive or structurally invalid input.
pub fn decode_manage_update_request(bytes: &[u8]) -> Result<ManageUpdateRequest, BoundaryError> {
    static VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
    if bytes.len() > MAX_MANAGE_UPDATE_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_MANAGE_UPDATE_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(
        validator_from(
            VALIDATOR.get_or_init(|| compile(&schema::request_schema::<ManageUpdateRequest>())),
        )?,
        &value,
    )?;
    serde_json::from_slice(bytes).map_err(|_| BoundaryError::DecodeMismatch)
}

/// Validate the outgoing manager receipt, independently of the submitting client.
///
/// # Errors
/// Rejects malformed identities and non-representable authoritative revisions.
pub fn encode_manage_update_response(
    response: &ManageUpdateResponse,
) -> Result<Vec<u8>, BoundaryError> {
    static VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(
            VALIDATOR.get_or_init(|| compile(&schema::response_schema::<ManageUpdateResponse>())),
        )?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}

/// Validate bounded trust and progress output; no client validator is trusted by the server.
///
/// # Errors
/// Rejects invalid identities, counters, versions or response structure.
pub fn encode_updates_response(response: &UpdatesResponse) -> Result<Vec<u8>, BoundaryError> {
    static VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(
            VALIDATOR.get_or_init(|| compile(&schema::response_schema::<UpdatesResponse>())),
        )?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}
