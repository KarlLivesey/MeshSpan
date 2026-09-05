// SPDX-License-Identifier: GPL-2.0-only

//! Rust validation independent of callers and generated clients.

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{
    BoundaryError, ConfigureBackupDestinationRequest, ConfigureBackupDestinationResponse,
    ListBackupDestinationsQuery, ListBackupDestinationsResponse, schema,
};
use schemars::JsonSchema;
use serde::Serialize;
use std::sync::OnceLock;

static REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static QUERY: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static PAGE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RECEIPT: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Maximum encoded destination mutation before parsing.
pub const MAX_CONFIGURE_BACKUP_DESTINATION_BYTES: usize = 2_048;

/// Decodes one exact-retry configuration without coercion or unknown fields.
///
/// # Errors
/// Rejects malformed, excessive or structurally invalid input.
pub fn decode_configure_backup_destination_request(
    bytes: &[u8],
) -> Result<ConfigureBackupDestinationRequest, BoundaryError> {
    if bytes.len() > MAX_CONFIGURE_BACKUP_DESTINATION_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_CONFIGURE_BACKUP_DESTINATION_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(
        validator_from(REQUEST.get_or_init(|| {
            compile(&schema::request_schema::<ConfigureBackupDestinationRequest>())
        }))?,
        &value,
    )?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

/// Checks page bounds and opaque continuation structure.
///
/// # Errors
/// Rejects invalid page sizes or token syntax; caller bindings are checked by the service.
pub fn validate_list_backup_destinations_query(
    query: &ListBackupDestinationsQuery,
) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(query).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(
            QUERY.get_or_init(|| compile(&schema::request_schema::<ListBackupDestinationsQuery>())),
        )?,
        &value,
    )
}

/// Validates current inventory before transmission.
///
/// # Errors
/// Rejects invalid records, unordered/duplicate identities and invalid continuation URLs.
pub fn encode_list_backup_destinations_response(
    response: &ListBackupDestinationsResponse,
) -> Result<Vec<u8>, BoundaryError> {
    if response
        .destinations
        .windows(2)
        .any(|pair| pair[0].destination_id >= pair[1].destination_id)
        || (response.destinations.is_empty() && response.next_page_url.is_some())
    {
        return Err(BoundaryError::EncodeMismatch);
    }
    encode(response, &PAGE)
}

/// Validates the original mutation receipt before transmission.
///
/// # Errors
/// Rejects zero, malformed or unrepresentable receipt fields.
pub fn encode_configure_backup_destination_response(
    response: &ConfigureBackupDestinationResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode(response, &RECEIPT)
}

fn encode<T: JsonSchema + Serialize>(
    response: &T,
    cache: &'static OnceLock<Result<CompiledValidator, String>>,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(response).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(cache.get_or_init(|| compile(&schema::response_schema::<T>())))?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}
