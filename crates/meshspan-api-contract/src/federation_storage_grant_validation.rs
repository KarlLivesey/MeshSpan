// SPDX-License-Identifier: GPL-2.0-only

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{BoundaryError, schema};
use schemars::JsonSchema;
use serde::{Serialize, de::DeserializeOwned};
use std::sync::OnceLock;

static REQUEST: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static QUERY: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RECEIPT: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
static RESPONSE: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
/// Maximum JSON input/output for this exact, non-collection grant endpoint.
pub const MAX_FEDERATION_STORAGE_GRANT_BYTES: usize = 4096;

/// Validates mutation input independently of the caller.
/// # Errors
/// Rejects oversized, malformed, unknown-field or schema-invalid requests.
pub fn decode_federation_storage_grant_request(
    bytes: &[u8],
) -> Result<crate::ConfigureFederationStorageGrantRequest, BoundaryError> {
    decode(bytes, &REQUEST)
}
/// Validates one exact lookup, including rejecting unknown query properties.
/// # Errors
/// Rejects invalid lookup structure or identities.
pub fn decode_federation_storage_grant_query(
    bytes: &[u8],
) -> Result<crate::FederationStorageGrantQuery, BoundaryError> {
    decode(bytes, &QUERY)
}
/// Validates the exact original mutation receipt before transmission.
/// # Errors
/// Rejects invalid receipt fields or encoding failure.
pub fn encode_federation_storage_grant_receipt(
    value: &crate::ConfigureFederationStorageGrantResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode(value, &RECEIPT)
}
/// Validates a revision-consistent offer lookup before transmission.
/// # Errors
/// Rejects malformed records or encoding failure.
pub fn encode_federation_storage_grant_response(
    value: &crate::FederationStorageGrantResponse,
) -> Result<Vec<u8>, BoundaryError> {
    encode(value, &RESPONSE)
}

fn decode<T: DeserializeOwned + JsonSchema>(
    bytes: &[u8],
    cache: &'static OnceLock<Result<CompiledValidator, String>>,
) -> Result<T, BoundaryError> {
    if bytes.len() > MAX_FEDERATION_STORAGE_GRANT_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_FEDERATION_STORAGE_GRANT_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(
        validator_from(cache.get_or_init(|| compile(&schema::request_schema::<T>())))?,
        &value,
    )?;
    serde_json::from_value(value).map_err(|_| BoundaryError::DecodeMismatch)
}

fn encode<T: Serialize + JsonSchema>(
    value: &T,
    cache: &'static OnceLock<Result<CompiledValidator, String>>,
) -> Result<Vec<u8>, BoundaryError> {
    let value = serde_json::to_value(value).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(cache.get_or_init(|| compile(&schema::response_schema::<T>())))?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| BoundaryError::EncodeMismatch)
}
