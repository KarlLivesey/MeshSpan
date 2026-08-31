// SPDX-License-Identifier: GPL-2.0-only

//! Runtime validation for native bounded file reads.

use std::sync::OnceLock;

use serde_json::Value;

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{BoundaryError, MAX_FILE_READ_BYTES, MAX_SAFE_FILE_OFFSET, ReadFileQuery, schema};

static QUERY_VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();

/// Validates one decoded file-read query before authentication or filesystem work.
///
/// # Errors
///
/// Rejects non-canonical paths, unsafe offsets, zero lengths and oversized ranges.
pub fn validate_read_file_query(query: &ReadFileQuery) -> Result<(), BoundaryError> {
    let value = serde_json::to_value(query).map_err(|_| BoundaryError::EncodeMismatch)?;
    validate_read_file_query_value(&value)?;
    if !query.path.is_canonical()
        || query
            .offset
            .is_some_and(|value| value > MAX_SAFE_FILE_OFFSET)
        || query
            .length
            .is_some_and(|value| value == 0 || value > MAX_FILE_READ_BYTES)
    {
        return Err(BoundaryError::DecodeMismatch);
    }
    Ok(())
}

/// Validates the raw JSON-equivalent form of one file-read query.
///
/// # Errors
///
/// Returns bounded structural issues or an invalid authoritative schema.
pub fn validate_read_file_query_value(value: &Value) -> Result<(), BoundaryError> {
    validate(query_validator()?, value)
}

fn query_validator() -> Result<&'static CompiledValidator, BoundaryError> {
    validator_from(
        QUERY_VALIDATOR.get_or_init(|| compile(&schema::request_schema::<ReadFileQuery>())),
    )
}
