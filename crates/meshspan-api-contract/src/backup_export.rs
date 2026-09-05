// SPDX-License-Identifier: GPL-2.0-only

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Exact native encrypted-export path. No provider path or private key is accepted.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupExportPath {
    /// Backup generation selected from the administration history.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub backup_id: String,
}

/// Headers binding a streamed encrypted container to authoritative catalogue evidence.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupExportHeaders {
    /// Exact generation; not a statement of current protection or restore readiness.
    #[serde(rename = "MeshSpan-Backup-ID")]
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub backup_id: String,
    /// Exact encrypted-container length as a lossless decimal string.
    #[serde(rename = "Content-Length")]
    #[schemars(length(min = 1, max = 19), pattern(r"^[1-9][0-9]*$"))]
    pub byte_length: String,
    /// SHA-256 of the complete encrypted container, verified during streaming.
    #[serde(rename = "MeshSpan-Backup-Digest")]
    #[schemars(length(equal = 71), pattern(r"^sha256:[0-9a-f]{64}$"))]
    pub digest: String,
}

/// Validates native export path parameters before metadata lookup.
///
/// # Errors
/// Rejects non-canonical or malformed generation identities.
pub fn validate_backup_export_path(value: &BackupExportPath) -> Result<(), crate::BoundaryError> {
    use crate::validation::{compile, validate, validator_from};
    static VALIDATOR: std::sync::OnceLock<Result<crate::validation::CompiledValidator, String>> =
        std::sync::OnceLock::new();
    validate(
        validator_from(
            VALIDATOR.get_or_init(|| compile(&crate::schema::request_schema::<BackupExportPath>())),
        )?,
        &serde_json::to_value(value).map_err(|_| crate::BoundaryError::EncodeMismatch)?,
    )
}

/// Validates export headers independently of HTTP and generated callers.
///
/// # Errors
/// Rejects malformed identity, exact length or digest before headers are emitted.
pub fn validate_backup_export_headers(
    value: &BackupExportHeaders,
) -> Result<(), crate::BoundaryError> {
    use crate::validation::{compile, validate, validator_from};
    static VALIDATOR: std::sync::OnceLock<Result<crate::validation::CompiledValidator, String>> =
        std::sync::OnceLock::new();
    validate(
        validator_from(
            VALIDATOR
                .get_or_init(|| compile(&crate::schema::response_schema::<BackupExportHeaders>())),
        )?,
        &serde_json::to_value(value).map_err(|_| crate::BoundaryError::EncodeMismatch)?,
    )
}
