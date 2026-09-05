// SPDX-License-Identifier: GPL-2.0-only

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Successful isolated restoration by a current gateway, never proof of offline-key custody.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupReadinessResponse {
    /// Exact encrypted generation actually read and restored.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub backup_id: String,
    /// Gateway whose protected recipient key opened the backup.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub checked_by_node_id: String,
    /// Partition recovered in a disposable workspace, not installed as authority.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub partition_id: String,
    /// Exact recovered committed index, represented losslessly.
    #[schemars(length(min = 1, max = 19), pattern(r"^[1-9][0-9]*$"))]
    pub source_log_index: String,
    /// Exact recovered committed term, represented losslessly.
    #[schemars(length(min = 1, max = 19), pattern(r"^[1-9][0-9]*$"))]
    pub source_log_term: String,
    /// Exact recovered metadata revision, represented losslessly.
    #[schemars(length(min = 1, max = 19), pattern(r"^[1-9][0-9]*$"))]
    pub state_revision: String,
    /// Completion time of the isolated check, not a future availability guarantee.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub checked_at_epoch_micros: i64,
    /// Precisely which key and recovery boundary were exercised.
    pub verification: BackupReadinessVerification,
}

/// The initial check deliberately makes no claim about an offline recovery bundle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupReadinessVerification {
    /// A current gateway decrypted the container and validated an isolated SQLite restore.
    GatewayKey,
}

/// Validates every outgoing field before serialising non-destructive restore evidence.
///
/// # Errors
/// Rejects contradictory structure, identifiers, bounds or unknown verification kinds.
pub fn encode_backup_readiness_response(
    value: &BackupReadinessResponse,
) -> Result<Vec<u8>, crate::BoundaryError> {
    use crate::validation::{compile, validate, validator_from};
    static VALIDATOR: std::sync::OnceLock<Result<crate::validation::CompiledValidator, String>> =
        std::sync::OnceLock::new();
    let value = serde_json::to_value(value).map_err(|_| crate::BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(VALIDATOR.get_or_init(|| {
            compile(&crate::schema::response_schema::<BackupReadinessResponse>())
        }))?,
        &value,
    )?;
    serde_json::to_vec(&value).map_err(|_| crate::BoundaryError::EncodeMismatch)
}
