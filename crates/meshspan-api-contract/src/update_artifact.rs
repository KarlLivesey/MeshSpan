// SPDX-License-Identifier: GPL-2.0-only

use crate::{OperationId, UpdateIdentifier};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Maximum executable size from the signed candidate format; raw bytes are streamed.
pub const MAX_UPDATE_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Public signed executable identity; no download URL or host path is trusted from a manifest.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateArtifactDescriptor {
    /// Platform in the signed manifest.
    #[schemars(
        length(min = 1, max = 64),
        pattern(r"^(aarch64|x86_64)-(apple-darwin|unknown-linux-musl)$")
    )]
    pub target: String,
    /// Expected positive executable bytes, at most eight GiB.
    #[schemars(range(min = 1, max = 8_589_934_592_u64))]
    pub byte_length: u64,
    /// Exact signed executable digest.
    #[schemars(length(equal = 64), pattern(r"^[0-9a-f]{64}$"))]
    pub sha256: String,
}

/// Durable source publication, not node staging readiness or software installation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StageUpdateArtifactResponse {
    /// Original public operation identity.
    pub operation_id: OperationId,
    /// Selected candidate.
    pub rollout_id: UpdateIdentifier,
    /// Node holding the locally fsynced, verified executable.
    pub node_id: UpdateIdentifier,
    /// Signed executable platform.
    #[schemars(
        length(min = 1, max = 64),
        pattern(r"^(aarch64|x86_64)-(apple-darwin|unknown-linux-musl)$")
    )]
    pub target: String,
    /// Exact signed byte count, represented without floating-point loss.
    #[schemars(length(min = 1, max = 10), pattern(r"^[1-9][0-9]*$"))]
    pub byte_length: String,
    /// Independently reverified signed SHA-256.
    #[schemars(length(equal = 64), pattern(r"^[0-9a-f]{64}$"))]
    pub sha256: String,
    /// Original authoritative revision advertising this source.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub committed_revision: u64,
}

/// Validate source publication before output; a successful file write alone is insufficient.
///
/// # Errors
/// Rejects invalid identities, target, size, digest or revision.
pub fn encode_stage_update_artifact_response(
    response: &StageUpdateArtifactResponse,
) -> Result<Vec<u8>, crate::BoundaryError> {
    use crate::validation::{CompiledValidator, compile, validate, validator_from};
    use std::sync::OnceLock;
    static VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
    let value = serde_json::to_value(response).map_err(|_| crate::BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(VALIDATOR.get_or_init(|| {
            compile(&crate::schema::response_schema::<StageUpdateArtifactResponse>())
        }))?,
        &value,
    )?;
    if response
        .byte_length
        .parse::<u64>()
        .ok()
        .is_none_or(|length| length > MAX_UPDATE_ARTIFACT_BYTES)
    {
        return Err(crate::BoundaryError::EncodeMismatch);
    }
    serde_json::to_vec(&value).map_err(|_| crate::BoundaryError::EncodeMismatch)
}
