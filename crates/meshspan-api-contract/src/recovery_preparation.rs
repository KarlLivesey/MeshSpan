// SPDX-License-Identifier: GPL-2.0-only

//! Offline operator selection, not a service-admission or storage-readiness receipt.

use crate::validation::{CompiledValidator, compile, validate, validator_from};
use crate::{BoundaryError, OperationId, schema};

#[cfg(test)]
#[path = "recovery_preparation_tests.rs"]
mod tests;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Bound the complete untrusted selection before JSON allocation.
pub const MAX_RECOVERY_SELECTION_BYTES: usize = 2 * 1024 * 1024;

/// Node-local physical restoration request; source identity is checked against the signed archive.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTargetRestoreRequest {
    /// Existing prepared destination folder, identified by its signed marker rather than its path.
    pub path: crate::StorageFolderPath,
    /// Existing salvage inventory; every selected byte is checked against archived shard hashes.
    pub inventory_directory: crate::StorageFolderPath,
    /// Exact original target whose retained slices should be copied to this destination.
    #[schemars(
        length(min = 36, max = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    )]
    pub source_target_id: String,
    /// Positive original generation, lossless decimal text.
    #[schemars(length(min = 1, max = 19), pattern(r"^[1-9][0-9]*$"))]
    pub source_generation: String,
}

/// Decodes one bounded, closed node-local restore request. No input claim grants service authority.
/// # Errors
/// Rejects excessive input, duplicate/unknown fields, coercion, invalid paths or identities.
pub fn decode_recovery_target_restore_request(
    bytes: &[u8],
) -> Result<RecoveryTargetRestoreRequest, BoundaryError> {
    static VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
    if bytes.len() > 32 * 1024 {
        return Err(BoundaryError::BodyTooLarge { limit: 32 * 1024 });
    }
    decode_selection(bytes, &VALIDATOR)
}

/// Offline physical-source selection. Paths are local operator input, never serving authority.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryStorageSelection {
    /// Cumulative source-copy budget; private index and SQLite overhead are additional.
    #[schemars(length(min = 1, max = 19), pattern(r"^[1-9][0-9]*$"))]
    pub maximum_copied_bytes: String,
    /// Exact historical targets to compare with authenticated backup metadata.
    #[schemars(length(min = 1, max = 1024))]
    pub targets: Vec<RecoveryStorageTarget>,
}

/// One source folder with independently selected target and generation, not a claimed fingerprint.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryStorageTarget {
    /// Canonical public target UUID, checked again against the domain identity.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
    )]
    pub target_id: String,
    /// Exact historical generation, even when retired from normal access.
    #[schemars(length(min = 1, max = 19), pattern(r"^[1-9][0-9]*$"))]
    pub generation: String,
    /// Existing source folder; never created, registered or repaired by offline verification.
    #[schemars(length(min = 1, max = 16384))]
    pub storage_path: String,
}

/// Public replacement intent supplied alongside independently saved recovery material.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPreparationSelection {
    /// Distinct operator-selected recovery operation; no secret belongs here.
    pub recovery_id: OperationId,
    /// Surviving physical sources. Preparation derives its commitment only after verification.
    pub storage: RecoveryStorageSelection,
    /// Automatic flat quorum by default; omission is distinct from invalid null.
    #[serde(default)]
    pub quorum: RecoveryQuorumSelection,
    /// Initial replacement set; further nodes may join normally after admission.
    #[schemars(length(min = 1, max = 1024))]
    pub nodes: Vec<RecoveryNodeSelection>,
}

/// Simple default with an explicit escape hatch for already compiled flexible quorum plans.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryQuorumSelection {
    /// Every selected metadata-eligible node votes in a flat majority plan.
    #[default]
    Automatic,
    /// Canonical `ActiveQuorumPlan` bytes; the server decodes and re-proves its predicates.
    Compiled {
        /// Lowercase hexadecimal, bounded before decoding; must be stable and successor-epoch.
        #[schemars(length(min = 2, max = 131_072), pattern(r"^([0-9a-f]{2})+$"))]
        specification: String,
    },
}

/// Public node description. Private keys remain on that node.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryNodeSelection {
    /// Exact selected node identity, distinct from its host identity.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
    )]
    pub node_id: String,
    /// Shared physical-host failure identity.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
    )]
    pub host_id: String,
    /// Human-readable host name, validated again by the domain model.
    #[schemars(length(min = 1, max = 256))]
    pub host_name: String,
    /// Human-readable node name, distinct within this selection.
    #[schemars(length(min = 1, max = 256))]
    pub node_name: String,
    /// Positive decimal incarnation, avoiding JSON integer precision loss.
    #[schemars(length(min = 1, max = 19), pattern(r"^[1-9][0-9]*$"))]
    pub incarnation: String,
    /// Explicit role set; duplicates are rejected during domain conversion.
    #[schemars(length(min = 1, max = 3))]
    pub roles: Vec<RecoveryNodeRole>,
    /// Canonical uncompressed P-256 public identity, never a private key.
    #[schemars(length(equal = 130), pattern(r"^04[0-9a-f]{128}$"))]
    pub identity_public_key: String,
    /// Canonical public X25519 wrapping recipient.
    #[schemars(length(equal = 64), pattern(r"^[0-9a-f]{64}$"))]
    pub wrapping_public_key: String,
    /// Private QUIC endpoint, not proof of reachability.
    #[schemars(length(min = 3, max = 512))]
    pub private_endpoint: String,
}

/// Selected responsibility; this is not an automatic permission grant.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryNodeRole {
    /// Store encrypted shards without obtaining gateway decryption keys.
    Storage,
    /// Serve authorised filesystem access and open assigned encryption envelopes.
    Gateway,
    /// Be eligible for the replacement metadata voter set.
    Metadata,
}

/// Decodes original JSON bytes, rejecting unknown/duplicate fields, coercion and bounds.
/// # Errors
/// Rejects malformed JSON or structural schema violations; domain/cryptographic checks follow.
pub fn decode_recovery_preparation_selection(
    bytes: &[u8],
) -> Result<RecoveryPreparationSelection, BoundaryError> {
    static VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
    decode_selection(bytes, &VALIDATOR)
}

/// Decodes bounded offline storage input without coercion or unknown/duplicate fields.
/// # Errors
/// Rejects malformed JSON and schema violations; identities, permissions and IO are rechecked.
pub fn decode_recovery_storage_selection(
    bytes: &[u8],
) -> Result<RecoveryStorageSelection, BoundaryError> {
    static VALIDATOR: OnceLock<Result<CompiledValidator, String>> = OnceLock::new();
    decode_selection(bytes, &VALIDATOR)
}

fn decode_selection<T: serde::de::DeserializeOwned + JsonSchema>(
    bytes: &[u8],
    validator: &'static OnceLock<Result<CompiledValidator, String>>,
) -> Result<T, BoundaryError> {
    if bytes.len() > MAX_RECOVERY_SELECTION_BYTES {
        return Err(BoundaryError::BodyTooLarge {
            limit: MAX_RECOVERY_SELECTION_BYTES,
        });
    }
    let value = serde_json::from_slice(bytes).map_err(|_| BoundaryError::MalformedJson)?;
    validate(
        validator_from(validator.get_or_init(|| compile(&schema::request_schema::<T>())))?,
        &value,
    )?;
    serde_json::from_slice(bytes).map_err(|_| BoundaryError::DecodeMismatch)
}
