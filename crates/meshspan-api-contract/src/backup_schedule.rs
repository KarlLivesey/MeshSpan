// SPDX-License-Identifier: GPL-2.0-only

//! Public policy for automatic encrypted metadata backups.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::OperationId;

/// Desired backup frequency, retention and verified-copy thresholds.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSchedulePolicy {
    /// Delay between completed attempts, in seconds.
    #[schemars(range(min = 1, max = 4_294_967_295_u64))]
    pub interval_seconds: u32,
    /// Number of newest usable generations to retain.
    #[schemars(range(min = 1, max = 1_024))]
    pub retained_generations: u16,
    /// Verified destination copies required before reporting protection.
    #[schemars(range(min = 1))]
    pub minimum_verified_copies: u8,
    /// Required independent copies; cannot exceed the verified-copy threshold.
    pub minimum_independent_copies: u8,
    /// Whether automatic backup attempts are enabled.
    pub enabled: bool,
}

/// Exact-retry replacement of the current partition backup policy.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigureBackupScheduleRequest {
    /// Stable logical operation identity, retained across retries.
    pub operation_id: OperationId,
    /// Observed policy sequence; zero creates the first policy.
    #[schemars(range(min = 0, max = 9_007_199_254_740_990_u64))]
    pub expected_sequence: u64,
    /// Complete desired policy; omission never silently resets a field.
    pub policy: BackupSchedulePolicy,
}

/// Current configured policy and scheduling state, without a claim of completed protection.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupScheduleStatus {
    /// Immutable configuration sequence used for compare-and-swap updates.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub sequence: u64,
    /// Complete desired policy.
    pub policy: BackupSchedulePolicy,
    /// Next eligible attempt time; an unfinished run can delay it.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub next_due_at_epoch_micros: i64,
}

/// Current backup schedule for the gateway's authoritative partition.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupScheduleResponse {
    /// Exact partition whose policy is returned.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub partition_id: String,
    /// Explicitly null until the first policy is configured.
    pub schedule: Option<BackupScheduleStatus>,
}

/// Original durable configuration receipt, including when a later policy supersedes it.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigureBackupScheduleResponse {
    /// Original logical operation identity.
    pub operation_id: OperationId,
    /// Immutable policy sequence created by this operation.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub sequence: u64,
    /// Original committed metadata revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub committed_revision: u64,
}
