// SPDX-License-Identifier: GPL-2.0-only

//! Bounded local runtime evidence, separate from authoritative metadata and audit history.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{DiagnosticCounter, DiagnosticIdentifier, MetadataDiagnosticsResponse};

/// Maximum encoded combined diagnostic download, shared with generated clients.
pub const MAX_DIAGNOSTICS_BUNDLE_BYTES: usize = 512 * 1024;

/// Local metadata and runtime observations; never an atomic swarm snapshot or a backup.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsBundleResponse {
    /// Independently validated metadata section with its own revision bounds.
    pub metadata: MetadataDiagnosticsResponse,
    /// Null when the bounded observation store cannot be read immediately.
    pub runtime: Option<RuntimeDiagnosticsResponse>,
}

/// Process-lifetime observations only; restart clears these samples and counters.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDiagnosticsResponse {
    /// Monotonic time since this runtime observation store started.
    pub uptime_millis: DiagnosticCounter,
    /// Last accepted local observation sequence, unrelated to consensus ordering.
    pub observation_sequence: DiagnosticCounter,
    /// Updates omitted because observation admission or the local clock was unavailable.
    pub dropped_updates: DiagnosticCounter,
    /// Older target samples evicted to bound this diagnostic window, not removed targets.
    pub target_check_evictions: DiagnosticCounter,
    /// Older transient events evicted from the bounded process-lifetime window.
    pub event_evictions: DiagnosticCounter,
    /// Completed reconciliation cycles; not the number of durable work operations.
    pub reconciliation_cycles: DiagnosticCounter,
    /// Cycles reporting at least one failure, including recoverable background failures.
    pub reconciliation_failures: DiagnosticCounter,
    /// Successful provider health checks, not full content scrubs or protection proofs.
    pub target_probe_passes: DiagnosticCounter,
    /// Failed provider health checks, without raw provider errors or paths.
    pub target_probe_failures: DiagnosticCounter,
    /// Last completed cycle, or null before any cycle finishes.
    pub storage_reconciliation: Option<DiagnosticStorageReconciliation>,
    /// At most 100 latest target-generation checks; this is not the target inventory.
    #[schemars(length(max = 100))]
    pub target_checks: Vec<DiagnosticTargetCheck>,
    /// At most 100 newest-first redacted runtime transitions, not durable audit records.
    #[schemars(length(max = 100))]
    pub recent_events: Vec<DiagnosticRuntimeEvent>,
}

/// Local observation time with independently monotonic age and ordering.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticObservationTime {
    /// Positive process-local sequence; a wall-clock correction cannot reorder samples.
    pub sequence: DiagnosticCounter,
    /// Local clock at completion, not quorum time or a clock-uncertainty proof.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub observed_at_epoch_micros: i64,
    /// Monotonic sample age at collection; old successful checks are not current health.
    pub age_millis: DiagnosticCounter,
}

/// Exact provider generation to which an observation applies.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticTargetIdentity {
    /// Target identity only; never its filesystem path or display name.
    pub target_id: DiagnosticIdentifier,
    /// Positive registered provider generation.
    pub generation: DiagnosticCounter,
}

/// Completed provider health-check outcome, not a promise that every shard is intact.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticTargetCheck {
    /// Exact provider observed.
    pub target: DiagnosticTargetIdentity,
    /// Completion time and current sample age.
    pub observation: DiagnosticObservationTime,
    /// Monotonic time spent in the existing provider check.
    pub duration_millis: DiagnosticCounter,
    /// Closed result; no raw errors are accepted.
    pub result: DiagnosticProbeResult,
}

/// Result of the specific provider probe, not general availability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticProbeResult {
    /// The provider's configured health check completed successfully.
    Passed,
    /// The provider's configured health check failed.
    Failed,
}

/// Latest completed local storage reconciliation, including partial failures.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticStorageReconciliation {
    /// Completion time, not the scheduled start time.
    pub observation: DiagnosticObservationTime,
    /// Monotonic cycle duration.
    pub duration_millis: DiagnosticCounter,
    /// Configured folder count; no names or paths are included.
    pub configured_folders: DiagnosticCounter,
    /// Open local provider handles, not independently verified readable data.
    pub open_targets: DiagnosticCounter,
    /// Return scans awaiting admission, not the entire durable maintenance queue.
    pub pending_return_scans: DiagnosticCounter,
    /// Failed cycle steps, not failed nodes, files or shards.
    pub failed_steps: DiagnosticCounter,
}

/// Redacted local transition; intentionally cannot carry arbitrary text or payloads.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticRuntimeEvent {
    /// Event time and process-local ordering.
    pub observation: DiagnosticObservationTime,
    /// Closed transition vocabulary.
    pub code: DiagnosticRuntimeEventCode,
    /// Present only for target-check transitions.
    pub target: Option<DiagnosticTargetIdentity>,
}

/// Version-one transient runtime transitions; not notification delivery authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticRuntimeEventCode {
    /// The latest target check changed to failure.
    TargetProbeFailed,
    /// A previously failing target check now passes.
    TargetProbeRecovered,
    /// A storage cycle first reported failed steps.
    StorageReconciliationFailed,
    /// A previously failing storage cycle completed without failed steps.
    StorageReconciliationRecovered,
}
