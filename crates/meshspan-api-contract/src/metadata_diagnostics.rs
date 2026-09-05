// SPDX-License-Identifier: GPL-2.0-only

//! Explicitly redacted metadata diagnostics, not a database export or availability proof.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Maximum encoded metadata diagnostic response; shared by server and generated clients.
pub const MAX_METADATA_DIAGNOSTICS_BYTES: usize = 256 * 1024;

/// Canonical identity retained for correlating diagnostic observations.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DiagnosticIdentifier(
    /// UUID text; validated again before transmission.
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    pub String,
);

/// Lossless unsigned counter, including zero, on the JSON boundary.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DiagnosticCounter(
    /// Canonical decimal representation, never a floating-point JSON number.
    #[schemars(length(min = 1, max = 20), pattern(r"^(0|[1-9][0-9]*)$"))]
    pub String,
);

/// Bounded selection; truncation means more records exist, not that they are healthy.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticSection<T> {
    /// At most one hundred explicitly redacted records.
    #[schemars(length(max = 100))]
    pub items: Vec<T>,
    /// More records existed at this section's read; use the normal inventory API for paging.
    pub truncated: bool,
}

/// Metadata-only snapshot; sections are local observations, not one atomic swarm-wide read.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataDiagnosticsResponse {
    /// Owning swarm identity, independent of reactor responsiveness.
    pub mesh_id: DiagnosticIdentifier,
    /// Local queried metadata partition.
    pub partition_id: DiagnosticIdentifier,
    /// Gateway which collected this snapshot.
    pub node_id: DiagnosticIdentifier,
    /// Daemon package version, not an assertion of signed release provenance.
    #[schemars(length(min = 1, max = 64), pattern(r"^[0-9A-Za-z.+-]+$"))]
    pub daemon_version: String,
    /// Local system-clock time at collection start, not a mesh-time uncertainty proof.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub collected_at_epoch_micros: i64,
    /// Local metadata revision before collection.
    pub revision_before: DiagnosticCounter,
    /// Local metadata revision after collection; a change exposes concurrent application.
    pub revision_after: DiagnosticCounter,
    /// One coherent local reactor observation, or null if it did not answer within its budget.
    pub consensus: Option<DiagnosticConsensus>,
    /// Configured nodes, never inferred reachability; names and endpoints are omitted.
    pub nodes: DiagnosticSection<DiagnosticNode>,
    /// Configured storage, never inferred live IO health; paths and names are omitted.
    pub targets: DiagnosticSection<DiagnosticTarget>,
    /// Newest recorded operation outcomes, not the complete background-work inventory.
    pub recent_operations: DiagnosticSection<DiagnosticOperation>,
}

/// Observed reactor state; role alone never implies a live quorum or write availability.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticConsensus {
    /// Exact local partition.
    pub partition_id: DiagnosticIdentifier,
    /// Observed reactor node.
    pub node_id: DiagnosticIdentifier,
    /// Last observed role.
    pub role: DiagnosticConsensusRole,
    /// Known leader identity, without a reachability guarantee.
    pub known_leader: Option<DiagnosticIdentifier>,
    /// Current local durable term.
    pub term: DiagnosticCounter,
    /// Highest locally known committed index.
    pub commit_index: DiagnosticCounter,
    /// Highest locally applied index.
    pub applied_index: DiagnosticCounter,
    /// Active stable or transitional membership epoch.
    pub membership_epoch: DiagnosticCounter,
    /// Exact active plan proof digest, not a fresh quorum acknowledgement.
    #[schemars(length(equal = 64), pattern(r"^[0-9a-f]{64}$"))]
    pub plan_digest: String,
    /// Whether persistence has fenced further mutation.
    pub persistence_blocked: bool,
    /// Operations awaiting committed results.
    pub pending_operations: DiagnosticCounter,
    /// Mutations waiting for reactor admission.
    pub queued_operations: DiagnosticCounter,
}

/// Closed local consensus-role vocabulary for advanced diagnostics only.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticConsensusRole {
    /// Replication follower.
    Follower,
    /// Campaign in progress.
    Candidate,
    /// Locally elected leader, which may have lost contact with its quorum.
    Leader,
}

/// Configured node record with no user-supplied names or network addresses.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticNode {
    /// Daemon identity.
    pub node_id: DiagnosticIdentifier,
    /// Shared physical-machine identity.
    pub host_id: DiagnosticIdentifier,
    /// Persisted lifecycle, not current reachability.
    pub configured_state: crate::TopologyNodeState,
    /// Persisted restart incarnation.
    pub incarnation: DiagnosticCounter,
    /// Configured capabilities, not current readiness.
    pub roles: crate::TopologyNodeRoles,
}

/// Configured target record, with no provider path or content.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticTarget {
    /// Registered target identity.
    pub target_id: DiagnosticIdentifier,
    /// Owning daemon.
    pub node_id: DiagnosticIdentifier,
    /// Persisted lifecycle, not a fresh probe.
    pub configured_state: crate::TopologyTargetState,
    /// Authority-fenced provider generation.
    pub generation: DiagnosticCounter,
    /// Configured capacity ceiling, not measured free space.
    pub usage_limit: crate::StorageFolderUsageLimit,
}

/// Recent durable operation event with actor, input, result entity and raw errors omitted.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticOperation {
    /// Exact operation correlation identity.
    pub operation_id: DiagnosticIdentifier,
    /// Recorded lifecycle outcome.
    pub state: crate::OperationState,
    /// Recorded event revision.
    pub revision: DiagnosticCounter,
    /// Recorded start time.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub started_at_epoch_micros: i64,
    /// Recorded terminal time, if any.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub completed_at_epoch_micros: Option<i64>,
}

/// Validates the complete explicit response model before serialisation.
///
/// # Errors
/// Rejects invalid identifiers, bounds, counters, enums or contradictory indices/revisions.
pub fn encode_metadata_diagnostics_response(
    value: &MetadataDiagnosticsResponse,
) -> Result<Vec<u8>, crate::BoundaryError> {
    use crate::validation::{compile, validate, validator_from};
    static VALIDATOR: std::sync::OnceLock<Result<crate::validation::CompiledValidator, String>> =
        std::sync::OnceLock::new();
    let json = serde_json::to_value(value).map_err(|_| crate::BoundaryError::EncodeMismatch)?;
    validate(
        validator_from(VALIDATOR.get_or_init(|| {
            compile(&crate::schema::response_schema::<MetadataDiagnosticsResponse>())
        }))?,
        &json,
    )?;
    if counter(&value.revision_before)? > counter(&value.revision_after)? {
        return Err(crate::BoundaryError::EncodeMismatch);
    }
    if let Some(consensus) = &value.consensus {
        if consensus.node_id != value.node_id || consensus.partition_id != value.partition_id {
            return Err(crate::BoundaryError::EncodeMismatch);
        }
        for field in [
            &consensus.term,
            &consensus.membership_epoch,
            &consensus.pending_operations,
            &consensus.queued_operations,
        ] {
            counter(field)?;
        }
        if counter(&consensus.applied_index)? > counter(&consensus.commit_index)? {
            return Err(crate::BoundaryError::EncodeMismatch);
        }
    }
    for node in &value.nodes.items {
        counter(&node.incarnation)?;
    }
    for target in &value.targets.items {
        counter(&target.generation)?;
    }
    for operation in &value.recent_operations.items {
        counter(&operation.revision)?;
        if operation
            .completed_at_epoch_micros
            .is_some_and(|end| end < operation.started_at_epoch_micros)
        {
            return Err(crate::BoundaryError::EncodeMismatch);
        }
    }
    serde_json::to_vec(&json).map_err(|_| crate::BoundaryError::EncodeMismatch)
}

pub(crate) fn counter(value: &DiagnosticCounter) -> Result<u64, crate::BoundaryError> {
    value
        .0
        .parse()
        .map_err(|_| crate::BoundaryError::EncodeMismatch)
}
