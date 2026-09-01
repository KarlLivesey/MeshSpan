// SPDX-License-Identifier: GPL-2.0-only

//! Pollable public state for durable long-running and committed operations.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::OperationId;

/// Opaque continuation for one reverse-chronological operation page.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct OperationCursor(
    #[schemars(length(min = 1, max = 256), pattern(r"^[A-Za-z0-9._~-]+$"))] String,
);

impl OperationCursor {
    /// Constructs a cursor after its authoritative fields have been validated.
    #[must_use]
    pub fn from_encoded(value: String) -> Option<Self> {
        let valid_length = (1..=256).contains(&value.len());
        let valid_alphabet = value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte));
        (valid_length && valid_alphabet).then_some(Self(value))
    }

    /// Returns the opaque continuation token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One bounded administrator operation-inventory query.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListOperationsQuery {
    /// Exact continuation returned by the preceding page.
    pub cursor: Option<OperationCursor>,
    /// Requested result bound; omission applies the server default.
    #[schemars(range(min = 1, max = 200))]
    pub limit: Option<u16>,
}

/// Stable operation families shared by browser, CLI and future access connectors.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    /// One ordinary consensus-committed metadata mutation.
    MetadataMutation,
    /// First-start enrolment into an existing swarm.
    SetupJoin,
    /// Placement or protection convergence.
    Placement,
    /// Reconstruction of missing or corrupt protected content.
    Repair,
    /// Integrity verification.
    Scrub,
    /// Safe removal of a node, target or location.
    Drain,
    /// Disconnected-history or federation convergence.
    Reconciliation,
    /// Certificate issuance, distribution or rotation.
    Certificate,
    /// Metadata backup or restore-readiness work.
    Backup,
    /// Compatibility-checked software update work.
    Update,
}

/// Authoritative lifecycle state; progress is advisory and never implies success.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Accepted but not yet claimed by a worker.
    Queued,
    /// A fenced worker currently owns the next attempt.
    Running,
    /// Durable input from an authorised user or external system is required.
    AwaitingAction,
    /// The terminal committed outcome is available.
    Succeeded,
    /// The operation reached a terminal typed failure.
    Failed,
    /// A safe cancellation reached its terminal state.
    Cancelled,
}

/// Bounded units used by operation progress without embedding arbitrary metric names.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationProgressUnit {
    /// Logical steps whose exact meaning is operation-specific.
    Steps,
    /// Immutable bytes verified or moved.
    Bytes,
    /// Bounded logical items processed.
    Items,
    /// Nodes which have reached the required state.
    Nodes,
    /// Storage targets which have reached the required state.
    Targets,
}

/// Advisory monotonic progress; the operation state remains authoritative.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationProgress {
    /// Completed work in the declared unit.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_u64))]
    pub completed: u64,
    /// Current known total, which may increase as bounded discovery proceeds.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub total: u64,
    /// Meaning of both counters.
    pub unit: OperationProgressUnit,
}

/// Whether and how another attempt may safely proceed after a failure.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationRetryClass {
    /// The operation is terminal and another attempt would not help.
    Never,
    /// `MeshSpan` owns bounded automatic retries.
    Automatic,
    /// A caller may retry only with the same operation identity.
    SameOperation,
    /// Authorised action or changed external state is required first.
    ActionRequired,
}

/// Stable failure details safe to show without raw paths, inputs or secrets.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationFailure {
    /// Stable machine-readable failure category.
    #[schemars(length(min = 1, max = 64), pattern(r"^[a-z][a-z0-9_]*$"))]
    pub code: String,
    /// Bounded plain-language explanation.
    #[schemars(length(min = 1, max = 512))]
    pub message: String,
    /// Safe retry classification independent of the prose.
    pub retry: OperationRetryClass,
}

/// Current durable state of one exact operation visible to the caller.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationStatusResponse {
    /// Exact operation being resolved.
    pub operation_id: OperationId,
    /// Stable work family.
    pub kind: OperationKind,
    /// Authoritative lifecycle state.
    pub state: OperationState,
    /// Advisory bounded progress, or null when the work is not meaningfully countable.
    pub progress: Option<OperationProgress>,
    /// Whether a cancellation request is currently safe and supported.
    pub cancellation_available: bool,
    /// Original accepted instant.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub started_at_epoch_micros: i64,
    /// Most recent authoritative lifecycle change.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub updated_at_epoch_micros: i64,
    /// Terminal instant, or null while work remains non-terminal.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub completed_at_epoch_micros: Option<i64>,
    /// Typed terminal failure, or null for non-failed states.
    pub failure: Option<OperationFailure>,
    /// Ready-to-follow current status URL.
    #[schemars(length(min = 1, max = 512), pattern(r"^/api/latest/operations/"))]
    pub status_url: String,
    /// Ready-to-follow committed result URL when the result has an addressable resource.
    #[schemars(length(min = 1, max = 16_384), pattern(r"^/api/latest/"))]
    pub result_url: Option<String>,
    /// Authoritative operation revision used by conditional clients and event projections.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded reverse-chronological administrator operation page.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListOperationsResponse {
    /// Current authoritative operation projections, newest revision first.
    #[schemars(length(max = 200))]
    pub operations: Vec<OperationStatusResponse>,
    /// Ready-to-follow relative URL, or null at the terminal page.
    #[schemars(
        length(min = 1, max = 16_384),
        pattern(r"^/api/latest/admin/operations")
    )]
    pub next_page_url: Option<String>,
}
