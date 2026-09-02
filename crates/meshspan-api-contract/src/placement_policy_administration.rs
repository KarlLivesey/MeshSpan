// SPDX-License-Identifier: GPL-2.0-only

//! Public manager-only locality and write-acknowledgement policy models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{OperationId, ProtectionName, TopologyCursor};

/// Stable protection-scenario identity accepted by acknowledgement predicates.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProtectionScenarioReferenceId(
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    String,
);

impl ProtectionScenarioReferenceId {
    /// Parses exact canonical versioned UUID text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        crate::directory_listing::parse_public_uuid(value).map(Self)
    }

    /// Constructs canonical UUID text from already validated versioned UUID bytes.
    #[must_use]
    pub fn from_uuid_bytes(value: [u8; 16]) -> Option<Self> {
        let version = value[6] >> 4;
        if !(1..=8).contains(&version) || value[8] >> 6 != 2 {
            return None;
        }
        Some(Self(crate::model::format_uuid(value)))
    }

    /// Returns canonical UUID text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One availability cell which must hold a complete locally decodable copy.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateLocalityRequirement {
    /// Stable availability-cell identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub cell_id: String,
    /// Optional data-survival policy evaluated only inside this cell.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub local_protection_policy_id: Option<String>,
}

/// Exact-retry request to create one immutable desired-locality policy.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateLocalityPolicyRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// User-visible policy name.
    pub name: ProtectionName,
    /// Optional lag limit used to prioritise incomplete-locality repair.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub maximum_lag_micros: Option<u64>,
    /// Cells which must each independently reconstruct the selected version.
    #[schemars(length(min = 1, max = 64))]
    pub requirements: Vec<CreateLocalityRequirement>,
}

/// One committed complete-local requirement.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalityRequirementSummary {
    /// Stable requirement identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub requirement_id: String,
    /// Stable availability-cell identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub cell_id: String,
    /// Optional survival policy evaluated within the cell.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub local_protection_policy_id: Option<String>,
}

/// One immutable desired-locality policy.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalityPolicySummary {
    /// Stable policy identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub policy_id: String,
    /// User-visible policy name.
    #[schemars(length(min = 1, max = 256))]
    pub name: String,
    /// Optional lag limit used to prioritise repair debt.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub maximum_lag_micros: Option<u64>,
    /// Ordered complete-local requirements.
    #[schemars(length(min = 1, max = 64))]
    pub requirements: Vec<LocalityRequirementSummary>,
    /// Immutable authoritative policy revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded page of desired-locality policies.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListLocalityPoliciesResponse {
    /// Stable name-ordered policy summaries.
    #[schemars(length(max = 256))]
    pub policies: Vec<LocalityPolicySummary>,
    /// Ready-to-follow same-origin URL, or null at the terminal page.
    #[schemars(
        length(min = 1, max = 16_384),
        pattern(r"^/api/latest/admin/locality-policies")
    )]
    pub next_page_url: Option<String>,
}

/// Durable locality-policy creation result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateLocalityPolicyResponse {
    /// Exact idempotency identity whose result was resolved.
    pub operation_id: OperationId,
    /// Current created immutable policy.
    pub policy: LocalityPolicySummary,
}

/// Exact-retry request selecting a policy for one volume.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssignVolumePlacementPolicyRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
}

/// Durable volume placement-policy selection result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssignVolumePlacementPolicyResponse {
    /// Exact idempotency identity whose result was resolved.
    pub operation_id: OperationId,
    /// Volume receiving the immutable policy.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub volume_id: String,
    /// Selected immutable policy.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub policy_id: String,
    /// Authoritative assignment revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// Availability-first or strong write acknowledgement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgementConsistency {
    /// Commit a durable branch and reconcile wider promises automatically.
    Eventual,
    /// Wait for declared predicates and a globally converged metadata commit.
    Strong,
}

/// Explicit result when a strong deadline cannot be met.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrongFallback {
    /// Retain the exact operation as pending.
    RemainPending,
    /// Return failure while retaining safe staged work.
    FailAtDeadline,
    /// Explicitly permit a weaker eventual branch receipt.
    Eventual,
}

/// How one cell participates in acknowledgement and placement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgementCellMode {
    /// This cell's predicates block strong acknowledgement.
    RequiredBeforeCommit,
    /// Copy here automatically without delaying acknowledgement.
    Eventual,
    /// Never place this policy's content in this cell.
    Excluded,
}

/// One cell-specific acknowledgement predicate.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAcknowledgementCellRequirement {
    /// Stable availability-cell identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub cell_id: String,
    /// Synchronous, eventual, or excluded participation.
    pub mode: AcknowledgementCellMode,
    /// Optional minimum durable targets within this cell.
    #[schemars(range(min = 1, max = 65_535))]
    pub minimum_durable_targets: Option<u16>,
    /// Optional minimum distinct machines within this cell.
    #[schemars(range(min = 1, max = 65_535))]
    pub minimum_distinct_nodes: Option<u16>,
    /// Optional survival policy evaluated within this cell.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub local_protection_policy_id: Option<String>,
}

/// Exact-retry request to create one immutable acknowledgement policy.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAcknowledgementPolicyRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// User-visible policy name.
    pub name: ProtectionName,
    /// Availability-first or strong publication semantics.
    pub consistency: AcknowledgementConsistency,
    /// Minimum durable target count required before acknowledgement.
    #[schemars(range(min = 1, max = 65_535))]
    pub minimum_durable_targets: u16,
    /// Minimum distinct machine count represented by durable targets.
    #[schemars(range(min = 1, max = 65_535))]
    pub minimum_distinct_nodes: u16,
    /// Optional deadline used only by strong policies.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub strong_wait_micros: Option<u64>,
    /// Explicit deadline result.
    pub fallback: StrongFallback,
    /// Protection-scenario identities which must be proved before acknowledgement.
    #[schemars(length(max = 64))]
    pub required_scenario_ids: Vec<ProtectionScenarioReferenceId>,
    /// Cell-specific acknowledgement and placement predicates.
    #[schemars(length(max = 256))]
    pub cells: Vec<CreateAcknowledgementCellRequirement>,
}

/// One immutable write-acknowledgement policy.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcknowledgementPolicySummary {
    /// Stable policy identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub policy_id: String,
    /// User-visible policy name.
    #[schemars(length(min = 1, max = 256))]
    pub name: String,
    /// Availability-first or strong publication semantics.
    pub consistency: AcknowledgementConsistency,
    /// Minimum durable target count.
    pub minimum_durable_targets: u16,
    /// Minimum distinct machine count.
    pub minimum_distinct_nodes: u16,
    /// Optional strong acknowledgement deadline.
    pub strong_wait_micros: Option<u64>,
    /// Explicit deadline result.
    pub fallback: StrongFallback,
    /// Protection scenarios required before acknowledgement.
    #[schemars(length(max = 64))]
    pub required_scenario_ids: Vec<ProtectionScenarioReferenceId>,
    /// Cell-specific acknowledgement and placement predicates.
    #[schemars(length(max = 256))]
    pub cells: Vec<CreateAcknowledgementCellRequirement>,
    /// Immutable authoritative policy revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded page of write-acknowledgement policies.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListAcknowledgementPoliciesResponse {
    /// Stable name-ordered policy summaries.
    #[schemars(length(max = 256))]
    pub policies: Vec<AcknowledgementPolicySummary>,
    /// Ready-to-follow same-origin URL, or null at the terminal page.
    #[schemars(
        length(min = 1, max = 16_384),
        pattern(r"^/api/latest/admin/acknowledgement-policies")
    )]
    pub next_page_url: Option<String>,
}

/// Durable acknowledgement-policy creation result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAcknowledgementPolicyResponse {
    /// Exact idempotency identity whose result was resolved.
    pub operation_id: OperationId,
    /// Current created immutable policy.
    pub policy: AcknowledgementPolicySummary,
}

/// Bounded policy-list query, sharing the topology inventory cursor codec.
pub type ListPlacementPoliciesQuery = crate::ListTopologyQuery;

/// Opaque placement-policy continuation.
pub type PlacementPolicyCursor = TopologyCursor;
