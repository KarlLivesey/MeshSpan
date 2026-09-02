// SPDX-License-Identifier: GPL-2.0-only

//! Public manager-only data-survival policy administration models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{OperationId, TopologyCursor};

/// A bounded user-visible protection-policy or scenario name.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProtectionName(
    #[schemars(length(min = 1, max = 256), pattern(r"^[^\x00-\x1f\x2f\x7f\\]+$"))] String,
);

impl ProtectionName {
    /// Returns the untrusted domain name candidate.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One simultaneous failure count within a scenario.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionFailureTerm {
    /// Stable failure-class identity, including built-in machine and storage-device classes.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub class_id: String,
    /// Number of members of this failure class which may fail simultaneously.
    #[schemars(range(min = 1, max = 65_535))]
    pub failure_count: u16,
}

/// One alternative combined failure scenario the data must survive.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateProtectionScenario {
    /// User-visible scenario name.
    pub name: ProtectionName,
    /// Failure terms which occur together, such as two machines and three devices.
    #[schemars(length(min = 1, max = 16))]
    pub terms: Vec<ProtectionFailureTerm>,
}

/// Exact-retry request to create one immutable survival policy.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateProtectionPolicyRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// User-visible policy name.
    pub name: ProtectionName,
    /// Alternative combined failure scenarios; every scenario must remain decodable.
    #[schemars(length(min = 1, max = 16))]
    pub scenarios: Vec<CreateProtectionScenario>,
}

/// One committed failure term projected with its current class name.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionFailureTermSummary {
    /// Stable failure-class identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub class_id: String,
    /// User-visible failure-class name.
    #[schemars(length(min = 1, max = 128))]
    pub class_name: String,
    /// Simultaneous failures promised by this term.
    #[schemars(range(min = 1, max = 65_535))]
    pub failure_count: u16,
}

/// One named committed scenario.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionScenarioSummary {
    /// Stable scenario identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub scenario_id: String,
    /// User-visible scenario name.
    #[schemars(length(min = 1, max = 256))]
    pub name: String,
    /// Failure terms which happen together in this scenario.
    #[schemars(length(min = 1, max = 16))]
    pub terms: Vec<ProtectionFailureTermSummary>,
}

/// One immutable survival policy.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionPolicySummary {
    /// Stable policy identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub policy_id: String,
    /// User-visible policy name.
    #[schemars(length(min = 1, max = 256))]
    pub name: String,
    /// Alternative failure scenarios; every scenario is independently promised.
    #[schemars(length(min = 1, max = 16))]
    pub scenarios: Vec<ProtectionScenarioSummary>,
    /// Immutable authoritative policy revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded page of immutable survival policies.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListProtectionPoliciesResponse {
    /// Stable name-ordered policy summaries.
    #[schemars(length(max = 256))]
    pub policies: Vec<ProtectionPolicySummary>,
    /// Ready-to-follow same-origin URL, or null at the terminal page.
    #[schemars(
        length(min = 1, max = 16_384),
        pattern(r"^/api/latest/admin/protection-policies")
    )]
    pub next_page_url: Option<String>,
}

/// Durable survival-policy creation result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateProtectionPolicyResponse {
    /// Exact idempotency identity whose result was resolved.
    pub operation_id: OperationId,
    /// Current created immutable policy.
    pub policy: ProtectionPolicySummary,
}

/// Exact-retry request selecting an immutable policy for one volume.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssignVolumeProtectionPolicyRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
}

/// Durable volume survival-policy selection result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssignVolumeProtectionPolicyResponse {
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

/// Bounded policy-list query, sharing the topology inventory cursor codec.
pub type ListProtectionPoliciesQuery = crate::ListTopologyQuery;

/// Opaque policy-list continuation.
pub type ProtectionPolicyCursor = TopologyCursor;
