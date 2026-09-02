// SPDX-License-Identifier: GPL-2.0-only

//! Public manager-only mesh topology administration models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{OperationId, StorageFolderUsageLimit};

/// Opaque continuation for any topology inventory endpoint.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TopologyCursor(
    #[schemars(length(min = 1, max = 1_024), pattern(r"^[A-Za-z0-9._~-]+$"))] String,
);

impl TopologyCursor {
    /// Constructs one cursor after server-side codec validation.
    #[must_use]
    pub fn from_encoded(value: String) -> Option<Self> {
        ((1..=1_024).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte)))
        .then_some(Self(value))
    }

    /// Returns the opaque cursor text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded topology inventory query.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListTopologyQuery {
    /// Exact continuation returned by the preceding page.
    pub cursor: Option<TopologyCursor>,
    /// Requested page bound; omission applies the server default.
    #[schemars(range(min = 1, max = 256))]
    pub limit: Option<u16>,
}

/// Current lifecycle state of one daemon node.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyNodeState {
    /// Admitted learner not yet serving its full role set.
    Joining,
    /// Active mesh member.
    Active,
    /// Gracefully leaving or draining.
    Draining,
    /// Terminally retired.
    Retired,
}

/// Public role projection of one daemon node.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyNodeRoles {
    /// May host encrypted storage shards.
    pub storage: bool,
    /// May expose configured access protocols.
    pub gateway: bool,
    /// Eligible for metadata learner/voter placement.
    pub metadata_eligible: bool,
}

/// One daemon and its physical machine boundary.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyNodeSummary {
    /// Stable daemon identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub node_id: String,
    /// Stable machine identity shared by daemons on the same machine.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub host_id: String,
    /// User-visible node name.
    #[schemars(length(min = 1, max = 256))]
    pub display_name: String,
    /// Current lifecycle state.
    pub state: TopologyNodeState,
    /// Current restart incarnation as lossless positive decimal text.
    #[schemars(length(min = 1, max = 20), pattern(r"^[1-9][0-9]{0,19}$"))]
    pub incarnation: String,
    /// Configured daemon roles.
    pub roles: TopologyNodeRoles,
    /// Private mesh endpoint once activated.
    #[schemars(length(min = 3, max = 512))]
    pub private_endpoint: Option<String>,
    /// Last authoritative metadata revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded page of daemon nodes.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListTopologyNodesResponse {
    /// Stable name-ordered node summaries.
    #[schemars(length(max = 256))]
    pub nodes: Vec<TopologyNodeSummary>,
    /// Ready-to-follow same-origin URL, or null at the terminal page.
    #[schemars(
        length(min = 1, max = 16_384),
        pattern(r"^/api/latest/admin/topology/nodes")
    )]
    pub next_page_url: Option<String>,
}

/// Current lifecycle state of one mesh-wide storage target.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyTargetState {
    /// Registration is not yet available for placement.
    Configuring,
    /// Target may accept and serve shards.
    Active,
    /// New placement is disabled while data leaves.
    Draining,
    /// Target is temporarily unavailable.
    Unavailable,
    /// Terminally retired.
    Retired,
}

/// One mesh-wide target; its node-local filesystem path is deliberately absent.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TopologyTargetSummary {
    /// Stable target identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub target_id: String,
    /// Owning daemon identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub node_id: String,
    /// Owning machine identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub host_id: String,
    /// User-visible target name.
    #[schemars(length(min = 1, max = 256))]
    pub display_name: String,
    /// Current target state.
    pub state: TopologyTargetState,
    /// Current authority-fenced generation as lossless positive decimal text.
    #[schemars(length(min = 1, max = 20), pattern(r"^[1-9][0-9]{0,19}$"))]
    pub generation: String,
    /// Current provider-owned capacity ceiling.
    pub usage_limit: StorageFolderUsageLimit,
    /// Last authoritative metadata revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded page of mesh-wide targets.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListTopologyTargetsResponse {
    /// Stable name-ordered target summaries.
    #[schemars(length(max = 256))]
    pub targets: Vec<TopologyTargetSummary>,
    /// Ready-to-follow same-origin URL, or null at the terminal page.
    #[schemars(
        length(min = 1, max = 16_384),
        pattern(r"^/api/latest/admin/topology/targets")
    )]
    pub next_page_url: Option<String>,
}

/// A bounded display name for a shared-failure class.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FaultGroupClassName(
    #[schemars(length(min = 1, max = 128), pattern(r"^[^\x00-\x1f\x2f\x7f\\]+$"))] String,
);

impl FaultGroupClassName {
    /// Returns the untrusted domain name candidate.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A bounded display name for one concrete shared-failure group.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FaultGroupName(
    #[schemars(length(min = 1, max = 256), pattern(r"^[^\x00-\x1f\x2f\x7f\\]+$"))] String,
);

impl FaultGroupName {
    /// Returns the untrusted domain name candidate.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One named shared machine-failure boundary.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FaultGroupSummary {
    /// Stable failure-class identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub class_id: String,
    /// User-visible failure-class name, such as room or power source.
    #[schemars(length(min = 1, max = 128))]
    pub class_name: String,
    /// Stable concrete group identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub group_id: String,
    /// User-visible concrete boundary name.
    #[schemars(length(min = 1, max = 256))]
    pub group_name: String,
    /// Last authoritative metadata revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded page of shared-failure groups.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListFaultGroupsResponse {
    /// Stable class/name-ordered groups.
    #[schemars(length(max = 256))]
    pub groups: Vec<FaultGroupSummary>,
    /// Ready-to-follow same-origin URL, or null at the terminal page.
    #[schemars(
        length(min = 1, max = 16_384),
        pattern(r"^/api/latest/admin/topology/fault-groups")
    )]
    pub next_page_url: Option<String>,
}

/// One overlapping machine/group membership edge.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FaultGroupMembershipSummary {
    /// Member machine identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub host_id: String,
    /// Shared-failure group identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub group_id: String,
    /// Last authoritative edge revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded page of overlapping membership edges.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListFaultGroupMembershipsResponse {
    /// Stable machine/group-ordered membership edges.
    #[schemars(length(max = 256))]
    pub memberships: Vec<FaultGroupMembershipSummary>,
    /// Ready-to-follow same-origin URL, or null at the terminal page.
    #[schemars(
        length(min = 1, max = 16_384),
        pattern(r"^/api/latest/admin/topology/fault-group-memberships")
    )]
    pub next_page_url: Option<String>,
}

/// Exact-retry request to create one shared-failure group.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFaultGroupRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// Failure-boundary class, such as room, building, PSU or hypervisor.
    pub class_name: FaultGroupClassName,
    /// Concrete group within that class.
    pub group_name: FaultGroupName,
}

/// Durable shared-failure-group creation result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFaultGroupResponse {
    /// Exact idempotency identity whose result was resolved.
    pub operation_id: OperationId,
    /// Current created group.
    pub group: FaultGroupSummary,
}

/// Exact-retry desired machine/group membership.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetFaultGroupMembershipRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// `true` to add the machine or `false` to remove it.
    pub present: bool,
}

/// Durable desired-membership result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetFaultGroupMembershipResponse {
    /// Exact idempotency identity whose result was resolved.
    pub operation_id: OperationId,
    /// Machine identity from the route.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub host_id: String,
    /// Group identity from the route.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub group_id: String,
    /// Current desired membership state.
    pub present: bool,
    /// Authoritative mutation revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One named availability locality used by placement and acknowledgement policy.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AvailabilityCellSummary {
    /// Stable cell identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub cell_id: String,
    /// User-visible cell name.
    #[schemars(length(min = 1, max = 256))]
    pub name: String,
    /// Optional parent used for presentation and inherited target membership.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub parent_cell_id: Option<String>,
    /// Last authoritative metadata revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded page of availability localities.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListAvailabilityCellsResponse {
    /// Stable name-ordered cells.
    #[schemars(length(max = 256))]
    pub cells: Vec<AvailabilityCellSummary>,
    /// Ready-to-follow same-origin URL, or null at the terminal page.
    #[schemars(
        length(min = 1, max = 16_384),
        pattern(r"^/api/latest/admin/topology/availability-cells")
    )]
    pub next_page_url: Option<String>,
}

/// Exact-retry request to create one availability locality.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAvailabilityCellRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// Human-readable locality name.
    pub name: FaultGroupName,
    /// Optional existing parent cell.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub parent_cell_id: Option<String>,
}

/// Durable availability-cell creation result.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAvailabilityCellResponse {
    /// Exact idempotency identity whose result was resolved.
    pub operation_id: OperationId,
    /// Current created cell.
    pub cell: AvailabilityCellSummary,
}

/// Durable desired membership of a machine or target in one availability cell.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetAvailabilityCellMembershipResponse {
    /// Exact idempotency identity whose result was resolved.
    pub operation_id: OperationId,
    /// Availability-cell identity from the route.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub cell_id: String,
    /// Machine or target identity from the route.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub member_id: String,
    /// `true` when the member is present after this operation.
    pub present: bool,
    /// Authoritative mutation revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}
