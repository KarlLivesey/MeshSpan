// SPDX-License-Identifier: GPL-2.0-only

//! Public administrator direct-group-membership models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{NullableField, OperationId, PrincipalId, PrincipalSummary};

/// An opaque, bounded continuation for one direct-membership page.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct GroupMembershipCursor(
    #[schemars(length(min = 1, max = 1_024), pattern(r"^[A-Za-z0-9._~-]+$"))] String,
);

impl GroupMembershipCursor {
    /// Constructs a cursor that has passed the authoritative cursor codec.
    #[must_use]
    pub fn from_encoded(value: String) -> Option<Self> {
        let valid_length = (1..=1_024).contains(&value.len());
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

/// One bounded direct-group-membership query.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListGroupMembershipsQuery {
    /// Exact continuation returned by the preceding page.
    pub cursor: Option<GroupMembershipCursor>,
    /// Requested result bound; omission applies the server default.
    #[schemars(range(min = 1, max = 256))]
    pub limit: Option<u16>,
}

/// One exact public membership validity instant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct GroupMembershipInstant(#[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))] i64);

impl GroupMembershipInstant {
    /// Returns the untrusted epoch-microsecond value.
    #[must_use]
    pub const fn epoch_micros(self) -> i64 {
        self.0
    }
}

/// A non-blank bounded reason for removing authority-bearing membership.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct GroupMembershipRemovalReason(
    #[schemars(length(min = 1, max = 512), pattern(r"^\S(?:[\s\S]*\S)?$"))] String,
);

impl GroupMembershipRemovalReason {
    /// Returns the validated audit-reason candidate.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_domain_candidate(&self) -> bool {
        self.0 == self.0.trim() && (1..=512).contains(&self.0.len())
    }
}

/// One active direct membership with enough data for a bounded administration view.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMembershipSummary {
    /// Structurally containing group.
    pub group_id: PrincipalId,
    /// Direct user or nested-group member.
    pub member: PrincipalSummary,
    /// Inclusive validity start, or null when unbounded below.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub valid_from_epoch_micros: Option<i64>,
    /// Exclusive validity end, or null when unbounded above.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub valid_until_epoch_micros: Option<i64>,
    /// Whether the affected user must activate this membership before it contributes rights.
    pub activation_required: bool,
    /// Administrator that originally created the current edge.
    pub created_by: PrincipalId,
    /// Original authoritative creation instant.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub created_at_epoch_micros: i64,
    /// Last authoritative membership revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// One bounded, stable direct-membership page.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListGroupMembershipsResponse {
    /// Group whose direct edges are represented.
    pub group_id: PrincipalId,
    /// Direct active memberships ordered by stable member identity.
    #[schemars(length(max = 256))]
    pub memberships: Vec<GroupMembershipSummary>,
    /// Ready-to-follow relative URL, or null at the terminal page.
    #[schemars(length(min = 1, max = 16_384), pattern(r"^/api/latest/admin/groups/"))]
    pub next_page_url: Option<String>,
}

/// Idempotent administrator request to add one direct user or nested-group member.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddGroupMemberRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// Direct user or group to add.
    pub member_principal_id: PrincipalId,
    /// Omitted applies policy defaults, null is unbounded, and a value is exact.
    #[serde(default, skip_serializing_if = "NullableField::is_missing")]
    pub valid_from_epoch_micros: NullableField<GroupMembershipInstant>,
    /// Omitted applies policy defaults, null is unbounded, and a value is exact.
    #[serde(default, skip_serializing_if = "NullableField::is_missing")]
    pub valid_until_epoch_micros: NullableField<GroupMembershipInstant>,
    /// Whether this edge requires explicit, reasoned, time-bounded user activation.
    pub activation_required: bool,
}

/// Durable result of adding or exactly replaying one direct membership.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddGroupMemberResponse {
    /// Exact idempotency identity whose committed result was resolved.
    pub operation_id: OperationId,
    /// Newly active or exactly replayed direct membership.
    pub membership: GroupMembershipSummary,
}

/// Idempotent administrator request to remove one exact active direct membership.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveGroupMemberRequest {
    /// Client-generated exact-retry identity.
    pub operation_id: OperationId,
    /// Human-readable audit reason retained with the removal evidence.
    pub reason: GroupMembershipRemovalReason,
}

/// Durable result of removing or exactly replaying one direct membership.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveGroupMemberResponse {
    /// Exact idempotency identity whose committed result was resolved.
    pub operation_id: OperationId,
    /// Structurally containing group.
    pub group_id: PrincipalId,
    /// Direct user or group removed from it.
    pub member_principal_id: PrincipalId,
    /// Original authoritative removal instant used by exact retries.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub removed_at_epoch_micros: i64,
    /// Authoritative removal revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}
