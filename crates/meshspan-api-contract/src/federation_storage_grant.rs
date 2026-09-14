// SPDX-License-Identifier: GPL-2.0-only

//! Native provider-owned storage offers, immutable replacement and withdrawal.

use crate::{NullableField, OperationId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Provider capacity ceiling and independent protection/serving classifications.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederationStorageGrantPolicy {
    /// Positive decimal bytes; domain admission also enforces the metadata integer range.
    #[schemars(length(min = 1, max = 19), pattern(r"^[1-9][0-9]{0,18}$"))]
    pub maximum_bytes: String,
    /// Whether verified placements may count towards protection; this alone proves no copies.
    pub counts_towards_protection: bool,
    /// Whether ordinary reads may query this storage, independently of backup/recovery reads.
    pub serves_reads: bool,
    /// Whether the recipient can re-offer an equal or narrower storage delegation.
    pub allow_downstream_delegation: bool,
}

/// Bounded explicit permission lifetime, separate from the retention of already-stored bytes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FederationStorageGrantLifetime(#[schemars(range(min = 60, max = 31_536_000))] pub u32);

/// One exact immutable grant change; only the provider's own direct storage grants are editable.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FederationStorageGrantChange {
    /// Offers local capacity to an already paired swarm; does not configure its backups.
    Issue {
        /// Client-chosen unused grant identity.
        grant_id: OperationId,
        /// Existing mutually approved relationship, not a node join grant.
        relationship_id: OperationId,
        /// This provider's offered upper bound; consumer-local limits remain independent.
        policy: FederationStorageGrantPolicy,
        /// Omitted means 30 days; null explicitly means indefinite authority.
        #[serde(default, skip_serializing_if = "NullableField::is_missing")]
        valid_for_seconds: NullableField<FederationStorageGrantLifetime>,
    },
    /// Replaces one immutable grant and preserves its existing allocation/storage lineage.
    Replace {
        /// Exact previous grant; its current state is fenced by the request's metadata revision.
        predecessor_grant_id: OperationId,
        /// New unused grant identity.
        grant_id: OperationId,
        /// New provider ceiling, still intersected with every retained peer restriction.
        policy: FederationStorageGrantPolicy,
        /// Omitted means 30 days; null explicitly means indefinite authority.
        #[serde(default, skip_serializing_if = "NullableField::is_missing")]
        valid_for_seconds: NullableField<FederationStorageGrantLifetime>,
        /// True requires an equal or narrower effective policy; false is renewal/reconfiguration.
        restricts_authority: bool,
        /// Non-secret administrator explanation.
        #[schemars(length(min = 1, max = 512), pattern(r"^\P{Cc}+$"))]
        reason: String,
    },
    /// Withdraws future authority; does not physically delete retained encrypted objects.
    Revoke {
        /// Exact grant to withdraw.
        grant_id: OperationId,
        /// Non-secret administrator explanation.
        #[schemars(length(min = 1, max = 512), pattern(r"^\P{Cc}+$"))]
        reason: String,
    },
}

/// Exact-retry mutation against an observed root-metadata revision.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigureFederationStorageGrantRequest {
    /// Stable operation identity, never reused for changed input.
    pub operation_id: OperationId,
    /// Root revision returned by the grant lookup; concurrent changes return conflict.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub expected_metadata_revision: u64,
    /// Exact provider-owned change.
    pub change: FederationStorageGrantChange,
}

/// Durable original mutation receipt, not a claim of transferred or protected bytes.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigureFederationStorageGrantResponse {
    /// Original operation identity.
    pub operation_id: OperationId,
    /// Created, replaced or withdrawn grant identity.
    pub grant_id: OperationId,
    /// Original commit revision, retained on exact retry.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub committed_revision: u64,
}

/// Exact lookup rather than a collection scan; absent grants return null for creation planning.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederationStorageGrantQuery {
    /// Exact identity to inspect.
    pub grant_id: OperationId,
}

/// Current provider offer, without secrets, storage paths or remote user identities.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationStorageGrantState {
    /// Not terminated; callers must also observe its validity interval.
    Active,
    /// Replaced by the exact successor in the response.
    Superseded,
    /// Explicitly withdrawn without a successor.
    Revoked,
}

/// Current provider offer, without secrets, storage paths or remote user identities.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederationStorageGrantSummary {
    /// Exact immutable identity.
    pub grant_id: OperationId,
    /// Paired swarm relationship.
    pub relationship_id: OperationId,
    /// Effective intersection, not necessarily the provider's original requested maximum.
    pub policy: FederationStorageGrantPolicy,
    /// Active, superseded or revoked grants remain visible to current managers.
    pub state: FederationStorageGrantState,
    /// Original first authorised instant.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_i64))]
    pub valid_from_epoch_micros: i64,
    /// Null represents explicitly indefinite authority.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_i64))]
    pub valid_until_epoch_micros: Option<i64>,
    /// Replacement identity when this historical grant has a successor.
    pub successor_grant_id: Option<OperationId>,
    /// Last change of this grant record.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
}

/// Revision-consistent exact lookup; current authentication is applied on every call.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FederationStorageGrantResponse {
    /// Root revision for the next conditional mutation.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub metadata_revision: u64,
    /// Null means this identity has not been issued in the provider's authority.
    pub grant: Option<FederationStorageGrantSummary>,
}
