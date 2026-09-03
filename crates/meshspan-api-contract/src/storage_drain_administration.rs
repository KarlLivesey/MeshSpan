// SPDX-License-Identifier: GPL-2.0-only

//! Public manager-only storage-drain models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::OperationId;

/// Generation-fenced storage scope selected for graceful removal.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum StorageDrainScope {
    /// One exact storage-folder generation.
    Target {
        /// Stable target identity.
        #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
        target_id: String,
        /// Exact generation so path reuse cannot inherit a drain.
        #[schemars(length(min = 1, max = 20), pattern(r"^[1-9][0-9]{0,19}$"))]
        generation: String,
    },
    /// One exact daemon incarnation and all of its storage folders.
    Node {
        /// Stable daemon identity.
        #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
        node_id: String,
        /// Exact restart incarnation.
        #[schemars(length(min = 1, max = 20), pattern(r"^[1-9][0-9]{0,19}$"))]
        incarnation: String,
    },
    /// Every machine and folder currently inside one frozen shared-failure group.
    FaultGroup {
        /// Stable fault-group identity.
        #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
        fault_group_id: String,
    },
}

/// Durable storage-drain lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageDrainState {
    /// New placement is fenced while protected bytes evacuate.
    Evacuating,
    /// An evacuated node is leaving metadata consensus.
    MembershipFenced,
    /// Authority has committed exact evidence that the scope may be detached.
    SafeToDetach,
}

/// Exact-retry request to start one safe storage drain.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BeginStorageDrainRequest {
    /// Client-generated idempotency identity; also becomes the stable drain identity.
    pub operation_id: OperationId,
    /// Exact target, node incarnation or fault group to remove.
    pub scope: StorageDrainScope,
    /// Permit safe removal while desired redundancy is temporarily degraded.
    pub allow_temporary_degraded: bool,
    /// Reclaim physical shard bytes after the safe-to-detach proof commits.
    pub cleanup_requested: bool,
}

/// One current manager-visible storage drain.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageDrainSummary {
    /// Stable drain identity.
    #[schemars(length(equal = 36), pattern(r"^[0-9a-f-]{36}$"))]
    pub drain_id: String,
    /// Exact fenced scope.
    pub scope: StorageDrainScope,
    /// Whether temporary protection debt was accepted.
    pub allow_temporary_degraded: bool,
    /// Whether post-proof physical cleanup was requested.
    pub cleanup_requested: bool,
    /// Current authoritative lifecycle.
    pub state: StorageDrainState,
    /// Authority-agreed admission instant.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub requested_at_epoch_micros: i64,
    /// Terminal safe instant, or null until detachment is proved safe.
    #[schemars(range(min = 0, max = 9_007_199_254_740_991_i64))]
    pub safe_at_epoch_micros: Option<i64>,
    /// Latest authoritative revision.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub revision: u64,
    /// Ready-to-follow current-status URL.
    #[schemars(
        length(min = 1, max = 512),
        pattern(r"^/api/latest/admin/storage-drains/")
    )]
    pub status_url: String,
}

/// Durable result returned after drain admission.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BeginStorageDrainResponse {
    /// Exact idempotency identity whose result was resolved.
    pub operation_id: OperationId,
    /// Current admitted drain.
    pub drain: StorageDrainSummary,
}

/// Opaque continuation for newest-first drain inventory.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct StorageDrainCursor(
    #[schemars(length(min = 1, max = 256), pattern(r"^[A-Za-z0-9._~-]+$"))] String,
);

impl StorageDrainCursor {
    /// Constructs one cursor after bounded-alphabet validation.
    #[must_use]
    pub fn from_encoded(value: String) -> Option<Self> {
        ((1..=256).contains(&value.len())
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

/// Bounded newest-first storage-drain query.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListStorageDrainsQuery {
    /// Exact continuation returned by the preceding page.
    pub cursor: Option<StorageDrainCursor>,
    /// Requested page bound; omission applies the server default.
    #[schemars(range(min = 1, max = 200))]
    pub limit: Option<u16>,
}

/// One current manager-only storage-drain page.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListStorageDrainsResponse {
    /// Newest-first authoritative drain summaries.
    #[schemars(length(max = 200))]
    pub drains: Vec<StorageDrainSummary>,
    /// Ready-to-follow same-origin URL, or null at the terminal page.
    #[schemars(
        length(min = 1, max = 16_384),
        pattern(r"^/api/latest/admin/storage-drains")
    )]
    pub next_page_url: Option<String>,
}
