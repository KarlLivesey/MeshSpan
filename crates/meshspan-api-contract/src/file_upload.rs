// SPDX-License-Identifier: GPL-2.0-only

//! Public models for `MeshSpan`'s native resumable file-upload API.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{FileVersionId, GetObjectResponse, NamespacePath, ObjectId, OperationId, VolumeId};

/// Largest raw byte range accepted by one upload request.
pub const MAX_UPLOAD_RANGE_BYTES: usize = 8 * 1_024 * 1_024;

/// Opaque identifier of one durable resumable upload.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct UploadId(
    #[schemars(
        length(equal = 36),
        pattern(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    )]
    String,
);

impl UploadId {
    /// Parses exact canonical versioned UUID text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        crate::directory_listing::parse_public_uuid(value).map(Self)
    }

    /// Constructs canonical UUID text from validated versioned UUID bytes.
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

/// Namespace precondition applied by the final atomic commit.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum UploadDisposition {
    /// Commit only when the destination is absent.
    CreateNew,
    /// Replace whichever immutable version is current when commit authority is acquired.
    ReplaceCurrent,
    /// Replace exactly the supplied immutable version or report a conflict.
    ReplaceIfVersion {
        /// Required current immutable version.
        version_id: FileVersionId,
    },
}

/// Durable upload lifecycle exposed to clients.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadState {
    /// Bounded range writes are accepted.
    Active,
    /// One exact complete checkpoint is being published.
    Committing,
    /// Immutable content and namespace state are published.
    Committed,
    /// Private bytes were abandoned and can never publish.
    Aborted,
}

/// Starts one durable private upload session.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BeginUploadRequest {
    /// Client-generated idempotency identity.
    pub operation_id: OperationId,
    /// Canonical root-relative destination path.
    pub path: NamespacePath,
    /// Final namespace precondition.
    pub disposition: UploadDisposition,
    /// Hard maximum logical file bytes reserved for this upload.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub maximum_bytes: u64,
}

/// Common exact upload state returned after every lifecycle operation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UploadStatusResponse {
    /// Opaque upload identity.
    pub upload_id: UploadId,
    /// Selected logical volume.
    pub volume_id: VolumeId,
    /// Canonical destination path.
    pub path: NamespacePath,
    /// Current durable lifecycle state.
    pub state: UploadState,
    /// Positive current writer fence.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub stage_fence: u64,
    /// Hard maximum logical file bytes.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub maximum_bytes: u64,
    /// Exact current private-stage mutation sequence.
    #[schemars(range(max = 9_007_199_254_740_991_u64))]
    pub checkpoint_sequence: u64,
    /// Highest byte written, exclusive; this does not imply gap-free coverage.
    #[schemars(range(max = 9_007_199_254_740_991_u64))]
    pub logical_extent: u64,
    /// Exclusive server-authoritative expiry as Unix epoch microseconds.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_i64))]
    pub expires_at_epoch_micros: i64,
    /// Stable object published by a committed upload; otherwise null.
    pub committed_object_id: Option<ObjectId>,
    /// Immutable version published by a committed upload; otherwise null.
    pub committed_version_id: Option<FileVersionId>,
    /// Absolute-path reference for bounded exact received-range pages.
    #[schemars(length(min = 1, max = 4096), pattern(r"^/api/"))]
    pub ranges_url: String,
}

/// Opaque continuation for one immutable upload-checkpoint range view.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct UploadRangeCursor(
    #[schemars(length(min = 1, max = 1024), pattern(r"^[A-Za-z0-9._~-]+$"))] String,
);

impl UploadRangeCursor {
    /// Constructs one bounded cursor from its already URL-safe encoded form.
    #[must_use]
    pub fn from_encoded(value: String) -> Option<Self> {
        let valid = !value.is_empty()
            && value.len() <= 1024
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte));
        valid.then_some(Self(value))
    }

    /// Returns the opaque cursor text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One bounded page query over exact received ranges.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListUploadRangesQuery {
    /// Continuation returned by the preceding page.
    pub cursor: Option<UploadRangeCursor>,
    /// Requested page bound; omission selects the server default.
    #[schemars(range(min = 1, max = 256))]
    pub limit: Option<u16>,
}

/// One exact non-empty initialised byte range, end-exclusive.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UploadRange {
    /// First initialised byte.
    #[schemars(range(max = 9_007_199_254_740_991_u64))]
    pub start: u64,
    /// Exclusive end, strictly greater than start.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub end: u64,
}

/// Bounded exact coverage page pinned to one upload checkpoint.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListUploadRangesResponse {
    /// Selected upload.
    pub upload_id: UploadId,
    /// Immutable stage sequence represented by every page in this traversal.
    #[schemars(range(max = 9_007_199_254_740_991_u64))]
    pub checkpoint_sequence: u64,
    /// Sorted, non-overlapping, non-adjacent exact received ranges.
    #[schemars(length(max = 256))]
    pub ranges: Vec<UploadRange>,
    /// Complete next-page URL under current authority, or null at the end.
    #[schemars(length(min = 1, max = 4096), pattern(r"^/api/"))]
    pub next_page_url: Option<String>,
}

/// Starts and returns one ready durable upload.
pub type BeginUploadResponse = UploadStatusResponse;

/// Acknowledges one bounded raw range and the resulting exact checkpoint.
pub type WriteUploadRangeResponse = UploadStatusResponse;

/// Explicit final publication request for one complete checkpoint.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommitUploadRequest {
    /// Client-generated idempotency identity.
    pub operation_id: OperationId,
    /// Exact current positive writer fence.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub stage_fence: u64,
    /// Exact checkpoint sequence; later writes make this request stale.
    #[schemars(range(max = 9_007_199_254_740_991_u64))]
    pub expected_sequence: u64,
    /// Exact final logical file length.
    #[schemars(range(max = 9_007_199_254_740_991_u64))]
    pub final_length: u64,
    /// Whether uncovered ranges are intentional logical zeroes.
    pub sparse: bool,
    /// Optional independently checked BLAKE3 digest of the complete logical file.
    #[schemars(length(equal = 64), pattern(r"^[0-9a-f]{64}$"))]
    pub expected_blake3: Option<String>,
}

/// Strongest durable scope honestly proved by one successful publication.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteDurabilityScope {
    /// Required bytes and the immutable branch record are durable on one node.
    NodeLocal,
    /// Required bytes satisfy a multi-target, multi-node or availability-cell predicate.
    CellReplicated,
    /// A strong policy and its globally converged namespace transition both committed.
    GloballyConverged,
}

/// Immutable proof summary for the exact successful write acknowledgement.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WriteAcknowledgement {
    /// Honest durability scope reached by this publication.
    pub durability_scope: WriteDurabilityScope,
    /// True only after every predicate required by the selected policy has committed.
    pub policy_committed: bool,
    /// Number of required durable shard receipts included in the achieved evidence.
    #[schemars(range(max = 9_007_199_254_740_991_u64))]
    pub required_shard_receipts: u64,
    /// Number of non-blocking shard placements already completed.
    #[schemars(range(max = 9_007_199_254_740_991_u64))]
    pub eventual_shard_receipts: u64,
    /// Number of non-blocking shard placements still owed by automatic reconciliation.
    #[schemars(range(max = 9_007_199_254_740_991_u64))]
    pub pending_eventual_shards: u64,
    /// BLAKE3 digest binding the fixed-revision acknowledgement predicates.
    #[schemars(length(equal = 64), pattern(r"^[0-9a-f]{64}$"))]
    pub policy_evidence_blake3: String,
    /// BLAKE3 digest binding the exact durable shard receipts.
    #[schemars(length(equal = 64), pattern(r"^[0-9a-f]{64}$"))]
    pub achieved_protection_blake3: String,
    /// BLAKE3 digest binding the exact non-blocking shard debt at acknowledgement.
    #[schemars(length(equal = 64), pattern(r"^[0-9a-f]{64}$"))]
    pub pending_debt_blake3: String,
}

/// Complete successful upload publication.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommitUploadResponse {
    /// Terminal upload state.
    pub upload: UploadStatusResponse,
    /// Immutable metadata for the newly published exact version.
    pub object: GetObjectResponse,
    /// Exact policy, receipt and outstanding-debt evidence for the success response.
    pub acknowledgement: WriteAcknowledgement,
}

/// Permanently abandons one unpublished upload.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AbortUploadRequest {
    /// Client-generated idempotency identity.
    pub operation_id: OperationId,
    /// Exact current positive writer fence.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub stage_fence: u64,
}

/// Terminal abandoned upload state.
pub type AbortUploadResponse = UploadStatusResponse;
