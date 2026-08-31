// SPDX-License-Identifier: GPL-2.0-only

//! Public specialised-API contracts for atomic logical namespace mutations.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    DirectoryEntryKind, NamespaceCommitId, NamespacePath, ObjectId, ObjectRevisionId, OperationId,
    VolumeId,
};

/// Creates one empty logical directory at an exact path.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDirectoryRequest {
    /// Client-generated end-to-end idempotency identity.
    pub operation_id: OperationId,
    /// Root-relative path of the new empty directory.
    pub path: NamespacePath,
}

/// Durable result of one atomic empty-directory creation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDirectoryResponse {
    /// Exact operation which created or previously created the directory.
    pub operation_id: OperationId,
    /// Selected logical volume.
    pub volume_id: VolumeId,
    /// Exact created path.
    pub path: NamespacePath,
    /// Stable logical directory identity.
    pub object_id: ObjectId,
    /// Newly published immutable directory revision.
    pub object_revision_id: ObjectRevisionId,
    /// Namespace commit made current by the operation.
    pub namespace_commit_id: NamespaceCommitId,
    /// Resulting local branch-head sequence.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub head_sequence: u64,
}

/// Atomically renames or moves one object within a logical volume.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RenameObjectRequest {
    /// Client-generated end-to-end idempotency identity.
    pub operation_id: OperationId,
    /// Exact current root-relative path.
    pub source_path: NamespacePath,
    /// Exact unoccupied destination, or the same canonical name with changed display case.
    pub target_path: NamespacePath,
}

/// Durable result of one atomic same-volume rename or move.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RenameObjectResponse {
    /// Exact operation which moved or previously moved the object.
    pub operation_id: OperationId,
    /// Selected logical volume.
    pub volume_id: VolumeId,
    /// Exact source path named by the operation.
    pub source_path: NamespacePath,
    /// Exact resulting path.
    pub target_path: NamespacePath,
    /// Stable moved logical-object identity.
    pub object_id: ObjectId,
    /// Immutable object revision retained by the move.
    pub object_revision_id: ObjectRevisionId,
    /// Namespace commit made current by the operation.
    pub namespace_commit_id: NamespaceCommitId,
    /// Resulting local branch-head sequence.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub head_sequence: u64,
}

/// Logically deletes one exact current file or empty directory.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteObjectRequest {
    /// Client-generated end-to-end idempotency identity.
    pub operation_id: OperationId,
    /// Exact current root-relative path to remove.
    pub path: NamespacePath,
}

/// Honest durability scope reached by one successful delete response.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteObjectScope {
    /// The complete local/cell branch mutation is durably committed.
    BranchDeleted,
}

/// Durable result of one atomic logical namespace removal.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteObjectResponse {
    /// Exact operation which removed or previously removed the object.
    pub operation_id: OperationId,
    /// Selected logical volume.
    pub volume_id: VolumeId,
    /// Exact removed path.
    pub path: NamespacePath,
    /// Stable removed logical-object identity.
    pub object_id: ObjectId,
    /// Exact immutable object revision removed from the namespace.
    pub object_revision_id: ObjectRevisionId,
    /// Whether the removed object was a file or directory.
    pub object_kind: DirectoryEntryKind,
    /// Namespace commit made current by the operation.
    pub namespace_commit_id: NamespaceCommitId,
    /// Resulting local branch-head sequence.
    #[schemars(range(min = 1, max = 9_007_199_254_740_991_u64))]
    pub head_sequence: u64,
    /// Exact achieved scope; physical reclamation is intentionally separate.
    pub scope: DeleteObjectScope,
}
