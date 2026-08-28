// SPDX-License-Identifier: GPL-2.0-only

//! Canonical cross-layer filesystem evidence digests.

use meshspan_domain::{NamespaceCommitId, ObjectRevisionId, OperationId, SnapshotId};

/// Binds the complete durable result of one local namespace reconciliation transaction.
#[must_use]
pub fn namespace_reconciliation_result_digest(
    operation_id: OperationId,
    namespace_commit_id: NamespaceCommitId,
    request_digest: [u8; 32],
    causal_plan_digest: [u8; 32],
    replay_plan_digest: [u8; 32],
    root_object_revision_id: ObjectRevisionId,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.namespace-reconciliation-result.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&causal_plan_digest);
    digest.update(&replay_plan_digest);
    digest.update(&namespace_commit_id.as_bytes());
    digest.update(&root_object_revision_id.as_bytes());
    digest.finalize().into()
}

/// Binds the complete durable result of one prepared whole-volume snapshot restore.
#[must_use]
pub fn namespace_snapshot_restore_result_digest(
    operation_id: OperationId,
    request_digest: [u8; 32],
    snapshot_id: SnapshotId,
    snapshot_namespace_commit_id: NamespaceCommitId,
    expected_namespace_commit_id: NamespaceCommitId,
    namespace_commit_id: NamespaceCommitId,
    root_object_revision_id: ObjectRevisionId,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.namespace-snapshot-restore-result.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&snapshot_id.as_bytes());
    digest.update(&snapshot_namespace_commit_id.as_bytes());
    digest.update(&expected_namespace_commit_id.as_bytes());
    digest.update(&namespace_commit_id.as_bytes());
    digest.update(&root_object_revision_id.as_bytes());
    digest.finalize().into()
}
