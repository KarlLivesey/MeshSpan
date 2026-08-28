// SPDX-License-Identifier: GPL-2.0-only

//! Verified local-reconciliation to replicated-volume-head command boundary.

use meshspan_domain::{NamespaceCommitId, Revision, VolumeId};
use meshspan_filesystem::{
    NamespaceReconciliationReceipt, PublicationError, SnapshotRestoreReceipt,
    VersionPublicationStore,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommitConvergedVolumeHead, ConvergedHeadEvidence, RestoreVolumeSnapshot,
};

/// Reloads exact local evidence and constructs the only replicated head command it proves.
///
/// # Errors
///
/// Rejects missing, substituted or corrupt local evidence, the wrong volume, or a merge that does
/// not causally include the presented current replicated head.
pub fn reconciliation_head_command(
    publications: &VersionPublicationStore,
    volume_id: VolumeId,
    expected_namespace_commit_id: NamespaceCommitId,
    receipt: NamespaceReconciliationReceipt,
) -> Result<AuthoritativeCommand, PublicationError> {
    let verified = publications.verify_reconciliation_head(
        volume_id,
        expected_namespace_commit_id,
        receipt,
    )?;
    let durable = verified.receipt();
    Ok(AuthoritativeCommand::CommitConvergedVolumeHead(
        CommitConvergedVolumeHead {
            volume_id: verified.volume_id(),
            expected_namespace_commit_id: Some(verified.expected_namespace_commit_id()),
            namespace_commit_id: durable.namespace_commit_id,
            root_object_revision_id: durable.root_object_revision_id,
            evidence: ConvergedHeadEvidence::Reconciliation {
                operation_id: durable.operation_id,
                request_digest: durable.request_digest,
                causal_plan_digest: durable.causal_plan_digest,
                replay_plan_digest: durable.replay_plan_digest,
                result_digest: durable.result_digest,
            },
        },
    ))
}

/// Reloads one prepared restore and constructs the authoritative snapshot-head transition.
///
/// # Errors
///
/// Rejects missing, substituted or corrupt local evidence and a commit from another volume.
pub fn snapshot_restore_head_command(
    publications: &VersionPublicationStore,
    volume_id: VolumeId,
    expected_snapshot_revision: Revision,
    receipt: SnapshotRestoreReceipt,
) -> Result<AuthoritativeCommand, PublicationError> {
    let verified = publications.verify_snapshot_restore_head(volume_id, receipt)?;
    let durable = verified.receipt();
    Ok(AuthoritativeCommand::RestoreVolumeSnapshot(
        RestoreVolumeSnapshot {
            snapshot_id: durable.snapshot_id,
            expected_snapshot_revision,
            volume_id: verified.volume_id(),
            snapshot_namespace_commit_id: durable.snapshot_namespace_commit_id,
            expected_namespace_commit_id: durable.expected_namespace_commit_id,
            namespace_commit_id: durable.namespace_commit_id,
            root_object_revision_id: durable.root_object_revision_id,
            source_operation_id: durable.operation_id,
            source_request_digest: durable.request_digest,
            source_result_digest: durable.result_digest,
        },
    ))
}
