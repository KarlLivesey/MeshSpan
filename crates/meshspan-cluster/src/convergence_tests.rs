// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId,
    OperationId, PrincipalId, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    FilePublication, ManifestPublication, NamespaceLimits, NamespacePath, NamespacePublicationPath,
    NamespaceReconciliationApplication, ReconciliationFrontier, ReconciliationLimits,
    RootFilePublication, VersionPublicationStore,
};
use meshspan_metadata::{AuthoritativeCommand, ConvergedHeadEvidence};
use tempfile::tempdir;

use crate::reconciliation_head_command;

#[test]
fn local_merge_receipt_becomes_one_exact_replicated_head_command()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(1))?;
    let first = publication(20, 21, 22, 23, "Report")?;
    let second = publication(30, 31, 32, 33, "Other")?;
    store.publish_root_file(&first)?;
    store.publish_root_file(&second)?;
    let frontier = ReconciliationFrontier {
        converged_head: Some(first.namespace_commit_id),
        eligible_heads: vec![second.namespace_commit_id],
    };
    let prepared =
        store.prepare_namespace_reconciliation(&frontier, ReconciliationLimits::DEFAULT)?;
    let receipt = store.apply_namespace_reconciliation(
        NamespaceReconciliationApplication {
            operation_id: OperationId::from_bytes([40; 16])?,
            namespace_commit_id: NamespaceCommitId::from_bytes([41; 16])?,
            created_by: first.file.created_by,
            created_at: UnixMicros::new(40),
        },
        &prepared,
    )?;
    let command = reconciliation_head_command(
        &store,
        first.file.volume_id,
        first.namespace_commit_id,
        receipt,
    )?;
    let AuthoritativeCommand::CommitConvergedVolumeHead(command) = command else {
        return Err("wrong authoritative command".into());
    };
    assert_eq!(command.volume_id, first.file.volume_id);
    assert_eq!(
        command.expected_namespace_commit_id,
        Some(first.namespace_commit_id)
    );
    assert_eq!(command.namespace_commit_id, receipt.namespace_commit_id);
    assert_eq!(
        command.root_object_revision_id,
        receipt.root_object_revision_id
    );
    assert_eq!(
        command.evidence,
        ConvergedHeadEvidence::Reconciliation {
            operation_id: receipt.operation_id,
            request_digest: receipt.request_digest,
            causal_plan_digest: receipt.causal_plan_digest,
            replay_plan_digest: receipt.replay_plan_digest,
            result_digest: receipt.result_digest,
        }
    );
    Ok(())
}

fn publication(
    identity: u8,
    branch: u8,
    commit: u8,
    root_revision: u8,
    name: &str,
) -> Result<RootFilePublication, Box<dyn std::error::Error>> {
    Ok(RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes([identity; 16])?,
            branch_id: BranchId::from_bytes([branch; 16])?,
            volume_id: VolumeId::from_bytes([10; 16])?,
            object_id: ObjectId::from_bytes([identity.saturating_add(1); 16])?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes([identity.saturating_add(2); 16])?,
            parent_version_id: None,
            manifest: ManifestPublication {
                manifest_id: ContentManifestId::from_bytes([identity.saturating_add(3); 16])?,
                format_version: 1,
                logical_length: 4,
                content_digest: [identity; 32],
                root_digest: [identity.saturating_add(4); 32],
            },
            created_by: PrincipalId::from_bytes([11; 16])?,
            created_at: UnixMicros::new(i64::from(identity)),
        },
        root_object_id: ObjectId::from_bytes([12; 16])?,
        expected_namespace_commit_id: None,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([identity.saturating_add(5); 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([root_revision; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([commit; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components([name], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
    })
}
