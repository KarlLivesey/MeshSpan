// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, transactional exchange of disconnected mutation history.

#[path = "transfer/commit_import.rs"]
mod commit_import;
#[path = "transfer/export.rs"]
pub(in crate::publication) mod export;
#[path = "transfer/export_graph.rs"]
pub(in crate::publication) mod export_graph;
#[path = "transfer/import.rs"]
pub(in crate::publication) mod import;

use meshspan_domain::{
    BranchId, ContentManifestId, FederatedMutationAcknowledgement, FileVersionId,
    NamespaceCommitId, ObjectId, OperationId, PrincipalId, UnixMicros, VolumeId,
};

use crate::{BranchMutationIntent, ReconciliationCommit};

pub(in crate::publication) use export::export_history;
pub(in crate::publication) use import::{import_federated_history, import_history};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::publication) struct TransferredFileVersion {
    pub(in crate::publication) version_id: FileVersionId,
    pub(in crate::publication) branch_id: BranchId,
    pub(in crate::publication) volume_id: VolumeId,
    pub(in crate::publication) object_id: ObjectId,
    pub(in crate::publication) parent_version_id: Option<FileVersionId>,
    pub(in crate::publication) manifest_id: ContentManifestId,
    pub(in crate::publication) logical_length: u64,
    pub(in crate::publication) content_digest: [u8; 32],
    pub(in crate::publication) created_by: PrincipalId,
    pub(in crate::publication) created_at: UnixMicros,
    pub(in crate::publication) operation_id: OperationId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::publication) struct TransferredNamespaceCommit {
    pub(in crate::publication) commit: ReconciliationCommit,
    pub(in crate::publication) created_by: PrincipalId,
    pub(in crate::publication) created_at: UnixMicros,
    pub(in crate::publication) commit_digest: [u8; 32],
    pub(in crate::publication) evidence: CommitEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::publication) enum CommitEvidence {
    Mutation {
        intent: BranchMutationIntent,
        acknowledgement: Option<Box<FederatedMutationAcknowledgement>>,
    },
    Merge {
        causal_plan_digest: [u8; 32],
        result_digest: [u8; 32],
    },
    Restore {
        result_digest: [u8; 32],
    },
}

impl TransferredNamespaceCommit {
    pub(in crate::publication) fn acknowledgement(
        &self,
    ) -> Option<FederatedMutationAcknowledgement> {
        match &self.evidence {
            CommitEvidence::Mutation {
                acknowledgement, ..
            } => acknowledgement.as_deref().copied(),
            CommitEvidence::Merge { .. } | CommitEvidence::Restore { .. } => None,
        }
    }

    pub(in crate::publication) fn intent(&self) -> Option<&BranchMutationIntent> {
        match &self.evidence {
            CommitEvidence::Mutation { intent, .. } => Some(intent),
            CommitEvidence::Merge { .. } | CommitEvidence::Restore { .. } => None,
        }
    }

    /// Restore sources are immutable dependencies, not additional causal parents.
    pub(in crate::publication) fn dependencies(
        &self,
    ) -> impl Iterator<Item = NamespaceCommitId> + '_ {
        let snapshot = match self.commit.payload {
            crate::ReconciliationCommitPayload::Restore {
                snapshot_namespace_commit_id,
                ..
            } => Some(snapshot_namespace_commit_id),
            crate::ReconciliationCommitPayload::Mutation { .. }
            | crate::ReconciliationCommitPayload::Merge { .. } => None,
        };
        self.commit.parents.iter().copied().chain(snapshot)
    }

    pub(in crate::publication) fn restore_publication(
        &self,
    ) -> Result<crate::SnapshotRestorePublication, crate::PublicationError> {
        let crate::ReconciliationCommitPayload::Restore {
            snapshot_id,
            snapshot_namespace_commit_id,
        } = self.commit.payload
        else {
            return Err(crate::PublicationError::InvalidInput);
        };
        let [expected_namespace_commit_id] = self.commit.parents.as_slice() else {
            return Err(crate::PublicationError::InvalidInput);
        };
        Ok(crate::SnapshotRestorePublication {
            operation_id: self.commit.operation_id,
            branch_id: self.commit.branch_id,
            volume_id: self.commit.volume_id,
            snapshot_id,
            snapshot_namespace_commit_id,
            expected_namespace_commit_id: *expected_namespace_commit_id,
            root_object_id: self.commit.root_object_id,
            root_object_revision_id: self.commit.root_object_revision_id,
            namespace_commit_id: self.commit.commit_id,
            created_by: self.created_by,
            created_at: self.created_at,
        })
    }

    pub(in crate::publication) fn without_acknowledgement(&self) -> Self {
        let mut bare = self.clone();
        if let CommitEvidence::Mutation {
            acknowledgement, ..
        } = &mut bare.evidence
        {
            *acknowledgement = None;
        }
        bare
    }
}

pub(super) fn imported_evidence_digest(
    commit_id: NamespaceCommitId,
    request_digest: [u8; 32],
    intent_digest: [u8; 32],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.imported-namespace-commit-evidence.v1\0");
    digest.update(&commit_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&intent_digest);
    digest.finalize().into()
}
