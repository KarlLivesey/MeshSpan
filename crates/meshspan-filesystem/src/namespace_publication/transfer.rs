// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, transactional exchange of disconnected mutation history.

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
pub(in crate::publication) use import::import_history;

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
pub(in crate::publication) struct TransferredMutationCommit {
    pub(in crate::publication) commit: ReconciliationCommit,
    pub(in crate::publication) created_by: PrincipalId,
    pub(in crate::publication) created_at: UnixMicros,
    pub(in crate::publication) commit_digest: [u8; 32],
    pub(in crate::publication) intent: BranchMutationIntent,
    pub(in crate::publication) acknowledgement: Option<FederatedMutationAcknowledgement>,
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
