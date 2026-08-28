// SPDX-License-Identifier: GPL-2.0-only

//! Canonical domain-separated digests for namespace requests, records and receipts.

use meshspan_domain::{
    BranchId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId,
    PrincipalId, UnixMicros, VolumeId,
};

use super::repository::{ObjectRevisionInsert, StoredCommit};
use super::{NamespaceIntent, publication_request_digest};
use crate::{
    DirectoryNodeDigest, DirectoryPublication, NamespacePath, NamespacePublicationPath,
    RootFilePublication,
};
use crate::{NamespaceReconciliationApplication, PreparedNamespaceReconciliation};

pub(super) fn file_request(publication: &RootFilePublication) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.path-file-publication.v1\0");
    digest.update(&publication_request_digest(publication.file));
    digest.update(&publication.root_object_id.as_bytes());
    update_optional_commit(&mut digest, publication.expected_namespace_commit_id);
    update_optional_revision(&mut digest, publication.expected_file_object_revision_id);
    digest.update(&publication.file_object_revision_id.as_bytes());
    digest.update(&publication.root_object_revision_id.as_bytes());
    digest.update(&publication.namespace_commit_id.as_bytes());
    update_publication_path(&mut digest, &publication.path);
    digest.update(&publication.entry_generation.to_be_bytes());
    digest.finalize().into()
}

pub(super) fn directory_request(publication: &DirectoryPublication) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.directory-publication.v1\0");
    digest.update(&publication.operation_id.as_bytes());
    digest.update(&publication.branch_id.as_bytes());
    digest.update(&publication.volume_id.as_bytes());
    digest.update(&publication.root_object_id.as_bytes());
    update_optional_commit(&mut digest, publication.expected_namespace_commit_id);
    digest.update(&publication.directory_object_id.as_bytes());
    digest.update(&publication.directory_object_revision_id.as_bytes());
    digest.update(&publication.root_object_revision_id.as_bytes());
    digest.update(&publication.namespace_commit_id.as_bytes());
    update_publication_path(&mut digest, &publication.path);
    digest.update(&publication.entry_generation.to_be_bytes());
    digest.update(&publication.created_by.as_bytes());
    digest.update(&publication.created_at.get().to_be_bytes());
    digest.finalize().into()
}

pub(super) fn commit(intent: NamespaceIntent<'_>, request_digest: [u8; 32]) -> [u8; 32] {
    commit_fields(
        &StoredCommit {
            commit_id: intent.commit_id,
            branch_id: intent.branch_id,
            volume_id: intent.volume_id,
            root_object_id: intent.root_object_id,
            root_object_revision_id: intent.root_revision_id,
            parent_id: intent.expected_commit_id,
            created_by: intent.created_by,
            operation_id: intent.operation_id,
            created_at: intent.created_at,
        },
        request_digest,
    )
}

pub(super) fn commit_fields(commit: &StoredCommit, request_digest: [u8; 32]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.namespace-commit.v1\0");
    digest.update(&commit.commit_id.as_bytes());
    digest.update(&commit.branch_id.as_bytes());
    digest.update(&commit.volume_id.as_bytes());
    digest.update(&commit.root_object_id.as_bytes());
    digest.update(&commit.root_object_revision_id.as_bytes());
    update_optional_commit(&mut digest, commit.parent_id);
    digest.update(&commit.created_by.as_bytes());
    digest.update(&commit.operation_id.as_bytes());
    digest.update(&commit.created_at.get().to_be_bytes());
    digest.update(&request_digest);
    digest.finalize().into()
}

pub(super) fn object_revision(revision: &ObjectRevisionInsert) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.object-revision.v1\0");
    digest.update(&revision.revision_id.as_bytes());
    digest.update(&revision.volume_id.as_bytes());
    digest.update(&revision.object_id.as_bytes());
    digest.update(&[revision.kind]);
    update_optional_revision(&mut digest, revision.prior_revision_id);
    update_optional_digest(&mut digest, revision.directory_root);
    update_optional_version(&mut digest, revision.file_version_id);
    digest.update(&revision.created_by.as_bytes());
    digest.update(&revision.created_at.get().to_be_bytes());
    digest.finalize().into()
}

pub(super) fn reconciliation_request(
    application: NamespaceReconciliationApplication,
    prepared: &PreparedNamespaceReconciliation,
) -> [u8; 32] {
    let causal = prepared.causal_plan();
    let replay = prepared.replay_plan();
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.namespace-reconciliation-request.v1\0");
    digest.update(&application.operation_id.as_bytes());
    digest.update(&application.namespace_commit_id.as_bytes());
    digest.update(&application.created_by.as_bytes());
    digest.update(&application.created_at.get().to_be_bytes());
    digest.update(&causal.digest());
    digest.update(&replay.digest());
    update_optional_commit(&mut digest, causal.converged_head());
    if let Some(branch_id) = causal.converged_branch_id() {
        digest.update(&[1]);
        digest.update(&branch_id.as_bytes());
    } else {
        digest.update(&[0]);
    }
    digest.update(&causal.volume_id().as_bytes());
    digest.update(&causal.root_object_id().as_bytes());
    update_optional_revision(&mut digest, replay.final_root_object_revision_id());
    update_commit_ids(&mut digest, causal.merge_parents());
    digest.finalize().into()
}

pub(super) struct MergeCommitDigest<'a> {
    pub commit_id: NamespaceCommitId,
    pub branch_id: BranchId,
    pub volume_id: VolumeId,
    pub root_object_id: ObjectId,
    pub root_revision_id: ObjectRevisionId,
    pub parents: &'a [NamespaceCommitId],
    pub created_by: PrincipalId,
    pub operation_id: OperationId,
    pub created_at: UnixMicros,
    pub request_digest: [u8; 32],
    pub replay_digest: [u8; 32],
}

pub(super) fn merge_commit(commit: &MergeCommitDigest<'_>) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.namespace-merge-commit.v1\0");
    digest.update(&commit.commit_id.as_bytes());
    digest.update(&commit.branch_id.as_bytes());
    digest.update(&commit.volume_id.as_bytes());
    digest.update(&commit.root_object_id.as_bytes());
    digest.update(&commit.root_revision_id.as_bytes());
    update_commit_ids(&mut digest, commit.parents);
    digest.update(&commit.created_by.as_bytes());
    digest.update(&commit.operation_id.as_bytes());
    digest.update(&commit.created_at.get().to_be_bytes());
    digest.update(&commit.request_digest);
    digest.update(&commit.replay_digest);
    digest.finalize().into()
}

pub(super) fn file_result(
    operation_id: OperationId,
    request_digest: [u8; 32],
    file_version_id: FileVersionId,
    namespace_commit_id: NamespaceCommitId,
    head_sequence: u64,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.namespace-publication-result.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&file_version_id.as_bytes());
    digest.update(&namespace_commit_id.as_bytes());
    digest.update(&head_sequence.to_be_bytes());
    digest.finalize().into()
}

pub(super) fn directory_result(
    operation_id: OperationId,
    request_digest: [u8; 32],
    directory_object_revision_id: ObjectRevisionId,
    namespace_commit_id: NamespaceCommitId,
    head_sequence: u64,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.directory-publication-result.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&request_digest);
    digest.update(&directory_object_revision_id.as_bytes());
    digest.update(&namespace_commit_id.as_bytes());
    digest.update(&head_sequence.to_be_bytes());
    digest.finalize().into()
}

fn update_publication_path(digest: &mut blake3::Hasher, path: &NamespacePublicationPath) {
    update_namespace_path(digest, path.path());
    for transition in path.ancestors() {
        digest.update(&transition.object_id().as_bytes());
        digest.update(&transition.expected_revision_id().as_bytes());
        digest.update(&transition.new_revision_id().as_bytes());
    }
}

fn update_namespace_path(digest: &mut blake3::Hasher, path: &NamespacePath) {
    digest.update(
        &u16::try_from(path.components().len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    for component in path.components() {
        update_text(digest, component.canonical());
        update_text(digest, component.display());
    }
}

fn update_optional_commit(digest: &mut blake3::Hasher, value: Option<NamespaceCommitId>) {
    update_optional_bytes(digest, value.map(NamespaceCommitId::as_bytes).as_ref());
}

fn update_commit_ids(digest: &mut blake3::Hasher, values: &[NamespaceCommitId]) {
    digest.update(
        &u32::try_from(values.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for value in values {
        digest.update(&value.as_bytes());
    }
}

fn update_optional_revision(digest: &mut blake3::Hasher, value: Option<ObjectRevisionId>) {
    update_optional_bytes(digest, value.map(ObjectRevisionId::as_bytes).as_ref());
}

fn update_optional_version(digest: &mut blake3::Hasher, value: Option<FileVersionId>) {
    update_optional_bytes(digest, value.map(FileVersionId::as_bytes).as_ref());
}

fn update_optional_digest(digest: &mut blake3::Hasher, value: Option<DirectoryNodeDigest>) {
    update_optional_bytes(digest, value.map(DirectoryNodeDigest::as_bytes).as_ref());
}

fn update_optional_bytes<const LENGTH: usize>(
    digest: &mut blake3::Hasher,
    value: Option<&[u8; LENGTH]>,
) {
    if let Some(value) = value {
        digest.update(&[1]);
        digest.update(value);
    } else {
        digest.update(&[0]);
    }
}

fn update_text(digest: &mut blake3::Hasher, value: &str) {
    digest.update(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    digest.update(value.as_bytes());
}
