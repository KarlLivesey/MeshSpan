// SPDX-License-Identifier: GPL-2.0-only

//! Canonical digest for exact namespace replay plans.

use meshspan_domain::{FileVersionId, ObjectRevisionId, OperationId};

use super::naming::path_key;
use super::{NamespaceReplayAction, NamespaceReplayBase, NamespaceReplayDisposition};
use crate::{BranchMutation, DirectoryEntryKind, NamespacePath};

pub(super) fn replay_digest(
    causal_digest: [u8; 32],
    base: &NamespaceReplayBase,
    actions: &[NamespaceReplayAction],
    final_root: Option<ObjectRevisionId>,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.namespace-replay-plan.v2\0");
    digest.update(&causal_digest);
    update_optional_revision(&mut digest, base.root_object_revision_id);
    let mut entries = base.entries.iter().collect::<Vec<_>>();
    entries.sort_by_key(|entry| path_key(&entry.path));
    update_count(&mut digest, entries.len());
    for entry in entries {
        update_path(&mut digest, &entry.path);
        digest.update(&entry.object_id.as_bytes());
        digest.update(&entry.object_revision_id.as_bytes());
        digest.update(&[kind_code(entry.kind)]);
        update_optional_identifier(
            &mut digest,
            entry.file_version_id.map(FileVersionId::as_bytes),
        );
        digest.update(&entry.entry_generation.to_be_bytes());
    }
    update_count(&mut digest, actions.len());
    for action in actions {
        update_action(&mut digest, action);
    }
    update_optional_revision(&mut digest, final_root);
    digest.finalize().into()
}

fn update_action(digest: &mut blake3::Hasher, action: &NamespaceReplayAction) {
    digest.update(&action.commit_id.as_bytes());
    if let Some(removal) = &action.source_removal {
        digest.update(&[1]);
        update_path(digest, &removal.path);
        digest.update(&removal.object_id.as_bytes());
        digest.update(&removal.object_revision_id.as_bytes());
        digest.update(&removal.entry_generation.to_be_bytes());
        update_optional_revision(digest, Some(removal.intermediate_root_object_revision_id));
        update_count(digest, removal.ancestors.len());
        for ancestor in &removal.ancestors {
            digest.update(&ancestor.object_id().as_bytes());
            digest.update(&ancestor.expected_revision_id().as_bytes());
            digest.update(&ancestor.new_revision_id().as_bytes());
        }
    } else {
        digest.update(&[0]);
    }
    update_path(digest, &action.source_path);
    update_path(digest, &action.target_path);
    digest.update(&action.source_object_id.as_bytes());
    digest.update(&action.target_object_id.as_bytes());
    digest.update(&action.source_object_revision_id.as_bytes());
    digest.update(&action.target_object_revision_id.as_bytes());
    digest.update(&action.target_entry_generation.to_be_bytes());
    update_optional_revision(digest, action.target_prior_object_revision_id);
    update_optional_identifier(
        digest,
        action.target_file_version_id.map(FileVersionId::as_bytes),
    );
    update_optional_identifier(
        digest,
        action
            .target_publication_operation_id
            .map(OperationId::as_bytes),
    );
    match action.mutation {
        BranchMutation::File { version_id } => {
            digest.update(&[1]);
            digest.update(&version_id.as_bytes());
        }
        BranchMutation::CreateDirectory => {
            digest.update(&[2]);
        }
        BranchMutation::DeleteFile { version_id } => {
            digest.update(&[3]);
            digest.update(&version_id.as_bytes());
        }
        BranchMutation::DeleteDirectory => {
            digest.update(&[4]);
        }
    }
    digest.update(&[disposition_code(action.disposition)]);
    update_optional_revision(digest, action.target_root_object_revision_id);
    update_count(digest, action.target_ancestors.len());
    for ancestor in &action.target_ancestors {
        digest.update(&ancestor.object_id().as_bytes());
        digest.update(&ancestor.expected_revision_id().as_bytes());
        digest.update(&ancestor.new_revision_id().as_bytes());
    }
}

fn kind_code(kind: DirectoryEntryKind) -> u8 {
    match kind {
        DirectoryEntryKind::Directory => 1,
        DirectoryEntryKind::File => 2,
    }
}

fn disposition_code(disposition: NamespaceReplayDisposition) -> u8 {
    match disposition {
        NamespaceReplayDisposition::Applied => 1,
        NamespaceReplayDisposition::Recovered => 2,
        NamespaceReplayDisposition::AlreadyApplied => 3,
    }
}

fn update_count(digest: &mut blake3::Hasher, count: usize) {
    digest.update(&u32::try_from(count).unwrap_or(u32::MAX).to_be_bytes());
}

fn update_path(digest: &mut blake3::Hasher, path: &NamespacePath) {
    digest.update(
        &u32::try_from(path.components().len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for component in path.components() {
        digest.update(
            &u32::try_from(component.display().len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        digest.update(component.display().as_bytes());
        digest.update(
            &u32::try_from(component.canonical().len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        digest.update(component.canonical().as_bytes());
    }
}

fn update_optional_revision(digest: &mut blake3::Hasher, revision: Option<ObjectRevisionId>) {
    update_optional_identifier(digest, revision.map(ObjectRevisionId::as_bytes));
}

fn update_optional_identifier(digest: &mut blake3::Hasher, value: Option<[u8; 16]>) {
    if let Some(value) = value {
        digest.update(&[1]);
        digest.update(&value);
    } else {
        digest.update(&[0]);
    }
}
