// SPDX-License-Identifier: GPL-2.0-only

//! Canonical digest for exact namespace replay plans.

use meshspan_domain::ObjectRevisionId;

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
    digest.update(b"meshspan.filesystem.namespace-replay-plan.v1\0");
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
    update_path(digest, &action.source_path);
    update_path(digest, &action.target_path);
    digest.update(&action.source_object_id.as_bytes());
    digest.update(&action.target_object_id.as_bytes());
    digest.update(&action.source_object_revision_id.as_bytes());
    digest.update(&action.target_object_revision_id.as_bytes());
    match action.mutation {
        BranchMutation::File { version_id } => {
            digest.update(&[1]);
            digest.update(&version_id.as_bytes());
        }
        BranchMutation::CreateDirectory => {
            digest.update(&[2]);
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
    if let Some(revision) = revision {
        digest.update(&[1]);
        digest.update(&revision.as_bytes());
    } else {
        digest.update(&[0]);
    }
}
