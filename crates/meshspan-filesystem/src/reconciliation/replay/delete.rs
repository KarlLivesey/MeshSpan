// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic deletion replay and delete/edit conflict preservation.

use std::collections::BTreeMap;

use meshspan_domain::{NamespaceCommitId, ObjectRevisionId};

use super::naming::{derived_revision, path_key, recovered_path};
use super::{
    EffectiveEntry, NamespaceReplayAction, NamespaceReplayDisposition, NamespaceReplayEffect,
    NamespaceReplayRemoval, ReplayState,
};
use crate::{
    BranchMutation, BranchMutationIntent, DirectoryEntryKind, DirectoryRevisionTransition,
    ReconciliationCommit, ReconciliationError,
};

impl ReplayState {
    pub(super) fn apply_delete(
        &mut self,
        plan_digest: [u8; 32],
        commit: &ReconciliationCommit,
        intent: &BranchMutationIntent,
        commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
    ) -> Result<NamespaceReplayAction, ReconciliationError> {
        let (deleted_kind, deleted_version) = deletion_identity(intent.mutation)?;
        let intended_path = self.effective_path_for(&intent.path, &intent.ancestors)?;
        let selected = self
            .objects
            .get(&intent.object_id)
            .or_else(|| self.revisions.get(&intent.object_revision_id))
            .cloned();
        let exact = selected.as_ref().is_some_and(|entry| {
            entry.path == intended_path
                && entry.object_id == intent.object_id
                && entry.revision_id == intent.object_revision_id
                && entry.generation == intent.entry_generation
                && entry.kind == deleted_kind
        });
        if let Some(selected) = selected.as_ref()
            && selected.kind == DirectoryEntryKind::Directory
            && selected.object_id == intent.object_id
            && selected.path == intended_path
            && self.has_descendants(&selected.path)
        {
            return self.recover_changed_directory(plan_digest, commit, intent, selected);
        }
        if !exact {
            let retained =
                selected.or_else(|| self.entries.get(&path_key(&intended_path)).cloned());
            return Ok(preserve_delete(
                commit,
                intent,
                intended_path,
                retained,
                self.current_root,
                deleted_kind,
                deleted_version,
            ));
        }
        let selected = selected.ok_or(ReconciliationError::MissingBaseEntry)?;
        self.remove_exact_delete(plan_digest, commit, intent, selected, commits)
    }

    fn remove_exact_delete(
        &mut self,
        plan_digest: [u8; 32],
        commit: &ReconciliationCommit,
        intent: &BranchMutationIntent,
        selected: EffectiveEntry,
        commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
    ) -> Result<NamespaceReplayAction, ReconciliationError> {
        let ancestors =
            self.advance_ancestors_for(plan_digest, commit, &intent.ancestors, &selected.path)?;
        let source_root = commit_parent_root(commit, commits)?;
        let can_reuse = self.current_root == source_root
            && selected.path == intent.path
            && ancestors == intent.ancestors;
        let final_root = if can_reuse {
            commit.root_object_revision_id
        } else {
            derived_revision(
                plan_digest,
                commit.commit_id,
                commit.root_object_revision_id,
                u32::MAX,
            )?
        };
        self.current_root = Some(final_root);
        self.entries.remove(&path_key(&selected.path));
        self.objects.remove(&selected.object_id);
        Ok(delete_action(
            commit, intent, selected, ancestors, final_root,
        ))
    }

    fn recover_changed_directory(
        &mut self,
        plan_digest: [u8; 32],
        commit: &ReconciliationCommit,
        intent: &BranchMutationIntent,
        selected: &EffectiveEntry,
    ) -> Result<NamespaceReplayAction, ReconciliationError> {
        let source_ancestors =
            self.advance_ancestors_for(plan_digest, commit, &intent.ancestors, &selected.path)?;
        let intermediate_root = derived_revision(
            plan_digest,
            commit.commit_id,
            commit.root_object_revision_id,
            u32::MAX - 1,
        )?;
        self.current_root = Some(intermediate_root);
        self.entries.remove(&path_key(&selected.path));
        self.objects.remove(&selected.object_id);
        let target_path = recovered_path(
            &selected.path,
            commit.commit_id,
            self.entries.len(),
            |candidate| self.entries.contains_key(&path_key(candidate)),
        )?;
        let target_sources = recovered_target_ancestors(plan_digest, commit, &source_ancestors)?;
        let target_ancestors =
            self.advance_ancestors_for(plan_digest, commit, &target_sources, &target_path)?;
        let final_root = derived_revision(
            plan_digest,
            commit.commit_id,
            commit.root_object_revision_id,
            u32::MAX,
        )?;
        self.current_root = Some(final_root);
        self.relocate_descendants(&selected.path, &target_path, selected.kind)?;
        let target = EffectiveEntry {
            path: target_path.clone(),
            ..selected.clone()
        };
        self.entries.insert(path_key(&target_path), target.clone());
        self.objects.insert(target.object_id, target.clone());
        self.revisions.insert(target.revision_id, target);
        Ok(NamespaceReplayAction {
            commit_id: commit.commit_id,
            source_removal: Some(NamespaceReplayRemoval {
                path: selected.path.clone(),
                object_id: selected.object_id,
                object_revision_id: selected.revision_id,
                entry_generation: selected.generation,
                ancestors: source_ancestors,
                intermediate_root_object_revision_id: intermediate_root,
            }),
            effect: NamespaceReplayEffect::Upsert,
            source_path: intent.path.clone(),
            target_path,
            source_object_id: intent.object_id,
            target_object_id: selected.object_id,
            source_object_revision_id: intent.object_revision_id,
            target_object_revision_id: selected.revision_id,
            target_kind: selected.kind,
            target_entry_generation: selected.generation,
            target_prior_object_revision_id: None,
            target_file_version_id: selected.file_version_id,
            target_publication_operation_id: None,
            target_ancestors,
            target_root_object_revision_id: Some(final_root),
            mutation: intent.mutation,
            disposition: NamespaceReplayDisposition::Recovered,
        })
    }

    fn has_descendants(&self, source: &crate::NamespacePath) -> bool {
        let source_key = path_key(source);
        self.entries
            .keys()
            .any(|key| key.len() > source_key.len() && key.starts_with(&source_key))
    }
}

fn delete_action(
    commit: &ReconciliationCommit,
    intent: &BranchMutationIntent,
    selected: EffectiveEntry,
    ancestors: Vec<DirectoryRevisionTransition>,
    final_root: ObjectRevisionId,
) -> NamespaceReplayAction {
    NamespaceReplayAction {
        commit_id: commit.commit_id,
        source_removal: Some(NamespaceReplayRemoval {
            path: selected.path.clone(),
            object_id: selected.object_id,
            object_revision_id: selected.revision_id,
            entry_generation: selected.generation,
            ancestors,
            intermediate_root_object_revision_id: final_root,
        }),
        effect: NamespaceReplayEffect::Remove,
        source_path: intent.path.clone(),
        target_path: selected.path,
        source_object_id: intent.object_id,
        target_object_id: selected.object_id,
        source_object_revision_id: intent.object_revision_id,
        target_object_revision_id: selected.revision_id,
        target_kind: selected.kind,
        target_entry_generation: selected.generation,
        target_prior_object_revision_id: None,
        target_file_version_id: selected.file_version_id,
        target_publication_operation_id: None,
        target_ancestors: Vec::new(),
        target_root_object_revision_id: Some(final_root),
        mutation: intent.mutation,
        disposition: NamespaceReplayDisposition::Applied,
    }
}

fn preserve_delete(
    commit: &ReconciliationCommit,
    intent: &BranchMutationIntent,
    intended_path: crate::NamespacePath,
    retained: Option<EffectiveEntry>,
    root: Option<ObjectRevisionId>,
    deleted_kind: DirectoryEntryKind,
    deleted_version: Option<meshspan_domain::FileVersionId>,
) -> NamespaceReplayAction {
    let disposition = if retained.is_some() {
        NamespaceReplayDisposition::Preserved
    } else {
        NamespaceReplayDisposition::AlreadyApplied
    };
    let target = retained.unwrap_or(EffectiveEntry {
        path: intended_path,
        object_id: intent.object_id,
        revision_id: intent.object_revision_id,
        kind: deleted_kind,
        file_version_id: deleted_version,
        generation: intent.entry_generation,
    });
    NamespaceReplayAction {
        commit_id: commit.commit_id,
        source_removal: None,
        effect: NamespaceReplayEffect::Preserve,
        source_path: intent.path.clone(),
        target_path: target.path,
        source_object_id: intent.object_id,
        target_object_id: target.object_id,
        source_object_revision_id: intent.object_revision_id,
        target_object_revision_id: target.revision_id,
        target_kind: target.kind,
        target_entry_generation: target.generation,
        target_prior_object_revision_id: Some(target.revision_id),
        target_file_version_id: target.file_version_id,
        target_publication_operation_id: None,
        target_ancestors: Vec::new(),
        target_root_object_revision_id: root,
        mutation: intent.mutation,
        disposition,
    }
}

fn recovered_target_ancestors(
    plan_digest: [u8; 32],
    commit: &ReconciliationCommit,
    source: &[DirectoryRevisionTransition],
) -> Result<Vec<DirectoryRevisionTransition>, ReconciliationError> {
    source
        .iter()
        .enumerate()
        .map(|(index, transition)| {
            DirectoryRevisionTransition::new(
                transition.object_id(),
                transition.new_revision_id(),
                derived_revision(
                    plan_digest,
                    commit.commit_id,
                    transition.new_revision_id(),
                    0x4000_0000_u32
                        .checked_add(
                            u32::try_from(index)
                                .map_err(|_| ReconciliationError::BoundsExceeded)?,
                        )
                        .ok_or(ReconciliationError::BoundsExceeded)?,
                )?,
            )
            .map_err(|_| ReconciliationError::InvalidLineage)
        })
        .collect()
}

fn commit_parent_root(
    commit: &ReconciliationCommit,
    commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
) -> Result<Option<ObjectRevisionId>, ReconciliationError> {
    match commit.parents.as_slice() {
        [] => Ok(None),
        [parent] => commits
            .get(parent)
            .map(|parent| Some(parent.root_object_revision_id))
            .ok_or(ReconciliationError::MissingCommit),
        _ => Err(ReconciliationError::InvalidLineage),
    }
}

const fn deletion_identity(
    mutation: BranchMutation,
) -> Result<(DirectoryEntryKind, Option<meshspan_domain::FileVersionId>), ReconciliationError> {
    match mutation {
        BranchMutation::DeleteFile { version_id } => {
            Ok((DirectoryEntryKind::File, Some(version_id)))
        }
        BranchMutation::DeleteDirectory => Ok((DirectoryEntryKind::Directory, None)),
        BranchMutation::File { .. } | BranchMutation::CreateDirectory => {
            Err(ReconciliationError::InvalidLineage)
        }
    }
}
