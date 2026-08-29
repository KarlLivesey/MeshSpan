// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic two-path replay for same-volume rename and move intents.

use std::collections::BTreeMap;

use meshspan_domain::{NamespaceCommitId, ObjectRevisionId};

use super::naming::{
    derived_file_version, derived_object, derived_operation, derived_revision, path_key,
    recovered_path,
};
use super::{
    EffectiveEntry, NamespaceReplayAction, NamespaceReplayDisposition, NamespaceReplayRemoval,
    ReplayState, mutation_kind,
};
use crate::{
    BranchMutation, BranchMutationIntent, BranchRenameIntent, DirectoryEntryKind, NamespacePath,
    ReconciliationCommit, ReconciliationError,
};

struct DirectRenameSource {
    entry: EffectiveEntry,
    removal: NamespaceReplayRemoval,
    persisted_transition_reused: bool,
}

struct ResolvedRenameSource {
    path: NamespacePath,
    entry: EffectiveEntry,
}

struct RenameTarget {
    path: NamespacePath,
    generation: u64,
    disposition: NamespaceReplayDisposition,
}

impl ReplayState {
    pub(super) fn apply_rename(
        &mut self,
        plan_digest: [u8; 32],
        commit: &ReconciliationCommit,
        intent: &BranchMutationIntent,
        rename: &BranchRenameIntent,
        commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
    ) -> Result<NamespaceReplayAction, ReconciliationError> {
        let source_path = self.effective_path_for(&rename.source_path, &rename.source_ancestors)?;
        let source = self
            .objects
            .get(&intent.object_id)
            .or_else(|| self.revisions.get(&intent.object_revision_id))
            .cloned()
            .ok_or(ReconciliationError::MissingBaseEntry)?;
        if source.kind != mutation_kind(intent.mutation) {
            return Err(ReconciliationError::InvalidLineage);
        }
        let intended_target = self.effective_path(intent)?;
        if source.path == intended_target
            && source.revision_id == intent.object_revision_id
            && source.generation == intent.entry_generation
        {
            self.revisions
                .insert(intent.object_revision_id, source.clone());
            return Ok(already_applied(
                commit,
                intent,
                rename,
                source,
                self.current_root,
            ));
        }
        if source.generation != rename.source_entry_generation {
            return Err(ReconciliationError::InvalidLineage);
        }
        if path_key(&source.path) != path_key(&source_path) {
            return self.apply_competing_rename(plan_digest, commit, intent, rename, commits);
        }
        if source.kind == DirectoryEntryKind::Directory
            && is_path_prefix(&source_path, &intended_target)
        {
            return Err(ReconciliationError::InvalidLineage);
        }
        let source = self.remove_source(
            plan_digest,
            commit,
            intent,
            rename,
            commits,
            ResolvedRenameSource {
                path: source_path,
                entry: source,
            },
        )?;
        let target = self.select_target(commit, intent)?;
        self.complete_direct(plan_digest, commit, intent, rename, source, target)
    }

    fn remove_source(
        &mut self,
        plan_digest: [u8; 32],
        commit: &ReconciliationCommit,
        intent: &BranchMutationIntent,
        rename: &BranchRenameIntent,
        commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
        source: ResolvedRenameSource,
    ) -> Result<DirectRenameSource, ReconciliationError> {
        let selected = self
            .entries
            .get(&path_key(&source.path))
            .ok_or(ReconciliationError::MissingBaseEntry)?;
        if selected.object_id != source.entry.object_id
            || selected.revision_id != source.entry.revision_id
            || selected.generation != source.entry.generation
        {
            return Err(ReconciliationError::InvalidLineage);
        }
        let ancestors = self.advance_ancestors_for(
            plan_digest,
            commit,
            &rename.source_ancestors,
            &source.path,
        )?;
        let persisted_transition_reused = self.current_root == commit_parent_root(commit, commits)?
            && source.path == rename.source_path
            && ancestors == rename.source_ancestors
            && source.entry.object_id == intent.object_id
            && source.entry.revision_id == intent.object_revision_id;
        let intermediate_root = if persisted_transition_reused {
            rename.intermediate_root_object_revision_id
        } else {
            derived_revision(
                plan_digest,
                commit.commit_id,
                rename.intermediate_root_object_revision_id,
                u32::MAX - 1,
            )?
        };
        self.current_root = Some(intermediate_root);
        self.entries.remove(&path_key(&source.path));
        self.objects.remove(&source.entry.object_id);
        Ok(DirectRenameSource {
            removal: NamespaceReplayRemoval {
                path: source.path,
                object_id: source.entry.object_id,
                object_revision_id: source.entry.revision_id,
                entry_generation: source.entry.generation,
                ancestors,
                intermediate_root_object_revision_id: intermediate_root,
            },
            entry: source.entry,
            persisted_transition_reused,
        })
    }

    fn select_target(
        &self,
        commit: &ReconciliationCommit,
        intent: &BranchMutationIntent,
    ) -> Result<RenameTarget, ReconciliationError> {
        let effective = self.effective_path(intent)?;
        if self.entries.contains_key(&path_key(&effective)) {
            Ok(RenameTarget {
                path: recovered_path(
                    &effective,
                    commit.commit_id,
                    self.entries.len(),
                    |candidate| self.entries.contains_key(&path_key(candidate)),
                )?,
                generation: 1,
                disposition: NamespaceReplayDisposition::Recovered,
            })
        } else {
            Ok(RenameTarget {
                path: effective,
                generation: intent.entry_generation,
                disposition: NamespaceReplayDisposition::Applied,
            })
        }
    }

    fn complete_direct(
        &mut self,
        plan_digest: [u8; 32],
        commit: &ReconciliationCommit,
        intent: &BranchMutationIntent,
        rename: &BranchRenameIntent,
        source: DirectRenameSource,
        target: RenameTarget,
    ) -> Result<NamespaceReplayAction, ReconciliationError> {
        let target_ancestors =
            self.advance_ancestors_for(plan_digest, commit, &intent.ancestors, &target.path)?;
        let can_reuse_final = source.persisted_transition_reused
            && target.disposition == NamespaceReplayDisposition::Applied
            && target.path == intent.path
            && target_ancestors == intent.ancestors;
        let final_root = if can_reuse_final {
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
        let mutation = effective_mutation(&source.entry)?;
        let target_entry = EffectiveEntry {
            path: target.path.clone(),
            generation: target.generation,
            ..source.entry.clone()
        };
        self.relocate_descendants(&source.removal.path, &target.path, source.entry.kind)?;
        self.entries
            .insert(path_key(&target.path), target_entry.clone());
        self.objects
            .insert(target_entry.object_id, target_entry.clone());
        self.revisions
            .insert(intent.object_revision_id, target_entry.clone());
        self.revisions
            .insert(target_entry.revision_id, target_entry);
        Ok(NamespaceReplayAction {
            commit_id: commit.commit_id,
            source_removal: Some(source.removal),
            effect: super::NamespaceReplayEffect::Upsert,
            source_path: rename.source_path.clone(),
            target_path: target.path,
            source_object_id: source.entry.object_id,
            target_object_id: source.entry.object_id,
            source_object_revision_id: source.entry.revision_id,
            target_object_revision_id: source.entry.revision_id,
            target_kind: source.entry.kind,
            target_entry_generation: target.generation,
            target_prior_object_revision_id: None,
            target_file_version_id: source.entry.file_version_id,
            target_publication_operation_id: None,
            target_ancestors,
            target_root_object_revision_id: Some(final_root),
            mutation,
            disposition: target.disposition,
        })
    }

    fn apply_competing_rename(
        &mut self,
        plan_digest: [u8; 32],
        commit: &ReconciliationCommit,
        intent: &BranchMutationIntent,
        rename: &BranchRenameIntent,
        commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
    ) -> Result<NamespaceReplayAction, ReconciliationError> {
        let BranchMutation::File { version_id } = intent.mutation else {
            return Err(ReconciliationError::InvalidLineage);
        };
        let effective_target = self.effective_path(intent)?;
        let target_path = if self.entries.contains_key(&path_key(&effective_target)) {
            recovered_path(
                &effective_target,
                commit.commit_id,
                self.entries.len(),
                |candidate| self.entries.contains_key(&path_key(candidate)),
            )?
        } else {
            effective_target
        };
        let target_object = derived_object(plan_digest, commit.commit_id, intent.object_id)?;
        let target_revision =
            derived_revision(plan_digest, commit.commit_id, intent.object_revision_id, 0)?;
        let target_version = derived_file_version(plan_digest, commit.commit_id, version_id)?;
        let target_operation =
            derived_operation(plan_digest, commit.commit_id, commit.operation_id)?;
        let target_ancestors =
            self.advance_ancestors_for(plan_digest, commit, &intent.ancestors, &target_path)?;
        let root = self.advance_root(
            plan_digest,
            commit,
            intent,
            &target_ancestors,
            NamespaceReplayDisposition::Recovered,
            commits,
        )?;
        let target = EffectiveEntry {
            path: target_path.clone(),
            object_id: target_object,
            revision_id: target_revision,
            kind: DirectoryEntryKind::File,
            file_version_id: Some(target_version),
            generation: 1,
        };
        self.entries.insert(path_key(&target_path), target.clone());
        self.objects.insert(target_object, target.clone());
        self.revisions
            .insert(intent.object_revision_id, target.clone());
        self.revisions.insert(target_revision, target);
        Ok(NamespaceReplayAction {
            commit_id: commit.commit_id,
            source_removal: None,
            effect: super::NamespaceReplayEffect::Upsert,
            source_path: rename.source_path.clone(),
            target_path,
            source_object_id: intent.object_id,
            target_object_id: target_object,
            source_object_revision_id: intent.object_revision_id,
            target_object_revision_id: target_revision,
            target_kind: DirectoryEntryKind::File,
            target_entry_generation: 1,
            target_prior_object_revision_id: None,
            target_file_version_id: Some(target_version),
            target_publication_operation_id: Some(target_operation),
            target_ancestors,
            target_root_object_revision_id: root,
            mutation: intent.mutation,
            disposition: NamespaceReplayDisposition::Recovered,
        })
    }

    pub(super) fn relocate_descendants(
        &mut self,
        source: &NamespacePath,
        target: &NamespacePath,
        kind: DirectoryEntryKind,
    ) -> Result<(), ReconciliationError> {
        if kind != DirectoryEntryKind::Directory {
            return Ok(());
        }
        let source_key = path_key(source);
        let affected = self
            .entries
            .iter()
            .filter(|(key, _)| key.len() > source_key.len() && key.starts_with(&source_key))
            .map(|(key, entry)| (key.clone(), entry.clone()))
            .collect::<Vec<_>>();
        for (key, mut entry) in affected {
            self.entries.remove(&key);
            let mut components = target.components().to_vec();
            components.extend_from_slice(&entry.path.components()[source.components().len()..]);
            entry.path = NamespacePath::from_stored_components(components)
                .map_err(|_| ReconciliationError::BoundsExceeded)?;
            self.entries.insert(path_key(&entry.path), entry.clone());
            if let Some(indexed) = self.objects.get_mut(&entry.object_id) {
                indexed.path = entry.path.clone();
            }
            for indexed in self.revisions.values_mut() {
                if indexed.object_id == entry.object_id {
                    indexed.path = entry.path.clone();
                }
            }
        }
        Ok(())
    }
}

fn effective_mutation(entry: &EffectiveEntry) -> Result<BranchMutation, ReconciliationError> {
    match (entry.kind, entry.file_version_id) {
        (DirectoryEntryKind::File, Some(version_id)) => Ok(BranchMutation::File { version_id }),
        (DirectoryEntryKind::Directory, None) => Ok(BranchMutation::CreateDirectory),
        _ => Err(ReconciliationError::InvalidInput),
    }
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

fn is_path_prefix(source: &NamespacePath, target: &NamespacePath) -> bool {
    let source = path_key(source);
    let target = path_key(target);
    source.len() < target.len() && target.starts_with(&source)
}

fn already_applied(
    commit: &ReconciliationCommit,
    intent: &BranchMutationIntent,
    rename: &BranchRenameIntent,
    current: EffectiveEntry,
    root: Option<ObjectRevisionId>,
) -> NamespaceReplayAction {
    NamespaceReplayAction {
        commit_id: commit.commit_id,
        source_removal: None,
        effect: super::NamespaceReplayEffect::Preserve,
        source_path: rename.source_path.clone(),
        target_path: current.path,
        source_object_id: intent.object_id,
        target_object_id: current.object_id,
        source_object_revision_id: intent.object_revision_id,
        target_object_revision_id: current.revision_id,
        target_kind: current.kind,
        target_entry_generation: current.generation,
        target_prior_object_revision_id: Some(current.revision_id),
        target_file_version_id: current.file_version_id,
        target_publication_operation_id: None,
        target_ancestors: Vec::new(),
        target_root_object_revision_id: root,
        mutation: intent.mutation,
        disposition: NamespaceReplayDisposition::AlreadyApplied,
    }
}
