// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic affected-path replay and recovered-conflict planning.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{NamespaceCommitId, ObjectId, ObjectRevisionId};

use super::{
    BranchMutation, BranchMutationIntent, ReconciliationCommit, ReconciliationCommitPayload,
    ReconciliationError, ReconciliationPlan,
};
use crate::{DirectoryEntryKind, DirectoryRevisionTransition, NamespacePath};

#[path = "replay/digest.rs"]
mod digest;
#[path = "replay/naming.rs"]
mod naming;

use digest::replay_digest;
use naming::{derived_object, derived_revision, path_key, path_prefix, recovered_path};

/// One exact namespace entry visible at the converged replay base.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceReplayEntry {
    /// Root-relative logical path.
    pub path: NamespacePath,
    /// Stable object selected at that path.
    pub object_id: ObjectId,
    /// Immutable revision currently selected.
    pub object_revision_id: ObjectRevisionId,
    /// File or directory kind.
    pub kind: DirectoryEntryKind,
    /// Stable incarnation of the canonical leaf name.
    pub entry_generation: u64,
}

/// Current root revision and bounded affected entries used for deterministic replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceReplayBase {
    /// Current converged root revision, absent only for an empty volume.
    pub root_object_revision_id: Option<ObjectRevisionId>,
    /// Every affected leaf and source ancestor reachable at the converged base.
    pub entries: Vec<NamespaceReplayEntry>,
}

/// Whether an operation kept its source identity/path or required recovered placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceReplayDisposition {
    /// Source immutable leaf and path apply directly.
    Applied,
    /// A concurrent alternative is preserved at a deterministic recovered path/identity.
    Recovered,
    /// The exact source revision is already selected and needs no namespace mutation.
    AlreadyApplied,
}

/// Exact target transition for one ordered branch intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceReplayAction {
    /// Source commit being included.
    pub commit_id: NamespaceCommitId,
    /// Source path recorded by the disconnected branch.
    pub source_path: NamespacePath,
    /// Effective path after any recovered-directory remapping.
    pub target_path: NamespacePath,
    /// Source leaf object identity.
    pub source_object_id: ObjectId,
    /// Effective leaf object identity; different only to avoid an unsafe hard link.
    pub target_object_id: ObjectId,
    /// Source immutable leaf revision.
    pub source_object_revision_id: ObjectRevisionId,
    /// Effective immutable leaf revision selected by the target path.
    pub target_object_revision_id: ObjectRevisionId,
    /// Exact target ancestor revisions in root-to-leaf order.
    pub target_ancestors: Vec<DirectoryRevisionTransition>,
    /// Resulting root revision after this action, unchanged only for exact inclusion.
    pub target_root_object_revision_id: Option<ObjectRevisionId>,
    /// File-version selection or directory creation semantics.
    pub mutation: BranchMutation,
    /// Direct, recovered or already-applied disposition.
    pub disposition: NamespaceReplayDisposition,
}

/// Canonical affected-path replay result suitable for a receipt-bound transactional applier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceReplayPlan {
    actions: Vec<NamespaceReplayAction>,
    final_root_object_revision_id: Option<ObjectRevisionId>,
    digest: [u8; 32],
}

impl NamespaceReplayPlan {
    /// One action for every ordered mutation commit.
    #[must_use]
    pub fn actions(&self) -> &[NamespaceReplayAction] {
        &self.actions
    }

    /// Root revision selected after all actions.
    #[must_use]
    pub const fn final_root_object_revision_id(&self) -> Option<ObjectRevisionId> {
        self.final_root_object_revision_id
    }

    /// Versioned digest binding the causal plan, base and every effective transition.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

#[derive(Clone)]
struct EffectiveEntry {
    path: NamespacePath,
    object_id: ObjectId,
    revision_id: ObjectRevisionId,
    kind: DirectoryEntryKind,
    generation: u64,
}

struct ReplayState {
    entries: BTreeMap<Vec<String>, EffectiveEntry>,
    revisions: BTreeMap<ObjectRevisionId, EffectiveEntry>,
    current_root: Option<ObjectRevisionId>,
}

enum LeafSelection {
    Already(EffectiveEntry),
    Change {
        path: NamespacePath,
        object_id: ObjectId,
        revision_id: ObjectRevisionId,
        generation: u64,
        disposition: NamespaceReplayDisposition,
    },
}

/// Converts a validated causal plan and durable intents into exact deterministic path mutations.
///
/// # Errors
///
/// Rejects missing/extra intents, duplicate or incomplete base entries, invalid source lineage,
/// unsafe object-kind transitions, generated-name exhaustion and inconsistent causal revisions.
pub fn plan_namespace_replay(
    causal_plan: &ReconciliationPlan,
    commits: &[ReconciliationCommit],
    intents: &[BranchMutationIntent],
    base: &NamespaceReplayBase,
) -> Result<NamespaceReplayPlan, ReconciliationError> {
    if !causal_plan.validates_commits(commits) {
        return Err(ReconciliationError::InvalidInput);
    }
    let commits = index_commits(commits)?;
    let intents = index_intents(causal_plan, &commits, intents)?;
    let mut state = ReplayState::from_base(base)?;
    let mut actions = Vec::with_capacity(causal_plan.ordered_commits().len());
    for commit_id in causal_plan.ordered_commits() {
        let commit = commits
            .get(commit_id)
            .ok_or(ReconciliationError::MissingCommit)?;
        if matches!(commit.payload, ReconciliationCommitPayload::Merge { .. }) {
            continue;
        }
        let intent = intents
            .get(commit_id)
            .ok_or(ReconciliationError::MissingIntent)?;
        validate_intent(commit, intent)?;
        actions.push(state.apply(causal_plan.digest(), commit, intent, &commits)?);
    }
    let digest = replay_digest(causal_plan.digest(), base, &actions, state.current_root);
    Ok(NamespaceReplayPlan {
        actions,
        final_root_object_revision_id: state.current_root,
        digest,
    })
}

impl ReplayState {
    fn from_base(base: &NamespaceReplayBase) -> Result<Self, ReconciliationError> {
        let mut entries = BTreeMap::new();
        let mut revisions = BTreeMap::new();
        let mut objects = BTreeSet::new();
        for entry in &base.entries {
            if entry.entry_generation == 0 || entry.path.components().is_empty() {
                return Err(ReconciliationError::InvalidInput);
            }
            let effective = EffectiveEntry {
                path: entry.path.clone(),
                object_id: entry.object_id,
                revision_id: entry.object_revision_id,
                kind: entry.kind,
                generation: entry.entry_generation,
            };
            if entries
                .insert(path_key(&entry.path), effective.clone())
                .is_some()
                || revisions
                    .insert(entry.object_revision_id, effective)
                    .is_some()
                || !objects.insert(entry.object_id)
            {
                return Err(ReconciliationError::InvalidInput);
            }
        }
        Ok(Self {
            entries,
            revisions,
            current_root: base.root_object_revision_id,
        })
    }

    fn apply(
        &mut self,
        plan_digest: [u8; 32],
        commit: &ReconciliationCommit,
        intent: &BranchMutationIntent,
        commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
    ) -> Result<NamespaceReplayAction, ReconciliationError> {
        let source_path = intent.path.clone();
        let selection = self.select_leaf(plan_digest, commit, intent)?;
        let LeafSelection::Change {
            path: target_path,
            object_id: target_object,
            revision_id: target_revision,
            generation,
            disposition,
        } = selection
        else {
            let LeafSelection::Already(current) = selection else {
                return Err(ReconciliationError::InvalidInput);
            };
            self.revisions
                .insert(intent.object_revision_id, current.clone());
            return Ok(already_applied(
                commit,
                intent,
                current.path,
                self.current_root,
            ));
        };
        let target_kind = mutation_kind(intent.mutation);
        let target_ancestors = self.advance_ancestors(plan_digest, commit, intent, &target_path)?;
        let root_revision = self.advance_root(
            plan_digest,
            commit,
            intent,
            &target_ancestors,
            disposition,
            commits,
        )?;
        let target = EffectiveEntry {
            path: target_path.clone(),
            object_id: target_object,
            revision_id: target_revision,
            kind: target_kind,
            generation,
        };
        self.entries.insert(path_key(&target_path), target.clone());
        self.revisions
            .insert(intent.object_revision_id, target.clone());
        if target_kind == DirectoryEntryKind::Directory {
            self.revisions.insert(target_revision, target);
        }
        Ok(NamespaceReplayAction {
            commit_id: commit.commit_id,
            source_path,
            target_path,
            source_object_id: intent.object_id,
            target_object_id: target_object,
            source_object_revision_id: intent.object_revision_id,
            target_object_revision_id: target_revision,
            target_ancestors,
            target_root_object_revision_id: root_revision,
            mutation: intent.mutation,
            disposition,
        })
    }

    fn select_leaf(
        &self,
        plan_digest: [u8; 32],
        commit: &ReconciliationCommit,
        intent: &BranchMutationIntent,
    ) -> Result<LeafSelection, ReconciliationError> {
        let effective_path = self.effective_path(intent)?;
        let prior_target = intent
            .prior_object_revision_id
            .and_then(|revision| self.revisions.get(&revision).cloned());
        let selected_path = prior_target
            .as_ref()
            .map_or_else(|| effective_path.clone(), |target| target.path.clone());
        let current = self.entries.get(&path_key(&selected_path)).cloned();
        if current.as_ref().is_some_and(|entry| {
            entry.object_id == intent.object_id
                && entry.revision_id == intent.object_revision_id
                && entry.kind == mutation_kind(intent.mutation)
        }) {
            return current
                .map(LeafSelection::Already)
                .ok_or(ReconciliationError::InvalidInput);
        }

        let direct = direct_application(
            intent,
            &selected_path,
            current.as_ref(),
            prior_target.as_ref(),
        );
        let (path, object_id, revision_id, disposition) = if direct {
            (
                selected_path.clone(),
                prior_target
                    .as_ref()
                    .map_or(intent.object_id, |target| target.object_id),
                if prior_target
                    .as_ref()
                    .is_some_and(|target| target.object_id != intent.object_id)
                {
                    derived_revision(plan_digest, commit.commit_id, intent.object_revision_id, 0)?
                } else {
                    intent.object_revision_id
                },
                if prior_target
                    .as_ref()
                    .is_some_and(|target| target.object_id != intent.object_id)
                {
                    NamespaceReplayDisposition::Recovered
                } else {
                    NamespaceReplayDisposition::Applied
                },
            )
        } else {
            self.recovered_target(plan_digest, commit, intent, &selected_path)?
        };
        let generation =
            if disposition == NamespaceReplayDisposition::Recovered && path != intent.path {
                1
            } else {
                prior_target
                    .as_ref()
                    .map_or(intent.entry_generation, |target| target.generation)
            };
        Ok(LeafSelection::Change {
            path,
            object_id,
            revision_id,
            generation,
            disposition,
        })
    }

    fn effective_path(
        &self,
        intent: &BranchMutationIntent,
    ) -> Result<NamespacePath, ReconciliationError> {
        for (index, ancestor) in intent.ancestors.iter().enumerate().rev() {
            if let Some(target) = self.revisions.get(&ancestor.expected_revision_id()) {
                if target.kind != DirectoryEntryKind::Directory
                    || target.object_id != ancestor.object_id()
                {
                    return Err(ReconciliationError::InvalidLineage);
                }
                let mut components = target.path.components().to_vec();
                components.extend_from_slice(&intent.path.components()[index + 1..]);
                return NamespacePath::from_stored_components(components)
                    .map_err(|_| ReconciliationError::BoundsExceeded);
            }
        }
        Ok(intent.path.clone())
    }

    fn recovered_target(
        &self,
        plan_digest: [u8; 32],
        commit: &ReconciliationCommit,
        intent: &BranchMutationIntent,
        effective_path: &NamespacePath,
    ) -> Result<
        (
            NamespacePath,
            ObjectId,
            ObjectRevisionId,
            NamespaceReplayDisposition,
        ),
        ReconciliationError,
    > {
        let recovered_path = recovered_path(
            effective_path,
            commit.commit_id,
            self.entries.len(),
            |path| self.entries.contains_key(&path_key(path)),
        )?;
        let object_is_visible = self
            .entries
            .values()
            .any(|entry| entry.object_id == intent.object_id);
        let target_object = if object_is_visible {
            if mutation_kind(intent.mutation) == DirectoryEntryKind::Directory {
                return Err(ReconciliationError::InvalidLineage);
            }
            derived_object(plan_digest, commit.commit_id, intent.object_id)?
        } else {
            intent.object_id
        };
        let target_revision = if target_object == intent.object_id {
            intent.object_revision_id
        } else {
            derived_revision(plan_digest, commit.commit_id, intent.object_revision_id, 0)?
        };
        Ok((
            recovered_path,
            target_object,
            target_revision,
            NamespaceReplayDisposition::Recovered,
        ))
    }

    fn advance_ancestors(
        &mut self,
        plan_digest: [u8; 32],
        commit: &ReconciliationCommit,
        intent: &BranchMutationIntent,
        target_path: &NamespacePath,
    ) -> Result<Vec<DirectoryRevisionTransition>, ReconciliationError> {
        let mut transitions = Vec::with_capacity(intent.ancestors.len());
        for (index, source) in intent.ancestors.iter().enumerate() {
            let source_target = self
                .revisions
                .get(&source.expected_revision_id())
                .cloned()
                .ok_or(ReconciliationError::MissingBaseEntry)?;
            if source_target.kind != DirectoryEntryKind::Directory
                || source_target.object_id != source.object_id()
            {
                return Err(ReconciliationError::InvalidLineage);
            }
            let prefix = path_prefix(target_path, index + 1)?;
            let current = self
                .entries
                .get(&path_key(&prefix))
                .cloned()
                .ok_or(ReconciliationError::MissingBaseEntry)?;
            if current.kind != DirectoryEntryKind::Directory
                || current.object_id != source_target.object_id
            {
                return Err(ReconciliationError::InvalidLineage);
            }
            let next = if current.revision_id == source.expected_revision_id()
                && current.object_id == source.object_id()
            {
                source.new_revision_id()
            } else {
                derived_revision(
                    plan_digest,
                    commit.commit_id,
                    source.new_revision_id(),
                    u32::try_from(index + 1).map_err(|_| ReconciliationError::BoundsExceeded)?,
                )?
            };
            let transition =
                DirectoryRevisionTransition::new(current.object_id, current.revision_id, next)
                    .map_err(|_| ReconciliationError::InvalidLineage)?;
            let updated = EffectiveEntry {
                revision_id: next,
                ..current
            };
            self.entries.insert(path_key(&prefix), updated.clone());
            self.revisions.insert(source.new_revision_id(), updated);
            transitions.push(transition);
        }
        Ok(transitions)
    }

    fn advance_root(
        &mut self,
        plan_digest: [u8; 32],
        commit: &ReconciliationCommit,
        intent: &BranchMutationIntent,
        ancestors: &[DirectoryRevisionTransition],
        disposition: NamespaceReplayDisposition,
        commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
    ) -> Result<Option<ObjectRevisionId>, ReconciliationError> {
        let source_base = match commit.parents.as_slice() {
            [] => None,
            [parent] => Some(
                commits
                    .get(parent)
                    .ok_or(ReconciliationError::MissingCommit)?
                    .root_object_revision_id,
            ),
            _ => return Err(ReconciliationError::InvalidLineage),
        };
        let can_reuse = disposition == NamespaceReplayDisposition::Applied
            && self.current_root == source_base
            && ancestors == intent.ancestors;
        let next = if can_reuse {
            commit.root_object_revision_id
        } else {
            derived_revision(
                plan_digest,
                commit.commit_id,
                commit.root_object_revision_id,
                u32::MAX,
            )?
        };
        self.current_root = Some(next);
        Ok(self.current_root)
    }
}

fn index_commits(
    commits: &[ReconciliationCommit],
) -> Result<BTreeMap<NamespaceCommitId, &ReconciliationCommit>, ReconciliationError> {
    let mut indexed = BTreeMap::new();
    for commit in commits {
        if indexed.insert(commit.commit_id, commit).is_some() {
            return Err(ReconciliationError::InvalidInput);
        }
    }
    Ok(indexed)
}

fn index_intents<'a>(
    plan: &ReconciliationPlan,
    commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
    intents: &'a [BranchMutationIntent],
) -> Result<BTreeMap<NamespaceCommitId, &'a BranchMutationIntent>, ReconciliationError> {
    let ordered = plan
        .ordered_commits()
        .iter()
        .filter_map(|commit_id| {
            commits
                .get(commit_id)
                .is_some_and(|commit| {
                    matches!(commit.payload, ReconciliationCommitPayload::Mutation { .. })
                })
                .then_some(*commit_id)
        })
        .collect::<BTreeSet<_>>();
    if intents.len() != ordered.len() {
        return Err(ReconciliationError::MissingIntent);
    }
    let mut indexed = BTreeMap::new();
    for intent in intents {
        if !ordered.contains(&intent.commit_id)
            || indexed.insert(intent.commit_id, intent).is_some()
        {
            return Err(ReconciliationError::InvalidInput);
        }
    }
    Ok(indexed)
}

fn validate_intent(
    commit: &ReconciliationCommit,
    intent: &BranchMutationIntent,
) -> Result<(), ReconciliationError> {
    let ReconciliationCommitPayload::Mutation { intent_digest } = commit.payload else {
        return Err(ReconciliationError::InvalidInput);
    };
    if intent.commit_id != commit.commit_id
        || intent.digest() != intent_digest
        || intent.entry_generation == 0
        || intent.ancestors.len().checked_add(1) != Some(intent.path.components().len())
    {
        return Err(ReconciliationError::InvalidInput);
    }
    let mut objects = BTreeSet::from([intent.object_id]);
    let mut revisions = BTreeSet::from([intent.object_revision_id]);
    for ancestor in &intent.ancestors {
        if !objects.insert(ancestor.object_id())
            || !revisions.insert(ancestor.expected_revision_id())
            || !revisions.insert(ancestor.new_revision_id())
        {
            return Err(ReconciliationError::InvalidLineage);
        }
    }
    Ok(())
}

fn direct_application(
    intent: &BranchMutationIntent,
    effective_path: &NamespacePath,
    current: Option<&EffectiveEntry>,
    prior_target: Option<&EffectiveEntry>,
) -> bool {
    if let Some(prior) = prior_target {
        return current.is_some_and(|entry| {
            entry.path == prior.path
                && entry.object_id == prior.object_id
                && entry.revision_id == prior.revision_id
                && entry.kind == mutation_kind(intent.mutation)
        });
    }
    match (intent.prior_object_revision_id, current) {
        (None, None) => true,
        (Some(prior), Some(entry)) => {
            entry.path == *effective_path
                && entry.object_id == intent.object_id
                && entry.revision_id == prior
                && entry.kind == mutation_kind(intent.mutation)
        }
        _ => false,
    }
}

fn mutation_kind(mutation: BranchMutation) -> DirectoryEntryKind {
    match mutation {
        BranchMutation::File { .. } => DirectoryEntryKind::File,
        BranchMutation::CreateDirectory => DirectoryEntryKind::Directory,
    }
}

fn already_applied(
    commit: &ReconciliationCommit,
    intent: &BranchMutationIntent,
    target_path: NamespacePath,
    root: Option<ObjectRevisionId>,
) -> NamespaceReplayAction {
    NamespaceReplayAction {
        commit_id: commit.commit_id,
        source_path: intent.path.clone(),
        target_path,
        source_object_id: intent.object_id,
        target_object_id: intent.object_id,
        source_object_revision_id: intent.object_revision_id,
        target_object_revision_id: intent.object_revision_id,
        target_ancestors: Vec::new(),
        target_root_object_revision_id: root,
        mutation: intent.mutation,
        disposition: NamespaceReplayDisposition::AlreadyApplied,
    }
}

#[cfg(test)]
#[path = "replay_tests.rs"]
mod tests;
