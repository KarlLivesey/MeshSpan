// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic hostile-input validation and ordering for disconnected branch reconciliation.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{
    BranchId, NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId, VolumeId,
};
use thiserror::Error;

const MAXIMUM_COMMITS: usize = 65_536;
const MAXIMUM_FRONTIER_HEADS: usize = 1_024;
const MAXIMUM_PARENTS: usize = 1_024;

/// Resource bounds for one independently validated reconciliation page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconciliationLimits {
    commits: usize,
    frontier_heads: usize,
    parents: usize,
}

impl ReconciliationLimits {
    /// Conservative defaults for an appliance reconciliation page.
    pub const DEFAULT: Self = Self {
        commits: 4_096,
        frontier_heads: 64,
        parents: 64,
    };

    /// Creates bounded per-page limits beneath fixed allocation ceilings.
    ///
    /// # Errors
    ///
    /// Rejects zero limits and values beyond the implementation allocation ceilings.
    pub fn new(
        maximum_commits: usize,
        maximum_frontier_heads: usize,
        maximum_parents: usize,
    ) -> Result<Self, ReconciliationError> {
        if maximum_commits == 0
            || maximum_commits > MAXIMUM_COMMITS
            || maximum_frontier_heads == 0
            || maximum_frontier_heads > MAXIMUM_FRONTIER_HEADS
            || maximum_parents == 0
            || maximum_parents > MAXIMUM_PARENTS
        {
            return Err(ReconciliationError::BoundsExceeded);
        }
        Ok(Self {
            commits: maximum_commits,
            frontier_heads: maximum_frontier_heads,
            parents: maximum_parents,
        })
    }
}

/// Untrusted immutable header for one locally acknowledged namespace commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationCommit {
    /// Immutable commit identity.
    pub commit_id: NamespaceCommitId,
    /// Writable branch that originally acknowledged the commit.
    pub branch_id: BranchId,
    /// Volume whose namespace root the commit selects.
    pub volume_id: VolumeId,
    /// Stable volume-root object identity.
    pub root_object_id: ObjectId,
    /// Immutable root revision selected by this commit.
    pub root_object_revision_id: ObjectRevisionId,
    /// Causal parents. Ordinary commits have at most one; merge commits may have several.
    pub parents: Vec<NamespaceCommitId>,
    /// Stable idempotency identity of the user-visible mutation.
    pub operation_id: OperationId,
    /// Digest of the complete canonical mutation request.
    pub request_digest: [u8; 32],
}

/// Current converged head and disconnected heads eligible for one reconciliation plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationFrontier {
    /// Current authoritative head, absent only for a new volume.
    pub converged_head: Option<NamespaceCommitId>,
    /// Local/cell heads whose complete causal closures were supplied.
    pub eligible_heads: Vec<NamespaceCommitId>,
}

/// Canonical, replayable result of validating and ordering one causal closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationPlan {
    ordered_commits: Vec<NamespaceCommitId>,
    merge_parents: Vec<NamespaceCommitId>,
    digest: [u8; 32],
}

impl ReconciliationPlan {
    /// Commits not already included, in deterministic causal application order.
    #[must_use]
    pub fn ordered_commits(&self) -> &[NamespaceCommitId] {
        &self.ordered_commits
    }

    /// Minimal sorted frontier that the resulting merge commit must name as parents.
    #[must_use]
    pub fn merge_parents(&self) -> &[NamespaceCommitId] {
        &self.merge_parents
    }

    /// Versioned digest binding the validated graph, frontier and selected order.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Validates a complete causal closure and produces one delivery-order-independent plan.
///
/// # Errors
///
/// Rejects resource-limit violations, missing/unreachable commits, cycles, mixed namespace
/// identity and conflicting operation reuse. Every collection is treated as hostile input.
pub fn plan_reconciliation(
    commits: &[ReconciliationCommit],
    frontier: &ReconciliationFrontier,
    limits: ReconciliationLimits,
) -> Result<ReconciliationPlan, ReconciliationError> {
    validate_bounds(commits, frontier, limits)?;
    let by_id = index_commits(commits, limits)?;
    validate_namespace(&by_id, frontier)?;
    let converged = reachable(frontier.converged_head, &by_id)?;
    let eligible = reachable(frontier.eligible_heads.iter().copied(), &by_id)?;
    let mut all_reachable = converged.clone();
    all_reachable.extend(eligible.iter().copied());
    if all_reachable.len() != by_id.len() {
        return Err(ReconciliationError::UnreachableCommit);
    }
    validate_acyclic(&by_id)?;
    validate_operations(&by_id)?;

    let pending = select_pending(&by_id, &eligible, &converged);
    let ordered_commits = order_pending(&by_id, &pending)?;
    let merge_parents = minimal_frontier(frontier, &by_id)?;
    let digest = plan_digest(&by_id, frontier, &ordered_commits, &merge_parents);
    Ok(ReconciliationPlan {
        ordered_commits,
        merge_parents,
        digest,
    })
}

/// Stable reconciliation planning failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReconciliationError {
    /// A collection exceeded its explicit per-page allocation bound.
    #[error("reconciliation input exceeds its bounded page")]
    BoundsExceeded,
    /// A commit/head identity was duplicated or the frontier was empty.
    #[error("reconciliation input is malformed")]
    InvalidInput,
    /// A causal parent or named head is absent from the supplied closure.
    #[error("reconciliation causal closure is incomplete")]
    MissingCommit,
    /// Supplied commits do not all belong to the same volume-root namespace.
    #[error("reconciliation input mixes namespace identities")]
    MixedNamespace,
    /// The supplied parent graph is cyclic.
    #[error("reconciliation commit graph contains a cycle")]
    Cycle,
    /// One operation identity is bound to different request digests.
    #[error("reconciliation operation identity conflicts")]
    OperationConflict,
    /// The page contains a commit outside the named frontier's causal closure.
    #[error("reconciliation page contains an unreachable commit")]
    UnreachableCommit,
}

fn validate_bounds(
    commits: &[ReconciliationCommit],
    frontier: &ReconciliationFrontier,
    limits: ReconciliationLimits,
) -> Result<(), ReconciliationError> {
    if commits.is_empty() || frontier.eligible_heads.is_empty() {
        return Err(ReconciliationError::InvalidInput);
    }
    if commits.len() > limits.commits
        || frontier.eligible_heads.len() > limits.frontier_heads
        || commits
            .iter()
            .any(|commit| commit.parents.len() > limits.parents)
    {
        return Err(ReconciliationError::BoundsExceeded);
    }
    Ok(())
}

fn index_commits(
    commits: &[ReconciliationCommit],
    limits: ReconciliationLimits,
) -> Result<BTreeMap<NamespaceCommitId, &ReconciliationCommit>, ReconciliationError> {
    let mut indexed = BTreeMap::new();
    for commit in commits {
        let parents = commit.parents.iter().copied().collect::<BTreeSet<_>>();
        if parents.len() != commit.parents.len()
            || parents.contains(&commit.commit_id)
            || commit.parents.len() > limits.parents
            || indexed.insert(commit.commit_id, commit).is_some()
        {
            return Err(ReconciliationError::InvalidInput);
        }
    }
    for commit in commits {
        if commit
            .parents
            .iter()
            .any(|parent| !indexed.contains_key(parent))
        {
            return Err(ReconciliationError::MissingCommit);
        }
    }
    Ok(indexed)
}

fn validate_namespace(
    commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
    frontier: &ReconciliationFrontier,
) -> Result<(), ReconciliationError> {
    let first = commits
        .values()
        .next()
        .ok_or(ReconciliationError::InvalidInput)?;
    if commits.values().any(|commit| {
        commit.volume_id != first.volume_id || commit.root_object_id != first.root_object_id
    }) {
        return Err(ReconciliationError::MixedNamespace);
    }
    let heads = frontier
        .converged_head
        .into_iter()
        .chain(frontier.eligible_heads.iter().copied())
        .collect::<Vec<_>>();
    if heads.iter().collect::<BTreeSet<_>>().len() != heads.len() {
        return Err(ReconciliationError::InvalidInput);
    }
    if heads.iter().any(|head| !commits.contains_key(head)) {
        return Err(ReconciliationError::MissingCommit);
    }
    Ok(())
}

fn reachable(
    heads: impl IntoIterator<Item = NamespaceCommitId>,
    commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
) -> Result<BTreeSet<NamespaceCommitId>, ReconciliationError> {
    let mut selected = BTreeSet::new();
    let mut pending = heads.into_iter().collect::<Vec<_>>();
    while let Some(commit_id) = pending.pop() {
        if !selected.insert(commit_id) {
            continue;
        }
        let commit = commits
            .get(&commit_id)
            .ok_or(ReconciliationError::MissingCommit)?;
        pending.extend(commit.parents.iter().copied());
    }
    Ok(selected)
}

fn validate_acyclic(
    commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
) -> Result<(), ReconciliationError> {
    let mut unresolved = commits
        .iter()
        .map(|(commit_id, commit)| (*commit_id, commit.parents.len()))
        .collect::<BTreeMap<_, _>>();
    let mut ready = unresolved
        .iter()
        .filter_map(|(commit_id, count)| (*count == 0).then_some(*commit_id))
        .collect::<BTreeSet<_>>();
    let mut visited = 0_usize;
    while let Some(commit_id) = ready.pop_first() {
        visited += 1;
        for (child_id, child) in commits {
            if child.parents.contains(&commit_id) {
                let count = unresolved
                    .get_mut(child_id)
                    .ok_or(ReconciliationError::MissingCommit)?;
                *count = count.checked_sub(1).ok_or(ReconciliationError::Cycle)?;
                if *count == 0 {
                    ready.insert(*child_id);
                }
            }
        }
    }
    if visited == commits.len() {
        Ok(())
    } else {
        Err(ReconciliationError::Cycle)
    }
}

fn validate_operations(
    commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
) -> Result<(), ReconciliationError> {
    let mut operations = BTreeMap::new();
    for commit in commits.values() {
        match operations.insert(commit.operation_id, commit.request_digest) {
            Some(digest) if digest != commit.request_digest => {
                return Err(ReconciliationError::OperationConflict);
            }
            _ => {}
        }
    }
    Ok(())
}

fn select_pending(
    commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
    eligible: &BTreeSet<NamespaceCommitId>,
    converged: &BTreeSet<NamespaceCommitId>,
) -> BTreeSet<NamespaceCommitId> {
    let included_operations = converged
        .iter()
        .map(|commit_id| commits[commit_id].operation_id)
        .collect::<BTreeSet<_>>();
    let mut selected_by_operation = BTreeMap::new();
    for commit_id in eligible.difference(converged) {
        let operation = commits[commit_id].operation_id;
        if included_operations.contains(&operation) {
            continue;
        }
        selected_by_operation
            .entry(operation)
            .and_modify(|selected: &mut NamespaceCommitId| {
                *selected = (*selected).min(*commit_id);
            })
            .or_insert(*commit_id);
    }
    selected_by_operation.into_values().collect()
}

fn order_pending(
    commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
    pending: &BTreeSet<NamespaceCommitId>,
) -> Result<Vec<NamespaceCommitId>, ReconciliationError> {
    let mut unresolved = pending
        .iter()
        .map(|commit_id| {
            let count = commits[commit_id]
                .parents
                .iter()
                .filter(|parent| pending.contains(parent))
                .count();
            (*commit_id, count)
        })
        .collect::<BTreeMap<_, _>>();
    let mut ready = unresolved
        .iter()
        .filter_map(|(commit_id, count)| {
            (*count == 0).then_some((commits[commit_id].operation_id, *commit_id))
        })
        .collect::<BTreeSet<_>>();
    let mut ordered = Vec::with_capacity(pending.len());
    while let Some((_, commit_id)) = ready.pop_first() {
        ordered.push(commit_id);
        for child_id in pending {
            if commits[child_id].parents.contains(&commit_id) {
                let count = unresolved
                    .get_mut(child_id)
                    .ok_or(ReconciliationError::MissingCommit)?;
                *count = count.checked_sub(1).ok_or(ReconciliationError::Cycle)?;
                if *count == 0 {
                    ready.insert((commits[child_id].operation_id, *child_id));
                }
            }
        }
    }
    if ordered.len() == pending.len() {
        Ok(ordered)
    } else {
        Err(ReconciliationError::Cycle)
    }
}

fn minimal_frontier(
    frontier: &ReconciliationFrontier,
    commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
) -> Result<Vec<NamespaceCommitId>, ReconciliationError> {
    let candidates = frontier
        .converged_head
        .into_iter()
        .chain(frontier.eligible_heads.iter().copied())
        .collect::<BTreeSet<_>>();
    let mut minimal = Vec::new();
    for candidate in &candidates {
        let mut superseded = false;
        for head in candidates.iter().filter(|head| *head != candidate) {
            if reachable([*head], commits)?.contains(candidate) {
                superseded = true;
                break;
            }
        }
        if !superseded {
            minimal.push(*candidate);
        }
    }
    Ok(minimal)
}

fn plan_digest(
    commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
    frontier: &ReconciliationFrontier,
    ordered: &[NamespaceCommitId],
    parents: &[NamespaceCommitId],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.reconciliation-plan.v1\0");
    if let Some(head) = frontier.converged_head {
        digest.update(&[1]);
        digest.update(&head.as_bytes());
    } else {
        digest.update(&[0]);
    }
    update_commits(&mut digest, commits);
    update_ids(&mut digest, &frontier.eligible_heads);
    update_ids(&mut digest, ordered);
    for commit_id in ordered {
        let commit = commits[commit_id];
        digest.update(&commit.operation_id.as_bytes());
        digest.update(&commit.request_digest);
        digest.update(&commit.root_object_revision_id.as_bytes());
    }
    update_ids(&mut digest, parents);
    digest.finalize().into()
}

fn update_commits(
    digest: &mut blake3::Hasher,
    commits: &BTreeMap<NamespaceCommitId, &ReconciliationCommit>,
) {
    digest.update(
        &u32::try_from(commits.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for (commit_id, commit) in commits {
        digest.update(&commit_id.as_bytes());
        digest.update(&commit.branch_id.as_bytes());
        digest.update(&commit.volume_id.as_bytes());
        digest.update(&commit.root_object_id.as_bytes());
        digest.update(&commit.root_object_revision_id.as_bytes());
        update_ids(digest, &commit.parents);
        digest.update(&commit.operation_id.as_bytes());
        digest.update(&commit.request_digest);
    }
}

fn update_ids(digest: &mut blake3::Hasher, values: &[NamespaceCommitId]) {
    let mut canonical = values.to_vec();
    canonical.sort_unstable();
    digest.update(
        &u32::try_from(canonical.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for value in canonical {
        digest.update(&value.as_bytes());
    }
}

#[cfg(test)]
#[path = "reconciliation_tests.rs"]
mod tests;
