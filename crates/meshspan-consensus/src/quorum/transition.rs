// SPDX-License-Identifier: GPL-2.0-only

//! Old/new cross-family proof required before entering joint membership.

use std::collections::BTreeSet;

use meshspan_domain::NodeId;
use sha2::{Digest, Sha256};

use super::{CompiledQuorumPlan, QuorumFamily, QuorumPlanError};

/// Verified immutable evidence that two compiled plans may enter joint membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JointTransitionProof {
    /// Membership epoch being replaced.
    pub old_epoch: u64,
    /// Strictly newer membership epoch.
    pub new_epoch: u64,
    /// Digest binding both plan proofs and all required cross-intersection results.
    pub proof_digest: [u8; 32],
}

/// Proves old/new election, commit and read intersections required for safe reconfiguration.
///
/// # Errors
///
/// Rejects a non-increasing epoch or any unsafe old/joint/new phase intersection.
pub fn prove_joint_transition(
    old: &CompiledQuorumPlan,
    new: &CompiledQuorumPlan,
) -> Result<JointTransitionProof, QuorumPlanError> {
    if new.spec().membership_epoch <= old.spec().membership_epoch {
        return Err(QuorumPlanError::UnsafeTransition);
    }
    let old_election = node_sets(old, QuorumFamily::Election);
    let old_commit = node_sets(old, QuorumFamily::Commit);
    let new_election = node_sets(new, QuorumFamily::Election);
    let new_commit = node_sets(new, QuorumFamily::Commit);
    let joint_election = compose_joint(&old_election, &new_election);
    let joint_commit = compose_joint(&old_commit, &new_commit);
    let joint_read = compose_joint(
        &node_sets(old, QuorumFamily::Read),
        &node_sets(new, QuorumFamily::Read),
    );
    let safe = intersects_all(&old_election, &joint_commit)
        && intersects_all(&joint_election, &old_commit)
        && intersects_all(&joint_election, &joint_election)
        && intersects_all(&joint_election, &joint_commit)
        && intersects_all(&joint_read, &joint_election)
        && intersects_all(&joint_election, &new_commit)
        && intersects_all(&new_election, &joint_commit);
    if !safe {
        return Err(QuorumPlanError::UnsafeTransition);
    }
    let mut digest = Sha256::new();
    digest.update(b"meshspan.consensus.joint-transition.v1");
    digest.update(old.proof_digest());
    digest.update(new.proof_digest());
    digest.update(old.spec().membership_epoch.to_be_bytes());
    digest.update(new.spec().membership_epoch.to_be_bytes());
    digest.update([1; 5]);
    Ok(JointTransitionProof {
        old_epoch: old.spec().membership_epoch,
        new_epoch: new.spec().membership_epoch,
        proof_digest: digest.finalize().into(),
    })
}

fn intersects_all(left: &[BTreeSet<NodeId>], right: &[BTreeSet<NodeId>]) -> bool {
    left.iter()
        .all(|first| right.iter().all(|second| !first.is_disjoint(second)))
}

fn compose_joint(old: &[BTreeSet<NodeId>], new: &[BTreeSet<NodeId>]) -> Vec<BTreeSet<NodeId>> {
    let candidates: Vec<BTreeSet<NodeId>> = old
        .iter()
        .flat_map(|old_set| {
            new.iter().map(|new_set| {
                old_set
                    .union(new_set)
                    .copied()
                    .collect::<BTreeSet<NodeId>>()
            })
        })
        .collect();
    candidates
        .iter()
        .filter(|candidate| {
            !candidates
                .iter()
                .any(|other| other != *candidate && other.is_subset(candidate))
        })
        .cloned()
        .collect()
}

fn node_sets(plan: &CompiledQuorumPlan, family: QuorumFamily) -> Vec<BTreeSet<NodeId>> {
    plan.family(family)
        .minimal_quorums()
        .iter()
        .map(|set| set.to_nodes(plan.ordered_voters()))
        .collect()
}
