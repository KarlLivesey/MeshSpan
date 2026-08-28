// SPDX-License-Identifier: GPL-2.0-only

//! Exhaustive flexible and hierarchical quorum compilation for one to nine voters.

mod compile;
mod digest;
mod predicate;
mod transition;

use std::collections::BTreeSet;

use meshspan_domain::{NodeId, QuorumPlanId};
use thiserror::Error;

pub use compile::{FamilyProof, VoterSet, compile_plan};
pub use predicate::{QuorumPredicate, WeightedVoter};
pub use transition::{JointTransitionProof, prove_joint_transition};

const MAXIMUM_VOTERS: usize = 9;
const MAXIMUM_LEARNERS: usize = 256;

/// Immutable administrator/compiler input for one partition membership epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumPlanSpec {
    /// Stable plan identity.
    pub plan_id: QuorumPlanId,
    /// Independently versioned canonical plan format.
    pub format_version: u16,
    /// Monotonic partition membership epoch.
    pub membership_epoch: u64,
    /// Exact active voters.
    pub voters: BTreeSet<NodeId>,
    /// Non-voting fully replicated or catching-up members.
    pub learners: BTreeSet<NodeId>,
    /// Voters allowed to stand for leadership.
    pub eligible_leaders: BTreeSet<NodeId>,
    /// Same-term leader-election predicate.
    pub election: QuorumPredicate,
    /// Consensus-write commitment predicate.
    pub commit: QuorumPredicate,
    /// Current-leader linearizable read-barrier predicate.
    pub read: QuorumPredicate,
}

/// The three independently compiled quorum families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuorumFamily {
    /// Same-term leader election.
    Election,
    /// Replicated-log commitment.
    Commit,
    /// Current-leader read barrier.
    Read,
}

/// Fully verified canonical plan used by the hot-path core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledQuorumPlan {
    spec: QuorumPlanSpec,
    ordered_voters: Vec<NodeId>,
    election: FamilyProof,
    commit: FamilyProof,
    read: FamilyProof,
    proof_digest: [u8; 32],
}

impl CompiledQuorumPlan {
    /// Returns the immutable source specification independently recompiled by every voter.
    #[must_use]
    pub const fn spec(&self) -> &QuorumPlanSpec {
        &self.spec
    }

    /// Returns voters in canonical identity order used by bit sets and proof bytes.
    #[must_use]
    pub fn ordered_voters(&self) -> &[NodeId] {
        &self.ordered_voters
    }

    /// Returns one family's exhaustive minimal-quorum and cut-set proof.
    #[must_use]
    pub const fn family(&self, family: QuorumFamily) -> &FamilyProof {
        match family {
            QuorumFamily::Election => &self.election,
            QuorumFamily::Commit => &self.commit,
            QuorumFamily::Read => &self.read,
        }
    }

    /// Returns the digest binding canonical input, minimal sets and safety proof.
    #[must_use]
    pub const fn proof_digest(&self) -> [u8; 32] {
        self.proof_digest
    }

    /// Evaluates already-authenticated acknowledgements against one compiled family.
    #[must_use]
    pub fn satisfies(&self, family: QuorumFamily, acknowledgements: &BTreeSet<NodeId>) -> bool {
        let mask = VoterSet::from_nodes(&self.ordered_voters, acknowledgements);
        self.family(family).satisfies(mask)
    }
}

/// Rejection of unsafe, ambiguous or unbounded quorum input.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum QuorumPlanError {
    /// Plan version, epoch or membership cardinality is invalid.
    #[error("quorum plan header or membership is invalid")]
    InvalidPlan,
    /// A voter is duplicated, unknown, both voter and learner, or leader-ineligible.
    #[error("quorum plan contains an invalid member reference")]
    InvalidMember,
    /// Predicate depth, node count, threshold, weight or voter reference is invalid.
    #[error("quorum predicate is invalid or exceeds its bound")]
    InvalidPredicate,
    /// One quorum family has no satisfying voter subset.
    #[error("quorum family cannot make progress")]
    NoQuorum,
    /// Required election/election, election/commit or election/read intersection failed.
    #[error("quorum families do not satisfy required safety intersections")]
    UnsafeIntersection,
    /// Old and new plans cannot form a safe joint transition.
    #[error("quorum plans have no safe joint transition")]
    UnsafeTransition,
}

/// Builds the useful flat default for any supported one-to-nine voter set.
///
/// Election requires a strict majority. Commit/read use the smallest flat
/// threshold that intersects every election quorum, making even voter counts useful.
///
/// # Errors
///
/// Rejects zero or more than nine voters, learners overlapping voters or invalid identities.
pub fn flat_plan(
    plan_id: QuorumPlanId,
    membership_epoch: u64,
    voters: BTreeSet<NodeId>,
    learners: BTreeSet<NodeId>,
) -> Result<QuorumPlanSpec, QuorumPlanError> {
    validate_membership(&voters, &learners)?;
    let count = voters.len();
    let election_threshold = count / 2 + 1;
    let write_threshold = count
        .checked_sub(election_threshold)
        .and_then(|value| value.checked_add(1))
        .ok_or(QuorumPlanError::InvalidPlan)?;
    let children: Vec<QuorumPredicate> =
        voters.iter().copied().map(QuorumPredicate::Voter).collect();
    Ok(QuorumPlanSpec {
        plan_id,
        format_version: 1,
        membership_epoch,
        voters: voters.clone(),
        learners,
        eligible_leaders: voters,
        election: QuorumPredicate::AtLeast {
            threshold: u8::try_from(election_threshold)
                .map_err(|_| QuorumPlanError::InvalidPlan)?,
            children: children.clone(),
        },
        commit: QuorumPredicate::AtLeast {
            threshold: u8::try_from(write_threshold).map_err(|_| QuorumPlanError::InvalidPlan)?,
            children: children.clone(),
        },
        read: QuorumPredicate::AtLeast {
            threshold: u8::try_from(write_threshold).map_err(|_| QuorumPlanError::InvalidPlan)?,
            children,
        },
    })
}

fn validate_membership(
    voters: &BTreeSet<NodeId>,
    learners: &BTreeSet<NodeId>,
) -> Result<(), QuorumPlanError> {
    if voters.is_empty()
        || voters.len() > MAXIMUM_VOTERS
        || learners.len() > MAXIMUM_LEARNERS
        || !voters.is_disjoint(learners)
    {
        Err(QuorumPlanError::InvalidPlan)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
