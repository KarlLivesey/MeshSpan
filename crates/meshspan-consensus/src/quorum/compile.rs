// SPDX-License-Identifier: GPL-2.0-only

//! Exhaustive minimal-set compilation and fixed-plan intersection proof.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::NodeId;

use super::digest::plan_digest;
use super::{CompiledQuorumPlan, QuorumPlanError, QuorumPlanSpec, validate_membership};

/// Compact voter subset under one plan's canonical voter ordering.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct VoterSet(u16);

impl VoterSet {
    /// Empty acknowledgement/removal set.
    pub const EMPTY: Self = Self(0);

    /// Returns the stable compact representation used in proof fixtures.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Reports whether two voter subsets share at least one voter.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Reports whether this set contains every voter in `required`.
    #[must_use]
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub(super) const fn contains_bit(self, bit: u8) -> bool {
        self.0 & (1_u16 << bit) != 0
    }

    pub(super) fn from_nodes(ordered: &[NodeId], nodes: &BTreeSet<NodeId>) -> Self {
        let mut bits = 0_u16;
        for (index, voter) in ordered.iter().enumerate() {
            if nodes.contains(voter)
                && let Ok(bit) = u8::try_from(index)
            {
                bits |= 1_u16 << bit;
            }
        }
        Self(bits)
    }

    pub(super) fn to_nodes(self, ordered: &[NodeId]) -> BTreeSet<NodeId> {
        ordered
            .iter()
            .enumerate()
            .filter_map(|(index, voter)| {
                u8::try_from(index)
                    .ok()
                    .filter(|bit| self.contains_bit(*bit))
                    .map(|_| *voter)
            })
            .collect()
    }
}

/// Exhaustive upward-closed proof summary for one quorum family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FamilyProof {
    minimal_quorums: Vec<VoterSet>,
    minimal_cut_sets: Vec<VoterSet>,
}

impl FamilyProof {
    /// Returns every inclusion-minimal satisfying voter set in canonical order.
    #[must_use]
    pub fn minimal_quorums(&self) -> &[VoterSet] {
        &self.minimal_quorums
    }

    /// Returns every inclusion-minimal voter-removal set that blocks this family.
    #[must_use]
    pub fn minimal_cut_sets(&self) -> &[VoterSet] {
        &self.minimal_cut_sets
    }

    /// Evaluates acknowledgements using the mechanically reduced minimal family.
    #[must_use]
    pub fn satisfies(&self, acknowledgements: VoterSet) -> bool {
        self.minimal_quorums
            .iter()
            .any(|required| acknowledgements.contains(*required))
    }
}

/// Compiles and exhaustively proves one immutable plan of at most nine voters.
///
/// # Errors
///
/// Rejects invalid membership/predicates, families unable to progress, and every missing required
/// election/election, election/commit or election/read intersection.
pub fn compile_plan(spec: QuorumPlanSpec) -> Result<CompiledQuorumPlan, QuorumPlanError> {
    validate_header(&spec)?;
    let ordered_voters: Vec<NodeId> = spec.voters.iter().copied().collect();
    let voter_bits: BTreeMap<NodeId, u8> = ordered_voters
        .iter()
        .enumerate()
        .map(|(index, voter)| {
            u8::try_from(index)
                .map(|bit| (*voter, bit))
                .map_err(|_| QuorumPlanError::InvalidPlan)
        })
        .collect::<Result<_, _>>()?;
    spec.election.validate(&spec.voters)?;
    spec.commit.validate(&spec.voters)?;
    spec.read.validate(&spec.voters)?;
    let election = compile_family(&spec.election, &voter_bits, ordered_voters.len())?;
    let commit = compile_family(&spec.commit, &voter_bits, ordered_voters.len())?;
    let read = compile_family(&spec.read, &voter_bits, ordered_voters.len())?;
    prove_intersections(&election, &commit, &read)?;
    let proof_digest = plan_digest(&spec, &ordered_voters, &election, &commit, &read);
    Ok(CompiledQuorumPlan {
        spec,
        ordered_voters,
        election,
        commit,
        read,
        proof_digest,
    })
}

fn validate_header(spec: &QuorumPlanSpec) -> Result<(), QuorumPlanError> {
    validate_membership(&spec.voters, &spec.learners)?;
    if spec.format_version == 0
        || spec.membership_epoch == 0
        || spec.eligible_leaders.is_empty()
        || !spec.eligible_leaders.is_subset(&spec.voters)
    {
        Err(QuorumPlanError::InvalidPlan)
    } else {
        Ok(())
    }
}

fn compile_family(
    predicate: &super::QuorumPredicate,
    voter_bits: &BTreeMap<NodeId, u8>,
    voter_count: usize,
) -> Result<FamilyProof, QuorumPlanError> {
    let set_count = 1_u16
        .checked_shl(u32::try_from(voter_count).map_err(|_| QuorumPlanError::InvalidPlan)?)
        .ok_or(QuorumPlanError::InvalidPlan)?;
    let satisfying: Vec<VoterSet> = (1..set_count)
        .map(VoterSet)
        .filter(|set| predicate.evaluate(*set, voter_bits))
        .collect();
    if satisfying.is_empty() {
        return Err(QuorumPlanError::NoQuorum);
    }
    let minimal_quorums = reduce_minimal(&satisfying);
    let full = VoterSet(set_count - 1);
    let blocking: Vec<VoterSet> = (1..set_count)
        .map(VoterSet)
        .filter(|removed| {
            !minimal_quorums.iter().any(|quorum| {
                let available = VoterSet(full.0 & !removed.0);
                available.contains(*quorum)
            })
        })
        .collect();
    Ok(FamilyProof {
        minimal_quorums,
        minimal_cut_sets: reduce_minimal(&blocking),
    })
}

fn reduce_minimal(sets: &[VoterSet]) -> Vec<VoterSet> {
    sets.iter()
        .copied()
        .filter(|candidate| {
            !sets
                .iter()
                .any(|other| *other != *candidate && candidate.contains(*other))
        })
        .collect()
}

fn prove_intersections(
    election: &FamilyProof,
    commit: &FamilyProof,
    read: &FamilyProof,
) -> Result<(), QuorumPlanError> {
    let election_unique = intersects_all(&election.minimal_quorums, &election.minimal_quorums);
    let election_commit = intersects_all(&election.minimal_quorums, &commit.minimal_quorums);
    let election_read = intersects_all(&election.minimal_quorums, &read.minimal_quorums);
    if election_unique && election_commit && election_read {
        Ok(())
    } else {
        Err(QuorumPlanError::UnsafeIntersection)
    }
}

pub(super) fn intersects_all(left: &[VoterSet], right: &[VoterSet]) -> bool {
    left.iter()
        .all(|first| right.iter().all(|second| first.intersects(*second)))
}
