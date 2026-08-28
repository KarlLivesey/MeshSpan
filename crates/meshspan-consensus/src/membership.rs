// SPDX-License-Identifier: GPL-2.0-only

//! Learner catch-up evidence, automatic flat-plan promotion and joint quorum evaluation.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{NodeId, QuorumPlanId};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    CompiledQuorumPlan, JointTransitionProof, LogPosition, MemberIncarnations, QuorumFamily,
    compile_plan, flat_plan, prove_joint_transition,
};

/// Exact evidence that one learner contains the committed history it must preserve as a voter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatchUpEvidence {
    /// Learner identity.
    pub node_id: NodeId,
    /// Exact currently accepted process incarnation.
    pub incarnation: u64,
    /// Exact committed position independently verified on the learner.
    pub committed_position: LogPosition,
    /// Digest of the complete log entry at `committed_position`.
    pub committed_entry_digest: [u8; 32],
    /// Administrator policy permits automatic voter promotion.
    pub promotion_eligible: bool,
}

/// Verified old+new joint phase; every decision must satisfy both plans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JointQuorumPlan {
    old: CompiledQuorumPlan,
    new: CompiledQuorumPlan,
    proof: JointTransitionProof,
    digest: [u8; 32],
}

impl JointQuorumPlan {
    /// Constructs a joint plan only after the transition proof succeeds.
    ///
    /// # Errors
    ///
    /// Rejects a non-adjacent epoch or unsafe transition.
    pub fn new(
        old: CompiledQuorumPlan,
        new: CompiledQuorumPlan,
    ) -> Result<Self, MembershipChangeError> {
        if new.spec().membership_epoch != old.spec().membership_epoch.saturating_add(1) {
            return Err(MembershipChangeError::InvalidTransition);
        }
        let proof = prove_joint_transition(&old, &new)
            .map_err(|_| MembershipChangeError::InvalidTransition)?;
        let mut digest = Sha256::new();
        digest.update(b"meshspan.consensus.active-joint-plan.v1");
        digest.update(old.proof_digest());
        digest.update(new.proof_digest());
        digest.update(proof.proof_digest);
        Ok(Self {
            old,
            new,
            proof,
            digest: digest.finalize().into(),
        })
    }

    /// Requires the old and new family predicates simultaneously.
    #[must_use]
    pub fn satisfies(&self, family: QuorumFamily, acknowledgements: &BTreeSet<NodeId>) -> bool {
        self.old.satisfies(family, acknowledgements) && self.new.satisfies(family, acknowledgements)
    }

    /// Returns all nodes recognised during the joint phase.
    #[must_use]
    pub fn members(&self) -> BTreeSet<NodeId> {
        let old = self
            .old
            .spec()
            .voters
            .union(&self.old.spec().learners)
            .copied();
        let new: BTreeSet<NodeId> = self
            .new
            .spec()
            .voters
            .union(&self.new.spec().learners)
            .copied()
            .collect();
        old.chain(new).collect()
    }

    /// Only nodes eligible under both plans may lead during transition.
    #[must_use]
    pub fn eligible_leaders(&self) -> BTreeSet<NodeId> {
        self.old
            .spec()
            .eligible_leaders
            .intersection(&self.new.spec().eligible_leaders)
            .copied()
            .collect()
    }

    /// Returns the new membership epoch used by joint-phase messages.
    #[must_use]
    pub const fn membership_epoch(&self) -> u64 {
        self.proof.new_epoch
    }

    /// Returns a digest distinct from both stable plan digests.
    #[must_use]
    pub const fn proof_digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the proposed stable successor after joint commit.
    #[must_use]
    pub const fn new_plan(&self) -> &CompiledQuorumPlan {
        &self.new
    }

    /// Returns the stable predecessor required to commit the joint phase.
    #[must_use]
    pub const fn old_plan(&self) -> &CompiledQuorumPlan {
        &self.old
    }
}

/// One safe next automatic learner promotion, always applied through a joint phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedPromotion {
    /// Learner selected deterministically by stable node identity.
    pub promoted_node_id: NodeId,
    /// Verified joint phase.
    pub joint_plan: JointQuorumPlan,
}

/// One deterministic authoritative learner admission through a safe joint phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedLearnerAdmission {
    /// Lowest stable admitted identity selected from the authoritative candidate set.
    pub admitted_node_id: NodeId,
    /// Verified joint phase adding the selected identity as a non-voting learner.
    pub joint_plan: JointQuorumPlan,
    /// Exact incumbent-preserving incarnation set for the expanded membership.
    pub member_incarnations: MemberIncarnations,
}

/// Adds at most one authoritative candidate to a flat plan as a non-voting learner.
///
/// # Errors
///
/// Rejects zero incarnations, candidates already present in the plan, mismatched incumbent
/// incarnation state, an exhausted epoch or an unsafe compiled transition.
pub fn plan_next_flat_learner_admission(
    old: &CompiledQuorumPlan,
    accepted_incarnations: &MemberIncarnations,
    admitted_candidates: &BTreeMap<NodeId, u64>,
    new_plan_id: QuorumPlanId,
) -> Result<Option<PlannedLearnerAdmission>, MembershipChangeError> {
    let old_members = old.members();
    if !accepted_incarnations.matches_members(&old_members)
        || admitted_candidates
            .iter()
            .any(|(node, incarnation)| *incarnation == 0 || old_members.contains(node))
    {
        return Err(MembershipChangeError::InvalidTarget);
    }
    let Some((admitted_node_id, incarnation)) = admitted_candidates.first_key_value() else {
        return Ok(None);
    };
    let mut learners = old.spec().learners.clone();
    learners.insert(*admitted_node_id);
    let new = compile_plan(
        flat_plan(
            new_plan_id,
            old.spec()
                .membership_epoch
                .checked_add(1)
                .ok_or(MembershipChangeError::InvalidTransition)?,
            old.spec().voters.clone(),
            learners,
        )
        .map_err(|_| MembershipChangeError::InvalidTransition)?,
    )
    .map_err(|_| MembershipChangeError::InvalidTransition)?;
    let mut values = accepted_incarnations.values().clone();
    values.insert(*admitted_node_id, *incarnation);
    let member_incarnations =
        MemberIncarnations::new(values, &new).map_err(|_| MembershipChangeError::InvalidTarget)?;
    Ok(Some(PlannedLearnerAdmission {
        admitted_node_id: *admitted_node_id,
        joint_plan: JointQuorumPlan::new(old.clone(), new)?,
        member_incarnations,
    }))
}

/// Selects at most one fully caught-up eligible learner and builds the next flat plan.
///
/// Promotion is deliberately one node per committed joint transition. Calling this again after
/// the new stable plan commits continues towards `desired_voters` without skipping a safety phase.
///
/// # Errors
///
/// Rejects invalid targets, absent/stale evidence, digest mismatch or unsafe plan transition.
pub fn plan_next_flat_promotion(
    old: &CompiledQuorumPlan,
    accepted_incarnations: &MemberIncarnations,
    evidence: &BTreeMap<NodeId, CatchUpEvidence>,
    committed_position: LogPosition,
    committed_entry_digest: [u8; 32],
    desired_voters: usize,
    new_plan_id: QuorumPlanId,
) -> Result<Option<PlannedPromotion>, MembershipChangeError> {
    let current_voters = old.spec().voters.len();
    if desired_voters < current_voters || desired_voters > 9 || committed_position.index == 0 {
        return Err(MembershipChangeError::InvalidTarget);
    }
    if current_voters == desired_voters {
        return Ok(None);
    }
    let promoted_node_id = old
        .spec()
        .learners
        .iter()
        .copied()
        .find(|node| {
            evidence.get(node).is_some_and(|candidate| {
                candidate.node_id == *node
                    && candidate.promotion_eligible
                    && candidate.incarnation != 0
                    && accepted_incarnations.incarnation(*node) == Some(candidate.incarnation)
                    && candidate.committed_position == committed_position
                    && candidate.committed_entry_digest == committed_entry_digest
            })
        })
        .ok_or(MembershipChangeError::NoCaughtUpLearner)?;
    let mut voters = old.spec().voters.clone();
    voters.insert(promoted_node_id);
    let mut learners = old.spec().learners.clone();
    learners.remove(&promoted_node_id);
    let new = compile_plan(
        flat_plan(
            new_plan_id,
            old.spec()
                .membership_epoch
                .checked_add(1)
                .ok_or(MembershipChangeError::InvalidTransition)?,
            voters,
            learners,
        )
        .map_err(|_| MembershipChangeError::InvalidTransition)?,
    )
    .map_err(|_| MembershipChangeError::InvalidTransition)?;
    Ok(Some(PlannedPromotion {
        promoted_node_id,
        joint_plan: JointQuorumPlan::new(old.clone(), new)?,
    }))
}

/// Returns the normal automatic active-voter target for the available eligible population.
///
/// One and two voters are establishment modes. Above that, stable plans use the largest odd count
/// through nine, avoiding a needless voter when it does not improve failure tolerance.
#[must_use]
pub const fn recommended_voter_count(available_eligible_nodes: usize) -> usize {
    match available_eligible_nodes {
        0 => 0,
        1 => 1,
        2 => 2,
        value => {
            let bounded = if value > 9 { 9 } else { value };
            if bounded.is_multiple_of(2) {
                bounded - 1
            } else {
                bounded
            }
        }
    }
}

/// Stable automatic membership-planning failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MembershipChangeError {
    /// Desired count or committed history position is invalid.
    #[error("membership promotion target is invalid")]
    InvalidTarget,
    /// No learner has exact current-incarnation committed-history evidence.
    #[error("no eligible fully caught-up learner is available")]
    NoCaughtUpLearner,
    /// Old/new plans cannot form the required adjacent safe joint transition.
    #[error("membership transition is invalid")]
    InvalidTransition,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{QuorumPlanSpec, flat_plan};

    #[test]
    fn promotion_requires_exact_history_and_joint_quorums() -> Result<(), Box<dyn std::error::Error>>
    {
        let first = node(1)?;
        let second = node(2)?;
        let third = node(3)?;
        let old = compiled(1, BTreeSet::from([first]), BTreeSet::from([second, third]))?;
        let incarnations =
            MemberIncarnations::new(BTreeMap::from([(first, 1), (second, 4), (third, 2)]), &old)?;
        let position = LogPosition { term: 7, index: 9 };
        let digest = [8; 32];
        let evidence = BTreeMap::from([
            (
                second,
                CatchUpEvidence {
                    node_id: second,
                    incarnation: 4,
                    committed_position: position,
                    committed_entry_digest: digest,
                    promotion_eligible: true,
                },
            ),
            (
                third,
                CatchUpEvidence {
                    node_id: third,
                    incarnation: 1,
                    committed_position: position,
                    committed_entry_digest: digest,
                    promotion_eligible: true,
                },
            ),
        ]);
        let promotion = plan_next_flat_promotion(
            &old,
            &incarnations,
            &evidence,
            position,
            digest,
            3,
            QuorumPlanId::from_bytes([2; 16])?,
        )?
        .ok_or("promotion was unexpectedly complete")?;
        assert_eq!(promotion.promoted_node_id, second);
        assert_eq!(promotion.joint_plan.membership_epoch(), 2);
        assert!(
            !promotion
                .joint_plan
                .satisfies(QuorumFamily::Election, &BTreeSet::from([second, third]))
        );
        assert!(
            promotion
                .joint_plan
                .satisfies(QuorumFamily::Election, &BTreeSet::from([first, second]))
        );
        assert!(
            promotion
                .joint_plan
                .satisfies(QuorumFamily::Commit, &BTreeSet::from([first, second]))
        );
        Ok(())
    }

    #[test]
    fn learner_admission_is_authoritative_ordered_and_incarnation_fenced()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = node(1)?;
        let second = node(2)?;
        let third = node(3)?;
        let old = compiled(1, BTreeSet::from([first]), BTreeSet::new())?;
        let accepted = MemberIncarnations::new(BTreeMap::from([(first, 4)]), &old)?;
        let admission = plan_next_flat_learner_admission(
            &old,
            &accepted,
            &BTreeMap::from([(third, 2), (second, 7)]),
            QuorumPlanId::from_bytes([8; 16])?,
        )?
        .ok_or("admission was unexpectedly absent")?;
        assert_eq!(admission.admitted_node_id, second);
        assert_eq!(
            admission.joint_plan.new_plan().spec().learners,
            BTreeSet::from([second])
        );
        assert_eq!(admission.member_incarnations.incarnation(first), Some(4));
        assert_eq!(admission.member_incarnations.incarnation(second), Some(7));
        assert_eq!(admission.member_incarnations.incarnation(third), None);
        assert!(matches!(
            plan_next_flat_learner_admission(
                &old,
                &accepted,
                &BTreeMap::from([(first, 5)]),
                QuorumPlanId::from_bytes([9; 16])?,
            ),
            Err(MembershipChangeError::InvalidTarget)
        ));
        Ok(())
    }

    #[test]
    fn stale_or_wrong_history_evidence_never_promotes() -> Result<(), Box<dyn std::error::Error>> {
        let first = node(1)?;
        let second = node(2)?;
        let old = compiled(1, BTreeSet::from([first]), BTreeSet::from([second]))?;
        let incarnations =
            MemberIncarnations::new(BTreeMap::from([(first, 1), (second, 2)]), &old)?;
        let evidence = BTreeMap::from([(
            second,
            CatchUpEvidence {
                node_id: second,
                incarnation: 1,
                committed_position: LogPosition { term: 1, index: 5 },
                committed_entry_digest: [4; 32],
                promotion_eligible: true,
            },
        )]);
        assert!(matches!(
            plan_next_flat_promotion(
                &old,
                &incarnations,
                &evidence,
                LogPosition { term: 1, index: 5 },
                [4; 32],
                2,
                QuorumPlanId::from_bytes([3; 16])?,
            ),
            Err(MembershipChangeError::NoCaughtUpLearner)
        ));
        Ok(())
    }

    #[test]
    fn normal_voter_targets_keep_establishment_modes_then_odd_sets() {
        assert_eq!(
            (0..=12).map(recommended_voter_count).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 3, 5, 5, 7, 7, 9, 9, 9, 9]
        );
    }

    fn compiled(
        epoch: u64,
        voters: BTreeSet<NodeId>,
        learners: BTreeSet<NodeId>,
    ) -> Result<CompiledQuorumPlan, Box<dyn std::error::Error>> {
        let spec: QuorumPlanSpec = flat_plan(
            QuorumPlanId::from_bytes([u8::try_from(epoch)?; 16])?,
            epoch,
            voters,
            learners,
        )?;
        Ok(compile_plan(spec)?)
    }

    fn node(value: u8) -> Result<NodeId, Box<dyn std::error::Error>> {
        Ok(NodeId::from_bytes([value; 16])?)
    }
}
