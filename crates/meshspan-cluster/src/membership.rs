// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic bridge from authoritative enrolment and replication evidence to membership logs.

use std::collections::BTreeMap;

use meshspan_consensus::{
    ActiveQuorumPlan, CatchUpEvidence, CompiledQuorumPlan, LogEntry, MemberIncarnations,
    MembershipChangeError, MembershipCommandError, MembershipTransitionCommand, ProposalId,
    plan_flat_member_removal, plan_next_flat_learner_admission, plan_next_flat_promotion,
    recommended_voter_count,
};
use meshspan_domain::{NodeId, OperationId, QuorumPlanId};
use meshspan_metadata::AuthoritativeRepository;
use thiserror::Error;

pub(crate) fn plan_next_transition(
    active: &ActiveQuorumPlan,
    accepted_incarnations: &MemberIncarnations,
    active_voters: &BTreeMap<NodeId, u64>,
    admitted_learners: &BTreeMap<NodeId, u64>,
    retiring_members: &BTreeMap<NodeId, u64>,
    committed_entry: Option<&LogEntry>,
    matched_index: impl Fn(NodeId) -> Option<u64>,
) -> Result<Option<MembershipTransitionCommand>, MembershipCoordinatorError> {
    let stable = match active {
        ActiveQuorumPlan::Stable(stable) => stable,
        ActiveQuorumPlan::Joint(joint) => {
            return Ok(Some(MembershipTransitionCommand::FinaliseStable {
                plan: Box::new(joint.new_plan().clone()),
            }));
        }
    };
    let authoritative =
        authoritative_incarnations(active_voters, admitted_learners, retiring_members)?;
    verify_current_incarnations(stable, accepted_incarnations, &authoritative)?;
    if let Some((node_id, incarnation)) = retiring_members
        .iter()
        .find(|(node_id, _)| stable.members().contains(node_id))
    {
        let removal = plan_flat_member_removal(
            stable,
            accepted_incarnations,
            *node_id,
            *incarnation,
            next_plan_id(stable, 3)?,
        )?;
        return Ok(Some(MembershipTransitionCommand::RemoveMember {
            joint_plan: Box::new(removal.joint_plan),
            node_id: removal.removed_node_id,
            incarnation: *incarnation,
        }));
    }
    let eligible = authoritative_incarnations(active_voters, admitted_learners, &BTreeMap::new())?;
    let candidates = admitted_learners
        .iter()
        .filter(|(node, _)| !stable.members().contains(node))
        .map(|(node, incarnation)| (*node, *incarnation))
        .collect::<BTreeMap<_, _>>();
    if let Some(admission) = plan_next_flat_learner_admission(
        stable,
        accepted_incarnations,
        &candidates,
        next_plan_id(stable, 1)?,
    )? {
        let incarnation = admission
            .member_incarnations
            .incarnation(admission.admitted_node_id)
            .ok_or(MembershipCoordinatorError::InvalidAuthority)?;
        return Ok(Some(MembershipTransitionCommand::AdmitLearner {
            joint_plan: Box::new(admission.joint_plan),
            node_id: admission.admitted_node_id,
            incarnation,
        }));
    }
    plan_promotion(
        stable,
        accepted_incarnations,
        &eligible,
        committed_entry,
        matched_index,
    )
}

pub(crate) fn validate_transition(
    active: &ActiveQuorumPlan,
    accepted_incarnations: &MemberIncarnations,
    active_voters: &BTreeMap<NodeId, u64>,
    admitted_learners: &BTreeMap<NodeId, u64>,
    retiring_members: &BTreeMap<NodeId, u64>,
    command: &MembershipTransitionCommand,
    evidence_entry: Option<&LogEntry>,
) -> Result<MemberIncarnations, MembershipCoordinatorError> {
    command.validate()?;
    let authoritative =
        authoritative_incarnations(active_voters, admitted_learners, retiring_members)?;
    match (active, command) {
        (
            ActiveQuorumPlan::Stable(current),
            MembershipTransitionCommand::AdmitLearner {
                joint_plan,
                node_id,
                incarnation,
            },
        ) => validate_admission(
            current,
            accepted_incarnations,
            admitted_learners,
            joint_plan,
            *node_id,
            *incarnation,
        ),
        (
            ActiveQuorumPlan::Stable(current),
            MembershipTransitionCommand::PromoteLearner {
                joint_plan,
                evidence,
            },
        ) => validate_promotion(
            current,
            accepted_incarnations,
            &authoritative,
            joint_plan,
            evidence,
            evidence_entry,
        ),
        (
            ActiveQuorumPlan::Stable(current),
            MembershipTransitionCommand::RemoveMember {
                joint_plan,
                node_id,
                incarnation,
            },
        ) => validate_removal(
            current,
            accepted_incarnations,
            &authoritative,
            retiring_members,
            joint_plan,
            *node_id,
            *incarnation,
        ),
        (ActiveQuorumPlan::Joint(joint), MembershipTransitionCommand::FinaliseStable { plan })
            if joint.new_plan() == plan.as_ref() =>
        {
            incarnations_for_members(
                &authoritative,
                &ActiveQuorumPlan::Stable(plan.clone()).members(),
            )
        }
        _ => Err(MembershipCoordinatorError::InvalidTransition),
    }
}

/// Rebuilds exact accepted incarnations from the authoritative membership projection.
///
/// # Errors
///
/// Rejects unreadable metadata or any disagreement between the plan and projected members.
pub fn restore_member_incarnations(
    repository: &AuthoritativeRepository,
    active_plan: &ActiveQuorumPlan,
) -> Result<MemberIncarnations, MembershipRestoreError> {
    let values = if let Some(membership) = repository.partition_membership()? {
        let mut values = membership.active_voters().clone();
        values.extend(membership.admitted_learners());
        values.extend(membership.retiring_members());
        active_plan
            .members()
            .into_iter()
            .map(|node| {
                values
                    .get(&node)
                    .copied()
                    .map(|incarnation| (node, incarnation))
                    .ok_or(MembershipRestoreError::InvalidAuthority)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?
    } else {
        active_plan
            .members()
            .into_iter()
            .map(|node| (node, 1))
            .collect()
    };
    MemberIncarnations::for_members(values, &active_plan.members())
        .map_err(|_| MembershipRestoreError::InvalidAuthority)
}

fn plan_promotion(
    stable: &CompiledQuorumPlan,
    accepted_incarnations: &MemberIncarnations,
    authoritative: &BTreeMap<NodeId, u64>,
    committed_entry: Option<&LogEntry>,
    matched_index: impl Fn(NodeId) -> Option<u64>,
) -> Result<Option<MembershipTransitionCommand>, MembershipCoordinatorError> {
    let desired = recommended_voter_count(authoritative.len());
    if desired <= stable.spec().voters.len() {
        return Ok(None);
    }
    let Some(committed_entry) = committed_entry else {
        return Ok(None);
    };
    let evidence = stable
        .spec()
        .learners
        .iter()
        .filter_map(|node| {
            let incarnation = accepted_incarnations.incarnation(*node)?;
            (matched_index(*node)? >= committed_entry.position.index).then_some((
                *node,
                CatchUpEvidence {
                    node_id: *node,
                    incarnation,
                    committed_position: committed_entry.position,
                    committed_entry_digest: committed_entry.entry_digest(),
                    promotion_eligible: true,
                },
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let promotion = match plan_next_flat_promotion(
        stable,
        accepted_incarnations,
        &evidence,
        committed_entry.position,
        committed_entry.entry_digest(),
        desired,
        next_plan_id(stable, 2)?,
    ) {
        Ok(value) => value,
        Err(MembershipChangeError::NoCaughtUpLearner) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(
        promotion.map(|planned| MembershipTransitionCommand::PromoteLearner {
            evidence: evidence[&planned.promoted_node_id],
            joint_plan: Box::new(planned.joint_plan),
        }),
    )
}

fn validate_admission(
    current: &CompiledQuorumPlan,
    accepted: &MemberIncarnations,
    admitted: &BTreeMap<NodeId, u64>,
    proposed: &meshspan_consensus::JointQuorumPlan,
    node_id: NodeId,
    incarnation: u64,
) -> Result<MemberIncarnations, MembershipCoordinatorError> {
    let candidates = admitted
        .iter()
        .filter(|(node, _)| !current.members().contains(node))
        .map(|(node, incarnation)| (*node, *incarnation))
        .collect::<BTreeMap<_, _>>();
    let planned = plan_next_flat_learner_admission(
        current,
        accepted,
        &candidates,
        proposed.new_plan().spec().plan_id,
    )?
    .ok_or(MembershipCoordinatorError::InvalidTransition)?;
    if planned.joint_plan != *proposed
        || planned.admitted_node_id != node_id
        || planned.member_incarnations.incarnation(node_id) != Some(incarnation)
    {
        Err(MembershipCoordinatorError::InvalidTransition)
    } else {
        Ok(planned.member_incarnations)
    }
}

fn validate_promotion(
    current: &CompiledQuorumPlan,
    accepted: &MemberIncarnations,
    authoritative: &BTreeMap<NodeId, u64>,
    proposed: &meshspan_consensus::JointQuorumPlan,
    evidence: &CatchUpEvidence,
    evidence_entry: Option<&LogEntry>,
) -> Result<MemberIncarnations, MembershipCoordinatorError> {
    let entry = evidence_entry.ok_or(MembershipCoordinatorError::InvalidTransition)?;
    if authoritative.get(&evidence.node_id) != Some(&evidence.incarnation)
        || entry.position != evidence.committed_position
        || entry.entry_digest() != evidence.committed_entry_digest
    {
        return Err(MembershipCoordinatorError::InvalidTransition);
    }
    let planned = plan_next_flat_promotion(
        current,
        accepted,
        &BTreeMap::from([(evidence.node_id, *evidence)]),
        evidence.committed_position,
        evidence.committed_entry_digest,
        current.spec().voters.len().saturating_add(1),
        proposed.new_plan().spec().plan_id,
    )?
    .ok_or(MembershipCoordinatorError::InvalidTransition)?;
    if planned.joint_plan != *proposed {
        return Err(MembershipCoordinatorError::InvalidTransition);
    }
    incarnations_for_members(authoritative, &proposed.members())
}

fn validate_removal(
    current: &CompiledQuorumPlan,
    accepted: &MemberIncarnations,
    authoritative: &BTreeMap<NodeId, u64>,
    retiring_members: &BTreeMap<NodeId, u64>,
    proposed: &meshspan_consensus::JointQuorumPlan,
    node_id: NodeId,
    incarnation: u64,
) -> Result<MemberIncarnations, MembershipCoordinatorError> {
    if retiring_members.get(&node_id) != Some(&incarnation) {
        return Err(MembershipCoordinatorError::InvalidTransition);
    }
    let planned = plan_flat_member_removal(
        current,
        accepted,
        node_id,
        incarnation,
        proposed.new_plan().spec().plan_id,
    )?;
    if planned.joint_plan != *proposed {
        return Err(MembershipCoordinatorError::InvalidTransition);
    }
    incarnations_for_members(authoritative, &proposed.members())
}

fn authoritative_incarnations(
    active_voters: &BTreeMap<NodeId, u64>,
    admitted_learners: &BTreeMap<NodeId, u64>,
    retiring_members: &BTreeMap<NodeId, u64>,
) -> Result<BTreeMap<NodeId, u64>, MembershipCoordinatorError> {
    if active_voters.is_empty()
        || active_voters.values().any(|value| *value == 0)
        || admitted_learners.values().any(|value| *value == 0)
        || retiring_members.values().any(|value| *value == 0)
    {
        return Err(MembershipCoordinatorError::InvalidAuthority);
    }
    let mut combined = active_voters.clone();
    for (node, incarnation) in admitted_learners {
        if combined.insert(*node, *incarnation).is_some() {
            return Err(MembershipCoordinatorError::InvalidAuthority);
        }
    }
    for (node, incarnation) in retiring_members {
        if combined.insert(*node, *incarnation).is_some() {
            return Err(MembershipCoordinatorError::InvalidAuthority);
        }
    }
    Ok(combined)
}

fn verify_current_incarnations(
    plan: &CompiledQuorumPlan,
    accepted: &MemberIncarnations,
    authoritative: &BTreeMap<NodeId, u64>,
) -> Result<(), MembershipCoordinatorError> {
    let expected = incarnations_for_members(authoritative, &plan.members())?;
    if &expected == accepted {
        Ok(())
    } else {
        Err(MembershipCoordinatorError::InvalidAuthority)
    }
}

fn incarnations_for_members(
    authoritative: &BTreeMap<NodeId, u64>,
    members: &std::collections::BTreeSet<NodeId>,
) -> Result<MemberIncarnations, MembershipCoordinatorError> {
    let values = members
        .iter()
        .map(|node| {
            authoritative
                .get(node)
                .copied()
                .map(|incarnation| (*node, incarnation))
                .ok_or(MembershipCoordinatorError::InvalidAuthority)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    MemberIncarnations::for_members(values, members)
        .map_err(|_| MembershipCoordinatorError::InvalidAuthority)
}

fn next_plan_id(
    current: &CompiledQuorumPlan,
    transition_kind: u8,
) -> Result<QuorumPlanId, MembershipCoordinatorError> {
    let mut bytes: [u8; 16] = current.proof_digest()[..16]
        .try_into()
        .map_err(|_| MembershipCoordinatorError::InvalidAuthority)?;
    bytes[0] ^= transition_kind;
    let next_epoch = current
        .spec()
        .membership_epoch
        .checked_add(1)
        .ok_or(MembershipCoordinatorError::InvalidTransition)?;
    for (target, source) in bytes[8..].iter_mut().zip(next_epoch.to_be_bytes()) {
        *target ^= source;
    }
    QuorumPlanId::from_bytes(bytes).map_err(|_| MembershipCoordinatorError::InvalidTransition)
}

pub(crate) fn membership_proposal_id(
    command: &MembershipTransitionCommand,
) -> Result<ProposalId, MembershipCoordinatorError> {
    let value = transition_epoch(command)
        .checked_mul(5)
        .and_then(|value| value.checked_add(u64::from(transition_kind(command))))
        .map(|value| value | (1_u64 << 63))
        .ok_or(MembershipCoordinatorError::InvalidTransition)?;
    Ok(ProposalId(value))
}

pub(crate) fn membership_operation_id(
    command: &MembershipTransitionCommand,
) -> Result<OperationId, MembershipCoordinatorError> {
    let digest = transition_digest(command);
    let mut bytes: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| MembershipCoordinatorError::InvalidTransition)?;
    bytes[0] ^= transition_kind(command);
    OperationId::from_bytes(bytes).map_err(|_| MembershipCoordinatorError::InvalidTransition)
}

const fn transition_kind(command: &MembershipTransitionCommand) -> u8 {
    match command {
        MembershipTransitionCommand::AdmitLearner { .. } => 1,
        MembershipTransitionCommand::PromoteLearner { .. } => 2,
        MembershipTransitionCommand::RemoveMember { .. } => 3,
        MembershipTransitionCommand::FinaliseStable { .. } => 4,
    }
}

fn transition_epoch(command: &MembershipTransitionCommand) -> u64 {
    match command {
        MembershipTransitionCommand::AdmitLearner { joint_plan, .. }
        | MembershipTransitionCommand::PromoteLearner { joint_plan, .. }
        | MembershipTransitionCommand::RemoveMember { joint_plan, .. } => {
            joint_plan.membership_epoch()
        }
        MembershipTransitionCommand::FinaliseStable { plan } => plan.spec().membership_epoch,
    }
}

fn transition_digest(command: &MembershipTransitionCommand) -> [u8; 32] {
    match command {
        MembershipTransitionCommand::AdmitLearner { joint_plan, .. }
        | MembershipTransitionCommand::PromoteLearner { joint_plan, .. }
        | MembershipTransitionCommand::RemoveMember { joint_plan, .. } => joint_plan.proof_digest(),
        MembershipTransitionCommand::FinaliseStable { plan } => plan.proof_digest(),
    }
}

/// Closed membership orchestration failures without topology or identity disclosure.
#[derive(Debug, Error)]
pub(crate) enum MembershipCoordinatorError {
    /// Authoritative membership rows and accepted incarnations disagree.
    #[error("authoritative membership state is invalid")]
    InvalidAuthority,
    /// The proposed phase is not the unique safe next automatic transition.
    #[error("membership transition is invalid")]
    InvalidTransition,
    /// Consensus membership planning rejected the target or evidence.
    #[error("membership planning failed")]
    Planning(#[from] MembershipChangeError),
    /// Canonical log command validation failed.
    #[error("membership command validation failed")]
    Command(#[from] MembershipCommandError),
}

/// Closed restoration failure for persisted member incarnations.
#[derive(Debug, Error)]
pub enum MembershipRestoreError {
    /// The persisted membership projection could not be read safely.
    #[error("membership repository failed")]
    Repository(#[from] meshspan_metadata::RepositoryError),
    /// The active quorum plan and authoritative projection disagree.
    #[error("membership authority is invalid")]
    InvalidAuthority,
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use meshspan_consensus::{
        ActiveQuorumPlan, CompiledQuorumPlan, MemberIncarnations, MembershipTransitionCommand,
        compile_plan, flat_plan,
    };
    use meshspan_domain::{NodeId, QuorumPlanId};

    use super::{plan_next_transition, validate_transition};

    #[test]
    fn retiring_voter_is_removed_through_the_only_valid_joint_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = node(1)?;
        let second = node(2)?;
        let third = node(3)?;
        let stable = plan(1, [first, second, third])?;
        let accepted = MemberIncarnations::new(
            BTreeMap::from([(first, 1), (second, 2), (third, 3)]),
            &stable,
        )?;
        let command = plan_next_transition(
            &ActiveQuorumPlan::Stable(Box::new(stable.clone())),
            &accepted,
            &BTreeMap::from([(first, 1), (second, 2)]),
            &BTreeMap::new(),
            &BTreeMap::from([(third, 3)]),
            None,
            |_| None,
        )?
        .ok_or("removal was not planned")?;
        let MembershipTransitionCommand::RemoveMember {
            joint_plan,
            node_id,
            incarnation,
        } = &command
        else {
            return Err("unexpected membership transition".into());
        };
        assert_eq!((*node_id, *incarnation), (third, 3));
        assert_eq!(joint_plan.old_plan(), &stable);
        assert_eq!(
            joint_plan.new_plan().spec().voters,
            BTreeSet::from([first, second])
        );
        let next_incarnations = validate_transition(
            &ActiveQuorumPlan::Stable(Box::new(stable)),
            &accepted,
            &BTreeMap::from([(first, 1), (second, 2)]),
            &BTreeMap::new(),
            &BTreeMap::from([(third, 3)]),
            &command,
            None,
        )?;
        assert_eq!(next_incarnations.incarnation(first), Some(1));
        assert_eq!(next_incarnations.incarnation(second), Some(2));
        assert_eq!(next_incarnations.incarnation(third), Some(3));
        let final_plan = Box::new(joint_plan.new_plan().clone());
        let stable_incarnations = validate_transition(
            &ActiveQuorumPlan::Joint(joint_plan.clone()),
            &next_incarnations,
            &BTreeMap::from([(first, 1), (second, 2)]),
            &BTreeMap::new(),
            &BTreeMap::from([(third, 3)]),
            &MembershipTransitionCommand::FinaliseStable { plan: final_plan },
            None,
        )?;
        assert_eq!(stable_incarnations.incarnation(first), Some(1));
        assert_eq!(stable_incarnations.incarnation(second), Some(2));
        assert_eq!(stable_incarnations.incarnation(third), None);
        Ok(())
    }

    #[test]
    fn retiring_final_voter_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let only = node(1)?;
        let stable = plan(1, [only])?;
        let accepted = MemberIncarnations::new(BTreeMap::from([(only, 1)]), &stable)?;
        assert!(
            plan_next_transition(
                &ActiveQuorumPlan::Stable(Box::new(stable)),
                &accepted,
                &BTreeMap::new(),
                &BTreeMap::new(),
                &BTreeMap::from([(only, 1)]),
                None,
                |_| None,
            )
            .is_err()
        );
        Ok(())
    }

    fn plan(
        epoch: u64,
        voters: impl IntoIterator<Item = NodeId>,
    ) -> Result<CompiledQuorumPlan, Box<dyn std::error::Error>> {
        let spec = flat_plan(
            QuorumPlanId::from_bytes([u8::try_from(epoch)?; 16])?,
            epoch,
            voters.into_iter().collect(),
            BTreeSet::new(),
        )?;
        Ok(compile_plan(spec)?)
    }

    fn node(value: u8) -> Result<NodeId, Box<dyn std::error::Error>> {
        Ok(NodeId::from_bytes([value; 16])?)
    }
}
