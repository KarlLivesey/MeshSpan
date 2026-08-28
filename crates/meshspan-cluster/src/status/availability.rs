// SPDX-License-Identifier: GPL-2.0-only

//! Metadata-partition availability derived from compiled quorum truth.

use std::collections::BTreeSet;

use meshspan_consensus::{CompiledQuorumPlan, QuorumFamily};
use meshspan_domain::NodeId;
use thiserror::Error;

/// Stable reason explaining an unavailable metadata operation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AvailabilityReason {
    /// No current eligible leader is known.
    NoKnownAuthority,
    /// The known leader is not reachable from this node.
    AuthorityUnreachable,
    /// Reachable voters cannot elect a replacement.
    ElectionQuorumUnavailable,
    /// Reachable voters cannot prove a consensus write.
    WriteQuorumUnavailable,
    /// Reachable voters cannot prove a linearizable read barrier.
    ReadQuorumUnavailable,
    /// The authority has not applied its committed state before serving a read.
    AuthorityApplicationBehind,
    /// This node has no locally readable applied state.
    LocalStateUnavailable,
}

/// Binary result for one independently evaluated availability property.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AvailabilityState {
    /// Current evidence satisfies the property's exact predicate.
    Available,
    /// Current evidence does not satisfy the property's exact predicate.
    Unavailable,
}

impl From<bool> for AvailabilityState {
    fn from(value: bool) -> Self {
        if value {
            Self::Available
        } else {
            Self::Unavailable
        }
    }
}

/// Complete input used to derive honest partition availability.
#[derive(Clone, Copy, Debug)]
pub struct PartitionStatusInput<'a> {
    /// Local node producing the projection.
    pub local_node_id: NodeId,
    /// Current leader learned from the active consensus term.
    pub known_authority: Option<NodeId>,
    /// Authenticated, lease-live voters reachable from the local node.
    pub reachable_voters: &'a BTreeSet<NodeId>,
    /// Whether the known authority has applied through its commit index.
    pub authority_applied_through_commit: bool,
    /// Whether this node has a valid bounded-stale applied view.
    pub local_state_available: bool,
}

/// Honest operation availability derived from one compiled quorum plan and live reachability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionAvailability {
    /// Current consensus authority, even when it is temporarily unreachable.
    pub known_authority: Option<NodeId>,
    /// Whether the known authority is reachable from this node.
    pub authority_reachable: AvailabilityState,
    /// Whether the reachable set could elect a valid authority.
    pub election: AvailabilityState,
    /// Whether a current authority can prove a new consensus write.
    pub consensus_write: AvailabilityState,
    /// Whether a current authority can complete a linearizable read barrier.
    pub linearizable_read: AvailabilityState,
    /// Whether this node can serve an explicitly bounded-stale read.
    pub bounded_stale_read: AvailabilityState,
    /// Deterministic reasons for every unavailable aspect.
    pub reasons: BTreeSet<AvailabilityReason>,
}

/// Rejection of contradictory status input.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AvailabilityError {
    /// Reachability contains a non-voter, local membership is unknown or the leader is ineligible.
    #[error("partition availability input contradicts the active quorum plan")]
    InvalidInput,
}

/// Derives read, write and election availability without claiming more than the active plan proves.
///
/// # Errors
///
/// Rejects non-voter reachability, an unknown local member or an ineligible known authority.
pub fn evaluate_partition_availability(
    plan: &CompiledQuorumPlan,
    input: PartitionStatusInput<'_>,
) -> Result<PartitionAvailability, AvailabilityError> {
    let membership = &plan.spec().voters | &plan.spec().learners;
    if !membership.contains(&input.local_node_id)
        || !input.reachable_voters.is_subset(&plan.spec().voters)
        || input
            .known_authority
            .is_some_and(|authority| !plan.spec().eligible_leaders.contains(&authority))
    {
        return Err(AvailabilityError::InvalidInput);
    }
    let authority_reachable = input
        .known_authority
        .is_some_and(|authority| input.reachable_voters.contains(&authority));
    let election_available = plan.satisfies(QuorumFamily::Election, input.reachable_voters);
    let write_quorum = plan.satisfies(QuorumFamily::Commit, input.reachable_voters);
    let read_quorum = plan.satisfies(QuorumFamily::Read, input.reachable_voters);
    let write_available = authority_reachable && write_quorum;
    let linearizable_read_available =
        authority_reachable && read_quorum && input.authority_applied_through_commit;
    let mut reasons = BTreeSet::new();
    add_authority_reasons(input.known_authority, authority_reachable, &mut reasons);
    add_quorum_reasons(election_available, write_quorum, read_quorum, &mut reasons);
    if authority_reachable && read_quorum && !input.authority_applied_through_commit {
        reasons.insert(AvailabilityReason::AuthorityApplicationBehind);
    }
    if !input.local_state_available {
        reasons.insert(AvailabilityReason::LocalStateUnavailable);
    }
    Ok(PartitionAvailability {
        known_authority: input.known_authority,
        authority_reachable: authority_reachable.into(),
        election: election_available.into(),
        consensus_write: write_available.into(),
        linearizable_read: linearizable_read_available.into(),
        bounded_stale_read: input.local_state_available.into(),
        reasons,
    })
}

fn add_authority_reasons(
    authority: Option<NodeId>,
    reachable: bool,
    reasons: &mut BTreeSet<AvailabilityReason>,
) {
    if authority.is_none() {
        reasons.insert(AvailabilityReason::NoKnownAuthority);
    } else if !reachable {
        reasons.insert(AvailabilityReason::AuthorityUnreachable);
    }
}

fn add_quorum_reasons(
    election: bool,
    write: bool,
    read: bool,
    reasons: &mut BTreeSet<AvailabilityReason>,
) {
    if !election {
        reasons.insert(AvailabilityReason::ElectionQuorumUnavailable);
    }
    if !write {
        reasons.insert(AvailabilityReason::WriteQuorumUnavailable);
    }
    if !read {
        reasons.insert(AvailabilityReason::ReadQuorumUnavailable);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshspan_consensus::{compile_plan, flat_plan};
    use meshspan_domain::QuorumPlanId;

    #[test]
    fn status_distinguishes_election_write_read_and_local_stale_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let voters = BTreeSet::from([node(1)?, node(2)?, node(3)?, node(4)?]);
        let plan = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([9; 16])?,
            1,
            voters,
            BTreeSet::new(),
        )?)?;
        let reachable = BTreeSet::from([node(1)?, node(2)?]);
        let status = evaluate_partition_availability(
            &plan,
            PartitionStatusInput {
                local_node_id: node(1)?,
                known_authority: Some(node(1)?),
                reachable_voters: &reachable,
                authority_applied_through_commit: true,
                local_state_available: true,
            },
        )?;
        assert_eq!(status.election, AvailabilityState::Unavailable);
        assert_eq!(status.consensus_write, AvailabilityState::Available);
        assert_eq!(status.linearizable_read, AvailabilityState::Available);
        assert_eq!(status.bounded_stale_read, AvailabilityState::Available);
        assert_eq!(
            status.reasons,
            BTreeSet::from([AvailabilityReason::ElectionQuorumUnavailable])
        );

        let isolated = BTreeSet::from([node(1)?]);
        let unavailable = evaluate_partition_availability(
            &plan,
            PartitionStatusInput {
                local_node_id: node(1)?,
                known_authority: None,
                reachable_voters: &isolated,
                authority_applied_through_commit: false,
                local_state_available: true,
            },
        )?;
        assert_eq!(unavailable.consensus_write, AvailabilityState::Unavailable);
        assert_eq!(
            unavailable.linearizable_read,
            AvailabilityState::Unavailable
        );
        assert_eq!(unavailable.bounded_stale_read, AvailabilityState::Available);
        assert!(
            unavailable
                .reasons
                .contains(&AvailabilityReason::NoKnownAuthority)
        );
        assert!(
            unavailable
                .reasons
                .contains(&AvailabilityReason::WriteQuorumUnavailable)
        );
        Ok(())
    }

    fn node(value: u8) -> Result<NodeId, meshspan_domain::IdentifierError> {
        NodeId::from_bytes([value; 16])
    }
}
