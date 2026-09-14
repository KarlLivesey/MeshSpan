// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeSet;

use meshspan_consensus::{ActiveQuorumPlan, JointQuorumPlan, compile_plan, flat_plan};
use meshspan_domain::{NodeId, QuorumPlanId};
use meshspan_metadata::JoinRoles;
use meshspan_protocol::v1::NodeRole;

use super::advertised_node_roles;

#[test]
fn private_hello_never_invents_services_or_consensus_membership()
-> Result<(), Box<dyn std::error::Error>> {
    let voter = NodeId::from_bytes([1; 16])?;
    let learner = NodeId::from_bytes([2; 16])?;
    let storage = NodeId::from_bytes([3; 16])?;
    let plan = ActiveQuorumPlan::Stable(Box::new(compile_plan(flat_plan(
        QuorumPlanId::from_bytes([4; 16])?,
        1,
        BTreeSet::from([voter]),
        BTreeSet::from([learner]),
    )?)?));
    for (node, bits, expected) in [
        (storage, JoinRoles::STORAGE, vec![NodeRole::Storage]),
        (storage, JoinRoles::GATEWAY, vec![NodeRole::Gateway]),
        (
            storage,
            JoinRoles::STORAGE | JoinRoles::METADATA_ELIGIBLE,
            vec![NodeRole::Storage],
        ),
        (
            learner,
            JoinRoles::METADATA_ELIGIBLE,
            vec![NodeRole::MetadataLearner],
        ),
        (
            voter,
            JoinRoles::METADATA_ELIGIBLE,
            vec![NodeRole::MetadataVoter],
        ),
        (
            voter,
            JoinRoles::STORAGE | JoinRoles::GATEWAY | JoinRoles::METADATA_ELIGIBLE,
            vec![
                NodeRole::Storage,
                NodeRole::Gateway,
                NodeRole::MetadataVoter,
            ],
        ),
    ] {
        assert_eq!(
            advertised_node_roles(node, JoinRoles::new(bits)?, &plan),
            Ok(expected)
        );
    }
    // An inconsistent role/membership projection is not an invitation to broaden roles.
    for node in [voter, learner] {
        assert!(advertised_node_roles(node, JoinRoles::new(JoinRoles::STORAGE)?, &plan).is_err());
    }
    // Eligibility by itself cannot advertise a service before actual learner admission.
    assert!(
        advertised_node_roles(
            storage,
            JoinRoles::new(JoinRoles::METADATA_ELIGIBLE)?,
            &plan,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn private_hello_preserves_voter_status_during_joint_transition()
-> Result<(), Box<dyn std::error::Error>> {
    let first = NodeId::from_bytes([1; 16])?;
    let second = NodeId::from_bytes([2; 16])?;
    let old = compile_plan(flat_plan(
        QuorumPlanId::from_bytes([3; 16])?,
        1,
        BTreeSet::from([first]),
        BTreeSet::from([second]),
    )?)?;
    let new = compile_plan(flat_plan(
        QuorumPlanId::from_bytes([4; 16])?,
        2,
        BTreeSet::from([first, second]),
        BTreeSet::new(),
    )?)?;
    let joint = ActiveQuorumPlan::Joint(Box::new(JointQuorumPlan::new(old, new)?));
    for node in [first, second] {
        assert_eq!(
            advertised_node_roles(node, JoinRoles::new(JoinRoles::METADATA_ELIGIBLE)?, &joint),
            Ok(vec![NodeRole::MetadataVoter]),
        );
    }
    Ok(())
}
