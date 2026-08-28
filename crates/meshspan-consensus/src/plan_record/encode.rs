// SPDX-License-Identifier: GPL-2.0-only

//! Canonical active-plan encoder.

use meshspan_domain::NodeId;

use super::{
    ActiveQuorumPlan, MAXIMUM_RECORD_BYTES, QuorumPlanRecordError, RECORD_MAGIC, RECORD_VERSION,
};
use crate::{QuorumPlanSpec, QuorumPredicate, WeightedVoter};

const STABLE_PHASE: u8 = 1;
const JOINT_PHASE: u8 = 2;

pub(super) fn encode(plan: &ActiveQuorumPlan) -> Result<Vec<u8>, QuorumPlanRecordError> {
    let mut output = Vec::new();
    output.extend_from_slice(RECORD_MAGIC);
    unsigned_16(&mut output, RECORD_VERSION);
    match plan {
        ActiveQuorumPlan::Stable(stable) => {
            output.push(STABLE_PHASE);
            plan_spec(&mut output, stable.spec())?;
        }
        ActiveQuorumPlan::Joint(joint) => {
            output.push(JOINT_PHASE);
            plan_spec(&mut output, joint.old_plan().spec())?;
            plan_spec(&mut output, joint.new_plan().spec())?;
        }
    }
    if output.len() > MAXIMUM_RECORD_BYTES {
        Err(QuorumPlanRecordError::Malformed)
    } else {
        Ok(output)
    }
}

fn plan_spec(output: &mut Vec<u8>, spec: &QuorumPlanSpec) -> Result<(), QuorumPlanRecordError> {
    output.extend_from_slice(&spec.plan_id.as_bytes());
    unsigned_16(output, spec.format_version);
    unsigned_64(output, spec.membership_epoch);
    identifiers(output, spec.voters.iter().copied())?;
    identifiers(output, spec.learners.iter().copied())?;
    identifiers(output, spec.eligible_leaders.iter().copied())?;
    predicate(output, &spec.election)?;
    predicate(output, &spec.commit)?;
    predicate(output, &spec.read)
}

fn identifiers(
    output: &mut Vec<u8>,
    values: impl Iterator<Item = NodeId>,
) -> Result<(), QuorumPlanRecordError> {
    let values: Vec<NodeId> = values.collect();
    counted_length(output, values.len())?;
    for value in values {
        output.extend_from_slice(&value.as_bytes());
    }
    Ok(())
}

fn predicate(output: &mut Vec<u8>, value: &QuorumPredicate) -> Result<(), QuorumPlanRecordError> {
    match value {
        QuorumPredicate::Voter(node_id) => {
            output.push(1);
            output.extend_from_slice(&node_id.as_bytes());
        }
        QuorumPredicate::AtLeast {
            threshold,
            children,
        } => {
            output.push(2);
            output.push(*threshold);
            predicates(output, children)?;
        }
        QuorumPredicate::WeightedAtLeast { threshold, voters } => {
            output.push(3);
            unsigned_32(output, *threshold);
            weighted_voters(output, voters)?;
        }
        QuorumPredicate::All { children } => {
            output.push(4);
            predicates(output, children)?;
        }
    }
    Ok(())
}

fn predicates(
    output: &mut Vec<u8>,
    values: &[QuorumPredicate],
) -> Result<(), QuorumPlanRecordError> {
    counted_length(output, values.len())?;
    for value in values {
        predicate(output, value)?;
    }
    Ok(())
}

fn weighted_voters(
    output: &mut Vec<u8>,
    values: &[WeightedVoter],
) -> Result<(), QuorumPlanRecordError> {
    counted_length(output, values.len())?;
    for value in values {
        output.extend_from_slice(&value.voter.as_bytes());
        unsigned_16(output, value.weight);
    }
    Ok(())
}

fn counted_length(output: &mut Vec<u8>, value: usize) -> Result<(), QuorumPlanRecordError> {
    unsigned_16(
        output,
        u16::try_from(value).map_err(|_| QuorumPlanRecordError::Malformed)?,
    );
    Ok(())
}

fn unsigned_16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn unsigned_32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn unsigned_64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}
