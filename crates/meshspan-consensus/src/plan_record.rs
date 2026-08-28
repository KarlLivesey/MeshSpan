// SPDX-License-Identifier: GPL-2.0-only

//! Canonical durable representation of an independently re-provable active quorum plan.

mod decode;
mod encode;

use std::collections::BTreeSet;

use meshspan_domain::NodeId;
use thiserror::Error;

use crate::{CompiledQuorumPlan, JointQuorumPlan};

const RECORD_MAGIC: &[u8; 4] = b"MSQP";
const RECORD_VERSION: u16 = 1;
const MAXIMUM_RECORD_BYTES: usize = 64 * 1_024;

/// Stable or joint quorum phase that must survive process and host restart exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActiveQuorumPlan {
    /// One committed stable plan.
    Stable(Box<CompiledQuorumPlan>),
    /// A committed old-and-new joint phase awaiting stable finalisation.
    Joint(Box<JointQuorumPlan>),
}

impl ActiveQuorumPlan {
    /// Returns the membership epoch carried by consensus messages in this phase.
    #[must_use]
    pub fn membership_epoch(&self) -> u64 {
        match self {
            Self::Stable(plan) => plan.spec().membership_epoch,
            Self::Joint(plan) => plan.membership_epoch(),
        }
    }

    /// Returns the mechanically derived proof digest for the active phase.
    #[must_use]
    pub fn proof_digest(&self) -> [u8; 32] {
        match self {
            Self::Stable(plan) => plan.proof_digest(),
            Self::Joint(plan) => plan.proof_digest(),
        }
    }

    /// Returns every voter and learner recognised during the active phase.
    #[must_use]
    pub fn members(&self) -> BTreeSet<NodeId> {
        match self {
            Self::Stable(plan) => plan
                .spec()
                .voters
                .union(&plan.spec().learners)
                .copied()
                .collect(),
            Self::Joint(plan) => plan.members(),
        }
    }

    /// Encodes the source plan specifications, never cached proof output.
    ///
    /// # Errors
    ///
    /// Rejects a representation that exceeds the durable record bound.
    pub fn encode(&self) -> Result<Vec<u8>, QuorumPlanRecordError> {
        encode::encode(self)
    }

    /// Decodes, validates and independently recompiles every proof from untrusted durable bytes.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions/phases, malformed or excessive values, trailing bytes and every
    /// plan or joint transition that cannot reproduce a safe compiled result.
    pub fn decode(bytes: &[u8]) -> Result<Self, QuorumPlanRecordError> {
        decode::decode(bytes)
    }
}

/// Stable failures for an invalid or unsafe durable quorum-plan record.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum QuorumPlanRecordError {
    /// Record framing, bounds, identifiers or canonical collection rules are invalid.
    #[error("durable quorum plan record is malformed")]
    Malformed,
    /// Plan compilation or old/new joint-transition proof failed.
    #[error("durable quorum plan record cannot prove a safe plan")]
    Unsafe,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use meshspan_domain::{NodeId, QuorumPlanId};

    use super::*;
    use crate::{JointQuorumPlan, compile_plan, flat_plan};

    #[test]
    fn stable_and_joint_records_round_trip_then_reject_corruption()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = node(1)?;
        let second = node(2)?;
        let learner = node(3)?;
        let old = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([11; 16])?,
            1,
            BTreeSet::from([first, second]),
            BTreeSet::from([learner]),
        )?)?;
        let new = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([12; 16])?,
            2,
            BTreeSet::from([first, second, learner]),
            BTreeSet::new(),
        )?)?;
        let stable = ActiveQuorumPlan::Stable(Box::new(old.clone()));
        assert_eq!(ActiveQuorumPlan::decode(&stable.encode()?)?, stable);

        let joint = ActiveQuorumPlan::Joint(Box::new(JointQuorumPlan::new(old, new)?));
        let encoded = joint.encode()?;
        assert_eq!(ActiveQuorumPlan::decode(&encoded)?, joint);
        let mut corrupt = encoded;
        let last = corrupt.last_mut().ok_or(QuorumPlanRecordError::Malformed)?;
        *last ^= 0xff;
        assert!(ActiveQuorumPlan::decode(&corrupt).is_err());
        Ok(())
    }

    fn node(value: u8) -> Result<NodeId, meshspan_domain::IdentifierError> {
        NodeId::from_bytes([value; 16])
    }
}
