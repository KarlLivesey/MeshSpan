// SPDX-License-Identifier: GPL-2.0-only

//! Canonical replicated-log commands for learner admission, promotion and stable finalisation.

use meshspan_domain::NodeId;
use thiserror::Error;

use crate::{
    ActiveQuorumPlan, CatchUpEvidence, CompiledQuorumPlan, JointQuorumPlan, LogPosition,
    QuorumPlanRecordError,
};

/// Positive log command version reserved for canonical membership transitions.
pub const MEMBERSHIP_COMMAND_VERSION: u16 = 2;

const MAGIC: &[u8; 4] = b"MSMC";
const FORMAT_VERSION: u16 = 1;
const ADMIT_LEARNER: u8 = 1;
const PROMOTE_LEARNER: u8 = 2;
const FINALISE_STABLE: u8 = 3;
const REMOVE_MEMBER: u8 = 4;
const MAXIMUM_COMMAND_BYTES: usize = 96 * 1_024;

/// One independently validated membership transition carried by a committed log entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MembershipTransitionCommand {
    /// Adds one authoritative current-incarnation identity as a non-voting learner.
    AdmitLearner {
        /// Safe old+new phase whose new plan adds exactly this learner.
        joint_plan: Box<JointQuorumPlan>,
        /// Authoritative admitted identity.
        node_id: NodeId,
        /// Exact positive incarnation committed by enrolment.
        incarnation: u64,
    },
    /// Promotes one existing learner only with exact committed-history evidence.
    PromoteLearner {
        /// Safe old+new phase whose new plan promotes exactly this learner.
        joint_plan: Box<JointQuorumPlan>,
        /// Current-incarnation catch-up evidence bound to an exact committed entry.
        evidence: CatchUpEvidence,
    },
    /// Removes one exact current-incarnation voter or learner through a safe joint phase.
    RemoveMember {
        /// Safe old+new phase whose successor excludes exactly this member.
        joint_plan: Box<JointQuorumPlan>,
        /// Exact authoritative member identity being removed.
        node_id: NodeId,
        /// Current positive incarnation fenced by authoritative membership.
        incarnation: u64,
    },
    /// Leaves the active joint phase for its exact stable successor.
    FinaliseStable {
        /// Exact stable successor already proved inside the joint phase.
        plan: Box<CompiledQuorumPlan>,
    },
}

impl MembershipTransitionCommand {
    /// Revalidates semantic shape independently of how this value was constructed.
    ///
    /// # Errors
    ///
    /// Rejects anything except one-node admission, one caught-up learner promotion, or a stable
    /// finalisation record.
    pub fn validate(&self) -> Result<(), MembershipCommandError> {
        match self {
            Self::AdmitLearner {
                joint_plan,
                node_id,
                incarnation,
            } => validate_admission(joint_plan, *node_id, *incarnation),
            Self::PromoteLearner {
                joint_plan,
                evidence,
            } => validate_promotion(joint_plan, evidence),
            Self::RemoveMember {
                joint_plan,
                node_id,
                incarnation,
            } => validate_removal(joint_plan, *node_id, *incarnation),
            Self::FinaliseStable { .. } => Ok(()),
        }
    }

    /// Encodes one bounded canonical command containing source plan specifications, not cached
    /// proof output.
    ///
    /// # Errors
    ///
    /// Rejects invalid transition shape or a command exceeding the allocation bound.
    pub fn encode(&self) -> Result<Vec<u8>, MembershipCommandError> {
        self.validate()?;
        let (kind, active) = match self {
            Self::AdmitLearner { joint_plan, .. } => {
                (ADMIT_LEARNER, ActiveQuorumPlan::Joint(joint_plan.clone()))
            }
            Self::PromoteLearner { joint_plan, .. } => {
                (PROMOTE_LEARNER, ActiveQuorumPlan::Joint(joint_plan.clone()))
            }
            Self::RemoveMember { joint_plan, .. } => {
                (REMOVE_MEMBER, ActiveQuorumPlan::Joint(joint_plan.clone()))
            }
            Self::FinaliseStable { plan } => {
                (FINALISE_STABLE, ActiveQuorumPlan::Stable(plan.clone()))
            }
        };
        let plan = active.encode()?;
        let plan_length =
            u32::try_from(plan.len()).map_err(|_| MembershipCommandError::Malformed)?;
        let mut output = Vec::with_capacity(12 + plan.len() + 64);
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        output.push(kind);
        output.push(0);
        output.extend_from_slice(&plan_length.to_be_bytes());
        output.extend_from_slice(&plan);
        encode_evidence(self, &mut output);
        if output.len() > MAXIMUM_COMMAND_BYTES {
            return Err(MembershipCommandError::Malformed);
        }
        Ok(output)
    }

    /// Decodes hostile bytes, independently recompiles the embedded quorum proof and validates
    /// exact transition shape.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions/kinds, excessive lengths, invalid identifiers, trailing bytes and
    /// unsafe or semantically mismatched plans.
    pub fn decode(bytes: &[u8]) -> Result<Self, MembershipCommandError> {
        if bytes.len() > MAXIMUM_COMMAND_BYTES {
            return Err(MembershipCommandError::Malformed);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.read_array::<4>()? != *MAGIC || cursor.read_u16()? != FORMAT_VERSION {
            return Err(MembershipCommandError::Malformed);
        }
        let kind = cursor.read_u8()?;
        if cursor.read_u8()? != 0 {
            return Err(MembershipCommandError::Malformed);
        }
        let plan_length =
            usize::try_from(cursor.read_u32()?).map_err(|_| MembershipCommandError::Malformed)?;
        let plan = ActiveQuorumPlan::decode(cursor.read_slice(plan_length)?)?;
        let command = decode_evidence(kind, plan, &mut cursor)?;
        if !cursor.is_empty() {
            return Err(MembershipCommandError::Malformed);
        }
        command.validate()?;
        Ok(command)
    }
}

fn encode_evidence(command: &MembershipTransitionCommand, output: &mut Vec<u8>) {
    match command {
        MembershipTransitionCommand::AdmitLearner {
            node_id,
            incarnation,
            ..
        }
        | MembershipTransitionCommand::RemoveMember {
            node_id,
            incarnation,
            ..
        } => {
            output.extend_from_slice(&node_id.as_bytes());
            output.extend_from_slice(&incarnation.to_be_bytes());
        }
        MembershipTransitionCommand::PromoteLearner { evidence, .. } => {
            output.extend_from_slice(&evidence.node_id.as_bytes());
            output.extend_from_slice(&evidence.incarnation.to_be_bytes());
            output.extend_from_slice(&evidence.committed_position.term.to_be_bytes());
            output.extend_from_slice(&evidence.committed_position.index.to_be_bytes());
            output.extend_from_slice(&evidence.committed_entry_digest);
        }
        MembershipTransitionCommand::FinaliseStable { .. } => {}
    }
}

fn decode_evidence(
    kind: u8,
    active: ActiveQuorumPlan,
    cursor: &mut Cursor<'_>,
) -> Result<MembershipTransitionCommand, MembershipCommandError> {
    match (kind, active) {
        (ADMIT_LEARNER, ActiveQuorumPlan::Joint(joint_plan)) => {
            Ok(MembershipTransitionCommand::AdmitLearner {
                joint_plan,
                node_id: cursor.read_node_id()?,
                incarnation: cursor.read_u64()?,
            })
        }
        (PROMOTE_LEARNER, ActiveQuorumPlan::Joint(joint_plan)) => {
            Ok(MembershipTransitionCommand::PromoteLearner {
                joint_plan,
                evidence: CatchUpEvidence {
                    node_id: cursor.read_node_id()?,
                    incarnation: cursor.read_u64()?,
                    committed_position: LogPosition {
                        term: cursor.read_u64()?,
                        index: cursor.read_u64()?,
                    },
                    committed_entry_digest: cursor.read_array::<32>()?,
                    promotion_eligible: true,
                },
            })
        }
        (REMOVE_MEMBER, ActiveQuorumPlan::Joint(joint_plan)) => {
            Ok(MembershipTransitionCommand::RemoveMember {
                joint_plan,
                node_id: cursor.read_node_id()?,
                incarnation: cursor.read_u64()?,
            })
        }
        (FINALISE_STABLE, ActiveQuorumPlan::Stable(plan)) => {
            Ok(MembershipTransitionCommand::FinaliseStable { plan })
        }
        _ => Err(MembershipCommandError::InvalidTransition),
    }
}

fn validate_admission(
    joint: &JointQuorumPlan,
    node_id: NodeId,
    incarnation: u64,
) -> Result<(), MembershipCommandError> {
    let old = joint.old_plan().spec();
    let new = joint.new_plan().spec();
    let mut expected_learners = old.learners.clone();
    let inserted = expected_learners.insert(node_id);
    if incarnation == 0
        || !inserted
        || old.voters != new.voters
        || expected_learners != new.learners
    {
        Err(MembershipCommandError::InvalidTransition)
    } else {
        Ok(())
    }
}

fn validate_promotion(
    joint: &JointQuorumPlan,
    evidence: &CatchUpEvidence,
) -> Result<(), MembershipCommandError> {
    let old = joint.old_plan().spec();
    let new = joint.new_plan().spec();
    let mut expected_voters = old.voters.clone();
    let mut expected_learners = old.learners.clone();
    let was_learner = expected_learners.remove(&evidence.node_id);
    let became_voter = expected_voters.insert(evidence.node_id);
    if !evidence.promotion_eligible
        || evidence.incarnation == 0
        || evidence.committed_position == LogPosition::GENESIS
        || !was_learner
        || !became_voter
        || expected_voters != new.voters
        || expected_learners != new.learners
    {
        Err(MembershipCommandError::InvalidTransition)
    } else {
        Ok(())
    }
}

fn validate_removal(
    joint: &JointQuorumPlan,
    node_id: NodeId,
    incarnation: u64,
) -> Result<(), MembershipCommandError> {
    let old = joint.old_plan().spec();
    let new = joint.new_plan().spec();
    let mut expected_voters = old.voters.clone();
    let mut expected_learners = old.learners.clone();
    let removed = expected_voters.remove(&node_id) || expected_learners.remove(&node_id);
    if incarnation == 0
        || !removed
        || expected_voters.is_empty()
        || expected_voters != new.voters
        || expected_learners != new.learners
    {
        Err(MembershipCommandError::InvalidTransition)
    } else {
        Ok(())
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_slice(&mut self, length: usize) -> Result<&'a [u8], MembershipCommandError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(MembershipCommandError::Malformed)?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], MembershipCommandError> {
        self.read_slice(N)?
            .try_into()
            .map_err(|_| MembershipCommandError::Malformed)
    }

    fn read_u8(&mut self) -> Result<u8, MembershipCommandError> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, MembershipCommandError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, MembershipCommandError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, MembershipCommandError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_node_id(&mut self) -> Result<NodeId, MembershipCommandError> {
        NodeId::from_bytes(self.read_array()?).map_err(|_| MembershipCommandError::Malformed)
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Stable rejection categories for hostile membership command bytes or unsafe transitions.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MembershipCommandError {
    /// Framing, bounds, identifiers or canonical byte rules are invalid.
    #[error("membership command is malformed")]
    Malformed,
    /// The embedded plan cannot reproduce an independently safe proof.
    #[error("membership command quorum plan is invalid")]
    Plan(#[from] QuorumPlanRecordError),
    /// Command kind, plan phase or exact one-member transition shape is invalid.
    #[error("membership command transition is invalid")]
    InvalidTransition,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use meshspan_domain::QuorumPlanId;

    use super::*;
    use crate::{compile_plan, flat_plan};

    #[test]
    fn every_membership_command_round_trips_and_rejects_corruption()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = node(1)?;
        let learner = node(2)?;
        let old = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([3; 16])?,
            1,
            BTreeSet::from([first]),
            BTreeSet::new(),
        )?)?;
        let admitted = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([4; 16])?,
            2,
            BTreeSet::from([first]),
            BTreeSet::from([learner]),
        )?)?;
        let admission = MembershipTransitionCommand::AdmitLearner {
            joint_plan: Box::new(JointQuorumPlan::new(old, admitted.clone())?),
            node_id: learner,
            incarnation: 7,
        };
        assert_round_trip(&admission)?;

        let promoted = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([5; 16])?,
            3,
            BTreeSet::from([first, learner]),
            BTreeSet::new(),
        )?)?;
        let promotion = MembershipTransitionCommand::PromoteLearner {
            joint_plan: Box::new(JointQuorumPlan::new(admitted, promoted.clone())?),
            evidence: CatchUpEvidence {
                node_id: learner,
                incarnation: 7,
                committed_position: LogPosition { term: 2, index: 9 },
                committed_entry_digest: [6; 32],
                promotion_eligible: true,
            },
        };
        assert_round_trip(&promotion)?;
        let removed = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([7; 16])?,
            4,
            BTreeSet::from([first]),
            BTreeSet::new(),
        )?)?;
        assert_round_trip(&MembershipTransitionCommand::RemoveMember {
            joint_plan: Box::new(JointQuorumPlan::new(promoted.clone(), removed.clone())?),
            node_id: learner,
            incarnation: 7,
        })?;
        assert_round_trip(&MembershipTransitionCommand::FinaliseStable {
            plan: Box::new(removed),
        })?;

        let mut corrupt = promotion.encode()?;
        corrupt.push(0);
        assert!(matches!(
            MembershipTransitionCommand::decode(&corrupt),
            Err(MembershipCommandError::Malformed)
        ));
        Ok(())
    }

    fn assert_round_trip(
        command: &MembershipTransitionCommand,
    ) -> Result<(), MembershipCommandError> {
        assert_eq!(
            MembershipTransitionCommand::decode(&command.encode()?)?,
            *command
        );
        Ok(())
    }

    fn node(value: u8) -> Result<NodeId, meshspan_domain::IdentifierError> {
        NodeId::from_bytes([value; 16])
    }
}
