// SPDX-License-Identifier: GPL-2.0-only

//! Committed phase boundaries used only to replay a lagging member's historical prefix.

use std::collections::BTreeMap;

use super::{CoreError, LogEntry, LogPosition};
use crate::{ActiveQuorumPlan, MEMBERSHIP_COMMAND_VERSION, MembershipTransitionCommand};

#[derive(Default)]
pub(super) struct MembershipHistory {
    boundaries: BTreeMap<(u64, [u8; 32]), PhaseBoundary>,
}

pub(super) struct PhaseBoundary {
    pub plan: ActiveQuorumPlan,
    pub committed_position: LogPosition,
}

impl MembershipHistory {
    pub fn record(&mut self, plan: ActiveQuorumPlan, committed_position: LogPosition) {
        self.boundaries.insert(
            (plan.membership_epoch(), plan.proof_digest()),
            PhaseBoundary {
                plan,
                committed_position,
            },
        );
    }

    pub fn find(&self, epoch: u64, digest: [u8; 32]) -> Option<&PhaseBoundary> {
        self.boundaries.get(&(epoch, digest))
    }

    /// Reconstructs only applied transitions from the already bounded, verified durable log.
    /// An uncommitted tail can never authorise historical replay.
    pub fn restore(
        log: &[LogEntry],
        applied_index: u64,
        active: &ActiveQuorumPlan,
    ) -> Result<Self, CoreError> {
        let mut history = Self::default();
        let mut previous_successor = None;
        for entry in log
            .iter()
            .take_while(|entry| entry.position.index <= applied_index)
        {
            if entry.command_version != MEMBERSHIP_COMMAND_VERSION {
                continue;
            }
            let command = MembershipTransitionCommand::decode(&entry.command)
                .map_err(|_| CoreError::InvalidConfiguration)?;
            let (previous, successor) = phase_change(command, previous_successor.as_ref())?;
            history.record(previous, entry.position);
            previous_successor = Some(successor);
        }
        if previous_successor
            .as_ref()
            .is_some_and(|plan| plan != active)
        {
            return Err(CoreError::InvalidConfiguration);
        }
        Ok(history)
    }
}

fn phase_change(
    command: MembershipTransitionCommand,
    previous_successor: Option<&ActiveQuorumPlan>,
) -> Result<(ActiveQuorumPlan, ActiveQuorumPlan), CoreError> {
    match command {
        MembershipTransitionCommand::AdmitLearner { joint_plan, .. }
        | MembershipTransitionCommand::PromoteLearner { joint_plan, .. }
        | MembershipTransitionCommand::RemoveMember { joint_plan, .. } => {
            let previous = ActiveQuorumPlan::Stable(Box::new(joint_plan.old_plan().clone()));
            if previous_successor.is_some_and(|plan| plan != &previous) {
                return Err(CoreError::InvalidConfiguration);
            }
            Ok((previous, ActiveQuorumPlan::Joint(joint_plan)))
        }
        MembershipTransitionCommand::FinaliseStable { plan } => {
            let Some(ActiveQuorumPlan::Joint(joint)) = previous_successor else {
                return Err(CoreError::InvalidConfiguration);
            };
            if joint.new_plan() != plan.as_ref() {
                return Err(CoreError::InvalidConfiguration);
            }
            Ok((
                ActiveQuorumPlan::Joint(joint.clone()),
                ActiveQuorumPlan::Stable(plan),
            ))
        }
    }
}
