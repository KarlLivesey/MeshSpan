// SPDX-License-Identifier: GPL-2.0-only

//! Drops old-phase commit notifications only in the dedicated process-proof executable.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use meshspan_consensus::{
    ActiveQuorumPlan, CoreMessage, LogEntry, MEMBERSHIP_COMMAND_VERSION,
    MembershipTransitionCommand,
};

use crate::node_runtime::NodeRuntimeError;

pub(super) struct CommitLoss {
    marker: Option<PathBuf>,
}

impl CommitLoss {
    pub fn load(state_path: &Path) -> Result<Self, NodeRuntimeError> {
        let marker = match std::env::var_os("MESHSPAN_TEST_DROP_MEMBERSHIP_COMMITS") {
            None => None,
            Some(value) if value == "true" => {
                Some(state_path.with_extension("lost-commits.marker"))
            }
            Some(_) => return Err(NodeRuntimeError::InvalidConfiguration),
        };
        Ok(Self { marker })
    }

    pub fn suppress(
        &self,
        message: &CoreMessage,
        entry: Option<&LogEntry>,
    ) -> Result<bool, NodeRuntimeError> {
        let Some(marker) = &self.marker else {
            return Ok(false);
        };
        let (CoreMessage::AppendRequest(request), Some(entry)) = (message, entry) else {
            return Ok(false);
        };
        if entry.command_version != MEMBERSHIP_COMMAND_VERSION {
            return Ok(false);
        }
        let successor = match MembershipTransitionCommand::decode(&entry.command)
            .map_err(|_| NodeRuntimeError::InvalidConfiguration)?
        {
            MembershipTransitionCommand::AdmitLearner { joint_plan, .. }
            | MembershipTransitionCommand::PromoteLearner { joint_plan, .. }
            | MembershipTransitionCommand::RemoveMember { joint_plan, .. } => {
                ActiveQuorumPlan::Joint(joint_plan)
            }
            MembershipTransitionCommand::FinaliseStable { plan } => ActiveQuorumPlan::Stable(plan),
        };
        if request.plan_digest == successor.proof_digest() {
            return Ok(false);
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(marker)?
            .write_all(b"dropped old-plan commit\n")?;
        Ok(true)
    }
}
