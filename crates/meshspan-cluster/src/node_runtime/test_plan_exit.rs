// SPDX-License-Identifier: GPL-2.0-only

//! Exact durable-plan crash point used only by real-process recovery proofs.

mod commit_loss;

use std::cell::Cell;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use meshspan_consensus::ActiveQuorumPlan;

use super::NodeRuntimeError;

const TARGET_ENVIRONMENT_VARIABLE: &str = "MESHSPAN_TEST_EXIT_AFTER_PLAN";
const TEST_EXIT_CODE: i32 = 86;
const PHASE_PROPAGATION_WINDOW: Duration = Duration::from_millis(300);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlanPhase {
    Joint,
    Stable,
}

pub(super) struct TestPlanExit {
    commit_loss: commit_loss::CommitLoss,
    target: Option<(PlanPhase, u64)>,
    marker_path: Option<PathBuf>,
    armed: Cell<bool>,
}

impl TestPlanExit {
    pub(super) fn load(state_path: &Path) -> Result<Self, NodeRuntimeError> {
        let commit_loss = commit_loss::CommitLoss::load(state_path)?;
        let Some(raw) = std::env::var_os(TARGET_ENVIRONMENT_VARIABLE) else {
            return Ok(Self {
                commit_loss,
                target: None,
                marker_path: None,
                armed: Cell::new(false),
            });
        };
        let raw = raw.to_str().ok_or(NodeRuntimeError::InvalidConfiguration)?;
        let (phase, epoch) = raw
            .split_once(':')
            .ok_or(NodeRuntimeError::InvalidConfiguration)?;
        let phase = match phase {
            "joint" => PlanPhase::Joint,
            "stable" => PlanPhase::Stable,
            _ => return Err(NodeRuntimeError::InvalidConfiguration),
        };
        let epoch = epoch
            .parse::<u64>()
            .ok()
            .filter(|epoch| *epoch > 0)
            .ok_or(NodeRuntimeError::InvalidConfiguration)?;
        Ok(Self {
            commit_loss,
            target: Some((phase, epoch)),
            marker_path: Some(state_path.with_extension(format!(
                "test-exit-{phase}-{epoch}.marker",
                phase = match phase {
                    PlanPhase::Joint => "joint",
                    PlanPhase::Stable => "stable",
                },
            ))),
            armed: Cell::new(false),
        })
    }

    pub(super) fn suppress_commit_notification(
        &self,
        message: &meshspan_consensus::CoreMessage,
        entry: Option<&meshspan_consensus::LogEntry>,
    ) -> Result<bool, NodeRuntimeError> {
        self.commit_loss.suppress(message, entry)
    }

    pub(super) fn arm_if_reached(&self, active_plan: &ActiveQuorumPlan) {
        let Some((target_phase, target_epoch)) = self.target else {
            return;
        };
        let actual_phase = match active_plan {
            ActiveQuorumPlan::Joint(_) => PlanPhase::Joint,
            ActiveQuorumPlan::Stable(_) => PlanPhase::Stable,
        };
        if actual_phase != target_phase || active_plan.membership_epoch() != target_epoch {
            return;
        }
        self.armed.set(true);
    }

    pub(super) fn exit_if_armed(&self) -> Result<(), NodeRuntimeError> {
        if !self.armed.replace(false) {
            return Ok(());
        }
        let marker_path = self
            .marker_path
            .as_ref()
            .ok_or(NodeRuntimeError::InvalidConfiguration)?;
        let mut marker = match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(marker_path)
        {
            Ok(marker) => marker,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        marker.write_all(b"durable plan phase reached\n")?;
        marker.sync_all()?;
        std::thread::sleep(PHASE_PROPAGATION_WINDOW);
        std::process::exit(TEST_EXIT_CODE);
    }
}
