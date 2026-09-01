// SPDX-License-Identifier: GPL-2.0-only

//! Learner admission, catch-up snapshots and automatic voter promotion.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use meshspan_consensus::{ActiveQuorumPlan, CoreInput, MEMBERSHIP_COMMAND_VERSION, Role};
use meshspan_domain::{BackupId, NodeId, Revision, SnapshotId};
use meshspan_metadata::{
    AuthoritativeRepository, LogPosition as MetadataLogPosition, PartitionBackupManifest,
    PartitionSnapshotManifest, PreservedVote, restore_partition_snapshot,
};

use super::NodeRuntimeError;
use super::config::NodeConfig;
use super::network::{OutboundSnapshot, PeerNetwork, ReceivedSnapshot};
use super::service::{node_number, now, partition_id};
use crate::membership::{
    MembershipCoordinatorError, membership_operation_id, membership_proposal_id,
    plan_next_transition,
};
use crate::{DriverEffect, PartitionConsensusDriver};

pub(super) struct SnapshotDispatch {
    state_path: PathBuf,
    sent: BTreeSet<NodeId>,
}

impl SnapshotDispatch {
    pub(super) fn new(state_path: PathBuf) -> Self {
        Self {
            state_path,
            sent: BTreeSet::new(),
        }
    }
}

pub(super) fn install_admission_snapshot(
    config: &NodeConfig,
    received: ReceivedSnapshot,
) -> Result<(), NodeRuntimeError> {
    let active = ActiveQuorumPlan::decode(&received.snapshot.quorum_plan)
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    let ActiveQuorumPlan::Stable(plan) = active else {
        return Err(NodeRuntimeError::InvalidConfiguration);
    };
    if !plan.spec().voters.contains(&received.from)
        || !plan.spec().learners.contains(&config.node_id)
        || plan.proof_digest() != received.snapshot.quorum_plan_digest
        || plan.spec().membership_epoch != received.snapshot.membership_epoch
    {
        return Err(NodeRuntimeError::InvalidConfiguration);
    }
    let snapshot_id = SnapshotId::from_bytes(received.snapshot.snapshot_id)?;
    let included = received.snapshot.included_position;
    let manifest = PartitionSnapshotManifest {
        snapshot_id,
        backup: PartitionBackupManifest {
            backup_id: BackupId::from_bytes(snapshot_id.as_bytes())?,
            partition_id: partition_id()?,
            applied_position: MetadataLogPosition {
                term: included.term,
                index: included.index,
            },
            state_revision: Revision::new(received.snapshot.state_revision),
            schema_version: received.snapshot.format_version,
            byte_length: received.snapshot.total_bytes,
            digest: received.snapshot.digest,
            created_at: now(),
        },
        membership_epoch: received.snapshot.membership_epoch,
        quorum_plan_digest: received.snapshot.quorum_plan_digest,
    };
    let database = restore_partition_snapshot(
        &received.snapshot.staging_path,
        &config.state_path,
        manifest,
        &plan,
        PreservedVote {
            current_term: 1,
            voted_for: None,
            membership_epoch: 0,
        },
        now(),
    )?;
    let membership = AuthoritativeRepository::new(database)
        .partition_membership()?
        .ok_or(NodeRuntimeError::InvalidConfiguration)?;
    if membership.admitted_learners().get(&config.node_id) != Some(&1) {
        return Err(NodeRuntimeError::InvalidConfiguration);
    }
    received
        .installed
        .send(())
        .map_err(|()| NodeRuntimeError::InvalidConfiguration)
}

pub(super) fn dispatch_learner_snapshots(
    driver: &PartitionConsensusDriver<AuthoritativeRepository>,
    network: &PeerNetwork,
    dispatch: &mut SnapshotDispatch,
) -> Result<(), NodeRuntimeError> {
    if driver.role() != Role::Leader {
        return Ok(());
    }
    let ActiveQuorumPlan::Stable(plan) = driver.active_plan() else {
        return Ok(());
    };
    let Some(membership) = driver.persistence().partition_membership()? else {
        return Ok(());
    };
    for learner in &plan.spec().learners {
        if dispatch.sent.contains(learner) || !membership.admitted_learners().contains_key(learner)
        {
            continue;
        }
        let snapshot_id = learner_snapshot_id(plan, *learner)?;
        let destination = dispatch.state_path.with_extension(format!(
            "learner-{}-epoch-{}.snapshot",
            node_number(*learner).ok_or(NodeRuntimeError::InvalidConfiguration)?,
            plan.spec().membership_epoch,
        ));
        remove_owned_snapshot(&destination)?;
        let manifest =
            driver
                .persistence()
                .create_snapshot(snapshot_id, &destination, plan, now())?;
        let quorum_plan = ActiveQuorumPlan::Stable(plan.clone())
            .encode()
            .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
        network.send_snapshot(
            *learner,
            OutboundSnapshot {
                path: destination,
                manifest,
                quorum_plan,
            },
        );
        dispatch.sent.insert(*learner);
    }
    Ok(())
}

pub(super) fn maybe_plan_membership_transition(
    driver: &mut PartitionConsensusDriver<AuthoritativeRepository>,
) -> Result<Vec<DriverEffect>, NodeRuntimeError> {
    if driver.role() != Role::Leader
        || driver
            .last_log_entry()
            .is_some_and(|entry| entry.position.index > driver.commit_index())
    {
        return Ok(Vec::new());
    }
    let Some(membership) = driver.persistence().partition_membership()? else {
        return Ok(Vec::new());
    };
    let committed = driver.committed_entry().cloned();
    let command = plan_next_transition(
        driver.active_plan(),
        driver.member_incarnations(),
        membership.active_voters(),
        membership.admitted_learners(),
        committed.as_ref(),
        |node| driver.peer_matched_index(node),
    )?;
    let Some(command) = command else {
        return Ok(Vec::new());
    };
    let command_bytes = command.encode().map_err(MembershipCoordinatorError::from)?;
    driver
        .step(
            CoreInput::Propose {
                proposal_id: membership_proposal_id(&command)?,
                operation_id: membership_operation_id(&command)?,
                command_version: MEMBERSHIP_COMMAND_VERSION,
                command: command_bytes,
            },
            now(),
        )
        .map_err(Into::into)
}

fn learner_snapshot_id(
    plan: &meshspan_consensus::CompiledQuorumPlan,
    learner: NodeId,
) -> Result<SnapshotId, NodeRuntimeError> {
    let mut bytes: [u8; 16] = plan.proof_digest()[..16]
        .try_into()
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    for (target, source) in bytes.iter_mut().zip(learner.as_bytes()) {
        *target ^= source;
    }
    SnapshotId::from_bytes(bytes).map_err(Into::into)
}

fn remove_owned_snapshot(file_path: &Path) -> Result<(), NodeRuntimeError> {
    match std::fs::symlink_metadata(file_path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            std::fs::remove_file(file_path).map_err(Into::into)
        }
        Ok(_) => Err(NodeRuntimeError::InvalidConfiguration),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
