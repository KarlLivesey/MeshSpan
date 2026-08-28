// SPDX-License-Identifier: GPL-2.0-only

//! Verified complete-state consensus snapshot creation and staged installation.

use std::path::Path;

use meshspan_consensus::{CompiledQuorumPlan, DurableCoreState};
use meshspan_domain::{BackupId, NodeId, SnapshotId, UnixMicros};
use rusqlite::{TransactionBehavior, params};

use super::backup::{create_partition_backup, restore_partition_backup};
use super::consensus::load_state;
use super::{LogPosition, PartitionBackupManifest, RepositoryError};
use crate::PartitionDatabase;

/// Complete image manifest bound to one independently compiled consensus plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PartitionSnapshotManifest {
    /// Stable transfer/install identity.
    pub snapshot_id: SnapshotId,
    /// Exact complete SQLite image manifest.
    pub backup: PartitionBackupManifest,
    /// Membership epoch represented by the snapshot.
    pub membership_epoch: u64,
    /// Independently compiled quorum-plan proof digest.
    pub quorum_plan_digest: [u8; 32],
}

/// Receiver vote that a snapshot installation is forbidden to forget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreservedVote {
    /// Receiver's latest durable term.
    pub current_term: u64,
    /// Receiver's exact vote in that term, if any.
    pub voted_for: Option<NodeId>,
    /// Receiver's current accepted membership epoch.
    pub membership_epoch: u64,
}

pub(super) fn create_snapshot(
    database: &PartitionDatabase,
    snapshot_id: SnapshotId,
    destination: &Path,
    plan: &CompiledQuorumPlan,
    created_at: UnixMicros,
) -> Result<PartitionSnapshotManifest, RepositoryError> {
    let membership_epoch = plan.spec().membership_epoch;
    let consensus = load_state(database, membership_epoch).map_err(snapshot_store_error)?;
    validate_snapshot_state(&consensus)?;
    let backup_id = BackupId::from_bytes(snapshot_id.as_bytes())
        .map_err(|_| RepositoryError::SnapshotMismatch)?;
    let backup = create_partition_backup(database, backup_id, destination, created_at)?;
    validate_applied_position(&consensus, backup.applied_position)?;
    Ok(PartitionSnapshotManifest {
        snapshot_id,
        backup,
        membership_epoch,
        quorum_plan_digest: plan.proof_digest(),
    })
}

/// Verifies a staged image and opens a new installation without overwriting current state.
///
/// A newer/equal receiver vote is copied into the staged database before it is returned. The
/// caller atomically swaps repository ownership only after `ConsensusCore::restore` accepts the
/// independently compiled plan and returned durable state.
///
/// # Errors
///
/// Rejects image corruption, plan/epoch mismatch, vote downgrade or invalid restored state.
pub fn restore_partition_snapshot(
    source: &Path,
    destination: &Path,
    manifest: PartitionSnapshotManifest,
    plan: &CompiledQuorumPlan,
    preserved_vote: PreservedVote,
    migration_time: UnixMicros,
) -> Result<PartitionDatabase, RepositoryError> {
    if manifest.snapshot_id.as_bytes() != manifest.backup.backup_id.as_bytes()
        || manifest.membership_epoch != plan.spec().membership_epoch
        || manifest.quorum_plan_digest != plan.proof_digest()
        || preserved_vote.current_term == 0
        || preserved_vote.membership_epoch > manifest.membership_epoch
        || preserved_vote
            .voted_for
            .is_some_and(|node| !plan.spec().voters.contains(&node))
    {
        return Err(RepositoryError::SnapshotMismatch);
    }
    let mut restored =
        restore_partition_backup(source, destination, manifest.backup, migration_time)?;
    let snapshot_state =
        load_state(&restored, manifest.membership_epoch).map_err(snapshot_store_error)?;
    validate_snapshot_state(&snapshot_state)?;
    validate_applied_position(&snapshot_state, manifest.backup.applied_position)?;
    preserve_vote(
        &mut restored,
        manifest.membership_epoch,
        &snapshot_state,
        preserved_vote,
    )?;
    restored.check_integrity()?;
    Ok(restored)
}

fn preserve_vote(
    database: &mut PartitionDatabase,
    membership_epoch: u64,
    snapshot_state: &DurableCoreState,
    preserved: PreservedVote,
) -> Result<(), RepositoryError> {
    let installed_term = preserved.current_term.max(snapshot_state.current_term);
    let installed_vote = (preserved.current_term >= snapshot_state.current_term)
        .then_some(preserved.voted_for)
        .flatten();
    let transaction = database
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let vote = installed_vote.map(|node| node.as_bytes().to_vec());
    let changed = transaction.execute(
        "UPDATE consensus_vote
         SET current_term = ?1, voted_for_node_id = ?2, membership_epoch = ?3
         WHERE singleton = 1",
        params![
            i64::try_from(installed_term).map_err(|_| RepositoryError::SnapshotMismatch)?,
            vote,
            i64::try_from(membership_epoch).map_err(|_| RepositoryError::SnapshotMismatch)?
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::SnapshotMismatch);
    }
    transaction.commit()?;
    Ok(())
}

fn validate_snapshot_state(state: &DurableCoreState) -> Result<(), RepositoryError> {
    if state.current_term == 0 || state.applied_index == 0 || state.log.is_empty() {
        Err(RepositoryError::SnapshotMismatch)
    } else {
        Ok(())
    }
}

fn validate_applied_position(
    state: &DurableCoreState,
    applied: LogPosition,
) -> Result<(), RepositoryError> {
    let offset = state
        .applied_index
        .checked_sub(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(RepositoryError::SnapshotMismatch)?;
    let entry = state
        .log
        .get(offset)
        .ok_or(RepositoryError::SnapshotMismatch)?;
    if applied.index == state.applied_index && applied.term == entry.position.term {
        Ok(())
    } else {
        Err(RepositoryError::SnapshotMismatch)
    }
}

fn snapshot_store_error(_: super::ConsensusStoreError) -> RepositoryError {
    RepositoryError::SnapshotMismatch
}
