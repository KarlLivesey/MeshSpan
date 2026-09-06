// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeSet;

use meshspan_consensus::{DurableMutation, LogEntry, compile_plan, flat_plan};
use meshspan_domain::{OperationId, PartitionId, PrincipalId, QuorumPlanId};
use tempfile::tempdir;

use super::*;
use crate::repository::{AuthoritativeRepository, tests::bootstrap_snapshot_repository};

#[test]
fn snapshot_capture_keeps_one_read_view_while_another_connection_commits()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let source = directory.path().join("authority.sqlite3");
    let destination = directory.path().join("snapshot.sqlite3");
    let partition = PartitionId::from_bytes([1; 16])?;
    let voter = NodeId::from_bytes([2; 16])?;
    let mut repository = AuthoritativeRepository::new(PartitionDatabase::open(
        &source,
        partition,
        UnixMicros::new(1),
    )?);
    bootstrap_snapshot_repository(&mut repository, PrincipalId::from_bytes([3; 16])?, voter)?;
    let plan = compile_plan(flat_plan(
        QuorumPlanId::from_bytes([4; 16])?,
        1,
        BTreeSet::from([voter]),
        BTreeSet::new(),
    )?)?;
    repository.initialise_consensus_quorum_plan(&plan, UnixMicros::new(19))?;
    repository.persist_consensus_mutation(
        1,
        &DurableMutation {
            vote_state: Some((1, Some(voter))),
            truncate_from: None,
            append: vec![LogEntry::new(
                meshspan_consensus::LogPosition { index: 1, term: 1 },
                OperationId::from_bytes([5; 16])?,
                1,
                b"bootstrap".to_vec(),
            )?],
            membership_epoch: None,
            quorum_plan: None,
        },
        UnixMicros::new(20),
    )?;
    let writer = rusqlite::Connection::open(&source)?;
    let appended = LogEntry::new(
        meshspan_consensus::LogPosition { index: 2, term: 1 },
        OperationId::from_bytes([7; 16])?,
        1,
        b"concurrent commit".to_vec(),
    )?;
    let mut payload = appended.operation_id.as_bytes().to_vec();
    payload.extend_from_slice(&appended.command);
    let manifest = create_snapshot_observed(
        &repository.database,
        SnapshotId::from_bytes([6; 16])?,
        &destination,
        &plan,
        UnixMicros::new(21),
        || {
            // A separate writer advances a consistent log/applied head exactly between
            // the source-state read and the online copy. No sleeps or serial test lock.
            let transaction = writer.unchecked_transaction()?;
            transaction.execute(
                "INSERT INTO consensus_log(log_index,term,entry_kind,entry_version,payload,payload_digest)
                 VALUES(2,1,1,1,?1,?2)", params![payload, appended.entry_digest().as_slice()],
            )?;
            transaction.execute(
                "UPDATE applied_state SET last_log_index=2 WHERE singleton=1",
                [],
            )?;
            transaction.commit()?;
            Ok(())
        },
    )?;
    assert_eq!(
        manifest.backup.applied_position,
        LogPosition { index: 1, term: 1 }
    );
    assert_eq!(repository.load_consensus_state(1)?.applied_index, 2);
    let restored = restore_partition_snapshot(
        &destination,
        &directory.path().join("restored.sqlite3"),
        manifest,
        &plan,
        PreservedVote {
            current_term: 1,
            voted_for: None,
            membership_epoch: 1,
        },
        UnixMicros::new(22),
    )?;
    assert_eq!(load_state(&restored, 1)?.applied_index, 1);
    Ok(())
}
