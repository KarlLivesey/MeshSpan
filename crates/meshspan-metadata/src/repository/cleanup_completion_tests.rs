// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::{TombstoneReceipt, tombstone_receipt_digest};
use meshspan_domain::{NodeId, OperationId, Revision, UnixMicros};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::cleanup_attestation_tests::ProposalFixture;
use super::cleanup_inventory_tests::{sealed_inventory, sealed_inventory_with_count};
use super::cleanup_permit_tests::issue_command;
use super::volume_head_tests::context;
use super::{ApplyDisposition, LogPosition, RepositoryError, VersionCleanupPermitAttempt};
use crate::{AuthoritativeCommand, CompleteVersionCleanupItem, PartitionDatabase};

#[test]
fn exact_completion_is_replayable_restart_safe_and_terminal()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("completion.sqlite3");
    let ProposalFixture {
        mut repository,
        administrator,
        partition,
        cleanup_id,
        ..
    } = sealed_inventory(&file_path)?;
    let attempt = issue(&mut repository, administrator, cleanup_id, 0, 10, 210)?;
    let command = completion_command(cleanup_id, Revision::new(9), attempt, 0)?;
    let command_context = context(212, administrator, 213, 120, Some(10))?;
    let receipt = repository.apply_committed(
        LogPosition { index: 11, term: 1 },
        command_context,
        &command,
    )?;
    let completed = repository
        .version_cleanup_item_completion(cleanup_id, 0)?
        .ok_or("missing item completion")?;
    assert_eq!(completed.receipt, tombstone(attempt));
    let summary = repository
        .version_cleanup_completion(cleanup_id)?
        .ok_or("missing terminal completion")?;
    assert_eq!(summary.completed_item_count, 1);
    assert_eq!(
        summary.completion_operation_id,
        command_context.operation_id
    );
    assert_eq!(summary.revision, Revision::new(11));
    assert!(
        repository
            .version_cleanup_permit_authority(cleanup_id, 0)
            .is_err()
    );
    let replay = repository.apply_committed(
        LogPosition { index: 12, term: 1 },
        command_context,
        &command,
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 13, term: 1 },
            context(234, administrator, 235, 121, Some(11))?,
            &command,
        ),
        Err(RepositoryError::OperationConflict)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(11));
    drop(repository);

    let reopened = PartitionDatabase::open(&file_path, partition, UnixMicros::new(500))?;
    let repository = super::AuthoritativeRepository::new(reopened);
    assert_eq!(
        repository
            .version_cleanup_completion(cleanup_id)?
            .ok_or("completion did not survive restart")?,
        summary
    );
    Ok(())
}

#[test]
fn final_summary_waits_for_every_item_and_is_order_independent()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ProposalFixture {
        mut repository,
        administrator,
        cleanup_id,
        ..
    } = sealed_inventory_with_count(&directory.path().join("ordered.sqlite3"), 2)?;
    let first = issue(&mut repository, administrator, cleanup_id, 0, 10, 214)?;
    let second = issue(&mut repository, administrator, cleanup_id, 1, 11, 216)?;
    repository.apply_committed(
        LogPosition { index: 12, term: 1 },
        context(218, administrator, 219, 122, Some(11))?,
        &completion_command(cleanup_id, Revision::new(9), second, 1)?,
    )?;
    assert_eq!(repository.version_cleanup_completion(cleanup_id)?, None);
    repository.apply_committed(
        LogPosition { index: 13, term: 1 },
        context(220, administrator, 221, 123, Some(12))?,
        &completion_command(cleanup_id, Revision::new(9), first, 0)?,
    )?;
    let summary = repository
        .version_cleanup_completion(cleanup_id)?
        .ok_or("final item did not create summary")?;
    assert_eq!(summary.completed_item_count, 2);
    assert_eq!(summary.revision, Revision::new(13));
    Ok(())
}

#[test]
fn substituted_receipt_attempt_seal_or_reporter_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ProposalFixture {
        mut repository,
        administrator,
        cleanup_id,
        ..
    } = sealed_inventory(&directory.path().join("reject.sqlite3"))?;
    let attempt = issue(&mut repository, administrator, cleanup_id, 0, 10, 222)?;
    let AuthoritativeCommand::CompleteVersionCleanupItem(valid) =
        completion_command(cleanup_id, Revision::new(9), attempt, 0)?
    else {
        return Err("wrong completion fixture".into());
    };
    let mut commands = Vec::new();
    let mut wrong_receipt = valid;
    wrong_receipt.receipt.target_generation += 1;
    commands.push(wrong_receipt);
    let mut forged_digest = valid;
    forged_digest.receipt.tombstone_digest[0] ^= 1;
    commands.push(forged_digest);
    let mut wrong_attempt = valid;
    wrong_attempt.permit_attempt_sequence = 2;
    commands.push(wrong_attempt);
    let mut wrong_seal = valid;
    wrong_seal.inventory_sealed_revision = Revision::new(8);
    commands.push(wrong_seal);
    let mut stale_reporter = valid;
    stale_reporter.reporter_incarnation = 2;
    commands.push(stale_reporter);
    for command in commands {
        assert!(
            repository
                .apply_committed(
                    LogPosition { index: 11, term: 1 },
                    context(224, administrator, 225, 124, Some(10))?,
                    &AuthoritativeCommand::CompleteVersionCleanupItem(command),
                )
                .is_err()
        );
        assert_eq!(repository.current_revision()?, Revision::new(10));
    }
    assert_eq!(
        repository.version_cleanup_item_completion(cleanup_id, 0)?,
        None
    );
    assert_eq!(repository.version_cleanup_completion(cleanup_id)?, None);
    Ok(())
}

#[test]
fn every_apply_fault_rolls_back_item_and_terminal_summary() -> Result<(), Box<dyn std::error::Error>>
{
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        let directory = tempdir()?;
        let ProposalFixture {
            mut repository,
            administrator,
            cleanup_id,
            ..
        } = sealed_inventory(&directory.path().join("fault.sqlite3"))?;
        let attempt = issue(&mut repository, administrator, cleanup_id, 0, 10, 226)?;
        let command = completion_command(cleanup_id, Revision::new(9), attempt, 0)?;
        let command_context = context(228, administrator, 229, 125, Some(10))?;
        assert!(matches!(
            apply_committed_with_fault(
                &mut repository.database,
                LogPosition { index: 11, term: 1 },
                command_context,
                &command,
                fault,
            ),
            Err(RepositoryError::InjectedFault)
        ));
        assert_eq!(repository.current_revision()?, Revision::new(10));
        assert_eq!(
            repository.version_cleanup_item_completion(cleanup_id, 0)?,
            None
        );
        assert_eq!(repository.version_cleanup_completion(cleanup_id)?, None);
        repository.apply_committed(
            LogPosition { index: 11, term: 1 },
            command_context,
            &command,
        )?;
    }
    Ok(())
}

#[test]
fn persisted_completion_corruption_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ProposalFixture {
        mut repository,
        administrator,
        cleanup_id,
        ..
    } = sealed_inventory(&directory.path().join("corrupt.sqlite3"))?;
    let attempt = issue(&mut repository, administrator, cleanup_id, 0, 10, 230)?;
    repository.apply_committed(
        LogPosition { index: 11, term: 1 },
        context(232, administrator, 233, 126, Some(10))?,
        &completion_command(cleanup_id, Revision::new(9), attempt, 0)?,
    )?;
    repository.database.connection_mut().execute(
        "UPDATE version_cleanup_item_completions SET tombstone_digest = ?1",
        [[9_u8; 32].as_slice()],
    )?;
    assert!(matches!(
        repository.version_cleanup_item_completion(cleanup_id, 0),
        Err(RepositoryError::CorruptState)
    ));
    assert!(matches!(
        repository.version_cleanup_completion(cleanup_id),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

fn issue(
    repository: &mut super::AuthoritativeRepository,
    administrator: meshspan_domain::PrincipalId,
    cleanup_id: OperationId,
    item_index: u64,
    log_index: u64,
    identity: u8,
) -> Result<VersionCleanupPermitAttempt, Box<dyn std::error::Error>> {
    let authority = repository.version_cleanup_permit_authority(cleanup_id, item_index)?;
    let digest_byte = u8::try_from(item_index.checked_add(1).ok_or("item overflow")?)?;
    let command = issue_command(
        authority,
        1,
        UnixMicros::new(1_000),
        [digest_byte; 32],
        None,
    )?;
    repository.apply_committed(
        LogPosition {
            index: log_index,
            term: 1,
        },
        context(
            identity,
            administrator,
            identity.saturating_add(1),
            115,
            Some(log_index - 1),
        )?,
        &command,
    )?;
    repository
        .version_cleanup_permit_attempt(cleanup_id, item_index)?
        .ok_or_else(|| "missing permit attempt".into())
}

fn completion_command(
    cleanup_id: OperationId,
    sealed_revision: Revision,
    attempt: VersionCleanupPermitAttempt,
    item_index: u64,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::CompleteVersionCleanupItem(
        CompleteVersionCleanupItem {
            cleanup_operation_id: cleanup_id,
            inventory_sealed_revision: sealed_revision,
            item_index,
            permit_attempt_sequence: attempt.attempt_sequence,
            receipt: tombstone(attempt),
            reporter_node_id: NodeId::from_bytes([15; 16])?,
            reporter_incarnation: 1,
        },
    ))
}

fn tombstone(attempt: VersionCleanupPermitAttempt) -> TombstoneReceipt {
    let permit = attempt.permit;
    TombstoneReceipt {
        operation_id: permit.operation_id,
        shard: permit.shard,
        target_id: permit.target_id,
        target_generation: permit.target_generation,
        permit_digest: permit.permit_digest,
        tombstone_digest: tombstone_receipt_digest(permit),
    }
}
