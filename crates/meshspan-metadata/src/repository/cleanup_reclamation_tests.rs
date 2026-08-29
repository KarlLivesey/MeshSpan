// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::{ReclamationReceipt, reclamation_receipt_digest};
use meshspan_domain::{NodeId, OperationId, Revision, UnixMicros};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::cleanup_attestation_tests::ProposalFixture;
use super::cleanup_completion_tests::{completion_command, issue, tombstone};
use super::cleanup_inventory_tests::{sealed_inventory, sealed_inventory_with_count};
use super::volume_head_tests::context;
use super::{ApplyDisposition, LogPosition, RepositoryError, VersionCleanupPermitAttempt};
use crate::{AuthoritativeCommand, ConfirmVersionCleanupReclamation, PartitionDatabase};

#[test]
fn exact_reclamation_is_replayable_restart_safe_and_terminal()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("reclamation.sqlite3");
    let ProposalFixture {
        mut repository,
        administrator,
        partition,
        cleanup_id,
        ..
    } = sealed_inventory(&file_path)?;
    let attempt = complete(&mut repository, administrator, cleanup_id, 0, 10, 240)?;
    let command = reclamation_command(cleanup_id, 0, attempt, 4_096, 118)?;
    let command_context = context(244, administrator, 245, 120, Some(11))?;
    let receipt = repository.apply_committed(
        LogPosition { index: 12, term: 1 },
        command_context,
        &command,
    )?;
    let item = repository
        .version_cleanup_item_reclamation(cleanup_id, 0)?
        .ok_or("missing item reclamation")?;
    assert_eq!(item.receipt.reclaimed_bytes, 4_096);
    assert_eq!(item.receipt.bytes_unlinked_at, UnixMicros::new(118));
    let summary = repository
        .version_cleanup_reclamation(cleanup_id)?
        .ok_or("missing terminal reclamation")?;
    assert_eq!(summary.reclaimed_item_count, 1);
    assert_eq!(summary.reclaimed_bytes, 4_096);
    assert_eq!(
        summary.reclamation_operation_id,
        command_context.operation_id
    );
    assert_eq!(summary.revision, Revision::new(12));
    let replay = repository.apply_committed(
        LogPosition { index: 13, term: 1 },
        command_context,
        &command,
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    assert_eq!(repository.current_revision()?, Revision::new(12));
    drop(repository);

    let reopened = PartitionDatabase::open(&file_path, partition, UnixMicros::new(500))?;
    let repository = super::AuthoritativeRepository::new(reopened);
    assert_eq!(
        repository
            .version_cleanup_reclamation(cleanup_id)?
            .ok_or("reclamation did not survive restart")?,
        summary
    );
    Ok(())
}

#[test]
fn summary_waits_for_every_item_and_sums_out_of_order_results()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ProposalFixture {
        mut repository,
        administrator,
        cleanup_id,
        ..
    } = sealed_inventory_with_count(&directory.path().join("ordered.sqlite3"), 2)?;
    let first = issue(&mut repository, administrator, cleanup_id, 0, 10, 246)?;
    let second = issue(&mut repository, administrator, cleanup_id, 1, 11, 248)?;
    repository.apply_committed(
        LogPosition { index: 12, term: 1 },
        context(250, administrator, 251, 122, Some(11))?,
        &completion_command(cleanup_id, Revision::new(9), first, 0)?,
    )?;
    repository.apply_committed(
        LogPosition { index: 13, term: 1 },
        context(252, administrator, 253, 123, Some(12))?,
        &reclamation_command(cleanup_id, 0, first, 5_000, 122)?,
    )?;
    assert_eq!(repository.version_cleanup_reclamation(cleanup_id)?, None);
    repository.apply_committed(
        LogPosition { index: 14, term: 1 },
        context(200, administrator, 201, 124, Some(13))?,
        &completion_command(cleanup_id, Revision::new(9), second, 1)?,
    )?;
    assert_eq!(repository.version_cleanup_reclamation(cleanup_id)?, None);
    repository.apply_committed(
        LogPosition { index: 15, term: 1 },
        context(202, administrator, 203, 125, Some(14))?,
        &reclamation_command(cleanup_id, 1, second, 7_000, 123)?,
    )?;
    let summary = repository
        .version_cleanup_reclamation(cleanup_id)?
        .ok_or("final reclamation did not create summary")?;
    assert_eq!(summary.reclaimed_item_count, 2);
    assert_eq!(summary.reclaimed_bytes, 12_000);
    assert_eq!(summary.revision, Revision::new(15));
    Ok(())
}

#[test]
fn missing_completion_substitution_forgery_and_stale_reporter_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ProposalFixture {
        mut repository,
        administrator,
        cleanup_id,
        ..
    } = sealed_inventory(&directory.path().join("reject.sqlite3"))?;
    let attempt = issue(&mut repository, administrator, cleanup_id, 0, 10, 204)?;
    let valid = reclamation_value(cleanup_id, 0, attempt, 1_024, 118)?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 11, term: 1 },
            context(206, administrator, 207, 120, Some(10))?,
            &AuthoritativeCommand::ConfirmVersionCleanupReclamation(valid),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    repository.apply_committed(
        LogPosition { index: 11, term: 1 },
        context(208, administrator, 209, 121, Some(10))?,
        &completion_command(cleanup_id, Revision::new(9), attempt, 0)?,
    )?;
    let mut invalid = Vec::new();
    let mut forged = valid;
    forged.receipt.reclamation_digest[0] ^= 1;
    invalid.push(forged);
    let mut substituted = valid;
    substituted.receipt.tombstone.tombstone_digest[0] ^= 1;
    invalid.push(substituted);
    let mut zero_bytes = valid;
    zero_bytes.receipt.reclaimed_bytes = 0;
    zero_bytes.receipt.reclamation_digest = reclamation_receipt_digest(
        zero_bytes.receipt.tombstone,
        zero_bytes.receipt.bytes_unlinked_at,
        0,
    );
    invalid.push(zero_bytes);
    let mut other_reporter = valid;
    other_reporter.reporter_node_id = NodeId::from_bytes([14; 16])?;
    invalid.push(other_reporter);
    let mut stale_reporter = valid;
    stale_reporter.reporter_incarnation = 2;
    invalid.push(stale_reporter);
    let mut future = valid;
    future.receipt.bytes_unlinked_at = UnixMicros::new(130);
    future.receipt.reclamation_digest = reclamation_receipt_digest(
        future.receipt.tombstone,
        future.receipt.bytes_unlinked_at,
        future.receipt.reclaimed_bytes,
    );
    invalid.push(future);
    for command in invalid {
        assert!(
            repository
                .apply_committed(
                    LogPosition { index: 12, term: 1 },
                    context(210, administrator, 211, 125, Some(11))?,
                    &AuthoritativeCommand::ConfirmVersionCleanupReclamation(command),
                )
                .is_err()
        );
        assert_eq!(repository.current_revision()?, Revision::new(11));
    }
    assert_eq!(
        repository.version_cleanup_item_reclamation(cleanup_id, 0)?,
        None
    );
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
        let attempt = complete(&mut repository, administrator, cleanup_id, 0, 10, 212)?;
        let command = reclamation_command(cleanup_id, 0, attempt, 2_048, 120)?;
        let command_context = context(216, administrator, 217, 126, Some(11))?;
        assert!(matches!(
            apply_committed_with_fault(
                &mut repository.database,
                LogPosition { index: 12, term: 1 },
                command_context,
                &command,
                fault,
            ),
            Err(RepositoryError::InjectedFault)
        ));
        assert_eq!(repository.current_revision()?, Revision::new(11));
        assert_eq!(
            repository.version_cleanup_item_reclamation(cleanup_id, 0)?,
            None
        );
        assert_eq!(repository.version_cleanup_reclamation(cleanup_id)?, None);
        repository.apply_committed(
            LogPosition { index: 12, term: 1 },
            command_context,
            &command,
        )?;
    }
    Ok(())
}

#[test]
fn persisted_item_or_summary_corruption_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    for corrupt_summary in [false, true] {
        let directory = tempdir()?;
        let ProposalFixture {
            mut repository,
            administrator,
            cleanup_id,
            ..
        } = sealed_inventory(&directory.path().join("corrupt.sqlite3"))?;
        let attempt = complete(&mut repository, administrator, cleanup_id, 0, 10, 218)?;
        repository.apply_committed(
            LogPosition { index: 12, term: 1 },
            context(222, administrator, 223, 127, Some(11))?,
            &reclamation_command(cleanup_id, 0, attempt, 3_072, 126)?,
        )?;
        if corrupt_summary {
            repository.database.connection_mut().execute(
                "UPDATE version_cleanup_reclamations SET reclaimed_bytes = 1",
                [],
            )?;
            assert!(matches!(
                repository.version_cleanup_reclamation(cleanup_id),
                Err(RepositoryError::CorruptState)
            ));
        } else {
            repository.database.connection_mut().execute(
                "UPDATE version_cleanup_item_reclamations SET reclamation_digest = ?1",
                [[9_u8; 32].as_slice()],
            )?;
            assert!(matches!(
                repository.version_cleanup_item_reclamation(cleanup_id, 0),
                Err(RepositoryError::CorruptState)
            ));
            assert!(matches!(
                repository.version_cleanup_reclamation(cleanup_id),
                Err(RepositoryError::CorruptState)
            ));
        }
    }
    Ok(())
}

fn complete(
    repository: &mut super::AuthoritativeRepository,
    administrator: meshspan_domain::PrincipalId,
    cleanup_id: OperationId,
    item_index: u64,
    issue_log_index: u64,
    identity: u8,
) -> Result<VersionCleanupPermitAttempt, Box<dyn std::error::Error>> {
    let attempt = issue(
        repository,
        administrator,
        cleanup_id,
        item_index,
        issue_log_index,
        identity,
    )?;
    repository.apply_committed(
        LogPosition {
            index: issue_log_index + 1,
            term: 1,
        },
        context(
            identity.saturating_add(2),
            administrator,
            identity.saturating_add(3),
            117,
            Some(issue_log_index),
        )?,
        &completion_command(cleanup_id, Revision::new(9), attempt, item_index)?,
    )?;
    Ok(attempt)
}

fn reclamation_command(
    cleanup_id: OperationId,
    item_index: u64,
    attempt: VersionCleanupPermitAttempt,
    reclaimed_bytes: u64,
    bytes_unlinked_at: i64,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::ConfirmVersionCleanupReclamation(
        reclamation_value(
            cleanup_id,
            item_index,
            attempt,
            reclaimed_bytes,
            bytes_unlinked_at,
        )?,
    ))
}

fn reclamation_value(
    cleanup_id: OperationId,
    item_index: u64,
    attempt: VersionCleanupPermitAttempt,
    reclaimed_bytes: u64,
    bytes_unlinked_at: i64,
) -> Result<ConfirmVersionCleanupReclamation, Box<dyn std::error::Error>> {
    let tombstone = tombstone(attempt);
    let bytes_unlinked_at = UnixMicros::new(bytes_unlinked_at);
    Ok(ConfirmVersionCleanupReclamation {
        cleanup_operation_id: cleanup_id,
        item_index,
        receipt: ReclamationReceipt {
            tombstone,
            bytes_unlinked_at,
            reclaimed_bytes,
            reclamation_digest: reclamation_receipt_digest(
                tombstone,
                bytes_unlinked_at,
                reclaimed_bytes,
            ),
        },
        reporter_node_id: NodeId::from_bytes([15; 16])?,
        reporter_incarnation: 1,
    })
}
