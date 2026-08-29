// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{DurationMicros, OperationId, Revision, UnixMicros};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::cleanup_attestation_tests::{
    ProposalFixture, SIGNING_KEY, proposal, register_key, signed_attestation,
};
use super::volume_head_tests::{HeadFixture, commit, context, publication_command};
use super::{ApplyDisposition, LogPosition, RepositoryError, VersionCleanupState};
use crate::{
    AuthoriseVersionCleanup, AuthoritativeCommand, CancelVersionCleanup, ConfigureVersionRetention,
    PartitionDatabase, RetentionReclaimMode,
};

#[test]
fn complete_current_evidence_authorises_once_and_survives_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("authorise.sqlite3");
    let ProposalFixture {
        mut repository,
        administrator,
        partition,
        cleanup_id,
        scan_request_digest,
        subject_digest,
        ..
    } = proposal(&file_path)?;
    register_key(&mut repository, administrator, 5, 1, SIGNING_KEY)?;
    repository.apply_committed(
        LogPosition { index: 6, term: 1 },
        context(60, administrator, 61, 106, Some(5))?,
        &signed_attestation(
            cleanup_id,
            Revision::new(4),
            scan_request_digest,
            subject_digest,
            62,
        )?,
    )?;

    let command = authorise(cleanup_id, subject_digest);
    let command_context = context(63, administrator, 64, 107, Some(6))?;
    let receipt =
        repository.apply_committed(LogPosition { index: 7, term: 1 }, command_context, &command)?;
    assert_eq!(receipt.committed_revision, Revision::new(7));
    assert_authorised(&repository, cleanup_id, command_context.operation_id)?;
    let replay =
        repository.apply_committed(LogPosition { index: 8, term: 1 }, command_context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    drop(repository);

    let reopened = PartitionDatabase::open(&file_path, partition, UnixMicros::new(500))?;
    assert_authorised(
        &super::AuthoritativeRepository::new(reopened),
        cleanup_id,
        command_context.operation_id,
    )?;
    Ok(())
}

#[test]
fn incomplete_proposal_can_only_cancel_without_deletion_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ProposalFixture {
        mut repository,
        administrator,
        cleanup_id,
        subject_digest,
        ..
    } = proposal(&directory.path().join("cancel.sqlite3"))?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 5, term: 1 },
            context(70, administrator, 71, 105, Some(4))?,
            &authorise(cleanup_id, subject_digest),
        ),
        Err(RepositoryError::StaleRevision)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(4));

    let cancel_context = context(72, administrator, 73, 106, Some(4))?;
    repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        cancel_context,
        &cancel(cleanup_id, subject_digest),
    )?;
    let intent = repository
        .version_cleanup_intent(cleanup_id)?
        .ok_or("missing cancelled intent")?;
    assert_eq!(intent.state, VersionCleanupState::Cancelled);
    assert_eq!(
        intent.terminal_operation_id,
        Some(cancel_context.operation_id)
    );
    assert_eq!(intent.terminal_revision, Some(Revision::new(5)));
    assert_eq!(intent.cancelled_at, Some(cancel_context.occurred_at));
    assert_eq!(intent.authorised_at, None);
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 6, term: 1 },
            context(74, administrator, 75, 107, Some(5))?,
            &authorise(cleanup_id, subject_digest),
        ),
        Err(RepositoryError::StaleRevision)
    ));
    Ok(())
}

#[test]
fn schema_rejects_partial_or_mixed_terminal_state() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ProposalFixture {
        repository,
        cleanup_id,
        ..
    } = proposal(&directory.path().join("constraints.sqlite3"))?;
    assert!(
        repository
            .database
            .connection()
            .execute(
                "UPDATE version_cleanup_intents SET state = 3
                 WHERE cleanup_operation_id = ?1",
                [cleanup_id.as_bytes().as_slice()],
            )
            .is_err()
    );
    assert!(
        repository
            .database
            .connection()
            .execute(
                "UPDATE version_cleanup_intents
                 SET terminal_kind = 2, terminal_operation_id = ?1,
                     terminal_revision = 5, cancelled_at = 100
                 WHERE cleanup_operation_id = ?2",
                rusqlite::params![
                    OperationId::from_bytes([76; 16])?.as_bytes().as_slice(),
                    cleanup_id.as_bytes().as_slice()
                ],
            )
            .is_err()
    );
    assert_eq!(
        repository
            .version_cleanup_intent(cleanup_id)?
            .ok_or("missing unchanged intent")?
            .state,
        VersionCleanupState::Pending
    );
    Ok(())
}

#[test]
fn changed_roots_or_policy_invalidate_complete_attestations()
-> Result<(), Box<dyn std::error::Error>> {
    for change_roots in [true, false] {
        let directory = tempdir()?;
        let ProposalFixture {
            mut repository,
            administrator,
            partition,
            volume,
            cleanup_id,
            scan_request_digest,
            subject_digest,
            manifest_root_digest: _,
        } = proposal(&directory.path().join("stale.sqlite3"))?;
        register_key(&mut repository, administrator, 5, 1, SIGNING_KEY)?;
        repository.apply_committed(
            LogPosition { index: 6, term: 1 },
            context(80, administrator, 81, 106, Some(5))?,
            &signed_attestation(
                cleanup_id,
                Revision::new(4),
                scan_request_digest,
                subject_digest,
                82,
            )?,
        )?;
        let change = if change_roots {
            publication_command(
                &HeadFixture {
                    administrator,
                    partition,
                    volume,
                },
                Some(commit(32)?),
                83,
                84,
                85,
                86,
                87,
            )?
        } else {
            replacement_policy(volume)
        };
        repository.apply_committed(
            LogPosition { index: 7, term: 1 },
            context(88, administrator, 89, 107, Some(6))?,
            &change,
        )?;
        let result = repository.apply_committed(
            LogPosition { index: 8, term: 1 },
            context(90, administrator, 91, 108, Some(7))?,
            &authorise(cleanup_id, subject_digest),
        );
        if change_roots {
            assert!(matches!(result, Err(RepositoryError::StaleRevision)));
        } else {
            assert!(matches!(result, Err(RepositoryError::StaleRetentionPolicy)));
        }
        assert_eq!(
            repository
                .version_cleanup_intent(cleanup_id)?
                .ok_or("missing pending intent")?
                .state,
            VersionCleanupState::Pending
        );
    }
    Ok(())
}

#[test]
fn rotated_key_or_tampered_signature_invalidates_complete_coverage()
-> Result<(), Box<dyn std::error::Error>> {
    for rotate_key in [true, false] {
        let directory = tempdir()?;
        let ProposalFixture {
            mut repository,
            administrator,
            cleanup_id,
            scan_request_digest,
            subject_digest,
            ..
        } = proposal(&directory.path().join("key-state.sqlite3"))?;
        register_key(&mut repository, administrator, 5, 1, SIGNING_KEY)?;
        repository.apply_committed(
            LogPosition { index: 6, term: 1 },
            context(100, administrator, 101, 106, Some(5))?,
            &signed_attestation(
                cleanup_id,
                Revision::new(4),
                scan_request_digest,
                subject_digest,
                102,
            )?,
        )?;
        let expected_revision = if rotate_key {
            register_key(&mut repository, administrator, 7, 2, [92; 32])?;
            Revision::new(7)
        } else {
            repository.database.connection().execute(
                "UPDATE version_cleanup_participants SET signature = ?1
                 WHERE cleanup_operation_id = ?2",
                rusqlite::params![[1_u8; 64].as_slice(), cleanup_id.as_bytes().as_slice()],
            )?;
            Revision::new(6)
        };
        assert!(
            repository
                .apply_committed(
                    LogPosition {
                        index: expected_revision.get() + 1,
                        term: 1,
                    },
                    context(103, administrator, 104, 108, Some(expected_revision.get()),)?,
                    &authorise(cleanup_id, subject_digest),
                )
                .is_err()
        );
        assert_eq!(repository.current_revision()?, expected_revision);
    }
    Ok(())
}

#[test]
fn every_apply_fault_rolls_back_terminal_authority() -> Result<(), Box<dyn std::error::Error>> {
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
            scan_request_digest,
            subject_digest,
            ..
        } = proposal(&directory.path().join("fault.sqlite3"))?;
        register_key(&mut repository, administrator, 5, 1, SIGNING_KEY)?;
        repository.apply_committed(
            LogPosition { index: 6, term: 1 },
            context(110, administrator, 111, 106, Some(5))?,
            &signed_attestation(
                cleanup_id,
                Revision::new(4),
                scan_request_digest,
                subject_digest,
                112,
            )?,
        )?;
        let command = authorise(cleanup_id, subject_digest);
        let command_context = context(113, administrator, 114, 107, Some(6))?;
        assert!(matches!(
            apply_committed_with_fault(
                &mut repository.database,
                LogPosition { index: 7, term: 1 },
                command_context,
                &command,
                fault,
            ),
            Err(RepositoryError::InjectedFault)
        ));
        assert_eq!(repository.current_revision()?, Revision::new(6));
        assert_eq!(
            repository
                .version_cleanup_intent(cleanup_id)?
                .ok_or("missing rolled-back intent")?
                .state,
            VersionCleanupState::Pending
        );
        repository.apply_committed(LogPosition { index: 7, term: 1 }, command_context, &command)?;
        assert_authorised(&repository, cleanup_id, command_context.operation_id)?;
    }
    Ok(())
}

pub(super) fn authorised_proposal(
    file_path: &std::path::Path,
) -> Result<ProposalFixture, Box<dyn std::error::Error>> {
    let mut fixture = proposal(file_path)?;
    register_key(
        &mut fixture.repository,
        fixture.administrator,
        5,
        1,
        SIGNING_KEY,
    )?;
    fixture.repository.apply_committed(
        LogPosition { index: 6, term: 1 },
        context(120, fixture.administrator, 121, 106, Some(5))?,
        &signed_attestation(
            fixture.cleanup_id,
            Revision::new(4),
            fixture.scan_request_digest,
            fixture.subject_digest,
            122,
        )?,
    )?;
    fixture.repository.apply_committed(
        LogPosition { index: 7, term: 1 },
        context(123, fixture.administrator, 124, 107, Some(6))?,
        &authorise(fixture.cleanup_id, fixture.subject_digest),
    )?;
    Ok(fixture)
}

pub(super) fn authorise(
    cleanup_operation_id: OperationId,
    subject: [u8; 32],
) -> AuthoritativeCommand {
    AuthoritativeCommand::AuthoriseVersionCleanup(AuthoriseVersionCleanup {
        cleanup_operation_id,
        cleanup_revision: Revision::new(4),
        reachability_subject_digest: subject,
    })
}

fn cancel(cleanup_operation_id: OperationId, subject: [u8; 32]) -> AuthoritativeCommand {
    AuthoritativeCommand::CancelVersionCleanup(CancelVersionCleanup {
        cleanup_operation_id,
        cleanup_revision: Revision::new(4),
        reachability_subject_digest: subject,
    })
}

fn replacement_policy(volume_id: meshspan_domain::VolumeId) -> AuthoritativeCommand {
    AuthoritativeCommand::ConfigureVersionRetention(ConfigureVersionRetention {
        volume_id,
        expected_policy_sequence: 1,
        history_enabled: true,
        minimum_age: DurationMicros::new(10_000),
        maximum_age: Some(DurationMicros::new(20_000)),
        minimum_versions: Some(2),
        reclaim_mode: RetentionReclaimMode::AfterMaximumAge,
        soft_minimum_breakable: false,
        conflict_minimum_age: DurationMicros::new(30_000),
    })
}

fn assert_authorised(
    repository: &super::AuthoritativeRepository,
    cleanup_operation_id: OperationId,
    terminal_operation_id: OperationId,
) -> Result<(), Box<dyn std::error::Error>> {
    let intent = repository
        .version_cleanup_intent(cleanup_operation_id)?
        .ok_or("missing authorised intent")?;
    assert_eq!(intent.state, VersionCleanupState::Authorised);
    assert_eq!(intent.terminal_operation_id, Some(terminal_operation_id));
    assert_eq!(intent.terminal_revision, Some(Revision::new(7)));
    assert_eq!(intent.authorised_at, Some(UnixMicros::new(107)));
    assert_eq!(intent.cancelled_at, None);
    Ok(())
}
