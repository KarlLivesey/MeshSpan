// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::RemovalPermit;
use meshspan_domain::{MeshId, OperationId, Revision, UnixMicros};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::cleanup_attestation_tests::ProposalFixture;
use super::cleanup_inventory_tests::sealed_inventory;
use super::volume_head_tests::context;
use super::{ApplyDisposition, LogPosition, RepositoryError};
use crate::{AuthoritativeCommand, IssueVersionCleanupPermit, PartitionDatabase};

#[test]
fn exact_short_lived_permit_is_replayable_and_restart_safe()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("permit.sqlite3");
    let ProposalFixture {
        mut repository,
        administrator,
        partition,
        cleanup_id,
        ..
    } = sealed_inventory(&file_path)?;
    let authority = repository.version_cleanup_permit_authority(cleanup_id, 0)?;
    assert_eq!(authority.issue_revision, Revision::new(10));
    assert_eq!(authority.attempt_sequence, 1);
    assert_eq!(
        authority.item.removal_operation_id,
        OperationId::from_bytes([130; 16])?
    );
    let command = issue_command(authority, 1, UnixMicros::new(200), [1; 32], None)?;
    let command_context = context(190, administrator, 191, 110, Some(9))?;
    let receipt = repository.apply_committed(
        LogPosition { index: 10, term: 1 },
        command_context,
        &command,
    )?;
    let attempt = repository
        .version_cleanup_permit_attempt(cleanup_id, 0)?
        .ok_or("missing permit attempt")?;
    assert_eq!(attempt.attempt_sequence, 1);
    assert_eq!(attempt.permit.catalogue_revision, Revision::new(10));
    assert_eq!(
        attempt.permit.operation_id,
        authority.item.removal_operation_id
    );
    assert_eq!(attempt.issue_operation_id, command_context.operation_id);
    assert_eq!(attempt.issued_at, command_context.occurred_at);
    let replay = repository.apply_committed(
        LogPosition { index: 11, term: 1 },
        command_context,
        &command,
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    drop(repository);

    let reopened = PartitionDatabase::open(&file_path, partition, UnixMicros::new(500))?;
    let repository = super::AuthoritativeRepository::new(reopened);
    assert_eq!(
        repository
            .version_cleanup_permit_attempt(cleanup_id, 0)?
            .ok_or("permit did not survive restart")?,
        attempt
    );
    Ok(())
}

#[test]
fn same_epoch_reissue_waits_for_expiry_but_new_epoch_fences_it_early()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ProposalFixture {
        mut repository,
        administrator,
        cleanup_id,
        ..
    } = sealed_inventory(&directory.path().join("renew.sqlite3"))?;
    let first_authority = repository.version_cleanup_permit_authority(cleanup_id, 0)?;
    repository.apply_committed(
        LogPosition { index: 10, term: 1 },
        context(192, administrator, 193, 110, Some(9))?,
        &issue_command(first_authority, 1, UnixMicros::new(200), [1; 32], None)?,
    )?;
    let second_authority = repository.version_cleanup_permit_authority(cleanup_id, 0)?;
    assert_eq!(second_authority.attempt_sequence, 2);
    let same_epoch = issue_command(
        second_authority,
        1,
        UnixMicros::new(300),
        [2; 32],
        Some(OperationId::from_bytes([131; 16])?),
    )?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 11, term: 1 },
            context(194, administrator, 195, 150, Some(10))?,
            &same_epoch,
        ),
        Err(RepositoryError::StaleRevision)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(10));

    let next_epoch = issue_command(
        second_authority,
        2,
        UnixMicros::new(300),
        [3; 32],
        Some(OperationId::from_bytes([131; 16])?),
    )?;
    repository.apply_committed(
        LogPosition { index: 11, term: 1 },
        context(196, administrator, 197, 150, Some(10))?,
        &next_epoch,
    )?;
    let latest = repository
        .version_cleanup_permit_attempt(cleanup_id, 0)?
        .ok_or("missing renewed permit")?;
    assert_eq!(latest.attempt_sequence, 2);
    assert_eq!(latest.permit.authority_epoch, 2);
    assert_eq!(
        latest.permit.operation_id,
        OperationId::from_bytes([131; 16])?
    );
    Ok(())
}

#[test]
fn substituted_item_mesh_revision_and_lifetime_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ProposalFixture {
        mut repository,
        administrator,
        cleanup_id,
        ..
    } = sealed_inventory(&directory.path().join("reject.sqlite3"))?;
    let authority = repository.version_cleanup_permit_authority(cleanup_id, 0)?;
    let AuthoritativeCommand::IssueVersionCleanupPermit(valid) =
        issue_command(authority, 1, UnixMicros::new(200), [1; 32], None)?
    else {
        return Err("wrong command fixture".into());
    };
    let mut commands = Vec::new();
    let mut wrong_mesh = valid;
    wrong_mesh.permit.mesh_id = MeshId::from_bytes([99; 16])?;
    commands.push(wrong_mesh);
    let mut wrong_target = valid;
    wrong_target.permit.target_generation = 2;
    commands.push(wrong_target);
    let mut wrong_revision = valid;
    wrong_revision.permit.catalogue_revision = Revision::new(9);
    commands.push(wrong_revision);
    let mut too_long = valid;
    too_long.permit.expires_at = UnixMicros::new(86_400_000_111);
    commands.push(too_long);
    let mut wrong_seal = valid;
    wrong_seal.inventory_sealed_revision = Revision::new(8);
    commands.push(wrong_seal);
    for command in commands {
        assert!(
            repository
                .apply_committed(
                    LogPosition { index: 10, term: 1 },
                    context(198, administrator, 199, 110, Some(9))?,
                    &AuthoritativeCommand::IssueVersionCleanupPermit(command),
                )
                .is_err()
        );
        assert_eq!(repository.current_revision()?, Revision::new(9));
    }
    assert_eq!(
        repository.version_cleanup_permit_attempt(cleanup_id, 0)?,
        None
    );
    Ok(())
}

#[test]
fn every_apply_fault_rolls_back_complete_permit_attempt() -> Result<(), Box<dyn std::error::Error>>
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
        let authority = repository.version_cleanup_permit_authority(cleanup_id, 0)?;
        let command = issue_command(authority, 1, UnixMicros::new(200), [1; 32], None)?;
        let command_context = context(202, administrator, 203, 110, Some(9))?;
        assert!(matches!(
            apply_committed_with_fault(
                &mut repository.database,
                LogPosition { index: 10, term: 1 },
                command_context,
                &command,
                fault,
            ),
            Err(RepositoryError::InjectedFault)
        ));
        assert_eq!(repository.current_revision()?, Revision::new(9));
        assert_eq!(
            repository.version_cleanup_permit_attempt(cleanup_id, 0)?,
            None
        );
        repository.apply_committed(
            LogPosition { index: 10, term: 1 },
            command_context,
            &command,
        )?;
    }
    Ok(())
}

#[test]
fn persisted_permit_corruption_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ProposalFixture {
        mut repository,
        administrator,
        cleanup_id,
        ..
    } = sealed_inventory(&directory.path().join("corrupt.sqlite3"))?;
    let authority = repository.version_cleanup_permit_authority(cleanup_id, 0)?;
    repository.apply_committed(
        LogPosition { index: 10, term: 1 },
        context(204, administrator, 205, 110, Some(9))?,
        &issue_command(authority, 1, UnixMicros::new(200), [1; 32], None)?,
    )?;
    repository.database.connection_mut().execute(
        "UPDATE version_cleanup_permit_attempts SET permit_digest = ?1",
        [[0_u8; 32].as_slice()],
    )?;
    assert!(matches!(
        repository.version_cleanup_permit_attempt(cleanup_id, 0),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

pub(super) fn issue_command(
    authority: super::VersionCleanupPermitAuthority,
    authority_epoch: u64,
    expires_at: UnixMicros,
    permit_digest: [u8; 32],
    operation_id: Option<OperationId>,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::IssueVersionCleanupPermit(
        IssueVersionCleanupPermit {
            cleanup_operation_id: authority.cleanup_operation_id,
            inventory_sealed_revision: authority.inventory_sealed_revision,
            item_index: authority.item.item_index,
            attempt_sequence: authority.attempt_sequence,
            permit: RemovalPermit {
                operation_id: operation_id.unwrap_or(authority.item.removal_operation_id),
                mesh_id: MeshId::from_bytes([12; 16])?,
                target_id: authority.item.target_id,
                shard: authority.item.shard,
                target_generation: authority.item.target_generation,
                authority_epoch,
                catalogue_revision: authority.issue_revision,
                expires_at,
                permit_digest,
            },
        },
    ))
}
