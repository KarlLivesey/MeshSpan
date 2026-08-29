// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::{BoundedItems, ShardIdentity};
use meshspan_domain::{OperationId, Revision, TargetId, UnixMicros};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::cleanup_attestation_tests::ProposalFixture;
use super::version_cleanup_finalisation_tests::authorised_proposal;
use super::volume_head_tests::context;
use super::{
    ApplyDisposition, LogPosition, PageLimit, RepositoryError, VersionCleanupInventoryState,
};
use crate::{
    AppendVersionCleanupItems, AuthoritativeCommand, PartitionDatabase,
    SealVersionCleanupInventory, VersionCleanupItemPlacement,
};

#[test]
fn bounded_pages_seal_exact_inventory_and_survive_restart() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let file_path = directory.path().join("inventory.sqlite3");
    let ProposalFixture {
        mut repository,
        administrator,
        partition,
        cleanup_id,
        manifest_root_digest,
        ..
    } = authorised_proposal(&file_path)?;
    let first = append_command(cleanup_id, manifest_root_digest, 3, 0, 2)?;
    repository.apply_committed(
        LogPosition { index: 8, term: 1 },
        context(150, administrator, 151, 108, Some(7))?,
        &first,
    )?;
    let building = repository
        .version_cleanup_inventory(cleanup_id)?
        .ok_or("missing building inventory")?;
    assert_eq!(building.state, VersionCleanupInventoryState::Building);
    assert_eq!(building.item_count, 2);
    assert!(matches!(
        repository.version_cleanup_items(cleanup_id, None, PageLimit::new(2)?),
        Err(RepositoryError::InvalidCommand)
    ));

    let second = append_command(cleanup_id, manifest_root_digest, 3, 2, 1)?;
    let second_context = context(152, administrator, 153, 109, Some(8))?;
    repository.apply_committed(LogPosition { index: 9, term: 1 }, second_context, &second)?;
    let complete = repository
        .version_cleanup_inventory(cleanup_id)?
        .ok_or("missing complete inventory")?;
    assert_eq!(complete.item_count, 3);
    let seal = seal_command(cleanup_id, 3, complete.inventory_digest);
    let seal_context = context(154, administrator, 155, 110, Some(9))?;
    let receipt =
        repository.apply_committed(LogPosition { index: 10, term: 1 }, seal_context, &seal)?;
    assert_eq!(receipt.committed_revision, Revision::new(10));
    assert_sealed(&repository, cleanup_id, seal_context.operation_id)?;

    let first_page = repository.version_cleanup_items(cleanup_id, None, PageLimit::new(2)?)?;
    assert_eq!(first_page.items.len(), 2);
    let second_page = repository.version_cleanup_items(
        cleanup_id,
        first_page.next.as_ref(),
        PageLimit::new(2)?,
    )?;
    assert_eq!(second_page.items.len(), 1);
    assert_eq!(second_page.next, None);
    assert_eq!(first_page.items[0].item_index, 0);
    assert_eq!(second_page.items[0].item_index, 2);
    let replay =
        repository.apply_committed(LogPosition { index: 11, term: 1 }, seal_context, &seal)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    drop(repository);

    let reopened = PartitionDatabase::open(&file_path, partition, UnixMicros::new(500))?;
    let repository = super::AuthoritativeRepository::new(reopened);
    assert_sealed(&repository, cleanup_id, seal_context.operation_id)?;
    assert_eq!(
        repository
            .version_cleanup_items(cleanup_id, None, PageLimit::new(10)?)?
            .items
            .len(),
        3
    );
    Ok(())
}

#[test]
fn wrong_root_order_count_and_post_seal_append_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ProposalFixture {
        mut repository,
        administrator,
        cleanup_id,
        manifest_root_digest,
        ..
    } = authorised_proposal(&directory.path().join("reject.sqlite3"))?;
    let wrong_root = append_command(cleanup_id, [99; 32], 2, 0, 1)?;
    assert_rejected_without_advance(&mut repository, administrator, &wrong_root, 8, 7)?;
    assert_eq!(repository.version_cleanup_inventory(cleanup_id)?, None);

    let first = append_command(cleanup_id, manifest_root_digest, 2, 0, 1)?;
    repository.apply_committed(
        LogPosition { index: 8, term: 1 },
        context(160, administrator, 161, 108, Some(7))?,
        &first,
    )?;
    assert!(
        repository
            .database
            .connection()
            .execute(
                "UPDATE version_cleanup_inventories SET state = 2
                 WHERE cleanup_operation_id = ?1",
                [cleanup_id.as_bytes().as_slice()],
            )
            .is_err()
    );
    let building = repository
        .version_cleanup_inventory(cleanup_id)?
        .ok_or("missing partial inventory")?;
    assert_rejected_without_advance(
        &mut repository,
        administrator,
        &seal_command(cleanup_id, 2, building.inventory_digest),
        9,
        8,
    )?;
    let wrong_start = append_command(cleanup_id, manifest_root_digest, 2, 0, 1)?;
    assert_rejected_without_advance(&mut repository, administrator, &wrong_start, 9, 8)?;

    let second = append_command(cleanup_id, manifest_root_digest, 2, 1, 1)?;
    repository.apply_committed(
        LogPosition { index: 9, term: 1 },
        context(162, administrator, 163, 109, Some(8))?,
        &second,
    )?;
    let complete = repository
        .version_cleanup_inventory(cleanup_id)?
        .ok_or("missing complete inventory")?;
    let seal = seal_command(cleanup_id, 2, complete.inventory_digest);
    repository.apply_committed(
        LogPosition { index: 10, term: 1 },
        context(164, administrator, 165, 110, Some(9))?,
        &seal,
    )?;
    let later = append_command(cleanup_id, manifest_root_digest, 3, 2, 1)?;
    assert_rejected_without_advance(&mut repository, administrator, &later, 11, 10)?;
    Ok(())
}

#[test]
fn sealed_inventory_rejects_missing_or_substituted_items() -> Result<(), Box<dyn std::error::Error>>
{
    for delete_item in [true, false] {
        let directory = tempdir()?;
        let ProposalFixture {
            mut repository,
            administrator,
            cleanup_id,
            manifest_root_digest,
            ..
        } = authorised_proposal(&directory.path().join("corrupt.sqlite3"))?;
        repository.apply_committed(
            LogPosition { index: 8, term: 1 },
            context(166, administrator, 167, 108, Some(7))?,
            &append_command(cleanup_id, manifest_root_digest, 2, 0, 2)?,
        )?;
        let inventory = repository
            .version_cleanup_inventory(cleanup_id)?
            .ok_or("missing complete inventory")?;
        repository.apply_committed(
            LogPosition { index: 9, term: 1 },
            context(168, administrator, 169, 109, Some(8))?,
            &seal_command(cleanup_id, 2, inventory.inventory_digest),
        )?;
        if delete_item {
            repository.database.connection().execute(
                "DELETE FROM version_cleanup_items
                 WHERE cleanup_operation_id = ?1 AND item_index = 1",
                [cleanup_id.as_bytes().as_slice()],
            )?;
        } else {
            repository.database.connection().execute(
                "UPDATE version_cleanup_items SET manifest_digest = ?1
                 WHERE cleanup_operation_id = ?2 AND item_index = 1",
                rusqlite::params![[99_u8; 32].as_slice(), cleanup_id.as_bytes().as_slice()],
            )?;
        }
        assert!(matches!(
            repository.version_cleanup_items(cleanup_id, None, PageLimit::new(10)?),
            Err(RepositoryError::CorruptState)
        ));
    }
    Ok(())
}

#[test]
fn duplicate_item_authority_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ProposalFixture {
        mut repository,
        administrator,
        cleanup_id,
        manifest_root_digest,
        ..
    } = authorised_proposal(&directory.path().join("duplicates.sqlite3"))?;
    let mut duplicate_items = placements(manifest_root_digest, 0, 2)?;
    duplicate_items[1].removal_operation_id = duplicate_items[0].removal_operation_id;
    let duplicate = AuthoritativeCommand::AppendVersionCleanupItems(AppendVersionCleanupItems {
        cleanup_operation_id: cleanup_id,
        cleanup_revision: Revision::new(4),
        authorisation_revision: Revision::new(7),
        expected_item_count: 2,
        start_index: 0,
        items: BoundedItems::new(duplicate_items, 2)?,
    });
    assert_rejected_without_advance(&mut repository, administrator, &duplicate, 8, 7)?;

    let only = append_command(cleanup_id, manifest_root_digest, 1, 0, 1)?;
    repository.apply_committed(
        LogPosition { index: 8, term: 1 },
        context(170, administrator, 171, 108, Some(7))?,
        &only,
    )?;
    let complete = repository
        .version_cleanup_inventory(cleanup_id)?
        .ok_or("missing inventory")?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 9, term: 1 },
            context(130, administrator, 173, 109, Some(8))?,
            &seal_command(cleanup_id, 1, complete.inventory_digest),
        ),
        Err(RepositoryError::OperationConflict)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(8));
    repository.apply_committed(
        LogPosition { index: 9, term: 1 },
        context(172, administrator, 173, 109, Some(8))?,
        &seal_command(cleanup_id, 1, complete.inventory_digest),
    )?;
    let page = repository.version_cleanup_items(cleanup_id, None, PageLimit::new(1)?)?;
    assert_eq!(page.next, None);
    Ok(())
}

#[test]
fn every_apply_fault_rolls_back_inventory_append_and_seal() -> Result<(), Box<dyn std::error::Error>>
{
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        prove_append_fault(fault)?;
        prove_seal_fault(fault)?;
    }
    Ok(())
}

fn prove_append_fault(fault: ApplyFaultPoint) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ProposalFixture {
        mut repository,
        administrator,
        cleanup_id,
        manifest_root_digest,
        ..
    } = authorised_proposal(&directory.path().join("append-fault.sqlite3"))?;
    let command = append_command(cleanup_id, manifest_root_digest, 1, 0, 1)?;
    let command_context = context(180, administrator, 181, 108, Some(7))?;
    assert!(matches!(
        apply_committed_with_fault(
            &mut repository.database,
            LogPosition { index: 8, term: 1 },
            command_context,
            &command,
            fault,
        ),
        Err(RepositoryError::InjectedFault)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(7));
    assert_eq!(repository.version_cleanup_inventory(cleanup_id)?, None);
    repository.apply_committed(LogPosition { index: 8, term: 1 }, command_context, &command)?;
    Ok(())
}

fn prove_seal_fault(fault: ApplyFaultPoint) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ProposalFixture {
        mut repository,
        administrator,
        cleanup_id,
        manifest_root_digest,
        ..
    } = authorised_proposal(&directory.path().join("seal-fault.sqlite3"))?;
    repository.apply_committed(
        LogPosition { index: 8, term: 1 },
        context(182, administrator, 183, 108, Some(7))?,
        &append_command(cleanup_id, manifest_root_digest, 1, 0, 1)?,
    )?;
    let inventory = repository
        .version_cleanup_inventory(cleanup_id)?
        .ok_or("missing inventory")?;
    let command = seal_command(cleanup_id, 1, inventory.inventory_digest);
    let command_context = context(184, administrator, 185, 109, Some(8))?;
    assert!(matches!(
        apply_committed_with_fault(
            &mut repository.database,
            LogPosition { index: 9, term: 1 },
            command_context,
            &command,
            fault,
        ),
        Err(RepositoryError::InjectedFault)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(8));
    assert_eq!(
        repository
            .version_cleanup_inventory(cleanup_id)?
            .ok_or("missing rolled-back inventory")?
            .state,
        VersionCleanupInventoryState::Building
    );
    repository.apply_committed(LogPosition { index: 9, term: 1 }, command_context, &command)?;
    Ok(())
}

pub(super) fn sealed_inventory(
    file_path: &std::path::Path,
) -> Result<ProposalFixture, Box<dyn std::error::Error>> {
    sealed_inventory_with_count(file_path, 1)
}

pub(super) fn sealed_inventory_with_count(
    file_path: &std::path::Path,
    item_count: usize,
) -> Result<ProposalFixture, Box<dyn std::error::Error>> {
    let mut fixture = authorised_proposal(file_path)?;
    let expected_item_count = u64::try_from(item_count)?;
    fixture.repository.apply_committed(
        LogPosition { index: 8, term: 1 },
        context(186, fixture.administrator, 187, 108, Some(7))?,
        &append_command(
            fixture.cleanup_id,
            fixture.manifest_root_digest,
            expected_item_count,
            0,
            item_count,
        )?,
    )?;
    let inventory = fixture
        .repository
        .version_cleanup_inventory(fixture.cleanup_id)?
        .ok_or("missing inventory")?;
    fixture.repository.apply_committed(
        LogPosition { index: 9, term: 1 },
        context(188, fixture.administrator, 189, 109, Some(8))?,
        &seal_command(
            fixture.cleanup_id,
            expected_item_count,
            inventory.inventory_digest,
        ),
    )?;
    Ok(fixture)
}

pub(super) fn append_command(
    cleanup_operation_id: OperationId,
    manifest_digest: [u8; 32],
    expected_item_count: u64,
    start_index: u64,
    count: usize,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::AppendVersionCleanupItems(
        AppendVersionCleanupItems {
            cleanup_operation_id,
            cleanup_revision: Revision::new(4),
            authorisation_revision: Revision::new(7),
            expected_item_count,
            start_index,
            items: BoundedItems::new(placements(manifest_digest, start_index, count)?, 1_000)?,
        },
    ))
}

pub(super) fn placements(
    manifest_digest: [u8; 32],
    start_index: u64,
    count: usize,
) -> Result<Vec<VersionCleanupItemPlacement>, Box<dyn std::error::Error>> {
    (0..count)
        .map(|offset| {
            let index = start_index + u64::try_from(offset)?;
            let identity = u8::try_from(index + 130)?;
            Ok(VersionCleanupItemPlacement {
                removal_operation_id: OperationId::from_bytes([identity; 16])?,
                shard: ShardIdentity {
                    manifest_digest,
                    stripe_index: index,
                    shard_index: 0,
                    generation: 1,
                },
                target_id: TargetId::from_bytes([140; 16])?,
                target_generation: 1,
            })
        })
        .collect()
}

pub(super) fn seal_command(
    cleanup_operation_id: OperationId,
    expected_item_count: u64,
    inventory_digest: [u8; 32],
) -> AuthoritativeCommand {
    AuthoritativeCommand::SealVersionCleanupInventory(SealVersionCleanupInventory {
        cleanup_operation_id,
        cleanup_revision: Revision::new(4),
        authorisation_revision: Revision::new(7),
        expected_item_count,
        inventory_digest,
    })
}

fn assert_sealed(
    repository: &super::AuthoritativeRepository,
    cleanup_operation_id: OperationId,
    seal_operation_id: OperationId,
) -> Result<(), Box<dyn std::error::Error>> {
    let inventory = repository
        .version_cleanup_inventory(cleanup_operation_id)?
        .ok_or("missing sealed inventory")?;
    assert_eq!(inventory.state, VersionCleanupInventoryState::Sealed);
    assert_eq!(inventory.item_count, inventory.expected_item_count);
    assert_eq!(inventory.seal_operation_id, Some(seal_operation_id));
    assert_eq!(inventory.sealed_revision, Some(Revision::new(10)));
    assert_eq!(inventory.sealed_at, Some(UnixMicros::new(110)));
    Ok(())
}

fn assert_rejected_without_advance(
    repository: &mut super::AuthoritativeRepository,
    administrator: meshspan_domain::PrincipalId,
    command: &AuthoritativeCommand,
    log_index: u64,
    expected_revision: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        repository
            .apply_committed(
                LogPosition {
                    index: log_index,
                    term: 1,
                },
                context(200, administrator, 201, 200, Some(expected_revision))?,
                command,
            )
            .is_err()
    );
    assert_eq!(
        repository.current_revision()?,
        Revision::new(expected_revision)
    );
    Ok(())
}
