// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::{BackupObjectIdentity, ContractVersion, RequestContext, ReservationClass};
use meshspan_domain::{
    BackupDestinationId, BackupId, EntropyError, MeshId, OperationId, RandomSource, Revision,
    TargetId, UnixMicros,
};

use super::{
    CapacityObservation, CapacityPolicy, ReserveCapacityRequest, TargetJournal, TargetJournalError,
};
use crate::{TargetMarker, UsageLimit};

#[test]
fn backup_and_shard_admission_share_counters_through_restart_and_exact_release()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = open(directory.path())?;
    let backup = object(1, 600)?;
    journal.reserve_backup_capacity(backup, observation())?;
    journal.reserve(shard_request(2, 400)?)?;
    assert_eq!(journal.capacity()?.reserved_bytes, 1_000);
    assert!(matches!(
        journal.reserve_backup_capacity(object(3, 1)?, observation()),
        Err(TargetJournalError::CapacityExhausted)
    ));
    drop(journal);
    let mut journal = open(directory.path())?;
    journal.reserve_backup_capacity(backup, observation())?;
    journal.expire_reservations(UnixMicros::new(100))?;
    assert_eq!(journal.capacity()?.reserved_bytes, 600);
    journal.commit_backup_capacity(backup)?;
    journal.commit_backup_capacity(backup)?;
    assert_eq!(journal.capacity()?.reserved_bytes, 0);
    assert_eq!(journal.capacity()?.committed_bytes, 600);
    assert!(matches!(
        journal.reserve(shard_request(4, 401)?),
        Err(TargetJournalError::CapacityExhausted)
    ));
    let mut changed = backup;
    changed.digest = [8; 32];
    assert!(matches!(
        journal.release_backup_capacity(changed),
        Err(TargetJournalError::OperationConflict)
    ));
    journal.release_backup_capacity(backup)?;
    journal.release_backup_capacity(backup)?;
    assert_eq!(journal.capacity()?.committed_bytes, 0);
    assert!(matches!(
        journal.reserve_backup_capacity(backup, observation()),
        Err(TargetJournalError::OperationConflict)
    ));
    journal.reserve(shard_request(5, 1_000)?)?;
    journal.check_integrity()?;
    Ok(())
}

#[test]
fn existing_objects_are_accounted_even_above_a_reduced_ceiling()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = open(directory.path())?;
    let backup = object(6, 1_200)?;
    journal.reconcile_backup_capacity(backup)?;
    journal.reconcile_backup_capacity(backup)?;
    assert_eq!(journal.capacity()?.committed_bytes, 1_200);
    assert!(matches!(
        journal.reserve(shard_request(7, 1)?),
        Err(TargetJournalError::CapacityExhausted)
    ));
    journal.release_backup_capacity(backup)?;
    assert_eq!(journal.capacity()?.committed_bytes, 0);
    let mut stale = object(8, 10)?;
    stale.provider_generation = 2;
    assert!(matches!(
        journal.reserve_backup_capacity(stale, observation()),
        Err(TargetJournalError::InvalidInput)
    ));
    Ok(())
}

#[test]
fn version_one_target_migrates_without_losing_shard_reservations()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = open(directory.path())?;
    journal.reserve(shard_request(9, 400)?)?;
    // Construct the exact prior schema: no new-table contents exist in this fixture.
    journal.connection.execute_batch("DROP TABLE backup_capacity; DELETE FROM schema_migrations WHERE version = 2; PRAGMA user_version = 1;")?;
    drop(journal);
    let mut journal = open(directory.path())?;
    assert_eq!(journal.capacity()?.reserved_bytes, 400);
    journal.reserve_backup_capacity(object(10, 600)?, observation())?;
    assert_eq!(journal.capacity()?.reserved_bytes, 1_000);
    journal.check_integrity()?;
    Ok(())
}

#[test]
fn unpublished_cancellation_is_exact_and_retry_does_not_revive_retired_objects()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = open(directory.path())?;
    let backup = object(20, 600)?;
    journal.reserve_backup_capacity(backup, observation())?;
    let mut changed = backup;
    changed.digest = [99; 32];
    assert!(matches!(
        journal.cancel_unpublished_backup(changed),
        Err(TargetJournalError::OperationConflict)
    ));
    assert_eq!(journal.capacity()?.reserved_bytes, 600);
    journal.cancel_unpublished_backup(backup)?;
    journal.cancel_unpublished_backup(backup)?;
    assert_eq!(journal.capacity()?.reserved_bytes, 0);
    journal.reserve_backup_capacity(backup, observation())?;
    journal.commit_backup_capacity(backup)?;
    assert!(matches!(
        journal.cancel_unpublished_backup(backup),
        Err(TargetJournalError::OperationConflict)
    ));
    assert_eq!(journal.capacity()?.committed_bytes, 600);
    journal.release_backup_capacity(backup)?;
    assert!(matches!(
        journal.cancel_unpublished_backup(backup),
        Err(TargetJournalError::OperationConflict)
    ));
    journal.check_integrity()?;
    Ok(())
}

#[test]
fn cancellation_rolls_back_counters_if_hold_removal_fails() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let mut journal = open(directory.path())?;
    let backup = object(21, 600)?;
    journal.reserve_backup_capacity(backup, observation())?;
    journal.connection.execute_batch("CREATE TRIGGER fail_hold_delete BEFORE DELETE ON backup_capacity BEGIN SELECT RAISE(ABORT, 'injected cancellation failure'); END;")?;
    assert!(journal.cancel_unpublished_backup(backup).is_err());
    assert_eq!(journal.capacity()?.reserved_bytes, 600);
    assert_eq!(
        journal.pending_backup_holds(backup.destination_id, 1, None)?,
        vec![backup]
    );
    journal
        .connection
        .execute_batch("DROP TRIGGER fail_hold_delete;")?;
    journal.cancel_unpublished_backup(backup)?;
    assert_eq!(journal.capacity()?.reserved_bytes, 0);
    journal.check_integrity()?;
    Ok(())
}

#[test]
fn pending_holds_seek_by_destination_without_stored_or_released_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = open(directory.path())?;
    for id in 1..=70 {
        journal.reserve_backup_capacity(object(id, 1)?, observation())?;
    }
    journal.commit_backup_capacity(object(1, 1)?)?;
    journal.release_backup_capacity(object(2, 1)?)?;
    let mut other = object(71, 1)?;
    other.destination_id = BackupDestinationId::from_bytes([12; 16])?;
    journal.reserve_backup_capacity(other, observation())?;
    let destination = object(1, 1)?.destination_id;
    let first = journal.pending_backup_holds(destination, 1, None)?;
    assert_eq!(first.len(), 64);
    assert_eq!(first[0], object(3, 1)?);
    assert_eq!(first[63], object(66, 1)?);
    for pending in &first {
        journal.cancel_unpublished_backup(*pending)?;
    }
    let second = journal.pending_backup_holds(destination, 1, Some(first[63].backup_id))?;
    assert_eq!(
        second,
        (67..=70)
            .map(|id| object(id, 1))
            .collect::<Result<Vec<_>, _>>()?
    );
    assert!(journal.pending_backup_holds(destination, 2, None).is_err());
    Ok(())
}

fn open(directory: &std::path::Path) -> Result<TargetJournal, Box<dyn std::error::Error>> {
    Ok(TargetJournal::open(
        directory,
        marker()?,
        CapacityPolicy {
            usage_limit: UsageLimit::Bytes(1_000),
            repair_reserve_bytes: 0,
            revision: Revision::new(1),
        },
        UnixMicros::new(1),
        &mut FixedRandom,
    )?)
}

fn marker() -> Result<TargetMarker, Box<dyn std::error::Error>> {
    Ok(TargetMarker::new(
        MeshId::from_bytes([1; 16])?,
        TargetId::from_bytes([2; 16])?,
        1,
        [3; 32],
    )?)
}

const fn observation() -> CapacityObservation {
    CapacityObservation {
        total_bytes: 10_000,
        available_bytes: 10_000,
    }
}

fn object(id: u8, byte_length: u64) -> Result<BackupObjectIdentity, Box<dyn std::error::Error>> {
    Ok(BackupObjectIdentity {
        backup_id: BackupId::from_bytes([id; 16])?,
        destination_id: BackupDestinationId::from_bytes([11; 16])?,
        provider_generation: 1,
        byte_length,
        digest: [4; 32],
    })
}

fn shard_request(id: u8, bytes: u64) -> Result<ReserveCapacityRequest, Box<dyn std::error::Error>> {
    Ok(ReserveCapacityRequest {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([id; 16])?,
            deadline: UnixMicros::new(50),
            expected_revision: Some(Revision::new(1)),
        },
        target_id: marker()?.target_id(),
        target_generation: 1,
        class: ReservationClass::ForegroundWrite,
        bytes,
        observation: observation(),
        now: UnixMicros::new(10),
    })
}

struct FixedRandom;
impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(42);
        Ok(())
    }
}
