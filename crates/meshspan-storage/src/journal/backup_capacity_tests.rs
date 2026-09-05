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
