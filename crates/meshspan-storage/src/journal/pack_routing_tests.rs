// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_contracts::{ShardIdentity, ShardReceipt};
use meshspan_domain::{EntropyError, MeshId};

struct FixedRandom;
impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(7);
        Ok(())
    }
}

#[test]
fn record_limit_and_failed_preparation_do_not_lose_or_duplicate_routes()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = open(directory.path())?;
    journal.set_pack_limits(PackLimits {
        payload_bytes: 100,
        records: 2,
    });
    let first = request(&mut journal, 10, 1)?;
    let second = request(&mut journal, 11, 1)?;
    let third = request(&mut journal, 12, 1)?;
    journal.prepare_put(first)?;
    journal.prepare_put(second)?;
    assert_eq!(journal.pack_sequence(first.shard)?, Some(1));
    assert_eq!(journal.pack_sequence(second.shard)?, Some(1));
    journal.connection.execute_batch(
        "CREATE TRIGGER fail_prepare BEFORE INSERT ON provider_operations
         BEGIN SELECT RAISE(ABORT, 'injected preparation interruption'); END;",
    )?;
    assert!(journal.prepare_put(third).is_err());
    assert_eq!(journal.pack_sequence(third.shard)?, None);
    assert_eq!(journal.active_pack_sequence()?, 1);
    journal
        .connection
        .execute_batch("DROP TRIGGER fail_prepare;")?;
    journal.prepare_put(third)?;
    journal.prepare_put(first)?;
    assert_eq!(journal.pack_sequence(third.shard)?, Some(2));
    assert_eq!(journal.pack_sequences(10)?, vec![1, 2]);
    let counters: (i64, i64) = journal.connection.query_row(
        "SELECT assigned_bytes, assigned_records FROM pack_segments WHERE sequence = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(counters, (2, 2));
    journal.check_integrity()?;
    Ok(())
}

#[test]
fn version_two_migration_retains_committed_and_incomplete_pack_locations()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = open(directory.path())?;
    let first = request(&mut journal, 20, 7)?;
    let second = request(&mut journal, 21, 9)?;
    journal.prepare_put(first)?;
    journal.prepare_put(second)?;
    let receipt = ShardReceipt {
        operation_id: first.reservation.operation_id,
        shard: first.shard,
        length: first.expected_length,
        digest: first.expected_digest,
        target_id: journal.marker().target_id(),
        target_generation: journal.marker().generation(),
    };
    journal.commit_put(
        first,
        DurablePackEvidence {
            receipt,
            pack_sequence: 1,
            pack_offset: 1,
        },
    )?;
    // These are exactly the v2 tables and receipts. Only the additive v3 schema is removed.
    journal.connection.execute_batch(
        "DROP TABLE pack_routes; DROP TABLE pack_segments;
         DELETE FROM schema_migrations WHERE version = 3; PRAGMA user_version = 2;",
    )?;
    drop(journal);
    let mut journal = open(directory.path())?;
    assert_eq!(journal.pack_sequence(first.shard)?, Some(1));
    assert_eq!(journal.pack_sequence(second.shard)?, Some(1));
    assert_eq!(
        journal.prepare_put(first)?,
        PreparePutResult::Committed(receipt)
    );
    assert_eq!(journal.pending_puts(None, 10)?.puts.len(), 1);
    assert_eq!(journal.capacity()?.committed_bytes, 7);
    assert_eq!(journal.capacity()?.reserved_bytes, 9);
    assert_eq!(journal.active_pack_sequence()?, 1);
    journal.check_integrity()?;
    Ok(())
}

fn open(directory: &Path) -> Result<TargetJournal, Box<dyn std::error::Error>> {
    Ok(TargetJournal::open(
        directory,
        TargetMarker::new(
            MeshId::from_bytes([1; 16])?,
            TargetId::from_bytes([2; 16])?,
            3,
            [4; 32],
        )?,
        CapacityPolicy {
            usage_limit: UsageLimit::Bytes(10_000),
            repair_reserve_bytes: 0,
            revision: Revision::new(1),
        },
        UnixMicros::new(1),
        &mut FixedRandom,
    )?)
}

fn request(
    journal: &mut TargetJournal,
    seed: u8,
    length: u64,
) -> Result<JournalPutRequest, Box<dyn std::error::Error>> {
    let reservation = journal.reserve(ReserveCapacityRequest {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([seed; 16])?,
            deadline: UnixMicros::new(1_000),
            expected_revision: Some(Revision::new(1)),
        },
        target_id: journal.marker().target_id(),
        target_generation: journal.marker().generation(),
        class: ReservationClass::ForegroundWrite,
        bytes: length,
        observation: CapacityObservation {
            total_bytes: 10_000,
            available_bytes: 10_000,
        },
        now: UnixMicros::new(10),
    })?;
    Ok(JournalPutRequest {
        reservation,
        request_digest: [seed; 32],
        shard: ShardIdentity {
            manifest_digest: [seed; 32],
            stripe_index: 0,
            shard_index: 0,
            generation: 1,
        },
        expected_length: length,
        expected_digest: [seed; 32],
        now: UnixMicros::new(20),
    })
}
