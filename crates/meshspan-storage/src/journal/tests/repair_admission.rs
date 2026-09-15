// SPDX-License-Identifier: GPL-2.0-only

//! Admission and capacity accounting for the same repair intent after a lost ready response.

use super::*;
use meshspan_contracts::{ShardIdentity, ShardPutIntent};

#[test]
fn lost_admission_reacquires_capacity_atomically_and_retains_original_token()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let marker = marker(3, 4)?;
    let mut journal = TargetJournal::open(
        directory.path(),
        marker,
        policy(UsageLimit::Bytes(100), 10, 1),
        UnixMicros::new(1),
        &mut FixedRandom(5),
    )?;
    let intent = intent(marker)?;
    let ample = CapacityObservation {
        total_bytes: 1_000,
        available_bytes: 1_000,
    };
    let original = journal.reserve(reservation_request(
        marker,
        intent.context,
        ReservationClass::Repair,
        24,
        ample,
        UnixMicros::new(10),
    ))?;
    assert_eq!(journal.expire_reservations(UnixMicros::new(1_000))?, 1);
    assert!(matches!(
        journal.prepare_repair_put(
            intent,
            CapacityObservation {
                available_bytes: 0,
                ..ample
            },
            UnixMicros::new(2_000)
        ),
        Err(TargetJournalError::CapacityExhausted)
    ));
    assert_eq!(journal.capacity()?.reserved_bytes, 0);
    assert!(journal.pending_puts(None, 10)?.puts.is_empty());
    let admission = journal.prepare_repair_put(intent, ample, UnixMicros::new(2_001))?;
    assert_eq!(admission.reservation, original);
    assert_eq!(journal.capacity()?.reserved_bytes, 24);
    assert_eq!(journal.expire_reservations(UnixMicros::new(2_002))?, 0);
    drop(journal);
    let mut journal = TargetJournal::reopen(
        directory.path(),
        marker,
        policy(UsageLimit::Bytes(100), 10, 1),
        UnixMicros::new(2_003),
        &mut FailingRandom,
    )?;
    // Prepared work already owns its capacity; a changed free-space observation cannot duplicate it.
    assert_eq!(
        journal.prepare_repair_put(
            intent,
            CapacityObservation {
                available_bytes: 0,
                ..ample
            },
            UnixMicros::new(2_004)
        )?,
        admission
    );
    assert_eq!(journal.capacity()?.reserved_bytes, 24);
    assert_eq!(journal.capacity()?.committed_bytes, 0);
    assert_eq!(journal.pending_puts(None, 10)?.puts.len(), 1);
    assert!(matches!(
        journal.prepare_repair_put(
            ShardPutIntent {
                expected_digest: [99; 32],
                ..intent
            },
            ample,
            UnixMicros::new(2_005)
        ),
        Err(TargetJournalError::OperationConflict)
    ));
    assert_eq!(journal.capacity()?.reserved_bytes, 24);
    journal.check_integrity()?;
    Ok(())
}

#[test]
fn previously_unreceived_intent_is_prepared_without_changing_expired_context()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let marker = marker(3, 4)?;
    let mut journal = TargetJournal::open(
        directory.path(),
        marker,
        policy(UsageLimit::Bytes(100), 10, 1),
        UnixMicros::new(1),
        &mut FixedRandom(5),
    )?;
    let intent = intent(marker)?;
    let observation = CapacityObservation {
        total_bytes: 1_000,
        available_bytes: 1_000,
    };
    let admission = journal.prepare_repair_put(intent, observation, UnixMicros::new(2_000))?;
    assert_eq!(admission.context, intent.context);
    assert_eq!(admission.reservation.expires_at, UnixMicros::new(1_000));
    assert_eq!(
        admission.reservation.operation_id,
        intent.context.operation_id
    );
    assert_eq!(journal.capacity()?.reserved_bytes, 24);
    assert_eq!(journal.pending_puts(None, 10)?.puts.len(), 1);
    assert_eq!(journal.expire_reservations(UnixMicros::new(3_000))?, 0);
    journal.check_integrity()?;
    Ok(())
}

fn intent(marker: TargetMarker) -> Result<ShardPutIntent, Box<dyn std::error::Error>> {
    Ok(ShardPutIntent {
        context: context(81, 1_000)?,
        target_id: marker.target_id(),
        target_generation: marker.generation(),
        reservation_class: ReservationClass::Repair,
        maximum_bytes: 24,
        shard: ShardIdentity {
            manifest_digest: [7; 32],
            stripe_index: 8,
            shard_index: 4,
            generation: 9,
        },
        expected_length: 24,
        expected_digest: [8; 32],
    })
}
