// SPDX-License-Identifier: GPL-2.0-only

//! Freshly authorised repair admission pins the original operation before returning to the wire.

use meshspan_contracts::{ReservationClass, ShardPutIdentity, ShardPutIntent, StorageReservation};
use meshspan_domain::UnixMicros;
use rusqlite::{Transaction, TransactionBehavior, params};

use super::{
    CapacityObservation, CapacityPolicy, JournalPutRequest, PreparePutResult, TargetJournal,
    TargetJournalError,
};
use crate::TargetMarker;

#[derive(Clone, Copy)]
struct RepairAdmission {
    intent: ShardPutIntent,
    observation: CapacityObservation,
    now: UnixMicros,
}

impl TargetJournal {
    /// The provider must authenticate fresh repair authority before entering this transaction.
    pub(crate) fn prepare_repair_put(
        &mut self,
        intent: ShardPutIntent,
        observation: CapacityObservation,
        now: UnixMicros,
    ) -> Result<ShardPutIdentity, TargetJournalError> {
        intent
            .validate()
            .map_err(|_| TargetJournalError::InvalidInput)?;
        super::validate_reservation_identity(
            intent.context,
            self.marker,
            intent.target_id,
            intent.target_generation,
            intent.maximum_bytes,
        )?;
        if intent.reservation_class == ReservationClass::ForegroundWrite || now.get() < 0 {
            return Err(TargetJournalError::InvalidInput);
        }
        observation.validate()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        super::expire_active_reservations(&transaction, now)?;
        let reservation = original_reservation(
            &transaction,
            self.marker,
            self.policy,
            RepairAdmission {
                intent,
                observation,
                now,
            },
        )?;
        let original = intent
            .admitted(reservation)
            .map_err(|_| TargetJournalError::OperationConflict)?;
        let request = JournalPutRequest {
            reservation,
            request_digest: original.request_digest(),
            shard: original.shard,
            expected_length: original.expected_length,
            expected_digest: original.expected_digest,
            now,
        };
        retain_preparation(&transaction, request, self.pack_limits)?;
        transaction.commit()?;
        Ok(original)
    }
}

fn original_reservation(
    transaction: &Transaction<'_>,
    marker: TargetMarker,
    policy: CapacityPolicy,
    admission: RepairAdmission,
) -> Result<StorageReservation, TargetJournalError> {
    let RepairAdmission {
        intent,
        observation,
        now,
    } = admission;
    let request_digest = super::reservation_request_digest(
        intent.context,
        intent.target_id,
        intent.target_generation,
        intent.reservation_class,
        intent.maximum_bytes,
    );
    if let Some(existing) = super::load_reservation(transaction, intent.context.operation_id)? {
        let reservation = super::resolve_existing(
            existing,
            request_digest,
            marker,
            intent.context.operation_id,
        )?;
        match existing.state {
            1..=3 => {}
            4 => {
                super::admit_capacity(
                    transaction,
                    policy,
                    intent.reservation_class,
                    intent.maximum_bytes,
                    observation,
                )?;
                transaction.execute(
                    "UPDATE reservations SET state = 1, terminal_at = NULL
                    WHERE operation_id = ?1 AND state = 4",
                    [intent.context.operation_id.as_bytes().as_slice()],
                )?;
            }
            _ => return Err(TargetJournalError::CorruptState),
        }
        return Ok(reservation);
    }
    if super::inventory::load_provider_operation(transaction, intent.context.operation_id)?
        .is_some()
    {
        return Err(TargetJournalError::CorruptState);
    }
    super::admit_capacity(
        transaction,
        policy,
        intent.reservation_class,
        intent.maximum_bytes,
        observation,
    )?;
    let key = super::load_capability_key(transaction)?;
    let reservation_digest = super::reservation_authority_digest(&key, request_digest);
    super::insert_reservation(
        transaction,
        intent.context,
        intent.reservation_class,
        intent.maximum_bytes,
        request_digest,
        reservation_digest,
        now,
    )?;
    Ok(StorageReservation {
        operation_id: intent.context.operation_id,
        target_id: intent.target_id,
        target_generation: intent.target_generation,
        class: intent.reservation_class,
        maximum_bytes: intent.maximum_bytes,
        expires_at: intent.context.deadline,
        reservation_digest,
    })
}

fn retain_preparation(
    transaction: &Transaction<'_>,
    request: JournalPutRequest,
    limits: super::PackLimits,
) -> Result<(), TargetJournalError> {
    let state: i64 = transaction.query_row(
        "SELECT state FROM reservations WHERE operation_id = ?1",
        [request.reservation.operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    match super::inventory::load_provider_operation(transaction, request.reservation.operation_id)?
    {
        Some(existing) => {
            let outcome = super::inventory::resolve_provider_operation(existing, request)?;
            if !matches!(
                (outcome, state),
                (PreparePutResult::Prepared, 2) | (PreparePutResult::Committed(_), 3)
            ) {
                return Err(TargetJournalError::CorruptState);
            }
        }
        None if state == 1 => super::inventory::insert_prepared_put(transaction, request, limits)?,
        None => return Err(TargetJournalError::CorruptState),
    }
    // A fresh authority permits progress; it does not change the original expiry or digest.
    transaction.execute(
        "UPDATE provider_operations SET updated_at = ?1 WHERE operation_id = ?2",
        params![
            request.now.get(),
            request.reservation.operation_id.as_bytes().as_slice()
        ],
    )?;
    Ok(())
}
