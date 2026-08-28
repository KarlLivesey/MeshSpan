// SPDX-License-Identifier: GPL-2.0-only

//! Prepared/committed shard transitions, recovery and bounded inventory reads.

use meshspan_contracts::{
    BoundedBytes, BoundedItems, InventoryEntry, InventoryPage, ShardIdentity, ShardReceipt,
    StorageReservation,
};
use meshspan_domain::{OperationId, UnixMicros};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use super::{TargetJournal, TargetJournalError, decode_reservation_class, to_i64, to_u64};
use crate::shard::{SHARD_KEY_BYTES, decode_receipt, decode_shard, encode_receipt, encode_shard};

const MAXIMUM_INVENTORY_ITEMS: usize = 1_000;
const MAXIMUM_PENDING_ITEMS: usize = 1_000;
const PUT_OPERATION_KIND: i64 = 1;
const OPERATION_PREPARED: i64 = 1;
const OPERATION_COMMITTED: i64 = 4;
const INVENTORY_COMMITTED: i64 = 1;
const RESERVATION_ACTIVE: i64 = 1;
const RESERVATION_IN_PROGRESS: i64 = 2;
const RESERVATION_CONSUMED: i64 = 3;

/// Exact journal input recorded before provider bytes are made durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalPutRequest {
    /// Local capacity authority consumed by this write.
    pub reservation: StorageReservation,
    /// Canonical digest of the complete put request excluding its byte buffer.
    pub request_digest: [u8; 32],
    /// Exact immutable shard identity.
    pub shard: ShardIdentity,
    /// Exact final stored length.
    pub expected_length: u64,
    /// Canonical digest of the final stored bytes.
    pub expected_digest: [u8; 32],
    /// Current authoritative instant.
    pub now: UnixMicros,
}

/// Independently durable provider-pack evidence accepted by the local journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurablePackEvidence {
    /// Exact storage-provider durability receipt.
    pub receipt: ShardReceipt,
    /// Positive provider-private pack sequence.
    pub pack_sequence: u64,
    /// Provider-private byte or record offset within that pack.
    pub pack_offset: u64,
}

/// Result of preparing an exact put operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparePutResult {
    /// Bytes still need to be proved durable in the provider pack.
    Prepared,
    /// The exact operation already committed and resolves to this receipt.
    Committed(ShardReceipt),
}

/// One bounded incomplete put recovered after restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingPut {
    /// Pinned capacity authority whose provider outcome must be reconciled.
    pub reservation: StorageReservation,
    /// Exact canonical request digest.
    pub request_digest: [u8; 32],
    /// Immutable shard identity.
    pub shard: ShardIdentity,
    /// Expected persisted length.
    pub expected_length: u64,
    /// Expected persisted digest.
    pub expected_digest: [u8; 32],
}

/// Stable bounded recovery page with continuation only when more work exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingPutPage {
    /// Prepared puts in stable operation-ID order.
    pub puts: BoundedItems<PendingPut>,
    /// Opaque next-page operation cursor, or `None` at the end.
    pub next_cursor: Option<BoundedBytes>,
}

impl TargetJournal {
    /// Records or resolves one exact put before touching provider bytes.
    ///
    /// # Errors
    ///
    /// Rejects an expired/consumed/forged reservation, stale target generation, excessive length,
    /// conflicting operation reuse and malformed durable state without changing inventory.
    pub fn prepare_put(
        &mut self,
        request: JournalPutRequest,
    ) -> Result<PreparePutResult, TargetJournalError> {
        validate_put_request(self, request)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) =
            load_provider_operation(&transaction, request.reservation.operation_id)?
        {
            return resolve_provider_operation(existing, request);
        }
        validate_reservation(&transaction, request)?;
        let operation = request.reservation.operation_id.as_bytes();
        let shard = encode_shard(request.shard);
        transaction.execute(
            "INSERT INTO provider_operations(
                operation_id, operation_kind, request_digest, state, shard_identity,
                expected_length, expected_digest, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                operation.as_slice(),
                PUT_OPERATION_KIND,
                request.request_digest.as_slice(),
                OPERATION_PREPARED,
                shard.as_slice(),
                to_i64(request.expected_length)?,
                request.expected_digest.as_slice(),
                request.now.get(),
            ],
        )?;
        attach_reservation(&transaction, request)?;
        transaction.commit()?;
        Ok(PreparePutResult::Prepared)
    }

    /// Commits journal inventory only after the provider pack independently proved exact bytes.
    ///
    /// # Errors
    ///
    /// Rejects absent/conflicting preparation or pack evidence and updates operation, inventory,
    /// reservation and capacity counters atomically.
    pub fn commit_put(
        &mut self,
        request: JournalPutRequest,
        evidence: DurablePackEvidence,
    ) -> Result<ShardReceipt, TargetJournalError> {
        validate_put_request(self, request)?;
        let pack_receipt = evidence.receipt;
        if pack_receipt.operation_id != request.reservation.operation_id
            || pack_receipt.shard != request.shard
            || pack_receipt.length != request.expected_length
            || pack_receipt.digest != request.expected_digest
            || pack_receipt.target_id != self.marker.target_id()
            || pack_receipt.target_generation != self.marker.generation()
            || evidence.pack_sequence == 0
            || i64::try_from(evidence.pack_sequence).is_err()
            || i64::try_from(evidence.pack_offset).is_err()
        {
            return Err(TargetJournalError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = load_provider_operation(&transaction, request.reservation.operation_id)?
            .ok_or(TargetJournalError::InvalidInput)?;
        match resolve_provider_operation(existing, request)? {
            PreparePutResult::Committed(receipt) => return Ok(receipt),
            PreparePutResult::Prepared => {}
        }
        let inserted = upsert_inventory(&transaction, request, evidence)?;
        complete_operation(&transaction, request, pack_receipt)?;
        consume_reservation(&transaction, request, inserted)?;
        transaction.commit()?;
        Ok(pack_receipt)
    }

    /// Returns a bounded stable page of journal-confirmed committed shards.
    ///
    /// # Errors
    ///
    /// Rejects malformed cursors, zero/excessive limits and corrupt persisted identities.
    pub fn inventory(
        &self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
    ) -> Result<InventoryPage, TargetJournalError> {
        if limit == 0 || limit > MAXIMUM_INVENTORY_ITEMS {
            return Err(TargetJournalError::InvalidInput);
        }
        let lower = match cursor {
            Some(value) if value.len() == SHARD_KEY_BYTES => value.as_slice(),
            Some(_) => return Err(TargetJournalError::InvalidInput),
            None => &[],
        };
        let sql_limit = to_i64(
            u64::try_from(limit.saturating_add(1)).map_err(|_| TargetJournalError::InvalidInput)?,
        )?;
        let mut statement = self.connection.prepare(
            "SELECT shard_identity, stored_length, stored_digest, last_verified_at
             FROM inventory WHERE state = ?1 AND shard_identity > ?2
             ORDER BY shard_identity LIMIT ?3",
        )?;
        let rows = statement.query_map(params![INVENTORY_COMMITTED, lower, sql_limit], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })?;
        let mut entries = Vec::with_capacity(limit.saturating_add(1));
        let mut keys = Vec::with_capacity(limit.saturating_add(1));
        for row in rows {
            let row = row?;
            let digest: [u8; 32] = row
                .2
                .try_into()
                .map_err(|_| TargetJournalError::CorruptState)?;
            entries.push(InventoryEntry {
                shard: decode_shard(&row.0)?,
                length: to_u64(row.1)?,
                digest,
                bytes_verified: row.3.is_some(),
            });
            keys.push(row.0);
        }
        let next_cursor = if entries.len() > limit {
            let key = keys
                .get(limit - 1)
                .ok_or(TargetJournalError::CorruptState)?;
            Some(
                BoundedBytes::copy_from(key, SHARD_KEY_BYTES)
                    .map_err(|_| TargetJournalError::CorruptState)?,
            )
        } else {
            None
        };
        entries.truncate(limit);
        Ok(InventoryPage {
            entries: BoundedItems::new(entries, limit)
                .map_err(|_| TargetJournalError::CorruptState)?,
            next_cursor,
        })
    }

    /// Returns bounded prepared puts for pack/journal reconciliation after restart.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive limits and malformed persisted operation rows.
    pub fn pending_puts(
        &self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
    ) -> Result<PendingPutPage, TargetJournalError> {
        if limit == 0 || limit > MAXIMUM_PENDING_ITEMS {
            return Err(TargetJournalError::InvalidInput);
        }
        let lower = match cursor {
            Some(value) if value.len() == 16 => value.as_slice(),
            Some(_) => return Err(TargetJournalError::InvalidInput),
            None => &[],
        };
        let mut statement = self.connection.prepare(
            "SELECT o.operation_id, o.request_digest, o.shard_identity,
                    o.expected_length, o.expected_digest,
                    r.reservation_digest, r.reservation_class, r.maximum_bytes, r.expires_at
             FROM provider_operations o
             JOIN reservations r ON r.operation_id = o.operation_id
             WHERE o.operation_kind = ?1 AND o.state = ?2 AND o.operation_id > ?3
             ORDER BY o.operation_id LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![
                PUT_OPERATION_KIND,
                OPERATION_PREPARED,
                lower,
                to_i64(
                    u64::try_from(limit.saturating_add(1))
                        .map_err(|_| TargetJournalError::InvalidInput)?
                )?
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )?;
        let mut puts = rows
            .map(|row| {
                let row = row?;
                Ok(PendingPut {
                    reservation: StorageReservation {
                        operation_id: OperationId::from_bytes(copy_array(&row.0)?)
                            .map_err(|_| TargetJournalError::CorruptState)?,
                        target_id: self.marker.target_id(),
                        target_generation: self.marker.generation(),
                        class: decode_reservation_class(row.6)?,
                        maximum_bytes: to_u64(row.7)?,
                        expires_at: UnixMicros::new(row.8),
                        reservation_digest: copy_array(&row.5)?,
                    },
                    request_digest: copy_array(&row.1)?,
                    shard: decode_shard(&row.2)?,
                    expected_length: to_u64(row.3)?,
                    expected_digest: copy_array(&row.4)?,
                })
            })
            .collect::<Result<Vec<_>, TargetJournalError>>()?;
        let next_cursor = if puts.len() > limit {
            let operation = puts
                .get(limit - 1)
                .ok_or(TargetJournalError::CorruptState)?
                .reservation
                .operation_id
                .as_bytes();
            Some(
                BoundedBytes::copy_from(&operation, 16)
                    .map_err(|_| TargetJournalError::CorruptState)?,
            )
        } else {
            None
        };
        puts.truncate(limit);
        Ok(PendingPutPage {
            puts: BoundedItems::new(puts, limit).map_err(|_| TargetJournalError::CorruptState)?,
            next_cursor,
        })
    }
}

struct StoredProviderOperation {
    request_digest: [u8; 32],
    state: i64,
    shard: ShardIdentity,
    expected_length: u64,
    expected_digest: [u8; 32],
    receipt: Option<Vec<u8>>,
}

fn validate_put_request(
    journal: &TargetJournal,
    request: JournalPutRequest,
) -> Result<(), TargetJournalError> {
    if request.reservation.target_id != journal.marker.target_id()
        || request.reservation.target_generation != journal.marker.generation()
        || request.expected_length == 0
        || request.expected_length > request.reservation.maximum_bytes
        || i64::try_from(request.expected_length).is_err()
    {
        Err(TargetJournalError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_reservation(
    transaction: &Transaction<'_>,
    request: JournalPutRequest,
) -> Result<(), TargetJournalError> {
    let operation = request.reservation.operation_id.as_bytes();
    let stored: Option<(Vec<u8>, i64, i64, i64)> = transaction
        .query_row(
            "SELECT reservation_digest, maximum_bytes, expires_at, state
             FROM reservations WHERE operation_id = ?1",
            [operation.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((digest, maximum, expires_at, state)) = stored else {
        return Err(TargetJournalError::InvalidInput);
    };
    if digest.as_slice() != request.reservation.reservation_digest
        || to_u64(maximum)? != request.reservation.maximum_bytes
        || expires_at != request.reservation.expires_at.get()
        || state != RESERVATION_ACTIVE
        || request.now >= request.reservation.expires_at
    {
        Err(TargetJournalError::InvalidInput)
    } else {
        Ok(())
    }
}

fn attach_reservation(
    transaction: &Transaction<'_>,
    request: JournalPutRequest,
) -> Result<(), TargetJournalError> {
    let operation = request.reservation.operation_id.as_bytes();
    let updated = transaction.execute(
        "UPDATE reservations SET state = ?1
         WHERE operation_id = ?2 AND state = ?3",
        params![
            RESERVATION_IN_PROGRESS,
            operation.as_slice(),
            RESERVATION_ACTIVE,
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(TargetJournalError::CorruptState)
    }
}

fn load_provider_operation(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
) -> Result<Option<StoredProviderOperation>, TargetJournalError> {
    let operation = operation_id.as_bytes();
    transaction
        .query_row(
            "SELECT request_digest, state, shard_identity, expected_length,
                    expected_digest, receipt
             FROM provider_operations WHERE operation_id = ?1 AND operation_kind = ?2",
            params![operation.as_slice(), PUT_OPERATION_KIND],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(StoredProviderOperation {
                request_digest: copy_array(&row.0)?,
                state: row.1,
                shard: decode_shard(&row.2)?,
                expected_length: to_u64(row.3)?,
                expected_digest: copy_array(&row.4)?,
                receipt: row.5,
            })
        })
        .transpose()
}

fn resolve_provider_operation(
    existing: StoredProviderOperation,
    request: JournalPutRequest,
) -> Result<PreparePutResult, TargetJournalError> {
    if existing.request_digest != request.request_digest
        || existing.shard != request.shard
        || existing.expected_length != request.expected_length
        || existing.expected_digest != request.expected_digest
    {
        return Err(TargetJournalError::OperationConflict);
    }
    match (existing.state, existing.receipt) {
        (OPERATION_PREPARED, None) => Ok(PreparePutResult::Prepared),
        (OPERATION_COMMITTED, Some(receipt)) => {
            Ok(PreparePutResult::Committed(decode_receipt(&receipt)?))
        }
        _ => Err(TargetJournalError::CorruptState),
    }
}

fn upsert_inventory(
    transaction: &Transaction<'_>,
    request: JournalPutRequest,
    evidence: DurablePackEvidence,
) -> Result<bool, TargetJournalError> {
    let shard = encode_shard(request.shard);
    let existing: Option<(i64, Vec<u8>, i64)> = transaction
        .query_row(
            "SELECT stored_length, stored_digest, state FROM inventory WHERE shard_identity = ?1",
            [shard.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((length, digest, state)) = existing {
        if to_u64(length)? == request.expected_length
            && digest.as_slice() == request.expected_digest
            && state == INVENTORY_COMMITTED
        {
            return Ok(false);
        }
        return Err(TargetJournalError::OperationConflict);
    }
    let operation = request.reservation.operation_id.as_bytes();
    transaction.execute(
        "INSERT INTO inventory(
            shard_identity, manifest_digest, stripe_index, shard_index, shard_generation,
            pack_sequence, pack_offset, stored_length, stored_digest, state,
            committed_operation_id, committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            shard.as_slice(),
            request.shard.manifest_digest.as_slice(),
            to_i64(request.shard.stripe_index)?,
            i64::from(request.shard.shard_index),
            i64::from(request.shard.generation),
            to_i64(evidence.pack_sequence)?,
            to_i64(evidence.pack_offset)?,
            to_i64(request.expected_length)?,
            request.expected_digest.as_slice(),
            INVENTORY_COMMITTED,
            operation.as_slice(),
            request.now.get(),
        ],
    )?;
    Ok(true)
}

fn complete_operation(
    transaction: &Transaction<'_>,
    request: JournalPutRequest,
    receipt: ShardReceipt,
) -> Result<(), TargetJournalError> {
    let operation = request.reservation.operation_id.as_bytes();
    let receipt = encode_receipt(receipt);
    let updated = transaction.execute(
        "UPDATE provider_operations SET state = ?1, receipt = ?2, updated_at = ?3
         WHERE operation_id = ?4 AND state = ?5 AND request_digest = ?6",
        params![
            OPERATION_COMMITTED,
            receipt.as_slice(),
            request.now.get(),
            operation.as_slice(),
            OPERATION_PREPARED,
            request.request_digest.as_slice(),
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(TargetJournalError::CorruptState)
    }
}

fn consume_reservation(
    transaction: &Transaction<'_>,
    request: JournalPutRequest,
    inserted: bool,
) -> Result<(), TargetJournalError> {
    let operation = request.reservation.operation_id.as_bytes();
    let updated = transaction.execute(
        "UPDATE reservations SET state = ?1, terminal_at = ?2
         WHERE operation_id = ?3 AND state = ?4",
        params![
            RESERVATION_CONSUMED,
            request.now.get(),
            operation.as_slice(),
            RESERVATION_IN_PROGRESS,
        ],
    )?;
    if updated != 1 {
        return Err(TargetJournalError::CorruptState);
    }
    let committed_increment = if inserted { request.expected_length } else { 0 };
    let counters = transaction.execute(
        "UPDATE target_state
         SET reserved_bytes = reserved_bytes - ?1,
             committed_bytes = committed_bytes + ?2
         WHERE singleton = 1 AND reserved_bytes >= ?1 AND committed_bytes <= ?3",
        params![
            to_i64(request.reservation.maximum_bytes)?,
            to_i64(committed_increment)?,
            i64::MAX - to_i64(committed_increment)?,
        ],
    )?;
    if counters == 1 {
        Ok(())
    } else {
        Err(TargetJournalError::CorruptState)
    }
}

fn copy_array<const LENGTH: usize>(value: &[u8]) -> Result<[u8; LENGTH], TargetJournalError> {
    value
        .try_into()
        .map_err(|_| TargetJournalError::CorruptState)
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::{
        ContractVersion, RequestContext, ReservationClass, ShardIdentity, ShardReceipt,
    };
    use meshspan_domain::{
        EntropyError, MeshId, OperationId, RandomSource, Revision, TargetId, UnixMicros,
    };
    use tempfile::tempdir;

    use super::{DurablePackEvidence, JournalPutRequest, PreparePutResult};
    use crate::{
        CapacityObservation, CapacityPolicy, ReserveCapacityRequest, TargetJournal, TargetMarker,
        UsageLimit,
    };

    struct FixedRandom;

    impl RandomSource for FixedRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(9);
            Ok(())
        }
    }

    #[test]
    fn put_transitions_consume_capacity_page_inventory_and_replay_after_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let marker = TargetMarker::new(
            MeshId::from_bytes([1; 16])?,
            TargetId::from_bytes([2; 16])?,
            3,
            [4; 32],
        )?;
        let mut random = FixedRandom;
        let mut journal = TargetJournal::open(
            directory.path(),
            marker,
            CapacityPolicy {
                usage_limit: UsageLimit::Percent(95),
                repair_reserve_bytes: 100,
                revision: Revision::new(1),
            },
            UnixMicros::new(1),
            &mut random,
        )?;
        let first = put_request(&mut journal, marker, 10, 0, 50)?;
        assert_eq!(journal.prepare_put(first)?, PreparePutResult::Prepared);
        let second = put_request(&mut journal, marker, 11, 1, 60)?;
        assert_eq!(journal.prepare_put(second)?, PreparePutResult::Prepared);
        let first_pending_page = journal.pending_puts(None, 1)?;
        assert_eq!(first_pending_page.puts.len(), 1);
        let pending_cursor = first_pending_page
            .next_cursor
            .as_ref()
            .ok_or("missing pending cursor")?;
        let second_pending_page = journal.pending_puts(Some(pending_cursor), 1)?;
        assert_eq!(second_pending_page.puts.len(), 1);
        assert!(second_pending_page.next_cursor.is_none());
        drop(journal);

        let mut journal = TargetJournal::open(
            directory.path(),
            marker,
            CapacityPolicy {
                usage_limit: UsageLimit::Percent(95),
                repair_reserve_bytes: 100,
                revision: Revision::new(1),
            },
            UnixMicros::new(2),
            &mut random,
        )?;
        assert_eq!(journal.pending_puts(None, 10)?.puts.len(), 2);
        let first_receipt = receipt(marker, first);
        assert_eq!(
            journal.commit_put(first, evidence(first_receipt, 0))?,
            first_receipt
        );
        assert_eq!(
            journal.prepare_put(first)?,
            PreparePutResult::Committed(first_receipt)
        );
        assert_eq!(journal.pending_puts(None, 10)?.puts.len(), 1);
        assert_eq!(journal.capacity()?.committed_bytes, 50);
        assert_eq!(journal.capacity()?.reserved_bytes, 60);

        assert_eq!(journal.prepare_put(second)?, PreparePutResult::Prepared);
        journal.commit_put(second, evidence(receipt(marker, second), 1))?;
        assert!(journal.pending_puts(None, 10)?.puts.is_empty());
        assert_eq!(journal.capacity()?.committed_bytes, 110);
        assert_eq!(journal.capacity()?.reserved_bytes, 0);
        let page = journal.inventory(None, 1)?;
        assert_eq!(page.entries.len(), 1);
        let cursor = page.next_cursor.as_ref().ok_or("missing next cursor")?;
        let final_page = journal.inventory(Some(cursor), 1)?;
        assert_eq!(final_page.entries.len(), 1);
        assert!(final_page.next_cursor.is_none());
        assert_eq!(final_page.entries.as_slice()[0].shard, second.shard);
        assert!(journal.inventory(None, 0).is_err());
        assert!(journal.pending_puts(None, 0).is_err());
        Ok(())
    }

    fn put_request(
        journal: &mut TargetJournal,
        marker: TargetMarker,
        operation: u8,
        shard_index: u16,
        length: u64,
    ) -> Result<JournalPutRequest, Box<dyn std::error::Error>> {
        let context = RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([operation; 16])?,
            deadline: UnixMicros::new(1_000),
            expected_revision: Some(Revision::new(5)),
        };
        let reservation = journal.reserve(ReserveCapacityRequest {
            context,
            target_id: marker.target_id(),
            target_generation: marker.generation(),
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
            request_digest: [operation.wrapping_add(1); 32],
            shard: ShardIdentity {
                manifest_digest: [7; 32],
                stripe_index: 8,
                shard_index,
                generation: 9,
            },
            expected_length: length,
            expected_digest: [operation.wrapping_add(2); 32],
            now: UnixMicros::new(20),
        })
    }

    fn receipt(marker: TargetMarker, request: JournalPutRequest) -> ShardReceipt {
        ShardReceipt {
            operation_id: request.reservation.operation_id,
            shard: request.shard,
            length: request.expected_length,
            digest: request.expected_digest,
            target_id: marker.target_id(),
            target_generation: marker.generation(),
        }
    }

    const fn evidence(receipt: ShardReceipt, pack_offset: u64) -> DurablePackEvidence {
        DurablePackEvidence {
            receipt,
            pack_sequence: 1,
            pack_offset,
        }
    }
}
