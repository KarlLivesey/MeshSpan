// SPDX-License-Identifier: GPL-2.0-only

//! Durable shard-to-pack assignment, committed before any payload IO.

use meshspan_contracts::ShardIdentity;
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use super::{JournalPutRequest, TargetJournal, TargetJournalError, to_i64, to_u64};
use crate::shard::encode_shard;

#[derive(Clone, Copy)]
pub(crate) struct PackLimits {
    pub payload_bytes: u64,
    pub records: u64,
}

impl Default for PackLimits {
    fn default() -> Self {
        Self {
            payload_bytes: 256 * 1024 * 1024,
            records: 4_096,
        }
    }
}

impl TargetJournal {
    pub(crate) fn next_pack_sequence(&self, after: u64) -> Result<Option<u64>, TargetJournalError> {
        // Both fresh and interrupted maintenance participate in the same cyclic cursor.
        // Each arm seeks one indexed candidate, independent of retained terminal history.
        let sequence: Option<i64> = self.connection.query_row(
            "SELECT min(sequence) FROM (
                SELECT sequence FROM (SELECT sequence FROM pack_segments
                    WHERE lifecycle_state = 1 AND sequence > ?1 ORDER BY sequence LIMIT 1)
                UNION ALL
                SELECT sequence FROM (SELECT sequence FROM pack_segments
                    WHERE lifecycle_state = 2 AND sequence > ?1 ORDER BY sequence LIMIT 1)
             )",
            [to_i64(after)?],
            |row| row.get(0),
        )?;
        sequence.map(to_u64).transpose()
    }

    /// Exact routing survives rollover, deletion and incomplete put recovery.
    pub(crate) fn pack_sequence(
        &self,
        shard: ShardIdentity,
    ) -> Result<Option<u64>, TargetJournalError> {
        let key = encode_shard(shard);
        let sequence: Option<i64> = self
            .connection
            .query_row(
                "SELECT pack_sequence FROM pack_routes WHERE shard_identity = ?1",
                [key.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        sequence.map(to_u64).transpose()
    }

    pub(crate) fn active_pack_sequence(&self) -> Result<u64, TargetJournalError> {
        let sequence: i64 = self.connection.query_row(
            "SELECT sequence FROM pack_segments ORDER BY sequence DESC LIMIT 1",
            [],
            |row| row.get(0),
        )?;
        to_u64(sequence)
    }

    /// Bounded inspection only; callers must not report a partial list as complete coverage.
    pub(crate) fn pack_sequences(&self, limit: u32) -> Result<Vec<u64>, TargetJournalError> {
        // Each indexed arm examines at most one page; sorting never visits retired history.
        // Pending retirement still counts until directory durability is confirmed.
        let mut statement = self.connection.prepare(
            "SELECT sequence FROM (SELECT sequence FROM pack_segments
                 WHERE lifecycle_state = 1 ORDER BY sequence LIMIT ?1)
             UNION ALL
             SELECT sequence FROM (SELECT sequence FROM pack_segments
                 WHERE lifecycle_state = 2 ORDER BY sequence LIMIT ?1)
             ORDER BY sequence LIMIT ?1",
        )?;
        let rows = statement.query_map([i64::from(limit)], |row| row.get::<_, i64>(0))?;
        rows.map(|row| to_u64(row?)).collect()
    }

    /// Checks only the selected segment; a blocked retirement cannot starve later work.
    pub(crate) fn pack_retirement_pending(
        &self,
        sequence: u64,
    ) -> Result<bool, TargetJournalError> {
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pack_segments
             WHERE sequence = ?1 AND lifecycle_state = 2)",
                [to_i64(sequence)?],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    /// Fences a bounded, fully reclaimed old pack before any filesystem deletion.
    pub(crate) fn prepare_pack_retirement(
        &mut self,
        sequence: u64,
    ) -> Result<bool, TargetJournalError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let sequence = to_i64(sequence)?;
        let eligible: bool = transaction.query_row(
            "SELECT lifecycle_state = 1 AND assigned_records BETWEEN 1 AND 4096
                    AND sequence < (SELECT max(sequence) FROM pack_segments)
             FROM pack_segments WHERE sequence = ?1",
            [sequence],
            |row| row.get(0),
        )?;
        let routes: i64 = transaction.query_row(
            "SELECT count(*) FROM (SELECT 1 FROM pack_routes
             WHERE pack_sequence = ?1 LIMIT 4097)",
            [sequence],
            |row| row.get(0),
        )?;
        if !eligible
            || !(1..=4096).contains(&routes)
            || !pack_routes_reclaimed(&transaction, sequence)?
        {
            return Ok(false);
        }
        let changed = transaction.execute(
            "UPDATE pack_segments SET lifecycle_state = 2
             WHERE sequence = ?1 AND lifecycle_state = 1",
            [sequence],
        )?;
        if changed != 1 {
            return Err(TargetJournalError::CorruptState);
        }
        transaction.commit()?;
        Ok(true)
    }

    /// Runs only after all pack files were removed and the parent directory was synced.
    pub(crate) fn complete_pack_retirement(
        &mut self,
        sequence: u64,
    ) -> Result<(), TargetJournalError> {
        let changed = self.connection.execute(
            "UPDATE pack_segments SET lifecycle_state = 3
             WHERE sequence = ?1 AND lifecycle_state = 2",
            [to_i64(sequence)?],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(TargetJournalError::CorruptState)
        }
    }

    #[cfg(test)]
    pub(crate) fn set_pack_limits(&mut self, limits: PackLimits) {
        self.pack_limits = limits;
    }
}

pub(super) fn assign_pack(
    transaction: &Transaction<'_>,
    request: JournalPutRequest,
    limits: PackLimits,
) -> Result<(), TargetJournalError> {
    let key = encode_shard(request.shard);
    let existing: Option<(i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT r.expected_length, r.expected_digest FROM pack_routes r
             JOIN pack_segments p ON p.sequence = r.pack_sequence
             WHERE r.shard_identity = ?1 AND p.lifecycle_state = 1",
            [key.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((length, digest)) = existing {
        return if to_u64(length)? == request.expected_length
            && digest.as_slice() == request.expected_digest
        {
            Ok(())
        } else {
            Err(TargetJournalError::OperationConflict)
        };
    }
    let retired: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM pack_routes WHERE shard_identity = ?1)",
        [key.as_slice()],
        |row| row.get(0),
    )?;
    if retired {
        return Err(TargetJournalError::OperationConflict);
    }
    if request.expected_length == 0
        || request.expected_length > limits.payload_bytes
        || limits.records == 0
    {
        return Err(TargetJournalError::InvalidInput);
    }
    let sequence = choose_segment(transaction, request.expected_length, limits)?;
    transaction.execute(
        "INSERT INTO pack_routes(shard_identity, pack_sequence, expected_length, expected_digest)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            key.as_slice(),
            sequence,
            to_i64(request.expected_length)?,
            request.expected_digest.as_slice()
        ],
    )?;
    let updated = transaction.execute(
        "UPDATE pack_segments SET assigned_bytes = assigned_bytes + ?1,
         assigned_records = assigned_records + 1 WHERE sequence = ?2
         AND assigned_bytes <= ?3 AND assigned_records < ?4",
        params![
            to_i64(request.expected_length)?,
            sequence,
            to_i64(limits.payload_bytes - request.expected_length)?,
            to_i64(limits.records)?
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(TargetJournalError::CorruptState)
    }
}

fn choose_segment(
    transaction: &Transaction<'_>,
    length: u64,
    limits: PackLimits,
) -> Result<i64, TargetJournalError> {
    let (sequence, bytes, records): (i64, i64, i64) = transaction.query_row(
        "SELECT sequence, assigned_bytes, assigned_records FROM pack_segments
         ORDER BY sequence DESC LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if to_u64(bytes)? <= limits.payload_bytes - length && to_u64(records)? < limits.records {
        return Ok(sequence);
    }
    let next = sequence
        .checked_add(1)
        .ok_or(TargetJournalError::CapacityExhausted)?;
    transaction.execute(
        "INSERT INTO pack_segments(sequence, assigned_bytes, assigned_records) VALUES (?1, 0, 0)",
        [next],
    )?;
    Ok(next)
}

fn pack_routes_reclaimed(
    transaction: &Transaction<'_>,
    sequence: i64,
) -> Result<bool, TargetJournalError> {
    // Inventory, receipts and the unlink timestamp retain replay authority after payload loss.
    // An incomplete put of the same shard also pins the pack, even if another put committed.
    let blocked: bool = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM pack_routes r
            LEFT JOIN inventory i ON i.shard_identity = r.shard_identity
            LEFT JOIN tombstones t ON t.shard_identity = r.shard_identity
            LEFT JOIN provider_operations o ON o.operation_id = t.cleanup_operation_id
            WHERE r.pack_sequence = ?1 AND (
                i.state IS NULL OR i.state <> 3 OR i.pack_sequence <> ?1
                OR t.bytes_unlinked_at IS NULL OR o.state IS NULL OR o.state <> 4
                OR o.operation_kind <> 2 OR o.receipt IS NULL
                OR EXISTS (SELECT 1 FROM provider_operations pending
                    WHERE pending.shard_identity = r.shard_identity AND pending.state <> 4)
            )
        )",
        [sequence],
        |row| row.get(0),
    )?;
    Ok(!blocked)
}
