// SPDX-License-Identifier: GPL-2.0-only

//! Durable shard-to-pack assignment, committed before any payload IO.

use meshspan_contracts::ShardIdentity;
use rusqlite::{OptionalExtension, Transaction, params};

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
        let sequence: Option<i64> = self
            .connection
            .query_row(
                "SELECT sequence FROM pack_segments WHERE sequence > ?1 ORDER BY sequence LIMIT 1",
                [to_i64(after)?],
                |row| row.get(0),
            )
            .optional()?;
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
        let mut statement = self
            .connection
            .prepare("SELECT sequence FROM pack_segments ORDER BY sequence LIMIT ?1")?;
        let rows = statement.query_map([i64::from(limit)], |row| row.get::<_, i64>(0))?;
        rows.map(|row| to_u64(row?)).collect()
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
            "SELECT expected_length, expected_digest FROM pack_routes WHERE shard_identity = ?1",
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
    transaction.execute("INSERT INTO pack_segments VALUES (?1, 0, 0)", [next])?;
    Ok(next)
}
