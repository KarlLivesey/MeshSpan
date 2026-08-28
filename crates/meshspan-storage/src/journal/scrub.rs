// SPDX-License-Identifier: GPL-2.0-only

//! Compare-and-set recording of independently verified shard bytes.

use meshspan_contracts::{BoundedBytes, InventoryEntry};
use meshspan_domain::UnixMicros;
use rusqlite::{TransactionBehavior, params};

use super::{TargetJournal, TargetJournalError, to_i64, to_u64};
use crate::shard::{SHARD_KEY_BYTES, encode_shard};

const INVENTORY_COMMITTED: i64 = 1;

/// Durable continuation for the target's default continuous scrub loop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScrubCheckpoint {
    /// Last completed inventory key, or `None` at the beginning of a cycle.
    pub cursor: Option<BoundedBytes>,
    /// Number of complete inventory passes.
    pub completed_cycles: u64,
}

impl TargetJournal {
    /// Records a healthy observation only while exact committed inventory remains unchanged.
    ///
    /// # Errors
    ///
    /// Rejects a stale observation or missing/non-live inventory rather than blessing new state.
    pub fn mark_shard_verified(
        &mut self,
        expected: InventoryEntry,
        verified_at: UnixMicros,
    ) -> Result<(), TargetJournalError> {
        let shard = encode_shard(expected.shard);
        let changed = self.connection.execute(
            "UPDATE inventory SET last_verified_at = ?1
             WHERE shard_identity = ?2 AND stored_length = ?3 AND stored_digest = ?4
                   AND state = ?5",
            params![
                verified_at.get(),
                shard.as_slice(),
                to_i64(expected.length)?,
                expected.digest.as_slice(),
                INVENTORY_COMMITTED,
            ],
        )?;
        if changed == 1 {
            Ok(())
        } else {
            Err(TargetJournalError::OperationConflict)
        }
    }

    /// Loads the durable continuation for continuous background scrub.
    ///
    /// # Errors
    ///
    /// Rejects malformed durable cursor bytes or counters.
    pub fn scrub_checkpoint(&self) -> Result<ScrubCheckpoint, TargetJournalError> {
        let (cursor, completed_cycles): (Vec<u8>, i64) = self.connection.query_row(
            "SELECT cursor_value, completed_cycles FROM scrub_cursor WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok(ScrubCheckpoint {
            cursor: decode_cursor(&cursor)?,
            completed_cycles: to_u64(completed_cycles)?,
        })
    }

    /// Advances continuous scrub only from the exact checkpoint that produced the page.
    ///
    /// # Errors
    ///
    /// Rejects malformed cursors, concurrent/stale advancement and counter exhaustion.
    pub fn advance_scrub_checkpoint(
        &mut self,
        expected: &ScrubCheckpoint,
        next_cursor: Option<&BoundedBytes>,
        updated_at: UnixMicros,
    ) -> Result<(), TargetJournalError> {
        validate_cursor(next_cursor)?;
        let expected_cursor = expected
            .cursor
            .as_ref()
            .map_or(&[][..], BoundedBytes::as_slice);
        let next = next_cursor.map_or(&[][..], BoundedBytes::as_slice);
        let next_cycles = if next_cursor.is_none() {
            expected
                .completed_cycles
                .checked_add(1)
                .ok_or(TargetJournalError::InvalidInput)?
        } else {
            expected.completed_cycles
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE scrub_cursor
             SET cursor_value = ?1, completed_cycles = ?2, updated_at = ?3
             WHERE singleton = 1 AND cursor_value = ?4 AND completed_cycles = ?5",
            params![
                next,
                to_i64(next_cycles)?,
                updated_at.get(),
                expected_cursor,
                to_i64(expected.completed_cycles)?,
            ],
        )?;
        if changed != 1 {
            return Err(TargetJournalError::OperationConflict);
        }
        transaction.commit()?;
        Ok(())
    }
}

fn decode_cursor(value: &[u8]) -> Result<Option<BoundedBytes>, TargetJournalError> {
    if value.is_empty() {
        Ok(None)
    } else if value.len() == SHARD_KEY_BYTES {
        BoundedBytes::copy_from(value, SHARD_KEY_BYTES)
            .map(Some)
            .map_err(|_| TargetJournalError::CorruptState)
    } else {
        Err(TargetJournalError::CorruptState)
    }
}

fn validate_cursor(value: Option<&BoundedBytes>) -> Result<(), TargetJournalError> {
    if value.is_some_and(|cursor| cursor.len() != SHARD_KEY_BYTES) {
        Err(TargetJournalError::InvalidInput)
    } else {
        Ok(())
    }
}
