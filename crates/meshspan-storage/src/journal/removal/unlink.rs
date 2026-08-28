// SPDX-License-Identifier: GPL-2.0-only

//! Journal authority checks and accounting for physical shard reclamation.

use meshspan_contracts::TombstoneReceipt;
use meshspan_domain::UnixMicros;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::{INVENTORY_TOMBSTONED, OPERATION_COMMITTED, TOMBSTONE_OPERATION_KIND};
use crate::journal::{TargetJournal, TargetJournalError, to_i64, to_u64};
use crate::shard::{decode_tombstone_receipt, encode_shard};

const INVENTORY_UNLINKED: i64 = 3;
type CommittedTombstoneRow = (Vec<u8>, Vec<u8>, i64, Vec<u8>);

impl TargetJournal {
    /// Verifies that an exact pack receipt is already journal-committed deletion authority.
    ///
    /// # Errors
    ///
    /// Rejects pack-only, missing, forged or state-inconsistent tombstone receipts.
    pub fn verify_committed_tombstone(
        &self,
        receipt: TombstoneReceipt,
    ) -> Result<(), TargetJournalError> {
        let shard = encode_shard(receipt.shard);
        let stored: Option<CommittedTombstoneRow> = self
            .connection
            .query_row(
                "SELECT t.permit_digest, t.tombstone_digest, i.state, o.receipt
                 FROM tombstones t
                 JOIN inventory i ON i.shard_identity = t.shard_identity
                 JOIN provider_operations o ON o.operation_id = t.cleanup_operation_id
                 WHERE t.shard_identity = ?1 AND t.cleanup_operation_id = ?2
                       AND o.operation_kind = ?3 AND o.state = ?4",
                params![
                    shard.as_slice(),
                    receipt.operation_id.as_bytes().as_slice(),
                    TOMBSTONE_OPERATION_KIND,
                    OPERATION_COMMITTED,
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((permit_digest, tombstone_digest, state, encoded_receipt)) = stored else {
            return Err(TargetJournalError::InvalidInput);
        };
        if permit_digest.as_slice() == receipt.permit_digest
            && tombstone_digest.as_slice() == receipt.tombstone_digest
            && matches!(state, INVENTORY_TOMBSTONED | INVENTORY_UNLINKED)
            && decode_tombstone_receipt(&encoded_receipt)? == receipt
        {
            Ok(())
        } else {
            Err(TargetJournalError::OperationConflict)
        }
    }

    /// Accounts physical reclamation only after the pack accepted the exact tombstone receipt.
    ///
    /// # Errors
    ///
    /// Rejects missing/conflicting receipts and inconsistent tombstone/inventory state.
    pub fn commit_unlink(
        &mut self,
        receipt: TombstoneReceipt,
        now: UnixMicros,
    ) -> Result<(), TargetJournalError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let shard = encode_shard(receipt.shard);
        let stored = load_unlink_state(&transaction, receipt)?;
        validate_unlink_state(&stored, receipt)?;
        if stored.2.is_some() && stored.4 == INVENTORY_UNLINKED {
            return Ok(());
        }
        let length = to_u64(stored.3)?;
        let changed = transaction.execute(
            "UPDATE tombstones SET bytes_unlinked_at = ?1
             WHERE shard_identity = ?2 AND bytes_unlinked_at IS NULL",
            params![now.get(), shard.as_slice()],
        )?;
        let inventory_changed = transaction.execute(
            "UPDATE inventory SET state = ?1 WHERE shard_identity = ?2 AND state = ?3",
            params![INVENTORY_UNLINKED, shard.as_slice(), INVENTORY_TOMBSTONED],
        )?;
        let capacity_changed = transaction.execute(
            "UPDATE target_state SET committed_bytes = committed_bytes - ?1
             WHERE singleton = 1 AND committed_bytes >= ?1",
            [to_i64(length)?],
        )?;
        if changed != 1 || inventory_changed != 1 || capacity_changed != 1 {
            return Err(TargetJournalError::CorruptState);
        }
        transaction.commit()?;
        Ok(())
    }
}

type UnlinkState = (Vec<u8>, Vec<u8>, Option<i64>, i64, i64);

fn load_unlink_state(
    transaction: &rusqlite::Transaction<'_>,
    receipt: TombstoneReceipt,
) -> Result<UnlinkState, TargetJournalError> {
    let shard = encode_shard(receipt.shard);
    transaction
        .query_row(
            "SELECT t.permit_digest, t.tombstone_digest, t.bytes_unlinked_at,
                    i.stored_length, i.state
             FROM tombstones t JOIN inventory i ON i.shard_identity = t.shard_identity
             WHERE t.shard_identity = ?1 AND t.cleanup_operation_id = ?2",
            params![shard.as_slice(), receipt.operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(TargetJournalError::InvalidInput)
}

fn validate_unlink_state(
    stored: &UnlinkState,
    receipt: TombstoneReceipt,
) -> Result<(), TargetJournalError> {
    if stored.0.as_slice() != receipt.permit_digest
        || stored.1.as_slice() != receipt.tombstone_digest
    {
        Err(TargetJournalError::OperationConflict)
    } else if stored.2.is_some() != (stored.4 == INVENTORY_UNLINKED)
        || !matches!(stored.4, INVENTORY_TOMBSTONED | INVENTORY_UNLINKED)
    {
        Err(TargetJournalError::CorruptState)
    } else {
        Ok(())
    }
}
