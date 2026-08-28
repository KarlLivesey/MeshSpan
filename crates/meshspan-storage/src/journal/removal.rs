// SPDX-License-Identifier: GPL-2.0-only

//! Prepared/committed removal transitions and guarded capacity reclamation.

use meshspan_contracts::{RemovalPermit, TombstoneReceipt};
use meshspan_domain::{OperationId, UnixMicros};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use super::{TargetJournal, TargetJournalError, to_i64};
use crate::shard::{decode_tombstone_receipt, encode_shard, encode_tombstone_receipt};

mod recovery;
mod unlink;

pub use recovery::{PendingTombstone, PendingTombstonePage};

const TOMBSTONE_OPERATION_KIND: i64 = 2;
const OPERATION_PREPARED: i64 = 1;
const OPERATION_COMMITTED: i64 = 4;
const INVENTORY_COMMITTED: i64 = 1;
const INVENTORY_TOMBSTONED: i64 = 2;

/// Exact journal input recorded before pack bytes become unreachable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalTombstoneRequest {
    /// Current authority-issued exact removal permit.
    pub permit: RemovalPermit,
    /// Canonical digest of the complete request, including the permit MAC.
    pub request_digest: [u8; 32],
    /// Current authority instant.
    pub now: UnixMicros,
}

/// Independently durable pack tombstone accepted by the target journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableTombstoneEvidence {
    /// Exact receipt read from the pack operation log.
    pub receipt: TombstoneReceipt,
}

/// Result of preparing an exact tombstone operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrepareTombstoneResult {
    /// The pack still needs to make the shard unreadable durably.
    Prepared,
    /// The exact operation already committed.
    Committed(TombstoneReceipt),
}

impl TargetJournal {
    /// Records or resolves one exact removal intent before touching pack reachability.
    ///
    /// # Errors
    ///
    /// Rejects stale/foreign authority, absent live inventory and conflicting operation reuse.
    pub fn prepare_tombstone(
        &mut self,
        request: JournalTombstoneRequest,
    ) -> Result<PrepareTombstoneResult, TargetJournalError> {
        validate_request(self, request, true)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = load_operation(&transaction, request.permit.operation_id)? {
            return resolve_operation(existing, request);
        }
        require_live_inventory(&transaction, request.permit)?;
        insert_prepared(&transaction, request)?;
        transaction.commit()?;
        Ok(PrepareTombstoneResult::Prepared)
    }

    /// Commits inventory removal only after the pack independently persisted a tombstone.
    ///
    /// # Errors
    ///
    /// Rejects absent preparation, conflicting replay or evidence not bound to the exact permit.
    pub fn commit_tombstone(
        &mut self,
        request: JournalTombstoneRequest,
        evidence: DurableTombstoneEvidence,
    ) -> Result<TombstoneReceipt, TargetJournalError> {
        validate_request(self, request, false)?;
        validate_evidence(request.permit, evidence.receipt)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = load_operation(&transaction, request.permit.operation_id)?
            .ok_or(TargetJournalError::InvalidInput)?;
        if let PrepareTombstoneResult::Committed(receipt) = resolve_operation(existing, request)? {
            return Ok(receipt);
        }
        install_tombstone(&transaction, request, evidence.receipt)?;
        complete_operation(&transaction, request, evidence.receipt)?;
        transaction.commit()?;
        Ok(evidence.receipt)
    }
}

struct StoredOperation {
    kind: i64,
    request_digest: [u8; 32],
    state: i64,
    shard: [u8; crate::shard::SHARD_KEY_BYTES],
    receipt: Option<Vec<u8>>,
}

fn validate_request(
    journal: &TargetJournal,
    request: JournalTombstoneRequest,
    require_unexpired: bool,
) -> Result<(), TargetJournalError> {
    let permit = request.permit;
    if permit.mesh_id != journal.marker.mesh_id()
        || permit.target_id != journal.marker.target_id()
        || permit.target_generation != journal.marker.generation()
        || permit.authority_epoch == 0
        || (require_unexpired && permit.expires_at <= request.now)
    {
        Err(TargetJournalError::InvalidInput)
    } else {
        Ok(())
    }
}

fn require_live_inventory(
    transaction: &Transaction<'_>,
    permit: RemovalPermit,
) -> Result<(), TargetJournalError> {
    let shard = encode_shard(permit.shard);
    let state: Option<i64> = transaction
        .query_row(
            "SELECT state FROM inventory WHERE shard_identity = ?1",
            [shard.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if state == Some(INVENTORY_COMMITTED) {
        Ok(())
    } else {
        Err(TargetJournalError::InvalidInput)
    }
}

fn insert_prepared(
    transaction: &Transaction<'_>,
    request: JournalTombstoneRequest,
) -> Result<(), TargetJournalError> {
    let permit = request.permit;
    let operation = permit.operation_id.as_bytes();
    let shard = encode_shard(permit.shard);
    transaction.execute(
        "INSERT INTO provider_operations(
            operation_id, operation_kind, request_digest, state, shard_identity,
            expected_digest, updated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            operation.as_slice(),
            TOMBSTONE_OPERATION_KIND,
            request.request_digest.as_slice(),
            OPERATION_PREPARED,
            shard.as_slice(),
            permit.permit_digest.as_slice(),
            request.now.get(),
        ],
    )?;
    transaction.execute(
        "INSERT INTO removal_intents(
            operation_id, mesh_id, target_id, target_generation, shard_identity,
            authority_epoch, catalogue_revision, expires_at, permit_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            operation.as_slice(),
            permit.mesh_id.as_bytes().as_slice(),
            permit.target_id.as_bytes().as_slice(),
            to_i64(permit.target_generation)?,
            shard.as_slice(),
            to_i64(permit.authority_epoch)?,
            to_i64(permit.catalogue_revision.get())?,
            permit.expires_at.get(),
            permit.permit_digest.as_slice(),
        ],
    )?;
    Ok(())
}

fn load_operation(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
) -> Result<Option<StoredOperation>, TargetJournalError> {
    transaction
        .query_row(
            "SELECT operation_kind, request_digest, state, shard_identity, receipt
             FROM provider_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(StoredOperation {
                kind: row.0,
                request_digest: copy_array(&row.1)?,
                state: row.2,
                shard: copy_array(&row.3)?,
                receipt: row.4,
            })
        })
        .transpose()
}

fn resolve_operation(
    existing: StoredOperation,
    request: JournalTombstoneRequest,
) -> Result<PrepareTombstoneResult, TargetJournalError> {
    if existing.kind != TOMBSTONE_OPERATION_KIND
        || existing.request_digest != request.request_digest
        || existing.shard != encode_shard(request.permit.shard)
    {
        return Err(TargetJournalError::OperationConflict);
    }
    match (existing.state, existing.receipt) {
        (OPERATION_PREPARED, None) => Ok(PrepareTombstoneResult::Prepared),
        (OPERATION_COMMITTED, Some(receipt)) => Ok(PrepareTombstoneResult::Committed(
            decode_tombstone_receipt(&receipt)?,
        )),
        _ => Err(TargetJournalError::CorruptState),
    }
}

fn install_tombstone(
    transaction: &Transaction<'_>,
    request: JournalTombstoneRequest,
    receipt: TombstoneReceipt,
) -> Result<(), TargetJournalError> {
    let shard = encode_shard(request.permit.shard);
    let changed = transaction.execute(
        "UPDATE inventory SET state = ?1 WHERE shard_identity = ?2 AND state = ?3",
        params![INVENTORY_TOMBSTONED, shard.as_slice(), INVENTORY_COMMITTED],
    )?;
    if changed != 1 {
        return Err(TargetJournalError::OperationConflict);
    }
    transaction.execute(
        "INSERT INTO tombstones(
            shard_identity, cleanup_operation_id, permit_digest, tombstone_digest, tombstoned_at
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            shard.as_slice(),
            request.permit.operation_id.as_bytes().as_slice(),
            receipt.permit_digest.as_slice(),
            receipt.tombstone_digest.as_slice(),
            request.now.get(),
        ],
    )?;
    Ok(())
}

fn complete_operation(
    transaction: &Transaction<'_>,
    request: JournalTombstoneRequest,
    receipt: TombstoneReceipt,
) -> Result<(), TargetJournalError> {
    let encoded = encode_tombstone_receipt(receipt);
    let changed = transaction.execute(
        "UPDATE provider_operations SET state = ?1, receipt = ?2, updated_at = ?3
         WHERE operation_id = ?4 AND operation_kind = ?5 AND state = ?6
               AND request_digest = ?7",
        params![
            OPERATION_COMMITTED,
            encoded.as_slice(),
            request.now.get(),
            request.permit.operation_id.as_bytes().as_slice(),
            TOMBSTONE_OPERATION_KIND,
            OPERATION_PREPARED,
            request.request_digest.as_slice(),
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(TargetJournalError::CorruptState)
    }
}

fn validate_evidence(
    permit: RemovalPermit,
    receipt: TombstoneReceipt,
) -> Result<(), TargetJournalError> {
    if receipt.operation_id == permit.operation_id
        && receipt.shard == permit.shard
        && receipt.target_id == permit.target_id
        && receipt.target_generation == permit.target_generation
        && receipt.permit_digest == permit.permit_digest
    {
        Ok(())
    } else {
        Err(TargetJournalError::InvalidInput)
    }
}

fn copy_array<const LENGTH: usize>(value: &[u8]) -> Result<[u8; LENGTH], TargetJournalError> {
    value
        .try_into()
        .map_err(|_| TargetJournalError::CorruptState)
}
