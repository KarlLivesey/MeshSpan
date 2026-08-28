// SPDX-License-Identifier: GPL-2.0-only

//! Durable pack tombstones and guarded physical byte reclamation.

use meshspan_contracts::{RemovalPermit, TombstoneReceipt};
use meshspan_domain::{OperationId, UnixMicros};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use super::{PackStore, PackStoreError};
use crate::shard::{decode_tombstone_receipt, encode_shard, encode_tombstone_receipt};

const TOMBSTONE_OPERATION_KIND: i64 = 2;
const SHARD_ACTIVE: i64 = 1;
const SHARD_TOMBSTONED: i64 = 2;
const SHARD_UNLINKED: i64 = 3;

#[derive(Clone, Copy)]
pub(crate) struct PackTombstoneRequest {
    pub permit: RemovalPermit,
    pub request_digest: [u8; 32],
    pub now: UnixMicros,
}

impl PackStore {
    pub fn tombstone_exact(
        &mut self,
        request: PackTombstoneRequest,
    ) -> Result<TombstoneReceipt, PackStoreError> {
        validate_request(self, request)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(receipt) = load_operation(
            &transaction,
            request.permit.operation_id,
            request.request_digest,
        )? {
            verify_tombstoned(&transaction, receipt)?;
            transaction.commit()?;
            return Ok(receipt);
        }
        mark_tombstoned(&transaction, request)?;
        let receipt = tombstone_receipt(request.permit);
        store_operation(&transaction, request, receipt)?;
        transaction.commit()?;
        Ok(receipt)
    }

    pub fn recover_tombstone(
        &self,
        operation_id: OperationId,
        request_digest: [u8; 32],
    ) -> Result<Option<TombstoneReceipt>, PackStoreError> {
        let transaction = self.connection.unchecked_transaction()?;
        let receipt = load_operation(&transaction, operation_id, request_digest)?;
        if let Some(value) = receipt {
            verify_tombstoned(&transaction, value)?;
        }
        transaction.commit()?;
        Ok(receipt)
    }

    pub fn unlink_tombstoned(
        &mut self,
        receipt: TombstoneReceipt,
        now: UnixMicros,
    ) -> Result<(), PackStoreError> {
        if receipt.target_id != self.marker.target_id()
            || receipt.target_generation != self.marker.generation()
        {
            return Err(PackStoreError::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        verify_stored_receipt(&transaction, receipt)?;
        let shard = encode_shard(receipt.shard);
        let state: i64 = transaction
            .query_row(
                "SELECT state FROM shards WHERE shard_identity = ?1",
                [shard.as_slice()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(PackStoreError::NotFound)?;
        match state {
            SHARD_TOMBSTONED => {
                let changed = transaction.execute(
                    "UPDATE shards SET stored_bytes = NULL, state = ?1, unlinked_at = ?2
                     WHERE shard_identity = ?3 AND state = ?4 AND stored_bytes IS NOT NULL",
                    params![
                        SHARD_UNLINKED,
                        now.get(),
                        shard.as_slice(),
                        SHARD_TOMBSTONED
                    ],
                )?;
                if changed != 1 {
                    return Err(PackStoreError::Corrupt);
                }
            }
            SHARD_UNLINKED => {}
            _ => return Err(PackStoreError::Corrupt),
        }
        transaction.commit()?;
        Ok(())
    }
}

fn validate_request(pack: &PackStore, request: PackTombstoneRequest) -> Result<(), PackStoreError> {
    let permit = request.permit;
    if permit.mesh_id != pack.marker.mesh_id()
        || permit.target_id != pack.marker.target_id()
        || permit.target_generation != pack.marker.generation()
        || permit.authority_epoch == 0
        || permit.expires_at <= request.now
    {
        Err(PackStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn load_operation(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
    request_digest: [u8; 32],
) -> Result<Option<TombstoneReceipt>, PackStoreError> {
    let operation = operation_id.as_bytes();
    let stored: Option<(Vec<u8>, Vec<u8>)> = transaction
        .query_row(
            "SELECT request_digest, result_receipt FROM pack_operations
             WHERE operation_id = ?1 AND operation_kind = ?2",
            params![operation.as_slice(), TOMBSTONE_OPERATION_KIND],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match stored {
        Some((digest, receipt)) if digest.as_slice() == request_digest => Ok(Some(
            decode_tombstone_receipt(&receipt).map_err(|_| PackStoreError::Corrupt)?,
        )),
        Some(_) => Err(PackStoreError::OperationConflict),
        None => Ok(None),
    }
}

fn mark_tombstoned(
    transaction: &Transaction<'_>,
    request: PackTombstoneRequest,
) -> Result<(), PackStoreError> {
    let shard = encode_shard(request.permit.shard);
    let changed = transaction.execute(
        "UPDATE shards SET state = ?1, tombstoned_at = ?2
         WHERE shard_identity = ?3 AND state = ?4 AND stored_bytes IS NOT NULL",
        params![
            SHARD_TOMBSTONED,
            request.now.get(),
            shard.as_slice(),
            SHARD_ACTIVE,
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(PackStoreError::NotFound)
    }
}

fn store_operation(
    transaction: &Transaction<'_>,
    request: PackTombstoneRequest,
    receipt: TombstoneReceipt,
) -> Result<(), PackStoreError> {
    let operation = request.permit.operation_id.as_bytes();
    let shard = encode_shard(request.permit.shard);
    let receipt = encode_tombstone_receipt(receipt);
    transaction.execute(
        "INSERT INTO pack_operations(
            operation_id, operation_kind, request_digest, shard_identity,
            result_receipt, completed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            operation.as_slice(),
            TOMBSTONE_OPERATION_KIND,
            request.request_digest.as_slice(),
            shard.as_slice(),
            receipt.as_slice(),
            request.now.get(),
        ],
    )?;
    Ok(())
}

fn verify_stored_receipt(
    transaction: &Transaction<'_>,
    expected: TombstoneReceipt,
) -> Result<(), PackStoreError> {
    let operation = expected.operation_id.as_bytes();
    let stored: Vec<u8> = transaction
        .query_row(
            "SELECT result_receipt FROM pack_operations
             WHERE operation_id = ?1 AND operation_kind = ?2",
            params![operation.as_slice(), TOMBSTONE_OPERATION_KIND],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(PackStoreError::NotFound)?;
    let actual = decode_tombstone_receipt(&stored).map_err(|_| PackStoreError::Corrupt)?;
    if actual == expected {
        Ok(())
    } else {
        Err(PackStoreError::OperationConflict)
    }
}

fn verify_tombstoned(
    transaction: &Transaction<'_>,
    receipt: TombstoneReceipt,
) -> Result<(), PackStoreError> {
    let shard = encode_shard(receipt.shard);
    let state: i64 = transaction
        .query_row(
            "SELECT state FROM shards WHERE shard_identity = ?1",
            [shard.as_slice()],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(PackStoreError::Corrupt)?;
    if matches!(state, SHARD_TOMBSTONED | SHARD_UNLINKED) {
        Ok(())
    } else {
        Err(PackStoreError::Corrupt)
    }
}

fn tombstone_receipt(permit: RemovalPermit) -> TombstoneReceipt {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.storage.tombstone-receipt.v1");
    digest.update(&permit.operation_id.as_bytes());
    digest.update(&encode_shard(permit.shard));
    digest.update(&permit.target_id.as_bytes());
    digest.update(&permit.target_generation.to_be_bytes());
    digest.update(&permit.permit_digest);
    TombstoneReceipt {
        operation_id: permit.operation_id,
        shard: permit.shard,
        target_id: permit.target_id,
        target_generation: permit.target_generation,
        permit_digest: permit.permit_digest,
        tombstone_digest: digest.finalize().into(),
    }
}
