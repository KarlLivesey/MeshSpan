// SPDX-License-Identifier: GPL-2.0-only

//! Bounded restart recovery pages for prepared removal intents.

use meshspan_contracts::{BoundedBytes, BoundedItems, RemovalPermit};
use meshspan_domain::{MeshId, OperationId, Revision, TargetId, UnixMicros};
use rusqlite::params;

use super::{OPERATION_PREPARED, TOMBSTONE_OPERATION_KIND};
use crate::journal::{TargetJournal, TargetJournalError, to_i64, to_u64};
use crate::shard::decode_shard;

const MAXIMUM_PENDING_ITEMS: usize = 1_000;

/// One bounded incomplete tombstone recovered after restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingTombstone {
    /// Complete current authority permit retained for exact reconciliation.
    pub permit: RemovalPermit,
    /// Exact request digest expected from the pack operation log.
    pub request_digest: [u8; 32],
}

/// Stable bounded page of incomplete tombstones.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingTombstonePage {
    /// Prepared tombstones in stable operation-ID order.
    pub tombstones: BoundedItems<PendingTombstone>,
    /// Opaque continuation cursor, or `None` at the end.
    pub next_cursor: Option<BoundedBytes>,
}

impl TargetJournal {
    /// Returns bounded prepared tombstones for pack/journal reconciliation after restart.
    ///
    /// # Errors
    ///
    /// Rejects malformed cursors/limits and corrupt persisted intent fields.
    pub fn pending_tombstones(
        &self,
        cursor: Option<&BoundedBytes>,
        limit: usize,
    ) -> Result<PendingTombstonePage, TargetJournalError> {
        if limit == 0 || limit > MAXIMUM_PENDING_ITEMS {
            return Err(TargetJournalError::InvalidInput);
        }
        let lower = match cursor {
            Some(value) if value.len() == 16 => value.as_slice(),
            Some(_) => return Err(TargetJournalError::InvalidInput),
            None => &[],
        };
        let mut statement = self.connection.prepare(
            "SELECT o.request_digest, r.operation_id, r.mesh_id, r.target_id,
                    r.target_generation, r.shard_identity, r.authority_epoch,
                    r.catalogue_revision, r.expires_at, r.permit_digest
             FROM provider_operations o
             JOIN removal_intents r ON r.operation_id = o.operation_id
             WHERE o.operation_kind = ?1 AND o.state = ?2 AND o.operation_id > ?3
             ORDER BY o.operation_id LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![
                TOMBSTONE_OPERATION_KIND,
                OPERATION_PREPARED,
                lower,
                to_i64(
                    u64::try_from(limit.saturating_add(1))
                        .map_err(|_| TargetJournalError::InvalidInput)?
                )?,
            ],
            read_row,
        )?;
        let mut tombstones = rows
            .map(|row| {
                row.map_err(Into::into)
                    .and_then(|value| decode_pending(&value))
            })
            .collect::<Result<Vec<_>, TargetJournalError>>()?;
        let next_cursor = next_cursor(&tombstones, limit)?;
        tombstones.truncate(limit);
        Ok(PendingTombstonePage {
            tombstones: BoundedItems::new(tombstones, limit)
                .map_err(|_| TargetJournalError::CorruptState)?,
            next_cursor,
        })
    }
}

type PendingRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
    i64,
    i64,
    Vec<u8>,
);

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PendingRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    ))
}

fn next_cursor(
    tombstones: &[PendingTombstone],
    limit: usize,
) -> Result<Option<BoundedBytes>, TargetJournalError> {
    if tombstones.len() <= limit {
        return Ok(None);
    }
    let operation = tombstones
        .get(limit - 1)
        .ok_or(TargetJournalError::CorruptState)?
        .permit
        .operation_id
        .as_bytes();
    BoundedBytes::copy_from(&operation, 16)
        .map(Some)
        .map_err(|_| TargetJournalError::CorruptState)
}

fn decode_pending(row: &PendingRow) -> Result<PendingTombstone, TargetJournalError> {
    Ok(PendingTombstone {
        request_digest: copy_array(&row.0)?,
        permit: RemovalPermit {
            operation_id: OperationId::from_bytes(copy_array(&row.1)?)
                .map_err(|_| TargetJournalError::CorruptState)?,
            mesh_id: MeshId::from_bytes(copy_array(&row.2)?)
                .map_err(|_| TargetJournalError::CorruptState)?,
            target_id: TargetId::from_bytes(copy_array(&row.3)?)
                .map_err(|_| TargetJournalError::CorruptState)?,
            target_generation: to_u64(row.4)?,
            shard: decode_shard(&row.5)?,
            authority_epoch: to_u64(row.6)?,
            catalogue_revision: Revision::new(to_u64(row.7)?),
            expires_at: UnixMicros::new(row.8),
            permit_digest: copy_array(&row.9)?,
        },
    })
}

fn copy_array<const LENGTH: usize>(value: &[u8]) -> Result<[u8; LENGTH], TargetJournalError> {
    value
        .try_into()
        .map_err(|_| TargetJournalError::CorruptState)
}
