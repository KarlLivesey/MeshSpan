// SPDX-License-Identifier: GPL-2.0-only

//! Bounded tenant-scoped provider catalogue for federated return reconciliation.

use meshspan_contracts::{
    BoundedItems, FederatedStorageInventoryRecord, ShardIdentity,
    validate_federated_storage_inventory_record,
};
use meshspan_domain::{
    FederationGrantId, FederationStorageAllocationId, MeshId, TargetId, UnixMicros,
};
use rusqlite::{params, types::Value};
use thiserror::Error;

use crate::LocalDatabase;

/// Hard ceiling independent of a peer-provided page limit.
pub const MAXIMUM_FEDERATED_STORAGE_INVENTORY_ITEMS: usize = 1_024;

/// Stable seek position within one remote-mesh/grant/target catalogue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageInventoryCursor {
    /// Opaque owning scope digest.
    pub scope_digest: [u8; 32],
    /// Last logical shard returned within that scope.
    pub shard: ShardIdentity,
}

/// One bounded page of active journal-backed federation shard records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationStorageInventoryPage {
    /// Active records in immutable provider catalogue order.
    pub records: BoundedItems<FederatedStorageInventoryRecord>,
    /// Last returned key when another record exists, otherwise no continuation.
    pub next_cursor: Option<FederationStorageInventoryCursor>,
}

impl LocalDatabase {
    /// Reads one bounded active catalogue page for an authenticated remote storage tenant.
    ///
    /// Reclaimed and logically retired shards are excluded. Every row is cross-checked against
    /// its allocation tenant and decoded fail closed before it can reach a signed response.
    ///
    /// # Errors
    ///
    /// Rejects malformed identities/cursors/bounds, contradictory persisted ownership or SQLite
    /// failure.
    pub fn federated_storage_inventory_page(
        &self,
        remote_mesh_id: MeshId,
        grant_id: FederationGrantId,
        target_id: TargetId,
        target_generation: u64,
        after: Option<FederationStorageInventoryCursor>,
        limit: usize,
    ) -> Result<FederationStorageInventoryPage, FederationStorageInventoryError> {
        page(
            self,
            remote_mesh_id,
            grant_id,
            target_id,
            target_generation,
            after,
            limit,
        )
    }
}

fn page(
    database: &LocalDatabase,
    remote_mesh_id: MeshId,
    grant_id: FederationGrantId,
    target_id: TargetId,
    target_generation: u64,
    after: Option<FederationStorageInventoryCursor>,
    limit: usize,
) -> Result<FederationStorageInventoryPage, FederationStorageInventoryError> {
    validate_query(target_generation, after, limit)?;
    let query_limit = limit
        .checked_add(1)
        .and_then(|value| i64::try_from(value).ok())
        .ok_or(FederationStorageInventoryError::InvalidQuery)?;
    let cursor_values = cursor_values(after)?;
    let mut statement = database.connection().prepare(
        "SELECT shard.scope_digest, shard.allocation_id, shard.manifest_digest,
                shard.stripe_index, shard.shard_index, shard.shard_generation,
                shard.length, shard.content_digest, shard.committed_at,
                usage.remote_mesh_id, usage.grant_id, usage.target_id,
                usage.target_generation
         FROM local_federation_storage_shards AS shard
         JOIN local_federation_storage_usage AS usage
           ON usage.allocation_id = shard.allocation_id
         WHERE shard.remote_mesh_id = ?1 AND shard.grant_id = ?2
           AND shard.target_id = ?3 AND shard.target_generation = ?4
           AND (?5 = 0 OR (
               shard.scope_digest, shard.manifest_digest, shard.stripe_index,
               shard.shard_index, shard.shard_generation
           ) > (?6, ?7, ?8, ?9, ?10))
           AND NOT EXISTS(
               SELECT 1 FROM local_federation_storage_lifecycle AS lifecycle
               WHERE lifecycle.remote_mesh_id = shard.remote_mesh_id
                 AND lifecycle.scope_digest = shard.scope_digest
                 AND lifecycle.target_id = shard.target_id
                 AND lifecycle.target_generation = shard.target_generation
                 AND lifecycle.manifest_digest = shard.manifest_digest
                 AND lifecycle.stripe_index = shard.stripe_index
                 AND lifecycle.shard_index = shard.shard_index
                 AND lifecycle.shard_generation = shard.shard_generation
           )
         ORDER BY shard.scope_digest, shard.manifest_digest, shard.stripe_index,
                  shard.shard_index, shard.shard_generation
         LIMIT ?11",
    )?;
    let rows = statement.query_map(
        params![
            remote_mesh_id.as_bytes().as_slice(),
            grant_id.as_bytes().as_slice(),
            target_id.as_bytes().as_slice(),
            to_i64(target_generation)?,
            i64::from(after.is_some()),
            cursor_values[0].clone(),
            cursor_values[1].clone(),
            cursor_values[2].clone(),
            cursor_values[3].clone(),
            cursor_values[4].clone(),
            query_limit,
        ],
        decode_row,
    )?;
    let mut decoded = Vec::with_capacity(limit.saturating_add(1));
    for row in rows {
        let row = row?;
        decoded.push(validate_row(
            &row,
            remote_mesh_id,
            grant_id,
            target_id,
            target_generation,
        )?);
    }
    let has_more = decoded.len() > limit;
    if has_more {
        decoded.pop();
    }
    let next_cursor = if has_more {
        decoded.last().copied().map(cursor_for)
    } else {
        None
    };
    Ok(FederationStorageInventoryPage {
        records: BoundedItems::new(decoded, limit)
            .map_err(|_| FederationStorageInventoryError::CorruptState)?,
        next_cursor,
    })
}

fn validate_query(
    target_generation: u64,
    after: Option<FederationStorageInventoryCursor>,
    limit: usize,
) -> Result<(), FederationStorageInventoryError> {
    let valid_cursor = after.is_none_or(|cursor| {
        cursor.scope_digest != [0; 32]
            && cursor.shard.manifest_digest != [0; 32]
            && cursor.shard.generation > 0
            && i64::try_from(cursor.shard.stripe_index).is_ok()
    });
    if target_generation > 0
        && (1..=MAXIMUM_FEDERATED_STORAGE_INVENTORY_ITEMS).contains(&limit)
        && valid_cursor
    {
        Ok(())
    } else {
        Err(FederationStorageInventoryError::InvalidQuery)
    }
}

fn cursor_values(
    after: Option<FederationStorageInventoryCursor>,
) -> Result<[Value; 5], FederationStorageInventoryError> {
    let Some(cursor) = after else {
        return Ok([
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
        ]);
    };
    Ok([
        Value::Blob(cursor.scope_digest.to_vec()),
        Value::Blob(cursor.shard.manifest_digest.to_vec()),
        Value::Integer(to_i64(cursor.shard.stripe_index)?),
        Value::Integer(i64::from(cursor.shard.shard_index)),
        Value::Integer(i64::from(cursor.shard.generation)),
    ])
}

type InventoryRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
);

fn decode_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<InventoryRow> {
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
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
    ))
}

fn validate_row(
    row: &InventoryRow,
    remote_mesh_id: MeshId,
    grant_id: FederationGrantId,
    target_id: TargetId,
    target_generation: u64,
) -> Result<FederatedStorageInventoryRecord, FederationStorageInventoryError> {
    let record = FederatedStorageInventoryRecord {
        scope_digest: exact(&row.0)?,
        allocation_id: FederationStorageAllocationId::from_bytes(exact(&row.1)?)
            .map_err(|_| FederationStorageInventoryError::CorruptState)?,
        shard: ShardIdentity {
            manifest_digest: exact(&row.2)?,
            stripe_index: nonnegative(row.3)?,
            shard_index: u16::try_from(row.4)
                .map_err(|_| FederationStorageInventoryError::CorruptState)?,
            generation: u32::try_from(row.5)
                .map_err(|_| FederationStorageInventoryError::CorruptState)?,
        },
        length: positive(row.6)?,
        digest: exact(&row.7)?,
        committed_at: UnixMicros::new(row.8),
    };
    let allocation_matches = MeshId::from_bytes(exact(&row.9)?)
        .is_ok_and(|value| value == remote_mesh_id)
        && FederationGrantId::from_bytes(exact(&row.10)?).is_ok_and(|value| value == grant_id)
        && TargetId::from_bytes(exact(&row.11)?).is_ok_and(|value| value == target_id)
        && positive(row.12)? == target_generation;
    if allocation_matches && validate_federated_storage_inventory_record(record).is_ok() {
        Ok(record)
    } else {
        Err(FederationStorageInventoryError::CorruptState)
    }
}

const fn cursor_for(record: FederatedStorageInventoryRecord) -> FederationStorageInventoryCursor {
    FederationStorageInventoryCursor {
        scope_digest: record.scope_digest,
        shard: record.shard,
    }
}

fn exact<const LENGTH: usize>(
    value: &[u8],
) -> Result<[u8; LENGTH], FederationStorageInventoryError> {
    value
        .try_into()
        .map_err(|_| FederationStorageInventoryError::CorruptState)
}

fn positive(value: i64) -> Result<u64, FederationStorageInventoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(FederationStorageInventoryError::CorruptState)
}

fn nonnegative(value: i64) -> Result<u64, FederationStorageInventoryError> {
    u64::try_from(value).map_err(|_| FederationStorageInventoryError::CorruptState)
}

fn to_i64(value: u64) -> Result<i64, FederationStorageInventoryError> {
    i64::try_from(value).map_err(|_| FederationStorageInventoryError::InvalidQuery)
}

/// Stable failures for bounded provider catalogue reads.
#[derive(Debug, Error)]
pub enum FederationStorageInventoryError {
    /// Query identity, cursor or page bound is invalid.
    #[error("federated storage inventory query is invalid")]
    InvalidQuery,
    /// Persisted tenant, allocation or shard evidence is contradictory.
    #[error("federated storage inventory state is corrupt")]
    CorruptState,
    /// SQLite could not complete the bounded read.
    #[error("federated storage inventory database read failed")]
    Database(#[from] rusqlite::Error),
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{FederationGrantId, MeshId, NodeId, TargetId, UnixMicros};
    use rusqlite::params;
    use tempfile::tempdir;

    use super::{
        FederationStorageInventoryError, LocalDatabase, MAXIMUM_FEDERATED_STORAGE_INVENTORY_ITEMS,
    };

    #[test]
    fn pages_are_bounded_stable_and_fail_closed_on_tenant_corruption()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let mut database = LocalDatabase::open(
            &directory.path().join("local.sqlite3"),
            NodeId::from_bytes([5; 16])?,
            UnixMicros::new(1),
        )?;
        seed_usage(&database)?;
        for seed in 1..=3 {
            seed_shard(&database, seed)?;
        }
        let mut after = None;
        let mut manifests = Vec::new();
        loop {
            let page = database.federated_storage_inventory_page(
                MeshId::from_bytes([3; 16])?,
                FederationGrantId::from_bytes([4; 16])?,
                TargetId::from_bytes([6; 16])?,
                7,
                after,
                1,
            )?;
            manifests.extend(
                page.records
                    .as_slice()
                    .iter()
                    .map(|record| record.shard.manifest_digest),
            );
            let Some(cursor) = page.next_cursor else {
                break;
            };
            after = Some(cursor);
        }
        assert_eq!(manifests, vec![[51; 32], [52; 32], [53; 32]]);
        assert!(matches!(
            database.federated_storage_inventory_page(
                MeshId::from_bytes([3; 16])?,
                FederationGrantId::from_bytes([4; 16])?,
                TargetId::from_bytes([6; 16])?,
                7,
                None,
                MAXIMUM_FEDERATED_STORAGE_INVENTORY_ITEMS + 1,
            ),
            Err(FederationStorageInventoryError::InvalidQuery)
        ));
        database.connection_mut().execute(
            "UPDATE local_federation_storage_usage SET remote_mesh_id = ?1
             WHERE allocation_id = ?2",
            params![[9_u8; 16].as_slice(), [1_u8; 16].as_slice()],
        )?;
        assert!(matches!(
            database.federated_storage_inventory_page(
                MeshId::from_bytes([3; 16])?,
                FederationGrantId::from_bytes([4; 16])?,
                TargetId::from_bytes([6; 16])?,
                7,
                None,
                1,
            ),
            Err(FederationStorageInventoryError::CorruptState)
        ));
        Ok(())
    }

    fn seed_usage(database: &LocalDatabase) -> rusqlite::Result<()> {
        database.connection().execute(
            "INSERT INTO local_federation_storage_usage(
                allocation_id, relationship_id, remote_mesh_id, grant_id, provider_node_id,
                target_id, target_generation, maximum_bytes, committed_bytes, reserved_bytes,
                valid_from, valid_until, relationship_authority_epoch, grant_revision,
                allocation_revision, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 7, 100, 30, 0, 1, 100, 1, 1, 1, 10)",
            params![
                [1_u8; 16].as_slice(),
                [2_u8; 16].as_slice(),
                [3_u8; 16].as_slice(),
                [4_u8; 16].as_slice(),
                [5_u8; 16].as_slice(),
                [6_u8; 16].as_slice(),
            ],
        )?;
        Ok(())
    }

    fn seed_shard(database: &LocalDatabase, seed: u8) -> rusqlite::Result<()> {
        let operation = [10_u8.saturating_add(seed); 16];
        let scope = [20_u8.saturating_add(seed); 32];
        let manifest = [50_u8.saturating_add(seed); 32];
        let content = [70_u8.saturating_add(seed); 32];
        database.connection().execute(
            "INSERT INTO local_federation_storage_reservations(
                operation_id, allocation_id, remote_mesh_id, scope_digest, request_digest,
                capability_nonce, manifest_digest, stripe_index, shard_index, shard_generation,
                action, maximum_bytes, permit_digest, expires_at, state, affected_bytes,
                charged_bytes, content_digest, result_digest, absence_evidence_digest, issued_at,
                completed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, 1, 1, 10, ?9, 50, 2,
                       10, 10, ?10, ?11, NULL, 10, 11)",
            params![
                operation.as_slice(),
                [1_u8; 16].as_slice(),
                [3_u8; 16].as_slice(),
                scope.as_slice(),
                [30_u8.saturating_add(seed); 32].as_slice(),
                [40_u8.saturating_add(seed); 32].as_slice(),
                manifest.as_slice(),
                i64::from(seed),
                [60_u8.saturating_add(seed); 32].as_slice(),
                content.as_slice(),
                [80_u8.saturating_add(seed); 32].as_slice(),
            ],
        )?;
        database.connection().execute(
            "INSERT INTO local_federation_storage_shards(
                grant_id, remote_mesh_id, scope_digest, target_id, target_generation,
                manifest_digest, stripe_index, shard_index, shard_generation, allocation_id,
                length, content_digest, committed_operation_id, committed_at
             ) VALUES (?1, ?2, ?3, ?4, 7, ?5, 1, ?6, 1, ?7, 10, ?8, ?9, ?10)",
            params![
                [4_u8; 16].as_slice(),
                [3_u8; 16].as_slice(),
                scope.as_slice(),
                [6_u8; 16].as_slice(),
                manifest.as_slice(),
                i64::from(seed),
                [1_u8; 16].as_slice(),
                content.as_slice(),
                operation.as_slice(),
                11_i64 + i64::from(seed),
            ],
        )?;
        Ok(())
    }
}
