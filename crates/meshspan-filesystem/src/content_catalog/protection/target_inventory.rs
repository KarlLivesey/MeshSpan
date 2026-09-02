// SPDX-License-Identifier: GPL-2.0-only

//! Bounded enumeration of current protected-shard routes for drain and reconciliation.

use meshspan_contracts::{BoundedItems, ShardIdentity};
use meshspan_domain::{OperationId, TargetId};
use rusqlite::params;

use super::{ShardRepairCandidate, repair};
use crate::content_catalog::repository::{copy_array, from_sql};
use crate::content_catalog::{ContentCatalogError, MAXIMUM_PAGE_ITEMS};

/// Stable keyset position within the complete current protected-shard route catalogue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetShardCursor {
    /// Publication whose immutable manifest owns the route.
    pub publication_operation_id: OperationId,
    /// Logical stripe within the publication.
    pub stripe_index: u64,
    /// Shard position within the stripe.
    pub shard_index: u16,
}

/// One current route on the selected target, with the exact repair identity it implies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetShardRoute {
    /// Stable catalogue position used for bounded continuation.
    pub cursor: TargetShardCursor,
    /// Manifest-validated current route and compare-and-swap generation.
    pub candidate: ShardRepairCandidate,
}

/// One bounded page of current routes on an exact target generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetShardPage {
    /// Routes in stable publication, stripe and shard order.
    pub routes: BoundedItems<TargetShardRoute>,
    /// Last returned route when another page exists.
    pub next: Option<TargetShardCursor>,
}

pub(super) fn page(
    connection: &rusqlite::Connection,
    target_id: TargetId,
    target_generation: u64,
    after: Option<TargetShardCursor>,
    limit: usize,
) -> Result<TargetShardPage, ContentCatalogError> {
    if target_generation == 0 || limit == 0 || limit > MAXIMUM_PAGE_ITEMS {
        return Err(ContentCatalogError::InvalidInput);
    }
    let after_operation = after.map(|cursor| cursor.publication_operation_id.as_bytes().to_vec());
    let after_stripe = after.map_or(0, |cursor| cursor.stripe_index);
    let after_shard = after.map_or(0, |cursor| cursor.shard_index);
    let mut statement = connection.prepare(
        "WITH current_target_routes AS (
            SELECT publication.operation_id, publication.root_digest,
                   route.chunk_index, route.shard_index, route.shard_generation
            FROM content_shard_repair_routes route
            JOIN content_publications publication
              ON publication.operation_id = route.publication_operation_id
            WHERE route.target_id = ?1 AND route.target_generation = ?2
              AND publication.state = 2 AND publication.root_digest IS NOT NULL
            UNION ALL
            SELECT publication.operation_id, publication.root_digest,
                   shard.chunk_index, shard.shard_index, shard.shard_generation
            FROM content_stripe_shards shard
            JOIN content_publications publication ON publication.operation_id = shard.operation_id
            WHERE shard.target_id = ?1 AND shard.target_generation = ?2
              AND shard.receipt_recorded_at IS NOT NULL
              AND publication.state = 2 AND publication.root_digest IS NOT NULL
              AND NOT EXISTS(
                  SELECT 1 FROM content_shard_repair_routes replacement
                  WHERE replacement.publication_operation_id = shard.operation_id
                    AND replacement.chunk_index = shard.chunk_index
                    AND replacement.shard_index = shard.shard_index
              )
        )
        SELECT operation_id, root_digest, chunk_index, shard_index, shard_generation
        FROM current_target_routes
        WHERE ?3 IS NULL OR operation_id > ?3
           OR (operation_id = ?3 AND chunk_index > ?4)
           OR (operation_id = ?3 AND chunk_index = ?4 AND shard_index > ?5)
        ORDER BY operation_id, chunk_index, shard_index LIMIT ?6",
    )?;
    let rows = statement.query_map(
        params![
            target_id.as_bytes().as_slice(),
            i64::try_from(target_generation).map_err(|_| ContentCatalogError::InvalidInput)?,
            after_operation,
            i64::try_from(after_stripe).map_err(|_| ContentCatalogError::InvalidInput)?,
            i64::from(after_shard),
            i64::try_from(limit.saturating_add(1))
                .map_err(|_| ContentCatalogError::InvalidInput)?,
        ],
        |row| {
            let operation_id = OperationId::from_bytes(copy_array(&row.get::<_, Vec<u8>>(0)?)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            let stripe_index = from_sql(row.get(2)?)?;
            let shard_index =
                u16::try_from(row.get::<_, i64>(3)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
            let shard_generation = u32::try_from(row.get::<_, i64>(4)?)
                .ok()
                .filter(|generation| *generation > 0)
                .ok_or(rusqlite::Error::InvalidQuery)?;
            Ok((
                TargetShardCursor {
                    publication_operation_id: operation_id,
                    stripe_index,
                    shard_index,
                },
                ShardIdentity {
                    manifest_digest: copy_array(&row.get::<_, Vec<u8>>(1)?)?,
                    stripe_index,
                    shard_index,
                    generation: shard_generation,
                },
            ))
        },
    )?;
    let mut identities = rows.collect::<Result<Vec<_>, _>>()?;
    let has_more = identities.len() > limit;
    if has_more {
        identities.pop();
    }
    let routes = identities
        .into_iter()
        .map(|(cursor, shard)| {
            let candidate = repair::candidate(connection, target_id, target_generation, shard)?
                .ok_or(ContentCatalogError::Corrupt)?;
            Ok(TargetShardRoute { cursor, candidate })
        })
        .collect::<Result<Vec<_>, ContentCatalogError>>()?;
    let next = if has_more {
        routes.last().map(|route| route.cursor)
    } else {
        None
    };
    Ok(TargetShardPage {
        routes: BoundedItems::new(routes, limit).map_err(|_| ContentCatalogError::Corrupt)?,
        next,
    })
}
