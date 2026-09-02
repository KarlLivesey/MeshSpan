// SPDX-License-Identifier: GPL-2.0-only

//! Bounded enumeration of complete protected stripes for one logical volume.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{ContentManifestId, OperationId, VolumeId};
use rusqlite::params;

use super::CommittedProtectedStripe;
use crate::content_catalog::repository::{copy_array, from_sql, load_request};
use crate::{ContentCatalogError, DurableContentCatalog, PublishedContentReference};

const MAXIMUM_PAGE_ITEMS: usize = 1_000;

/// Stable keyset position in a volume's committed protected-stripe catalogue.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VolumeStripeCursor {
    /// Publication owning the immutable protected stripe.
    pub publication_operation_id: OperationId,
    /// Zero-based stripe index inside that publication.
    pub stripe_index: u64,
}

/// One independently validated complete protected stripe selected for policy re-evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeStripeRecord {
    /// Stable page position and stripe identity.
    pub cursor: VolumeStripeCursor,
    /// Exact validated committed content reference.
    pub content: PublishedContentReference,
    /// Current protected layout and provider receipts.
    pub stripe: CommittedProtectedStripe,
}

/// One bounded page of complete protected stripes in stable catalogue order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeStripePage {
    /// Validated stripes in publication then stripe order.
    pub stripes: BoundedItems<VolumeStripeRecord>,
    /// Last returned position when another page exists.
    pub next: Option<VolumeStripeCursor>,
}

pub(super) fn page(
    catalogue: &DurableContentCatalog,
    volume_id: VolumeId,
    after: Option<VolumeStripeCursor>,
    limit: usize,
) -> Result<VolumeStripePage, ContentCatalogError> {
    if limit == 0 || limit > MAXIMUM_PAGE_ITEMS {
        return Err(ContentCatalogError::InvalidInput);
    }
    let after_operation = after.map(|cursor| cursor.publication_operation_id.as_bytes().to_vec());
    let after_stripe = after.map_or(0, |cursor| cursor.stripe_index);
    let mut statement = catalogue.connection.prepare(
        "SELECT publication.operation_id, publication.manifest_id, layout.chunk_index
         FROM content_publications publication
         JOIN content_stripe_layouts layout ON layout.operation_id = publication.operation_id
         WHERE publication.volume_id = ?1 AND publication.state = 2
           AND (?2 IS NULL OR publication.operation_id > ?2
                OR (publication.operation_id = ?2 AND layout.chunk_index > ?3))
           AND NOT EXISTS(
               SELECT 1 FROM content_stripe_shards shard
               WHERE shard.operation_id = layout.operation_id
                 AND shard.chunk_index = layout.chunk_index
                 AND shard.receipt_recorded_at IS NULL
           )
         ORDER BY publication.operation_id, layout.chunk_index LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            volume_id.as_bytes().as_slice(),
            after_operation,
            i64::try_from(after_stripe).map_err(|_| ContentCatalogError::InvalidInput)?,
            i64::try_from(limit.saturating_add(1))
                .map_err(|_| ContentCatalogError::InvalidInput)?,
        ],
        |row| {
            Ok((
                OperationId::from_bytes(copy_array(&row.get::<_, Vec<u8>>(0)?)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                ContentManifestId::from_bytes(copy_array(&row.get::<_, Vec<u8>>(1)?)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                from_sql(row.get::<_, i64>(2)?)?,
            ))
        },
    )?;
    let mut identities = rows.collect::<Result<Vec<_>, _>>()?;
    let has_more = identities.len() > limit;
    if has_more {
        identities.pop();
    }
    let records = identities
        .into_iter()
        .map(|identity| load_record(catalogue, volume_id, identity))
        .collect::<Result<Vec<_>, _>>()?;
    let next = has_more
        .then(|| records.last().map(|record| record.cursor))
        .flatten();
    Ok(VolumeStripePage {
        stripes: BoundedItems::new(records, limit).map_err(|_| ContentCatalogError::Corrupt)?,
        next,
    })
}

fn load_record(
    catalogue: &DurableContentCatalog,
    volume_id: VolumeId,
    (publication_operation_id, manifest_id, stripe_index): (OperationId, ContentManifestId, u64),
) -> Result<VolumeStripeRecord, ContentCatalogError> {
    let request = load_request(&catalogue.connection, publication_operation_id)?
        .ok_or(ContentCatalogError::Corrupt)?;
    if request.volume_id != volume_id || request.manifest_id != manifest_id {
        return Err(ContentCatalogError::Corrupt);
    }
    let content = catalogue
        .committed_content_by_manifest(manifest_id)?
        .filter(|content| content.publication_operation_id == publication_operation_id)
        .ok_or(ContentCatalogError::Corrupt)?;
    let stripe = catalogue.committed_protected_stripe(content, stripe_index)?;
    if stripe.receipts.len() != usize::from(stripe.stripe.coding_layout().total_slices()) {
        return Err(ContentCatalogError::Corrupt);
    }
    Ok(VolumeStripeRecord {
        cursor: VolumeStripeCursor {
            publication_operation_id,
            stripe_index,
        },
        content,
        stripe,
    })
}
