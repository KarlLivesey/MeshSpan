// SPDX-License-Identifier: GPL-2.0-only

//! Manifest-scoped replay of committed repair effects with atomic local progress.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{ContentManifestId, OperationId, PartitionId, Revision, VolumeId};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::repair::{self, ShardRepairTransition};
use crate::content_catalog::repository::{copy_array, from_sql, to_i64};
use crate::{ContentCatalogError, DurableContentCatalog, PublishedContentReference};

/// Exact position in an authority's ordered effect stream for one immutable manifest.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepairProjectionCursor {
    /// Authoritative effect revision; never a wall-clock ordering value.
    pub revision: Revision,
    /// Tie-breaker and exact replay identity at that revision.
    pub effect_operation_id: OperationId,
}

/// One validated, locally committed protected manifest eligible for effect replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairProjectionManifest {
    /// Owning volume used to scope the authoritative feed.
    pub volume_id: VolumeId,
    /// Canonical local content and immutable manifest identity.
    pub content: PublishedContentReference,
}

/// Bounded inventory of committed manifests; incomplete imports enter a later scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairProjectionManifestPage {
    /// Locally committed protected manifests, excluding aliases of another publication.
    pub manifests: BoundedItems<RepairProjectionManifest>,
    /// Last returned publication if another page exists.
    pub next: Option<OperationId>,
}

impl DurableContentCatalog {
    /// Enumerates committed protected manifests in publication order for automatic replay.
    ///
    /// # Errors
    /// Rejects invalid page bounds and contradictory local publication state.
    pub fn repair_projection_manifests(
        &self,
        after: Option<OperationId>,
        limit: usize,
    ) -> Result<RepairProjectionManifestPage, ContentCatalogError> {
        if !(1..=1_000).contains(&limit) {
            return Err(ContentCatalogError::InvalidInput);
        }
        let mut statement = self.connection.prepare(
            "SELECT publication.operation_id, publication.manifest_id, publication.volume_id
             FROM content_publications publication
             WHERE publication.state = 2 AND publication.format_version = 2
               AND (?1 IS NULL OR publication.operation_id > ?1)
               AND NOT EXISTS (SELECT 1 FROM content_reuse reuse
                               WHERE reuse.operation_id = publication.operation_id)
             ORDER BY publication.operation_id LIMIT ?2",
        )?;
        let after = after.map(|operation| operation.as_bytes().to_vec());
        let mut rows = statement
            .query_map(
                params![
                    after,
                    i64::try_from(limit + 1).map_err(|_| ContentCatalogError::InvalidInput)?
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let more = rows.len() > limit;
        rows.truncate(limit);
        let mut manifests = Vec::with_capacity(rows.len());
        for (operation, manifest, volume) in rows {
            let operation = OperationId::from_bytes(copy_array(&operation)?)
                .map_err(|_| ContentCatalogError::Corrupt)?;
            let manifest = ContentManifestId::from_bytes(copy_array(&manifest)?)
                .map_err(|_| ContentCatalogError::Corrupt)?;
            let volume_id = VolumeId::from_bytes(copy_array(&volume)?)
                .map_err(|_| ContentCatalogError::Corrupt)?;
            let content = self
                .committed_content_by_manifest(manifest)?
                .ok_or(ContentCatalogError::Corrupt)?;
            if content.publication_operation_id != operation
                || self.committed_layout(content)?.request.volume_id != volume_id
            {
                return Err(ContentCatalogError::Corrupt);
            }
            manifests.push(RepairProjectionManifest { volume_id, content });
        }
        let next = more
            .then(|| {
                manifests
                    .last()
                    .map(|item| item.content.publication_operation_id)
            })
            .flatten();
        Ok(RepairProjectionManifestPage {
            manifests: BoundedItems::new(manifests, limit)
                .map_err(|_| ContentCatalogError::InvalidInput)?,
            next,
        })
    }

    /// Reads durable replay progress independently of provisional/local repair effects.
    ///
    /// # Errors
    /// Rejects unknown content and corrupt or contradictory cursor/effect records.
    pub fn repair_projection_cursor(
        &self,
        partition: PartitionId,
        content: PublishedContentReference,
    ) -> Result<Option<RepairProjectionCursor>, ContentCatalogError> {
        let content = self.reused_reference(content)?;
        self.committed_layout(content)?;
        load_cursor(
            &self.connection,
            partition,
            content.publication_operation_id,
        )
    }

    /// Atomically installs the next verified authoritative effect and advances its cursor.
    ///
    /// The caller verifies partition/volume authority and obtains the next effect from the
    /// ordered manifest feed after `expected`. Exact retries preserve later cursor progress.
    /// No transaction spans authority or provider IO. A missing manifest must remain pending
    /// at the caller; this operation never manufactures a local publication.
    ///
    /// # Errors
    /// Rejects cursor races, unknown content, stale generations and substituted receipts.
    pub fn project_shard_repair(
        &mut self,
        partition: PartitionId,
        content: PublishedContentReference,
        expected: Option<RepairProjectionCursor>,
        transition: &ShardRepairTransition,
    ) -> Result<(), ContentCatalogError> {
        let content = self.reused_reference(content)?;
        let request = self.committed_layout(content)?.request;
        if request.format_version != 2 || transition.committed_revision == Revision::ZERO {
            return Err(ContentCatalogError::InvalidInput);
        }
        let next = RepairProjectionCursor {
            revision: transition.committed_revision,
            effect_operation_id: transition.effect_operation_id,
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_cursor(&transaction, partition, content.publication_operation_id)?;
        if current.is_some_and(|cursor| cursor >= next) {
            if repair::load_effect(&transaction, transition.effect_operation_id)?
                != Some(*transition)
            {
                return Err(ContentCatalogError::Conflict);
            }
            // An already applied exact effect can be acknowledged after a lost response,
            // even if another worker has since projected later effects for this manifest.
            repair::install_in_transaction(&transaction, request, content, transition)?;
            transaction.commit()?;
            return Ok(());
        }
        if current != expected {
            return Err(ContentCatalogError::Conflict);
        }
        repair::install_in_transaction(&transaction, request, content, transition)?;
        transaction.execute(
            "INSERT INTO content_repair_projection_cursors(
                partition_id, publication_operation_id, revision, effect_operation_id)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(partition_id, publication_operation_id) DO UPDATE SET
                revision = excluded.revision, effect_operation_id = excluded.effect_operation_id",
            params![
                partition.as_bytes().as_slice(),
                content.publication_operation_id.as_bytes().as_slice(),
                to_i64(next.revision.get())?,
                next.effect_operation_id.as_bytes().as_slice()
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

fn load_cursor(
    connection: &rusqlite::Connection,
    partition: PartitionId,
    publication: OperationId,
) -> Result<Option<RepairProjectionCursor>, ContentCatalogError> {
    connection
        .query_row(
            "SELECT cursor.revision, cursor.effect_operation_id,
                effect.publication_operation_id, effect.committed_revision
         FROM content_repair_projection_cursors cursor
         LEFT JOIN content_shard_repair_effects effect
           ON effect.effect_operation_id = cursor.effect_operation_id
         WHERE cursor.partition_id = ?1 AND cursor.publication_operation_id = ?2",
            params![
                partition.as_bytes().as_slice(),
                publication.as_bytes().as_slice()
            ],
            |row| {
                let revision = from_sql(row.get(0)?)?;
                let effect_revision = from_sql(row.get(3)?)?;
                let owner: [u8; 16] = copy_array(&row.get::<_, Vec<u8>>(2)?)?;
                if revision == 0 || revision != effect_revision || owner != publication.as_bytes() {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok(RepairProjectionCursor {
                    revision: Revision::new(revision),
                    effect_operation_id: OperationId::from_bytes(copy_array(
                        &row.get::<_, Vec<u8>>(1)?,
                    )?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}
