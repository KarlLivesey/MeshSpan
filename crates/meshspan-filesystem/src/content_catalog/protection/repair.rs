// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe projection of authoritative shard-repair route transitions.

use meshspan_contracts::ShardReceipt;
use meshspan_domain::{OperationId, Revision};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use super::{PreparedProtectedShard, load_protected_stripe};
use crate::content_catalog::repository::{copy_array, decode_target, from_sql, to_i64};
use crate::{ContentCatalogError, ContentPublicationRequest, PublishedContentReference};

/// One authoritative copy-on-write location transition ready for local projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardRepairTransition {
    /// Authoritative effect operation used for exact replay.
    pub effect_operation_id: OperationId,
    /// Compare-and-swap generation before the transition.
    pub source_layout_generation: u64,
    /// Active generation after the transition.
    pub replacement_layout_generation: u64,
    /// Exact location replaced by this effect.
    pub source_receipt: ShardReceipt,
    /// Exact durable replacement for the same immutable shard bytes.
    pub replacement_receipt: ShardReceipt,
    /// Authoritative metadata revision which committed the effect.
    pub committed_revision: Revision,
}

pub(super) fn install(
    connection: &mut rusqlite::Connection,
    request: ContentPublicationRequest,
    content: PublishedContentReference,
    transition: &ShardRepairTransition,
) -> Result<(), ContentCatalogError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(stored) = load_effect(&transaction, transition.effect_operation_id)? {
        return if stored == *transition {
            Ok(())
        } else {
            Err(ContentCatalogError::Conflict)
        };
    }
    let source = transition.source_receipt;
    let stripe = load_protected_stripe(&transaction, request, source.shard.stripe_index)?;
    let planned = stripe
        .shards()
        .get(usize::from(source.shard.shard_index))
        .copied()
        .ok_or(ContentCatalogError::InvalidInput)?;
    let original = original_receipt(&transaction, content, source.shard.stripe_index, planned)?;
    let (active, active_generation) =
        active_receipt(&transaction, content.publication_operation_id, original)?
            .unwrap_or((original, 1));
    validate_transition(
        content,
        transition,
        stripe.chunk().chunk_index,
        planned,
        active,
        active_generation,
    )?;
    insert_effect(&transaction, content, transition)?;
    replace_route(&transaction, content, transition, active_generation)?;
    transaction.commit()?;
    Ok(())
}

pub(super) fn current_receipt(
    connection: &rusqlite::Connection,
    publication_operation_id: OperationId,
    original: ShardReceipt,
) -> Result<ShardReceipt, ContentCatalogError> {
    active_receipt(connection, publication_operation_id, original)
        .map(|route| route.map_or(original, |value| value.0))
}

fn validate_transition(
    content: PublishedContentReference,
    transition: &ShardRepairTransition,
    chunk_index: u64,
    planned: PreparedProtectedShard,
    active: ShardReceipt,
    active_generation: u64,
) -> Result<(), ContentCatalogError> {
    let source = transition.source_receipt;
    let replacement = transition.replacement_receipt;
    let next = transition
        .source_layout_generation
        .checked_add(1)
        .ok_or(ContentCatalogError::InvalidInput)?;
    if transition.source_layout_generation != active_generation
        || transition.replacement_layout_generation != next
        || source != active
        || source.shard != replacement.shard
        || source.length != replacement.length
        || source.digest != replacement.digest
        || source.operation_id == replacement.operation_id
        || (source.target_id == replacement.target_id
            && source.target_generation == replacement.target_generation)
        || source.shard.manifest_digest != content.manifest.root_digest
        || source.shard.stripe_index != chunk_index
        || source.shard.shard_index != planned.shard_index
        || source.shard.generation != planned.shard_generation
        || source.length != planned.expected_length
        || source.digest != planned.expected_digest
        || replacement.target_generation == 0
    {
        Err(ContentCatalogError::InvalidInput)
    } else {
        Ok(())
    }
}

fn original_receipt(
    transaction: &rusqlite::Transaction<'_>,
    content: PublishedContentReference,
    chunk_index: u64,
    shard: PreparedProtectedShard,
) -> Result<ShardReceipt, ContentCatalogError> {
    let recorded = transaction.query_row(
        "SELECT receipt_recorded_at FROM content_stripe_shards
         WHERE operation_id = ?1 AND chunk_index = ?2 AND shard_index = ?3",
        params![
            content.publication_operation_id.as_bytes().as_slice(),
            to_i64(chunk_index)?,
            i64::from(shard.shard_index),
        ],
        |row| row.get::<_, Option<i64>>(0),
    )?;
    if recorded.is_none() {
        return Err(ContentCatalogError::Incomplete);
    }
    Ok(ShardReceipt {
        operation_id: shard.provider_operation_id,
        shard: meshspan_contracts::ShardIdentity {
            manifest_digest: content.manifest.root_digest,
            stripe_index: chunk_index,
            shard_index: shard.shard_index,
            generation: shard.shard_generation,
        },
        length: shard.expected_length,
        digest: shard.expected_digest,
        target_id: shard.target_id,
        target_generation: shard.target_generation,
    })
}

fn active_receipt(
    connection: &rusqlite::Connection,
    publication_operation_id: OperationId,
    original: ShardReceipt,
) -> Result<Option<(ShardReceipt, u64)>, ContentCatalogError> {
    connection
        .query_row(
            "SELECT provider_operation_id, target_id, target_generation, shard_generation,
                    expected_length, expected_digest, layout_generation
             FROM content_shard_repair_routes
             WHERE publication_operation_id = ?1 AND chunk_index = ?2 AND shard_index = ?3",
            params![
                publication_operation_id.as_bytes().as_slice(),
                to_i64(original.shard.stripe_index)?,
                i64::from(original.shard.shard_index),
            ],
            |row| {
                let receipt = ShardReceipt {
                    operation_id: decode_operation(&row.get::<_, Vec<u8>>(0)?)?,
                    shard: meshspan_contracts::ShardIdentity {
                        manifest_digest: original.shard.manifest_digest,
                        stripe_index: original.shard.stripe_index,
                        shard_index: original.shard.shard_index,
                        generation: u32::try_from(row.get::<_, i64>(3)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    },
                    length: from_sql(row.get(4)?)?,
                    digest: copy_array(&row.get::<_, Vec<u8>>(5)?)?,
                    target_id: decode_target(&row.get::<_, Vec<u8>>(1)?)?,
                    target_generation: from_sql(row.get(2)?)?,
                };
                if receipt.shard != original.shard
                    || receipt.length != original.length
                    || receipt.digest != original.digest
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok((receipt, from_sql(row.get(6)?)?))
            },
        )
        .optional()
        .map_err(Into::into)
}

fn insert_effect(
    transaction: &rusqlite::Transaction<'_>,
    content: PublishedContentReference,
    transition: &ShardRepairTransition,
) -> Result<(), ContentCatalogError> {
    let source = transition.source_receipt;
    let replacement = transition.replacement_receipt;
    transaction.execute(
        "INSERT INTO content_shard_repair_effects(
            effect_operation_id, publication_operation_id, chunk_index, shard_index,
            source_layout_generation, replacement_layout_generation,
            source_provider_operation_id, source_target_id, source_target_generation,
            replacement_provider_operation_id, replacement_target_id,
            replacement_target_generation, shard_generation, expected_length, expected_digest,
            committed_revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            transition.effect_operation_id.as_bytes().as_slice(),
            content.publication_operation_id.as_bytes().as_slice(),
            to_i64(source.shard.stripe_index)?,
            i64::from(source.shard.shard_index),
            to_i64(transition.source_layout_generation)?,
            to_i64(transition.replacement_layout_generation)?,
            source.operation_id.as_bytes().as_slice(),
            source.target_id.as_bytes().as_slice(),
            to_i64(source.target_generation)?,
            replacement.operation_id.as_bytes().as_slice(),
            replacement.target_id.as_bytes().as_slice(),
            to_i64(replacement.target_generation)?,
            i64::from(source.shard.generation),
            to_i64(source.length)?,
            source.digest.as_slice(),
            to_i64(transition.committed_revision.get())?,
        ],
    )?;
    Ok(())
}

fn replace_route(
    transaction: &rusqlite::Transaction<'_>,
    content: PublishedContentReference,
    transition: &ShardRepairTransition,
    active_generation: u64,
) -> Result<(), ContentCatalogError> {
    let replacement = transition.replacement_receipt;
    let changed = transaction.execute(
        "INSERT INTO content_shard_repair_routes(
            publication_operation_id, chunk_index, shard_index, provider_operation_id, target_id,
            target_generation, shard_generation, expected_length, expected_digest,
            layout_generation, effect_operation_id, committed_revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(publication_operation_id, chunk_index, shard_index) DO UPDATE SET
            provider_operation_id = excluded.provider_operation_id,
            target_id = excluded.target_id,
            target_generation = excluded.target_generation,
            shard_generation = excluded.shard_generation,
            expected_length = excluded.expected_length,
            expected_digest = excluded.expected_digest,
            layout_generation = excluded.layout_generation,
            effect_operation_id = excluded.effect_operation_id,
            committed_revision = excluded.committed_revision
         WHERE content_shard_repair_routes.layout_generation = ?13",
        params![
            content.publication_operation_id.as_bytes().as_slice(),
            to_i64(replacement.shard.stripe_index)?,
            i64::from(replacement.shard.shard_index),
            replacement.operation_id.as_bytes().as_slice(),
            replacement.target_id.as_bytes().as_slice(),
            to_i64(replacement.target_generation)?,
            i64::from(replacement.shard.generation),
            to_i64(replacement.length)?,
            replacement.digest.as_slice(),
            to_i64(transition.replacement_layout_generation)?,
            transition.effect_operation_id.as_bytes().as_slice(),
            to_i64(transition.committed_revision.get())?,
            to_i64(active_generation)?,
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(ContentCatalogError::Conflict)
    }
}

fn load_effect(
    connection: &rusqlite::Connection,
    effect_operation_id: OperationId,
) -> Result<Option<ShardRepairTransition>, ContentCatalogError> {
    connection
        .query_row(
            "SELECT effects.chunk_index, effects.shard_index,
                    effects.source_layout_generation, effects.replacement_layout_generation,
                    effects.source_provider_operation_id, effects.source_target_id,
                    effects.source_target_generation, effects.replacement_provider_operation_id,
                    effects.replacement_target_id, effects.replacement_target_generation,
                    effects.shard_generation, effects.expected_length, effects.expected_digest,
                    effects.committed_revision,
                    (SELECT root_digest FROM content_publications
                     WHERE operation_id = effects.publication_operation_id)
             FROM content_shard_repair_effects AS effects WHERE effect_operation_id = ?1",
            [effect_operation_id.as_bytes().as_slice()],
            |row| {
                let shard = meshspan_contracts::ShardIdentity {
                    manifest_digest: copy_array(&row.get::<_, Vec<u8>>(14)?)?,
                    stripe_index: from_sql(row.get(0)?)?,
                    shard_index: u16::try_from(row.get::<_, i64>(1)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    generation: u32::try_from(row.get::<_, i64>(10)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                };
                let length = from_sql(row.get(11)?)?;
                let digest = copy_array(&row.get::<_, Vec<u8>>(12)?)?;
                Ok(ShardRepairTransition {
                    effect_operation_id,
                    source_layout_generation: from_sql(row.get(2)?)?,
                    replacement_layout_generation: from_sql(row.get(3)?)?,
                    source_receipt: ShardReceipt {
                        operation_id: decode_operation(&row.get::<_, Vec<u8>>(4)?)?,
                        shard,
                        length,
                        digest,
                        target_id: decode_target(&row.get::<_, Vec<u8>>(5)?)?,
                        target_generation: from_sql(row.get(6)?)?,
                    },
                    replacement_receipt: ShardReceipt {
                        operation_id: decode_operation(&row.get::<_, Vec<u8>>(7)?)?,
                        shard,
                        length,
                        digest,
                        target_id: decode_target(&row.get::<_, Vec<u8>>(8)?)?,
                        target_generation: from_sql(row.get(9)?)?,
                    },
                    committed_revision: Revision::new(from_sql(row.get(13)?)?),
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn decode_operation(bytes: &[u8]) -> rusqlite::Result<OperationId> {
    OperationId::from_bytes(copy_array(bytes)?).map_err(|_| rusqlite::Error::InvalidQuery)
}
