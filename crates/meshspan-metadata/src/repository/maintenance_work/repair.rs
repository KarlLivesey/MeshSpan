// SPDX-License-Identifier: GPL-2.0-only

//! Atomic copy-on-write transitions for repaired shard locations.

use meshspan_contracts::{ShardIdentity, ShardReceipt};
use meshspan_domain::{OperationId, Revision, UnixMicros, WorkId};
use meshspan_work::WorkSubject;
use rusqlite::{OptionalExtension, Transaction, params};

use super::{
    entity, exact, load_job_for_transition, nonnegative, positive, require_live_claim,
    validate_worker,
};
use crate::repository::{EntityReference, RepositoryError};
use crate::{CommandContext, CommitShardRepair};

/// Exact authoritative copy-on-write transition for one repaired shard location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShardRepairEffectRecord {
    /// Committed effect operation linked by work completion.
    pub effect_operation_id: OperationId,
    /// Claimed repair job that authorised this transition.
    pub work_id: WorkId,
    /// Exact prior location receipt.
    pub source_receipt: ShardReceipt,
    /// Exact replacement provider receipt.
    pub replacement_receipt: ShardReceipt,
    /// Compare-and-swap generation before the transition.
    pub source_layout_generation: u64,
    /// Active layout generation after the transition.
    pub replacement_layout_generation: u64,
    /// Authoritative commit instant.
    pub committed_at: UnixMicros,
    /// Authoritative effect revision.
    pub revision: Revision,
}

pub(super) fn commit(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &CommitShardRepair,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_worker(transaction, value.worker_node_id, value.worker_incarnation)?;
    require_live_claim(
        transaction,
        context,
        value.work_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    validate_repair_subject(transaction, value)?;
    let replacement_generation = value
        .source_layout_generation
        .checked_add(1)
        .ok_or(RepositoryError::CapacityExceeded)?;
    ensure_repair_stripe(transaction, value, revision)?;
    validate_active_repair_route(transaction, value)?;
    insert_repair_effect(
        transaction,
        context,
        value,
        replacement_generation,
        revision,
    )?;
    replace_repair_route(transaction, value, replacement_generation, revision)?;
    let changed = transaction.execute(
        "UPDATE maintenance_repair_stripes
         SET current_layout_generation = ?1, revision = ?2
         WHERE manifest_id = ?3 AND stripe_index = ?4 AND current_layout_generation = ?5",
        params![
            super::to_i64(replacement_generation)?,
            super::to_i64(revision.get())?,
            value.manifest_id.as_bytes().as_slice(),
            super::to_i64(value.source_receipt.shard.stripe_index)?,
            super::to_i64(value.source_layout_generation)?,
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(entity(value.work_id))
}

fn validate_repair_subject(
    transaction: &Transaction<'_>,
    value: &CommitShardRepair,
) -> Result<(), RepositoryError> {
    let subject = load_job_for_transition(transaction, value.work_id)?.subject;
    let WorkSubject::Repair {
        volume_id,
        manifest_id,
        stripe_index,
        shard_index,
        source_generation,
    } = subject
    else {
        return Err(RepositoryError::InvalidCommand);
    };
    let source = value.source_receipt;
    let replacement = value.replacement_receipt;
    let same_immutable_shard = source.shard == replacement.shard
        && source.length == replacement.length
        && source.digest == replacement.digest;
    if value.volume_id != volume_id
        || value.manifest_id != manifest_id
        || source_generation != value.source_layout_generation
        || source.shard.stripe_index != stripe_index
        || source.shard.shard_index != shard_index
        || source.operation_id == replacement.operation_id
        || (source.target_id == replacement.target_id
            && source.target_generation == replacement.target_generation)
        || !valid_receipt(source)
        || !valid_receipt(replacement)
        || !same_immutable_shard
        || !super::entity_exists(
            transaction,
            "volumes",
            "volume_id",
            value.volume_id.as_bytes(),
            Some("state = 1"),
        )?
        || !target_generation_exists(transaction, source.target_id, source.target_generation)?
    {
        return Err(RepositoryError::InvalidCommand);
    }
    if active_target_generation_exists(
        transaction,
        replacement.target_id,
        replacement.target_generation,
    )? {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn ensure_repair_stripe(
    transaction: &Transaction<'_>,
    value: &CommitShardRepair,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let stripe = transaction
        .query_row(
            "SELECT volume_id, manifest_digest, current_layout_generation
             FROM maintenance_repair_stripes WHERE manifest_id = ?1 AND stripe_index = ?2",
            params![
                value.manifest_id.as_bytes().as_slice(),
                super::to_i64(value.source_receipt.shard.stripe_index)?,
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    if let Some((volume_id, manifest_digest, generation)) = stripe {
        if exact::<16>(volume_id)? != value.volume_id.as_bytes()
            || exact::<32>(manifest_digest)? != value.source_receipt.shard.manifest_digest
            || positive(generation)? != value.source_layout_generation
        {
            return Err(RepositoryError::InvalidCommand);
        }
        return Ok(());
    }
    if value.source_layout_generation != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO maintenance_repair_stripes(
            manifest_id, stripe_index, volume_id, manifest_digest, current_layout_generation,
            revision
         ) VALUES (?1, ?2, ?3, ?4, 1, ?5)",
        params![
            value.manifest_id.as_bytes().as_slice(),
            super::to_i64(value.source_receipt.shard.stripe_index)?,
            value.volume_id.as_bytes().as_slice(),
            value.source_receipt.shard.manifest_digest.as_slice(),
            super::to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn validate_active_repair_route(
    transaction: &Transaction<'_>,
    value: &CommitShardRepair,
) -> Result<(), RepositoryError> {
    let route = transaction
        .query_row(
            "SELECT provider_operation_id, shard_generation, expected_length, expected_digest,
                    target_id, target_generation
             FROM maintenance_repair_routes
             WHERE manifest_id = ?1 AND stripe_index = ?2 AND shard_index = ?3",
            params![
                value.manifest_id.as_bytes().as_slice(),
                super::to_i64(value.source_receipt.shard.stripe_index)?,
                i64::from(value.source_receipt.shard.shard_index),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    let Some(route) = route else {
        return Ok(());
    };
    let source = value.source_receipt;
    if exact::<16>(route.0)? == source.operation_id.as_bytes()
        && u32::try_from(positive(route.1)?).ok() == Some(source.shard.generation)
        && nonnegative(route.2)? == source.length
        && exact::<32>(route.3)? == source.digest
        && exact::<16>(route.4)? == source.target_id.as_bytes()
        && positive(route.5)? == source.target_generation
    {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn insert_repair_effect(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &CommitShardRepair,
    replacement_generation: u64,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let source = value.source_receipt;
    let replacement = value.replacement_receipt;
    if transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM maintenance_repair_effects WHERE work_id = ?1)",
        [value.work_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )? != 0
    {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO maintenance_repair_effects(
            effect_operation_id, work_id, claim_generation, worker_node_id, worker_incarnation,
            fence, volume_id, manifest_id, manifest_digest, stripe_index, shard_index,
            shard_generation, source_layout_generation, replacement_layout_generation,
            source_provider_operation_id, source_target_id, source_target_generation,
            replacement_provider_operation_id, replacement_target_id,
            replacement_target_generation, expected_length, expected_digest, committed_at,
            revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                   ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
        params![
            context.operation_id.as_bytes().as_slice(),
            value.work_id.as_bytes().as_slice(),
            super::to_i64(value.claim_generation)?,
            value.worker_node_id.as_bytes().as_slice(),
            super::to_i64(value.worker_incarnation)?,
            super::to_i64(value.fence)?,
            value.volume_id.as_bytes().as_slice(),
            value.manifest_id.as_bytes().as_slice(),
            source.shard.manifest_digest.as_slice(),
            super::to_i64(source.shard.stripe_index)?,
            i64::from(source.shard.shard_index),
            i64::from(source.shard.generation),
            super::to_i64(value.source_layout_generation)?,
            super::to_i64(replacement_generation)?,
            source.operation_id.as_bytes().as_slice(),
            source.target_id.as_bytes().as_slice(),
            super::to_i64(source.target_generation)?,
            replacement.operation_id.as_bytes().as_slice(),
            replacement.target_id.as_bytes().as_slice(),
            super::to_i64(replacement.target_generation)?,
            super::to_i64(source.length)?,
            source.digest.as_slice(),
            context.occurred_at.get(),
            super::to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn replace_repair_route(
    transaction: &Transaction<'_>,
    value: &CommitShardRepair,
    replacement_generation: u64,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let receipt = value.replacement_receipt;
    transaction.execute(
        "INSERT INTO maintenance_repair_routes(
            manifest_id, stripe_index, shard_index, provider_operation_id, shard_generation,
            expected_length, expected_digest, target_id, target_generation, layout_generation,
            revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(manifest_id, stripe_index, shard_index) DO UPDATE SET
            provider_operation_id = excluded.provider_operation_id,
            shard_generation = excluded.shard_generation,
            expected_length = excluded.expected_length,
            expected_digest = excluded.expected_digest,
            target_id = excluded.target_id,
            target_generation = excluded.target_generation,
            layout_generation = excluded.layout_generation,
            revision = excluded.revision",
        params![
            value.manifest_id.as_bytes().as_slice(),
            super::to_i64(receipt.shard.stripe_index)?,
            i64::from(receipt.shard.shard_index),
            receipt.operation_id.as_bytes().as_slice(),
            i64::from(receipt.shard.generation),
            super::to_i64(receipt.length)?,
            receipt.digest.as_slice(),
            receipt.target_id.as_bytes().as_slice(),
            super::to_i64(receipt.target_generation)?,
            super::to_i64(replacement_generation)?,
            super::to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn target_generation_exists(
    transaction: &Transaction<'_>,
    target_id: meshspan_domain::TargetId,
    generation: u64,
) -> Result<bool, RepositoryError> {
    Ok(transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM target_generations
         WHERE target_id = ?1 AND generation = ?2)",
        params![target_id.as_bytes().as_slice(), super::to_i64(generation)?],
        |row| row.get::<_, i64>(0),
    )? == 1)
}

fn active_target_generation_exists(
    transaction: &Transaction<'_>,
    target_id: meshspan_domain::TargetId,
    generation: u64,
) -> Result<bool, RepositoryError> {
    Ok(transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM storage_targets st
            JOIN target_generations tg
              ON tg.target_id = st.target_id AND tg.generation = st.current_generation
            JOIN nodes n ON n.node_id = st.node_id
            JOIN hosts h ON h.host_id = st.host_id
            WHERE st.target_id = ?1 AND st.current_generation = ?2
              AND st.state = 1 AND st.draining_at IS NULL AND st.retired_at IS NULL
              AND tg.state = 1 AND tg.retired_at IS NULL
              AND n.state = 2 AND n.retired_at IS NULL
              AND h.state = 1 AND h.retired_at IS NULL
              AND NOT EXISTS(
                SELECT 1 FROM storage_scope_drains d
                WHERE (
                    (d.scope_kind = 1 AND d.scope_id = st.node_id)
                    OR (d.scope_kind = 2 AND EXISTS(
                        SELECT 1 FROM host_fault_group_memberships hfg
                        WHERE hfg.host_id = st.host_id AND hfg.group_id = d.scope_id)))
         ))",
        params![target_id.as_bytes().as_slice(), super::to_i64(generation)?],
        |row| row.get::<_, i64>(0),
    )? == 1)
}

fn valid_receipt(receipt: ShardReceipt) -> bool {
    receipt.shard.manifest_digest != [0; 32]
        && receipt.shard.generation > 0
        && receipt.length > 0
        && receipt.digest != [0; 32]
        && receipt.target_generation > 0
        && i64::try_from(receipt.shard.stripe_index).is_ok()
        && i64::try_from(receipt.length).is_ok()
        && i64::try_from(receipt.target_generation).is_ok()
}

pub(super) fn load(
    connection: &rusqlite::Connection,
    effect_operation_id: OperationId,
) -> Result<Option<ShardRepairEffectRecord>, RepositoryError> {
    connection
        .query_row(
            "SELECT work_id, manifest_digest, stripe_index, shard_index, shard_generation,
                    source_layout_generation, replacement_layout_generation,
                    source_provider_operation_id, source_target_id, source_target_generation,
                    replacement_provider_operation_id, replacement_target_id,
                    replacement_target_generation, expected_length, expected_digest,
                    committed_at, revision
             FROM maintenance_repair_effects WHERE effect_operation_id = ?1",
            [effect_operation_id.as_bytes().as_slice()],
            |row| {
                let shard = ShardIdentity {
                    manifest_digest: exact_sql(row.get(1)?)?,
                    stripe_index: positive_or_zero_sql(row.get(2)?)?,
                    shard_index: u16::try_from(row.get::<_, i64>(3)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    generation: u32::try_from(positive_sql(row.get(4)?)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                };
                let length = positive_sql(row.get(13)?)?;
                let digest = exact_sql(row.get(14)?)?;
                Ok(ShardRepairEffectRecord {
                    effect_operation_id,
                    work_id: WorkId::from_bytes(exact_sql(row.get(0)?)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    source_receipt: ShardReceipt {
                        operation_id: OperationId::from_bytes(exact_sql(row.get(7)?)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        shard,
                        length,
                        digest,
                        target_id: meshspan_domain::TargetId::from_bytes(exact_sql(row.get(8)?)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        target_generation: positive_sql(row.get(9)?)?,
                    },
                    replacement_receipt: ShardReceipt {
                        operation_id: OperationId::from_bytes(exact_sql(row.get(10)?)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        shard,
                        length,
                        digest,
                        target_id: meshspan_domain::TargetId::from_bytes(exact_sql(row.get(11)?)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        target_generation: positive_sql(row.get(12)?)?,
                    },
                    source_layout_generation: positive_sql(row.get(5)?)?,
                    replacement_layout_generation: positive_sql(row.get(6)?)?,
                    committed_at: UnixMicros::new(row.get(15)?),
                    revision: Revision::new(positive_sql(row.get(16)?)?),
                })
            },
        )
        .optional()
        .map_err(RepositoryError::from)
}

fn exact_sql<const LENGTH: usize>(value: Vec<u8>) -> rusqlite::Result<[u8; LENGTH]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn positive_sql(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(rusqlite::Error::InvalidQuery)
}

fn positive_or_zero_sql(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}
