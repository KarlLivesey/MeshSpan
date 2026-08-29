// SPDX-License-Identifier: GPL-2.0-only

//! Replicated provider tombstone completions and exact final cleanup summary.

use meshspan_contracts::{TombstoneReceipt, tombstone_receipt_digest};
use meshspan_domain::{NodeId, OperationId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::cleanup_inventory::sealed_item;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, CompleteVersionCleanupItem, PartitionDatabase};

const COMPLETION_DIGEST_DOMAIN: &[u8] = b"meshspan.version-cleanup-completion.v1\0";

/// One independently validated provider tombstone completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupItemCompletion {
    /// Authorised cleanup proposal.
    pub cleanup_operation_id: OperationId,
    /// Stable item position in the sealed inventory.
    pub item_index: u64,
    /// Exact permit attempt accepted by the provider.
    pub permit_attempt_sequence: u64,
    /// Exact durable provider receipt.
    pub receipt: TombstoneReceipt,
    /// Authenticated reporting node.
    pub reporter_node_id: NodeId,
    /// Reporting process incarnation.
    pub reporter_incarnation: u64,
    /// Metadata operation that committed this completion.
    pub completion_operation_id: OperationId,
    /// Authoritative completion instant.
    pub completed_at: UnixMicros,
    /// Replicated completion revision.
    pub revision: Revision,
}

/// Terminal replicated proof that every exact sealed item has a durable tombstone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupCompletion {
    /// Authorised cleanup proposal.
    pub cleanup_operation_id: OperationId,
    /// Exact number of completed sealed items.
    pub completed_item_count: u64,
    /// Ordered digest of every independently validated item completion.
    pub completion_digest: [u8; 32],
    /// Operation that completed the final item and summary atomically.
    pub completion_operation_id: OperationId,
    /// Authoritative completion instant.
    pub completed_at: UnixMicros,
    /// Replicated terminal revision.
    pub revision: Revision,
}

pub(super) fn complete(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: CompleteVersionCleanupItem,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_shape(context, command)?;
    let sealed = sealed_item(
        transaction,
        command.cleanup_operation_id,
        command.item_index,
    )?;
    if command.inventory_sealed_revision != sealed.sealed_revision {
        return Err(RepositoryError::StaleRevision);
    }
    if command.reporter_node_id != sealed.item.storage_node_id {
        return Err(RepositoryError::InvalidCommand);
    }
    if load_item(
        transaction,
        command.cleanup_operation_id,
        command.item_index,
    )?
    .is_some()
    {
        return Err(RepositoryError::OperationConflict);
    }
    let attempt = super::cleanup_permit::exact_attempt(
        transaction,
        command.cleanup_operation_id,
        command.item_index,
        command.permit_attempt_sequence,
    )?;
    validate_receipt(command.receipt, attempt.permit)?;
    validate_reporter(
        transaction,
        command.reporter_node_id,
        command.reporter_incarnation,
    )?;
    insert_item(transaction, context, command, revision)?;
    complete_summary_if_ready(transaction, context, command.cleanup_operation_id, revision)?;
    Ok(EntityReference {
        kind: EntityKind::VersionCleanup,
        id: command.cleanup_operation_id.as_bytes(),
    })
}

pub(super) fn item(
    database: &PartitionDatabase,
    cleanup_operation_id: OperationId,
    item_index: u64,
) -> Result<Option<VersionCleanupItemCompletion>, RepositoryError> {
    sealed_item(database.connection(), cleanup_operation_id, item_index)?;
    load_item(database.connection(), cleanup_operation_id, item_index)
}

pub(super) fn summary(
    database: &PartitionDatabase,
    cleanup_operation_id: OperationId,
) -> Result<Option<VersionCleanupCompletion>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT completed_item_count, completion_digest, completion_operation_id,
                    completed_at, revision
             FROM version_cleanup_completions WHERE cleanup_operation_id = ?1",
            [cleanup_operation_id.as_bytes().as_slice()],
            |row| {
                Ok(VersionCleanupCompletion {
                    cleanup_operation_id,
                    completed_item_count: positive(row.get(0)?)?,
                    completion_digest: array(&row.get::<_, Vec<u8>>(1)?)?,
                    completion_operation_id: operation(&row.get::<_, Vec<u8>>(2)?)?,
                    completed_at: UnixMicros::new(row.get(3)?),
                    revision: revision(row.get(4)?)?,
                })
            },
        )
        .optional()?;
    let Some(completion) = stored else {
        return Ok(None);
    };
    let sealed = sealed_item(database.connection(), cleanup_operation_id, 0)?;
    let expected_count: i64 = database.connection().query_row(
        "SELECT expected_item_count FROM version_cleanup_inventories
         WHERE cleanup_operation_id = ?1 AND state = 2",
        [cleanup_operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    let (count, digest) = ordered_completion_digest(
        database.connection(),
        cleanup_operation_id,
        sealed.sealed_revision,
    )?;
    if completion.completed_item_count != positive(expected_count)?
        || completion.completed_item_count != count
        || completion.completion_digest != digest
        || completion.revision == Revision::ZERO
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(completion))
}

fn validate_shape(
    context: CommandContext,
    command: CompleteVersionCleanupItem,
) -> Result<(), RepositoryError> {
    let receipt = command.receipt;
    if context.expected_revision.is_none()
        || command.inventory_sealed_revision == Revision::ZERO
        || command.permit_attempt_sequence == 0
        || command.reporter_incarnation == 0
        || receipt.permit_digest == [0; 32]
        || receipt.tombstone_digest == [0; 32]
        || context.operation_id == command.cleanup_operation_id
        || context.operation_id == receipt.operation_id
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn validate_receipt(
    receipt: TombstoneReceipt,
    permit: meshspan_contracts::RemovalPermit,
) -> Result<(), RepositoryError> {
    if receipt.operation_id == permit.operation_id
        && receipt.shard == permit.shard
        && receipt.target_id == permit.target_id
        && receipt.target_generation == permit.target_generation
        && receipt.permit_digest == permit.permit_digest
        && receipt.tombstone_digest == tombstone_receipt_digest(permit)
    {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

pub(super) fn validate_reporter(
    transaction: &Transaction<'_>,
    node_id: NodeId,
    incarnation: u64,
) -> Result<(), RepositoryError> {
    let current: Option<i64> = transaction
        .query_row(
            "SELECT current_incarnation FROM nodes
             WHERE node_id = ?1 AND state IN (1, 2)",
            [node_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if current.and_then(|value| u64::try_from(value).ok()) == Some(incarnation) {
        Ok(())
    } else {
        Err(RepositoryError::StaleRevision)
    }
}

fn insert_item(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: CompleteVersionCleanupItem,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let receipt = command.receipt;
    let changed = transaction.execute(
        "INSERT INTO version_cleanup_item_completions(
            cleanup_operation_id, item_index, permit_attempt_sequence,
            provider_operation_id, target_id, target_generation, manifest_digest,
            stripe_index, shard_index, shard_generation, permit_digest, tombstone_digest,
            reporter_node_id, reporter_incarnation, completion_operation_id,
            completed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                   ?14, ?15, ?16, ?17)",
        params![
            command.cleanup_operation_id.as_bytes().as_slice(),
            to_i64(command.item_index)?,
            to_i64(command.permit_attempt_sequence)?,
            receipt.operation_id.as_bytes().as_slice(),
            receipt.target_id.as_bytes().as_slice(),
            to_i64(receipt.target_generation)?,
            receipt.shard.manifest_digest.as_slice(),
            to_i64(receipt.shard.stripe_index)?,
            i64::from(receipt.shard.shard_index),
            i64::from(receipt.shard.generation),
            receipt.permit_digest.as_slice(),
            receipt.tombstone_digest.as_slice(),
            command.reporter_node_id.as_bytes().as_slice(),
            to_i64(command.reporter_incarnation)?,
            context.operation_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn complete_summary_if_ready(
    transaction: &Transaction<'_>,
    context: CommandContext,
    cleanup_operation_id: OperationId,
    commit_revision: Revision,
) -> Result<(), RepositoryError> {
    let (expected_count, sealed_revision): (i64, i64) = transaction.query_row(
        "SELECT expected_item_count, sealed_revision
         FROM version_cleanup_inventories
         WHERE cleanup_operation_id = ?1 AND state = 2",
        [cleanup_operation_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let expected_count = positive(expected_count)?;
    let sealed_revision = revision(sealed_revision)?;
    let (completed_count, completion_digest) =
        ordered_completion_digest(transaction, cleanup_operation_id, sealed_revision)?;
    if completed_count < expected_count {
        return Ok(());
    }
    if completed_count != expected_count {
        return Err(RepositoryError::CorruptState);
    }
    transaction.execute(
        "INSERT INTO version_cleanup_completions(
            cleanup_operation_id, completed_item_count, completion_digest,
            completion_operation_id, completed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            cleanup_operation_id.as_bytes().as_slice(),
            to_i64(completed_count)?,
            completion_digest.as_slice(),
            context.operation_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(commit_revision.get())?,
        ],
    )?;
    Ok(())
}

fn ordered_completion_digest(
    connection: &rusqlite::Connection,
    cleanup_operation_id: OperationId,
    sealed_revision: Revision,
) -> Result<(u64, [u8; 32]), RepositoryError> {
    let completions = {
        let mut statement = connection.prepare(
            "SELECT item_index, permit_attempt_sequence, provider_operation_id,
                    target_id, target_generation, manifest_digest, stripe_index,
                    shard_index, shard_generation, permit_digest, tombstone_digest,
                    reporter_node_id, reporter_incarnation, completion_operation_id,
                    completed_at, revision
             FROM version_cleanup_item_completions
             WHERE cleanup_operation_id = ?1 ORDER BY item_index",
        )?;
        statement
            .query_map([cleanup_operation_id.as_bytes().as_slice()], |row| {
                decode_item(cleanup_operation_id, row)
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut digest = blake3::Hasher::new();
    digest.update(COMPLETION_DIGEST_DOMAIN);
    digest.update(&cleanup_operation_id.as_bytes());
    digest.update(&sealed_revision.get().to_be_bytes());
    let mut count = 0_u64;
    let mut previous_index = None;
    for completion in completions {
        if previous_index.is_some_and(|previous| completion.item_index <= previous) {
            return Err(RepositoryError::CorruptState);
        }
        validate_item_completion(completion)?;
        let attempt = super::cleanup_permit::exact_attempt(
            connection,
            cleanup_operation_id,
            completion.item_index,
            completion.permit_attempt_sequence,
        )?;
        validate_receipt(completion.receipt, attempt.permit)
            .map_err(|_| RepositoryError::CorruptState)?;
        update_completion_digest(&mut digest, completion);
        previous_index = Some(completion.item_index);
        count = count
            .checked_add(1)
            .ok_or(RepositoryError::CapacityExceeded)?;
    }
    digest.update(&count.to_be_bytes());
    Ok((count, digest.finalize().into()))
}

pub(super) fn load_item(
    connection: &rusqlite::Connection,
    cleanup_operation_id: OperationId,
    item_index: u64,
) -> Result<Option<VersionCleanupItemCompletion>, RepositoryError> {
    let completion = connection
        .query_row(
            "SELECT item_index, permit_attempt_sequence, provider_operation_id,
                    target_id, target_generation, manifest_digest, stripe_index,
                    shard_index, shard_generation, permit_digest, tombstone_digest,
                    reporter_node_id, reporter_incarnation, completion_operation_id,
                    completed_at, revision
             FROM version_cleanup_item_completions
             WHERE cleanup_operation_id = ?1 AND item_index = ?2",
            params![
                cleanup_operation_id.as_bytes().as_slice(),
                to_i64(item_index)?,
            ],
            |row| decode_item(cleanup_operation_id, row),
        )
        .optional()?
        .map(|completion| validate_item_completion(completion).map(|()| completion))
        .transpose()?;
    let Some(completion) = completion else {
        return Ok(None);
    };
    let attempt = super::cleanup_permit::exact_attempt(
        connection,
        cleanup_operation_id,
        item_index,
        completion.permit_attempt_sequence,
    )
    .map_err(|_| RepositoryError::CorruptState)?;
    validate_receipt(completion.receipt, attempt.permit)
        .map_err(|_| RepositoryError::CorruptState)?;
    Ok(Some(completion))
}

fn decode_item(
    cleanup_operation_id: OperationId,
    row: &rusqlite::Row<'_>,
) -> Result<VersionCleanupItemCompletion, rusqlite::Error> {
    Ok(VersionCleanupItemCompletion {
        cleanup_operation_id,
        item_index: non_negative(row.get(0)?)?,
        permit_attempt_sequence: positive(row.get(1)?)?,
        receipt: TombstoneReceipt {
            operation_id: operation(&row.get::<_, Vec<u8>>(2)?)?,
            target_id: meshspan_domain::TargetId::from_bytes(array(&row.get::<_, Vec<u8>>(3)?)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            target_generation: positive(row.get(4)?)?,
            shard: meshspan_contracts::ShardIdentity {
                manifest_digest: array(&row.get::<_, Vec<u8>>(5)?)?,
                stripe_index: non_negative(row.get(6)?)?,
                shard_index: u16::try_from(row.get::<_, i64>(7)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                generation: u32::try_from(row.get::<_, i64>(8)?)
                    .ok()
                    .filter(|value| *value > 0)
                    .ok_or(rusqlite::Error::InvalidQuery)?,
            },
            permit_digest: array(&row.get::<_, Vec<u8>>(9)?)?,
            tombstone_digest: array(&row.get::<_, Vec<u8>>(10)?)?,
        },
        reporter_node_id: NodeId::from_bytes(array(&row.get::<_, Vec<u8>>(11)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        reporter_incarnation: positive(row.get(12)?)?,
        completion_operation_id: operation(&row.get::<_, Vec<u8>>(13)?)?,
        completed_at: UnixMicros::new(row.get(14)?),
        revision: revision(row.get(15)?)?,
    })
}

fn validate_item_completion(
    completion: VersionCleanupItemCompletion,
) -> Result<(), RepositoryError> {
    let attempt = completion.permit_attempt_sequence;
    if attempt == 0
        || completion.reporter_incarnation == 0
        || completion.receipt.permit_digest == [0; 32]
        || completion.receipt.tombstone_digest == [0; 32]
        || completion.revision == Revision::ZERO
    {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(())
    }
}

fn update_completion_digest(digest: &mut blake3::Hasher, completion: VersionCleanupItemCompletion) {
    digest.update(&completion.item_index.to_be_bytes());
    digest.update(&completion.permit_attempt_sequence.to_be_bytes());
    let receipt = completion.receipt;
    digest.update(&receipt.operation_id.as_bytes());
    digest.update(&receipt.target_id.as_bytes());
    digest.update(&receipt.target_generation.to_be_bytes());
    digest.update(&receipt.shard.manifest_digest);
    digest.update(&receipt.shard.stripe_index.to_be_bytes());
    digest.update(&receipt.shard.shard_index.to_be_bytes());
    digest.update(&receipt.shard.generation.to_be_bytes());
    digest.update(&receipt.permit_digest);
    digest.update(&receipt.tombstone_digest);
    digest.update(&completion.reporter_node_id.as_bytes());
    digest.update(&completion.reporter_incarnation.to_be_bytes());
    digest.update(&completion.completion_operation_id.as_bytes());
    digest.update(&completion.completed_at.get().to_be_bytes());
    digest.update(&completion.revision.get().to_be_bytes());
}

fn revision(value: i64) -> Result<Revision, rusqlite::Error> {
    positive(value).map(Revision::new)
}

fn positive(value: i64) -> Result<u64, rusqlite::Error> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(rusqlite::Error::InvalidQuery)
}

fn non_negative(value: i64) -> Result<u64, rusqlite::Error> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], rusqlite::Error> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn operation(bytes: &[u8]) -> Result<OperationId, rusqlite::Error> {
    OperationId::from_bytes(array(bytes)?).map_err(|_| rusqlite::Error::InvalidQuery)
}
