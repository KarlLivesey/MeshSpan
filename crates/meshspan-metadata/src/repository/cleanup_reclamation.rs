// SPDX-License-Identifier: GPL-2.0-only

//! Replicated accounting for physical bytes unlinked after durable cleanup tombstones.

use meshspan_contracts::{ReclamationReceipt, TombstoneReceipt, reclamation_receipt_digest};
use meshspan_domain::{NodeId, OperationId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError, cleanup_completion};
use crate::{CommandContext, ConfirmVersionCleanupReclamation, PartitionDatabase};

const RECLAMATION_SUMMARY_DIGEST_DOMAIN: &[u8] = b"meshspan.version-cleanup-reclamation.v1\0";

/// One independently validated provider physical-unlink confirmation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupItemReclamation {
    /// Authorised cleanup proposal.
    pub cleanup_operation_id: OperationId,
    /// Stable item position in the sealed inventory.
    pub item_index: u64,
    /// Exact provider proof of physical byte reclamation.
    pub receipt: ReclamationReceipt,
    /// Authenticated reporting node.
    pub reporter_node_id: NodeId,
    /// Reporting process incarnation current when this result committed.
    pub reporter_incarnation: u64,
    /// Metadata operation that committed this result.
    pub reclamation_operation_id: OperationId,
    /// Authoritative metadata instant at which the result committed.
    pub reclaimed_at: UnixMicros,
    /// Replicated result revision.
    pub revision: Revision,
}

/// Terminal replicated accounting after every completed cleanup item was physically reclaimed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupReclamation {
    /// Authorised cleanup proposal.
    pub cleanup_operation_id: OperationId,
    /// Exact number of physically reclaimed items.
    pub reclaimed_item_count: u64,
    /// Checked sum of provider-confirmed reclaimed bytes.
    pub reclaimed_bytes: u64,
    /// Ordered digest of all independently validated reclamation confirmations.
    pub reclamation_digest: [u8; 32],
    /// Operation that atomically committed the final item and summary.
    pub reclamation_operation_id: OperationId,
    /// Authoritative terminal metadata instant.
    pub reclaimed_at: UnixMicros,
    /// Replicated terminal revision.
    pub revision: Revision,
}

pub(super) fn confirm(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: ConfirmVersionCleanupReclamation,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_shape(context, command)?;
    let completion = cleanup_completion::load_item(
        transaction,
        command.cleanup_operation_id,
        command.item_index,
    )?
    .ok_or(RepositoryError::InvalidCommand)?;
    validate_receipt(command.receipt, completion.receipt)?;
    if command.reporter_node_id != completion.reporter_node_id {
        return Err(RepositoryError::InvalidCommand);
    }
    cleanup_completion::validate_reporter(
        transaction,
        command.reporter_node_id,
        command.reporter_incarnation,
    )?;
    if load_item(
        transaction,
        command.cleanup_operation_id,
        command.item_index,
    )?
    .is_some()
    {
        return Err(RepositoryError::OperationConflict);
    }
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
) -> Result<Option<VersionCleanupItemReclamation>, RepositoryError> {
    cleanup_completion::load_item(database.connection(), cleanup_operation_id, item_index)?
        .ok_or(RepositoryError::InvalidCommand)?;
    load_item(database.connection(), cleanup_operation_id, item_index)
}

pub(super) fn summary(
    database: &PartitionDatabase,
    cleanup_operation_id: OperationId,
) -> Result<Option<VersionCleanupReclamation>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT reclaimed_item_count, reclaimed_bytes, reclamation_digest,
                    reclamation_operation_id, reclaimed_at, revision
             FROM version_cleanup_reclamations WHERE cleanup_operation_id = ?1",
            [cleanup_operation_id.as_bytes().as_slice()],
            |row| {
                Ok(VersionCleanupReclamation {
                    cleanup_operation_id,
                    reclaimed_item_count: positive(row.get(0)?)?,
                    reclaimed_bytes: positive(row.get(1)?)?,
                    reclamation_digest: array(&row.get::<_, Vec<u8>>(2)?)?,
                    reclamation_operation_id: operation(&row.get::<_, Vec<u8>>(3)?)?,
                    reclaimed_at: UnixMicros::new(row.get(4)?),
                    revision: revision(row.get(5)?)?,
                })
            },
        )
        .optional()?;
    let Some(summary) = stored else {
        return Ok(None);
    };
    let completion = cleanup_completion::summary(database, cleanup_operation_id)?
        .ok_or(RepositoryError::CorruptState)?;
    let (count, bytes, digest) = ordered_reclamation_digest(
        database.connection(),
        cleanup_operation_id,
        completion.completion_digest,
    )?;
    if summary.reclaimed_item_count != completion.completed_item_count
        || summary.reclaimed_item_count != count
        || summary.reclaimed_bytes != bytes
        || summary.reclamation_digest != digest
        || summary.revision <= completion.revision
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(summary))
}

fn validate_shape(
    context: CommandContext,
    command: ConfirmVersionCleanupReclamation,
) -> Result<(), RepositoryError> {
    let receipt = command.receipt;
    if context.expected_revision.is_none()
        || command.reporter_incarnation == 0
        || receipt.reclaimed_bytes == 0
        || receipt.reclamation_digest == [0; 32]
        || receipt.bytes_unlinked_at > context.occurred_at
        || context.operation_id == command.cleanup_operation_id
        || context.operation_id == receipt.tombstone.operation_id
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn validate_receipt(
    receipt: ReclamationReceipt,
    tombstone: TombstoneReceipt,
) -> Result<(), RepositoryError> {
    if receipt.tombstone == tombstone
        && receipt.reclaimed_bytes > 0
        && receipt.reclamation_digest
            == reclamation_receipt_digest(
                tombstone,
                receipt.bytes_unlinked_at,
                receipt.reclaimed_bytes,
            )
    {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn insert_item(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: ConfirmVersionCleanupReclamation,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let receipt = command.receipt;
    let changed = transaction.execute(
        "INSERT INTO version_cleanup_item_reclamations(
            cleanup_operation_id, item_index, tombstone_digest, bytes_unlinked_at,
            reclaimed_bytes, reclamation_digest, reporter_node_id, reporter_incarnation,
            reclamation_operation_id, reclaimed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            command.cleanup_operation_id.as_bytes().as_slice(),
            to_i64(command.item_index)?,
            receipt.tombstone.tombstone_digest.as_slice(),
            receipt.bytes_unlinked_at.get(),
            to_i64(receipt.reclaimed_bytes)?,
            receipt.reclamation_digest.as_slice(),
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
    let terminal: Option<(i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT completed_item_count, completion_digest
             FROM version_cleanup_completions WHERE cleanup_operation_id = ?1",
            [cleanup_operation_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((expected_count, completion_digest)) = terminal else {
        return Ok(());
    };
    let expected_count = positive(expected_count)?;
    let completion_digest = array(&completion_digest)?;
    let (count, reclaimed_bytes, reclamation_digest) =
        ordered_reclamation_digest(transaction, cleanup_operation_id, completion_digest)?;
    if count < expected_count {
        return Ok(());
    }
    if count != expected_count {
        return Err(RepositoryError::CorruptState);
    }
    transaction.execute(
        "INSERT INTO version_cleanup_reclamations(
            cleanup_operation_id, reclaimed_item_count, reclaimed_bytes,
            reclamation_digest, reclamation_operation_id, reclaimed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            cleanup_operation_id.as_bytes().as_slice(),
            to_i64(count)?,
            to_i64(reclaimed_bytes)?,
            reclamation_digest.as_slice(),
            context.operation_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(commit_revision.get())?,
        ],
    )?;
    Ok(())
}

fn ordered_reclamation_digest(
    connection: &rusqlite::Connection,
    cleanup_operation_id: OperationId,
    completion_digest: [u8; 32],
) -> Result<(u64, u64, [u8; 32]), RepositoryError> {
    let reclamations = {
        let mut statement = connection.prepare(
            "SELECT r.item_index, c.provider_operation_id, c.target_id,
                    c.target_generation, c.manifest_digest, c.stripe_index,
                    c.shard_index, c.shard_generation, c.permit_digest,
                    c.tombstone_digest, r.tombstone_digest, r.bytes_unlinked_at,
                    r.reclaimed_bytes, r.reclamation_digest, r.reporter_node_id,
                    r.reporter_incarnation, r.reclamation_operation_id,
                    r.reclaimed_at, r.revision
             FROM version_cleanup_item_reclamations r
             JOIN version_cleanup_item_completions c
               ON c.cleanup_operation_id = r.cleanup_operation_id
              AND c.item_index = r.item_index
             WHERE r.cleanup_operation_id = ?1 ORDER BY r.item_index",
        )?;
        statement
            .query_map([cleanup_operation_id.as_bytes().as_slice()], |row| {
                decode_item(cleanup_operation_id, row)
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut digest = blake3::Hasher::new();
    digest.update(RECLAMATION_SUMMARY_DIGEST_DOMAIN);
    digest.update(&cleanup_operation_id.as_bytes());
    digest.update(&completion_digest);
    let mut count = 0_u64;
    let mut bytes = 0_u64;
    let mut previous_index = None;
    for reclamation in reclamations {
        if previous_index.is_some_and(|previous| reclamation.item_index <= previous) {
            return Err(RepositoryError::CorruptState);
        }
        validate_stored_item(&reclamation)?;
        let completion = cleanup_completion::load_item(
            connection,
            cleanup_operation_id,
            reclamation.item_index,
        )?
        .ok_or(RepositoryError::CorruptState)?;
        validate_receipt(reclamation.receipt, completion.receipt)
            .map_err(|_| RepositoryError::CorruptState)?;
        if reclamation.reporter_node_id != completion.reporter_node_id {
            return Err(RepositoryError::CorruptState);
        }
        update_digest(&mut digest, &reclamation);
        previous_index = Some(reclamation.item_index);
        count = count
            .checked_add(1)
            .ok_or(RepositoryError::CapacityExceeded)?;
        bytes = bytes
            .checked_add(reclamation.receipt.reclaimed_bytes)
            .ok_or(RepositoryError::CapacityExceeded)?;
    }
    digest.update(&count.to_be_bytes());
    digest.update(&bytes.to_be_bytes());
    Ok((count, bytes, digest.finalize().into()))
}

fn load_item(
    connection: &rusqlite::Connection,
    cleanup_operation_id: OperationId,
    item_index: u64,
) -> Result<Option<VersionCleanupItemReclamation>, RepositoryError> {
    let item = connection
        .query_row(
            "SELECT r.item_index, c.provider_operation_id, c.target_id,
                    c.target_generation, c.manifest_digest, c.stripe_index,
                    c.shard_index, c.shard_generation, c.permit_digest,
                    c.tombstone_digest, r.tombstone_digest, r.bytes_unlinked_at,
                    r.reclaimed_bytes, r.reclamation_digest, r.reporter_node_id,
                    r.reporter_incarnation, r.reclamation_operation_id,
                    r.reclaimed_at, r.revision
             FROM version_cleanup_item_reclamations r
             JOIN version_cleanup_item_completions c
               ON c.cleanup_operation_id = r.cleanup_operation_id
              AND c.item_index = r.item_index
             WHERE r.cleanup_operation_id = ?1 AND r.item_index = ?2",
            params![
                cleanup_operation_id.as_bytes().as_slice(),
                to_i64(item_index)?
            ],
            |row| decode_item(cleanup_operation_id, row),
        )
        .optional()?
        .map(|item| validate_stored_item(&item).map(|()| item))
        .transpose()?;
    let Some(item) = item else {
        return Ok(None);
    };
    let completion = cleanup_completion::load_item(connection, cleanup_operation_id, item_index)?
        .ok_or(RepositoryError::CorruptState)?;
    validate_receipt(item.receipt, completion.receipt)
        .map_err(|_| RepositoryError::CorruptState)?;
    if item.reporter_node_id != completion.reporter_node_id {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(item))
}

fn decode_item(
    cleanup_operation_id: OperationId,
    row: &rusqlite::Row<'_>,
) -> Result<VersionCleanupItemReclamation, rusqlite::Error> {
    let completion_tombstone_digest = row.get::<_, Vec<u8>>(9)?;
    let recorded_tombstone_digest = row.get::<_, Vec<u8>>(10)?;
    if completion_tombstone_digest != recorded_tombstone_digest {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(VersionCleanupItemReclamation {
        cleanup_operation_id,
        item_index: non_negative(row.get(0)?)?,
        receipt: ReclamationReceipt {
            tombstone: TombstoneReceipt {
                operation_id: operation(&row.get::<_, Vec<u8>>(1)?)?,
                target_id: meshspan_domain::TargetId::from_bytes(array(
                    &row.get::<_, Vec<u8>>(2)?,
                )?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                target_generation: positive(row.get(3)?)?,
                shard: meshspan_contracts::ShardIdentity {
                    manifest_digest: array(&row.get::<_, Vec<u8>>(4)?)?,
                    stripe_index: non_negative(row.get(5)?)?,
                    shard_index: u16::try_from(row.get::<_, i64>(6)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    generation: u32::try_from(row.get::<_, i64>(7)?)
                        .ok()
                        .filter(|value| *value > 0)
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                },
                permit_digest: array(&row.get::<_, Vec<u8>>(8)?)?,
                tombstone_digest: array(&completion_tombstone_digest)?,
            },
            bytes_unlinked_at: UnixMicros::new(row.get(11)?),
            reclaimed_bytes: positive(row.get(12)?)?,
            reclamation_digest: array(&row.get::<_, Vec<u8>>(13)?)?,
        },
        reporter_node_id: NodeId::from_bytes(array(&row.get::<_, Vec<u8>>(14)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        reporter_incarnation: positive(row.get(15)?)?,
        reclamation_operation_id: operation(&row.get::<_, Vec<u8>>(16)?)?,
        reclaimed_at: UnixMicros::new(row.get(17)?),
        revision: revision(row.get(18)?)?,
    })
}

fn validate_stored_item(item: &VersionCleanupItemReclamation) -> Result<(), RepositoryError> {
    if item.reporter_incarnation == 0
        || item.receipt.reclaimed_bytes == 0
        || item.receipt.reclamation_digest == [0; 32]
        || item.receipt.bytes_unlinked_at > item.reclaimed_at
        || item.revision == Revision::ZERO
    {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(())
    }
}

fn update_digest(digest: &mut blake3::Hasher, item: &VersionCleanupItemReclamation) {
    digest.update(&item.item_index.to_be_bytes());
    let receipt = item.receipt;
    digest.update(&receipt.tombstone.tombstone_digest);
    digest.update(&receipt.bytes_unlinked_at.get().to_be_bytes());
    digest.update(&receipt.reclaimed_bytes.to_be_bytes());
    digest.update(&receipt.reclamation_digest);
    digest.update(&item.reporter_node_id.as_bytes());
    digest.update(&item.reporter_incarnation.to_be_bytes());
    digest.update(&item.reclamation_operation_id.as_bytes());
    digest.update(&item.reclaimed_at.get().to_be_bytes());
    digest.update(&item.revision.get().to_be_bytes());
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
