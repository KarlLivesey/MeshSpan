// SPDX-License-Identifier: GPL-2.0-only

//! Replicated short-lived removal-permit attempts for sealed cleanup items.

use meshspan_contracts::RemovalPermit;
use meshspan_domain::{DurationMicros, MeshId, OperationId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::cleanup_inventory::{VersionCleanupItem, sealed_item};
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, IssueVersionCleanupPermit, PartitionDatabase};

/// Compiled safety ceiling for one removal attempt; policy may choose a shorter lifetime.
pub const MAXIMUM_VERSION_CLEANUP_PERMIT_LIFETIME: DurationMicros =
    DurationMicros::new(86_400_000_000);

/// Current deterministic inputs needed to construct the next permit attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupPermitAuthority {
    /// Authorised cleanup proposal.
    pub cleanup_operation_id: OperationId,
    /// Exact sealed inventory revision.
    pub inventory_sealed_revision: Revision,
    /// Exact pending physical item.
    pub item: VersionCleanupItem,
    /// Revision the next committed issue command must bind.
    pub issue_revision: Revision,
    /// Strict next attempt sequence.
    pub attempt_sequence: u64,
    /// Previous authority epoch, or zero for the first attempt.
    pub previous_authority_epoch: u64,
    /// Previous exclusive expiry, if an attempt exists.
    pub previous_expires_at: Option<UnixMicros>,
}

/// One independently validated immutable permit-attempt record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupPermitAttempt {
    /// Authorised cleanup proposal.
    pub cleanup_operation_id: OperationId,
    /// Stable item position.
    pub item_index: u64,
    /// Monotonic attempt sequence for the item.
    pub attempt_sequence: u64,
    /// Complete provider-verifiable permit.
    pub permit: RemovalPermit,
    /// Metadata operation that durably issued the permit.
    pub issue_operation_id: OperationId,
    /// Authoritative issue instant.
    pub issued_at: UnixMicros,
    /// Replicated revision of the attempt.
    pub revision: Revision,
}

pub(super) fn issue(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: IssueVersionCleanupPermit,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_shape(context, command, revision)?;
    let authority = load_authority(
        transaction,
        command.cleanup_operation_id,
        command.item_index,
    )?;
    validate_authority(transaction, context, command, authority)?;
    let permit = command.permit;
    transaction.execute(
        "INSERT INTO version_cleanup_permit_attempts(
            cleanup_operation_id, item_index, attempt_sequence, permit_operation_id,
            mesh_id, authority_epoch, catalogue_revision, issued_at, expires_at,
            permit_digest, issue_operation_id, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            command.cleanup_operation_id.as_bytes().as_slice(),
            to_i64(command.item_index)?,
            to_i64(command.attempt_sequence)?,
            permit.operation_id.as_bytes().as_slice(),
            permit.mesh_id.as_bytes().as_slice(),
            to_i64(permit.authority_epoch)?,
            to_i64(permit.catalogue_revision.get())?,
            context.occurred_at.get(),
            permit.expires_at.get(),
            permit.permit_digest.as_slice(),
            context.operation_id.as_bytes().as_slice(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::VersionCleanup,
        id: command.cleanup_operation_id.as_bytes(),
    })
}

pub(super) fn authority(
    database: &PartitionDatabase,
    cleanup_operation_id: OperationId,
    item_index: u64,
) -> Result<VersionCleanupPermitAuthority, RepositoryError> {
    let state_revision = super::apply::read_current_revision(database)?;
    let issue_revision = state_revision
        .next()
        .map_err(|_| RepositoryError::CapacityExceeded)?;
    let sealed = sealed_item(database.connection(), cleanup_operation_id, item_index)?;
    let previous = load_latest(database.connection(), cleanup_operation_id, item_index)?;
    Ok(VersionCleanupPermitAuthority {
        cleanup_operation_id,
        inventory_sealed_revision: sealed.sealed_revision,
        item: sealed.item,
        issue_revision,
        attempt_sequence: previous.map_or(Ok(1), |attempt| {
            attempt
                .attempt_sequence
                .checked_add(1)
                .ok_or(RepositoryError::CapacityExceeded)
        })?,
        previous_authority_epoch: previous.map_or(0, |attempt| attempt.permit.authority_epoch),
        previous_expires_at: previous.map(|attempt| attempt.permit.expires_at),
    })
}

pub(super) fn latest(
    database: &PartitionDatabase,
    cleanup_operation_id: OperationId,
    item_index: u64,
) -> Result<Option<VersionCleanupPermitAttempt>, RepositoryError> {
    sealed_item(database.connection(), cleanup_operation_id, item_index)?;
    load_latest(database.connection(), cleanup_operation_id, item_index)
}

fn validate_shape(
    context: CommandContext,
    command: IssueVersionCleanupPermit,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let permit = command.permit;
    let lifetime = permit
        .expires_at
        .get()
        .checked_sub(context.occurred_at.get())
        .ok_or(RepositoryError::InvalidCommand)?;
    if context.expected_revision.is_none()
        || command.inventory_sealed_revision == Revision::ZERO
        || command.attempt_sequence == 0
        || permit.authority_epoch == 0
        || permit.catalogue_revision != revision
        || permit.permit_digest == [0; 32]
        || lifetime <= 0
        || u64::try_from(lifetime)
            .ok()
            .is_none_or(|lifetime| lifetime > MAXIMUM_VERSION_CLEANUP_PERMIT_LIFETIME.get())
        || permit.operation_id == command.cleanup_operation_id
        || permit.operation_id == context.operation_id
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn validate_authority(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: IssueVersionCleanupPermit,
    authority: VersionCleanupPermitAuthority,
) -> Result<(), RepositoryError> {
    let permit = command.permit;
    let mesh_id = load_mesh_id(transaction)?;
    if command.inventory_sealed_revision != authority.inventory_sealed_revision
        || command.attempt_sequence != authority.attempt_sequence
        || permit.mesh_id != mesh_id
        || permit.target_id != authority.item.target_id
        || permit.target_generation != authority.item.target_generation
        || permit.shard != authority.item.shard
        || permit.catalogue_revision != authority.issue_revision
        || permit.authority_epoch < authority.previous_authority_epoch
        || (permit.authority_epoch == authority.previous_authority_epoch
            && authority
                .previous_expires_at
                .is_some_and(|expires_at| expires_at > context.occurred_at))
    {
        return Err(RepositoryError::StaleRevision);
    }
    if command.attempt_sequence == 1 {
        if permit.operation_id != authority.item.removal_operation_id {
            return Err(RepositoryError::InvalidCommand);
        }
    } else if super::apply::operation_exists(transaction, permit.operation_id)?
        || super::cleanup_inventory::is_reserved_operation(transaction, permit.operation_id)?
    {
        return Err(RepositoryError::OperationConflict);
    }
    Ok(())
}

fn load_authority(
    transaction: &Transaction<'_>,
    cleanup_operation_id: OperationId,
    item_index: u64,
) -> Result<VersionCleanupPermitAuthority, RepositoryError> {
    let sealed = sealed_item(transaction, cleanup_operation_id, item_index)?;
    let previous = load_latest(transaction, cleanup_operation_id, item_index)?;
    let state_revision: i64 = transaction.query_row(
        "SELECT state_revision FROM applied_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let state_revision = Revision::new(non_negative(state_revision)?);
    Ok(VersionCleanupPermitAuthority {
        cleanup_operation_id,
        inventory_sealed_revision: sealed.sealed_revision,
        item: sealed.item,
        issue_revision: state_revision
            .next()
            .map_err(|_| RepositoryError::CapacityExceeded)?,
        attempt_sequence: previous.map_or(Ok(1), |attempt| {
            attempt
                .attempt_sequence
                .checked_add(1)
                .ok_or(RepositoryError::CapacityExceeded)
        })?,
        previous_authority_epoch: previous.map_or(0, |attempt| attempt.permit.authority_epoch),
        previous_expires_at: previous.map(|attempt| attempt.permit.expires_at),
    })
}

fn load_latest(
    connection: &rusqlite::Connection,
    cleanup_operation_id: OperationId,
    item_index: u64,
) -> Result<Option<VersionCleanupPermitAttempt>, RepositoryError> {
    let item = sealed_item(connection, cleanup_operation_id, item_index)?.item;
    connection
        .query_row(
            "SELECT attempt_sequence, permit_operation_id, mesh_id, authority_epoch,
                    catalogue_revision, issued_at, expires_at, permit_digest,
                    issue_operation_id, revision
             FROM version_cleanup_permit_attempts
             WHERE cleanup_operation_id = ?1 AND item_index = ?2
             ORDER BY attempt_sequence DESC LIMIT 1",
            params![
                cleanup_operation_id.as_bytes().as_slice(),
                to_i64(item_index)?,
            ],
            |row| {
                let permit_operation_id = operation(&row.get::<_, Vec<u8>>(1)?)?;
                let mesh_id = MeshId::from_bytes(array(&row.get::<_, Vec<u8>>(2)?)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let stored_revision = revision(row.get(9)?)?;
                let catalogue_revision = revision(row.get(4)?)?;
                if stored_revision != catalogue_revision {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Ok(VersionCleanupPermitAttempt {
                    cleanup_operation_id,
                    item_index,
                    attempt_sequence: positive(row.get(0)?)?,
                    permit: RemovalPermit {
                        operation_id: permit_operation_id,
                        mesh_id,
                        target_id: item.target_id,
                        shard: item.shard,
                        target_generation: item.target_generation,
                        authority_epoch: positive(row.get(3)?)?,
                        catalogue_revision,
                        expires_at: UnixMicros::new(row.get(6)?),
                        permit_digest: array(&row.get::<_, Vec<u8>>(7)?)?,
                    },
                    issue_operation_id: operation(&row.get::<_, Vec<u8>>(8)?)?,
                    issued_at: UnixMicros::new(row.get(5)?),
                    revision: stored_revision,
                })
            },
        )
        .optional()?
        .map(|attempt| validate_attempt(attempt).map(|()| attempt))
        .transpose()
}

fn validate_attempt(attempt: VersionCleanupPermitAttempt) -> Result<(), RepositoryError> {
    let lifetime = attempt
        .permit
        .expires_at
        .get()
        .checked_sub(attempt.issued_at.get())
        .ok_or(RepositoryError::CorruptState)?;
    if attempt.attempt_sequence == 0
        || attempt.permit.authority_epoch == 0
        || attempt.permit.permit_digest == [0; 32]
        || lifetime <= 0
        || u64::try_from(lifetime)
            .ok()
            .is_none_or(|lifetime| lifetime > MAXIMUM_VERSION_CLEANUP_PERMIT_LIFETIME.get())
    {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(())
    }
}

fn load_mesh_id(connection: &rusqlite::Connection) -> Result<MeshId, RepositoryError> {
    let mut statement =
        connection.prepare("SELECT mesh_id FROM meshes ORDER BY mesh_id LIMIT 2")?;
    let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let values = rows.collect::<Result<Vec<_>, _>>()?;
    if values.len() != 1 {
        return Err(RepositoryError::CorruptState);
    }
    MeshId::from_bytes(array(&values[0])?).map_err(|_| RepositoryError::CorruptState)
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

fn non_negative(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], rusqlite::Error> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn operation(bytes: &[u8]) -> Result<OperationId, rusqlite::Error> {
    OperationId::from_bytes(array(bytes)?).map_err(|_| rusqlite::Error::InvalidQuery)
}
