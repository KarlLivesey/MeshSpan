// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, digest-chained physical inventory for authorised version cleanup.

use std::collections::BTreeSet;

use meshspan_contracts::ShardIdentity;
use meshspan_domain::{OperationId, Revision, TargetId, UnixMicros};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::query::{Page, PageLimit};
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    AppendVersionCleanupItems, CommandContext, PartitionDatabase, SealVersionCleanupInventory,
    VersionCleanupItemPlacement,
};

const MAXIMUM_APPEND_ITEMS: usize = 1_000;
const INVENTORY_BUILDING: i64 = 1;
const INVENTORY_SEALED: i64 = 2;
const CLEANUP_AUTHORISED: i64 = 2;

/// Replicated readiness of one physical cleanup inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionCleanupInventoryState {
    /// More bounded contiguous pages are required.
    Building,
    /// The exact complete item count and digest are immutable.
    Sealed,
}

/// Summary of one independently validated cleanup inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupInventory {
    /// Owning authorised cleanup proposal.
    pub cleanup_operation_id: OperationId,
    /// Original proposal revision.
    pub cleanup_revision: Revision,
    /// Terminal revision that granted cleanup authority.
    pub authorisation_revision: Revision,
    /// Immutable total number of physical items.
    pub expected_item_count: u64,
    /// Number durably appended so far.
    pub item_count: u64,
    /// Digest chained over every exact ordered item.
    pub inventory_digest: [u8; 32],
    /// Current readiness state.
    pub state: VersionCleanupInventoryState,
    /// Operation that sealed the inventory, if complete.
    pub seal_operation_id: Option<OperationId>,
    /// Revision that sealed the inventory, if complete.
    pub sealed_revision: Option<Revision>,
    /// Authoritative sealing instant, if complete.
    pub sealed_at: Option<UnixMicros>,
}

/// One immutable item in a sealed cleanup inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupItem {
    /// Stable zero-based inventory position.
    pub item_index: u64,
    /// Stable provider mutation identity used for permit retries.
    pub removal_operation_id: OperationId,
    /// Exact immutable shard generation.
    pub shard: ShardIdentity,
    /// Exact target identity.
    pub target_id: TargetId,
    /// Exact target generation.
    pub target_generation: u64,
    /// Replicated revision that appended the item.
    pub revision: Revision,
}

/// Opaque seek cursor bound to one cleanup inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupItemCursor {
    cleanup_operation_id: OperationId,
    item_index: u64,
}

pub(super) struct SealedCleanupItem {
    pub(super) item: VersionCleanupItem,
    pub(super) sealed_revision: Revision,
}

pub(super) fn append(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AppendVersionCleanupItems,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_append(context, command)?;
    let manifest_digest = load_authorised_manifest(transaction, command.identity())?;
    validate_items(transaction, context, command, manifest_digest)?;
    let mut current = load_inventory(transaction, command.cleanup_operation_id)?;
    if current.is_none() {
        if command.start_index != 0 {
            return Err(RepositoryError::StaleRevision);
        }
        let seed = inventory_seed(command, manifest_digest);
        transaction.execute(
            "INSERT INTO version_cleanup_inventories(
                cleanup_operation_id, cleanup_revision, authorisation_revision,
                expected_item_count, item_count, rolling_digest, state, created_at,
                created_revision, last_append_revision
             ) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7, ?8, ?8)",
            params![
                command.cleanup_operation_id.as_bytes().as_slice(),
                to_i64(command.cleanup_revision.get())?,
                to_i64(command.authorisation_revision.get())?,
                to_i64(command.expected_item_count)?,
                seed.as_slice(),
                INVENTORY_BUILDING,
                context.occurred_at.get(),
                to_i64(revision.get())?,
            ],
        )?;
        current = Some(StoredInventory {
            cleanup_revision: command.cleanup_revision.get(),
            authorisation_revision: command.authorisation_revision.get(),
            expected_item_count: command.expected_item_count,
            item_count: 0,
            rolling_digest: seed,
            state: INVENTORY_BUILDING,
            seal_operation_id: None,
            sealed_at: None,
            sealed_revision: None,
        });
    }
    let current = current.ok_or(RepositoryError::CorruptState)?;
    validate_current(command, &current)?;
    let next_count = command
        .start_index
        .checked_add(
            u64::try_from(command.items.len()).map_err(|_| RepositoryError::InvalidCommand)?,
        )
        .ok_or(RepositoryError::CapacityExceeded)?;
    if next_count > command.expected_item_count {
        return Err(RepositoryError::InvalidCommand);
    }
    let mut digest = current.rolling_digest;
    for (offset, item) in command.items.as_slice().iter().enumerate() {
        let item_index = command
            .start_index
            .checked_add(u64::try_from(offset).map_err(|_| RepositoryError::InvalidCommand)?)
            .ok_or(RepositoryError::CapacityExceeded)?;
        digest = extend_digest(digest, item_index, *item);
        insert_item(
            transaction,
            context,
            revision,
            command.cleanup_operation_id,
            item_index,
            *item,
        )?;
    }
    let changed = transaction.execute(
        "UPDATE version_cleanup_inventories
         SET item_count = ?1, rolling_digest = ?2, last_append_revision = ?3
         WHERE cleanup_operation_id = ?4 AND state = ?5 AND item_count = ?6
           AND last_append_revision <= ?3",
        params![
            to_i64(next_count)?,
            digest.as_slice(),
            to_i64(revision.get())?,
            command.cleanup_operation_id.as_bytes().as_slice(),
            INVENTORY_BUILDING,
            to_i64(command.start_index)?,
        ],
    )?;
    entity(changed, command.cleanup_operation_id)
}

pub(super) fn seal(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: SealVersionCleanupInventory,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if context.expected_revision.is_none()
        || command.cleanup_revision == Revision::ZERO
        || command.authorisation_revision <= command.cleanup_revision
        || command.expected_item_count == 0
        || command.inventory_digest == [0; 32]
        || context.operation_id == command.cleanup_operation_id
    {
        return Err(RepositoryError::InvalidCommand);
    }
    load_authorised_manifest(transaction, command.identity())?;
    let changed = transaction.execute(
        "UPDATE version_cleanup_inventories
         SET state = ?1, seal_operation_id = ?2, sealed_at = ?3, sealed_revision = ?4
         WHERE cleanup_operation_id = ?5 AND cleanup_revision = ?6
           AND authorisation_revision = ?7 AND expected_item_count = ?8
           AND item_count = expected_item_count AND rolling_digest = ?9
           AND state = ?10 AND seal_operation_id IS NULL
           AND sealed_at IS NULL AND sealed_revision IS NULL
           AND last_append_revision < ?4",
        params![
            INVENTORY_SEALED,
            context.operation_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.cleanup_operation_id.as_bytes().as_slice(),
            to_i64(command.cleanup_revision.get())?,
            to_i64(command.authorisation_revision.get())?,
            to_i64(command.expected_item_count)?,
            command.inventory_digest.as_slice(),
            INVENTORY_BUILDING,
        ],
    )?;
    entity(changed, command.cleanup_operation_id)
}

pub(super) fn load(
    database: &PartitionDatabase,
    cleanup_operation_id: OperationId,
) -> Result<Option<VersionCleanupInventory>, RepositoryError> {
    let Some(stored) = load_inventory(database.connection(), cleanup_operation_id)? else {
        return Ok(None);
    };
    load_authorised_manifest(
        database.connection(),
        CleanupIdentity {
            cleanup_operation_id,
            cleanup_revision: Revision::new(stored.cleanup_revision),
            authorisation_revision: Revision::new(stored.authorisation_revision),
        },
    )?;
    decode_inventory(cleanup_operation_id, &stored).map(Some)
}

pub(super) fn page(
    database: &PartitionDatabase,
    cleanup_operation_id: OperationId,
    after: Option<&VersionCleanupItemCursor>,
    limit: PageLimit,
) -> Result<Page<VersionCleanupItem, VersionCleanupItemCursor>, RepositoryError> {
    let inventory = load_inventory(database.connection(), cleanup_operation_id)?
        .ok_or(RepositoryError::InvalidCommand)?;
    if inventory.state != INVENTORY_SEALED {
        return Err(RepositoryError::InvalidCommand);
    }
    let manifest_digest = load_authorised_manifest(
        database.connection(),
        CleanupIdentity {
            cleanup_operation_id,
            cleanup_revision: Revision::new(inventory.cleanup_revision),
            authorisation_revision: Revision::new(inventory.authorisation_revision),
        },
    )?;
    let stored_count: i64 = database.connection().query_row(
        "SELECT count(*) FROM version_cleanup_items WHERE cleanup_operation_id = ?1",
        [cleanup_operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if non_negative(stored_count)? != inventory.expected_item_count {
        return Err(RepositoryError::CorruptState);
    }
    let after_index = match after {
        Some(cursor) if cursor.cleanup_operation_id == cleanup_operation_id => {
            to_i64(cursor.item_index)?
        }
        Some(_) => return Err(RepositoryError::InvalidCommand),
        None => -1,
    };
    let maximum = limit.get();
    let mut statement = database.connection().prepare(
        "SELECT item_index, removal_operation_id, manifest_digest, stripe_index,
                shard_index, shard_generation, target_id, target_generation, revision
         FROM version_cleanup_items
         WHERE cleanup_operation_id = ?1 AND item_index > ?2
         ORDER BY item_index LIMIT ?3",
    )?;
    let rows = statement.query_map(
        params![
            cleanup_operation_id.as_bytes().as_slice(),
            after_index,
            i64::try_from(maximum.saturating_add(1))
                .map_err(|_| RepositoryError::InvalidPageLimit)?,
        ],
        decode_item,
    )?;
    let mut items = rows.collect::<Result<Vec<_>, _>>()?;
    let next = if items.len() > maximum {
        items.pop();
        items.last().map(|item| VersionCleanupItemCursor {
            cleanup_operation_id,
            item_index: item.item_index,
        })
    } else {
        None
    };
    let mut expected_index = after.map_or(0, |cursor| cursor.item_index.saturating_add(1));
    for item in &items {
        if item.item_index != expected_index || item.shard.manifest_digest != manifest_digest {
            return Err(RepositoryError::CorruptState);
        }
        expected_index = expected_index
            .checked_add(1)
            .ok_or(RepositoryError::CorruptState)?;
    }
    Ok(Page { items, next })
}

pub(super) fn sealed_item(
    connection: &rusqlite::Connection,
    cleanup_operation_id: OperationId,
    item_index: u64,
) -> Result<SealedCleanupItem, RepositoryError> {
    let inventory =
        load_inventory(connection, cleanup_operation_id)?.ok_or(RepositoryError::InvalidCommand)?;
    if inventory.state != INVENTORY_SEALED {
        return Err(RepositoryError::InvalidCommand);
    }
    let sealed_revision = inventory
        .sealed_revision
        .map(Revision::new)
        .ok_or(RepositoryError::CorruptState)?;
    let manifest_digest = load_authorised_manifest(
        connection,
        CleanupIdentity {
            cleanup_operation_id,
            cleanup_revision: Revision::new(inventory.cleanup_revision),
            authorisation_revision: Revision::new(inventory.authorisation_revision),
        },
    )?;
    let stored_count: i64 = connection.query_row(
        "SELECT count(*) FROM version_cleanup_items WHERE cleanup_operation_id = ?1",
        [cleanup_operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if non_negative(stored_count)? != inventory.expected_item_count
        || item_index >= inventory.expected_item_count
    {
        return Err(RepositoryError::CorruptState);
    }
    let item = connection
        .query_row(
            "SELECT item_index, removal_operation_id, manifest_digest, stripe_index,
                    shard_index, shard_generation, target_id, target_generation, revision
             FROM version_cleanup_items
             WHERE cleanup_operation_id = ?1 AND item_index = ?2",
            params![
                cleanup_operation_id.as_bytes().as_slice(),
                to_i64(item_index)?,
            ],
            decode_item,
        )
        .optional()?
        .ok_or(RepositoryError::CorruptState)?;
    if item.item_index != item_index || item.shard.manifest_digest != manifest_digest {
        return Err(RepositoryError::CorruptState);
    }
    Ok(SealedCleanupItem {
        item,
        sealed_revision,
    })
}

#[derive(Clone, Copy)]
struct CleanupIdentity {
    cleanup_operation_id: OperationId,
    cleanup_revision: Revision,
    authorisation_revision: Revision,
}

trait HasCleanupIdentity {
    fn identity(&self) -> CleanupIdentity;
}

impl HasCleanupIdentity for AppendVersionCleanupItems {
    fn identity(&self) -> CleanupIdentity {
        CleanupIdentity {
            cleanup_operation_id: self.cleanup_operation_id,
            cleanup_revision: self.cleanup_revision,
            authorisation_revision: self.authorisation_revision,
        }
    }
}

impl HasCleanupIdentity for SealVersionCleanupInventory {
    fn identity(&self) -> CleanupIdentity {
        CleanupIdentity {
            cleanup_operation_id: self.cleanup_operation_id,
            cleanup_revision: self.cleanup_revision,
            authorisation_revision: self.authorisation_revision,
        }
    }
}

struct StoredInventory {
    cleanup_revision: u64,
    authorisation_revision: u64,
    expected_item_count: u64,
    item_count: u64,
    rolling_digest: [u8; 32],
    state: i64,
    seal_operation_id: Option<Vec<u8>>,
    sealed_at: Option<i64>,
    sealed_revision: Option<u64>,
}

fn load_authorised_manifest(
    connection: &rusqlite::Connection,
    identity: CleanupIdentity,
) -> Result<[u8; 32], RepositoryError> {
    connection
        .query_row(
            "SELECT manifest_root_digest FROM version_cleanup_intents
             WHERE cleanup_operation_id = ?1 AND revision = ?2
               AND terminal_revision = ?3 AND state = ?4",
            params![
                identity.cleanup_operation_id.as_bytes().as_slice(),
                to_i64(identity.cleanup_revision.get())?,
                to_i64(identity.authorisation_revision.get())?,
                CLEANUP_AUTHORISED,
            ],
            |row| array(&row.get::<_, Vec<u8>>(0)?),
        )
        .optional()?
        .ok_or(RepositoryError::StaleRevision)
}

fn validate_append(
    context: CommandContext,
    command: &AppendVersionCleanupItems,
) -> Result<(), RepositoryError> {
    if context.expected_revision.is_none()
        || command.cleanup_revision == Revision::ZERO
        || command.authorisation_revision <= command.cleanup_revision
        || command.expected_item_count == 0
        || command.items.is_empty()
        || command.items.len() > MAXIMUM_APPEND_ITEMS
        || context.operation_id == command.cleanup_operation_id
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn validate_items(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AppendVersionCleanupItems,
    manifest_digest: [u8; 32],
) -> Result<(), RepositoryError> {
    let mut operations = BTreeSet::new();
    for item in command.items.as_slice() {
        if item.shard.manifest_digest != manifest_digest
            || item.shard.generation == 0
            || item.target_generation == 0
            || item.removal_operation_id == command.cleanup_operation_id
            || item.removal_operation_id == context.operation_id
            || !operations.insert(item.removal_operation_id)
            || i64::try_from(item.shard.stripe_index).is_err()
            || super::apply::operation_exists(transaction, item.removal_operation_id)?
            || is_reserved_operation(transaction, item.removal_operation_id)?
        {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    Ok(())
}

pub(super) fn is_reserved_operation(
    connection: &rusqlite::Connection,
    operation_id: OperationId,
) -> Result<bool, RepositoryError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM version_cleanup_items WHERE removal_operation_id = ?1
                UNION ALL
                SELECT 1 FROM version_cleanup_permit_attempts WHERE permit_operation_id = ?1
             )",
            [operation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn validate_current(
    command: &AppendVersionCleanupItems,
    current: &StoredInventory,
) -> Result<(), RepositoryError> {
    if current.cleanup_revision != command.cleanup_revision.get()
        || current.authorisation_revision != command.authorisation_revision.get()
        || current.expected_item_count != command.expected_item_count
        || current.item_count != command.start_index
        || current.state != INVENTORY_BUILDING
        || current.seal_operation_id.is_some()
        || current.sealed_at.is_some()
        || current.sealed_revision.is_some()
    {
        Err(RepositoryError::StaleRevision)
    } else {
        Ok(())
    }
}

fn insert_item(
    transaction: &Transaction<'_>,
    context: CommandContext,
    revision: Revision,
    cleanup_operation_id: OperationId,
    item_index: u64,
    item: VersionCleanupItemPlacement,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "INSERT INTO version_cleanup_items(
            cleanup_operation_id, item_index, removal_operation_id, manifest_digest,
            stripe_index, shard_index, shard_generation, target_id, target_generation,
            append_operation_id, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            cleanup_operation_id.as_bytes().as_slice(),
            to_i64(item_index)?,
            item.removal_operation_id.as_bytes().as_slice(),
            item.shard.manifest_digest.as_slice(),
            to_i64(item.shard.stripe_index)?,
            i64::from(item.shard.shard_index),
            i64::from(item.shard.generation),
            item.target_id.as_bytes().as_slice(),
            to_i64(item.target_generation)?,
            context.operation_id.as_bytes().as_slice(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn load_inventory(
    connection: &rusqlite::Connection,
    cleanup_operation_id: OperationId,
) -> Result<Option<StoredInventory>, RepositoryError> {
    connection
        .query_row(
            "SELECT cleanup_revision, authorisation_revision, expected_item_count,
                    item_count, rolling_digest, state, seal_operation_id,
                    sealed_at, sealed_revision
             FROM version_cleanup_inventories WHERE cleanup_operation_id = ?1",
            [cleanup_operation_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredInventory {
                    cleanup_revision: positive(row.get(0)?)?,
                    authorisation_revision: positive(row.get(1)?)?,
                    expected_item_count: positive(row.get(2)?)?,
                    item_count: non_negative(row.get(3)?)?,
                    rolling_digest: array(&row.get::<_, Vec<u8>>(4)?)?,
                    state: row.get(5)?,
                    seal_operation_id: row.get(6)?,
                    sealed_at: row.get(7)?,
                    sealed_revision: row.get::<_, Option<i64>>(8)?.map(positive).transpose()?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn decode_inventory(
    cleanup_operation_id: OperationId,
    stored: &StoredInventory,
) -> Result<VersionCleanupInventory, RepositoryError> {
    let terminal = match (
        stored.state,
        stored.seal_operation_id.as_deref(),
        stored.sealed_revision,
        stored.sealed_at,
    ) {
        (INVENTORY_BUILDING, None, None, None) => {
            (VersionCleanupInventoryState::Building, None, None, None)
        }
        (INVENTORY_SEALED, Some(operation), Some(revision), Some(at))
            if stored.item_count == stored.expected_item_count =>
        {
            (
                VersionCleanupInventoryState::Sealed,
                Some(decode_operation(operation)?),
                Some(Revision::new(revision)),
                Some(UnixMicros::new(at)),
            )
        }
        _ => return Err(RepositoryError::CorruptState),
    };
    Ok(VersionCleanupInventory {
        cleanup_operation_id,
        cleanup_revision: Revision::new(stored.cleanup_revision),
        authorisation_revision: Revision::new(stored.authorisation_revision),
        expected_item_count: stored.expected_item_count,
        item_count: stored.item_count,
        inventory_digest: stored.rolling_digest,
        state: terminal.0,
        seal_operation_id: terminal.1,
        sealed_revision: terminal.2,
        sealed_at: terminal.3,
    })
}

fn decode_item(row: &rusqlite::Row<'_>) -> Result<VersionCleanupItem, rusqlite::Error> {
    Ok(VersionCleanupItem {
        item_index: non_negative(row.get(0)?)?,
        removal_operation_id: decode_operation(&row.get::<_, Vec<u8>>(1)?)?,
        shard: ShardIdentity {
            manifest_digest: array(&row.get::<_, Vec<u8>>(2)?)?,
            stripe_index: non_negative(row.get(3)?)?,
            shard_index: u16::try_from(row.get::<_, i64>(4)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            generation: u32::try_from(positive(row.get(5)?)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        },
        target_id: TargetId::from_bytes(array(&row.get::<_, Vec<u8>>(6)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        target_generation: positive(row.get(7)?)?,
        revision: Revision::new(positive(row.get(8)?)?),
    })
}

fn inventory_seed(command: &AppendVersionCleanupItems, manifest_digest: [u8; 32]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.version-cleanup-inventory.seed.v1\0");
    digest.update(&command.cleanup_operation_id.as_bytes());
    digest.update(&command.cleanup_revision.get().to_be_bytes());
    digest.update(&command.authorisation_revision.get().to_be_bytes());
    digest.update(&command.expected_item_count.to_be_bytes());
    digest.update(&manifest_digest);
    digest.finalize().into()
}

fn extend_digest(prior: [u8; 32], item_index: u64, item: VersionCleanupItemPlacement) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.version-cleanup-inventory.item.v1\0");
    digest.update(&prior);
    digest.update(&item_index.to_be_bytes());
    digest.update(&item.removal_operation_id.as_bytes());
    digest.update(&item.shard.manifest_digest);
    digest.update(&item.shard.stripe_index.to_be_bytes());
    digest.update(&item.shard.shard_index.to_be_bytes());
    digest.update(&item.shard.generation.to_be_bytes());
    digest.update(&item.target_id.as_bytes());
    digest.update(&item.target_generation.to_be_bytes());
    digest.finalize().into()
}

fn entity(
    changed: usize,
    cleanup_operation_id: OperationId,
) -> Result<EntityReference, RepositoryError> {
    if changed != 1 {
        return Err(RepositoryError::StaleRevision);
    }
    Ok(EntityReference {
        kind: EntityKind::VersionCleanup,
        id: cleanup_operation_id.as_bytes(),
    })
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

fn decode_operation(bytes: &[u8]) -> Result<OperationId, rusqlite::Error> {
    OperationId::from_bytes(array(bytes)?).map_err(|_| rusqlite::Error::InvalidQuery)
}
