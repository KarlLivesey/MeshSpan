// SPDX-License-Identifier: GPL-2.0-only

//! Read-only volume snapshot authority and bounded listing.

use meshspan_domain::{
    NamespaceCommitId, ObjectRevisionId, Revision, SnapshotId, UnixMicros, VolumeId,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, Page, PageLimit, RepositoryError};
use crate::{
    CommandContext, CreateVolumeSnapshot, PartitionDatabase, RemoveVolumeSnapshotRoot,
    RequestVolumeSnapshotExpiry, SnapshotExpiryReason,
};

mod expiry;
mod restore;

pub(super) use expiry::due as due_expiries;
pub use expiry::{SnapshotExpiryCandidate, SnapshotExpiryCursor};

pub(super) fn restore(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: crate::RestoreVolumeSnapshot,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    restore::apply(transaction, context, command, revision)
}

/// Stable seek cursor for one volume's snapshot list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotCursor {
    canonical_name: String,
    snapshot_id: SnapshotId,
}

/// One independently validated read-only volume snapshot record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeSnapshot {
    /// Stable snapshot identity.
    pub snapshot_id: SnapshotId,
    /// Volume whose namespace root is pinned.
    pub volume_id: VolumeId,
    /// Exact immutable namespace commit pinned by this snapshot.
    pub namespace_commit_id: NamespaceCommitId,
    /// Immutable root revision selected by the pinned commit.
    pub root_object_revision_id: ObjectRevisionId,
    /// NFC display name.
    pub display_name: String,
    /// Canonical seek and uniqueness name.
    pub canonical_name: String,
    /// Active, expiring or removed persisted state code.
    pub state: u8,
    /// Whether automatic expiry is forbidden.
    pub protected_from_expiry: bool,
    /// Authoritative creation instant.
    pub created_at: UnixMicros,
    /// Optional automatic expiry instant.
    pub expires_at: Option<UnixMicros>,
    /// Last authoritative record revision.
    pub revision: Revision,
}

type StoredRemovalBase = (i64, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>, i64);

pub(super) fn create(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CreateVolumeSnapshot,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command
        .expires_at
        .is_some_and(|expires| expires.get() <= context.occurred_at.get())
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let (current_commit, root): (Vec<u8>, Vec<u8>) = transaction
        .query_row(
            "SELECT namespace_commit_id, root_object_revision_id
             FROM volume_head_transitions WHERE volume_id = ?1
             ORDER BY head_sequence DESC LIMIT 1",
            [command.volume_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    if current_commit.as_slice() != command.namespace_commit_id.as_bytes() || root.len() != 16 {
        return Err(RepositoryError::StaleVolumeHead);
    }
    transaction.execute(
        "INSERT INTO volume_snapshots(
            snapshot_id, volume_id, namespace_commit_id, root_object_revision_id,
            display_name, canonical_name, state, protected_from_expiry,
            created_by, created_at, expires_at, removed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?9, ?10, NULL, ?11)",
        params![
            command.snapshot_id.as_bytes().as_slice(),
            command.volume_id.as_bytes().as_slice(),
            command.namespace_commit_id.as_bytes().as_slice(),
            root,
            command.name.display(),
            command.name.canonical(),
            command.protected_from_expiry,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            command.expires_at.map(UnixMicros::get),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::VolumeSnapshot,
        id: command.snapshot_id.as_bytes(),
    })
}

pub(super) fn request_expiry(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: RequestVolumeSnapshotExpiry,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.expected_snapshot_revision == Revision::ZERO {
        return Err(RepositoryError::InvalidCommand);
    }
    let stored: Option<(i64, i64, Option<i64>, i64)> = transaction
        .query_row(
            "SELECT state, protected_from_expiry, expires_at, revision
             FROM volume_snapshots WHERE snapshot_id = ?1",
            [command.snapshot_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((state, protected, expires_at, stored_revision)) = stored else {
        return Err(RepositoryError::InvalidCommand);
    };
    if parse_u64(stored_revision)? != command.expected_snapshot_revision.get() {
        return Err(RepositoryError::StaleSnapshot);
    }
    if state != 1 || protected != 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    validate_expiry_reason(transaction, context, command, expires_at)?;
    let updated = transaction.execute(
        "UPDATE volume_snapshots SET state = 2, revision = ?1
         WHERE snapshot_id = ?2 AND state = 1 AND revision = ?3",
        params![
            to_i64(revision.get())?,
            command.snapshot_id.as_bytes().as_slice(),
            stored_revision,
        ],
    )?;
    if updated != 1 {
        return Err(RepositoryError::StaleSnapshot);
    }
    transaction.execute(
        "INSERT INTO snapshot_expiry_requests(
            snapshot_id, operation_id, automatic, reason_code, requested_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            command.snapshot_id.as_bytes().as_slice(),
            context.operation_id.as_bytes().as_slice(),
            command.reason != SnapshotExpiryReason::Manual,
            expiry_reason_code(command.reason),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::VolumeSnapshot,
        id: command.snapshot_id.as_bytes(),
    })
}

pub(super) fn remove_root(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: RemoveVolumeSnapshotRoot,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.expected_snapshot_revision == Revision::ZERO {
        return Err(RepositoryError::InvalidCommand);
    }
    let stored: StoredRemovalBase = transaction
        .query_row(
            "SELECT s.state, s.protected_from_expiry, s.revision,
                    s.namespace_commit_id, s.root_object_revision_id,
                    e.operation_id, e.revision
             FROM volume_snapshots s
             JOIN snapshot_expiry_requests e USING(snapshot_id)
             WHERE s.snapshot_id = ?1",
            [command.snapshot_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    let expected_revision = command.expected_snapshot_revision.get();
    if stored.0 != 2
        || stored.1 != 0
        || parse_u64(stored.2)? != expected_revision
        || parse_u64(stored.6)? != expected_revision
        || stored.3.as_slice() != command.namespace_commit_id.as_bytes()
        || stored.4.as_slice() != command.root_object_revision_id.as_bytes()
        || stored.5.as_slice() != command.expiry_operation_id.as_bytes()
    {
        return Err(RepositoryError::StaleSnapshot);
    }
    let updated = transaction.execute(
        "UPDATE volume_snapshots
         SET state = 3, removed_at = ?1, revision = ?2
         WHERE snapshot_id = ?3 AND state = 2 AND revision = ?4",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.snapshot_id.as_bytes().as_slice(),
            stored.2,
        ],
    )?;
    if updated != 1 {
        return Err(RepositoryError::StaleSnapshot);
    }
    transaction.execute(
        "INSERT INTO snapshot_root_removals(
            snapshot_id, operation_id, expiry_operation_id, namespace_commit_id,
            root_object_revision_id, removed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            command.snapshot_id.as_bytes().as_slice(),
            context.operation_id.as_bytes().as_slice(),
            command.expiry_operation_id.as_bytes().as_slice(),
            command.namespace_commit_id.as_bytes().as_slice(),
            command.root_object_revision_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::VolumeSnapshot,
        id: command.snapshot_id.as_bytes(),
    })
}

fn validate_expiry_reason(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: RequestVolumeSnapshotExpiry,
    expires_at: Option<i64>,
) -> Result<(), RepositoryError> {
    let eligible = match command.reason {
        SnapshotExpiryReason::Manual => true,
        SnapshotExpiryReason::RetentionAge => {
            expires_at.is_some_and(|expires| expires <= context.occurred_at.get())
        }
        SnapshotExpiryReason::RetentionCount => {
            expiry::count_eligible(transaction, command.snapshot_id)?
        }
    };
    if eligible {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

const fn expiry_reason_code(reason: SnapshotExpiryReason) -> u8 {
    match reason {
        SnapshotExpiryReason::Manual => 1,
        SnapshotExpiryReason::RetentionAge => 2,
        SnapshotExpiryReason::RetentionCount => 3,
    }
}

pub(super) fn list(
    database: &PartitionDatabase,
    volume_id: VolumeId,
    after: Option<&SnapshotCursor>,
    limit: PageLimit,
) -> Result<Page<VolumeSnapshot, SnapshotCursor>, RepositoryError> {
    let lower_name = after.map_or("", |cursor| cursor.canonical_name.as_str());
    let lower_id = after.map_or([0; 16], |cursor| cursor.snapshot_id.as_bytes());
    let row_limit = i64::try_from(
        limit
            .get()
            .checked_add(1)
            .ok_or(RepositoryError::InvalidPageLimit)?,
    )
    .map_err(|_| RepositoryError::InvalidPageLimit)?;
    let mut statement = database.connection().prepare(
        "SELECT snapshot_id, namespace_commit_id, root_object_revision_id,
                display_name, canonical_name, state, protected_from_expiry,
                created_at, expires_at, revision
         FROM volume_snapshots INDEXED BY volume_snapshots_by_volume
         WHERE volume_id = ?1 AND state IN (1, 2)
           AND (canonical_name, snapshot_id) > (?2, ?3)
         ORDER BY canonical_name, snapshot_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            volume_id.as_bytes().as_slice(),
            lower_name,
            lower_id.as_slice(),
            row_limit,
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, i64>(9)?,
            ))
        },
    )?;
    let mut items = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        let row = row?;
        items.push(decode_snapshot(volume_id, row)?);
    }
    let next = (items.len() > limit.get()).then(|| {
        let last = &items[limit.get() - 1];
        SnapshotCursor {
            canonical_name: last.canonical_name.clone(),
            snapshot_id: last.snapshot_id,
        }
    });
    items.truncate(limit.get());
    Ok(Page { items, next })
}

type StoredSnapshot = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    i64,
    i64,
    i64,
    Option<i64>,
    i64,
);

fn decode_snapshot(
    volume_id: VolumeId,
    stored: StoredSnapshot,
) -> Result<VolumeSnapshot, RepositoryError> {
    let state = u8::try_from(stored.5).map_err(|_| RepositoryError::CorruptState)?;
    if !matches!(state, 1..=3) || !matches!(stored.6, 0 | 1) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(VolumeSnapshot {
        snapshot_id: identifier(&stored.0, SnapshotId::from_bytes)?,
        volume_id,
        namespace_commit_id: identifier(&stored.1, NamespaceCommitId::from_bytes)?,
        root_object_revision_id: identifier(&stored.2, ObjectRevisionId::from_bytes)?,
        display_name: stored.3,
        canonical_name: stored.4,
        state,
        protected_from_expiry: stored.6 == 1,
        created_at: UnixMicros::new(stored.7),
        expires_at: stored.8.map(UnixMicros::new),
        revision: Revision::new(
            u64::try_from(stored.9).map_err(|_| RepositoryError::CorruptState)?,
        ),
    })
}

fn identifier<T>(
    bytes: &[u8],
    constructor: fn([u8; 16]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, RepositoryError> {
    constructor(
        bytes
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn parse_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}
