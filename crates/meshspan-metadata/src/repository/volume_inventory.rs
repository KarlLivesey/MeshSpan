// SPDX-License-Identifier: GPL-2.0-only

//! Indexed logical-volume candidates for permission-filtered inventories.

use meshspan_domain::{ObjectId, Revision, UnixMicros, VolumeId};
use rusqlite::OptionalExtension;
use rusqlite::params;

use super::{Page, PageLimit, RepositoryError};
use crate::PartitionDatabase;

/// Stable seek position for the global logical-volume index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeInventoryCursor {
    canonical_name: String,
    volume_id: VolumeId,
}

impl VolumeInventoryCursor {
    /// Reconstructs a cursor after the public boundary validates both fields.
    #[must_use]
    pub fn new(canonical_name: String, volume_id: VolumeId) -> Self {
        Self {
            canonical_name,
            volume_id,
        }
    }

    /// Returns the exact canonical seek name.
    #[must_use]
    pub fn canonical_name(&self) -> &str {
        &self.canonical_name
    }

    /// Returns the final stable identity seek key.
    #[must_use]
    pub const fn volume_id(&self) -> VolumeId {
        self.volume_id
    }
}

/// One logical-volume candidate whose root still requires current access evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeInventoryRecord {
    /// Stable logical-volume identity.
    pub volume_id: VolumeId,
    /// Stable root object used for permission evaluation.
    pub root_object_id: ObjectId,
    /// Case-preserved name.
    pub display_name: String,
    /// Canonical seek name.
    pub canonical_name: String,
    /// Lifecycle code from 1 through 4.
    pub state: u8,
    /// Original authoritative creation instant.
    pub created_at: UnixMicros,
    /// Last authoritative metadata revision.
    pub revision: Revision,
}

pub(super) fn volume_inventory_candidates(
    database: &PartitionDatabase,
    after: Option<&VolumeInventoryCursor>,
    limit: PageLimit,
) -> Result<Page<VolumeInventoryRecord, VolumeInventoryCursor>, RepositoryError> {
    let lower_name = after.map_or("", VolumeInventoryCursor::canonical_name);
    let lower_id = after.map_or([0; 16], |cursor| cursor.volume_id().as_bytes());
    let mut statement = database.connection().prepare(
        "SELECT volume.volume_id, root.object_id, volume.display_name,
                volume.canonical_name, volume.state, volume.created_at, volume.revision
         FROM volumes AS volume
         JOIN namespace_objects AS root
           ON root.volume_id = volume.volume_id AND root.parent_object_id IS NULL
         WHERE (volume.canonical_name, volume.volume_id) > (?1, ?2)
         ORDER BY volume.canonical_name, volume.volume_id
         LIMIT ?3",
    )?;
    let sql_limit = i64::try_from(limit.get().saturating_add(1))
        .map_err(|_| RepositoryError::InvalidPageLimit)?;
    let rows = statement.query_map(params![lower_name, lower_id.as_slice(), sql_limit], |row| {
        Ok(StoredVolume {
            volume_id: row.get(0)?,
            root_object_id: row.get(1)?,
            display_name: row.get(2)?,
            canonical_name: row.get(3)?,
            state: row.get(4)?,
            created_at: row.get(5)?,
            revision: row.get(6)?,
        })
    })?;
    let mut items = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        items.push(parse_record(row?)?);
    }
    let next = (items.len() > limit.get()).then(|| cursor(&items[limit.get() - 1]));
    items.truncate(limit.get());
    Ok(Page { items, next })
}

pub(super) fn volume_inventory_record(
    database: &PartitionDatabase,
    volume_id: VolumeId,
) -> Result<Option<VolumeInventoryRecord>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT volume.volume_id, root.object_id, volume.display_name,
                    volume.canonical_name, volume.state, volume.created_at, volume.revision
             FROM volumes AS volume
             JOIN namespace_objects AS root
               ON root.volume_id = volume.volume_id AND root.parent_object_id IS NULL
             WHERE volume.volume_id = ?1",
            [volume_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredVolume {
                    volume_id: row.get(0)?,
                    root_object_id: row.get(1)?,
                    display_name: row.get(2)?,
                    canonical_name: row.get(3)?,
                    state: row.get(4)?,
                    created_at: row.get(5)?,
                    revision: row.get(6)?,
                })
            },
        )
        .optional()?;
    stored.map(parse_record).transpose()
}

struct StoredVolume {
    volume_id: Vec<u8>,
    root_object_id: Vec<u8>,
    display_name: String,
    canonical_name: String,
    state: i64,
    created_at: i64,
    revision: i64,
}

fn parse_record(stored: StoredVolume) -> Result<VolumeInventoryRecord, RepositoryError> {
    let state = u8::try_from(stored.state).map_err(|_| RepositoryError::CorruptState)?;
    if !(1..=4).contains(&state)
        || stored.display_name.is_empty()
        || stored.canonical_name.is_empty()
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(VolumeInventoryRecord {
        volume_id: VolumeId::from_bytes(identifier(&stored.volume_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        root_object_id: ObjectId::from_bytes(identifier(&stored.root_object_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        display_name: stored.display_name,
        canonical_name: stored.canonical_name,
        state,
        created_at: UnixMicros::new(stored.created_at),
        revision: Revision::new(
            u64::try_from(stored.revision).map_err(|_| RepositoryError::CorruptState)?,
        ),
    })
}

fn cursor(record: &VolumeInventoryRecord) -> VolumeInventoryCursor {
    VolumeInventoryCursor::new(record.canonical_name.clone(), record.volume_id)
}

fn identifier(value: &[u8]) -> Result<[u8; 16], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}
