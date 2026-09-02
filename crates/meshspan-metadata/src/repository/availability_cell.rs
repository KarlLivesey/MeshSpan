// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative availability cells and explicit machine/target membership.

use meshspan_domain::{AvailabilityCellId, HostId, Revision, TargetId};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, Page, PageLimit, RepositoryError};
use crate::{
    CommandContext, CreateAvailabilityCell, PartitionDatabase, SetHostAvailabilityCellMembership,
    SetTargetAvailabilityCellMembership,
};

const ACTIVE_STATE: i64 = 1;
const MANUAL_MEMBERSHIP_SOURCE: i64 = 1;

/// Stable seek position in the availability-cell inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailabilityCellCursor {
    canonical_name: String,
    cell_id: AvailabilityCellId,
}

impl AvailabilityCellCursor {
    /// Reconstructs one validated public continuation cursor.
    #[must_use]
    pub fn new(canonical_name: String, cell_id: AvailabilityCellId) -> Self {
        Self {
            canonical_name,
            cell_id,
        }
    }

    /// Returns the exact canonical seek name.
    #[must_use]
    pub fn canonical_name(&self) -> &str {
        &self.canonical_name
    }

    /// Returns the exact seek identity.
    #[must_use]
    pub const fn cell_id(&self) -> AvailabilityCellId {
        self.cell_id
    }
}

/// One named availability locality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvailabilityCellRecord {
    /// Stable cell identity.
    pub cell_id: AvailabilityCellId,
    /// User-visible cell name.
    pub display_name: String,
    /// Canonical stable seek name.
    pub canonical_name: String,
    /// Optional presentation parent.
    pub parent_cell_id: Option<AvailabilityCellId>,
    /// Last authoritative revision.
    pub revision: Revision,
}

pub(super) fn create(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CreateAvailabilityCell,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if let Some(parent) = command.parent_cell_id {
        require_active_cell(transaction, parent)?;
    }
    transaction.execute(
        "INSERT INTO availability_cells(
            cell_id, display_name, canonical_name, parent_cell_id, state,
            created_by, created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            command.cell_id.as_bytes().as_slice(),
            command.name.display(),
            command.name.canonical(),
            command.parent_cell_id.map(AvailabilityCellId::as_bytes),
            ACTIVE_STATE,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    update_configuration_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::AvailabilityCell,
        id: command.cell_id.as_bytes(),
    })
}

pub(super) fn set_host_membership(
    transaction: &Transaction<'_>,
    command: SetHostAvailabilityCellMembership,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    require_active_cell(transaction, command.cell_id)?;
    require_active_host(transaction, command.host_id)?;
    if command.present {
        transaction.execute(
            "INSERT INTO host_cell_memberships(host_id, cell_id, source_kind, revision)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(host_id, cell_id) DO UPDATE SET
               source_kind = excluded.source_kind, revision = excluded.revision",
            params![
                command.host_id.as_bytes().as_slice(),
                command.cell_id.as_bytes().as_slice(),
                MANUAL_MEMBERSHIP_SOURCE,
                to_i64(revision.get())?,
            ],
        )?;
    } else {
        transaction.execute(
            "DELETE FROM host_cell_memberships WHERE host_id = ?1 AND cell_id = ?2",
            params![
                command.host_id.as_bytes().as_slice(),
                command.cell_id.as_bytes().as_slice(),
            ],
        )?;
    }
    update_configuration_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::AvailabilityCellMembership,
        id: command.cell_id.as_bytes(),
    })
}

pub(super) fn set_target_membership(
    transaction: &Transaction<'_>,
    command: SetTargetAvailabilityCellMembership,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    require_active_cell(transaction, command.cell_id)?;
    require_active_target(transaction, command.target_id)?;
    if command.present {
        transaction.execute(
            "INSERT INTO target_cell_memberships(target_id, cell_id, source_kind, revision)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(target_id, cell_id) DO UPDATE SET
               source_kind = excluded.source_kind, revision = excluded.revision",
            params![
                command.target_id.as_bytes().as_slice(),
                command.cell_id.as_bytes().as_slice(),
                MANUAL_MEMBERSHIP_SOURCE,
                to_i64(revision.get())?,
            ],
        )?;
    } else {
        transaction.execute(
            "DELETE FROM target_cell_memberships WHERE target_id = ?1 AND cell_id = ?2",
            params![
                command.target_id.as_bytes().as_slice(),
                command.cell_id.as_bytes().as_slice(),
            ],
        )?;
    }
    update_configuration_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::AvailabilityCellMembership,
        id: command.cell_id.as_bytes(),
    })
}

pub(super) fn cells(
    database: &PartitionDatabase,
    after: Option<&AvailabilityCellCursor>,
    limit: PageLimit,
) -> Result<Page<AvailabilityCellRecord, AvailabilityCellCursor>, RepositoryError> {
    let after_name = after.map_or("", |cursor| cursor.canonical_name.as_str());
    let after_id = after.map_or([0; 16], |cursor| cursor.cell_id.as_bytes());
    let mut statement = database.connection().prepare(
        "SELECT cell_id, display_name, canonical_name, parent_cell_id, revision
         FROM availability_cells
         WHERE state = ?1 AND (
           canonical_name > ?2 OR (canonical_name = ?2 AND cell_id > ?3)
         )
         ORDER BY canonical_name, cell_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            ACTIVE_STATE,
            after_name,
            after_id.as_slice(),
            i64::try_from(limit.get().saturating_add(1))
                .map_err(|_| RepositoryError::CapacityExceeded)?,
        ],
        decode_cell,
    )?;
    let mut records = rows.collect::<Result<Vec<_>, _>>()?;
    let has_more = records.len() > limit.get();
    if has_more {
        records.pop();
    }
    let next = if has_more {
        records.last().map(|record| {
            AvailabilityCellCursor::new(record.canonical_name.clone(), record.cell_id)
        })
    } else {
        None
    };
    Ok(Page {
        items: records,
        next,
    })
}

pub(super) fn cell(
    database: &PartitionDatabase,
    cell_id: AvailabilityCellId,
) -> Result<Option<AvailabilityCellRecord>, RepositoryError> {
    database
        .connection()
        .query_row(
            "SELECT cell_id, display_name, canonical_name, parent_cell_id, revision
             FROM availability_cells WHERE cell_id = ?1 AND state = ?2",
            params![cell_id.as_bytes().as_slice(), ACTIVE_STATE],
            decode_cell,
        )
        .optional()
        .map_err(RepositoryError::from)
}

/// Returns direct cells plus all presentation ancestors for one target and its host.
pub(super) fn target_cells(
    database: &PartitionDatabase,
    target_id: TargetId,
    host_id: HostId,
) -> Result<Vec<AvailabilityCellId>, RepositoryError> {
    let mut statement = database.connection().prepare(
        "WITH RECURSIVE direct(cell_id) AS (
           SELECT cell_id FROM target_cell_memberships WHERE target_id = ?1
           UNION
           SELECT cell_id FROM host_cell_memberships WHERE host_id = ?2
         ), ancestry(cell_id) AS (
           SELECT cell_id FROM direct
           UNION
           SELECT c.parent_cell_id FROM availability_cells c
             JOIN ancestry a ON c.cell_id = a.cell_id
             WHERE c.parent_cell_id IS NOT NULL
         )
         SELECT DISTINCT a.cell_id FROM ancestry a
         JOIN availability_cells c ON c.cell_id = a.cell_id
         WHERE c.state = ?3 ORDER BY a.cell_id",
    )?;
    let rows = statement.query_map(
        params![
            target_id.as_bytes().as_slice(),
            host_id.as_bytes().as_slice(),
            ACTIVE_STATE,
        ],
        |row| {
            AvailabilityCellId::from_bytes(exact_identifier(row.get(0)?)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)
        },
    )?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(RepositoryError::from)
}

fn require_active_cell(
    transaction: &Transaction<'_>,
    cell_id: AvailabilityCellId,
) -> Result<(), RepositoryError> {
    require_exists(
        transaction,
        "SELECT EXISTS(SELECT 1 FROM availability_cells WHERE cell_id = ?1 AND state = 1)",
        cell_id.as_bytes(),
    )
}

fn require_active_host(
    transaction: &Transaction<'_>,
    host_id: HostId,
) -> Result<(), RepositoryError> {
    require_exists(
        transaction,
        "SELECT EXISTS(SELECT 1 FROM hosts WHERE host_id = ?1 AND state = 1 AND retired_at IS NULL)",
        host_id.as_bytes(),
    )
}

fn require_active_target(
    transaction: &Transaction<'_>,
    target_id: TargetId,
) -> Result<(), RepositoryError> {
    require_exists(
        transaction,
        "SELECT EXISTS(SELECT 1 FROM storage_targets WHERE target_id = ?1 AND state = 1)",
        target_id.as_bytes(),
    )
}

fn require_exists(
    transaction: &Transaction<'_>,
    query: &str,
    identifier: [u8; 16],
) -> Result<(), RepositoryError> {
    let exists: bool = transaction.query_row(query, [identifier.as_slice()], |row| row.get(0))?;
    if exists {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn decode_cell(row: &rusqlite::Row<'_>) -> rusqlite::Result<AvailabilityCellRecord> {
    let parent = row.get::<_, Option<Vec<u8>>>(3)?;
    let revision = u64::try_from(row.get::<_, i64>(4)?)
        .ok()
        .filter(|revision| *revision != 0)
        .ok_or(rusqlite::Error::InvalidQuery)?;
    Ok(AvailabilityCellRecord {
        cell_id: AvailabilityCellId::from_bytes(exact_identifier(row.get(0)?)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        display_name: row.get(1)?,
        canonical_name: row.get(2)?,
        parent_cell_id: parent
            .map(exact_identifier)
            .transpose()?
            .map(AvailabilityCellId::from_bytes)
            .transpose()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        revision: Revision::new(revision),
    })
}

fn update_configuration_revision(
    transaction: &Transaction<'_>,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let updated = transaction.execute(
        "UPDATE meshes SET configuration_revision = ?1, revision = ?1",
        [to_i64(revision.get())?],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn exact_identifier(value: Vec<u8>) -> rusqlite::Result<[u8; 16]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
