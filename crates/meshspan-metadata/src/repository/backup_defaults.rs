// SPDX-License-Identifier: GPL-2.0-only

//! Appliance-owned configuration is distinct from explicit administrator choices.

mod selection;

use meshspan_domain::{DurationMicros, PartitionId, Revision};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{
    AuthoritativeRepository, EntityKind, EntityReference, RepositoryError, backup_schedule,
};
use crate::{CommandContext, ConfigureMetadataBackupSchedule, ReconcileMetadataBackupDefaults};

const DEFAULT_INTERVAL_MICROS: u64 = 86_400_000_000;
const DEFAULT_RETAINED_GENERATIONS: u16 = 3;
const MAXIMUM_DEFAULT_DESTINATIONS: usize = 3;

impl AuthoritativeRepository {
    /// Returns a reconciliation request only after topology or explicit configuration changes.
    ///
    /// Ordinary file writes and transient connectivity do not invalidate default protection.
    ///
    /// # Errors
    /// Rejects malformed or unavailable configuration state.
    pub fn metadata_backup_defaults_candidate(
        &self,
    ) -> Result<Option<ReconcileMetadataBackupDefaults>, RepositoryError> {
        let Some(topology) = self.mesh_configuration_revision()? else {
            return Ok(None);
        };
        let partition_id = self.database.partition_id();
        let state = load(self.database.connection(), partition_id)?;
        if state.is_some_and(|(observed, dirty, _)| observed == topology.get() && !dirty) {
            return Ok(None);
        }
        Ok(Some(ReconcileMetadataBackupDefaults {
            partition_id,
            expected_topology_revision: topology,
            expected_defaults_revision: Revision::new(state.map_or(0, |(_, _, revision)| revision)),
        }))
    }
}

pub(super) fn reconcile(
    transaction: &Transaction<'_>,
    partition: PartitionId,
    context: CommandContext,
    command: ReconcileMetadataBackupDefaults,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let state = load(transaction, partition)?;
    let topology: i64 =
        transaction.query_row("SELECT configuration_revision FROM meshes", [], |row| {
            row.get(0)
        })?;
    if command.partition_id != partition
        || command.expected_topology_revision.get() == 0
        || to_i64(command.expected_topology_revision.get())? != topology
        || command.expected_defaults_revision.get() != state.map_or(0, |(_, _, value)| value)
    {
        return Err(RepositoryError::StaleRevision);
    }
    let selected = selection::reconcile(transaction, partition, context, revision)?;
    reconcile_schedule(transaction, partition, context, revision, selected.len())?;
    transaction.execute(
        "INSERT INTO metadata_backup_defaults(partition_id, topology_revision, dirty, revision)
         VALUES (?1, ?2, 0, ?3) ON CONFLICT(partition_id) DO UPDATE SET
         topology_revision = excluded.topology_revision, dirty = 0, revision = excluded.revision",
        params![
            partition.as_bytes().as_slice(),
            topology,
            to_i64(revision.get())?
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::MetadataBackupSchedule,
        id: partition.as_bytes(),
    })
}

pub(super) fn invalidate(
    transaction: &Transaction<'_>,
    revision: Revision,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "UPDATE metadata_backup_defaults SET dirty = 1, revision = ?1",
        [to_i64(revision.get())?],
    )?;
    Ok(())
}

fn load(
    connection: &Connection,
    partition: PartitionId,
) -> Result<Option<(u64, bool, u64)>, RepositoryError> {
    let stored = connection.query_row("SELECT topology_revision, dirty, revision FROM metadata_backup_defaults WHERE partition_id = ?1",
        [partition.as_bytes().as_slice()], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?, row.get::<_, i64>(2)?))).optional()?;
    stored
        .map(|(topology, dirty, revision)| {
            Ok((
                u64::try_from(topology).map_err(|_| RepositoryError::CorruptState)?,
                dirty,
                u64::try_from(revision).map_err(|_| RepositoryError::CorruptState)?,
            ))
        })
        .transpose()
}

fn reconcile_schedule(
    transaction: &Transaction<'_>,
    partition: PartitionId,
    context: CommandContext,
    revision: Revision,
    destination_count: usize,
) -> Result<(), RepositoryError> {
    let current = backup_schedule::load(transaction, partition)?;
    let origin: Option<i64> = transaction.query_row("SELECT configuration_origin FROM metadata_backup_schedule_heads WHERE partition_id = ?1",
        [partition.as_bytes().as_slice()], |row| row.get(0)).optional()?;
    if origin == Some(2) {
        return Ok(());
    }
    let copies =
        u8::try_from(destination_count.max(1)).map_err(|_| RepositoryError::CapacityExceeded)?;
    if current.is_some_and(|schedule| schedule.minimum_verified_copies == copies) {
        return Ok(());
    }
    backup_schedule::configure(
        transaction,
        partition,
        context,
        ConfigureMetadataBackupSchedule {
            partition_id: partition,
            expected_schedule_sequence: current.map_or(0, |schedule| schedule.sequence),
            interval: DurationMicros::new(DEFAULT_INTERVAL_MICROS),
            retained_generations: DEFAULT_RETAINED_GENERATIONS,
            minimum_verified_copies: copies,
            minimum_independent_copies: 0,
            enabled: true,
            next_due_at: current.map_or(context.occurred_at, |schedule| {
                schedule.next_due_at.max(context.occurred_at)
            }),
        },
        revision,
    )?;
    transaction.execute("UPDATE metadata_backup_schedule_heads SET configuration_origin = 1 WHERE partition_id = ?1",
        [partition.as_bytes().as_slice()])?;
    Ok(())
}
