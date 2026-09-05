// SPDX-License-Identifier: GPL-2.0-only

//! A small sticky destination set prefers distinct declared failure boundaries.

use meshspan_domain::{BackupDestinationId, PartitionId, Revision, TargetId, uuid_v8};
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::MAXIMUM_DEFAULT_DESTINATIONS;
use crate::repository::apply::to_i64;
use crate::repository::{BackupDestinationState, RepositoryError, backup_catalogue};
use crate::{
    BackupDestinationBinding, BackupFailureRelationship, CommandContext,
    ConfigureBackupDestination, RecordName,
};

pub(super) fn reconcile(
    transaction: &Transaction<'_>,
    partition: PartitionId,
    context: CommandContext,
    revision: Revision,
) -> Result<Vec<BackupDestinationId>, RepositoryError> {
    let mut selected = explicit_destinations(transaction)?;
    let mut targets = Vec::new();
    for destination_id in &selected {
        if let Some(record) = backup_catalogue::destination(transaction, *destination_id)?
            && let BackupDestinationBinding::RegisteredTarget { target_id, .. } = record.binding
        {
            targets.push(target_id);
        }
    }
    while selected.len() < MAXIMUM_DEFAULT_DESTINATIONS {
        let Some((target, generation)) = next_target(transaction, &targets)? else {
            break;
        };
        selected.push(configure(
            transaction,
            partition,
            context,
            revision,
            (target, generation),
        )?);
        targets.push(target);
    }
    pause_unselected(transaction, &selected, revision)?;
    Ok(selected)
}

fn explicit_destinations(
    transaction: &Transaction<'_>,
) -> Result<Vec<BackupDestinationId>, RepositoryError> {
    let mut statement = transaction.prepare(
        "SELECT destination_id FROM backup_destinations
        WHERE configuration_origin = 2 AND state = 1 ORDER BY destination_id LIMIT 3",
    )?;
    statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .map(|bytes| {
            BackupDestinationId::from_bytes(
                bytes?
                    .try_into()
                    .map_err(|_| RepositoryError::CorruptState)?,
            )
            .map_err(|_| RepositoryError::CorruptState)
        })
        .collect()
}

fn next_target(
    transaction: &Transaction<'_>,
    selected: &[TargetId],
) -> Result<Option<(TargetId, u64)>, RepositoryError> {
    let bindings = selected_bindings(selected.iter().map(|value| value.as_bytes()));
    let stored = transaction
        .query_row(
            NEXT_TARGET_SQL,
            params![
                bindings[0].as_slice(),
                bindings[1].as_slice(),
                bindings[2].as_slice()
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    stored
        .map(|(target, generation)| {
            Ok((
                TargetId::from_bytes(
                    target
                        .try_into()
                        .map_err(|_| RepositoryError::CorruptState)?,
                )
                .map_err(|_| RepositoryError::CorruptState)?,
                u64::try_from(generation).map_err(|_| RepositoryError::CorruptState)?,
            ))
        })
        .transpose()
}

// Topology changes evaluate eligible inventory at most three times. The rank
// uses indexed identity/overlap lookups, not an assumed indexed global ordering.
const NEXT_TARGET_SQL: &str = "SELECT st.target_id, st.current_generation FROM storage_targets st
         JOIN target_generations tg ON tg.target_id = st.target_id AND tg.generation = st.current_generation
         JOIN nodes n ON n.node_id = st.node_id JOIN hosts h ON h.host_id = st.host_id
         WHERE st.state = 1 AND st.draining_at IS NULL AND st.retired_at IS NULL
           AND tg.state = 1 AND tg.retired_at IS NULL AND n.state = 2 AND n.retired_at IS NULL
           AND h.state = 1 AND h.retired_at IS NULL AND st.target_id NOT IN (?1, ?2, ?3)
           AND NOT EXISTS (SELECT 1 FROM backup_destinations b WHERE b.target_id = st.target_id
               AND b.provider_generation = st.current_generation AND b.configuration_origin = 2)
           AND NOT EXISTS (SELECT 1 FROM storage_scope_drains d WHERE
               (d.scope_kind = 1 AND d.scope_id = st.node_id) OR (d.scope_kind = 2 AND EXISTS(
                   SELECT 1 FROM host_fault_group_memberships f WHERE f.host_id = st.host_id AND f.group_id = d.scope_id)))
         ORDER BY
           EXISTS (SELECT 1 FROM storage_targets picked WHERE picked.target_id IN (?1, ?2, ?3)
             AND (picked.host_id = st.host_id OR EXISTS(
               SELECT 1 FROM host_fault_group_memberships a JOIN host_fault_group_memberships b USING(group_id)
               WHERE a.host_id = st.host_id AND b.host_id = picked.host_id))),
           EXISTS (SELECT 1 FROM storage_targets picked WHERE picked.target_id IN (?1, ?2, ?3) AND picked.host_id = st.host_id),
           EXISTS (SELECT 1 FROM storage_targets picked JOIN target_generations pg
               ON pg.target_id = picked.target_id AND pg.generation = picked.current_generation
               WHERE picked.target_id IN (?1, ?2, ?3) AND picked.host_id = st.host_id
                 AND ((tg.backing_device_fingerprint IS NOT NULL AND tg.backing_device_fingerprint = pg.backing_device_fingerprint)
                   OR (tg.filesystem_fingerprint IS NOT NULL AND tg.filesystem_fingerprint = pg.filesystem_fingerprint))),
           NOT EXISTS (SELECT 1 FROM backup_destinations b WHERE b.target_id = st.target_id
               AND b.provider_generation = st.current_generation AND b.configuration_origin = 1 AND b.state = 1),
           st.host_id, st.target_id LIMIT 1";

fn configure(
    transaction: &Transaction<'_>,
    partition: PartitionId,
    context: CommandContext,
    revision: Revision,
    target: (TargetId, u64),
) -> Result<BackupDestinationId, RepositoryError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.backup-default-destination.v1\0");
    digest.update(partition.as_bytes());
    digest.update(target.0.as_bytes());
    digest.update(target.1.to_be_bytes());
    let evidence: [u8; 32] = digest.finalize().into();
    let mut identity = [0; 16];
    identity.copy_from_slice(&evidence[..16]);
    let destination_id = BackupDestinationId::from_bytes(uuid_v8(identity))
        .map_err(|_| RepositoryError::CorruptState)?;
    let existing = backup_catalogue::destination(transaction, destination_id)?;
    let binding = BackupDestinationBinding::RegisteredTarget {
        target_id: target.0,
        target_generation: target.1,
    };
    if existing.as_ref().is_some_and(|record| {
        record.binding == binding && record.state == BackupDestinationState::Active
    }) {
        return Ok(destination_id);
    }
    backup_catalogue::configure_destination(
        transaction,
        context,
        &ConfigureBackupDestination {
            destination_id,
            expected_destination_revision: existing
                .map_or(Revision::new(0), |record| record.revision),
            name: RecordName::new(&format!(
                "Automatic backup {:032x}",
                u128::from_be_bytes(destination_id.as_bytes())
            ))
            .map_err(|_| RepositoryError::InvalidCommand)?,
            binding,
            failure_relationship: BackupFailureRelationship::Unknown,
            failure_evidence_digest: evidence,
            enabled: true,
        },
        revision,
    )?;
    transaction.execute(
        "UPDATE backup_destinations SET configuration_origin = 1 WHERE destination_id = ?1",
        [destination_id.as_bytes().as_slice()],
    )?;
    Ok(destination_id)
}

fn pause_unselected(
    transaction: &Transaction<'_>,
    selected: &[BackupDestinationId],
    revision: Revision,
) -> Result<(), RepositoryError> {
    let bindings = selected_bindings(selected.iter().map(|value| value.as_bytes()));
    transaction.execute(
        "UPDATE backup_destinations SET state = 2, revision = ?4
        WHERE configuration_origin = 1 AND state = 1 AND destination_id NOT IN (?1, ?2, ?3)",
        params![
            bindings[0].as_slice(),
            bindings[1].as_slice(),
            bindings[2].as_slice(),
            to_i64(revision.get())?
        ],
    )?;
    Ok(())
}

fn selected_bindings(values: impl Iterator<Item = [u8; 16]>) -> [[u8; 16]; 3] {
    let mut result = [[0; 16]; 3];
    for (slot, value) in result.iter_mut().zip(values) {
        *slot = value;
    }
    result
}

#[test]
fn destination_selection_uses_identity_indexes_for_correlated_lookups()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database = crate::PartitionDatabase::open(
        &directory.path().join("selection.sqlite3"),
        PartitionId::from_bytes([1; 16])?,
        meshspan_domain::UnixMicros::new(1),
    )?;
    let mut statement = database
        .connection()
        .prepare(&format!("EXPLAIN QUERY PLAN {NEXT_TARGET_SQL}"))?;
    let empty = [0_u8; 16];
    let plan = statement
        .query_map(
            params![empty.as_slice(), empty.as_slice(), empty.as_slice()],
            |row| row.get::<_, String>(3),
        )?
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    for expected in [
        "storage_targets_backup_selection",
        "backup_destination_target_binding",
        "SEARCH picked",
        "SEARCH tg",
        "SEARCH a",
        "SEARCH b",
    ] {
        assert!(plan.contains(expected), "missing {expected}: {plan}");
    }
    // A changing overlap score requires a bounded top-one ordering step.
    assert!(plan.contains("USE TEMP B-TREE FOR ORDER BY"), "{plan}");
    Ok(())
}
