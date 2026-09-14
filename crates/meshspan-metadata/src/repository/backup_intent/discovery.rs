// SPDX-License-Identifier: GPL-2.0-only

//! Bounded seek over authoritative abandoned uploads which still lack retirement evidence.

use crate::{
    AbandonedBackupPublication, AuthoritativeRepository, BackupReclamationCursor, Page, PageLimit,
    RepositoryError,
};
use meshspan_domain::{BackupDestinationId, BackupId};
use rusqlite::params;

const DISCOVERY_SQL: &str = "SELECT i.backup_id, i.destination_id FROM backup_publication_intents i
         WHERE (i.backup_id, i.destination_id) > (?1, ?2)
           AND EXISTS (SELECT 1 FROM metadata_backup_runs r WHERE r.backup_id = i.backup_id AND r.state = 5)
           AND NOT EXISTS (SELECT 1 FROM metadata_backups b WHERE b.backup_id = i.backup_id)
           AND NOT EXISTS (SELECT 1 FROM abandoned_backup_retirements a WHERE a.backup_id = i.backup_id AND a.destination_id = i.destination_id)
         ORDER BY i.backup_id, i.destination_id LIMIT ?3";

impl AuthoritativeRepository {
    /// Lists exact unadmitted upload intents after committed abandonment, including paused destinations.
    /// Absence at a provider never removes an intent from this queue.
    /// # Errors
    /// Rejects contradictory run/claim state, invalid rows or unavailable metadata.
    pub fn abandoned_backup_publications(
        &self,
        after: Option<BackupReclamationCursor>,
        limit: PageLimit,
    ) -> Result<Page<AbandonedBackupPublication, BackupReclamationCursor>, RepositoryError> {
        self.with_read_view(|view| page(view, after, limit))?
    }
}

fn page(
    repository: &AuthoritativeRepository,
    after: Option<BackupReclamationCursor>,
    limit: PageLimit,
) -> Result<Page<AbandonedBackupPublication, BackupReclamationCursor>, RepositoryError> {
    let connection = repository.database.connection();
    let lower_backup = after.map_or([0; 16], |cursor| cursor.backup_id.as_bytes());
    let lower_destination = after.map_or([0; 16], |cursor| cursor.destination_id.as_bytes());
    let mut statement = connection.prepare(DISCOVERY_SQL)?;
    let rows = statement.query_map(
        params![
            lower_backup.as_slice(),
            lower_destination.as_slice(),
            i64::try_from(limit.get()).map_err(|_| RepositoryError::CapacityExceeded)? + 1
        ],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
    )?;
    let mut items = Vec::new();
    for row in rows {
        let (backup, destination) = row?;
        let backup = BackupId::from_bytes(
            backup
                .try_into()
                .map_err(|_| RepositoryError::CorruptState)?,
        )
        .map_err(|_| RepositoryError::CorruptState)?;
        let destination = BackupDestinationId::from_bytes(
            destination
                .try_into()
                .map_err(|_| RepositoryError::CorruptState)?,
        )
        .map_err(|_| RepositoryError::CorruptState)?;
        let intent =
            super::load(connection, backup, destination)?.ok_or(RepositoryError::CorruptState)?;
        let run = repository
            .metadata_backup_run(backup)?
            .ok_or(RepositoryError::CorruptState)?;
        if run.completed_at.is_none()
            || run.result_digest.is_none_or(|digest| digest == [0; 32])
            || repository.metadata_backup_run_claim(backup)?.is_some()
        {
            return Err(RepositoryError::CorruptState);
        }
        items.push(AbandonedBackupPublication {
            intent,
            run_revision: run.revision,
        });
    }
    let next = if items.len() > limit.get() {
        items.pop();
        items.last().map(|value| BackupReclamationCursor {
            backup_id: value.intent.binding.object.backup_id,
            destination_id: value.intent.binding.object.destination_id,
        })
    } else {
        None
    };
    Ok(Page { items, next })
}

#[test]
fn discovery_seeks_primary_keys_without_sorting() -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = rusqlite::Connection::open_in_memory()?;
    crate::migration::migrate_partition(&mut connection, 1)?;
    let mut statement = connection.prepare(&format!("EXPLAIN QUERY PLAN {DISCOVERY_SQL}"))?;
    let details = statement
        .query_map(
            params![[0_u8; 16].as_slice(), [0_u8; 16].as_slice(), 2],
            |row| row.get::<_, String>(3),
        )?
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    for expected in [
        "SEARCH i USING PRIMARY KEY",
        "SEARCH r EXISTS USING INDEX sqlite_autoindex_metadata_backup_runs_1",
        "SEARCH b USING COVERING INDEX sqlite_autoindex_metadata_backups_1",
        "SEARCH a USING PRIMARY KEY",
    ] {
        assert!(details.contains(expected), "{details}");
    }
    assert!(!details.contains("TEMP B-TREE"), "{details}");
    Ok(())
}
