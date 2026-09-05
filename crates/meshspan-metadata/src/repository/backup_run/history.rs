// SPDX-License-Identifier: GPL-2.0-only

//! Bounded newest-first run history. Completion is historical, not current protection.

use meshspan_domain::{BackupId, PartitionId};
use rusqlite::{Connection, params};

use super::MetadataBackupRun;
use crate::repository::{Page, PageLimit, RepositoryError};

const HISTORY_SQL: &str = "SELECT backup_id FROM metadata_backup_runs
    WHERE partition_id = ?1 AND run_sequence <= ?2
    ORDER BY run_sequence DESC LIMIT ?3";

pub(in crate::repository) fn page(
    connection: &Connection,
    partition: PartitionId,
    before: Option<u64>,
    limit: PageLimit,
) -> Result<Page<MetadataBackupRun, u64>, RepositoryError> {
    let upper = match before {
        Some(sequence) => i64::try_from(sequence)
            .ok()
            .and_then(|value| value.checked_sub(1))
            .filter(|value| *value >= 0)
            .ok_or(RepositoryError::InvalidCommand)?,
        None => i64::MAX,
    };
    let mut statement = connection.prepare(HISTORY_SQL)?;
    let fetch_limit =
        i64::try_from(limit.get() + 1).map_err(|_| RepositoryError::InvalidPageLimit)?;
    let rows = statement.query_map(
        params![partition.as_bytes().as_slice(), upper, fetch_limit],
        |row| row.get::<_, Vec<u8>>(0),
    )?;
    let mut items = Vec::new();
    for bytes in rows {
        let identity = bytes?
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?;
        let backup = BackupId::from_bytes(identity).map_err(|_| RepositoryError::CorruptState)?;
        items.push(super::load(connection, backup)?.ok_or(RepositoryError::CorruptState)?);
    }
    let next = if items.len() > limit.get() {
        items.truncate(limit.get());
        items.last().map(|run| run.run_sequence)
    } else {
        None
    };
    Ok(Page { items, next })
}
