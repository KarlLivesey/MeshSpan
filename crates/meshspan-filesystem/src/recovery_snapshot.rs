// SPDX-License-Identifier: GPL-2.0-only

//! Isolated snapshots of surviving filesystem journals for offline recovery verification.

use crate::{
    ContentCatalogError, DurableContentCatalog, PublicationError, VersionPublicationStore,
};
use meshspan_domain::UnixMicros;
use rusqlite::{Connection, MAIN_DB, OpenFlags};
use std::{fs, path::Path};

/// Copies both existing journals using SQLite snapshots without opening the source for writes.
/// The destination must be a caller-owned private directory with neither journal present.
/// Only copied journals are migrated. Partial outputs remain isolated on failure.
///
/// The two read views are not a distributed transaction: callers must verify their complete
/// referenced history/layout closure against the separately selected authoritative roots.
/// This neither copies shards nor grants authority to serve the copied branches.
/// # Errors
/// Rejects missing/non-regular source files, existing destinations, invalid SQLite state,
/// unsupported schemas and filesystem errors.
pub fn snapshot_recovery_journals(
    source: &Path,
    destination: &Path,
    now: UnixMicros,
) -> Result<(VersionPublicationStore, DurableContentCatalog), RecoverySnapshotError> {
    let names = ["filesystem-branch.sqlite3", "filesystem-content.sqlite3"];
    for name in names {
        if !fs::symlink_metadata(source.join(name))?.is_file() {
            return Err(RecoverySnapshotError::InvalidSource);
        }
        match fs::symlink_metadata(destination.join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err(RecoverySnapshotError::DestinationExists),
        }
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let mut history = Connection::open_with_flags(source.join(names[0]), flags)?;
    let mut content = Connection::open_with_flags(source.join(names[1]), flags)?;
    let history_view = history.transaction()?;
    let content_view = content.transaction()?;
    // Materialise both read views before copying either file. Writes on a live donor are
    // not prevented; validation of the requested closure is the cross-journal barrier.
    history_view.query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
        row.get::<_, i64>(0)
    })?;
    content_view.query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
        row.get::<_, i64>(0)
    })?;
    history_view.backup(MAIN_DB, destination.join(names[0]), None)?;
    content_view.backup(MAIN_DB, destination.join(names[1]), None)?;
    history_view.commit()?;
    content_view.commit()?;
    Ok((
        VersionPublicationStore::open(destination, now)?,
        DurableContentCatalog::open(destination, now)?,
    ))
}

/// No snapshot is complete unless both copied journals and their authoritative closure verify.
#[derive(Debug, thiserror::Error)]
pub enum RecoverySnapshotError {
    /// Symlinks and non-regular source entries are not adopted.
    #[error("recovery journal source is not a regular file")]
    InvalidSource,
    /// Never overwrite a previous recovery candidate.
    #[error("recovery journal destination already exists")]
    DestinationExists,
    /// Snapshot IO failed; partial private output may remain.
    #[error("recovery journal filesystem operation failed")]
    Io(#[from] std::io::Error),
    /// SQLite could not read or capture the selected source.
    #[error("recovery journal SQLite snapshot failed")]
    Sqlite(#[from] rusqlite::Error),
    /// The copied namespace journal could not be validated.
    #[error("recovery namespace journal failed validation")]
    History(#[from] PublicationError),
    /// The copied content journal could not be validated.
    #[error("recovery content journal failed validation")]
    Content(#[from] ContentCatalogError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_are_independent_and_leave_source_bytes_unchanged()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = tempfile::tempdir()?;
        let destination = tempfile::tempdir()?;
        let now = UnixMicros::new(1);
        drop(VersionPublicationStore::open(source.path(), now)?);
        drop(DurableContentCatalog::open(source.path(), now)?);
        let names = ["filesystem-branch.sqlite3", "filesystem-content.sqlite3"];
        let before = names
            .iter()
            .map(|name| fs::read(source.path().join(name)))
            .collect::<Result<Vec<_>, _>>()?;

        drop(snapshot_recovery_journals(
            source.path(),
            destination.path(),
            now,
        )?);
        for (name, original) in names.iter().zip(&before) {
            assert_eq!(&fs::read(source.path().join(name))?, original);
            let copy = Connection::open(destination.path().join(name))?;
            let integrity: String =
                copy.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
            assert_eq!(integrity, "ok");
            copy.execute_batch("CREATE TABLE isolated_snapshot_probe(value INTEGER);")?;
            assert_eq!(&fs::read(source.path().join(name))?, original);
        }
        let retained = fs::read(destination.path().join(names[0]))?;
        assert!(matches!(
            snapshot_recovery_journals(source.path(), destination.path(), now),
            Err(RecoverySnapshotError::DestinationExists)
        ));
        assert_eq!(fs::read(destination.path().join(names[0]))?, retained);
        Ok(())
    }

    #[test]
    fn missing_or_invalid_sources_do_not_become_empty_recovery_databases()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = tempfile::tempdir()?;
        let destination = tempfile::tempdir()?;
        let now = UnixMicros::new(1);
        assert!(matches!(
            snapshot_recovery_journals(source.path(), destination.path(), now),
            Err(RecoverySnapshotError::Io(_))
        ));
        assert_eq!(fs::read_dir(source.path())?.count(), 0);
        assert_eq!(fs::read_dir(destination.path())?.count(), 0);

        fs::write(
            source.path().join("filesystem-branch.sqlite3"),
            b"not SQLite",
        )?;
        fs::write(
            source.path().join("filesystem-content.sqlite3"),
            b"not SQLite",
        )?;
        assert!(matches!(
            snapshot_recovery_journals(source.path(), destination.path(), now),
            Err(RecoverySnapshotError::Sqlite(_))
        ));
        assert_eq!(fs::read_dir(destination.path())?.count(), 0);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn source_symlinks_are_not_followed() -> Result<(), Box<dyn std::error::Error>> {
        let source = tempfile::tempdir()?;
        let destination = tempfile::tempdir()?;
        let target = tempfile::NamedTempFile::new()?;
        std::os::unix::fs::symlink(
            target.path(),
            source.path().join("filesystem-branch.sqlite3"),
        )?;
        assert!(matches!(
            snapshot_recovery_journals(source.path(), destination.path(), UnixMicros::new(1)),
            Err(RecoverySnapshotError::InvalidSource)
        ));
        assert_eq!(fs::read_dir(destination.path())?.count(), 0);
        assert!(fs::read(target.path())?.is_empty());
        Ok(())
    }
}
