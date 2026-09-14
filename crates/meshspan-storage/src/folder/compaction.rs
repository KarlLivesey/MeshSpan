// SPDX-License-Identifier: GPL-2.0-only

//! Fixed provider-private compaction names and durable atomic replacement.

use std::path::PathBuf;

use super::{PACK_DIRECTORY, RegisteredFolder, StorageFolderError, sync_directory};

impl RegisteredFolder {
    pub(crate) fn prepare_compaction(&self, sequence: u64) -> Result<PathBuf, StorageFolderError> {
        let original = self.pack_database_path(sequence)?;
        let directory = self.private_directory.open_dir(PACK_DIRECTORY)?;
        let pending_name = format!("{sequence:016x}.compact.sqlite3");
        // The original remains authoritative until atomic rename. These fixed scratch names
        // are exclusively owned by this provider, including after an interrupted copy.
        directory.open(format!("{sequence:016x}.sqlite3"))?;
        for suffix in ["", "-wal", "-shm", "-journal"] {
            match directory.remove_file(format!("{pending_name}{suffix}")) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let mut options = cap_std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        directory.open_with(&pending_name, &options)?.sync_all()?;
        sync_directory(&directory)?;
        Ok(original.with_file_name(pending_name))
    }

    /// Caller has closed both SQLite handles and holds the exclusive provider/read lock.
    pub(crate) fn publish_compaction(&self, sequence: u64) -> Result<(), StorageFolderError> {
        let directory = self.private_directory.open_dir(PACK_DIRECTORY)?;
        let installed = format!("{sequence:016x}.sqlite3");
        let pending = format!("{sequence:016x}.compact.sqlite3");
        directory.open(&pending)?.sync_all()?;
        for name in [&installed, &pending] {
            for suffix in ["-wal", "-shm", "-journal"] {
                match directory.symlink_metadata(format!("{name}{suffix}")) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err(StorageFolderError::CapabilityProbeFailed),
                }
            }
        }
        // Persist old WAL removal before publishing a new main DB at its former name.
        sync_directory(&directory)?;
        directory.rename(&pending, &directory, &installed)?;
        sync_directory(&directory)
    }
}
