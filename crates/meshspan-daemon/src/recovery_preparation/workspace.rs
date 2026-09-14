// SPDX-License-Identifier: GPL-2.0-only

//! One locked recovery intent, with disposable unpublished work and an immutable publication path.

use super::RecoveryPreparationError as Error;
#[cfg(test)]
#[path = "workspace_tests.rs"]
mod tests;
use crate::protected_file::{self, ProtectedFileError, PublishMode};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

pub(super) struct Workspace {
    root: PathBuf,
    _lock: File,
}

impl Workspace {
    pub(super) fn open(root: &Path, intent: &[u8; 32]) -> Result<Self, Error> {
        match DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => protected_file::sync_parent(root).map_err(|_| Error::Workspace)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(Error::Workspace),
        }
        private_directory(root)?;
        let lock_path = root.join("preparation.lock");
        let lock = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                protected_file::open_read(&lock_path).map_err(|_| Error::Workspace)?
            }
            Err(_) => return Err(Error::Workspace),
        };
        lock.try_lock().map_err(|_| Error::Busy)?;
        let workspace = Self {
            root: root.to_owned(),
            _lock: lock,
        };
        match protected_file::read_bounded(&root.join("intent"), 32, 32) {
            Ok(saved) if saved.as_slice() == intent => {}
            Ok(_) => return Err(Error::Conflict),
            Err(ProtectedFileError::Missing) => workspace.initialise(intent)?,
            Err(_) => return Err(Error::Workspace),
        }
        Ok(workspace)
    }

    pub(super) fn build_directory(&self) -> PathBuf {
        self.root.join("build")
    }

    pub(super) fn begin_build(&self) -> Result<PathBuf, Error> {
        self.cleanup_build()?;
        let directory = self.build_directory();
        DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|_| Error::Workspace)?;
        protected_file::sync_parent(&directory).map_err(|_| Error::Workspace)?;
        Ok(directory)
    }

    pub(super) fn cleanup_build(&self) -> Result<(), Error> {
        let directory = self.build_directory();
        match fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(Error::Cleanup),
            Ok(_) => private_directory(&directory)?,
        }
        // Validate the complete small owned inventory before removing any entry. Unknown
        // siblings or directories are never recursively removed or interpreted as our work.
        let mut files = Vec::new();
        for entry in fs::read_dir(&directory).map_err(|_| Error::Cleanup)? {
            let entry = entry.map_err(|_| Error::Cleanup)?;
            if files.len() >= 256
                || !entry.file_type().map_err(|_| Error::Cleanup)?.is_file()
                || !entry.file_name().to_str().is_some_and(build_file)
            {
                return Err(Error::Cleanup);
            }
            files.push(entry.path());
        }
        for file in files {
            fs::remove_file(file).map_err(|_| Error::Cleanup)?;
        }
        fs::remove_dir(&directory).map_err(|_| Error::Cleanup)?;
        protected_file::sync_parent(&directory).map_err(|_| Error::Cleanup)
    }

    pub(super) fn publish_database(&self, snapshot: &Path) -> Result<(), Error> {
        let file = File::open(snapshot).map_err(|_| Error::Workspace)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .and_then(|()| file.sync_all())
            .map_err(|_| Error::Workspace)?;
        fs::hard_link(snapshot, self.root.join("prepared.sqlite3"))
            .map_err(|_| Error::Workspace)?;
        protected_file::sync_parent(&self.root.join("prepared.sqlite3"))
            .map_err(|_| Error::Workspace)
    }

    pub(super) fn clean_publication_temporary(&self, name: &str) -> Result<(), Error> {
        for attempt in 0..32 {
            let file = self.root.join(format!(".{name}.meshspan-{attempt}.tmp"));
            match fs::symlink_metadata(&file) {
                Ok(metadata) if metadata.is_file() => {
                    fs::remove_file(file).map_err(|_| Error::Cleanup)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                _ => return Err(Error::Cleanup),
            }
        }
        Ok(())
    }

    fn initialise(&self, intent: &[u8; 32]) -> Result<(), Error> {
        for entry in fs::read_dir(&self.root).map_err(|_| Error::Workspace)? {
            let entry = entry.map_err(|_| Error::Workspace)?;
            if !entry.file_type().map_err(|_| Error::Workspace)?.is_file()
                || !entry.file_name().to_str().is_some_and(|name| {
                    name == "preparation.lock" || publication_temporary(name, "intent")
                })
            {
                return Err(Error::Conflict);
            }
        }
        self.clean_publication_temporary("intent")?;
        protected_file::publish(&self.root.join("intent"), intent, PublishMode::Create)
            .map_err(|_| Error::Workspace)
    }
}

fn private_directory(directory: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(directory).map_err(|_| Error::Workspace)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(Error::Workspace);
    }
    Ok(())
}

fn build_file(name: &str) -> bool {
    [
        "plaintext.sqlite3",
        "source.sqlite3",
        "verified.sqlite3",
        "restored.sqlite3",
        "prepared.sqlite3",
        "preparation.tmp",
        "snapshot.sqlite3",
        "filesystem-branch.sqlite3",
        "filesystem-content.sqlite3",
    ]
    .iter()
    .any(|database| {
        name == *database
            || ["-wal", "-shm", "-journal"]
                .iter()
                .any(|suffix| name == format!("{database}{suffix}"))
    }) || [
        "control.bin",
        "secrets.bin",
        "state.msb",
        "state.auth",
        "keys.bundle",
        "installed.json",
        "receipts.bin",
    ]
    .iter()
    .any(|file| name == *file || publication_temporary(name, file))
}

fn publication_temporary(name: &str, file: &str) -> bool {
    (0..32).any(|attempt| name == format!(".{file}.meshspan-{attempt}.tmp"))
}
