// SPDX-License-Identifier: GPL-2.0-only

//! Durable lookup over isolated pack copies; original target journals are not required.

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::{
    fs,
    path::{Path, PathBuf},
};

use super::{
    RecoveryFolder, RecoveryShardRetention, RecoveryStorageError as Error, workspace::Workspace,
};
use crate::pack::PackStore;
use meshspan_contracts::{BoundedBytes, ShardIdentity};

mod manifest;
mod repository;
use repository::{CandidateMatch, Repository};

/// One exclusively owned, restartable inventory bound to an independently selected backup scope.
/// This stages encrypted source copies, not live providers or proof of file recoverability.
pub struct RecoveryInventory {
    directory: PathBuf,
    repository: Repository,
    _lock: fs::File,
}

/// Catalogue completeness and copy accounting, not verified physical/file-byte readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryInventorySummary {
    /// Complete staged pack copies.
    pub packs: u64,
    /// Active or tombstoned locator records; independent byte checks are still required.
    pub retained_shards: u64,
    /// Source bytes copied, excluding SQLite/index overhead.
    pub copied_bytes: u64,
}

impl RecoveryInventory {
    /// Creates a new private inventory for the exact nonzero caller-supplied recovery scope.
    /// `maximum_copied_bytes` bounds cumulative source copies, not total filesystem overhead.
    /// Existing directories are never overwritten. No source media are read at creation.
    /// # Errors
    /// Rejects invalid scope/budget, existing destinations and filesystem/database failures.
    pub fn create(
        directory: &Path,
        scope: [u8; 32],
        maximum_copied_bytes: u64,
    ) -> Result<Self, Error> {
        if scope == [0; 32]
            || maximum_copied_bytes == 0
            || i64::try_from(maximum_copied_bytes).is_err()
        {
            return Err(Error::InvalidInput);
        }
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(directory)?;
        let directory = fs::canonicalize(directory)?;
        let lock = private_file(&directory.join("inventory.lock"), true)?;
        lock.try_lock().map_err(|_| Error::AlreadyOwned)?;
        private_file(&directory.join("inventory.sqlite3"), true)?.sync_all()?;
        let repository = Repository::create(
            &directory.join("inventory.sqlite3"),
            scope,
            maximum_copied_bytes,
        )?;
        sync_directory(&directory)?;
        Ok(Self {
            directory,
            repository,
            _lock: lock,
        })
    }

    /// Reopens this exact private recovery scope without reopening or modifying original media.
    /// Pending copies remain invisible and are rebuilt by the next matching `capture_pack` call.
    /// # Errors
    /// Rejects substituted scope, symlinks, unsafe Unix permissions, concurrent ownership or IO.
    pub fn open(directory: &Path, scope: [u8; 32]) -> Result<Self, Error> {
        if scope == [0; 32] {
            return Err(Error::InvalidInput);
        }
        require_private(directory, true)?;
        let directory = fs::canonicalize(directory)?;
        let lock = private_file(&directory.join("inventory.lock"), false)?;
        lock.try_lock().map_err(|_| Error::AlreadyOwned)?;
        require_private(&directory.join("inventory.sqlite3"), false)?;
        let repository = Repository::open(&directory.join("inventory.sqlite3"), scope)?;
        Ok(Self {
            directory,
            repository,
            _lock: lock,
        })
    }

    /// Captures and indexes one pack once; an exact completed retry reuses its immutable copy.
    /// Original media stay exclusively held while copying. Only the owned pending scratch copy
    /// may be rebuilt after interruption; completed copies are never silently replaced.
    /// # Errors
    /// Rejects source/identity conflicts, exhausted copy budget, corruption and interrupted IO.
    pub fn capture_pack(&mut self, source: &RecoveryFolder, sequence: u64) -> Result<(), Error> {
        if self.directory.starts_with(&source.canonical_path)
            || sequence == 0
            || i64::try_from(sequence).is_err()
        {
            return Err(Error::InvalidInput);
        }
        let pending = self.repository.reserve(source.marker(), sequence)?;
        if pending.complete {
            return Ok(());
        }
        let scratch = pack_directory(&self.directory, pending.id)?;
        Workspace::remove_pending(&scratch)?;
        self.repository.reset_pending(pending.id)?;
        let remaining = self.repository.remaining_bytes()?;
        let pack = source.open_pack(sequence, &scratch, remaining)?;
        let mut after = 0;
        loop {
            let page = pack.inventory_page(after, 256)?;
            self.repository.append(pending.id, &page.records)?;
            match page.next_after_record {
                Some(next) => after = next,
                None => break,
            }
        }
        let copied_bytes = pack.workspace.copied_bytes();
        pack.workspace.sync()?;
        drop(pack);
        sync_directory(&self.directory)?;
        self.repository.complete(pending.id, copied_bytes)?;
        Ok(())
    }

    /// Looks up exact independently expected shard evidence without scanning unrelated packs.
    /// Tries surviving duplicate copies after absent/corrupt bytes, but never fabricates success.
    /// # Errors
    /// Rejects invalid lengths, catalogue/path corruption and filesystem/database failures.
    pub fn read_exact(
        &self,
        shard: ShardIdentity,
        length: u64,
        digest: [u8; 32],
    ) -> Result<Option<BoundedBytes>, Error> {
        self.read_matching(CandidateMatch::Exact(shard), length, digest)
    }

    /// Recovers independently expected immutable bytes across physical repair generations.
    /// Only manifest identity, coding position, length and digest select candidates. Each copy
    /// is then read under its actual physical identity and reverified. Returned bytes confer no
    /// placement, deletion or write authority, and never claim that an older receipt survived.
    /// # Errors
    /// Rejects malformed identities/lengths, catalogue/path corruption and IO failures.
    pub fn read_content_shard(
        &self,
        shard: ShardIdentity,
        length: u64,
        digest: [u8; 32],
    ) -> Result<Option<BoundedBytes>, Error> {
        if shard.generation == 0 || shard.manifest_digest == [0; 32] || digest == [0; 32] {
            return Err(Error::InvalidInput);
        }
        self.read_matching(CandidateMatch::Content(shard), length, digest)
    }

    /// Returns copy/locator counts only if no reserved pack is incomplete.
    /// # Errors
    /// Rejects pending work, malformed accounting or database failures.
    pub fn summary(&self) -> Result<RecoveryInventorySummary, Error> {
        self.repository.summary()
    }

    fn read_matching(
        &self,
        selection: CandidateMatch,
        length: u64,
        digest: [u8; 32],
    ) -> Result<Option<BoundedBytes>, Error> {
        if length == 0 || length > 64 * 1024 * 1024 {
            return Err(Error::InvalidInput);
        }
        let mut after = None;
        while let Some(candidate) = self
            .repository
            .candidate(selection, length, digest, after)?
        {
            after = Some((candidate.shard, candidate.pack.id));
            let directory = pack_directory(&self.directory, candidate.pack.id)?;
            match validate_copy(&directory) {
                Ok(()) => {}
                Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            }
            let Ok(pack) = PackStore::open_recovery(
                &directory.join("pack.sqlite3"),
                candidate.pack.marker,
                candidate.pack.sequence,
            ) else {
                continue;
            };
            match pack.recover_bytes(candidate.shard) {
                Ok(bytes)
                    if u64::try_from(bytes.len()).ok() == Some(length)
                        && blake3::hash(bytes.as_slice()).as_bytes() == &digest =>
                {
                    return Ok(Some(bytes));
                }
                Ok(_) | Err(_) => {}
            }
        }
        Ok(None)
    }
}

/// Missing copies are unavailable candidates; substituted paths are not safe to open.
fn validate_copy(directory: &Path) -> Result<(), Error> {
    require_private(directory, true)?;
    for name in [
        "pack.sqlite3",
        "pack.sqlite3-wal",
        "pack.sqlite3-shm",
        "pack.sqlite3-journal",
    ] {
        match require_private(&directory.join(name), false) {
            Ok(()) => {}
            Err(Error::Io(error))
                if error.kind() == std::io::ErrorKind::NotFound && name != "pack.sqlite3" => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn pack_directory(directory: &Path, id: i64) -> Result<PathBuf, Error> {
    if id <= 0 {
        return Err(Error::Corrupt);
    }
    Ok(directory.join(format!("pack-{id:016x}")))
}

fn private_file(file: &Path, create: bool) -> Result<fs::File, Error> {
    if !create {
        require_private(file, false)?;
    }
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create_new(create);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed());
    Ok(options.open(file)?)
}

fn require_private(file: &Path, directory: bool) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(file)?;
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(Error::InvalidInput);
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

fn sync_directory(directory: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}
