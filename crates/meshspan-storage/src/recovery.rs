// SPDX-License-Identifier: GPL-2.0-only

//! Offline encrypted-byte salvage. No source writes, registration, repair or serving authority.

use crate::{MarkerFingerprint, TargetMarker, pack::PackStore};
use cap_std::{ambient_authority, fs::Dir};
use meshspan_contracts::{BoundedBytes, ShardIdentity};
use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
};

mod inventory;
#[cfg(test)]
mod tests;
mod workspace;
pub use inventory::{RecoveryInventory, RecoveryInventorySummary};

/// Exclusively held surviving media, bound to a fingerprint from a verified backup.
/// This is physical read access, not user/service authorisation or target re-admission.
pub struct RecoveryFolder {
    canonical_path: PathBuf,
    packs: Dir,
    marker: TargetMarker,
    _lock: fs::File,
}

impl RecoveryFolder {
    /// Opens existing media without probes, marker creation, journal recovery or source writes.
    ///
    /// `expected` must come from independently verified recovery metadata, not this folder.
    /// The returned guard excludes normal `MeshSpan` writers until every borrowed pack closes.
    ///
    /// # Errors
    /// Rejects absent/changed markers, symlinks inside the selected folder, a live owner and IO.
    pub fn open(
        storage_path: &Path,
        expected: MarkerFingerprint,
    ) -> Result<Self, RecoveryStorageError> {
        let canonical_path = fs::canonicalize(storage_path)?;
        let private = canonical_path.join(".meshspan");
        require_directory(&private)?;
        let packs_path = private.join("packs");
        require_directory(&packs_path)?;
        require_file(&private.join("target.lock"))?;
        let lock = fs::File::open(private.join("target.lock"))?;
        lock.try_lock()
            .map_err(|_| RecoveryStorageError::AlreadyOwned)?;
        require_file(&private.join("target.marker"))?;
        let mut bytes = Vec::with_capacity(crate::marker::MARKER_BYTES);
        fs::File::open(private.join("target.marker"))?
            .take(
                u64::try_from(crate::marker::MARKER_BYTES + 1)
                    .map_err(|_| RecoveryStorageError::InvalidInput)?,
            )
            .read_to_end(&mut bytes)?;
        let marker =
            TargetMarker::decode(&bytes).map_err(|_| RecoveryStorageError::IdentityMismatch)?;
        if marker.fingerprint() != expected {
            return Err(RecoveryStorageError::IdentityMismatch);
        }
        let packs = Dir::open_ambient_dir(&packs_path, ambient_authority())?;
        Ok(Self {
            canonical_path,
            packs,
            marker,
            _lock: lock,
        })
    }

    /// Exact media identity, independently bound by the expected marker fingerprint.
    #[must_use]
    pub const fn marker(&self) -> TargetMarker {
        self.marker
    }

    /// Streams pack identities once, without collecting all files in memory or requiring a journal.
    /// Order is unspecified; a restart may revisit packs. Callers own durable progress by identity.
    ///
    /// # Errors
    /// Returns IO or malformed-entry errors, never an invented empty inventory.
    pub fn pack_sequences(&self) -> Result<RecoveryPackSequences<'_>, RecoveryStorageError> {
        Ok(RecoveryPackSequences {
            entries: self.packs.entries()?,
            _folder: self,
        })
    }

    /// Copies one existing pack and crash journals into a new private workspace, then verifies it.
    /// `maximum_copy_bytes` bounds total source bytes staged. SQLite can recover only this copy.
    /// Call `RecoveryPack::finish` after inspection to remove the workspace. Errors may leave a
    /// partial private workspace; they never overwrite or repair the source or existing output.
    ///
    /// # Errors
    /// Rejects missing, substituted, corrupt or unsupported packs and unsafe sidecar paths.
    pub fn open_pack(
        &self,
        sequence: u64,
        workspace: &Path,
        maximum_copy_bytes: u64,
    ) -> Result<RecoveryPack<'_>, RecoveryStorageError> {
        if sequence == 0 || i64::try_from(sequence).is_err() {
            return Err(RecoveryStorageError::InvalidInput);
        }
        let workspace = std::env::current_dir()?.join(workspace);
        let parent = fs::canonicalize(
            workspace
                .parent()
                .ok_or(RecoveryStorageError::InvalidInput)?,
        )?;
        let workspace = parent.join(
            workspace
                .file_name()
                .ok_or(RecoveryStorageError::InvalidInput)?,
        );
        if workspace.starts_with(&self.canonical_path) {
            return Err(RecoveryStorageError::InvalidInput);
        }
        let name = format!("{sequence:016x}.sqlite3");
        let file_path = self.canonical_path.join(".meshspan/packs").join(&name);
        require_file(&file_path)?;
        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = file_path.with_file_name(format!("{name}{suffix}"));
            match fs::symlink_metadata(&sidecar) {
                Ok(metadata) if metadata.is_file() => {}
                Ok(_) => return Err(RecoveryStorageError::InvalidInput),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let workspace = workspace::Workspace::capture(&file_path, &workspace, maximum_copy_bytes)?;
        let pack = PackStore::open_recovery(&workspace.database(), self.marker, sequence)
            .map_err(|_| RecoveryStorageError::Corrupt)?;
        Ok(RecoveryPack {
            pack,
            workspace,
            _folder: self,
        })
    }
}

/// Bounded-memory physical directory scan. Holding it keeps the target owner lock alive.
pub struct RecoveryPackSequences<'a> {
    entries: cap_std::fs::ReadDir,
    _folder: &'a RecoveryFolder,
}

impl Iterator for RecoveryPackSequences<'_> {
    type Item = Result<u64, RecoveryStorageError>;

    fn next(&mut self) -> Option<Self::Item> {
        for entry in self.entries.by_ref() {
            match entry.and_then(|entry| Ok((entry.file_name(), entry.file_type()?))) {
                Ok((name, kind)) if kind.is_file() => {
                    let Some(name) = name.to_str() else {
                        return Some(Err(RecoveryStorageError::InvalidInput));
                    };
                    let base = name
                        .strip_suffix("-wal")
                        .or_else(|| name.strip_suffix("-shm"))
                        .or_else(|| name.strip_suffix("-journal"))
                        .unwrap_or(name);
                    let sequence = parse_pack_name(base);
                    if sequence.is_err() || base == name {
                        return Some(sequence);
                    }
                }
                Ok(_) => return Some(Err(RecoveryStorageError::InvalidInput)),
                Err(error) => return Some(Err(error.into())),
            }
        }
        None
    }
}

/// One immutable source pack. It cannot outlive the exclusively held recovery folder.
pub struct RecoveryPack<'a> {
    pack: PackStore,
    workspace: workspace::Workspace,
    _folder: &'a RecoveryFolder,
}

/// Untrusted pack catalogue entry, not proof that its bytes are intact or authorised.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryShardRecord {
    /// Stable position within this isolated pack copy.
    pub record_number: u64,
    /// Claimed physical shard identity.
    pub shard: ShardIdentity,
    /// Claimed encrypted byte length.
    pub length: u64,
    /// Claimed encrypted byte digest; verify against independent archive evidence.
    pub digest: [u8; 32],
    /// Whether bytes remain physically eligible for salvage.
    pub retention: RecoveryShardRetention,
}

/// Physical lifecycle recorded by a pack, independent of restored namespace authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryShardRetention {
    /// Bytes are recorded as active.
    Active,
    /// Bytes are tombstoned but have not yet been unlinked.
    Tombstoned,
    /// Bytes have been unlinked; this entry is not a recovery candidate.
    Unlinked,
}

/// Bounded keyset page, including unlinked records to bound work across sparse packs.
#[derive(Debug, Eq, PartialEq)]
pub struct RecoveryShardPage {
    /// At most the requested number of entries, ordered by record number.
    pub records: Vec<RecoveryShardRecord>,
    /// Pass as `after_record` to continue this same pack copy; absent at its end.
    pub next_after_record: Option<u64>,
}

impl RecoveryPack<'_> {
    /// Lists at most 1,000 catalogue records without loading encrypted BLOBs.
    /// Start at zero. This reads suspect locators; `read_exact` still requires independently
    /// verified identity, length and digest before any bytes may enter reconstruction.
    ///
    /// # Errors
    /// Rejects invalid bounds, malformed catalogue fields and database failures.
    pub fn inventory_page(
        &self,
        after_record: u64,
        limit: u16,
    ) -> Result<RecoveryShardPage, RecoveryStorageError> {
        if !(1..=1000).contains(&limit) || i64::try_from(after_record).is_err() {
            return Err(RecoveryStorageError::InvalidInput);
        }
        self.pack
            .recovery_inventory(after_record, limit)
            .map_err(|_| RecoveryStorageError::Corrupt)
    }

    /// Closes the private SQLite copy and removes its exact owned files and directory.
    ///
    /// # Errors
    /// Reports failed cleanup; unexpected files are never recursively removed.
    pub fn finish(self) -> Result<(), RecoveryStorageError> {
        drop(self.pack);
        self.workspace.remove()
    }

    /// Reads encrypted bytes only if both pack integrity and independently supplied evidence match.
    /// Tombstoned-but-present bytes may be salvaged; this never restores them to active service.
    ///
    /// # Errors
    /// Rejects missing, unlinked, corrupt or substituted data and excessive lengths.
    pub fn read_exact(
        &self,
        shard: ShardIdentity,
        length: u64,
        digest: [u8; 32],
    ) -> Result<BoundedBytes, RecoveryStorageError> {
        if length == 0 || length > 64 * 1024 * 1024 {
            return Err(RecoveryStorageError::InvalidInput);
        }
        let bytes = self
            .pack
            .recover_bytes(shard)
            .map_err(|error| match error {
                crate::pack::PackStoreError::NotFound => RecoveryStorageError::NotFound,
                _ => RecoveryStorageError::Corrupt,
            })?;
        if u64::try_from(bytes.len()).ok() != Some(length)
            || blake3::hash(bytes.as_slice()).as_bytes() != &digest
        {
            return Err(RecoveryStorageError::Corrupt);
        }
        Ok(bytes)
    }
}

fn parse_pack_name(name: &str) -> Result<u64, RecoveryStorageError> {
    let stem = name
        .strip_suffix(".sqlite3")
        .ok_or(RecoveryStorageError::InvalidInput)?;
    if stem.len() != 16
        || !stem
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RecoveryStorageError::InvalidInput);
    }
    let sequence = u64::from_str_radix(stem, 16).map_err(|_| RecoveryStorageError::InvalidInput)?;
    if sequence == 0 || i64::try_from(sequence).is_err() {
        return Err(RecoveryStorageError::InvalidInput);
    }
    Ok(sequence)
}

fn require_file(file_path: &Path) -> Result<(), RecoveryStorageError> {
    if fs::symlink_metadata(file_path)?.is_file() {
        Ok(())
    } else {
        Err(RecoveryStorageError::InvalidInput)
    }
}

fn require_directory(file_path: &Path) -> Result<(), RecoveryStorageError> {
    if fs::symlink_metadata(file_path)?.is_dir() {
        Ok(())
    } else {
        Err(RecoveryStorageError::InvalidInput)
    }
}

/// Redacted offline storage failures. No error establishes data absence beyond its exact request.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryStorageError {
    /// Invalid identity, size, directory entry or source path.
    #[error("recovery storage input is invalid")]
    InvalidInput,
    /// A process already owns the selected target.
    #[error("recovery storage target has a live owner")]
    AlreadyOwned,
    /// Marker did not match independently verified recovery metadata.
    #[error("recovery storage identity does not match")]
    IdentityMismatch,
    /// No retained bytes for the exact shard in the selected pack.
    #[error("recovery shard is absent from this pack")]
    NotFound,
    /// Pack schema, identity or ciphertext evidence could not be verified.
    #[error("recovery storage evidence is corrupt or unsupported")]
    Corrupt,
    /// A reserved private pack has not completed copying and indexing.
    #[error("recovery inventory has incomplete pack work")]
    Incomplete,
    /// Physical source IO failed.
    #[error("recovery storage IO failed")]
    Io(#[from] std::io::Error),
    /// The isolated inventory could not persist or decode its catalogue.
    #[error("recovery inventory database operation failed")]
    Database(#[from] rusqlite::Error),
}
