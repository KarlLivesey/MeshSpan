// SPDX-License-Identifier: GPL-2.0-only

//! Exclusive, capability-probed registration of an existing storage folder.

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use meshspan_domain::{EntropyError, MeshId, RandomSource, TargetId};
use thiserror::Error;

use crate::config::UsageLimit;
use crate::journal::CapacityObservation;
use crate::marker::{MARKER_BYTES, MarkerFingerprint, TargetMarker};

const PRIVATE_DIRECTORY: &str = ".meshspan";
const MARKER_FILE: &str = "target.marker";
const PENDING_MARKER_FILE: &str = "target.marker.pending";
const LOCK_FILE: &str = "target.lock";
const PACK_DIRECTORY: &str = "packs";
const PROBE_PENDING: &str = "capability-probe.pending";
const PROBE_INSTALLED: &str = "capability-probe.installed";
const PROBE_BYTES: &[u8] = b"meshspan-folder-capability-probe-v1";

/// Authority-selected identity and capacity policy for a new registered folder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FolderRegistration {
    /// Mesh that owns private bytes under this folder.
    pub mesh_id: MeshId,
    /// Stable storage-target identity independent of path spelling.
    pub target_id: TargetId,
    /// Positive authority-fenced target generation.
    pub generation: u64,
    /// Explicit provider-owned usage ceiling.
    pub usage_limit: UsageLimit,
}

/// Live exclusive ownership of one capability-scoped private provider directory.
pub struct RegisteredFolder {
    canonical_path: PathBuf,
    private_directory: Dir,
    marker: TargetMarker,
    usage_limit: UsageLimit,
    _lock: std::fs::File,
}

impl RegisteredFolder {
    /// Registers a new empty private subdirectory without touching sibling content.
    ///
    /// # Errors
    ///
    /// Rejects invalid identity, an existing/unknown private directory, unavailable entropy,
    /// a concurrent owner, or a filesystem that fails required capability probes.
    pub fn register_new(
        storage_path: &Path,
        registration: FolderRegistration,
        random: &mut impl RandomSource,
    ) -> Result<Self, StorageFolderError> {
        if registration.generation == 0 {
            return Err(StorageFolderError::InvalidRegistration);
        }
        let (canonical_path, private_directory, lock) = open_and_lock(storage_path)?;
        clear_interrupted_probe(&private_directory)?;
        let entries = private_entry_names(&private_directory)?;
        if entries.iter().any(|entry| entry != OsStr::new(LOCK_FILE)) {
            return Err(StorageFolderError::PrivateDirectoryNotEmpty);
        }
        probe_capabilities(&private_directory)?;
        let mut nonce = [0; 32];
        random.fill_bytes(&mut nonce)?;
        let marker = TargetMarker::new(
            registration.mesh_id,
            registration.target_id,
            registration.generation,
            nonce,
        )?;
        write_new_marker(&private_directory, marker)?;
        create_pack_directory(&private_directory)?;
        Ok(Self {
            canonical_path,
            private_directory,
            marker,
            usage_limit: registration.usage_limit,
            _lock: lock,
        })
    }

    /// Reopens the exact returning target after its expected marker was authorised.
    ///
    /// # Errors
    ///
    /// Rejects absent/corrupt/mismatched markers, unknown private entries, concurrent ownership
    /// and any failed capability probe. It never creates a missing marker while reopening.
    pub fn reopen(
        storage_path: &Path,
        expected: FolderRegistration,
        expected_fingerprint: MarkerFingerprint,
    ) -> Result<Self, StorageFolderError> {
        if expected.generation == 0 {
            return Err(StorageFolderError::InvalidRegistration);
        }
        let (canonical_path, private_directory, lock) = open_and_lock(storage_path)?;
        clear_interrupted_probe(&private_directory)?;
        validate_known_entries(&private_directory)?;
        let marker = read_marker(&private_directory)?;
        if marker.mesh_id() != expected.mesh_id
            || marker.target_id() != expected.target_id
            || marker.generation() != expected.generation
            || marker.fingerprint() != expected_fingerprint
        {
            return Err(StorageFolderError::IdentityMismatch);
        }
        probe_capabilities(&private_directory)?;
        create_pack_directory(&private_directory)?;
        Ok(Self {
            canonical_path,
            private_directory,
            marker,
            usage_limit: expected.usage_limit,
            _lock: lock,
        })
    }

    /// Reopens a marker created after a durable local intent but before its fingerprint journaled.
    ///
    /// This recovery path still requires the exact mesh, target and generation from the earlier
    /// local intent. It accepts the marker's self-validated fingerprint only after those identities,
    /// exclusive ownership, known private layout and filesystem capabilities all pass.
    ///
    /// # Errors
    ///
    /// Rejects absent/corrupt/substituted markers, unknown private entries, concurrent ownership
    /// and failed capability probes.
    pub fn reopen_pending(
        storage_path: &Path,
        expected: FolderRegistration,
    ) -> Result<Self, StorageFolderError> {
        if expected.generation == 0 {
            return Err(StorageFolderError::InvalidRegistration);
        }
        let (canonical_path, private_directory, lock) = open_and_lock(storage_path)?;
        clear_interrupted_probe(&private_directory)?;
        recover_pending_marker(&private_directory, expected)?;
        validate_known_entries(&private_directory)?;
        let marker = read_marker(&private_directory)?;
        if marker.mesh_id() != expected.mesh_id
            || marker.target_id() != expected.target_id
            || marker.generation() != expected.generation
        {
            return Err(StorageFolderError::IdentityMismatch);
        }
        probe_capabilities(&private_directory)?;
        create_pack_directory(&private_directory)?;
        Ok(Self {
            canonical_path,
            private_directory,
            marker,
            usage_limit: expected.usage_limit,
            _lock: lock,
        })
    }

    /// Returns the identity read from durable target media.
    #[must_use]
    pub const fn marker(&self) -> TargetMarker {
        self.marker
    }

    /// Returns the current canonical path as a local observation, never as target identity.
    #[must_use]
    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    /// Returns the configured target-local usage ceiling.
    #[must_use]
    pub const fn usage_limit(&self) -> UsageLimit {
        self.usage_limit
    }

    /// Re-runs the required folder capability probe for health recovery.
    ///
    /// # Errors
    ///
    /// Returns a target-local failure when write, flush, reopen or rename no longer works.
    pub fn probe(&self) -> Result<(), StorageFolderError> {
        clear_interrupted_probe(&self.private_directory)?;
        probe_capabilities(&self.private_directory)
    }

    /// Measures capacity from the already-open capability rather than a caller-supplied path.
    pub(crate) fn capacity_observation(&self) -> Result<CapacityObservation, StorageFolderError> {
        capacity_observation(&self.private_directory)
    }

    pub(crate) fn pack_database_path(&self, sequence: u64) -> Result<PathBuf, StorageFolderError> {
        if sequence == 0 {
            return Err(StorageFolderError::InvalidRegistration);
        }
        Ok(self
            .canonical_path
            .join(PRIVATE_DIRECTORY)
            .join(PACK_DIRECTORY)
            .join(format!("{sequence:016x}.sqlite3")))
    }
}

#[cfg(unix)]
fn capacity_observation(directory: &Dir) -> Result<CapacityObservation, StorageFolderError> {
    let statistics = rustix::fs::fstatvfs(directory).map_err(|error| {
        StorageFolderError::Io(std::io::Error::from_raw_os_error(error.raw_os_error()))
    })?;
    let fragment_bytes = if statistics.f_frsize == 0 {
        statistics.f_bsize
    } else {
        statistics.f_frsize
    };
    let total_bytes = statistics
        .f_blocks
        .checked_mul(fragment_bytes)
        .ok_or(StorageFolderError::CapabilityProbeFailed)?;
    let available_bytes = statistics
        .f_bavail
        .checked_mul(fragment_bytes)
        .ok_or(StorageFolderError::CapabilityProbeFailed)?;
    if total_bytes == 0 || available_bytes > total_bytes {
        return Err(StorageFolderError::CapabilityProbeFailed);
    }
    Ok(CapacityObservation {
        total_bytes,
        available_bytes,
    })
}

#[cfg(not(unix))]
fn capacity_observation(_directory: &Dir) -> Result<CapacityObservation, StorageFolderError> {
    Err(StorageFolderError::CapabilityProbeFailed)
}

fn open_and_lock(storage_path: &Path) -> Result<(PathBuf, Dir, std::fs::File), StorageFolderError> {
    let canonical_path = std::fs::canonicalize(storage_path)?;
    let root = Dir::open_ambient_dir(&canonical_path, ambient_authority())?;
    match root.create_dir(PRIVATE_DIRECTORY) {
        Ok(()) => sync_directory(&root)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let private_directory = root.open_dir(PRIVATE_DIRECTORY)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    let lock = private_directory.open_with(LOCK_FILE, &options)?.into_std();
    lock.try_lock()
        .map_err(|_| StorageFolderError::AlreadyOwned)?;
    Ok((canonical_path, private_directory, lock))
}

fn private_entry_names(directory: &Dir) -> Result<Vec<std::ffi::OsString>, StorageFolderError> {
    directory
        .entries()?
        .map(|entry| {
            entry
                .map(|value| value.file_name())
                .map_err(StorageFolderError::Io)
        })
        .collect()
}

fn validate_known_entries(directory: &Dir) -> Result<(), StorageFolderError> {
    for entry in private_entry_names(directory)? {
        if entry != OsStr::new(LOCK_FILE)
            && entry != OsStr::new(MARKER_FILE)
            && entry != OsStr::new(PACK_DIRECTORY)
        {
            return Err(StorageFolderError::UnknownPrivateEntry);
        }
    }
    Ok(())
}

fn clear_interrupted_probe(directory: &Dir) -> Result<(), StorageFolderError> {
    for name in [PROBE_PENDING, PROBE_INSTALLED] {
        match directory.remove_file(name) {
            Ok(()) => sync_directory(directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn probe_capabilities(directory: &Dir) -> Result<(), StorageFolderError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut pending = directory.open_with(PROBE_PENDING, &options)?;
    pending.write_all(PROBE_BYTES)?;
    pending.sync_all()?;
    drop(pending);

    let mut reopened = directory.open(PROBE_PENDING)?;
    let mut observed = Vec::with_capacity(PROBE_BYTES.len());
    reopened.read_to_end(&mut observed)?;
    if observed != PROBE_BYTES {
        return Err(StorageFolderError::CapabilityProbeFailed);
    }
    directory.rename(PROBE_PENDING, directory, PROBE_INSTALLED)?;
    sync_directory(directory)?;
    directory.remove_file(PROBE_INSTALLED)?;
    sync_directory(directory)?;
    Ok(())
}

fn write_new_marker(directory: &Dir, marker: TargetMarker) -> Result<(), StorageFolderError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut pending = directory.open_with(PENDING_MARKER_FILE, &options)?;
    pending.write_all(&marker.encode())?;
    pending.sync_all()?;
    drop(pending);
    directory.rename(PENDING_MARKER_FILE, directory, MARKER_FILE)?;
    sync_directory(directory)
}

fn recover_pending_marker(
    directory: &Dir,
    expected: FolderRegistration,
) -> Result<(), StorageFolderError> {
    let Some(pending) = read_optional_marker(directory, PENDING_MARKER_FILE)? else {
        return Ok(());
    };
    if read_optional_marker(directory, MARKER_FILE)?.is_some() {
        return Err(StorageFolderError::UnknownPrivateEntry);
    }
    if pending.mesh_id() != expected.mesh_id
        || pending.target_id() != expected.target_id
        || pending.generation() != expected.generation
    {
        return Err(StorageFolderError::IdentityMismatch);
    }
    directory.rename(PENDING_MARKER_FILE, directory, MARKER_FILE)?;
    sync_directory(directory)
}

fn read_marker(directory: &Dir) -> Result<TargetMarker, StorageFolderError> {
    read_optional_marker(directory, MARKER_FILE)?.ok_or_else(|| {
        StorageFolderError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "storage marker is absent",
        ))
    })
}

fn read_optional_marker(
    directory: &Dir,
    name: &str,
) -> Result<Option<TargetMarker>, StorageFolderError> {
    let mut file = match directory.open(name) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::with_capacity(MARKER_BYTES);
    file.read_to_end(&mut bytes)?;
    TargetMarker::decode(&bytes).map(Some)
}

fn create_pack_directory(directory: &Dir) -> Result<(), StorageFolderError> {
    match directory.create_dir(PACK_DIRECTORY) {
        Ok(()) => sync_directory(directory),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => directory
            .open_dir(PACK_DIRECTORY)
            .map(|_| ())
            .map_err(Into::into),
        Err(error) => Err(error.into()),
    }
}

fn sync_directory(directory: &Dir) -> Result<(), StorageFolderError> {
    directory
        .try_clone()?
        .into_std_file()
        .sync_all()
        .map_err(Into::into)
}

/// Closed folder-registration failures that never echo attacker-controlled paths.
#[derive(Debug, Error)]
pub enum StorageFolderError {
    /// Registration has a zero generation or another impossible value.
    #[error("storage folder registration is invalid")]
    InvalidRegistration,
    /// Secure marker material could not be generated.
    #[error("storage folder entropy is unavailable")]
    Entropy(#[from] EntropyError),
    /// The private directory is not empty during first registration.
    #[error("storage private directory is not empty")]
    PrivateDirectoryNotEmpty,
    /// Existing target marker bytes are malformed, unsupported or fail integrity.
    #[error("storage target marker is corrupt")]
    CorruptMarker,
    /// Existing marker identity, generation or fingerprint differs from authority.
    #[error("storage target identity does not match")]
    IdentityMismatch,
    /// An unknown record exists in the provider-owned directory.
    #[error("storage private directory contains an unknown record")]
    UnknownPrivateEntry,
    /// Another live process already owns this target.
    #[error("storage target already has a live owner")]
    AlreadyOwned,
    /// The filesystem failed required write, flush, reopen or atomic-rename behaviour.
    #[error("storage folder failed its capability probe")]
    CapabilityProbeFailed,
    /// A local filesystem operation failed without affecting sibling targets.
    #[error("storage folder IO failed")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::fs;

    use meshspan_domain::{EntropyError, MeshId, RandomSource, TargetId};
    use tempfile::tempdir;

    use super::{FolderRegistration, RegisteredFolder, StorageFolderError};
    use crate::UsageLimit;

    struct FixedRandom(u8);

    impl RandomSource for FixedRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            destination.fill(self.0);
            self.0 = self.0.wrapping_add(1);
            Ok(())
        }
    }

    #[test]
    fn registration_preserves_siblings_and_identity_survives_path_move()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let original = directory.path().join("disk-a");
        fs::create_dir(&original)?;
        fs::write(original.join("family-photo.jpg"), b"not meshspan data")?;
        let registration = registration()?;
        let mut random = FixedRandom(7);
        let folder = RegisteredFolder::register_new(&original, registration, &mut random)?;
        let fingerprint = folder.marker().fingerprint();
        assert_eq!(
            fs::read(original.join("family-photo.jpg"))?,
            b"not meshspan data"
        );
        assert_eq!(folder.usage_limit(), UsageLimit::Percent(95));
        drop(folder);

        let moved = directory.path().join("renamed-disk");
        fs::rename(&original, &moved)?;
        let reopened = RegisteredFolder::reopen(&moved, registration, fingerprint)?;
        assert_eq!(reopened.marker().target_id(), registration.target_id);
        assert_eq!(reopened.marker().generation(), registration.generation);
        assert_eq!(reopened.canonical_path(), fs::canonicalize(moved)?);
        reopened.probe()?;
        Ok(())
    }

    #[test]
    fn live_second_owner_and_unknown_private_state_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let owned = directory.path().join("owned");
        fs::create_dir(&owned)?;
        let registration = registration()?;
        let mut random = FixedRandom(1);
        let first = RegisteredFolder::register_new(&owned, registration, &mut random)?;
        assert!(matches!(
            RegisteredFolder::reopen(&owned, registration, first.marker().fingerprint()),
            Err(StorageFolderError::AlreadyOwned)
        ));
        drop(first);

        let fingerprint = marker_fingerprint(&owned)?;
        fs::write(owned.join(".meshspan").join("attacker-record"), b"hostile")?;
        assert!(matches!(
            RegisteredFolder::reopen(&owned, registration, fingerprint),
            Err(StorageFolderError::UnknownPrivateEntry)
        ));
        assert_eq!(
            fs::read(owned.join(".meshspan").join("attacker-record"))?,
            b"hostile"
        );
        Ok(())
    }

    #[test]
    fn corrupt_or_wrong_marker_is_never_adopted() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let folder_path = directory.path().join("target");
        fs::create_dir(&folder_path)?;
        let registration = registration()?;
        let mut random = FixedRandom(9);
        let folder = RegisteredFolder::register_new(&folder_path, registration, &mut random)?;
        let fingerprint = folder.marker().fingerprint();
        drop(folder);

        let wrong = FolderRegistration {
            target_id: TargetId::from_bytes([8; 16])?,
            ..registration
        };
        assert!(matches!(
            RegisteredFolder::reopen(&folder_path, wrong, fingerprint),
            Err(StorageFolderError::IdentityMismatch)
        ));
        let marker_path = folder_path.join(".meshspan").join("target.marker");
        let mut bytes = fs::read(&marker_path)?;
        bytes[50] ^= 1;
        fs::write(marker_path, bytes)?;
        assert!(matches!(
            RegisteredFolder::reopen(&folder_path, registration, fingerprint),
            Err(StorageFolderError::CorruptMarker)
        ));
        Ok(())
    }

    #[test]
    fn pending_reopen_recovers_only_the_exact_journalled_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let folder_path = directory.path().join("interrupted-registration");
        fs::create_dir(&folder_path)?;
        let registration = registration()?;
        let mut random = FixedRandom(11);
        let created = RegisteredFolder::register_new(&folder_path, registration, &mut random)?;
        let fingerprint = created.marker().fingerprint();
        drop(created);

        fs::rename(
            folder_path.join(".meshspan").join("target.marker"),
            folder_path.join(".meshspan").join("target.marker.pending"),
        )?;

        let recovered = RegisteredFolder::reopen_pending(&folder_path, registration)?;
        assert_eq!(recovered.marker().fingerprint(), fingerprint);
        drop(recovered);

        let wrong_mesh = FolderRegistration {
            mesh_id: MeshId::from_bytes([7; 16])?,
            ..registration
        };
        assert!(matches!(
            RegisteredFolder::reopen_pending(&folder_path, wrong_mesh),
            Err(StorageFolderError::IdentityMismatch)
        ));
        let wrong_target = FolderRegistration {
            target_id: TargetId::from_bytes([8; 16])?,
            ..registration
        };
        assert!(matches!(
            RegisteredFolder::reopen_pending(&folder_path, wrong_target),
            Err(StorageFolderError::IdentityMismatch)
        ));
        let wrong_generation = FolderRegistration {
            generation: registration.generation + 1,
            ..registration
        };
        assert!(matches!(
            RegisteredFolder::reopen_pending(&folder_path, wrong_generation),
            Err(StorageFolderError::IdentityMismatch)
        ));

        RegisteredFolder::reopen(&folder_path, registration, fingerprint)?;
        Ok(())
    }

    fn registration() -> Result<FolderRegistration, meshspan_domain::IdentifierError> {
        Ok(FolderRegistration {
            mesh_id: MeshId::from_bytes([1; 16])?,
            target_id: TargetId::from_bytes([2; 16])?,
            generation: 3,
            usage_limit: UsageLimit::DEFAULT,
        })
    }

    fn marker_fingerprint(
        storage_path: &std::path::Path,
    ) -> Result<crate::MarkerFingerprint, Box<dyn std::error::Error>> {
        let bytes = fs::read(storage_path.join(".meshspan").join("target.marker"))?;
        Ok(crate::TargetMarker::decode(&bytes)?.fingerprint())
    }
}
