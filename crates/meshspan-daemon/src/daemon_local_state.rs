// SPDX-License-Identifier: GPL-2.0-only

//! Exclusive daemon-state ownership and restart-safe first-start composition.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use meshspan_domain::{InitialBootstrapMaterial, NodeId, UnixMicros};
use meshspan_metadata::{LocalDatabase, MetadataStoreError};
use rustls::ServerConfig;
use thiserror::Error;

use crate::{
    ClaimEnsureOutcome, FirstBootClaimError, FirstBootClaimService, HeadlessDaemonConfig,
    LocalNodeIdentity, LocalNodeIdentityError, OperatingSystemRandom,
};

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const LOCAL_DATABASE_FILE: &str = "local.sqlite3";
const LOCK_FILE: &str = "daemon.lock";
const SECRET_DIRECTORY: &str = "secrets";
const IDENTITY_FILE: &str = "node-identity.pk8";
const DEFAULT_CLAIM_FILE: &str = "first-boot.claim";
const BOOTSTRAP_DNS_NAME: &str = "meshspan.local";

/// Exclusive, identity-bound node-local state needed before mesh services start.
///
/// The state-directory lock remains held for this value's lifetime. The type implements neither
/// `Clone` nor `Debug` because it owns a private node key through `LocalNodeIdentity`.
pub struct DaemonLocalState {
    directory: StateDirectory,
    database: LocalDatabase,
    identity: LocalNodeIdentity,
    claim_output_path: PathBuf,
    claim_outcome: ClaimEnsureOutcome,
}

impl DaemonLocalState {
    /// Opens or safely creates one daemon instance's complete local starting state.
    ///
    /// # Errors
    ///
    /// Rejects permissive/replaced state paths, another live daemon, state/storage overlap,
    /// missing or substituted identity material, database identity mismatch and inconsistent
    /// first-boot claim state.
    pub fn open(
        config: &HeadlessDaemonConfig,
        now: UnixMicros,
    ) -> Result<Self, DaemonLocalStateError> {
        let directory = StateDirectory::open(
            config.storage().daemon_state_dir(),
            config.storage().storage_paths(),
        )?;
        let database_path = directory.path().join(LOCAL_DATABASE_FILE);
        let database_exists = regular_file_exists(&database_path)?;
        let secret_directory = ensure_private_directory(&directory.path().join(SECRET_DIRECTORY))?;
        let identity_path = secret_directory.join(IDENTITY_FILE);
        let identity = if database_exists {
            LocalNodeIdentity::open(&identity_path, BOOTSTRAP_DNS_NAME)?
        } else {
            LocalNodeIdentity::open_or_create(&identity_path, BOOTSTRAP_DNS_NAME)?
        };
        let expected_node_id =
            InitialBootstrapMaterial::node_id(identity.public_key_fingerprint())?;
        let mut database = if database_exists {
            LocalDatabase::open_existing(&database_path, now)?
        } else {
            LocalDatabase::open(&database_path, expected_node_id, now)?
        };
        if database.node_id() != expected_node_id {
            return Err(DaemonLocalStateError::IdentityMismatch);
        }
        let claim_output_path = config.claim_output().map_or_else(
            || directory.path().join(DEFAULT_CLAIM_FILE),
            Path::to_path_buf,
        );
        let claim_outcome = FirstBootClaimService::ensure(
            &mut database,
            identity.public_key_fingerprint(),
            &claim_output_path,
            now,
            &mut OperatingSystemRandom,
        )?;
        Ok(Self {
            directory,
            database,
            identity,
            claim_output_path,
            claim_outcome,
        })
    }

    /// Returns the canonical private daemon-state directory.
    #[must_use]
    pub fn state_directory(&self) -> &Path {
        self.directory.path()
    }

    /// Returns the stable node identity bound to both the local database and private key.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.database.node_id()
    }

    /// Returns the current non-secret first-boot claim lifecycle outcome.
    #[must_use]
    pub const fn claim_outcome(&self) -> ClaimEnsureOutcome {
        self.claim_outcome
    }

    /// Returns the protected path where the active claim exists until consumption.
    #[must_use]
    pub fn claim_output_path(&self) -> &Path {
        &self.claim_output_path
    }

    /// Borrows the identity-bound local database for lifecycle reconciliation.
    #[must_use]
    pub const fn local_database(&self) -> &LocalDatabase {
        &self.database
    }

    /// Mutably borrows the identity-bound local database for one typed local transition.
    pub const fn local_database_mut(&mut self) -> &mut LocalDatabase {
        &mut self.database
    }

    /// Opens another hardened connection to this daemon's identity-bound local database.
    ///
    /// # Errors
    ///
    /// Rejects a missing, replaced, corrupt or differently identified local database.
    pub fn open_local_database(
        &self,
        now: UnixMicros,
    ) -> Result<LocalDatabase, DaemonLocalStateError> {
        LocalDatabase::open_existing(&self.directory.path().join(LOCAL_DATABASE_FILE), now)
            .map_err(Into::into)
    }

    /// Returns the node public-key fingerprint safe for claim and enrolment binding.
    #[must_use]
    pub fn public_key_fingerprint(&self) -> [u8; 32] {
        self.identity.public_key_fingerprint()
    }

    /// Builds the first-start TLS 1.3 public HTTPS configuration.
    ///
    /// # Errors
    ///
    /// Rejects an identity/provider mismatch.
    pub fn bootstrap_server_config(&self) -> Result<Arc<ServerConfig>, DaemonLocalStateError> {
        self.identity.bootstrap_server_config().map_err(Into::into)
    }
}

struct StateDirectory {
    canonical_path: PathBuf,
    _lock: File,
}

impl StateDirectory {
    fn open(path: &Path, storage_paths: &[PathBuf]) -> Result<Self, DaemonLocalStateError> {
        reject_storage_overlap(path, storage_paths)?;
        let canonical_path = ensure_private_directory(path)?;
        let lock_path = canonical_path.join(LOCK_FILE);
        validate_optional_private_file(&lock_path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(FILE_MODE)
            .open(lock_path)?;
        validate_private_file(&lock.metadata()?)?;
        lock.try_lock().map_err(|error| match error {
            fs::TryLockError::WouldBlock => DaemonLocalStateError::AlreadyRunning,
            fs::TryLockError::Error(error) => DaemonLocalStateError::Io(error),
        })?;
        Ok(Self {
            canonical_path,
            _lock: lock,
        })
    }

    fn path(&self) -> &Path {
        &self.canonical_path
    }
}

fn reject_storage_overlap(
    state_path: &Path,
    storage_paths: &[PathBuf],
) -> Result<(), DaemonLocalStateError> {
    let state = canonical_candidate(state_path)?;
    for storage_path in storage_paths {
        let storage = fs::canonicalize(storage_path)?;
        if storage.starts_with(&state) || state.starts_with(&storage) {
            return Err(DaemonLocalStateError::StateStorageOverlap);
        }
    }
    Ok(())
}

fn canonical_candidate(path: &Path) -> Result<PathBuf, DaemonLocalStateError> {
    match fs::canonicalize(path) {
        Ok(canonical) => Ok(canonical),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or(DaemonLocalStateError::UnsafeStateDirectory)?;
            let file_name = path
                .file_name()
                .ok_or(DaemonLocalStateError::UnsafeStateDirectory)?;
            Ok(fs::canonicalize(parent)?.join(file_name))
        }
        Err(error) => Err(error.into()),
    }
}

fn ensure_private_directory(path: &Path) -> Result<PathBuf, DaemonLocalStateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_directory(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(DIRECTORY_MODE).create(path)?;
            validate_private_directory(&fs::symlink_metadata(path)?)?;
            sync_parent(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    fs::canonicalize(path).map_err(Into::into)
}

fn validate_private_directory(metadata: &fs::Metadata) -> Result<(), DaemonLocalStateError> {
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o777 != DIRECTORY_MODE {
        return Err(DaemonLocalStateError::UnsafeStateDirectory);
    }
    Ok(())
}

fn regular_file_exists(path: &Path) -> Result<bool, DaemonLocalStateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(DaemonLocalStateError::UnsafeStateFile),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn validate_optional_private_file(path: &Path) -> Result<(), DaemonLocalStateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_file(&metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_private_file(metadata: &fs::Metadata) -> Result<(), DaemonLocalStateError> {
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(DaemonLocalStateError::UnsafeStateFile);
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), DaemonLocalStateError> {
    let parent = path
        .parent()
        .ok_or(DaemonLocalStateError::UnsafeStateDirectory)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Stable daemon-local-state failure without secret or path contents.
#[derive(Debug, Error)]
pub enum DaemonLocalStateError {
    /// A filesystem operation failed.
    #[error("daemon local-state filesystem operation failed")]
    Io(#[from] io::Error),
    /// The state directory is not one owner-only real directory.
    #[error("daemon state directory is unsafe")]
    UnsafeStateDirectory,
    /// A fixed state file is not one owner-only real file.
    #[error("daemon state file is unsafe")]
    UnsafeStateFile,
    /// Another process currently owns this daemon state directory.
    #[error("another daemon is already using this state directory")]
    AlreadyRunning,
    /// State and storage provider roots overlap.
    #[error("daemon state directory overlaps a storage path")]
    StateStorageOverlap,
    /// Protected node identity handling failed.
    #[error("daemon node identity failed")]
    Identity(#[from] LocalNodeIdentityError),
    /// The private key and local database identify different nodes.
    #[error("daemon node identity does not match local metadata")]
    IdentityMismatch,
    /// Local SQLite-compatible metadata failed or was inconsistent.
    #[error("daemon local metadata failed")]
    Metadata(#[from] MetadataStoreError),
    /// The public-key fingerprint could not form a node identity.
    #[error("daemon public identity is invalid")]
    BootstrapIdentity(#[from] meshspan_domain::InitialBootstrapMaterialError),
    /// First-start claim state could not be created or reconciled safely.
    #[error("daemon first-start claim failed")]
    Claim(#[from] FirstBootClaimError),
}
