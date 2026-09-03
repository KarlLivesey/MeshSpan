// SPDX-License-Identifier: GPL-2.0-only

//! Crash-safe preparation of one exact encrypted metadata-backup container.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use meshspan_domain::{BackupId, RandomSource, UnixMicros};
use meshspan_metadata::{
    EncryptedBackupPaths, EncryptedPartitionBackupManifest, LocalDatabase,
    LocalMetadataBackupStaging, LocalMetadataBackupStagingError, MetadataBackupRun,
    MetadataBackupRunState, RepositoryError,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ConsensusAuthenticationAuthority;

const STAGING_DIRECTORY: &str = "metadata-backup-staging";
const HASH_BUFFER_BYTES: usize = 64 * 1_024;

/// Exact-state snapshot and encryption boundary required by backup preparation.
pub trait MetadataBackupPreparationAuthority {
    /// Produces a new encrypted container for all current recovery recipients.
    ///
    /// # Errors
    ///
    /// Fails closed for unavailable authority, invalid recovery state, snapshot or encryption.
    fn create_encrypted_metadata_backup<Random: RandomSource>(
        &self,
        paths: EncryptedBackupPaths<'_>,
        backup_id: BackupId,
        created_at: UnixMicros,
        random: &mut Random,
    ) -> Result<EncryptedPartitionBackupManifest, RepositoryError>;
}

impl MetadataBackupPreparationAuthority for ConsensusAuthenticationAuthority {
    fn create_encrypted_metadata_backup<Random: RandomSource>(
        &self,
        paths: EncryptedBackupPaths<'_>,
        backup_id: BackupId,
        created_at: UnixMicros,
        random: &mut Random,
    ) -> Result<EncryptedPartitionBackupManifest, RepositoryError> {
        let recipients = self.reader().volume_key_recipients()?;
        self.reader()
            .create_encrypted_backup(paths, backup_id, created_at, &recipients, random)
    }
}

/// Durable encrypted container ready for bounded destination publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedMetadataBackup {
    /// Exact application-owned staging path.
    pub encrypted_path: PathBuf,
    /// Durable non-secret evidence which must accompany every provider write.
    pub staging: LocalMetadataBackupStaging,
}

/// One crash-safe encrypted-container preparer.
pub struct MetadataBackupPreparationService<'a, Authority, Random> {
    authority: &'a Authority,
    local: &'a mut LocalDatabase,
    random: &'a mut Random,
    directory: PathBuf,
}

impl<'a, Authority, Random> MetadataBackupPreparationService<'a, Authority, Random> {
    /// Opens or creates the private staging directory beneath one validated daemon state root.
    ///
    /// # Errors
    ///
    /// Rejects a non-directory, symlink or unavailable staging location.
    pub fn open(
        authority: &'a Authority,
        local: &'a mut LocalDatabase,
        random: &'a mut Random,
        state_directory: &Path,
    ) -> Result<Self, MetadataBackupPreparationError> {
        let directory = state_directory.join(STAGING_DIRECTORY);
        ensure_private_directory(&directory)?;
        Ok(Self {
            authority,
            local,
            random,
            directory,
        })
    }
}

impl<Authority, Random> MetadataBackupPreparationService<'_, Authority, Random>
where
    Authority: MetadataBackupPreparationAuthority,
    Random: RandomSource,
{
    /// Creates or resumes the exact staged container for one claimed backup run.
    ///
    /// The local journal is committed and the containing directory synchronised before this
    /// method returns. Provider IO must only begin after a successful return.
    ///
    /// # Errors
    ///
    /// Rejects terminal runs, changed evidence, missing recorded-run staging, substituted files,
    /// unsafe paths, authority failures and local durability failures.
    pub fn prepare(
        &mut self,
        run: MetadataBackupRun,
        now: UnixMicros,
    ) -> Result<PreparedMetadataBackup, MetadataBackupPreparationError> {
        validate_run(run, now)?;
        let relative_file_name = encrypted_file_name(run.backup_id);
        let encrypted_path = self.directory.join(&relative_file_name);
        if let Some(staging) = self.local.metadata_backup_staging(run.backup_id)? {
            validate_staging(run, &relative_file_name, &staging, &encrypted_path)?;
            return Ok(PreparedMetadataBackup {
                encrypted_path,
                staging,
            });
        }
        if run.state == MetadataBackupRunState::Recorded {
            return Err(MetadataBackupPreparationError::MissingRecordedStaging);
        }
        let plaintext_path = self.directory.join(plaintext_file_name(run.backup_id));
        remove_orphan(&plaintext_path)?;
        remove_orphan(&encrypted_path)?;
        sync_directory(&self.directory)?;
        let manifest = self.authority.create_encrypted_metadata_backup(
            EncryptedBackupPaths {
                plaintext_staging: &plaintext_path,
                encrypted_destination: &encrypted_path,
            },
            run.backup_id,
            now,
            self.random,
        )?;
        sync_directory(&self.directory)?;
        let staging = LocalMetadataBackupStaging {
            evidence: manifest.encrypted,
            relative_file_name,
            prepared_at: now,
            revision: 1,
        };
        validate_staging(run, &staging.relative_file_name, &staging, &encrypted_path)?;
        self.local.record_metadata_backup_staging(&staging)?;
        Ok(PreparedMetadataBackup {
            encrypted_path,
            staging,
        })
    }
}

fn validate_run(
    run: MetadataBackupRun,
    now: UnixMicros,
) -> Result<(), MetadataBackupPreparationError> {
    if now.get() < 0
        || !matches!(
            run.state,
            MetadataBackupRunState::Claimed | MetadataBackupRunState::Recorded
        )
    {
        Err(MetadataBackupPreparationError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_staging(
    run: MetadataBackupRun,
    expected_name: &str,
    staging: &LocalMetadataBackupStaging,
    encrypted_path: &Path,
) -> Result<(), MetadataBackupPreparationError> {
    let source = staging.evidence.source;
    if source.backup_id != run.backup_id
        || source.partition_id != run.partition_id
        || staging.relative_file_name != expected_name
    {
        return Err(MetadataBackupPreparationError::InvalidProjection);
    }
    let (byte_length, digest) = hash_regular_file(encrypted_path)?;
    if byte_length != staging.evidence.byte_length || digest != staging.evidence.digest {
        return Err(MetadataBackupPreparationError::ChangedStagingFile);
    }
    Ok(())
}

fn encrypted_file_name(backup_id: BackupId) -> String {
    format!("backup-{}.msbackup", identifier_hex(backup_id))
}

fn plaintext_file_name(backup_id: BackupId) -> String {
    format!("backup-{}.sqlite3.tmp", identifier_hex(backup_id))
}

fn identifier_hex(backup_id: BackupId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in backup_id.as_bytes() {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn ensure_private_directory(directory: &Path) -> Result<(), MetadataBackupPreparationError> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(MetadataBackupPreparationError::UnsafeStagingDirectory);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_directory(directory)?;
            let parent = directory
                .parent()
                .ok_or(MetadataBackupPreparationError::UnsafeStagingDirectory)?;
            sync_directory(parent)?;
        }
        Err(error) => return Err(error.into()),
    }
    require_private_permissions(directory)
}

#[cfg(unix)]
fn create_private_directory(directory: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(directory)
}

#[cfg(not(unix))]
fn create_private_directory(directory: &Path) -> Result<(), std::io::Error> {
    fs::create_dir(directory)
}

#[cfg(unix)]
fn require_private_permissions(directory: &Path) -> Result<(), MetadataBackupPreparationError> {
    use std::os::unix::fs::PermissionsExt;

    if fs::metadata(directory)?
        .permissions()
        .mode()
        .trailing_zeros()
        >= 6
    {
        Ok(())
    } else {
        Err(MetadataBackupPreparationError::UnsafeStagingDirectory)
    }
}

#[cfg(not(unix))]
fn require_private_permissions(_directory: &Path) -> Result<(), MetadataBackupPreparationError> {
    Ok(())
}

fn remove_orphan(file_path: &Path) -> Result<(), MetadataBackupPreparationError> {
    match fs::symlink_metadata(file_path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            Err(MetadataBackupPreparationError::UnsafeStagingFile)
        }
        Ok(_) => fs::remove_file(file_path).map_err(Into::into),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn hash_regular_file(file_path: &Path) -> Result<(u64, [u8; 32]), MetadataBackupPreparationError> {
    let metadata = fs::symlink_metadata(file_path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(MetadataBackupPreparationError::UnsafeStagingFile);
    }
    let mut file = File::open(file_path)?;
    let mut digest = Sha256::new();
    let mut byte_length = 0_u64;
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        byte_length = byte_length
            .checked_add(u64::try_from(read).map_err(|_| MetadataBackupPreparationError::Capacity)?)
            .ok_or(MetadataBackupPreparationError::Capacity)?;
        digest.update(&buffer[..read]);
    }
    Ok((byte_length, digest.finalize().into()))
}

fn sync_directory(directory: &Path) -> Result<(), MetadataBackupPreparationError> {
    File::open(directory)?.sync_all()?;
    Ok(())
}

/// Closed encrypted-backup preparation failure.
#[derive(Debug, Error)]
pub enum MetadataBackupPreparationError {
    /// Run identity, lifecycle or time was invalid.
    #[error("metadata backup preparation input was invalid")]
    InvalidInput,
    /// Snapshot output contradicted its claimed authoritative run.
    #[error("metadata backup preparation projection was invalid")]
    InvalidProjection,
    /// A recorded generation lost its only known local source and must be recovered from a copy.
    #[error("recorded metadata backup staging is missing and requires provider recovery")]
    MissingRecordedStaging,
    /// The staging directory was replaced, permissive or not a directory.
    #[error("metadata backup staging directory is unsafe")]
    UnsafeStagingDirectory,
    /// A staging path was replaced by a symlink, directory or another unsafe file kind.
    #[error("metadata backup staging file is unsafe")]
    UnsafeStagingFile,
    /// Durable evidence no longer matches the exact local encrypted bytes.
    #[error("metadata backup staging file changed after preparation")]
    ChangedStagingFile,
    /// A bounded byte counter could not advance safely.
    #[error("metadata backup preparation capacity was exceeded")]
    Capacity,
    /// Snapshot authority failed closed.
    #[error("metadata backup preparation authority failed")]
    Repository(#[from] RepositoryError),
    /// Local staging evidence could not be committed or reconciled.
    #[error("metadata backup preparation journal failed")]
    Staging(#[from] LocalMetadataBackupStagingError),
    /// Filesystem durability failed.
    #[error("metadata backup preparation filesystem operation failed")]
    Io(#[from] std::io::Error),
}
