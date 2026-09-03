// SPDX-License-Identifier: GPL-2.0-only

//! Non-destructive recovery proof for one exact verified metadata-backup copy.

use std::fs::{File, OpenOptions};
use std::path::Path;

use meshspan_backup::{BackupFileEvidence, BackupSourceManifest};
use meshspan_contracts::{
    BackupObjectIdentity, BackupObjectReference, BackupProvider, BackupReadRequest, ContractError,
    ContractVersion, RequestContext,
};
use meshspan_domain::{BackupDestinationId, BackupId, OperationId, Revision, UnixMicros};
use meshspan_metadata::{
    BackupCopyRecord, BackupCopyState, EncryptedPartitionBackupManifest, EncryptedRestorePaths,
    LogPosition, MetadataBackupRecord, MetadataBackupState, PartitionBackupManifest,
    RepositoryError, restore_encrypted_partition_backup,
};
use meshspan_secret_envelope::WrappingPrivateKey;
use thiserror::Error;

use crate::ConsensusAuthenticationAuthority;

/// Replicated reads needed to prove one restore candidate.
pub trait BackupRestoreReadinessAuthority {
    /// Loads the exact backup generation.
    ///
    /// # Errors
    ///
    /// Fails closed for unavailable or malformed replicated state.
    fn metadata_backup(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRecord>, RepositoryError>;

    /// Loads the exact provider copy.
    ///
    /// # Errors
    ///
    /// Fails closed for unavailable or malformed replicated state.
    fn backup_copy(
        &self,
        backup_id: BackupId,
        destination_id: BackupDestinationId,
    ) -> Result<Option<BackupCopyRecord>, RepositoryError>;
}

impl BackupRestoreReadinessAuthority for ConsensusAuthenticationAuthority {
    fn metadata_backup(
        &self,
        backup_id: BackupId,
    ) -> Result<Option<MetadataBackupRecord>, RepositoryError> {
        self.reader().metadata_backup(backup_id)
    }

    fn backup_copy(
        &self,
        backup_id: BackupId,
        destination_id: BackupDestinationId,
    ) -> Result<Option<BackupCopyRecord>, RepositoryError> {
        self.reader().backup_copy(backup_id, destination_id)
    }
}

/// Three distinct, absent paths used only during a non-destructive recovery proof.
#[derive(Clone, Copy, Debug)]
pub struct BackupRestoreReadinessPaths<'a> {
    /// New file receiving exact encrypted bytes from the provider.
    pub encrypted_staging: &'a Path,
    /// New file receiving authenticated plaintext SQLite bytes.
    pub plaintext_staging: &'a Path,
    /// New isolated database produced and validated by restore.
    pub restored_database: &'a Path,
}

/// Exact inputs for one bounded restore-readiness check.
pub struct BackupRestoreReadinessRequest<'a> {
    /// Catalogue backup generation.
    pub backup_id: BackupId,
    /// Verified destination copy to exercise.
    pub destination_id: BackupDestinationId,
    /// Unique provider read operation.
    pub operation_id: OperationId,
    /// Provider IO deadline.
    pub deadline: UnixMicros,
    /// Authority time of this check.
    pub checked_at: UnixMicros,
    /// Recovery recipient key retained outside provider storage.
    pub recovery_key: &'a WrappingPrivateKey,
    /// Caller-owned isolated staging paths.
    pub paths: BackupRestoreReadinessPaths<'a>,
}

/// Evidence returned only after complete decryption and SQLite recovery validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackupRestoreReadinessEvidence {
    /// Exact checked backup generation.
    pub backup_id: BackupId,
    /// Exact checked destination.
    pub destination_id: BackupDestinationId,
    /// Source partition recovered in isolation.
    pub partition_id: meshspan_domain::PartitionId,
    /// Committed position recovered from the database.
    pub applied_position: LogPosition,
    /// State revision recovered from the database.
    pub state_revision: Revision,
    /// Authority time of the successful check.
    pub checked_at: UnixMicros,
}

/// Read-only coordinator for a non-destructive restore proof.
pub struct MetadataBackupRestoreReadiness<'a, Authority> {
    authority: &'a Authority,
}

impl<'a, Authority> MetadataBackupRestoreReadiness<'a, Authority> {
    /// Binds readiness checks to current replicated catalogue reads.
    #[must_use]
    pub const fn new(authority: &'a Authority) -> Self {
        Self { authority }
    }
}

impl<Authority> MetadataBackupRestoreReadiness<'_, Authority>
where
    Authority: BackupRestoreReadinessAuthority,
{
    /// Streams, decrypts and validates one copy without touching live authority state.
    ///
    /// # Errors
    ///
    /// Rejects unverified/mismatched evidence, elapsed deadlines, existing/overlapping paths,
    /// provider failure, unavailable recovery material, invalid SQLite state or cleanup failure.
    pub fn check<P: BackupProvider>(
        &self,
        provider: &P,
        request: &BackupRestoreReadinessRequest<'_>,
    ) -> Result<BackupRestoreReadinessEvidence, BackupRestoreReadinessError> {
        validate_request(request)?;
        let backup = self
            .authority
            .metadata_backup(request.backup_id)?
            .ok_or(BackupRestoreReadinessError::NotReady)?;
        let copy = self
            .authority
            .backup_copy(request.backup_id, request.destination_id)?
            .ok_or(BackupRestoreReadinessError::NotReady)?;
        let manifest = validate_catalogue(backup, &copy, request.destination_id)?;
        let result = Self::run_check(provider, request, &manifest, &copy);
        cleanup_paths(request.paths)?;
        result
    }

    fn run_check<P: BackupProvider>(
        provider: &P,
        request: &BackupRestoreReadinessRequest<'_>,
        manifest: &EncryptedPartitionBackupManifest,
        copy: &BackupCopyRecord,
    ) -> Result<BackupRestoreReadinessEvidence, BackupRestoreReadinessError> {
        let mut encrypted = create_new(request.paths.encrypted_staging)?;
        let object_reference = BackupObjectReference::new(copy.object_reference.clone())?;
        let read = provider.read_exact(
            &BackupReadRequest {
                context: RequestContext {
                    contract_version: ContractVersion::V1_0,
                    operation_id: request.operation_id,
                    deadline: request.deadline,
                    expected_revision: Some(copy.revision),
                },
                object: BackupObjectIdentity {
                    backup_id: request.backup_id,
                    destination_id: request.destination_id,
                    provider_generation: copy.provider_generation,
                    byte_length: copy.byte_length,
                    digest: copy.copy_digest,
                },
                object_reference,
            },
            &mut encrypted,
            request.checked_at,
        )?;
        encrypted.sync_all()?;
        drop(encrypted);
        if read.operation_id != request.operation_id
            || read.byte_length != manifest.encrypted.byte_length
            || read.digest != manifest.encrypted.digest
        {
            return Err(BackupRestoreReadinessError::InvalidReceipt);
        }
        let restored = restore_encrypted_partition_backup(
            EncryptedRestorePaths {
                encrypted_source: request.paths.encrypted_staging,
                plaintext_staging: request.paths.plaintext_staging,
                restored_destination: request.paths.restored_database,
            },
            *manifest,
            request.recovery_key,
            request.checked_at,
        )?;
        drop(restored);
        Ok(BackupRestoreReadinessEvidence {
            backup_id: request.backup_id,
            destination_id: request.destination_id,
            partition_id: manifest.partition.partition_id,
            applied_position: manifest.partition.applied_position,
            state_revision: manifest.partition.state_revision,
            checked_at: request.checked_at,
        })
    }
}

fn validate_request(
    request: &BackupRestoreReadinessRequest<'_>,
) -> Result<(), BackupRestoreReadinessError> {
    let paths = request.paths;
    if request.checked_at.get() < 0
        || request.deadline <= request.checked_at
        || paths.encrypted_staging == paths.plaintext_staging
        || paths.encrypted_staging == paths.restored_database
        || paths.plaintext_staging == paths.restored_database
        || paths.encrypted_staging.try_exists()?
        || paths.plaintext_staging.try_exists()?
        || paths.restored_database.try_exists()?
    {
        return Err(BackupRestoreReadinessError::InvalidInput);
    }
    Ok(())
}

pub(crate) fn validate_catalogue(
    backup: MetadataBackupRecord,
    copy: &BackupCopyRecord,
    destination_id: BackupDestinationId,
) -> Result<EncryptedPartitionBackupManifest, BackupRestoreReadinessError> {
    if backup.state != MetadataBackupState::Verified
        || copy.state != BackupCopyState::Verified
        || copy.backup_id != backup.backup_id
        || copy.destination_id != destination_id
        || copy.provider_generation == 0
        || copy.byte_length != backup.encrypted_byte_length
        || copy.copy_digest != backup.encrypted_digest
        || backup.revision == Revision::ZERO
        || copy.revision == Revision::ZERO
    {
        return Err(BackupRestoreReadinessError::NotReady);
    }
    let source = BackupSourceManifest {
        backup_id: backup.backup_id,
        partition_id: backup.partition_id,
        mesh_id: backup.mesh_id,
        last_log_index: backup.last_log_index,
        last_log_term: backup.last_log_term,
        state_revision: backup.state_revision.get(),
        schema_version: backup.schema_version,
        byte_length: backup.source_byte_length,
        digest: backup.source_digest,
        created_at: backup.created_at,
    };
    source.validate()?;
    if source.catalogue_digest() != backup.manifest_digest {
        return Err(BackupRestoreReadinessError::NotReady);
    }
    Ok(EncryptedPartitionBackupManifest {
        partition: PartitionBackupManifest {
            backup_id: backup.backup_id,
            partition_id: backup.partition_id,
            mesh_id: backup.mesh_id,
            applied_position: LogPosition {
                index: backup.last_log_index,
                term: backup.last_log_term,
            },
            state_revision: backup.state_revision,
            schema_version: backup.schema_version,
            byte_length: backup.source_byte_length,
            digest: backup.source_digest,
            created_at: backup.created_at,
        },
        encrypted: BackupFileEvidence {
            source,
            byte_length: backup.encrypted_byte_length,
            digest: backup.encrypted_digest,
        },
    })
}

fn create_new(file_path: &Path) -> Result<File, BackupRestoreReadinessError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(file_path)
        .map_err(Into::into)
}

fn cleanup_paths(
    paths: BackupRestoreReadinessPaths<'_>,
) -> Result<(), BackupRestoreReadinessError> {
    let mut candidates = vec![
        paths.encrypted_staging.to_path_buf(),
        paths.plaintext_staging.to_path_buf(),
        paths.restored_database.to_path_buf(),
    ];
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = paths.restored_database.as_os_str().to_owned();
        sidecar.push(suffix);
        candidates.push(sidecar.into());
    }
    let mut first_error = None;
    for file_path in candidates {
        if let Err(error) = std::fs::remove_file(&file_path)
            && error.kind() != std::io::ErrorKind::NotFound
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    first_error.map_or(Ok(()), |error| Err(error.into()))
}

/// Failure to prove one metadata-backup copy can be restored safely.
#[derive(Debug, Error)]
pub enum BackupRestoreReadinessError {
    /// Time or staging paths are invalid.
    #[error("backup restore-readiness input is invalid")]
    InvalidInput,
    /// The selected generation or copy is absent, stale, unverified or contradictory.
    #[error("backup copy is not a valid restore candidate")]
    NotReady,
    /// Provider completion evidence contradicts the requested object.
    #[error("backup provider returned invalid read evidence")]
    InvalidReceipt,
    /// Replicated catalogue access failed closed.
    #[error("backup catalogue query failed")]
    Repository(#[from] RepositoryError),
    /// Provider IO or integrity validation failed closed.
    #[error("backup provider read failed")]
    Provider(#[from] ContractError),
    /// Backup container structure, authentication or key recovery failed.
    #[error("backup recovery validation failed")]
    Backup(#[from] meshspan_backup::BackupError),
    /// Local isolated staging IO failed.
    #[error("backup restore staging failed")]
    Io(#[from] std::io::Error),
}
