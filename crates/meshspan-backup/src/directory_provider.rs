// SPDX-License-Identifier: GPL-2.0-only

//! Durable capability-scoped directory implementation of the backup-provider contract.

mod catalogue;
mod object_io;

use std::io::{Read, Write};
use std::path::Path;

use cap_std::fs::Dir;
use catalogue::{Catalogue, OperationKind, operation_digest};
use meshspan_contracts::{
    BackupDeleteReceipt, BackupDeleteRequest, BackupObjectIdentity, BackupObjectReceipt,
    BackupProvider, BackupReadReceipt, BackupReadRequest, BackupStoreRequest, BackupVerifyRequest,
    ContractError, ContractKind, ContractLimits, ContractVersion, ImplementationDescriptor,
    validate_backup_delete_request, validate_backup_read_request, validate_backup_store_request,
    validate_backup_verify_request,
};
use meshspan_domain::{BackupDestinationId, UnixMicros};
use object_io::{
    object_reference, persist_stream, remove_if_present, stream_object, validate_reference,
    verify_measurement,
};
use thiserror::Error;

const PROVIDER_VERSIONS: &[ContractVersion] = &[ContractVersion::V1_0];

/// Self-contained encrypted-backup provider rooted beneath one administrator-selected folder.
pub struct DirectoryBackupProvider {
    objects: Dir,
    catalogue: Catalogue,
    destination_id: BackupDestinationId,
    provider_generation: u64,
    _lock: std::fs::File,
}

impl DirectoryBackupProvider {
    /// Opens or creates one identity-bound provider without inspecting or modifying sibling files.
    ///
    /// # Errors
    ///
    /// Rejects a zero generation/capacity, unavailable path, concurrent owner, schema drift,
    /// identity substitution, corruption or SQLite/IO failure.
    pub fn open(
        storage_path: &Path,
        destination_id: BackupDestinationId,
        provider_generation: u64,
        maximum_bytes: u64,
        opened_at: UnixMicros,
    ) -> Result<Self, DirectoryBackupProviderError> {
        if provider_generation == 0 || maximum_bytes == 0 {
            return Err(DirectoryBackupProviderError::InvalidInput);
        }
        let files = object_io::open(storage_path)?;
        let catalogue = Catalogue::open(
            &files.catalogue_path,
            destination_id,
            provider_generation,
            maximum_bytes,
            opened_at,
        )?;
        Ok(Self {
            objects: files.objects,
            catalogue,
            destination_id,
            provider_generation,
            _lock: files.lock,
        })
    }

    fn validate_binding(&self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        if object.destination_id != self.destination_id
            || object.provider_generation != self.provider_generation
        {
            Err(ContractError::Stale)
        } else {
            Ok(())
        }
    }

    fn store(
        &mut self,
        request: BackupStoreRequest,
        source: &mut dyn Read,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, DirectoryBackupProviderError> {
        validate_backup_store_request(request, observed_at)?;
        self.validate_binding(request.object)?;
        let reference = object_reference(request.object)?;
        let request_digest =
            operation_digest(OperationKind::Store, request, reference.as_str(), None);
        if self.catalogue.operation_completed(
            request.context.operation_id,
            OperationKind::Store,
            request_digest,
        )? {
            return Ok(store_receipt(request, reference));
        }
        self.catalogue.admit_capacity(request.object)?;
        persist_stream(
            &self.objects,
            request.context.operation_id,
            request.object,
            reference.as_str(),
            source,
        )?;
        self.catalogue
            .record_store(request, reference.as_str(), request_digest, observed_at)?;
        Ok(store_receipt(request, reference))
    }

    fn read(
        &self,
        request: &BackupReadRequest,
        destination: &mut dyn Write,
        observed_at: UnixMicros,
    ) -> Result<BackupReadReceipt, DirectoryBackupProviderError> {
        validate_backup_read_request(request, observed_at)?;
        self.validate_binding(request.object)?;
        validate_reference(request.object, &request.object_reference)?;
        self.catalogue
            .validate_live_object(request.object, &request.object_reference)?;
        let (byte_length, digest) = stream_object(
            &self.objects,
            request.object_reference.as_str(),
            destination,
        )?;
        verify_measurement(request.object, byte_length, digest)?;
        Ok(BackupReadReceipt {
            operation_id: request.context.operation_id,
            byte_length,
            digest,
        })
    }

    fn verify(
        &self,
        request: &BackupVerifyRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, DirectoryBackupProviderError> {
        validate_backup_verify_request(request, observed_at)?;
        self.validate_binding(request.object)?;
        validate_reference(request.object, &request.object_reference)?;
        self.catalogue
            .validate_live_object(request.object, &request.object_reference)?;
        let (byte_length, digest) = stream_object(
            &self.objects,
            request.object_reference.as_str(),
            &mut std::io::sink(),
        )?;
        verify_measurement(request.object, byte_length, digest)?;
        Ok(BackupObjectReceipt {
            operation_id: request.context.operation_id,
            object: request.object,
            object_reference: request.object_reference.clone(),
        })
    }

    fn delete(
        &mut self,
        request: &BackupDeleteRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupDeleteReceipt, DirectoryBackupProviderError> {
        validate_backup_delete_request(request, observed_at)?;
        self.validate_binding(request.object)?;
        validate_reference(request.object, &request.object_reference)?;
        let request_digest = operation_digest(
            OperationKind::Delete,
            BackupStoreRequest {
                context: request.context,
                object: request.object,
            },
            request.object_reference.as_str(),
            Some(request.retirement_revision.get()),
        );
        if self.catalogue.operation_completed(
            request.context.operation_id,
            OperationKind::Delete,
            request_digest,
        )? {
            return Ok(delete_receipt(request));
        }
        self.catalogue
            .validate_known_object(request.object, &request.object_reference)?;
        remove_if_present(&self.objects, request.object_reference.as_str())?;
        self.catalogue
            .record_delete(request, request_digest, observed_at)?;
        Ok(delete_receipt(request))
    }
}

impl BackupProvider for DirectoryBackupProvider {
    fn describe(&self) -> ImplementationDescriptor {
        ImplementationDescriptor {
            implementation_id: "meshspan-directory-backup",
            contract: ContractKind::BackupProvider,
            versions: PROVIDER_VERSIONS,
            limits: ContractLimits {
                maximum_control_bytes: 64 * 1_024,
                maximum_items: 1_000,
                maximum_concurrency: 1,
            },
        }
    }

    fn store_exact(
        &mut self,
        request: BackupStoreRequest,
        source: &mut dyn Read,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError> {
        self.store(request, source, observed_at)
            .map_err(|error| contract_error(&error))
    }

    fn read_exact(
        &self,
        request: &BackupReadRequest,
        destination: &mut dyn Write,
        observed_at: UnixMicros,
    ) -> Result<BackupReadReceipt, ContractError> {
        self.read(request, destination, observed_at)
            .map_err(|error| contract_error(&error))
    }

    fn verify_exact(
        &self,
        request: &BackupVerifyRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupObjectReceipt, ContractError> {
        self.verify(request, observed_at)
            .map_err(|error| contract_error(&error))
    }

    fn delete_exact(
        &mut self,
        request: &BackupDeleteRequest,
        observed_at: UnixMicros,
    ) -> Result<BackupDeleteReceipt, ContractError> {
        self.delete(request, observed_at)
            .map_err(|error| contract_error(&error))
    }
}

fn store_receipt(
    request: BackupStoreRequest,
    object_reference: meshspan_contracts::BackupObjectReference,
) -> BackupObjectReceipt {
    BackupObjectReceipt {
        operation_id: request.context.operation_id,
        object: request.object,
        object_reference,
    }
}

fn delete_receipt(request: &BackupDeleteRequest) -> BackupDeleteReceipt {
    BackupDeleteReceipt {
        operation_id: request.context.operation_id,
        object: request.object,
        retirement_revision: request.retirement_revision,
    }
}

fn contract_error(error: &DirectoryBackupProviderError) -> ContractError {
    match error {
        DirectoryBackupProviderError::Contract(error) => *error,
        DirectoryBackupProviderError::InvalidInput => ContractError::InvalidInput,
        DirectoryBackupProviderError::IdentityMismatch => ContractError::Stale,
        DirectoryBackupProviderError::Conflict => ContractError::Conflict,
        DirectoryBackupProviderError::NotFound => ContractError::NotFound,
        DirectoryBackupProviderError::ResourceExhausted => ContractError::ResourceExhausted,
        DirectoryBackupProviderError::Corrupt | DirectoryBackupProviderError::SchemaMismatch => {
            ContractError::Corrupt
        }
        DirectoryBackupProviderError::AlreadyOwned | DirectoryBackupProviderError::Io(_) => {
            ContractError::Unavailable
        }
        DirectoryBackupProviderError::Sqlite(_) => ContractError::Unavailable,
    }
}

/// Failure while opening or operating one directory backup provider.
#[derive(Debug, Error)]
pub enum DirectoryBackupProviderError {
    /// Shared contract validation rejected input before IO.
    #[error("backup provider request is invalid")]
    Contract(#[from] ContractError),
    /// Provider configuration or integer bounds are invalid.
    #[error("backup provider input is invalid")]
    InvalidInput,
    /// Existing state belongs to another destination generation or capacity configuration.
    #[error("backup provider identity does not match")]
    IdentityMismatch,
    /// The provider directory is already owned by another live process.
    #[error("backup provider directory is already owned")]
    AlreadyOwned,
    /// Existing operation or object evidence contradicts this request.
    #[error("backup provider operation conflicts with durable state")]
    Conflict,
    /// The exact requested object does not exist or is retired.
    #[error("backup object was not found")]
    NotFound,
    /// The configured provider-owned capacity ceiling would be exceeded.
    #[error("backup provider capacity is exhausted")]
    ResourceExhausted,
    /// Stored bytes or relational state failed integrity verification.
    #[error("backup provider state is corrupt")]
    Corrupt,
    /// On-disk schema is unknown or drifted from the compiled schema.
    #[error("backup provider schema is incompatible")]
    SchemaMismatch,
    /// Local filesystem operation failed.
    #[error("backup provider filesystem operation failed")]
    Io(#[from] std::io::Error),
    /// Local SQLite operation failed.
    #[error("backup provider catalogue operation failed")]
    Sqlite(#[from] rusqlite::Error),
}
