// SPDX-License-Identifier: GPL-2.0-only

//! Current consensus projection adapters for specialised filesystem APIs.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_cluster::{MetadataFilesystemAuthority, MetadataFilesystemAuthorityError};
use meshspan_filesystem::{
    FilesystemAccessAuthority, FilesystemAuthorityGrant, FilesystemAuthorityRequest,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, EntityKind, Page, PageLimit, RepositoryError,
    VolumeInventoryCursor, VolumeInventoryRecord,
};

use crate::{
    ConsensusAuthenticationAuthority, VolumeAdministrationAuthority,
    VolumeAdministrationAuthorityError, VolumeAdministrationCommit, VolumeInventoryAuthority,
    VolumeInventoryAuthorityError,
};

impl FilesystemAccessAuthority for ConsensusAuthenticationAuthority {
    type Error = MetadataFilesystemAuthorityError;

    fn authorise(
        &self,
        request: FilesystemAuthorityRequest,
    ) -> Result<FilesystemAuthorityGrant, Self::Error> {
        MetadataFilesystemAuthority::new(self.reader()).authorise(request)
    }
}

impl VolumeInventoryAuthority for ConsensusAuthenticationAuthority {
    fn volume_candidates(
        &self,
        after: Option<&VolumeInventoryCursor>,
        limit: PageLimit,
    ) -> Result<Page<VolumeInventoryRecord, VolumeInventoryCursor>, VolumeInventoryAuthorityError>
    {
        VolumeInventoryAuthority::volume_candidates(self.reader(), after, limit)
    }

    fn volume_rights(
        &self,
        context: meshspan_filesystem::FilesystemAccessContext,
        volume: &VolumeInventoryRecord,
    ) -> Result<Option<meshspan_domain::Rights>, VolumeInventoryAuthorityError> {
        VolumeInventoryAuthority::volume_rights(self.reader(), context, volume)
    }
}

impl VolumeAdministrationAuthority for ConsensusAuthenticationAuthority {
    fn is_system_manager(
        &self,
        principal_id: meshspan_domain::PrincipalId,
        now: meshspan_domain::UnixMicros,
    ) -> Result<bool, VolumeAdministrationAuthorityError> {
        self.reader()
            .principal_is_system_manager(principal_id, now)
            .map_err(|error| map_volume_repository_error(&error))
    }

    fn resolve_volume_creation(
        &self,
        operation_id: meshspan_domain::OperationId,
    ) -> Result<Option<VolumeAdministrationCommit>, VolumeAdministrationAuthorityError> {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| map_volume_repository_error(&error))?
            .map(|receipt| volume_commit(self.reader(), receipt))
            .transpose()
    }

    fn commit_or_resolve_volume_creation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<VolumeAdministrationCommit, VolumeAdministrationAuthorityError> {
        let expected_digest = command.request_digest(context);
        let receipt = self
            .commit_authoritative(context, command)
            .map_err(map_volume_authority_error)?;
        if receipt.request_digest != expected_digest {
            return Err(VolumeAdministrationAuthorityError::Conflict);
        }
        volume_commit(self.reader(), receipt)
    }
}

fn volume_commit(
    repository: &meshspan_metadata::AuthoritativeRepository,
    receipt: meshspan_metadata::CommandReceipt,
) -> Result<VolumeAdministrationCommit, VolumeAdministrationAuthorityError> {
    if receipt.entity.kind != EntityKind::Volume {
        return Err(VolumeAdministrationAuthorityError::Conflict);
    }
    let volume_id = meshspan_domain::VolumeId::from_bytes(receipt.entity.id)
        .map_err(|_| VolumeAdministrationAuthorityError::Failed)?;
    let record = repository
        .volume_inventory_record(volume_id)
        .map_err(|error| map_volume_repository_error(&error))?
        .ok_or(VolumeAdministrationAuthorityError::Failed)?;
    if record.revision != receipt.committed_revision {
        return Err(VolumeAdministrationAuthorityError::Failed);
    }
    Ok(VolumeAdministrationCommit {
        request_digest: receipt.request_digest,
        result_digest: receipt.result_digest,
        record,
    })
}

fn map_volume_authority_error(
    error: MetadataAuthorityRequestError,
) -> VolumeAdministrationAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            VolumeAdministrationAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            VolumeAdministrationAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            VolumeAdministrationAuthorityError::Failed
        }
    }
}

fn map_volume_repository_error(error: &RepositoryError) -> VolumeAdministrationAuthorityError {
    match error {
        RepositoryError::OperationConflict
        | RepositoryError::StaleRevision
        | RepositoryError::InvalidCommand => VolumeAdministrationAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            VolumeAdministrationAuthorityError::Unavailable
        }
        _ => VolumeAdministrationAuthorityError::Failed,
    }
}
