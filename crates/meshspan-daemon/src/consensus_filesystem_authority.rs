// SPDX-License-Identifier: GPL-2.0-only

//! Current consensus projection adapters for specialised filesystem APIs.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_cluster::{MetadataFilesystemAuthority, MetadataFilesystemAuthorityError};
use meshspan_filesystem::{
    FilesystemAccessAuthority, FilesystemAccessContext, FilesystemAuthorityGrant,
    FilesystemAuthorityRequest,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, EntityKind, Page, PageLimit, RepositoryError,
    VolumeInventoryCursor, VolumeInventoryRecord,
};

use crate::{
    ConsensusAuthenticationAuthority, NodeWrappingKeyRegistrationAuthority,
    NodeWrappingKeyRegistrationAuthorityError, RecoveryBundleVerificationAuthority,
    RecoveryBundleVerificationAuthorityError, RecoveryBundleVerificationCommit,
    StorageTargetRegistrationAuthority, StorageTargetRegistrationAuthorityError,
    VolumeAdministrationAuthority, VolumeAdministrationAuthorityError, VolumeAdministrationCommit,
    VolumeInventoryAuthority, VolumeInventoryAuthorityError,
};

impl FilesystemAccessAuthority for ConsensusAuthenticationAuthority {
    type Error = MetadataFilesystemAuthorityError;

    fn authorise(
        &self,
        request: FilesystemAuthorityRequest,
    ) -> Result<FilesystemAuthorityGrant, Self::Error> {
        MetadataFilesystemAuthority::new(self.reader()).authorise(request)
    }

    fn authorise_volume_root(
        &self,
        context: FilesystemAccessContext,
        volume_id: meshspan_domain::VolumeId,
        requested_rights: meshspan_domain::Rights,
    ) -> Result<FilesystemAuthorityGrant, Self::Error> {
        MetadataFilesystemAuthority::new(self.reader()).authorise_volume_root(
            context,
            volume_id,
            requested_rights,
        )
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

impl RecoveryBundleVerificationAuthority for ConsensusAuthenticationAuthority {
    fn is_system_manager(
        &self,
        principal_id: meshspan_domain::PrincipalId,
        now: meshspan_domain::UnixMicros,
    ) -> Result<bool, RecoveryBundleVerificationAuthorityError> {
        self.reader()
            .principal_is_system_manager(principal_id, now)
            .map_err(|error| map_recovery_repository_error(&error))
    }

    fn recovery_authority(
        &self,
        mesh_id: meshspan_domain::MeshId,
    ) -> Result<
        Option<meshspan_metadata::MeshRecoveryAuthority>,
        RecoveryBundleVerificationAuthorityError,
    > {
        self.reader()
            .mesh_recovery_authority(mesh_id)
            .map_err(|error| map_recovery_repository_error(&error))
    }

    fn resolve_recovery_bundle_verification(
        &self,
        operation_id: meshspan_domain::OperationId,
    ) -> Result<Option<RecoveryBundleVerificationCommit>, RecoveryBundleVerificationAuthorityError>
    {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| map_recovery_repository_error(&error))?
            .map(|receipt| recovery_verification_commit(self.reader(), receipt))
            .transpose()
    }

    fn commit_or_resolve_recovery_bundle_verification(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<RecoveryBundleVerificationCommit, RecoveryBundleVerificationAuthorityError> {
        let expected_digest = command.request_digest(context);
        let receipt = self
            .commit_authoritative(context, command)
            .map_err(map_recovery_authority_error)?;
        if receipt.request_digest != expected_digest {
            return Err(RecoveryBundleVerificationAuthorityError::Conflict);
        }
        recovery_verification_commit(self.reader(), receipt)
    }
}

impl StorageTargetRegistrationAuthority for ConsensusAuthenticationAuthority {
    fn registration_context(
        &self,
        node_id: meshspan_domain::NodeId,
        now: meshspan_domain::UnixMicros,
    ) -> Result<
        Option<meshspan_metadata::StorageTargetRegistrationContext>,
        StorageTargetRegistrationAuthorityError,
    > {
        self.reader()
            .storage_target_registration_context(node_id, now)
            .map_err(StorageTargetRegistrationAuthorityError::from)
    }

    fn commit_or_resolve_registration(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<meshspan_metadata::CommandReceipt, StorageTargetRegistrationAuthorityError> {
        self.commit_authoritative(context, command)
            .map_err(map_storage_target_authority_error)
    }
}

impl NodeWrappingKeyRegistrationAuthority for ConsensusAuthenticationAuthority {
    fn registration_context(
        &self,
        node_id: meshspan_domain::NodeId,
        now: meshspan_domain::UnixMicros,
    ) -> Result<
        Option<meshspan_metadata::StorageTargetRegistrationContext>,
        NodeWrappingKeyRegistrationAuthorityError,
    > {
        self.reader()
            .storage_target_registration_context(node_id, now)
            .map_err(NodeWrappingKeyRegistrationAuthorityError::from)
    }

    fn current_key(
        &self,
        node_id: meshspan_domain::NodeId,
    ) -> Result<
        Option<meshspan_metadata::NodeWrappingKeyRecord>,
        NodeWrappingKeyRegistrationAuthorityError,
    > {
        self.reader()
            .node_wrapping_key(node_id)
            .map_err(NodeWrappingKeyRegistrationAuthorityError::from)
    }

    fn commit_or_resolve_registration(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<meshspan_metadata::CommandReceipt, NodeWrappingKeyRegistrationAuthorityError> {
        self.commit_authoritative(context, command)
            .map_err(map_node_wrapping_key_authority_error)
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

fn recovery_verification_commit(
    repository: &meshspan_metadata::AuthoritativeRepository,
    receipt: meshspan_metadata::CommandReceipt,
) -> Result<RecoveryBundleVerificationCommit, RecoveryBundleVerificationAuthorityError> {
    if receipt.entity.kind != EntityKind::RecoveryAuthority {
        return Err(RecoveryBundleVerificationAuthorityError::Conflict);
    }
    let mesh_id = meshspan_domain::MeshId::from_bytes(receipt.entity.id)
        .map_err(|_| RecoveryBundleVerificationAuthorityError::Failed)?;
    let authority = repository
        .mesh_recovery_authority(mesh_id)
        .map_err(|error| map_recovery_repository_error(&error))?
        .ok_or(RecoveryBundleVerificationAuthorityError::Failed)?;
    if authority.revision != receipt.committed_revision
        || authority.state != meshspan_metadata::RecoveryBundleState::Verified
    {
        return Err(RecoveryBundleVerificationAuthorityError::Failed);
    }
    Ok(RecoveryBundleVerificationCommit {
        request_digest: receipt.request_digest,
        result_digest: receipt.result_digest,
        authority,
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

fn map_recovery_authority_error(
    error: MetadataAuthorityRequestError,
) -> RecoveryBundleVerificationAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            RecoveryBundleVerificationAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            RecoveryBundleVerificationAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            RecoveryBundleVerificationAuthorityError::Failed
        }
    }
}

fn map_storage_target_authority_error(
    error: MetadataAuthorityRequestError,
) -> StorageTargetRegistrationAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            StorageTargetRegistrationAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            StorageTargetRegistrationAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            StorageTargetRegistrationAuthorityError::Failed
        }
    }
}

fn map_node_wrapping_key_authority_error(
    error: MetadataAuthorityRequestError,
) -> NodeWrappingKeyRegistrationAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            NodeWrappingKeyRegistrationAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            NodeWrappingKeyRegistrationAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            NodeWrappingKeyRegistrationAuthorityError::Failed
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

fn map_recovery_repository_error(
    error: &RepositoryError,
) -> RecoveryBundleVerificationAuthorityError {
    match error {
        RepositoryError::OperationConflict
        | RepositoryError::StaleRevision
        | RepositoryError::InvalidCommand => RecoveryBundleVerificationAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            RecoveryBundleVerificationAuthorityError::Unavailable
        }
        _ => RecoveryBundleVerificationAuthorityError::Failed,
    }
}
