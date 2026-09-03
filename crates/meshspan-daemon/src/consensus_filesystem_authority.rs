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
    AuthenticationRootAuthority, CertificateOrderCompletionAuthority,
    CertificateOrderCompletionAuthorityError, CertificateProvisioningAuthority,
    CertificateProvisioningAuthorityError, CertificateProvisioningCommit,
    ConsensusAuthenticationAuthority, ExternalCertificatePublisherAuthority,
    ExternalCertificatePublisherAuthorityError, ExternalCertificatePublisherCommit,
    NodeWrappingKeyRegistrationAuthority, NodeWrappingKeyRegistrationAuthorityError,
    OnlineAuthorityLoadingAuthority, PublicCertificateInstallationAuthority,
    PublicCertificateInstallationAuthorityError, PublicCertificateSelectionAuthority,
    PublicCertificateSelectionAuthorityError, RecoveryBundleVerificationAuthority,
    RecoveryBundleVerificationAuthorityError, RecoveryBundleVerificationCommit,
    SecretGenerationAuthority, SecretGenerationAuthorityError, StoragePermitAuthority,
    StorageTargetRegistrationAuthority, StorageTargetRegistrationAuthorityError,
    VolumeAdministrationAuthority, VolumeAdministrationAuthorityError, VolumeAdministrationCommit,
    VolumeInventoryAuthority, VolumeInventoryAuthorityError, VolumeKeyAuthority,
};

impl ExternalCertificatePublisherAuthority for ConsensusAuthenticationAuthority {
    fn is_system_manager(
        &self,
        principal_id: meshspan_domain::PrincipalId,
        now: meshspan_domain::UnixMicros,
    ) -> Result<bool, ExternalCertificatePublisherAuthorityError> {
        self.reader()
            .principal_is_system_manager(principal_id, now)
            .map_err(|error| map_external_publisher_repository_error(&error))
    }

    fn resolve_external_certificate_publication(
        &self,
        operation_id: meshspan_domain::OperationId,
    ) -> Result<
        Option<ExternalCertificatePublisherCommit>,
        ExternalCertificatePublisherAuthorityError,
    > {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| map_external_publisher_repository_error(&error))?
            .map(|receipt| external_certificate_commit(self.reader(), receipt))
            .transpose()
    }

    fn certificate_secret_recipients(
        &self,
    ) -> Result<
        Vec<meshspan_secret_envelope::WrappingPublicKey>,
        ExternalCertificatePublisherAuthorityError,
    > {
        self.reader()
            .volume_key_recipients()
            .map_err(|error| map_external_publisher_repository_error(&error))
    }

    fn commit_or_resolve_external_certificate_publication(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<ExternalCertificatePublisherCommit, ExternalCertificatePublisherAuthorityError>
    {
        let expected_digest = command.request_digest(context);
        let receipt = self
            .commit_authoritative(context, command)
            .map_err(map_external_publisher_authority_error)?;
        if receipt.request_digest != expected_digest {
            return Err(ExternalCertificatePublisherAuthorityError::Conflict);
        }
        external_certificate_commit(self.reader(), receipt)
    }
}

impl CertificateProvisioningAuthority for ConsensusAuthenticationAuthority {
    fn is_system_manager(
        &self,
        principal_id: meshspan_domain::PrincipalId,
        now: meshspan_domain::UnixMicros,
    ) -> Result<bool, CertificateProvisioningAuthorityError> {
        self.reader()
            .principal_is_system_manager(principal_id, now)
            .map_err(|error| map_provisioning_repository_error(&error))
    }

    fn resolve_certificate_provisioning(
        &self,
        operation_id: meshspan_domain::OperationId,
    ) -> Result<Option<CertificateProvisioningCommit>, CertificateProvisioningAuthorityError> {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| map_provisioning_repository_error(&error))?
            .map(|receipt| certificate_commit(self.reader(), receipt))
            .transpose()
    }

    fn certificate_secret_recipients(
        &self,
    ) -> Result<
        Vec<meshspan_secret_envelope::WrappingPublicKey>,
        CertificateProvisioningAuthorityError,
    > {
        self.reader()
            .volume_key_recipients()
            .map_err(|error| map_provisioning_repository_error(&error))
    }

    fn commit_or_resolve_certificate_provisioning(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CertificateProvisioningCommit, CertificateProvisioningAuthorityError> {
        let expected_digest = command.request_digest(context);
        let receipt = self
            .commit_authoritative(context, command)
            .map_err(map_provisioning_authority_error)?;
        if receipt.request_digest != expected_digest {
            return Err(CertificateProvisioningAuthorityError::Conflict);
        }
        certificate_commit(self.reader(), receipt)
    }
}

impl PublicCertificateInstallationAuthority for ConsensusAuthenticationAuthority {
    fn resolve_public_certificate_installation(
        &self,
        operation_id: meshspan_domain::OperationId,
    ) -> Result<
        Option<meshspan_metadata::CommandReceipt>,
        PublicCertificateInstallationAuthorityError,
    > {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| map_installation_repository_error(&error))
    }

    fn acknowledge_public_certificate_installation(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<meshspan_metadata::CommandReceipt, PublicCertificateInstallationAuthorityError>
    {
        self.commit_authoritative(context, command)
            .map_err(map_installation_authority_error)
    }
}

impl PublicCertificateSelectionAuthority for ConsensusAuthenticationAuthority {
    fn latest_public_certificate(
        &self,
    ) -> Result<
        Option<meshspan_metadata::PublicCertificateSelection>,
        PublicCertificateSelectionAuthorityError,
    > {
        self.reader()
            .latest_public_certificate()
            .map_err(|error| match error {
                RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
                    PublicCertificateSelectionAuthorityError::Unavailable
                }
                _ => PublicCertificateSelectionAuthorityError::Failed,
            })
    }
}

fn map_installation_repository_error(
    error: &RepositoryError,
) -> PublicCertificateInstallationAuthorityError {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            PublicCertificateInstallationAuthorityError::Unavailable
        }
        RepositoryError::OperationConflict
        | RepositoryError::StaleRevision
        | RepositoryError::InvalidCommand => PublicCertificateInstallationAuthorityError::Conflict,
        _ => PublicCertificateInstallationAuthorityError::Failed,
    }
}

fn map_installation_authority_error(
    error: MetadataAuthorityRequestError,
) -> PublicCertificateInstallationAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            PublicCertificateInstallationAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            PublicCertificateInstallationAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            PublicCertificateInstallationAuthorityError::Failed
        }
    }
}

impl CertificateOrderCompletionAuthority for ConsensusAuthenticationAuthority {
    fn resolve_certificate_order_completion(
        &self,
        operation_id: meshspan_domain::OperationId,
    ) -> Result<Option<meshspan_metadata::CommandReceipt>, CertificateOrderCompletionAuthorityError>
    {
        self.reader()
            .resolve_operation(operation_id)
            .map_err(|error| map_certificate_repository_error(&error))
    }

    fn certificate_recipients(
        &self,
    ) -> Result<
        Vec<meshspan_secret_envelope::WrappingPublicKey>,
        CertificateOrderCompletionAuthorityError,
    > {
        self.reader()
            .volume_key_recipients()
            .map_err(|error| map_certificate_repository_error(&error))
    }

    fn complete_certificate_order(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<meshspan_metadata::CommandReceipt, CertificateOrderCompletionAuthorityError> {
        self.commit_authoritative(context, command)
            .map_err(map_certificate_authority_error)
    }
}

fn map_certificate_repository_error(
    error: &RepositoryError,
) -> CertificateOrderCompletionAuthorityError {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            CertificateOrderCompletionAuthorityError::Unavailable
        }
        _ => CertificateOrderCompletionAuthorityError::Failed,
    }
}

fn map_certificate_authority_error(
    error: MetadataAuthorityRequestError,
) -> CertificateOrderCompletionAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            CertificateOrderCompletionAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            CertificateOrderCompletionAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            CertificateOrderCompletionAuthorityError::Failed
        }
    }
}

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

    fn volume_key_recipients(
        &self,
    ) -> Result<Vec<meshspan_secret_envelope::WrappingPublicKey>, VolumeAdministrationAuthorityError>
    {
        self.reader()
            .volume_key_recipients()
            .map_err(|error| map_volume_repository_error(&error))
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

impl VolumeKeyAuthority for ConsensusAuthenticationAuthority {
    fn latest_generation(
        &self,
        volume_id: meshspan_domain::VolumeId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError> {
        self.reader()
            .latest_volume_key_generation(volume_id)
            .map_err(|error| map_volume_key_repository_error(&error))
    }
}

impl SecretGenerationAuthority for ConsensusAuthenticationAuthority {
    fn secret_generation(
        &self,
        context: meshspan_secret_envelope::SecretContext,
    ) -> Result<Option<meshspan_metadata::SecretGenerationRecord>, SecretGenerationAuthorityError>
    {
        self.reader()
            .secret_generation(context)
            .map_err(|error| map_volume_key_repository_error(&error))
    }
}

impl StoragePermitAuthority for ConsensusAuthenticationAuthority {
    fn latest_generation(
        &self,
        mesh_id: meshspan_domain::MeshId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError> {
        self.reader()
            .latest_storage_permit_generation(mesh_id)
            .map_err(|error| map_volume_key_repository_error(&error))
    }
}

impl AuthenticationRootAuthority for ConsensusAuthenticationAuthority {
    fn local_mesh_id(
        &self,
    ) -> Result<Option<meshspan_domain::MeshId>, SecretGenerationAuthorityError> {
        self.reader()
            .local_mesh_id()
            .map_err(|error| map_volume_key_repository_error(&error))
    }

    fn latest_authentication_root_generation(
        &self,
        mesh_id: meshspan_domain::MeshId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError> {
        self.reader()
            .latest_authentication_root_generation(mesh_id)
            .map_err(|error| map_volume_key_repository_error(&error))
    }
}

impl OnlineAuthorityLoadingAuthority for ConsensusAuthenticationAuthority {
    fn local_mesh_id(
        &self,
    ) -> Result<Option<meshspan_domain::MeshId>, SecretGenerationAuthorityError> {
        self.reader()
            .local_mesh_id()
            .map_err(|error| map_volume_key_repository_error(&error))
    }

    fn online_certificate_authority(
        &self,
        mesh_id: meshspan_domain::MeshId,
    ) -> Result<
        Option<meshspan_metadata::OnlineCertificateAuthorityRecord>,
        SecretGenerationAuthorityError,
    > {
        self.reader()
            .online_certificate_authority(mesh_id)
            .map_err(|error| map_volume_key_repository_error(&error))
    }
}

fn map_volume_key_repository_error(error: &RepositoryError) -> SecretGenerationAuthorityError {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            SecretGenerationAuthorityError::Unavailable
        }
        _ => SecretGenerationAuthorityError::Failed,
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

    fn provider_context(
        &self,
        node_id: meshspan_domain::NodeId,
        target_id: meshspan_domain::TargetId,
    ) -> Result<
        Option<meshspan_metadata::StorageTargetProviderContext>,
        StorageTargetRegistrationAuthorityError,
    > {
        self.reader()
            .readable_storage_target_provider_context(node_id, target_id)
            .map_err(StorageTargetRegistrationAuthorityError::from)
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
    let owners = volume_owners(repository, record.root_object_id)?;
    Ok(VolumeAdministrationCommit {
        request_digest: receipt.request_digest,
        result_digest: receipt.result_digest,
        record,
        owners,
    })
}

fn certificate_commit(
    repository: &meshspan_metadata::AuthoritativeRepository,
    receipt: meshspan_metadata::CommandReceipt,
) -> Result<CertificateProvisioningCommit, CertificateProvisioningAuthorityError> {
    if receipt.entity.kind != EntityKind::CertificateOrder {
        return Err(CertificateProvisioningAuthorityError::Conflict);
    }
    let order_id = meshspan_domain::CertificateOrderId::from_bytes(receipt.entity.id)
        .map_err(|_| CertificateProvisioningAuthorityError::Failed)?;
    let order = repository
        .certificate_order(order_id)
        .map_err(|error| map_provisioning_repository_error(&error))?
        .ok_or(CertificateProvisioningAuthorityError::Failed)?;
    let configuration = repository
        .acme_configuration(order.config_id)
        .map_err(|error| map_provisioning_repository_error(&error))?
        .ok_or(CertificateProvisioningAuthorityError::Failed)?;
    if configuration.revision != receipt.committed_revision
        || order.revision < receipt.committed_revision
    {
        return Err(CertificateProvisioningAuthorityError::Failed);
    }
    Ok(CertificateProvisioningCommit {
        request_digest: receipt.request_digest,
        result_digest: receipt.result_digest,
        committed_revision: receipt.committed_revision,
        configuration,
        order,
    })
}

fn external_certificate_commit(
    repository: &meshspan_metadata::AuthoritativeRepository,
    receipt: meshspan_metadata::CommandReceipt,
) -> Result<ExternalCertificatePublisherCommit, ExternalCertificatePublisherAuthorityError> {
    if receipt.entity.kind != EntityKind::ExternalCertificatePublication {
        return Err(ExternalCertificatePublisherAuthorityError::Conflict);
    }
    let publication_id =
        meshspan_domain::ExternalCertificatePublicationId::from_bytes(receipt.entity.id)
            .map_err(|_| ExternalCertificatePublisherAuthorityError::Failed)?;
    let publication = repository
        .external_certificate_publication(publication_id)
        .map_err(|error| map_external_publisher_repository_error(&error))?
        .ok_or(ExternalCertificatePublisherAuthorityError::Failed)?;
    if publication.revision != receipt.committed_revision {
        return Err(ExternalCertificatePublisherAuthorityError::Failed);
    }
    Ok(ExternalCertificatePublisherCommit {
        request_digest: receipt.request_digest,
        result_digest: receipt.result_digest,
        committed_revision: receipt.committed_revision,
        publication,
    })
}

fn volume_owners(
    repository: &meshspan_metadata::AuthoritativeRepository,
    root_object_id: meshspan_domain::ObjectId,
) -> Result<Vec<meshspan_domain::PrincipalId>, VolumeAdministrationAuthorityError> {
    let limit = PageLimit::new(1_000).map_err(|_| VolumeAdministrationAuthorityError::Failed)?;
    let mut cursor = None;
    let mut owners = Vec::new();
    loop {
        let page = repository
            .object_owners(root_object_id, cursor, limit)
            .map_err(|error| map_volume_repository_error(&error))?
            .ok_or(VolumeAdministrationAuthorityError::Failed)?;
        owners.extend(page.items.into_iter().map(|owner| owner.owner_principal_id));
        if owners.len() > 1_024 {
            return Err(VolumeAdministrationAuthorityError::Failed);
        }
        let Some(next) = page.next else {
            break;
        };
        cursor = Some(next);
    }
    if owners.is_empty() || owners.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(VolumeAdministrationAuthorityError::Failed);
    }
    Ok(owners)
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

fn map_provisioning_authority_error(
    error: MetadataAuthorityRequestError,
) -> CertificateProvisioningAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            CertificateProvisioningAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            CertificateProvisioningAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            CertificateProvisioningAuthorityError::Failed
        }
    }
}

fn map_external_publisher_authority_error(
    error: MetadataAuthorityRequestError,
) -> ExternalCertificatePublisherAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => {
            ExternalCertificatePublisherAuthorityError::Unavailable
        }
        MetadataAuthorityRequestError::Conflict | MetadataAuthorityRequestError::Rejected => {
            ExternalCertificatePublisherAuthorityError::Conflict
        }
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            ExternalCertificatePublisherAuthorityError::Failed
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

fn map_provisioning_repository_error(
    error: &RepositoryError,
) -> CertificateProvisioningAuthorityError {
    match error {
        RepositoryError::OperationConflict
        | RepositoryError::StaleRevision
        | RepositoryError::InvalidCommand => CertificateProvisioningAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            CertificateProvisioningAuthorityError::Unavailable
        }
        _ => CertificateProvisioningAuthorityError::Failed,
    }
}

fn map_external_publisher_repository_error(
    error: &RepositoryError,
) -> ExternalCertificatePublisherAuthorityError {
    match error {
        RepositoryError::OperationConflict
        | RepositoryError::StaleRevision
        | RepositoryError::InvalidCommand => ExternalCertificatePublisherAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            ExternalCertificatePublisherAuthorityError::Unavailable
        }
        _ => ExternalCertificatePublisherAuthorityError::Failed,
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
