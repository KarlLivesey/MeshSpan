// SPDX-License-Identifier: GPL-2.0-only

//! Replicated authorisation for serving exact remote backup-provider operations.

use std::sync::{Arc, Mutex};

use meshspan_contracts::{
    BackupObjectIdentity, BackupObjectReference, ContractError, RequestContext,
};
use meshspan_data_plane::{RemoteBackupAuthorisation, RemoteBackupAuthority};
use meshspan_domain::{NodeId, Revision, UnixMicros};
use meshspan_metadata::{
    AuthoritativeRepository, BackupCopyRecord, BackupCopyState, BackupDestinationBinding,
    BackupDestinationRecord, BackupDestinationState, MetadataBackupRecord, MetadataBackupState,
    RepositoryError,
};
use meshspan_transport::{AuthenticatedPeer, PeerBinding};

/// Cloneable, serialised read boundary over one SQLite-compatible authority projection.
#[derive(Clone)]
pub(crate) struct ConsensusRemoteBackupAuthority {
    repository: Arc<Mutex<AuthoritativeRepository>>,
    local_node_id: NodeId,
}

impl ConsensusRemoteBackupAuthority {
    #[must_use]
    pub(crate) fn new(repository: AuthoritativeRepository, local_node_id: NodeId) -> Self {
        Self {
            repository: Arc::new(Mutex::new(repository)),
            local_node_id,
        }
    }
}

impl RemoteBackupAuthority for ConsensusRemoteBackupAuthority {
    fn authorise(
        &self,
        peer: AuthenticatedPeer,
        request: RemoteBackupAuthorisation<'_>,
        observed_at: UnixMicros,
    ) -> Result<(), ContractError> {
        let repository = self
            .repository
            .lock()
            .map_err(|_| ContractError::Unavailable)?;
        validate_peer_identity(
            &repository,
            PeerBinding {
                node_id: peer.node_id(),
                incarnation: peer.incarnation(),
                certificate_fingerprint: peer.certificate_fingerprint(),
            },
            observed_at,
        )?;
        match request {
            RemoteBackupAuthorisation::Lookup(request) => {
                validate_lookup(&repository, self.local_node_id, peer, request, observed_at)
            }
            RemoteBackupAuthorisation::Store(request) => {
                validate_destination(
                    &repository,
                    self.local_node_id,
                    request.context,
                    request.object,
                )?;
                let claim = repository
                    .metadata_backup_run_claim(request.object.backup_id)
                    .map_err(|error| map_repository_error(&error))?
                    .ok_or(ContractError::Unauthorized)?;
                if claim.claim.worker_node_id == peer.node_id()
                    && claim.claim.worker_incarnation == peer.incarnation()
                    && claim.lease_expires_at > observed_at
                {
                    Ok(())
                } else {
                    Err(ContractError::Unauthorized)
                }
            }
            RemoteBackupAuthorisation::Read(request) => validate_copy(
                &repository,
                self.local_node_id,
                request.context,
                request.object,
                &request.object_reference,
            ),
            RemoteBackupAuthorisation::Verify(request) => validate_copy(
                &repository,
                self.local_node_id,
                request.context,
                request.object,
                &request.object_reference,
            ),
            RemoteBackupAuthorisation::Delete(request) => {
                if request.context.expected_revision != Some(request.retirement_revision) {
                    return Err(ContractError::Stale);
                }
                validate_deletion(
                    &repository,
                    self.local_node_id,
                    request.context,
                    request.object,
                    &request.object_reference,
                )
            }
        }
    }
}

fn validate_lookup(
    repository: &AuthoritativeRepository,
    local_node_id: NodeId,
    peer: AuthenticatedPeer,
    request: &meshspan_contracts::BackupLookupRequest,
    now: UnixMicros,
) -> Result<(), ContractError> {
    repository
        .with_read_view(|view| {
            validate_destination_without_revision(view, local_node_id, request.object)?;
            let intent = view
                .backup_publication_intent(request.object.backup_id, request.object.destination_id)
                .map_err(|error| map_repository_error(&error))?
                .ok_or(ContractError::Unauthorized)?;
            if intent.binding.object != request.object
                || request.context.expected_revision != Some(intent.revision)
            {
                return Err(ContractError::Stale);
            }
            let run = view
                .metadata_backup_run(request.object.backup_id)
                .map_err(|error| map_repository_error(&error))?
                .ok_or(ContractError::Unauthorized)?;
            let claim = view
                .metadata_backup_run_claim(request.object.backup_id)
                .map_err(|error| map_repository_error(&error))?;
            let active_worker = claim.as_ref().is_some_and(|claim| {
                claim.claim.worker_node_id == peer.node_id()
                    && claim.claim.worker_incarnation == peer.incarnation()
                    && claim.lease_expires_at > now
            });
            let abandoned = run.state == meshspan_metadata::MetadataBackupRunState::Incomplete
                && run.completed_at.is_some()
                && run.result_digest.is_some_and(|digest| digest != [0; 32])
                && claim.is_none()
                && view
                    .metadata_backup(run.backup_id)
                    .map_err(|error| map_repository_error(&error))?
                    .is_none();
            if active_worker || abandoned {
                Ok(())
            } else {
                Err(ContractError::Unauthorized)
            }
        })
        .map_err(|error| map_repository_error(&error))?
}

pub(crate) fn validate_peer_identity(
    repository: &AuthoritativeRepository,
    peer: PeerBinding,
    observed_at: UnixMicros,
) -> Result<(), ContractError> {
    // Bootstrap activates its initial node directly; join-activation receipts exist
    // only for later nodes. Current node state and certificate are the common authority.
    let certificate = repository
        .active_node_certificate(peer.node_id)
        .map_err(|error| map_repository_error(&error))?
        .ok_or(ContractError::Unauthorized)?;
    if certificate.incarnation == peer.incarnation
        && certificate.certificate_fingerprint == peer.certificate_fingerprint
        && certificate.valid_until > observed_at
    {
        Ok(())
    } else {
        Err(ContractError::Unauthorized)
    }
}

fn validate_destination(
    repository: &AuthoritativeRepository,
    local_node_id: NodeId,
    context: RequestContext,
    object: BackupObjectIdentity,
) -> Result<BackupDestinationRecord, ContractError> {
    let destination = repository
        .backup_destination(object.destination_id)
        .map_err(|error| map_repository_error(&error))?
        .ok_or(ContractError::NotFound)?;
    let BackupDestinationBinding::RegisteredTarget {
        target_id,
        target_generation,
    } = destination.binding
    else {
        return Err(ContractError::Stale);
    };
    let route = repository
        .storage_target_provider_context_by_target(target_id)
        .map_err(|error| map_repository_error(&error))?
        .ok_or(ContractError::Unavailable)?;
    if destination.state == BackupDestinationState::Active
        && destination.revision == required_revision(context)?
        && target_generation == object.provider_generation
        && route.node_id == local_node_id
        && route.target_id == target_id
        && route.generation == target_generation
    {
        Ok(destination)
    } else {
        Err(ContractError::Stale)
    }
}

fn validate_copy(
    repository: &AuthoritativeRepository,
    local_node_id: NodeId,
    context: RequestContext,
    object: BackupObjectIdentity,
    object_reference: &BackupObjectReference,
) -> Result<(), ContractError> {
    validate_destination_without_revision(repository, local_node_id, object)?;
    let backup = repository
        .metadata_backup(object.backup_id)
        .map_err(|error| map_repository_error(&error))?
        .ok_or(ContractError::NotFound)?;
    let copy = repository
        .backup_copy(object.backup_id, object.destination_id)
        .map_err(|error| map_repository_error(&error))?
        .ok_or(ContractError::NotFound)?;
    if copy.revision != required_revision(context)?
        || !backup_matches(backup, object)
        || !copy_matches(&copy, object, object_reference)
    {
        return Err(ContractError::Stale);
    }
    let valid_state = matches!(
        copy.state,
        BackupCopyState::Stored | BackupCopyState::Verified
    );
    if valid_state {
        Ok(())
    } else {
        Err(ContractError::Unauthorized)
    }
}

fn validate_deletion(
    repository: &AuthoritativeRepository,
    local_node_id: NodeId,
    context: RequestContext,
    object: BackupObjectIdentity,
    reference: &BackupObjectReference,
) -> Result<(), ContractError> {
    validate_destination_without_revision(repository, local_node_id, object)?;
    let candidate = repository
        .backup_reclamation_candidate(object.backup_id, object.destination_id)
        .map_err(|error| map_repository_error(&error))?
        .ok_or(ContractError::Unauthorized)?;
    if candidate.object == object
        && candidate.object_reference == *reference
        && candidate.retirement_revision == required_revision(context)?
    {
        Ok(())
    } else {
        Err(ContractError::Stale)
    }
}

fn validate_destination_without_revision(
    repository: &AuthoritativeRepository,
    local_node_id: NodeId,
    object: BackupObjectIdentity,
) -> Result<BackupDestinationRecord, ContractError> {
    let destination = repository
        .backup_destination(object.destination_id)
        .map_err(|error| map_repository_error(&error))?
        .ok_or(ContractError::NotFound)?;
    let BackupDestinationBinding::RegisteredTarget {
        target_id,
        target_generation,
    } = destination.binding
    else {
        return Err(ContractError::Stale);
    };
    let route = repository
        .readable_storage_target_provider_context_by_target(target_id)
        .map_err(|error| map_repository_error(&error))?
        .ok_or(ContractError::Unavailable)?;
    if target_generation == object.provider_generation
        && route.node_id == local_node_id
        && route.target_id == target_id
        && route.generation == target_generation
    {
        Ok(destination)
    } else {
        Err(ContractError::Stale)
    }
}

fn backup_matches(backup: MetadataBackupRecord, object: BackupObjectIdentity) -> bool {
    let valid_state = matches!(
        backup.state,
        MetadataBackupState::Recorded | MetadataBackupState::Verified
    );
    backup.backup_id == object.backup_id
        && backup.encrypted_byte_length == object.byte_length
        && backup.encrypted_digest == object.digest
        && valid_state
}

fn copy_matches(
    copy: &BackupCopyRecord,
    object: BackupObjectIdentity,
    reference: &BackupObjectReference,
) -> bool {
    copy.backup_id == object.backup_id
        && copy.destination_id == object.destination_id
        && copy.provider_generation == object.provider_generation
        && copy.object_reference == reference.as_str()
        && copy.byte_length == object.byte_length
        && copy.copy_digest == object.digest
}

fn required_revision(context: RequestContext) -> Result<Revision, ContractError> {
    context
        .expected_revision
        .filter(|revision| *revision != Revision::ZERO)
        .ok_or(ContractError::Stale)
}

fn map_repository_error(error: &RepositoryError) -> ContractError {
    match error {
        RepositoryError::CapacityExceeded => ContractError::ResourceExhausted,
        RepositoryError::StaleRevision
        | RepositoryError::StaleVolumeHead
        | RepositoryError::StaleRetentionPolicy
        | RepositoryError::StaleAuthenticationPolicy
        | RepositoryError::StaleSnapshot
        | RepositoryError::StaleSnapshotSchedule
        | RepositoryError::StaleMetadataBackupSchedule => ContractError::Stale,
        RepositoryError::InvalidCommand | RepositoryError::InvalidPageLimit => {
            ContractError::InvalidInput
        }
        RepositoryError::CorruptState
        | RepositoryError::OperationConflict
        | RepositoryError::InvalidLogPosition
        | RepositoryError::BackupDestinationExists
        | RepositoryError::BackupMismatch
        | RepositoryError::SnapshotMismatch
        | RepositoryError::InjectedFault => ContractError::InternalContract,
        RepositoryError::Store(_)
        | RepositoryError::Sqlite(_)
        | RepositoryError::Io(_)
        | RepositoryError::EncryptedBackup(_) => ContractError::Unavailable,
    }
}
