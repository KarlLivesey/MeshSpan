// SPDX-License-Identifier: GPL-2.0-only

//! Current metadata and node-local quota adapter around federated shard provider IO.

use meshspan_contracts::{
    ContractError, FederatedShardPermit, ReclamationReceipt, ScrubObservation, ShardReceipt,
    TombstoneReceipt, federated_shard_write_result_digest,
};
use meshspan_data_plane::{
    FederatedReclamationEvidence, FederatedRetirementEvidence, FederatedScrubEvidence,
    FederatedScrubPreparation, FederatedShardAuthority, FederatedWriteEvidence,
};
use meshspan_domain::{FederationStorageAction, UnixMicros};
use meshspan_metadata::{
    AuthoritativeRepository, FederationStorageAuthorityRequest, FederationStorageLifecycleError,
    FederationStorageReclamationCompletion, FederationStorageRetirementCompletion,
    FederationStorageScrubCompletion, FederationStorageScrubError,
    FederationStorageScrubPreparation as MetadataScrubPreparation,
    FederationStorageWriteCompletion, FederationStorageWriteReservation,
    FederationStorageWriteState, LocalDatabase,
};

/// Revalidates replicated bilateral authority and finalises node-local quota accounting.
pub struct MetadataFederatedShardAuthority<'a> {
    repository: &'a AuthoritativeRepository,
    local_database: &'a mut LocalDatabase,
}

impl<'a> MetadataFederatedShardAuthority<'a> {
    /// Composes the two persistence domains without pretending they share one transaction.
    #[must_use]
    pub const fn new(
        repository: &'a AuthoritativeRepository,
        local_database: &'a mut LocalDatabase,
    ) -> Self {
        Self {
            repository,
            local_database,
        }
    }
}

impl FederatedShardAuthority for MetadataFederatedShardAuthority<'_> {
    fn authorise(
        &self,
        permit: &FederatedShardPermit,
        capability_digest: [u8; 32],
        observed_at: UnixMicros,
    ) -> Result<(), ContractError> {
        let presentation = self
            .local_database
            .federated_storage_capability(capability_digest)
            .map_err(|_| ContractError::Unavailable)?
            .ok_or(ContractError::Unauthorized)?;
        if presentation.capability_digest != capability_digest || presentation.permit != *permit {
            return Err(ContractError::Unauthorized);
        }
        let current = self
            .repository
            .active_federation_storage_allocation_authority(FederationStorageAuthorityRequest {
                relationship_id: permit.relationship_id,
                remote_mesh_id: permit.remote_mesh_id,
                provider_node_id: permit.provider_node_id,
                allocation_id: permit.allocation_id,
                grant_id: permit.grant_id,
                target_id: permit.target_id,
                target_generation: permit.target_generation,
                requested_bytes: permit.maximum_bytes,
                observed_at,
            })
            .map_err(|_| ContractError::Unavailable)?
            .ok_or(ContractError::Unauthorized)?;
        let valid = current.provider_mesh_id() == permit.provider_mesh_id
            && current.relationship_authority_epoch() == permit.relationship_authority_epoch
            && current.grant_revision() == permit.grant_revision
            && current.allocation_revision() == permit.allocation_revision
            && current.requested_bytes() == permit.maximum_bytes
            && permit.expires_at > observed_at
            && (permit.action != FederationStorageAction::Get
                || current.participation().serves_reads());
        if !valid {
            return Err(ContractError::Stale);
        }
        if permit.action.reserves_capacity() {
            self.authorise_reserved_write(permit)?;
        }
        Ok(())
    }

    fn commit_write(
        &mut self,
        permit: &FederatedShardPermit,
        receipt: ShardReceipt,
        completed_at: UnixMicros,
    ) -> Result<FederatedWriteEvidence, ContractError> {
        validate_receipt(permit, receipt)?;
        let stored = self
            .local_database
            .federated_storage_write(permit.operation_id)
            .map_err(|_| ContractError::Unavailable)?
            .ok_or(ContractError::Unauthorized)?;
        if stored.state == FederationStorageWriteState::Committed {
            let replayed = stored.permit_digest == permit.permit_digest
                && stored.affected_bytes == Some(receipt.length)
                && stored.content_digest == Some(receipt.digest);
            return if replayed {
                write_evidence(&stored)
            } else {
                Err(ContractError::Conflict)
            };
        }
        if stored.state != FederationStorageWriteState::Reserved {
            return Err(ContractError::Stale);
        }
        let (_, completed) = self
            .local_database
            .commit_federated_storage_write(FederationStorageWriteCompletion {
                operation_id: permit.operation_id,
                permit_digest: permit.permit_digest,
                affected_bytes: receipt.length,
                content_digest: receipt.digest,
                result_digest: federated_shard_write_result_digest(permit, receipt, completed_at),
                completed_at,
            })
            .map_err(|_| ContractError::Unavailable)?;
        write_evidence(&completed)
    }

    fn prepare_scrub(
        &self,
        permit: &FederatedShardPermit,
    ) -> Result<FederatedScrubPreparation, ContractError> {
        match self
            .local_database
            .prepare_federated_storage_scrub(permit)
            .map_err(|error| scrub_error(&error))?
        {
            MetadataScrubPreparation::Pending(expected) => {
                Ok(FederatedScrubPreparation::Pending(expected))
            }
            MetadataScrubPreparation::Replayed(evidence) => Ok(
                FederatedScrubPreparation::Replayed(FederatedScrubEvidence::new(
                    evidence.observation,
                    evidence.completed_at,
                    evidence.result_digest,
                )?),
            ),
        }
    }

    fn commit_scrub(
        &mut self,
        permit: &FederatedShardPermit,
        capability_digest: [u8; 32],
        provider_observation: ScrubObservation,
        completed_at: UnixMicros,
    ) -> Result<FederatedScrubEvidence, ContractError> {
        let evidence = self
            .local_database
            .record_federated_storage_scrub(&FederationStorageScrubCompletion {
                permit: *permit,
                capability_digest,
                provider_observation,
                completed_at,
            })
            .map_err(|error| scrub_error(&error))?;
        FederatedScrubEvidence::new(
            evidence.observation,
            evidence.completed_at,
            evidence.result_digest,
        )
    }

    fn commit_retirement(
        &mut self,
        permit: &FederatedShardPermit,
        capability_digest: [u8; 32],
        provider_tombstone: TombstoneReceipt,
        completed_at: UnixMicros,
    ) -> Result<FederatedRetirementEvidence, ContractError> {
        let (_, lifecycle) = self
            .local_database
            .record_federated_storage_retirement(&FederationStorageRetirementCompletion {
                permit: *permit,
                capability_digest,
                provider_tombstone,
                completed_at,
            })
            .map_err(|error| lifecycle_error(&error))?;
        FederatedRetirementEvidence::new(
            lifecycle.logical_tombstone,
            lifecycle.charged_bytes,
            lifecycle.retired_at,
        )
    }

    fn provider_tombstone(
        &self,
        permit: &FederatedShardPermit,
        logical_tombstone: TombstoneReceipt,
    ) -> Result<TombstoneReceipt, ContractError> {
        let lifecycle = self
            .local_database
            .federated_storage_lifecycle(
                permit.remote_mesh_id,
                permit.scope_digest,
                permit.target_id,
                permit.target_generation,
                permit.shard,
            )
            .map_err(|error| lifecycle_error(&error))?
            .ok_or(ContractError::Unauthorized)?;
        if lifecycle.logical_tombstone == logical_tombstone {
            Ok(lifecycle.provider_tombstone)
        } else {
            Err(ContractError::Conflict)
        }
    }

    fn commit_reclamation(
        &mut self,
        permit: &FederatedShardPermit,
        capability_digest: [u8; 32],
        logical_tombstone: TombstoneReceipt,
        provider_reclamation: ReclamationReceipt,
    ) -> Result<FederatedReclamationEvidence, ContractError> {
        let (_, lifecycle) = self
            .local_database
            .record_federated_storage_reclamation(&FederationStorageReclamationCompletion {
                permit: *permit,
                capability_digest,
                logical_tombstone,
                provider_reclamation,
            })
            .map_err(|error| lifecycle_error(&error))?;
        FederatedReclamationEvidence::new(
            lifecycle
                .logical_reclamation
                .ok_or(ContractError::Corrupt)?,
        )
    }
}

fn lifecycle_error(error: &FederationStorageLifecycleError) -> ContractError {
    match error {
        FederationStorageLifecycleError::Invalid => ContractError::InvalidInput,
        FederationStorageLifecycleError::Conflict => ContractError::Conflict,
        FederationStorageLifecycleError::CorruptState
        | FederationStorageLifecycleError::Capability(_)
        | FederationStorageLifecycleError::Database(_) => ContractError::Unavailable,
    }
}

fn scrub_error(error: &FederationStorageScrubError) -> ContractError {
    match error {
        FederationStorageScrubError::Invalid => ContractError::InvalidInput,
        FederationStorageScrubError::Conflict => ContractError::Conflict,
        FederationStorageScrubError::CorruptState
        | FederationStorageScrubError::Capability(_)
        | FederationStorageScrubError::Database(_) => ContractError::Unavailable,
    }
}

fn write_evidence(
    stored: &FederationStorageWriteReservation,
) -> Result<FederatedWriteEvidence, ContractError> {
    if stored.state != FederationStorageWriteState::Committed {
        return Err(ContractError::Corrupt);
    }
    FederatedWriteEvidence::new(
        stored.completed_at.ok_or(ContractError::Corrupt)?,
        stored.result_digest.ok_or(ContractError::Corrupt)?,
    )
}

impl MetadataFederatedShardAuthority<'_> {
    fn authorise_reserved_write(&self, permit: &FederatedShardPermit) -> Result<(), ContractError> {
        let reservation = self
            .local_database
            .federated_storage_write(permit.operation_id)
            .map_err(|_| ContractError::Unavailable)?
            .ok_or(ContractError::Unauthorized)?;
        let valid = reservation.allocation_id == permit.allocation_id
            && reservation.request_digest == permit.request_digest
            && reservation.capability_nonce == permit.capability_nonce
            && reservation.shard == permit.shard
            && reservation.action == permit.action
            && reservation.maximum_bytes == permit.maximum_bytes
            && reservation.permit_digest == permit.permit_digest
            && reservation.expires_at == permit.expires_at
            && reservation.issued_at == permit.issued_at
            && reservation.state != FederationStorageWriteState::Released;
        if valid {
            Ok(())
        } else {
            Err(ContractError::Unauthorized)
        }
    }
}

fn validate_receipt(
    permit: &FederatedShardPermit,
    receipt: ShardReceipt,
) -> Result<(), ContractError> {
    let valid = receipt.operation_id == permit.operation_id
        && receipt.shard == permit.shard
        && receipt.target_id == permit.target_id
        && receipt.target_generation == permit.target_generation
        && receipt.length > 0
        && receipt.length <= permit.maximum_bytes
        && receipt.digest != [0; 32];
    if valid {
        Ok(())
    } else {
        Err(ContractError::Conflict)
    }
}
