// SPDX-License-Identifier: GPL-2.0-only

//! Current metadata and node-local quota adapter around federated shard provider IO.

use meshspan_contracts::{
    ContractError, FederatedShardPermit, ShardReceipt, federated_shard_write_result_digest,
};
use meshspan_data_plane::FederatedShardAuthority;
use meshspan_domain::{FederationStorageAction, UnixMicros};
use meshspan_metadata::{
    AuthoritativeRepository, FederationStorageAuthorityRequest, FederationStorageWriteCompletion,
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
        observed_at: UnixMicros,
    ) -> Result<(), ContractError> {
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
    ) -> Result<(), ContractError> {
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
                Ok(())
            } else {
                Err(ContractError::Conflict)
            };
        }
        if stored.state != FederationStorageWriteState::Reserved {
            return Err(ContractError::Stale);
        }
        self.local_database
            .commit_federated_storage_write(FederationStorageWriteCompletion {
                operation_id: permit.operation_id,
                permit_digest: permit.permit_digest,
                affected_bytes: receipt.length,
                content_digest: receipt.digest,
                result_digest: federated_shard_write_result_digest(permit, receipt, completed_at),
                completed_at,
            })
            .map(|_| ())
            .map_err(|_| ContractError::Unavailable)
    }
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
