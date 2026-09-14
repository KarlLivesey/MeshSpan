// SPDX-License-Identifier: GPL-2.0-only

//! Shared current-authority query for backup capability issuance and provider admission.

use crate::{
    AuthoritativeRepository, FederationStorageAllocationAuthority,
    FederationStorageAuthorityRequest,
};
use meshspan_contracts::{ContractError, FederatedBackupScope};
use meshspan_domain::UnixMicros;

impl AuthoritativeRepository {
    /// Requires an exact live bilateral backup allocation at the supplied mesh instant.
    ///
    /// The caller must separately bind this scope to its authenticated peer and local node.
    /// Recovery-only storage can serve backup recovery; this query does not grant ordinary
    /// file/shard reads. It checks eligibility, not available physical capacity or target health.
    ///
    /// # Errors
    /// Returns unauthorised for missing/revoked/expired authority, stale for changed provider
    /// or revision fences, and unavailable for metadata failure.
    pub fn require_federated_backup_authority(
        &self,
        scope: FederatedBackupScope,
        requested_bytes: u64,
        now: UnixMicros,
    ) -> Result<FederationStorageAllocationAuthority, ContractError> {
        let authority = self
            .active_federation_storage_allocation_authority(FederationStorageAuthorityRequest {
                relationship_id: scope.relationship_id,
                remote_mesh_id: scope.remote_mesh_id,
                provider_node_id: scope.provider_node_id,
                allocation_id: scope.allocation_id,
                grant_id: scope.grant_id,
                target_id: scope.target_id,
                target_generation: scope.target_generation,
                requested_bytes,
                observed_at: now,
            })
            .map_err(|_| ContractError::Unavailable)?
            .ok_or(ContractError::Unauthorized)?;
        if authority.provider_mesh_id() != scope.provider_mesh_id
            || authority.allocation().grant_id() != scope.namespace_grant_id
            || authority.relationship_authority_epoch() != scope.relationship_authority_epoch
            || authority.grant_revision() != scope.grant_revision
            || authority.allocation_revision() != scope.allocation_revision
        {
            return Err(ContractError::Stale);
        }
        Ok(authority)
    }
}
