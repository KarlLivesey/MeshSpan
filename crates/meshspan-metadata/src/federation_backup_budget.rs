// SPDX-License-Identifier: GPL-2.0-only

//! Provider-owned backup accounting against current bilateral storage allocations.

use meshspan_contracts::{
    BackupCapacityBudget, BackupObjectIdentity, ContractError, FederatedBackupScope,
    federated_provider_backup_identity,
};
use meshspan_domain::{BackupDestinationId, BackupId, Clock};

use crate::{
    AuthoritativeRepository, FederatedBackupCapacityState, FederationStorageAllocationAuthority,
    FederationStorageQuotaError, LocalDatabase,
};

/// Allocation half of a provider budget; compose with the real target's capacity budget.
///
/// Each reservation rereads authority. Recovery only settles previously admitted exact objects,
/// including after revocation; it cannot admit new bytes. This accounting owner does not verify
/// remote signatures or authorise read/delete requests. The federation dispatcher owns those
/// checks. Run these synchronous database operations on the provider's blocking worker.
pub struct FederatedBackupCapacityBudget {
    scope: FederatedBackupScope,
    destination: BackupDestinationId,
    repository: AuthoritativeRepository,
    local: LocalDatabase,
    clock: Box<dyn Clock + Send>,
}

impl FederatedBackupCapacityBudget {
    /// Binds an allocation to its provider-side destination namespace.
    ///
    /// `logical_object` selects the consumer destination and generation, not a single backup.
    /// Supply a current mesh clock; this adapter never adjusts or falls back to the OS clock.
    ///
    /// # Errors
    /// Rejects invalid scope/object or a local database belonging to a different provider node.
    pub fn new(
        scope: FederatedBackupScope,
        logical_object: BackupObjectIdentity,
        repository: AuthoritativeRepository,
        local: LocalDatabase,
        clock: Box<dyn Clock + Send>,
    ) -> Result<Self, ContractError> {
        let physical = federated_provider_backup_identity(scope, logical_object)?;
        if scope.provider_node_id != local.node_id() {
            return Err(ContractError::Stale);
        }
        Ok(Self {
            scope,
            destination: physical.destination_id,
            repository,
            local,
            clock,
        })
    }

    fn validate_binding(&self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        if object.destination_id != self.destination
            || object.provider_generation != self.scope.target_generation
        {
            return Err(ContractError::Stale);
        }
        if object.byte_length == 0 || object.digest == [0; 32] {
            return Err(ContractError::InvalidInput);
        }
        Ok(())
    }

    fn authority(
        &self,
        object: BackupObjectIdentity,
    ) -> Result<FederationStorageAllocationAuthority, ContractError> {
        self.validate_binding(object)?;
        self.repository.require_federated_backup_authority(
            self.scope,
            object.byte_length,
            self.clock.now(),
        )
    }
}

impl BackupCapacityBudget for FederatedBackupCapacityBudget {
    fn pending_holds(
        &self,
        destination: BackupDestinationId,
        generation: u64,
        after: Option<BackupId>,
    ) -> Result<Vec<BackupObjectIdentity>, ContractError> {
        if destination != self.destination || generation != self.scope.target_generation {
            return Err(ContractError::Stale);
        }
        self.local
            .pending_federated_backup_capacity(
                self.scope.allocation_id,
                destination,
                generation,
                after,
            )
            .map_err(|error| map_error(&error))
    }

    fn cancel_unpublished(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        self.validate_binding(object)?;
        match self
            .local
            .federated_backup_capacity_state(self.scope.allocation_id, object)
            .map_err(|error| map_error(&error))?
        {
            None => Ok(()), // The other budget may have the only outstanding hold.
            Some(_) => self
                .local
                .cancel_federated_backup_capacity(
                    self.scope.allocation_id,
                    object,
                    self.clock.now(),
                )
                .map(|_| ())
                .map_err(|error| map_error(&error)),
        }
    }

    fn reserve(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        let authority = self.authority(object)?;
        self.local
            .reserve_federated_backup_capacity(authority, object)
            .map(|_| ())
            .map_err(|error| map_error(&error))
    }

    fn commit(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        self.validate_binding(object)?;
        self.local
            .commit_federated_backup_capacity(self.scope.allocation_id, object, self.clock.now())
            .map(|_| ())
            .map_err(|error| map_error(&error))
    }

    fn reconcile_existing(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        // Every federated object must have a durable allocation hold before IO. A restored
        // catalogue without that ledger is inconsistent, not permission to invent free capacity.
        self.commit(object)
    }

    fn release(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        self.validate_binding(object)?;
        if self
            .local
            .federated_backup_capacity_state(self.scope.allocation_id, object)
            .map_err(|error| map_error(&error))?
            == Some(FederatedBackupCapacityState::Held)
        {
            // The provider proved publication in its catalogue before deleting. Its earlier
            // successful publication may have lost the final accounting response.
            self.commit(object)?;
        }
        self.local
            .release_federated_backup_capacity(self.scope.allocation_id, object, self.clock.now())
            .map(|_| ())
            .map_err(|error| map_error(&error))
    }
}

fn map_error(error: &FederationStorageQuotaError) -> ContractError {
    match error {
        FederationStorageQuotaError::Invalid => ContractError::InvalidInput,
        FederationStorageQuotaError::Conflict => ContractError::Conflict,
        FederationStorageQuotaError::CapacityExceeded => ContractError::ResourceExhausted,
        FederationStorageQuotaError::CorruptState => ContractError::Corrupt,
        FederationStorageQuotaError::Database(_) => ContractError::Unavailable,
    }
}
