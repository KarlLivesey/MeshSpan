// SPDX-License-Identifier: GPL-2.0-only

//! Ordered admission against independent allocation and physical-target budgets.

use std::collections::BTreeMap;

use meshspan_contracts::{
    BackupCapacityBudget, BackupObjectIdentity, ContractError, MAXIMUM_BACKUP_CAPACITY_PAGE,
};
use meshspan_domain::{BackupDestinationId, BackupId};

/// Requires both an allocation budget and the backing folder budget before writing bytes.
///
/// Admission is allocation-first. Completion and cancellation are target-first. An interruption
/// deliberately leaves conservative charges; exclusive provider recovery scans the union of
/// both ledgers. No rollback assumes that a failed accounting call had no durable effect.
pub struct IntersectedBackupCapacity {
    allocation: Box<dyn BackupCapacityBudget>,
    target: Box<dyn BackupCapacityBudget>,
}

impl IntersectedBackupCapacity {
    /// Composes already bound budgets without performing IO or granting remote authority.
    #[must_use]
    pub fn new(
        allocation: Box<dyn BackupCapacityBudget>,
        target: Box<dyn BackupCapacityBudget>,
    ) -> Self {
        Self { allocation, target }
    }
}

impl BackupCapacityBudget for IntersectedBackupCapacity {
    fn pending_holds(
        &self,
        destination: BackupDestinationId,
        generation: u64,
        after: Option<BackupId>,
    ) -> Result<Vec<BackupObjectIdentity>, ContractError> {
        let mut merged = BTreeMap::new();
        for budget in [&self.allocation, &self.target] {
            let page = budget.pending_holds(destination, generation, after)?;
            if page.len() > MAXIMUM_BACKUP_CAPACITY_PAGE {
                return Err(ContractError::InternalContract);
            }
            let mut previous = after;
            for object in page {
                if object.destination_id != destination
                    || object.provider_generation != generation
                    || object.byte_length == 0
                    || object.digest == [0; 32]
                    || previous.is_some_and(|id| object.backup_id <= id)
                {
                    return Err(ContractError::Corrupt);
                }
                previous = Some(object.backup_id);
                if merged
                    .insert(object.backup_id, object)
                    .is_some_and(|other| other != object)
                {
                    return Err(ContractError::Conflict);
                }
            }
        }
        Ok(merged
            .into_values()
            .take(MAXIMUM_BACKUP_CAPACITY_PAGE)
            .collect())
    }

    fn cancel_unpublished(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        self.target.cancel_unpublished(object)?;
        self.allocation.cancel_unpublished(object)
    }

    fn reserve(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        self.allocation.reserve(object)?;
        self.target.reserve(object)
    }

    fn commit(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        self.target.commit(object)?;
        self.allocation.commit(object)
    }

    fn reconcile_existing(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        self.target.reconcile_existing(object)?;
        self.allocation.reconcile_existing(object)
    }

    fn release(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        self.target.release(object)?;
        self.allocation.release(object)
    }
}
