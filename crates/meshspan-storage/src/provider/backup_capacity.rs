// SPDX-License-Identifier: GPL-2.0-only

//! Backup accounting against the folder's ordinary target journal.

use meshspan_contracts::{BackupCapacityBudget, BackupObjectIdentity, ContractError};

use super::{FolderShardStore, journal_contract_error};

impl BackupCapacityBudget for FolderShardStore {
    fn reserve(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        let observation = self
            .folder
            .capacity_observation()
            .map_err(|_| ContractError::Unavailable)?;
        self.journal
            .reserve_backup_capacity(object, observation)
            .map_err(|error| journal_contract_error(&error))
    }

    fn commit(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        self.journal
            .commit_backup_capacity(object)
            .map_err(|error| journal_contract_error(&error))
    }

    fn reconcile_existing(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        self.journal
            .reconcile_backup_capacity(object)
            .map_err(|error| journal_contract_error(&error))
    }

    fn release(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError> {
        self.journal
            .release_backup_capacity(object)
            .map_err(|error| journal_contract_error(&error))
    }
}
