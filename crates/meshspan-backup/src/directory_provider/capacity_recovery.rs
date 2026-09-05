// SPDX-License-Identifier: GPL-2.0-only

//! Reconcile reservation-only state under the exclusive destination ownership lock.

use meshspan_contracts::MAXIMUM_BACKUP_CAPACITY_PAGE;

use super::{DirectoryBackupProvider, DirectoryBackupProviderError, object_io};

impl DirectoryBackupProvider {
    pub(super) fn recover_pending_capacity(&mut self) -> Result<(), DirectoryBackupProviderError> {
        let Some(budget) = &mut self.capacity else {
            return Ok(());
        };
        // No other writer can own a staging file while this provider is exclusively held.
        object_io::discard_unpublished_staging(&self.objects)?;
        let mut after = None;
        loop {
            let objects =
                budget.pending_holds(self.destination_id, self.provider_generation, after)?;
            if objects.len() > MAXIMUM_BACKUP_CAPACITY_PAGE {
                return Err(DirectoryBackupProviderError::Corrupt);
            }
            if objects.is_empty() {
                return Ok(());
            }
            for object in objects {
                if object.destination_id != self.destination_id
                    || object.provider_generation != self.provider_generation
                    || object.byte_length == 0
                    || object.digest == [0; 32]
                    || after.is_some_and(|previous| object.backup_id <= previous)
                {
                    return Err(DirectoryBackupProviderError::Corrupt);
                }
                let reference = object_io::object_reference(object)?;
                match self.catalogue.validate_known_object(object, &reference) {
                    Ok(()) => {} // Catalogue evidence is never discarded by reservation recovery.
                    Err(DirectoryBackupProviderError::NotFound) => {
                        if object_io::confirm_object_absent(&self.objects, reference.as_str())? {
                            budget.cancel_unpublished(object)?;
                        }
                    }
                    Err(error) => return Err(error),
                }
                after = Some(object.backup_id);
            }
        }
    }
}
