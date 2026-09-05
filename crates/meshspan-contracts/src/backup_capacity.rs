// SPDX-License-Identifier: GPL-2.0-only

//! Destination-bound accounting when backups share capacity with other workloads.

use crate::{BackupObjectIdentity, ContractError};
use meshspan_domain::{BackupDestinationId, BackupId};

/// Maximum pending reservations returned by one destination-local recovery query.
pub const MAXIMUM_BACKUP_CAPACITY_PAGE: usize = 64;

/// Durable accounting adapter bound to one backing target and its current policy.
///
/// An exact object is charged once across operation IDs and restarts. The provider
/// owns IO ordering; this interface is not exposed as remote allocation authority.
pub trait BackupCapacityBudget: Send {
    /// Lists at most `MAXIMUM_BACKUP_CAPACITY_PAGE` held objects in identity order.
    /// Resume after the last returned backup ID; an empty page ends the scan.
    ///
    /// # Errors
    /// Rejects stale generations, malformed rows and unavailable accounting.
    fn pending_holds(
        &self,
        destination: BackupDestinationId,
        generation: u64,
        after: Option<BackupId>,
    ) -> Result<Vec<BackupObjectIdentity>, ContractError>;

    /// Cancels a hold after its exclusive provider proves there is no catalogue
    /// object or published/staging bytes. This is not deletion authority and is
    /// never exposed remotely. A later exact retry must reserve space again.
    ///
    /// # Errors
    /// Rejects changed identities, stored/released charges or corrupt counters.
    fn cancel_unpublished(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError>;

    /// Durably holds space before new bytes can be written.
    ///
    /// # Errors
    /// Rejects changed identity, retired objects, invalid input and insufficient capacity.
    fn reserve(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError>;

    /// Moves an existing hold to used space after durable provider publication.
    ///
    /// # Errors
    /// Rejects missing, changed or retired holds. Exact retries do not double-charge.
    fn commit(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError>;

    /// Accounts an already persisted object during provider startup reconciliation.
    ///
    /// This may exceed the current ceiling: existing bytes cannot be wished away.
    /// Subsequent admission must respect the resulting charge. It authorises no new IO.
    ///
    /// # Errors
    /// Rejects malformed/conflicting identity or failed durable accounting.
    fn reconcile_existing(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError>;

    /// Releases a charge only after the provider has durably removed the exact object.
    ///
    /// # Errors
    /// Rejects changed identities or corrupt accounting. Exact retries release at most once.
    fn release(&mut self, object: BackupObjectIdentity) -> Result<(), ContractError>;
}
