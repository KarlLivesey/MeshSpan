// SPDX-License-Identifier: GPL-2.0-only

//! Destination-bound accounting when backups share capacity with other workloads.

use crate::{BackupObjectIdentity, ContractError};

/// Durable accounting adapter bound to one backing target and its current policy.
///
/// An exact object is charged once across operation IDs and restarts. The provider
/// owns IO ordering; this interface is not exposed as remote allocation authority.
pub trait BackupCapacityBudget: Send {
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
