// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable replicated authority required by storage-drain administration.

use meshspan_domain::WorkId;
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, PageLimit, StorageDrainCursor,
    StorageDrainRecord, StorageDrainStatusPage,
};
use thiserror::Error;

use crate::IdentityAdministrationAuthority;

/// Replicated reads and mutations used to admit and inspect safe removal.
pub trait StorageDrainAdministrationAuthority: IdentityAdministrationAuthority {
    /// Returns one exact storage drain.
    ///
    /// # Errors
    ///
    /// Fails closed when committed drain state cannot be trusted.
    fn storage_drain(
        &self,
        drain_id: WorkId,
    ) -> Result<Option<StorageDrainRecord>, StorageDrainAdministrationAuthorityError>;

    /// Returns one newest-first bounded drain page.
    ///
    /// # Errors
    ///
    /// Fails closed when committed drain state cannot be trusted.
    fn storage_drains(
        &self,
        after: Option<StorageDrainCursor>,
        limit: PageLimit,
    ) -> Result<StorageDrainStatusPage, StorageDrainAdministrationAuthorityError>;

    /// Commits or exactly resolves one drain admission through consensus.
    ///
    /// # Errors
    ///
    /// Fails closed when authority cannot safely commit the request.
    fn commit_storage_drain_operation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, StorageDrainAdministrationAuthorityError>;
}

/// Closed authority failures safe for public classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StorageDrainAdministrationAuthorityError {
    /// Current replicated authority cannot be reached.
    #[error("storage-drain authority is unavailable")]
    Unavailable,
    /// The operation or exact scope conflicts with committed state.
    #[error("storage-drain authority reports a conflict")]
    Conflict,
    /// Persisted state or evidence failed validation.
    #[error("storage-drain authority failed closed")]
    Failed,
}
