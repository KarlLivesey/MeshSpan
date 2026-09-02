// SPDX-License-Identifier: GPL-2.0-only

//! Shared consensus mutation boundary for autonomous maintenance workers.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_metadata::{AuthoritativeCommand, CommandContext, CommandReceipt};

use crate::ConsensusAuthenticationAuthority;

/// Minimal consensus mutation boundary shared by repair, scrub, drain and rebalance workers.
pub trait MaintenanceMetadataAuthority {
    /// Commits or resolves one exact authoritative command.
    ///
    /// # Errors
    ///
    /// Returns only typed consensus/authority failures and never invents a durable receipt.
    fn commit(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError>;
}

impl MaintenanceMetadataAuthority for ConsensusAuthenticationAuthority {
    fn commit(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        self.commit_authoritative(context, command)
    }
}
