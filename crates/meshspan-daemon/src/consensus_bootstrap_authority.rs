// SPDX-License-Identifier: GPL-2.0-only

//! First-mesh adapter from synchronous HTTP service work to the consensus owner.

use meshspan_cluster::{MetadataAuthorityHandle, MetadataAuthorityRequestError};
use meshspan_metadata::{AuthoritativeCommand, CommandContext};

use crate::{BootstrapAuthority, BootstrapAuthorityError, BootstrapCommit};

/// Cloneable root-authority adapter intended for APIs already running on blocking workers.
#[derive(Clone)]
pub struct ConsensusBootstrapAuthority {
    authority: MetadataAuthorityHandle,
    runtime: tokio::runtime::Handle,
}

impl ConsensusBootstrapAuthority {
    /// Binds one authority ingress to the Tokio runtime which owns its reactor.
    #[must_use]
    pub const fn new(authority: MetadataAuthorityHandle, runtime: tokio::runtime::Handle) -> Self {
        Self { authority, runtime }
    }
}

impl BootstrapAuthority for ConsensusBootstrapAuthority {
    fn commit_or_resolve(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<BootstrapCommit, BootstrapAuthorityError> {
        let receipt = self
            .runtime
            .block_on(self.authority.commit_or_resolve(context, command.clone()))
            .map_err(map_authority_error)?;
        Ok(BootstrapCommit {
            result_digest: receipt.result_digest,
        })
    }
}

fn map_authority_error(error: MetadataAuthorityRequestError) -> BootstrapAuthorityError {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => BootstrapAuthorityError::Unavailable,
        MetadataAuthorityRequestError::Conflict => BootstrapAuthorityError::Conflict,
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            BootstrapAuthorityError::Failed
        }
    }
}
