// SPDX-License-Identifier: GPL-2.0-only

//! Storage registration forwarding and historical provider configuration, not user authority.

use super::{DaemonProcessError, open_root_repository_at};
use crate::private_consensus_runtime::PrivateConsensusRuntime;
use crate::{
    SecretGenerationAuthority, SecretGenerationAuthorityError, StoragePermitAuthority,
    StorageTargetRegistrationAuthority, StorageTargetRegistrationAuthorityError,
};
use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{NodeId, TargetId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommandContext, CommandReceipt,
    SecretGenerationRecord, StorageTargetProviderContext, StorageTargetRegistrationContext,
};
use meshspan_secret_envelope::SecretContext;
use std::sync::Arc;

pub(super) struct StorageNodeAuthority {
    reader: AuthoritativeRepository,
    network: Arc<PrivateConsensusRuntime>,
    runtime: tokio::runtime::Handle,
}

impl StorageNodeAuthority {
    pub(super) fn membership_epoch(&self) -> Result<u64, ()> {
        self.reader
            .load_active_consensus_quorum_plan()
            .map_err(|_| ())?
            .map(|plan| plan.membership_epoch())
            .ok_or(())
    }

    pub(super) fn open(
        directory: &std::path::Path,
        network: Arc<PrivateConsensusRuntime>,
        runtime: tokio::runtime::Handle,
        now: UnixMicros,
    ) -> Result<Self, DaemonProcessError> {
        Ok(Self {
            reader: open_root_repository_at(directory, now)?,
            network,
            runtime,
        })
    }
}

impl SecretGenerationAuthority for StorageNodeAuthority {
    fn secret_generation(
        &self,
        context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, SecretGenerationAuthorityError> {
        if context.kind() != meshspan_metadata::STORAGE_PERMIT_KEY_SECRET_KIND {
            return Err(SecretGenerationAuthorityError::Failed);
        }
        self.reader
            .runtime_secret_generation(context)
            .map_err(|_| SecretGenerationAuthorityError::Unavailable)
    }
}

impl StoragePermitAuthority for StorageNodeAuthority {
    fn latest_generation(
        &self,
        mesh: meshspan_domain::MeshId,
    ) -> Result<Option<u64>, SecretGenerationAuthorityError> {
        self.reader
            .latest_storage_permit_generation(mesh)
            .map_err(|_| SecretGenerationAuthorityError::Unavailable)
    }
}

impl StorageTargetRegistrationAuthority for StorageNodeAuthority {
    fn registration_context(
        &self,
        node: NodeId,
        now: UnixMicros,
    ) -> Result<Option<StorageTargetRegistrationContext>, StorageTargetRegistrationAuthorityError>
    {
        self.reader
            .storage_target_registration_context(node, now)
            .map_err(Into::into)
    }

    fn provider_context(
        &self,
        node: NodeId,
        target: TargetId,
    ) -> Result<Option<StorageTargetProviderContext>, StorageTargetRegistrationAuthorityError> {
        self.reader
            .readable_storage_target_provider_context(node, target)
            .map_err(Into::into)
    }

    fn commit_or_resolve_registration(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, StorageTargetRegistrationAuthorityError> {
        self.runtime
            .block_on(crate::metadata_forwarding::forward_from_replica(
                &self.network,
                &self.reader,
                context,
                command,
            ))
            .map_err(|error| match error {
                MetadataAuthorityRequestError::Conflict
                | MetadataAuthorityRequestError::Rejected => {
                    StorageTargetRegistrationAuthorityError::Conflict
                }
                MetadataAuthorityRequestError::NotLeader { .. }
                | MetadataAuthorityRequestError::Unavailable => {
                    StorageTargetRegistrationAuthorityError::Unavailable
                }
                MetadataAuthorityRequestError::Failed
                | MetadataAuthorityRequestError::Unsupported => {
                    StorageTargetRegistrationAuthorityError::Failed
                }
            })
    }
}
