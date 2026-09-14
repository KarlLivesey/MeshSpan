// SPDX-License-Identifier: GPL-2.0-only

//! Key-only certificate installation for a passive metadata replica, never CA issuance.

use std::sync::Arc;

use meshspan_certificates::NodeIdentityKey;
use meshspan_cluster::{ConsensusNetwork, MetadataAuthorityRequestError};
use meshspan_domain::UnixMicros;
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommandContext, NodeCertificateRotationState,
};

use super::{DaemonNodeRuntime, DaemonProcessError};
use crate::private_certificate_renewal::{command_context, install};
use crate::private_consensus_runtime::PrivateConsensusRuntime;

pub(super) struct StorageNodeCertificates {
    identity: NodeIdentityKey,
    network: Arc<PrivateConsensusRuntime>,
    pending: Option<(CommandContext, AuthoritativeCommand)>,
}

impl StorageNodeCertificates {
    pub(super) fn new(node: &DaemonNodeRuntime) -> Result<Self, DaemonProcessError> {
        Ok(Self {
            identity: NodeIdentityKey::from_pkcs8(
                node.local_state.node_identity_private_key_pkcs8(),
            )
            .map_err(|_| DaemonProcessError::Certificate)?,
            network: Arc::clone(&node.private_network),
            pending: None,
        })
    }

    /// Called by the single owned maintenance job, outside the storage-provider lock.
    pub(super) fn reconcile(
        &mut self,
        repository: &AuthoritativeRepository,
        runtime: &tokio::runtime::Handle,
        network: &ConsensusNetwork,
        now: UnixMicros,
    ) -> Result<(), ()> {
        if self.pending.is_none() {
            let Some(rotation) = repository
                .node_certificate_rotation(network.local_node_id())
                .map_err(|_| ())?
                .filter(|rotation| {
                    rotation.state == NodeCertificateRotationState::Staged
                        && rotation.incarnation == network.local_incarnation()
                        && rotation.valid_until > now
                })
            else {
                return Ok(());
            };
            let actor = repository
                .storage_target_registration_context(network.local_node_id(), now)
                .map_err(|_| ())?
                .ok_or(())?
                .actor_principal_id;
            let acknowledgement = install(&self.identity, network, &rotation).map_err(|_| ())?;
            self.pending = Some((
                command_context(actor, now).map_err(|_| ())?,
                AuthoritativeCommand::AcknowledgeNodeCertificateInstallation(acknowledgement),
            ));
        }
        let (context, command) = self.pending.as_ref().ok_or(())?;
        match runtime.block_on(crate::metadata_forwarding::forward_from_replica(
            &self.network,
            repository,
            *context,
            command,
        )) {
            Ok(receipt)
                if receipt.operation_id == context.operation_id
                    && receipt.request_digest == command.request_digest(*context)
                    && receipt.committed_revision.get() > 0 =>
            {
                self.pending = None;
                Ok(())
            }
            Err(
                MetadataAuthorityRequestError::Unavailable
                | MetadataAuthorityRequestError::NotLeader { .. },
            ) => Ok(()),
            Err(MetadataAuthorityRequestError::Rejected) => {
                // Reload committed rotation state; an ambiguous retry keeps exactly its old bytes.
                self.pending = None;
                Ok(())
            }
            Ok(_)
            | Err(
                MetadataAuthorityRequestError::Conflict
                | MetadataAuthorityRequestError::Unsupported
                | MetadataAuthorityRequestError::Failed,
            ) => Err(()),
        }
    }
}
