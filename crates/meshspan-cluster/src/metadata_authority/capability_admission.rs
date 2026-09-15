// SPDX-License-Identifier: GPL-2.0-only

//! Capability evidence is admitted only against exact current root-authoritative identity.

use super::{
    BTreeMap, ClusterDriverError, CoreError, MetadataAuthorityRequestError,
    MetadataAuthorityRuntime, MetadataAuthorityRuntimeError, NodeId, now,
};
use meshspan_protocol::{MAXIMUM_CONSENSUS_BULK_BODY_BYTES, MAXIMUM_CONSENSUS_COMMAND_BYTES};
use meshspan_transport::PeerBinding;

const CONTROL_BYTES: usize = 64 * 1024;
const ENVELOPE_OVERHEAD: usize = 1024;
const ENTRY_OVERHEAD: usize = 128;

impl MetadataAuthorityRuntime {
    pub(super) fn check_bulk_admission(
        &self,
        command_bytes: usize,
    ) -> Result<(), MetadataAuthorityRequestError> {
        if inline_budget()
            .map_err(|_| MetadataAuthorityRequestError::Failed)?
            .permits_command(command_bytes)
        {
            return Ok(());
        }
        for node in self.driver.active_plan().members() {
            let observed = self
                .admitted_transfer_support(node)
                .map_err(|_| MetadataAuthorityRequestError::Failed)?
                .ok_or(MetadataAuthorityRequestError::Unavailable)?;
            if !supports_complete_bulk(&observed) {
                return Err(MetadataAuthorityRequestError::Unsupported);
            }
        }
        Ok(())
    }

    pub(super) fn refresh_replication_budgets(
        &mut self,
    ) -> Result<(), MetadataAuthorityRuntimeError> {
        let default = inline_budget().map_err(ClusterDriverError::Core)?;
        let bulk = meshspan_consensus::ReplicationBatchBudget::new(
            MAXIMUM_CONSENSUS_COMMAND_BYTES + 64 * ENTRY_OVERHEAD,
            ENTRY_OVERHEAD,
        )
        .map_err(ClusterDriverError::Core)?;
        let mut peers = BTreeMap::new();
        for node in self.driver.active_plan().members() {
            if self
                .admitted_transfer_support(node)?
                .as_ref()
                .is_some_and(supports_complete_bulk)
            {
                peers.insert(node, bulk);
            }
        }
        self.driver.set_replication_budgets(default, peers)?;
        Ok(())
    }

    fn admitted_transfer_support(
        &self,
        node: NodeId,
    ) -> Result<Option<crate::ObservedConsensusTransferSupport>, meshspan_metadata::RepositoryError>
    {
        let repository = self.driver.persistence();
        let Some(certificate) = repository.active_node_certificate(node)? else {
            return Ok(None);
        };
        if self.driver.member_incarnations().incarnation(node) != Some(certificate.incarnation)
            || certificate.valid_until <= now()
        {
            return Ok(None);
        }
        let digest = if let Some(current) = repository.node_capability_presentation(node)? {
            if current.incarnation != certificate.incarnation
                || current.certificate_generation != certificate.generation
                || current.certificate_fingerprint != certificate.certificate_fingerprint
            {
                return Ok(None);
            }
            current.capability_digest
        } else {
            let Some(activation) = repository.node_activation(node)? else {
                return Ok(None);
            };
            if activation.incarnation != certificate.incarnation {
                return Ok(None);
            }
            activation.capability_digest
        };
        let expected = PeerBinding {
            node_id: node,
            incarnation: certificate.incarnation,
            certificate_fingerprint: certificate.certificate_fingerprint,
        };
        // A failed cache read cannot grant compatibility. Controls retain their safe budget.
        match self
            .transport
            .consensus_transfer_support_for(expected, digest)
        {
            Ok(observed) => Ok(observed.filter(|value| value.capability_digest == digest)),
            Err(_) => Ok(None),
        }
    }
}

fn supports_complete_bulk(observed: &crate::ObservedConsensusTransferSupport) -> bool {
    observed.support.as_ref().is_some_and(|support| {
        support.format_version == 1
            && support.maximum_command_bytes >= MAXIMUM_CONSENSUS_COMMAND_BYTES as u64
            && support.maximum_body_bytes >= MAXIMUM_CONSENSUS_BULK_BODY_BYTES as u64
            && support.maximum_entries >= 64
    })
}

fn inline_budget() -> Result<meshspan_consensus::ReplicationBatchBudget, CoreError> {
    meshspan_consensus::ReplicationBatchBudget::new(
        CONTROL_BYTES - ENVELOPE_OVERHEAD,
        ENTRY_OVERHEAD,
    )
}
