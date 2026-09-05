// SPDX-License-Identifier: GPL-2.0-only

//! Fixed-size, local-only observations; these never establish a quorum or authorise work.

use meshspan_consensus::Role;
use meshspan_domain::{NodeId, PartitionId};
use tokio::sync::oneshot;

use super::{
    AuthorityEvent, MetadataAuthorityHandle, MetadataAuthorityRequestError,
    MetadataAuthorityRuntime,
};

/// One coherent reactor observation, not a linearizable read or availability guarantee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataAuthorityObservation {
    /// Observed metadata partition.
    pub partition_id: PartitionId,
    /// Node running this reactor.
    pub node_id: NodeId,
    /// Local volatile role; a leader may have lost contact with its quorum.
    pub role: Role,
    /// Most recently known leader, not a reachability assertion.
    pub known_leader: Option<NodeId>,
    /// Durable term observed by the driver.
    pub term: u64,
    /// Highest locally known committed index.
    pub commit_index: u64,
    /// Highest locally applied index.
    pub applied_index: u64,
    /// Current stable or transitional membership epoch.
    pub membership_epoch: u64,
    /// Exact active quorum-plan proof identity, not a fresh quorum acknowledgement.
    pub plan_digest: [u8; 32],
    /// Whether persistence has fenced further driver mutations.
    pub persistence_blocked: bool,
    /// Operations admitted to consensus and awaiting their committed result.
    pub pending_operations: usize,
    /// Mutations queued for admission, excluding peer/lifecycle messages.
    pub queued_operations: usize,
}

impl MetadataAuthorityHandle {
    /// Observes this reactor without a database scan, network request or log append.
    ///
    /// Admission is immediate and bounded by the existing event queue. Waiting for the
    /// owner is limited to one second; cancellation drops only the response receiver.
    /// No cached observation is substituted if the owner is stopped or unresponsive.
    ///
    /// # Errors
    /// Returns unavailable when the queue is full, the owner stops, or the deadline expires.
    pub async fn observe(
        &self,
    ) -> Result<MetadataAuthorityObservation, MetadataAuthorityRequestError> {
        let (respond, response) = oneshot::channel();
        self.events
            .try_send(AuthorityEvent::Observe(respond))
            .map_err(|_| MetadataAuthorityRequestError::Unavailable)?;
        tokio::time::timeout(std::time::Duration::from_secs(1), response)
            .await
            .map_err(|_| MetadataAuthorityRequestError::Unavailable)?
            .map_err(|_| MetadataAuthorityRequestError::Unavailable)
    }
}

impl MetadataAuthorityRuntime {
    pub(super) fn observation(&self) -> MetadataAuthorityObservation {
        MetadataAuthorityObservation {
            partition_id: self.driver.persistence().partition_id(),
            node_id: self.driver.local_node_id(),
            role: self.driver.role(),
            known_leader: self.driver.leader_id(),
            term: self.driver.current_term(),
            commit_index: self.driver.commit_index(),
            applied_index: self.driver.applied_index(),
            membership_epoch: self.driver.active_plan().membership_epoch(),
            plan_digest: self.driver.active_plan().proof_digest(),
            persistence_blocked: self.driver.persistence_blocked(),
            pending_operations: self.pending.len(),
            queued_operations: self.queued.len(),
        }
    }
}
