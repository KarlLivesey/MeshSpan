// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, cancellable read barriers owned by the metadata reactor, not cached observations.

use std::time::{Duration, Instant};

use meshspan_consensus::{CoreInput, LogPosition, ProposalId, ReadBarrierId, Role};
use meshspan_domain::{NodeId, OperationId, PartitionId, Revision, uuid_v8};
use sha2::{Digest as _, Sha256};
use tokio::sync::oneshot;

use super::{
    AuthorityEvent, MetadataAuthorityHandle, MetadataAuthorityRequestError as RequestError,
    MetadataAuthorityRuntime, MetadataAuthorityRuntimeError as RuntimeError,
};

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const MAXIMUM_PENDING_READS: usize = 64;

/// A quorum-confirmed applied frontier for this request, never a reusable permission lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataReadFence {
    /// Exact authoritative partition.
    pub partition_id: PartitionId,
    /// Leader that completed the read quorum.
    pub leader_node_id: NodeId,
    /// Confirmed leadership term.
    pub term: u64,
    /// Stable or joint membership epoch used by the read.
    pub membership_epoch: u64,
    /// Exact compiled active quorum plan.
    pub plan_digest: [u8; 32],
    /// Coherent applied position observed after the barrier completed.
    pub applied: LogPosition,
    /// Complete digest of that applied entry.
    pub applied_digest: [u8; 32],
    /// Application revision at the same reactor observation.
    pub revision: Revision,
}

pub(super) struct ReadRequest {
    pub(super) deadline: Instant,
    pub(super) respond: oneshot::Sender<Result<MetadataReadFence, RequestError>>,
}

pub(super) struct PendingRead {
    request: ReadRequest,
    term: u64,
    epoch: u64,
}

impl PendingRead {
    pub(super) fn reject(self, error: RequestError) {
        let _closed = self.request.respond.send(Err(error));
    }
}

impl MetadataAuthorityHandle {
    /// Confirms a fresh read quorum and locally applied current-term history.
    ///
    /// Only the first read in a term without a current-term entry proposes a fixed no-op.
    /// Later reads do not append. Cancellation never undoes that durable confirmation.
    ///
    /// # Errors
    /// Redirects non-leaders; rejects full/stopped queues or a five-second deadline.
    pub async fn read_fence(&self) -> Result<MetadataReadFence, RequestError> {
        let (respond, response) = oneshot::channel();
        let deadline = Instant::now() + READ_TIMEOUT;
        self.events
            .try_send(AuthorityEvent::Read(ReadRequest { deadline, respond }))
            .map_err(|_| RequestError::Unavailable)?;
        tokio::time::timeout_at(deadline.into(), response)
            .await
            .map_err(|_| RequestError::Unavailable)?
            .map_err(|_| RequestError::Unavailable)?
    }
}

impl MetadataAuthorityRuntime {
    pub(super) fn begin_read(&mut self, request: ReadRequest) -> Result<(), RuntimeError> {
        if request.respond.is_closed()
            || request.deadline <= Instant::now()
            || self.reads.len() >= MAXIMUM_PENDING_READS
        {
            let _closed = request.respond.send(Err(RequestError::Unavailable));
            return Ok(());
        }
        if self.driver.role() != Role::Leader {
            let _closed = request.respond.send(Err(RequestError::NotLeader {
                leader_id: self.driver.leader_id(),
            }));
            return Ok(());
        }
        let id = ReadBarrierId(self.next_read_id);
        self.next_read_id = self
            .next_read_id
            .checked_add(1)
            .ok_or(RuntimeError::ProposalSpaceExhausted)?;
        self.reads.insert(
            id,
            PendingRead {
                request,
                term: self.driver.current_term(),
                epoch: self.driver.active_plan().membership_epoch(),
            },
        );
        self.process_input(CoreInput::BeginReadBarrier(id))?;
        self.confirm_read_term()
    }

    fn confirm_read_term(&mut self) -> Result<(), RuntimeError> {
        if self.reads.is_empty()
            || self.driver.role() != Role::Leader
            || self
                .driver
                .last_log_entry()
                .is_some_and(|entry| entry.position.term == self.driver.current_term())
        {
            return Ok(());
        }
        let mut hash = Sha256::new();
        hash.update(b"meshspan.consensus.term-confirmation.v1");
        hash.update(self.driver.persistence().partition_id().as_bytes());
        hash.update(self.driver.local_node_id().as_bytes());
        hash.update(self.driver.current_term().to_be_bytes());
        let digest: [u8; 32] = hash.finalize().into();
        let mut identifier = [0; 16];
        identifier.copy_from_slice(&digest[..16]);
        let operation_id = OperationId::from_bytes(uuid_v8(identifier))
            .map_err(|_| RuntimeError::ProposalSpaceExhausted)?;
        let proposal_id = ProposalId(self.next_proposal_id);
        self.next_proposal_id = self
            .next_proposal_id
            .checked_add(1)
            .ok_or(RuntimeError::ProposalSpaceExhausted)?;
        self.process_input(CoreInput::ConfirmTerm {
            proposal_id,
            operation_id,
        })
    }

    pub(super) fn expire_reads(&mut self, instant: Instant) -> Result<(), RuntimeError> {
        let expired: Vec<_> = self
            .reads
            .iter()
            .filter(|(_, read)| {
                read.request.deadline <= instant || read.request.respond.is_closed()
            })
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some(read) = self.reads.remove(&id) {
                read.reject(RequestError::Unavailable);
            }
            self.process_input(CoreInput::CancelReadBarrier(id))?;
        }
        Ok(())
    }

    pub(super) fn complete_read(
        &mut self,
        id: ReadBarrierId,
        minimum_applied: u64,
    ) -> Result<(), RuntimeError> {
        let Some(read) = self.reads.remove(&id) else {
            return Ok(());
        };
        if read.request.deadline <= Instant::now()
            || read.term != self.driver.current_term()
            || read.epoch != self.driver.active_plan().membership_epoch()
            || self.driver.role() != Role::Leader
            || self.driver.applied_index() < minimum_applied
        {
            read.reject(RequestError::Unavailable);
            return Ok(());
        }
        let Some(entry) = self.driver.log_entry(self.driver.applied_index()) else {
            read.reject(RequestError::Failed);
            return Ok(());
        };
        let fence = MetadataReadFence {
            partition_id: self.driver.persistence().partition_id(),
            leader_node_id: self.driver.local_node_id(),
            term: self.driver.current_term(),
            membership_epoch: self.driver.active_plan().membership_epoch(),
            plan_digest: self.driver.active_plan().proof_digest(),
            applied: entry.position,
            applied_digest: entry.entry_digest(),
            revision: self.driver.persistence().current_revision()?,
        };
        let _closed = read.request.respond.send(Ok(fence));
        Ok(())
    }
}
