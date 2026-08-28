// SPDX-License-Identifier: GPL-2.0-only

//! Persistence-first runtime loop around the deterministic consensus core.

use std::collections::VecDeque;

use meshspan_consensus::{
    ConsensusCore, CoreEffect, CoreError, CoreInput, CoreMessage, DurableMutation, LogEntry,
    LogPosition, PersistenceId, ProposalId, ReadBarrierId, Role,
};
use meshspan_domain::{NodeId, UnixMicros};
use meshspan_metadata::{ConsensusStoreError, PartitionConsensusPersistence};
use thiserror::Error;

struct BlockedPersistence {
    id: PersistenceId,
    membership_epoch: u64,
    mutation: DurableMutation,
}

/// IO effects safe to execute after every prerequisite durable mutation completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DriverEffect {
    /// Send one core-owned message to an authenticated peer.
    Send {
        /// Exact enrolled destination.
        to: NodeId,
        /// Validated consensus message.
        message: CoreMessage,
    },
    /// Apply committed entries atomically to the metadata state machine, then report applied index.
    ApplyCommitted {
        /// Ordered non-empty committed entries.
        entries: Vec<LogEntry>,
    },
    /// Observable role/term change.
    RoleChanged {
        /// New local role.
        role: Role,
        /// Durable term.
        term: u64,
    },
    /// A caller proposal has a durable local log position but may not yet be committed.
    ProposalAppended {
        /// Caller correlation.
        proposal_id: ProposalId,
        /// Durable local log position.
        position: LogPosition,
    },
    /// A linearizable read may execute against at least this applied index.
    ReadBarrierReady {
        /// Caller correlation.
        read_barrier_id: ReadBarrierId,
        /// Minimum applied state-machine index.
        applied_index: u64,
    },
    /// Input was safely rejected without inventing success.
    Rejected {
        /// Stable core rejection category.
        error: CoreError,
    },
}

/// One partition's core plus its replaceable durable consensus repository.
pub struct PartitionConsensusDriver<P> {
    core: ConsensusCore,
    persistence: P,
    blocked: Option<BlockedPersistence>,
}

impl<P: PartitionConsensusPersistence> PartitionConsensusDriver<P> {
    /// Takes ownership of an already restored core and matching persistence adapter.
    #[must_use]
    pub const fn new(core: ConsensusCore, persistence: P) -> Self {
        Self {
            core,
            persistence,
            blocked: None,
        }
    }

    /// Processes one input and every immediately dependent persistence acknowledgement.
    ///
    /// # Errors
    ///
    /// Refuses new input while a failed persistence request awaits exact retry. Persistence failure
    /// leaves all dependent effects withheld.
    pub fn step(
        &mut self,
        input: CoreInput,
        persisted_at: UnixMicros,
    ) -> Result<Vec<DriverEffect>, ClusterDriverError> {
        if self.blocked.is_some() {
            return Err(ClusterDriverError::PersistenceBlocked);
        }
        let effects = self.core.step(input)?;
        self.process(effects, persisted_at)
    }

    /// Retries the exact failed mutation; no caller can substitute another input or mutation.
    ///
    /// # Errors
    ///
    /// Rejects no pending failure and preserves the pending retry on repeated store failure.
    pub fn retry_persistence(
        &mut self,
        persisted_at: UnixMicros,
    ) -> Result<Vec<DriverEffect>, ClusterDriverError> {
        let blocked = self
            .blocked
            .take()
            .ok_or(ClusterDriverError::NoBlockedPersistence)?;
        if let Err(error) = self.persistence.persist_consensus_mutation(
            blocked.membership_epoch,
            &blocked.mutation,
            persisted_at,
        ) {
            self.blocked = Some(blocked);
            return Err(error.into());
        }
        let effects = self.core.step(CoreInput::Persisted(blocked.id))?;
        self.process(effects, persisted_at)
    }

    /// Returns whether an exact durable mutation must be retried before other input.
    #[must_use]
    pub const fn persistence_blocked(&self) -> bool {
        self.blocked.is_some()
    }

    /// Returns the core's current volatile role for routing/status decisions.
    #[must_use]
    pub fn role(&self) -> Role {
        self.core.role()
    }

    /// Returns the current known leader.
    #[must_use]
    pub const fn leader_id(&self) -> Option<NodeId> {
        self.core.leader_id()
    }

    /// Returns the highest committed log index.
    #[must_use]
    pub const fn commit_index(&self) -> u64 {
        self.core.commit_index()
    }

    /// Returns the highest state-machine-applied log index.
    #[must_use]
    pub const fn applied_index(&self) -> u64 {
        self.core.applied_index()
    }

    /// Borrows the durable repository for read-only state-machine queries.
    ///
    /// The single-owner runtime uses this only after processing emitted effects; consensus
    /// persistence remains exclusively mediated by this driver.
    #[must_use]
    pub(crate) const fn persistence(&self) -> &P {
        &self.persistence
    }

    /// Borrows the durable repository to apply an emitted committed-entry batch.
    ///
    /// Callers must apply entries in order and report the resulting durable applied index through
    /// `CoreInput::AppliedThrough`. The runtime owns both operations in one event-loop turn.
    pub(crate) const fn persistence_mut(&mut self) -> &mut P {
        &mut self.persistence
    }

    /// Returns ownership of persistence after orderly shutdown.
    #[must_use]
    pub fn into_persistence(self) -> P {
        self.persistence
    }

    fn process(
        &mut self,
        effects: Vec<CoreEffect>,
        persisted_at: UnixMicros,
    ) -> Result<Vec<DriverEffect>, ClusterDriverError> {
        let mut pending = VecDeque::from(effects);
        let mut safe = Vec::new();
        while let Some(effect) = pending.pop_front() {
            match effect {
                CoreEffect::Persist { id, mutation } => {
                    let membership_epoch = self.core.membership_epoch();
                    if let Err(error) = self.persistence.persist_consensus_mutation(
                        membership_epoch,
                        &mutation,
                        persisted_at,
                    ) {
                        self.blocked = Some(BlockedPersistence {
                            id,
                            membership_epoch,
                            mutation,
                        });
                        return Err(error.into());
                    }
                    prepend(&mut pending, self.core.step(CoreInput::Persisted(id))?);
                }
                CoreEffect::Send { to, message } => {
                    safe.push(DriverEffect::Send { to, message });
                }
                CoreEffect::CommitReady { entries } => {
                    safe.push(DriverEffect::ApplyCommitted { entries });
                }
                CoreEffect::RoleChanged { role, term } => {
                    safe.push(DriverEffect::RoleChanged { role, term });
                }
                CoreEffect::ProposalAppended {
                    proposal_id,
                    position,
                } => safe.push(DriverEffect::ProposalAppended {
                    proposal_id,
                    position,
                }),
                CoreEffect::ReadBarrierReady {
                    read_barrier_id,
                    applied_index,
                } => safe.push(DriverEffect::ReadBarrierReady {
                    read_barrier_id,
                    applied_index,
                }),
                CoreEffect::Rejected { error } => safe.push(DriverEffect::Rejected { error }),
            }
        }
        Ok(safe)
    }
}

fn prepend(queue: &mut VecDeque<CoreEffect>, effects: Vec<CoreEffect>) {
    for effect in effects.into_iter().rev() {
        queue.push_front(effect);
    }
}

/// Closed driver failures; no error includes command, credential or certificate bytes.
#[derive(Debug, Error)]
pub enum ClusterDriverError {
    /// Deterministic consensus rejected an input or acknowledgement.
    #[error("cluster consensus input was rejected")]
    Core(#[from] CoreError),
    /// Durable consensus persistence failed before dependent effects escaped.
    #[error("cluster consensus persistence failed")]
    Persistence(#[from] ConsensusStoreError),
    /// New input was attempted while exact persistence retry is required.
    #[error("cluster consensus persistence retry is required")]
    PersistenceBlocked,
    /// Retry was requested when no persistence mutation is pending.
    #[error("cluster consensus has no failed persistence to retry")]
    NoBlockedPersistence,
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use meshspan_consensus::{CoreConfig, MemberIncarnations, compile_plan, flat_plan};
    use meshspan_domain::{PartitionId, QuorumPlanId};

    use super::*;

    struct FailingPersistence {
        fail_next: bool,
        durable: Vec<DurableMutation>,
    }

    impl PartitionConsensusPersistence for FailingPersistence {
        fn load_consensus_state(
            &self,
            _membership_epoch: u64,
        ) -> Result<meshspan_consensus::DurableCoreState, ConsensusStoreError> {
            Ok(meshspan_consensus::DurableCoreState::default())
        }

        fn persist_consensus_mutation(
            &mut self,
            _membership_epoch: u64,
            mutation: &DurableMutation,
            _persisted_at: UnixMicros,
        ) -> Result<(), ConsensusStoreError> {
            if self.fail_next {
                self.fail_next = false;
                Err(ConsensusStoreError::InjectedFault)
            } else {
                self.durable.push(mutation.clone());
                Ok(())
            }
        }
    }

    #[test]
    fn failed_vote_persistence_withholds_campaign_until_exact_retry()
    -> Result<(), Box<dyn std::error::Error>> {
        let local = NodeId::from_bytes([1; 16])?;
        let peer = NodeId::from_bytes([2; 16])?;
        let voters = BTreeSet::from([local, peer]);
        let plan = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([3; 16])?,
            1,
            voters.clone(),
            BTreeSet::new(),
        )?)?;
        let incarnations = MemberIncarnations::new(BTreeMap::from([(local, 1), (peer, 1)]), &plan)?;
        let core = ConsensusCore::new(CoreConfig {
            partition_id: PartitionId::from_bytes([4; 16])?,
            local_node_id: local,
            local_incarnation: 1,
            plan,
            member_incarnations: incarnations,
        })?;
        let mut driver = PartitionConsensusDriver::new(
            core,
            FailingPersistence {
                fail_next: true,
                durable: Vec::new(),
            },
        );

        assert!(matches!(
            driver.step(CoreInput::ElectionTimeout, UnixMicros::new(1)),
            Err(ClusterDriverError::Persistence(
                ConsensusStoreError::InjectedFault
            ))
        ));
        assert!(driver.persistence_blocked());
        assert_eq!(driver.role(), Role::Follower);
        assert!(matches!(
            driver.step(CoreInput::Heartbeat, UnixMicros::new(2)),
            Err(ClusterDriverError::PersistenceBlocked)
        ));

        let effects = driver.retry_persistence(UnixMicros::new(3))?;
        assert!(!driver.persistence_blocked());
        assert_eq!(driver.role(), Role::Candidate);
        assert!(effects.iter().any(|effect| matches!(
            effect,
            DriverEffect::Send {
                to,
                message: CoreMessage::VoteRequest(_)
            } if *to == peer
        )));
        Ok(())
    }
}
