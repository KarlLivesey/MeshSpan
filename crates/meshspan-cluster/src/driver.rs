// SPDX-License-Identifier: GPL-2.0-only

//! Persistence-first runtime loop around the deterministic consensus core.

use std::collections::VecDeque;

use meshspan_consensus::{
    ActiveQuorumPlan, ConsensusCore, CoreEffect, CoreError, CoreInput, CoreMessage,
    DurableMutation, LogEntry, LogPosition, MemberIncarnations, PersistenceId, ProposalId,
    ReadBarrierId, Role,
};
use meshspan_domain::{NodeId, OperationId, ScopeId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommandContext, CommandReceipt,
    ConsensusStoreError, LogPosition as MetadataLogPosition, METADATA_COMMAND_VERSION,
    MetadataCommandCodecError, PartitionConsensusPersistence, RepositoryError, ScopeWriteAuthority,
    decode_authoritative_command,
};
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

/// One already validated scope mutation ready for the consensus proposal boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopedProposal {
    /// Routed scope whose current authority must accept the mutation.
    pub scope_id: ScopeId,
    /// Exact catalogue route epoch observed by the caller.
    pub routing_epoch: u64,
    /// Caller correlation for append acknowledgement.
    pub proposal_id: ProposalId,
    /// Stable idempotency identity committed with the log entry.
    pub operation_id: OperationId,
    /// Closed command codec version.
    pub command_version: u16,
    /// Validated command payload.
    pub command: Vec<u8>,
}

/// Durable state-machine result plus effects unlocked by reporting its applied position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedAuthoritativeCommand {
    /// Exact idempotent metadata receipt.
    pub receipt: CommandReceipt,
    /// Consensus effects which became safe only after state-machine durability.
    pub effects: Vec<DriverEffect>,
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

    /// Returns the current independently proved stable or joint quorum phase.
    #[must_use]
    pub const fn active_plan(&self) -> &ActiveQuorumPlan {
        self.core.active_plan()
    }

    /// Returns the exact current-incarnation map accepted by the consensus core.
    #[must_use]
    pub const fn member_incarnations(&self) -> &MemberIncarnations {
        self.core.member_incarnations()
    }

    /// Returns the complete entry at the current non-genesis commit position.
    #[must_use]
    pub fn committed_entry(&self) -> Option<&LogEntry> {
        self.core.committed_entry()
    }

    /// Returns one locally present replicated-log entry by exact index.
    #[must_use]
    pub fn log_entry(&self, index: u64) -> Option<&LogEntry> {
        self.core.log_entry(index)
    }

    /// Returns the durable log tail entry, if the log is non-empty.
    #[must_use]
    pub fn last_log_entry(&self) -> Option<&LogEntry> {
        self.core.last_log_entry()
    }

    /// Returns the leader's highest exact match position for one current member.
    #[must_use]
    pub fn peer_matched_index(&self, node_id: NodeId) -> Option<u64> {
        self.core.peer_matched_index(node_id)
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

impl<P: PartitionConsensusPersistence + ScopeWriteAuthority> PartitionConsensusDriver<P> {
    /// Proposes a mutation only when this partition owns the scope at the exact route epoch.
    ///
    /// # Errors
    ///
    /// Fails before touching consensus state when the route is missing, corrupt, stale or owned by
    /// another partition. Otherwise it has the same persistence-first failures as [`Self::step`].
    pub fn propose_scoped(
        &mut self,
        proposal: ScopedProposal,
        persisted_at: UnixMicros,
    ) -> Result<Vec<DriverEffect>, ClusterDriverError> {
        if !self
            .persistence
            .permits_scope_write(proposal.scope_id, proposal.routing_epoch)?
        {
            return Err(ClusterDriverError::WriteFenced);
        }
        self.step(
            CoreInput::Propose {
                proposal_id: proposal.proposal_id,
                operation_id: proposal.operation_id,
                command_version: proposal.command_version,
                command: proposal.command,
            },
            persisted_at,
        )
    }
}

impl PartitionConsensusDriver<AuthoritativeRepository> {
    /// Executes and rolls back the exact metadata transaction before log admission.
    ///
    /// # Errors
    ///
    /// Rejects semantic conflicts, stale revisions and invalid commands without appending them.
    pub fn preflight_authoritative_command(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<(), ClusterDriverError> {
        let mut preceding = Vec::new();
        let mut index = self
            .applied_index()
            .checked_add(1)
            .ok_or(ClusterDriverError::InvalidCommittedCommand)?;
        while let Some(entry) = self.log_entry(index) {
            if entry.command_version != METADATA_COMMAND_VERSION {
                return Err(ClusterDriverError::InvalidCommittedCommand);
            }
            let decoded = decode_authoritative_command(&entry.command)?;
            if decoded.context.operation_id != entry.operation_id {
                return Err(ClusterDriverError::InvalidCommittedCommand);
            }
            preceding.push((
                MetadataLogPosition {
                    term: entry.position.term,
                    index: entry.position.index,
                },
                decoded.context,
                decoded.command,
            ));
            index = index
                .checked_add(1)
                .ok_or(ClusterDriverError::InvalidCommittedCommand)?;
        }
        self.persistence
            .preflight_command(&preceding, context, command)?;
        Ok(())
    }

    /// Decodes and applies one exact entry previously emitted as committed by this driver.
    ///
    /// # Errors
    ///
    /// Rejects an uncommitted, substituted, unsupported or operation-mismatched entry before
    /// mutating metadata. Repository durability precedes the applied-through acknowledgement.
    pub fn apply_authoritative_committed(
        &mut self,
        entry: &LogEntry,
        applied_at: UnixMicros,
    ) -> Result<AppliedAuthoritativeCommand, ClusterDriverError> {
        if entry.command_version != METADATA_COMMAND_VERSION
            || entry.position.index > self.commit_index()
            || self.log_entry(entry.position.index) != Some(entry)
        {
            return Err(ClusterDriverError::InvalidCommittedCommand);
        }
        let decoded = decode_authoritative_command(&entry.command)?;
        if decoded.context.operation_id != entry.operation_id {
            return Err(ClusterDriverError::InvalidCommittedCommand);
        }
        let receipt = self.persistence.apply_committed(
            MetadataLogPosition {
                term: entry.position.term,
                index: entry.position.index,
            },
            decoded.context,
            &decoded.command,
        )?;
        let effects = self.step(CoreInput::AppliedThrough(entry.position.index), applied_at)?;
        Ok(AppliedAuthoritativeCommand { receipt, effects })
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
    /// The durable routing projection could not authorise a scoped proposal safely.
    #[error("cluster scope authority lookup failed")]
    Authority(#[from] RepositoryError),
    /// Replicated command bytes or their closed version are invalid.
    #[error("cluster metadata command codec rejected committed bytes")]
    CommandCodec(#[from] MetadataCommandCodecError),
    /// Entry was not the exact committed local log entry or named another operation.
    #[error("cluster committed metadata command is invalid")]
    InvalidCommittedCommand,
    /// This partition is not the sole writer for the presented scope route epoch.
    #[error("cluster scope write is fenced")]
    WriteFenced,
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
    use meshspan_domain::{
        AuditEventId, HostId, MeshId, OperationId, PartitionId, PrincipalId, QuorumPlanId,
        Revision, RoleId,
    };
    use meshspan_metadata::{
        AuthoritativeCommand, BootstrapMesh, CommandContext, PartitionDatabase, RecordName,
        encode_authoritative_command,
    };

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

    #[test]
    fn committed_command_is_verified_applied_and_acknowledged_in_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let local = NodeId::from_bytes([21; 16])?;
        let partition = PartitionId::from_bytes([22; 16])?;
        let plan = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([23; 16])?,
            1,
            BTreeSet::from([local]),
            BTreeSet::new(),
        )?)?;
        let database = PartitionDatabase::open(
            &directory.path().join("authority.sqlite3"),
            partition,
            UnixMicros::new(1),
        )?;
        let mut repository = AuthoritativeRepository::new(database);
        repository.initialise_consensus_quorum_plan(&plan, UnixMicros::new(2))?;
        let incarnations = MemberIncarnations::new(BTreeMap::from([(local, 1)]), &plan)?;
        let core = ConsensusCore::new(CoreConfig {
            partition_id: partition,
            local_node_id: local,
            local_incarnation: 1,
            plan,
            member_incarnations: incarnations,
        })?;
        let mut driver = PartitionConsensusDriver::new(core, repository);
        driver.step(CoreInput::ElectionTimeout, UnixMicros::new(3))?;
        assert_eq!(driver.role(), Role::Leader);

        let (context, command) = bootstrap_command(local)?;
        let command = encode_authoritative_command(context, &command)?;
        let effects = driver.step(
            CoreInput::Propose {
                proposal_id: ProposalId(1),
                operation_id: context.operation_id,
                command_version: METADATA_COMMAND_VERSION,
                command,
            },
            UnixMicros::new(4),
        )?;
        let entry = effects
            .into_iter()
            .find_map(|effect| match effect {
                DriverEffect::ApplyCommitted { mut entries } if entries.len() == 1 => entries.pop(),
                _ => None,
            })
            .ok_or("single-voter proposal did not commit")?;

        let mut substituted = entry.clone();
        substituted.operation_id = OperationId::from_bytes([99; 16])?;
        assert!(matches!(
            driver.apply_authoritative_committed(&substituted, UnixMicros::new(5)),
            Err(ClusterDriverError::InvalidCommittedCommand)
        ));
        assert_eq!(driver.persistence().current_revision()?, Revision::ZERO);

        let applied = driver.apply_authoritative_committed(&entry, UnixMicros::new(6))?;
        assert_eq!(applied.receipt.operation_id, context.operation_id);
        assert_eq!(applied.receipt.committed_revision, Revision::new(1));
        assert_eq!(driver.applied_index(), entry.position.index);
        let resolved = driver
            .persistence()
            .resolve_operation(context.operation_id)?
            .ok_or("committed operation did not resolve")?;
        assert_eq!(resolved.result_digest, applied.receipt.result_digest);
        assert_eq!(
            resolved.committed_position,
            applied.receipt.committed_position
        );
        Ok(())
    }

    fn bootstrap_command(
        node_id: NodeId,
    ) -> Result<(CommandContext, AuthoritativeCommand), Box<dyn std::error::Error>> {
        let administrator_id = PrincipalId::from_bytes([31; 16])?;
        let context = CommandContext {
            operation_id: OperationId::from_bytes([32; 16])?,
            actor_principal_id: administrator_id,
            audit_event_id: AuditEventId::from_bytes([33; 16])?,
            occurred_at: UnixMicros::new(10),
            expected_revision: Some(Revision::ZERO),
        };
        let command = crate::protected_volume_test_support::protected_bootstrap(BootstrapMesh {
            mesh_id: MeshId::from_bytes([34; 16])?,
            mesh_name: RecordName::new("Driver mesh")?,
            administrator_id,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([35; 16])?,
            host_id: HostId::from_bytes([36; 16])?,
            host_name: RecordName::new("Host")?,
            node_id,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        })?;
        Ok((context, command))
    }
}
