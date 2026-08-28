// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic election and log-replication state transitions.

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{NodeId, OperationId};

use super::types::{
    AppendRequest, AppendResponse, CoreConfig, CoreEffect, CoreError, CoreInput, CoreMessage,
    DurableCoreState, DurableMutation, LogEntry, LogPosition, PersistenceId, ProposalId,
    ReadBarrierId, Role, VoteRequest, VoteResponse, validate_append_entries,
};
use crate::{CompiledQuorumPlan, JointQuorumPlan, QuorumFamily};

const MAXIMUM_APPEND_ENTRIES: usize = 64;
const MAXIMUM_PENDING_READ_BARRIERS: usize = 1_024;

enum RoleState {
    Follower,
    Candidate { votes: BTreeSet<NodeId> },
    Leader(LeaderState),
}

enum ActivePlan {
    Stable(Box<CompiledQuorumPlan>),
    Joint(Box<JointQuorumPlan>),
}

struct LeaderState {
    matched: BTreeMap<NodeId, u64>,
    next: BTreeMap<NodeId, u64>,
    read_barriers: BTreeMap<ReadBarrierId, ReadBarrierState>,
}

struct ReadBarrierState {
    acknowledgements: BTreeSet<NodeId>,
    required_applied_index: u64,
    quorum_confirmed: bool,
}

struct PendingPersistence {
    id: PersistenceId,
    mutation: DurableMutation,
    action: AfterPersistence,
}

enum AfterPersistence {
    Campaign,
    VoteReply {
        to: NodeId,
        granted: bool,
    },
    AppendReply {
        to: NodeId,
        leader: NodeId,
        leader_commit_index: u64,
        accepted: bool,
        read_barrier_id: Option<ReadBarrierId>,
    },
    Proposal {
        proposal_id: ProposalId,
        position: LogPosition,
    },
    StepDown,
    ActivateJoint(Box<JointQuorumPlan>),
    ActivateStable(Box<CompiledQuorumPlan>),
}

/// Owned deterministic consensus core. It performs no IO and emits persistence before dependent
/// messages or commit evidence.
pub struct ConsensusCore {
    config: CoreConfig,
    active_plan: ActivePlan,
    current_term: u64,
    voted_for: Option<NodeId>,
    log: Vec<LogEntry>,
    commit_index: u64,
    applied_index: u64,
    leader_id: Option<NodeId>,
    role: RoleState,
    pending: Option<PendingPersistence>,
    next_persistence_id: u64,
}

impl ConsensusCore {
    /// Constructs an empty follower/learner at term zero under one verified plan.
    ///
    /// # Errors
    ///
    /// Rejects a zero/mismatched local incarnation or a node outside voters and learners.
    pub fn new(config: CoreConfig) -> Result<Self, CoreError> {
        Self::restore(config, DurableCoreState::default())
    }

    /// Restores a follower from independently verified durable vote, log and apply state.
    ///
    /// # Errors
    ///
    /// Rejects an invalid configuration, vote, non-contiguous/corrupt log or applied position.
    pub fn restore(config: CoreConfig, durable: DurableCoreState) -> Result<Self, CoreError> {
        let local_is_member = config.plan.spec().voters.contains(&config.local_node_id)
            || config.plan.spec().learners.contains(&config.local_node_id);
        if config.local_incarnation == 0
            || !local_is_member
            || config.member_incarnations.incarnation(config.local_node_id)
                != Some(config.local_incarnation)
            || (durable.current_term == 0 && durable.voted_for.is_some())
            || durable
                .voted_for
                .is_some_and(|voter| !config.plan.spec().voters.contains(&voter))
        {
            return Err(CoreError::InvalidConfiguration);
        }
        validate_durable_state(&durable)?;
        let active_plan = ActivePlan::Stable(Box::new(config.plan.clone()));
        Ok(Self {
            config,
            active_plan,
            current_term: durable.current_term,
            voted_for: durable.voted_for,
            log: durable.log,
            commit_index: durable.applied_index,
            applied_index: durable.applied_index,
            leader_id: None,
            role: RoleState::Follower,
            pending: None,
            next_persistence_id: 1,
        })
    }

    /// Returns current volatile role.
    #[must_use]
    pub fn role(&self) -> Role {
        match &self.role {
            RoleState::Follower => Role::Follower,
            RoleState::Candidate { .. } => Role::Candidate,
            RoleState::Leader(_) => Role::Leader,
        }
    }

    /// Returns current durable term.
    #[must_use]
    pub const fn current_term(&self) -> u64 {
        self.current_term
    }

    /// Returns highest committed log index.
    #[must_use]
    pub const fn commit_index(&self) -> u64 {
        self.commit_index
    }

    /// Returns highest state-machine-applied index reported by the driver.
    #[must_use]
    pub const fn applied_index(&self) -> u64 {
        self.applied_index
    }

    /// Returns current known leader, if any.
    #[must_use]
    pub const fn leader_id(&self) -> Option<NodeId> {
        self.leader_id
    }

    /// Returns the exact membership epoch accepted by this core.
    #[must_use]
    pub fn membership_epoch(&self) -> u64 {
        self.active_membership_epoch()
    }

    /// Returns the canonical digest of the mechanically verified quorum plan.
    #[must_use]
    pub fn plan_digest(&self) -> [u8; 32] {
        self.active_plan_digest()
    }

    /// Consumes one deterministic input and returns ordered side effects.
    ///
    /// # Errors
    ///
    /// Rejects malformed/stale input, a non-leader proposal, persistence reordering or any input
    /// received while a safety-critical durable mutation remains unacknowledged.
    pub fn step(&mut self, input: CoreInput) -> Result<Vec<CoreEffect>, CoreError> {
        if self.pending.is_some() && !matches!(input, CoreInput::Persisted(_)) {
            return Err(CoreError::PersistencePending);
        }
        match input {
            CoreInput::ElectionTimeout => self.start_election(),
            CoreInput::Heartbeat => self.heartbeat(),
            CoreInput::Persisted(id) => self.finish_persistence(id),
            CoreInput::Message {
                from,
                sender_incarnation,
                message,
            } => self.receive(from, sender_incarnation, message),
            CoreInput::Propose {
                proposal_id,
                operation_id,
                command_version,
                command,
            } => self.propose(proposal_id, operation_id, command_version, command),
            CoreInput::BeginReadBarrier(read_barrier_id) => {
                self.begin_read_barrier(read_barrier_id)
            }
            CoreInput::ActivateJointPlan {
                joint_plan,
                committed_position,
            } => self.activate_joint_plan(joint_plan, committed_position),
            CoreInput::ActivateStablePlan {
                plan,
                committed_position,
            } => self.activate_stable_plan(plan, committed_position),
            CoreInput::AppliedThrough(index) => self.applied_through(index),
        }
    }

    fn start_election(&mut self) -> Result<Vec<CoreEffect>, CoreError> {
        if matches!(self.role, RoleState::Leader(_)) {
            return Err(CoreError::InvalidInput);
        }
        if !self
            .active_eligible_leaders()
            .contains(&self.config.local_node_id)
        {
            return Err(CoreError::NotLeader);
        }
        let term = self
            .current_term
            .checked_add(1)
            .ok_or(CoreError::Exhausted)?;
        self.begin_persistence(
            DurableMutation {
                vote_state: Some((term, Some(self.config.local_node_id))),
                truncate_from: None,
                append: Vec::new(),
                membership_epoch: None,
            },
            AfterPersistence::Campaign,
        )
    }

    fn heartbeat(&self) -> Result<Vec<CoreEffect>, CoreError> {
        if self.role() != Role::Leader {
            return Err(CoreError::NotLeader);
        }
        self.peers()
            .into_iter()
            .map(|peer| self.append_effect(peer, None))
            .collect()
    }

    fn receive(
        &mut self,
        from: NodeId,
        sender_incarnation: u64,
        message: CoreMessage,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        self.validate_sender(from, sender_incarnation)?;
        match message {
            CoreMessage::VoteRequest(request) => self.vote_request(from, request),
            CoreMessage::VoteResponse(response) => self.vote_response(from, response),
            CoreMessage::AppendRequest(request) => self.append_request(from, &request),
            CoreMessage::AppendResponse(response) => self.append_response(from, response),
        }
    }

    fn vote_request(
        &mut self,
        from: NodeId,
        request: VoteRequest,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        self.validate_plan(request.membership_epoch, request.plan_digest)?;
        if request.candidate != from
            || request.candidate_incarnation != self.member_incarnation(from)?
            || request.term == 0
            || !request.last_log.is_valid()
            || !self.active_eligible_leaders().contains(&from)
        {
            return Err(CoreError::InvalidInput);
        }
        if request.term < self.current_term || !self.is_local_voter() {
            return Ok(vec![self.vote_effect(from, false)]);
        }
        let log_is_current = request.last_log >= self.last_position();
        let can_vote = request.term > self.current_term
            || self.voted_for.is_none()
            || self.voted_for == Some(from);
        let granted = log_is_current && can_vote;
        if request.term > self.current_term || (granted && self.voted_for != Some(from)) {
            return self.begin_persistence(
                DurableMutation {
                    vote_state: Some((request.term, granted.then_some(from))),
                    truncate_from: None,
                    append: Vec::new(),
                    membership_epoch: None,
                },
                AfterPersistence::VoteReply { to: from, granted },
            );
        }
        Ok(vec![self.vote_effect(from, granted)])
    }

    fn vote_response(
        &mut self,
        from: NodeId,
        response: VoteResponse,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        self.validate_plan(response.membership_epoch, response.plan_digest)?;
        if response.term == 0 {
            return Err(CoreError::InvalidInput);
        }
        if response.term > self.current_term {
            return self.persist_step_down(response.term);
        }
        if response.term < self.current_term {
            return Ok(Vec::new());
        }
        let votes = {
            let RoleState::Candidate { votes } = &mut self.role else {
                return Ok(Vec::new());
            };
            if response.granted {
                votes.insert(from);
            }
            votes.clone()
        };
        let has_election_quorum = self.active_satisfies(QuorumFamily::Election, &votes);
        if has_election_quorum {
            self.become_leader()
        } else {
            Ok(Vec::new())
        }
    }

    fn append_request(
        &mut self,
        from: NodeId,
        request: &AppendRequest,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        self.validate_plan(request.membership_epoch, request.plan_digest)?;
        validate_append_entries(request)?;
        if request.leader != from
            || request.leader_incarnation != self.member_incarnation(from)?
            || !self.active_eligible_leaders().contains(&from)
        {
            return Err(CoreError::InvalidInput);
        }
        if request.term < self.current_term {
            return Ok(vec![self.append_response_effect(
                from,
                false,
                request.read_barrier_id,
            )]);
        }
        let previous_matches = self.position_matches(request.previous, request.previous_digest);
        if !previous_matches {
            if request.term > self.current_term {
                return self.begin_persistence(
                    DurableMutation {
                        vote_state: Some((request.term, None)),
                        truncate_from: None,
                        append: Vec::new(),
                        membership_epoch: None,
                    },
                    AfterPersistence::AppendReply {
                        to: from,
                        leader: from,
                        leader_commit_index: 0,
                        accepted: false,
                        read_barrier_id: request.read_barrier_id,
                    },
                );
            }
            return Ok(vec![self.append_response_effect(
                from,
                false,
                request.read_barrier_id,
            )]);
        }
        let (truncate_from, append) = self.log_delta(&request.entries)?;
        let changes_term = request.term > self.current_term;
        if changes_term || truncate_from.is_some() || !append.is_empty() {
            return self.begin_persistence(
                DurableMutation {
                    vote_state: changes_term.then_some((request.term, None)),
                    truncate_from,
                    append,
                    membership_epoch: None,
                },
                AfterPersistence::AppendReply {
                    to: from,
                    leader: from,
                    leader_commit_index: request.leader_commit_index,
                    accepted: true,
                    read_barrier_id: request.read_barrier_id,
                },
            );
        }
        self.follow_leader(Some(from));
        let mut effects = self.advance_follower_commit(request.leader_commit_index)?;
        effects.push(self.append_response_effect(from, true, request.read_barrier_id));
        Ok(effects)
    }

    fn append_response(
        &mut self,
        from: NodeId,
        response: AppendResponse,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        self.validate_plan(response.membership_epoch, response.plan_digest)?;
        if response.term == 0
            || response.next_index_hint == 0
            || response
                .read_barrier_id
                .is_some_and(|read_barrier_id| read_barrier_id.0 == 0)
        {
            return Err(CoreError::InvalidInput);
        }
        if response.term > self.current_term {
            return self.persist_step_down(response.term);
        }
        if response.term < self.current_term {
            return Ok(Vec::new());
        }
        let last_index = self.last_position().index;
        let peer_next = {
            let RoleState::Leader(leader) = &mut self.role else {
                return Ok(Vec::new());
            };
            if response.accepted {
                if response.matched_index > last_index {
                    return Err(CoreError::InvalidInput);
                }
                leader.matched.insert(from, response.matched_index);
                leader.next.insert(
                    from,
                    response
                        .matched_index
                        .checked_add(1)
                        .ok_or(CoreError::Exhausted)?,
                );
            } else {
                let last_next = last_index.checked_add(1).ok_or(CoreError::Exhausted)?;
                leader
                    .next
                    .insert(from, response.next_index_hint.min(last_next).max(1));
            }
            leader.next.get(&from).copied().unwrap_or(1)
        };
        let mut effects = self.advance_leader_commit()?;
        effects.extend(self.acknowledge_read_barrier(from, response.read_barrier_id)?);
        if peer_next <= last_index {
            effects.push(self.append_effect(from, None)?);
        }
        Ok(effects)
    }

    fn propose(
        &mut self,
        proposal_id: ProposalId,
        operation_id: OperationId,
        command_version: u16,
        command: Vec<u8>,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        if self.role() != Role::Leader {
            return Err(CoreError::NotLeader);
        }
        if proposal_id.0 == 0 {
            return Err(CoreError::InvalidInput);
        }
        let index = self
            .last_position()
            .index
            .checked_add(1)
            .ok_or(CoreError::Exhausted)?;
        let position = LogPosition {
            term: self.current_term,
            index,
        };
        let entry = LogEntry::new(position, operation_id, command_version, command)?;
        self.begin_persistence(
            DurableMutation {
                vote_state: None,
                truncate_from: None,
                append: vec![entry],
                membership_epoch: None,
            },
            AfterPersistence::Proposal {
                proposal_id,
                position,
            },
        )
    }

    fn begin_read_barrier(
        &mut self,
        read_barrier_id: ReadBarrierId,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        if read_barrier_id.0 == 0 {
            return Err(CoreError::InvalidInput);
        }
        let required_applied_index = self.commit_index;
        let local_node_id = self.config.local_node_id;
        let quorum_confirmed =
            self.active_satisfies(QuorumFamily::Read, &BTreeSet::from([local_node_id]));
        {
            let RoleState::Leader(leader) = &mut self.role else {
                return Err(CoreError::NotLeader);
            };
            if leader.read_barriers.len() >= MAXIMUM_PENDING_READ_BARRIERS
                || leader.read_barriers.contains_key(&read_barrier_id)
            {
                return Err(CoreError::InvalidInput);
            }
            leader.read_barriers.insert(
                read_barrier_id,
                ReadBarrierState {
                    acknowledgements: BTreeSet::from([local_node_id]),
                    required_applied_index,
                    quorum_confirmed,
                },
            );
        }
        if quorum_confirmed {
            return Ok(self.complete_read_barriers());
        }
        self.peers()
            .into_iter()
            .map(|peer| self.append_effect(peer, Some(read_barrier_id)))
            .collect()
    }

    fn activate_joint_plan(
        &mut self,
        joint_plan: Box<JointQuorumPlan>,
        committed_position: LogPosition,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        let ActivePlan::Stable(current) = &self.active_plan else {
            return Err(CoreError::InvalidInput);
        };
        if current.proof_digest() != joint_plan.old_plan().proof_digest()
            || current.spec().membership_epoch != joint_plan.old_plan().spec().membership_epoch
            || joint_plan.members() != self.active_members()
        {
            return Err(CoreError::InvalidInput);
        }
        self.validate_applied_transition_position(committed_position)?;
        self.begin_persistence(
            DurableMutation {
                vote_state: None,
                truncate_from: None,
                append: Vec::new(),
                membership_epoch: Some(joint_plan.membership_epoch()),
            },
            AfterPersistence::ActivateJoint(joint_plan),
        )
    }

    fn activate_stable_plan(
        &mut self,
        plan: Box<CompiledQuorumPlan>,
        committed_position: LogPosition,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        let ActivePlan::Joint(joint) = &self.active_plan else {
            return Err(CoreError::InvalidInput);
        };
        if plan.proof_digest() != joint.new_plan().proof_digest()
            || plan.spec().membership_epoch != joint.membership_epoch()
            || joint.members() != self.active_members()
        {
            return Err(CoreError::InvalidInput);
        }
        self.validate_applied_transition_position(committed_position)?;
        self.begin_persistence(
            DurableMutation {
                vote_state: None,
                truncate_from: None,
                append: Vec::new(),
                membership_epoch: Some(plan.spec().membership_epoch),
            },
            AfterPersistence::ActivateStable(plan),
        )
    }

    fn validate_applied_transition_position(
        &self,
        committed_position: LogPosition,
    ) -> Result<(), CoreError> {
        if committed_position == LogPosition::GENESIS
            || committed_position.index > self.applied_index
            || self
                .entry(committed_position.index)
                .is_none_or(|entry| entry.position.term != committed_position.term)
        {
            Err(CoreError::InvalidInput)
        } else {
            Ok(())
        }
    }

    fn acknowledge_read_barrier(
        &mut self,
        from: NodeId,
        read_barrier_id: Option<ReadBarrierId>,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        let Some(read_barrier_id) = read_barrier_id else {
            return Ok(Vec::new());
        };
        if read_barrier_id.0 == 0 {
            return Err(CoreError::InvalidInput);
        }
        let acknowledgements = {
            let RoleState::Leader(leader) = &mut self.role else {
                return Ok(Vec::new());
            };
            let Some(barrier) = leader.read_barriers.get_mut(&read_barrier_id) else {
                return Ok(Vec::new());
            };
            barrier.acknowledgements.insert(from);
            barrier.acknowledgements.clone()
        };
        let quorum_confirmed = self.active_satisfies(QuorumFamily::Read, &acknowledgements);
        if let RoleState::Leader(leader) = &mut self.role
            && let Some(barrier) = leader.read_barriers.get_mut(&read_barrier_id)
        {
            barrier.quorum_confirmed = quorum_confirmed;
        }
        Ok(self.complete_read_barriers())
    }

    fn complete_read_barriers(&mut self) -> Vec<CoreEffect> {
        let RoleState::Leader(leader) = &mut self.role else {
            return Vec::new();
        };
        let completed: Vec<(ReadBarrierId, u64)> = leader
            .read_barriers
            .iter()
            .filter_map(|(id, barrier)| {
                (barrier.quorum_confirmed && barrier.required_applied_index <= self.applied_index)
                    .then_some((*id, barrier.required_applied_index))
            })
            .collect();
        for (id, _) in &completed {
            leader.read_barriers.remove(id);
        }
        completed
            .into_iter()
            .map(
                |(read_barrier_id, applied_index)| CoreEffect::ReadBarrierReady {
                    read_barrier_id,
                    applied_index,
                },
            )
            .collect()
    }

    fn applied_through(&mut self, index: u64) -> Result<Vec<CoreEffect>, CoreError> {
        if index < self.applied_index || index > self.commit_index {
            return Err(CoreError::InvalidInput);
        }
        self.applied_index = index;
        Ok(self.complete_read_barriers())
    }

    fn begin_persistence(
        &mut self,
        mutation: DurableMutation,
        action: AfterPersistence,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        let id = PersistenceId(self.next_persistence_id);
        self.next_persistence_id = self
            .next_persistence_id
            .checked_add(1)
            .ok_or(CoreError::Exhausted)?;
        self.pending = Some(PendingPersistence {
            id,
            mutation: mutation.clone(),
            action,
        });
        Ok(vec![CoreEffect::Persist { id, mutation }])
    }

    fn finish_persistence(&mut self, id: PersistenceId) -> Result<Vec<CoreEffect>, CoreError> {
        let pending = self.pending.take().ok_or(CoreError::StalePersistence)?;
        if pending.id != id {
            self.pending = Some(pending);
            return Err(CoreError::StalePersistence);
        }
        self.apply_durable_mutation(&pending.mutation)?;
        match pending.action {
            AfterPersistence::Campaign => self.finish_campaign(),
            AfterPersistence::VoteReply { to, granted } => {
                self.follow_leader(None);
                Ok(vec![self.vote_effect(to, granted)])
            }
            AfterPersistence::AppendReply {
                to,
                leader,
                leader_commit_index,
                accepted,
                read_barrier_id,
            } => {
                self.follow_leader(Some(leader));
                let mut effects = if accepted {
                    self.advance_follower_commit(leader_commit_index)?
                } else {
                    Vec::new()
                };
                effects.push(self.append_response_effect(to, accepted, read_barrier_id));
                Ok(effects)
            }
            AfterPersistence::Proposal {
                proposal_id,
                position,
            } => self.finish_proposal(proposal_id, position),
            AfterPersistence::StepDown => {
                self.follow_leader(None);
                Ok(vec![CoreEffect::RoleChanged {
                    role: Role::Follower,
                    term: self.current_term,
                }])
            }
            AfterPersistence::ActivateJoint(joint_plan) => {
                Ok(self.finish_plan_activation(ActivePlan::Joint(joint_plan)))
            }
            AfterPersistence::ActivateStable(plan) => {
                Ok(self.finish_plan_activation(ActivePlan::Stable(plan)))
            }
        }
    }

    fn finish_plan_activation(&mut self, active_plan: ActivePlan) -> Vec<CoreEffect> {
        self.active_plan = active_plan;
        let may_lead = self
            .active_eligible_leaders()
            .contains(&self.config.local_node_id);
        if let RoleState::Leader(leader) = &mut self.role {
            leader.read_barriers.clear();
        }
        if may_lead && self.is_local_voter() {
            return Vec::new();
        }
        let changed = self.role() != Role::Follower;
        self.follow_leader(None);
        changed
            .then_some(CoreEffect::RoleChanged {
                role: Role::Follower,
                term: self.current_term,
            })
            .into_iter()
            .collect()
    }

    fn finish_campaign(&mut self) -> Result<Vec<CoreEffect>, CoreError> {
        self.leader_id = None;
        self.role = RoleState::Candidate {
            votes: BTreeSet::from([self.config.local_node_id]),
        };
        let mut effects = vec![CoreEffect::RoleChanged {
            role: Role::Candidate,
            term: self.current_term,
        }];
        if self.active_satisfies(
            QuorumFamily::Election,
            &BTreeSet::from([self.config.local_node_id]),
        ) {
            effects.extend(self.become_leader()?);
            return Ok(effects);
        }
        let request = CoreMessage::VoteRequest(VoteRequest {
            term: self.current_term,
            candidate: self.config.local_node_id,
            candidate_incarnation: self.config.local_incarnation,
            last_log: self.last_position(),
            membership_epoch: self.active_membership_epoch(),
            plan_digest: self.active_plan_digest(),
        });
        for voter in self.active_voters() {
            if voter != self.config.local_node_id {
                effects.push(CoreEffect::Send {
                    to: voter,
                    message: request.clone(),
                });
            }
        }
        Ok(effects)
    }

    fn become_leader(&mut self) -> Result<Vec<CoreEffect>, CoreError> {
        let last = self.last_position().index;
        let next_index = last.checked_add(1).ok_or(CoreError::Exhausted)?;
        let mut matched = BTreeMap::from([(self.config.local_node_id, last)]);
        let mut next = BTreeMap::new();
        for member in self.members() {
            matched.entry(member).or_insert(0);
            next.insert(member, next_index);
        }
        self.role = RoleState::Leader(LeaderState {
            matched,
            next,
            read_barriers: BTreeMap::new(),
        });
        self.leader_id = Some(self.config.local_node_id);
        let mut effects = vec![CoreEffect::RoleChanged {
            role: Role::Leader,
            term: self.current_term,
        }];
        for peer in self.peers() {
            effects.push(self.append_effect(peer, None)?);
        }
        Ok(effects)
    }

    fn finish_proposal(
        &mut self,
        proposal_id: ProposalId,
        position: LogPosition,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        let RoleState::Leader(leader) = &mut self.role else {
            return Err(CoreError::NotLeader);
        };
        leader
            .matched
            .insert(self.config.local_node_id, position.index);
        leader.next.insert(
            self.config.local_node_id,
            position.index.checked_add(1).ok_or(CoreError::Exhausted)?,
        );
        let mut effects = vec![CoreEffect::ProposalAppended {
            proposal_id,
            position,
        }];
        for peer in self.peers() {
            effects.push(self.append_effect(peer, None)?);
        }
        effects.extend(self.advance_leader_commit()?);
        Ok(effects)
    }

    fn apply_durable_mutation(&mut self, mutation: &DurableMutation) -> Result<(), CoreError> {
        if let Some(membership_epoch) = mutation.membership_epoch
            && membership_epoch != self.active_membership_epoch()
            && membership_epoch != self.active_membership_epoch().saturating_add(1)
        {
            return Err(CoreError::InvalidInput);
        }
        if let Some((term, voted_for)) = mutation.vote_state {
            if term < self.current_term || term == 0 {
                return Err(CoreError::InvalidInput);
            }
            if term > self.current_term {
                self.role = RoleState::Follower;
                self.leader_id = None;
            }
            self.current_term = term;
            self.voted_for = voted_for;
        }
        if let Some(truncate_from) = mutation.truncate_from {
            if truncate_from <= self.commit_index || truncate_from == 0 {
                return Err(CoreError::InvalidInput);
            }
            self.log
                .retain(|entry| entry.position.index < truncate_from);
        }
        for entry in &mutation.append {
            entry.validate()?;
            let expected = self
                .last_position()
                .index
                .checked_add(1)
                .ok_or(CoreError::Exhausted)?;
            if entry.position.index != expected {
                return Err(CoreError::InvalidInput);
            }
            self.log.push(entry.clone());
        }
        Ok(())
    }

    fn log_delta(&self, incoming: &[LogEntry]) -> Result<(Option<u64>, Vec<LogEntry>), CoreError> {
        for (offset, entry) in incoming.iter().enumerate() {
            let local = self.entry(entry.position.index);
            match local {
                Some(existing)
                    if existing.position.term == entry.position.term
                        && existing.entry_digest() == entry.entry_digest() => {}
                Some(_) => {
                    if entry.position.index <= self.commit_index {
                        return Err(CoreError::InvalidInput);
                    }
                    return Ok((Some(entry.position.index), incoming[offset..].to_vec()));
                }
                None => return Ok((None, incoming[offset..].to_vec())),
            }
        }
        Ok((None, Vec::new()))
    }

    fn position_matches(&self, position: LogPosition, digest: [u8; 32]) -> bool {
        if position == LogPosition::GENESIS {
            return digest == [0; 32];
        }
        self.entry(position.index).is_some_and(|entry| {
            entry.position.term == position.term && entry.entry_digest() == digest
        })
    }

    fn append_effect(
        &self,
        peer: NodeId,
        read_barrier_id: Option<ReadBarrierId>,
    ) -> Result<CoreEffect, CoreError> {
        let RoleState::Leader(leader) = &self.role else {
            return Err(CoreError::NotLeader);
        };
        let next = leader.next.get(&peer).copied().unwrap_or(1).max(1);
        let previous_index = next.checked_sub(1).ok_or(CoreError::InvalidInput)?;
        let previous = if previous_index == 0 {
            LogPosition::GENESIS
        } else {
            self.entry(previous_index)
                .map(|entry| entry.position)
                .ok_or(CoreError::InvalidInput)?
        };
        let previous_digest = if previous_index == 0 {
            [0; 32]
        } else {
            self.entry(previous_index)
                .map(LogEntry::entry_digest)
                .ok_or(CoreError::InvalidInput)?
        };
        let entries: Vec<LogEntry> = self
            .log
            .iter()
            .filter(|entry| entry.position.index >= next)
            .take(MAXIMUM_APPEND_ENTRIES)
            .cloned()
            .collect();
        Ok(CoreEffect::Send {
            to: peer,
            message: CoreMessage::AppendRequest(AppendRequest {
                term: self.current_term,
                leader: self.config.local_node_id,
                leader_incarnation: self.config.local_incarnation,
                previous,
                previous_digest,
                entries,
                leader_commit_index: self.commit_index,
                read_barrier_id,
                membership_epoch: self.active_membership_epoch(),
                plan_digest: self.active_plan_digest(),
            }),
        })
    }

    fn advance_leader_commit(&mut self) -> Result<Vec<CoreEffect>, CoreError> {
        let RoleState::Leader(leader) = &self.role else {
            return Ok(Vec::new());
        };
        let matched = leader.matched.clone();
        let old_commit = self.commit_index;
        for index in ((old_commit + 1)..=self.last_position().index).rev() {
            let Some(entry) = self.entry(index) else {
                return Err(CoreError::InvalidInput);
            };
            if entry.position.term != self.current_term {
                continue;
            }
            let acknowledgements: BTreeSet<NodeId> = matched
                .iter()
                .filter_map(|(node, matched)| (*matched >= index).then_some(*node))
                .collect();
            if self.active_satisfies(QuorumFamily::Commit, &acknowledgements) {
                self.commit_index = index;
                break;
            }
        }
        self.commit_effects(old_commit)
    }

    fn advance_follower_commit(
        &mut self,
        leader_commit_index: u64,
    ) -> Result<Vec<CoreEffect>, CoreError> {
        let old_commit = self.commit_index;
        let next_commit = leader_commit_index.min(self.last_position().index);
        if next_commit < old_commit {
            return Err(CoreError::InvalidInput);
        }
        self.commit_index = next_commit;
        self.commit_effects(old_commit)
    }

    fn commit_effects(&self, old_commit: u64) -> Result<Vec<CoreEffect>, CoreError> {
        if self.commit_index <= old_commit {
            return Ok(Vec::new());
        }
        let entries = ((old_commit + 1)..=self.commit_index)
            .map(|index| self.entry(index).cloned().ok_or(CoreError::InvalidInput))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(vec![CoreEffect::CommitReady { entries }])
    }

    fn persist_step_down(&mut self, term: u64) -> Result<Vec<CoreEffect>, CoreError> {
        self.begin_persistence(
            DurableMutation {
                vote_state: Some((term, None)),
                truncate_from: None,
                append: Vec::new(),
                membership_epoch: None,
            },
            AfterPersistence::StepDown,
        )
    }

    fn follow_leader(&mut self, leader: Option<NodeId>) {
        self.role = RoleState::Follower;
        self.leader_id = leader;
    }

    fn vote_effect(&self, to: NodeId, granted: bool) -> CoreEffect {
        CoreEffect::Send {
            to,
            message: CoreMessage::VoteResponse(VoteResponse {
                term: self.current_term,
                granted,
                membership_epoch: self.active_membership_epoch(),
                plan_digest: self.active_plan_digest(),
            }),
        }
    }

    fn append_response_effect(
        &self,
        to: NodeId,
        accepted: bool,
        read_barrier_id: Option<ReadBarrierId>,
    ) -> CoreEffect {
        let last_index = self.last_position().index;
        let matched_index = if accepted { last_index } else { 0 };
        let next_index_hint = last_index.saturating_add(1).max(1);
        CoreEffect::Send {
            to,
            message: CoreMessage::AppendResponse(AppendResponse {
                term: self.current_term,
                accepted,
                matched_index,
                next_index_hint,
                read_barrier_id,
                membership_epoch: self.active_membership_epoch(),
                plan_digest: self.active_plan_digest(),
            }),
        }
    }

    fn validate_sender(&self, node_id: NodeId, incarnation: u64) -> Result<(), CoreError> {
        if self.config.member_incarnations.incarnation(node_id) == Some(incarnation) {
            Ok(())
        } else {
            Err(CoreError::StaleMember)
        }
    }

    fn validate_plan(&self, epoch: u64, digest: [u8; 32]) -> Result<(), CoreError> {
        if epoch == self.active_membership_epoch() && digest == self.active_plan_digest() {
            Ok(())
        } else {
            Err(CoreError::StaleMember)
        }
    }

    fn member_incarnation(&self, node_id: NodeId) -> Result<u64, CoreError> {
        self.config
            .member_incarnations
            .incarnation(node_id)
            .ok_or(CoreError::StaleMember)
    }

    fn is_local_voter(&self) -> bool {
        self.active_voters().contains(&self.config.local_node_id)
    }

    fn members(&self) -> BTreeSet<NodeId> {
        self.active_members()
    }

    fn peers(&self) -> BTreeSet<NodeId> {
        self.members()
            .into_iter()
            .filter(|node| *node != self.config.local_node_id)
            .collect()
    }

    fn active_satisfies(&self, family: QuorumFamily, acknowledgements: &BTreeSet<NodeId>) -> bool {
        match &self.active_plan {
            ActivePlan::Stable(plan) => plan.satisfies(family, acknowledgements),
            ActivePlan::Joint(plan) => plan.satisfies(family, acknowledgements),
        }
    }

    fn active_membership_epoch(&self) -> u64 {
        match &self.active_plan {
            ActivePlan::Stable(plan) => plan.spec().membership_epoch,
            ActivePlan::Joint(plan) => plan.membership_epoch(),
        }
    }

    fn active_plan_digest(&self) -> [u8; 32] {
        match &self.active_plan {
            ActivePlan::Stable(plan) => plan.proof_digest(),
            ActivePlan::Joint(plan) => plan.proof_digest(),
        }
    }

    fn active_voters(&self) -> BTreeSet<NodeId> {
        match &self.active_plan {
            ActivePlan::Stable(plan) => plan.spec().voters.clone(),
            ActivePlan::Joint(plan) => plan
                .old_plan()
                .spec()
                .voters
                .union(&plan.new_plan().spec().voters)
                .copied()
                .collect(),
        }
    }

    fn active_members(&self) -> BTreeSet<NodeId> {
        match &self.active_plan {
            ActivePlan::Stable(plan) => plan
                .spec()
                .voters
                .union(&plan.spec().learners)
                .copied()
                .collect(),
            ActivePlan::Joint(plan) => plan.members(),
        }
    }

    fn active_eligible_leaders(&self) -> BTreeSet<NodeId> {
        match &self.active_plan {
            ActivePlan::Stable(plan) => plan.spec().eligible_leaders.clone(),
            ActivePlan::Joint(plan) => plan.eligible_leaders(),
        }
    }

    fn last_position(&self) -> LogPosition {
        self.log
            .last()
            .map_or(LogPosition::GENESIS, |entry| entry.position)
    }

    fn entry(&self, index: u64) -> Option<&LogEntry> {
        let offset = index
            .checked_sub(1)
            .and_then(|value| usize::try_from(value).ok())?;
        self.log
            .get(offset)
            .filter(|entry| entry.position.index == index)
    }
}

fn validate_durable_state(durable: &DurableCoreState) -> Result<(), CoreError> {
    let mut expected_index = 1_u64;
    for entry in &durable.log {
        entry.validate()?;
        if entry.position.index != expected_index
            || entry.position.term > durable.current_term
            || (expected_index > 1
                && entry.position.term
                    < durable.log[usize::try_from(expected_index - 2)
                        .map_err(|_| CoreError::InvalidInput)?]
                    .position
                    .term)
        {
            return Err(CoreError::InvalidInput);
        }
        expected_index = expected_index.checked_add(1).ok_or(CoreError::Exhausted)?;
    }
    let last_index = durable.log.last().map_or(0, |entry| entry.position.index);
    if durable.applied_index > last_index {
        return Err(CoreError::InvalidInput);
    }
    Ok(())
}
