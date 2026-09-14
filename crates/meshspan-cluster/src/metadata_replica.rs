// SPDX-License-Identifier: GPL-2.0-only

//! Non-voting committed-history application; never a source of fresh permission or quorum evidence.

use meshspan_consensus::{
    ActiveQuorumPlan, DurableCoreState, DurableMutation, DurableQuorumPlan, LogEntry, LogPosition,
    MEMBERSHIP_COMMAND_VERSION, MembershipTransitionCommand,
};
use meshspan_domain::{NodeId, PartitionId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeRepository, ConsensusStoreError, RepositoryError,
    decode_authoritative_entry_for_version, is_supported_metadata_command_version,
};
#[cfg(test)]
use meshspan_metadata::{METADATA_COMMAND_VERSION, decode_authoritative_command};
use thiserror::Error;

use crate::{PartitionConsensusDriver, restore_member_incarnations};

#[cfg(test)]
#[path = "metadata_replica_tests.rs"]
mod tests;

/// Maximum entries in one history page, independently of the byte ceiling.
pub const MAXIMUM_METADATA_REPLICA_ENTRIES: usize =
    meshspan_protocol::MAXIMUM_METADATA_REPLICA_ENTRIES;
/// Maximum aggregate command bytes; permits one maximum-sized existing log record.
pub const MAXIMUM_METADATA_REPLICA_BYTES: usize =
    meshspan_protocol::MAXIMUM_METADATA_REPLICA_COMMAND_BYTES;

/// Exact applied frontier and phase of a trusted local metadata installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataReplicaCursor {
    /// Partition whose history is requested.
    pub partition_id: PartitionId,
    /// Current stable/joint membership epoch.
    pub membership_epoch: u64,
    /// Independently compiled current phase digest.
    pub plan_digest: [u8; 32],
    /// Last durably applied position, or genesis.
    pub applied: LogPosition,
    /// Complete entry digest; zero only for genesis.
    pub applied_digest: [u8; 32],
}

/// Bounded committed history for a non-voting consumer, not a consensus RPC or read barrier.
///
/// Transport must authenticate the supplying same-swarm voter and incarnation. All fields
/// remain suspect and are revalidated at application. A page stops at any membership transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataReplicaPage {
    /// Exact frontier requested by the consumer.
    pub after: MetadataReplicaCursor,
    /// Contiguous durably applied records, never an uncommitted source tail.
    pub entries: Vec<LogEntry>,
}

impl PartitionConsensusDriver<AuthoritativeRepository> {
    /// Reads a bounded applied prefix without changing consensus or scanning the database.
    ///
    /// The outer handler must authorise a same-swarm replication recipient before calling.
    /// Neither this page nor an empty result establishes current permissions or freshness.
    ///
    /// # Errors
    /// Rejects wrong partitions/phases, divergent cursors and unavailable historical prefixes.
    pub fn metadata_replica_page(
        &self,
        after: MetadataReplicaCursor,
    ) -> Result<MetadataReplicaPage, MetadataReplicaError> {
        let limit = self
            .applied_replication_limit(after.membership_epoch, after.plan_digest)
            .ok_or(MetadataReplicaError::StaleCursor)?;
        if after.partition_id != self.persistence().partition_id() || after.applied.index > limit {
            return Err(MetadataReplicaError::StaleCursor);
        }
        verify_frontier(after, self.log_entry(after.applied.index))?;
        let mut entries = Vec::new();
        let mut bytes = 0_usize;
        let mut index = after.applied.index;
        while index < limit && entries.len() < MAXIMUM_METADATA_REPLICA_ENTRIES {
            index = index
                .checked_add(1)
                .ok_or(MetadataReplicaError::InvalidPage)?;
            let entry = self
                .log_entry(index)
                .ok_or(MetadataReplicaError::StaleCursor)?;
            if bytes.saturating_add(entry.command.len()) > MAXIMUM_METADATA_REPLICA_BYTES {
                break;
            }
            bytes += entry.command.len();
            entries.push(entry.clone());
            if entry.command_version == MEMBERSHIP_COMMAND_VERSION {
                break;
            }
        }
        let page = MetadataReplicaPage { after, entries };
        validate_page(&page)?;
        Ok(page)
    }
}

/// Exclusive durable metadata consumer outside the voter/learner set.
///
/// The starting database must already be an authenticated installation. This adapter neither
/// bootstraps trust nor accepts client mutations, campaigns, votes or acknowledges replication
/// to a consensus leader. Its repository is a historical read model, not fresh authorisation.
pub struct MetadataReplica {
    repository: AuthoritativeRepository,
    local_node_id: NodeId,
    plan: ActiveQuorumPlan,
    durable: DurableCoreState,
    reload_required: bool,
}

impl MetadataReplica {
    /// Opens an admitted, non-member installation without constructing a consensus core.
    ///
    /// # Errors
    /// Rejects missing/corrupt plans, fenced recovery or a local voter/learner.
    pub fn new(
        repository: AuthoritativeRepository,
        local_node_id: NodeId,
    ) -> Result<Self, MetadataReplicaError> {
        let plan = repository
            .load_active_consensus_quorum_plan()?
            .ok_or(MetadataReplicaError::StaleCursor)?;
        if plan.members().contains(&local_node_id) {
            return Err(MetadataReplicaError::LocalMember);
        }
        let durable = repository.load_consensus_state(plan.membership_epoch())?;
        restore_member_incarnations(&repository, &plan)
            .map_err(|_| MetadataReplicaError::Source)?;
        Ok(Self {
            repository,
            local_node_id,
            plan,
            durable,
            reload_required: false,
        })
    }

    /// Returns the durable frontier to request after restart or an interrupted page.
    ///
    /// # Errors
    /// A failed persistence/application requires reopening, never a guessed progress receipt.
    pub fn cursor(&self) -> Result<MetadataReplicaCursor, MetadataReplicaError> {
        if self.reload_required {
            return Err(MetadataReplicaError::ReloadRequired);
        }
        let entry = self.entry(self.durable.applied_index);
        Ok(MetadataReplicaCursor {
            partition_id: self.repository.partition_id(),
            membership_epoch: self.plan.membership_epoch(),
            plan_digest: self.plan.proof_digest(),
            applied: entry.map_or(LogPosition::GENESIS, |entry| entry.position),
            applied_digest: entry.map_or([0; 32], LogEntry::entry_digest),
        })
    }

    /// Applies only history supplied by an authenticated voter in this replica's exact phase.
    ///
    /// Every entry uses the ordinary command/membership validators and durable transactions.
    /// Pages are not all-or-nothing: a valid prefix can survive an error; reopen and request its
    /// durable cursor. A transition admitting this node stops further passive application, so
    /// the daemon can hand off to its ordinary member runtime. No fresh permission is returned.
    ///
    /// # Errors
    /// Rejects stale identities, malformed/divergent pages and local membership. IO/application
    /// failure fences this instance until reopened. Exact already-applied pages are harmless.
    pub fn apply(
        &mut self,
        source: NodeId,
        incarnation: u64,
        page: &MetadataReplicaPage,
        now: UnixMicros,
    ) -> Result<MetadataReplicaCursor, MetadataReplicaError> {
        let cursor = self.cursor()?;
        if self.plan.members().contains(&self.local_node_id) {
            return Err(MetadataReplicaError::LocalMember);
        }
        let members = restore_member_incarnations(&self.repository, &self.plan)
            .map_err(|_| MetadataReplicaError::Source)?;
        if !self.plan.voters().contains(&source) || members.incarnation(source) != Some(incarnation)
        {
            return Err(MetadataReplicaError::Source);
        }
        validate_page(page)?;
        if page.after.partition_id != cursor.partition_id
            || page.after.membership_epoch != cursor.membership_epoch
            || page.after.plan_digest != cursor.plan_digest
            || page.after.applied.index > cursor.applied.index
        {
            return Err(MetadataReplicaError::StaleCursor);
        }
        verify_frontier(page.after, self.entry(page.after.applied.index))?;
        for entry in &page.entries {
            if entry.position.index <= self.durable.applied_index {
                if self.entry(entry.position.index) != Some(entry) {
                    return Err(MetadataReplicaError::StaleCursor);
                }
                continue;
            }
            self.reload_required = true;
            self.apply_entry(entry, now)?;
            self.reload_required = false;
        }
        self.cursor()
    }

    /// Borrows historical metadata. Callers must obtain fresh authority separately where required.
    #[must_use]
    pub const fn repository(&self) -> &AuthoritativeRepository {
        &self.repository
    }

    /// Returns voters in this installed phase, never advisory presence or a leader assertion.
    ///
    /// # Errors
    /// Rejects a fenced instance or a node that must now use the ordinary member runtime.
    pub fn source_voters(
        &self,
    ) -> Result<std::collections::BTreeMap<NodeId, u64>, MetadataReplicaError> {
        self.cursor()?;
        if self.plan.members().contains(&self.local_node_id) {
            return Err(MetadataReplicaError::LocalMember);
        }
        let members = restore_member_incarnations(&self.repository, &self.plan)
            .map_err(|_| MetadataReplicaError::Source)?;
        self.plan
            .voters()
            .into_iter()
            .map(|node| {
                Ok((
                    node,
                    members
                        .incarnation(node)
                        .ok_or(MetadataReplicaError::Source)?,
                ))
            })
            .collect()
    }

    fn entry(&self, index: u64) -> Option<&LogEntry> {
        let offset = usize::try_from(index.checked_sub(1)?).ok()?;
        self.durable
            .log
            .get(offset)
            .filter(|entry| entry.position.index == index)
    }

    fn apply_entry(
        &mut self,
        entry: &LogEntry,
        now: UnixMicros,
    ) -> Result<(), MetadataReplicaError> {
        if entry.position.index
            != self
                .durable
                .applied_index
                .checked_add(1)
                .ok_or(MetadataReplicaError::InvalidPage)?
        {
            return Err(MetadataReplicaError::StaleCursor);
        }
        let mutation = DurableMutation {
            vote_state: (entry.position.term > self.durable.current_term)
                .then_some((entry.position.term, None)),
            truncate_from: self
                .entry(entry.position.index)
                .map(|_| entry.position.index),
            append: vec![entry.clone()],
            membership_epoch: None,
            quorum_plan: None,
        };
        self.repository
            .persist_consensus_mutation(self.plan.membership_epoch(), &mutation, now)?;
        let retained = usize::try_from(self.durable.applied_index)
            .map_err(|_| MetadataReplicaError::InvalidPage)?;
        self.durable.log.truncate(retained);
        self.durable.log.push(entry.clone());
        if let Some((term, vote)) = mutation.vote_state {
            self.durable.current_term = term;
            self.durable.voted_for = vote;
        }
        if is_supported_metadata_command_version(entry.command_version) {
            let decoded =
                decode_authoritative_entry_for_version(entry.command_version, &entry.command)
                    .map_err(|_| MetadataReplicaError::InvalidPage)?;
            self.repository.apply_committed_entry(
                meshspan_metadata::LogPosition {
                    term: entry.position.term,
                    index: entry.position.index,
                },
                decoded.context,
                &decoded.command,
            )?;
        } else if entry.is_term_confirmation() {
            self.repository.apply_term_confirmation(entry)?;
        } else {
            self.apply_membership(entry, now)?;
        }
        self.durable.applied_index = entry.position.index;
        Ok(())
    }

    fn apply_membership(
        &mut self,
        entry: &LogEntry,
        now: UnixMicros,
    ) -> Result<(), MetadataReplicaError> {
        let command = MembershipTransitionCommand::decode(&entry.command)
            .map_err(|_| MetadataReplicaError::InvalidPage)?;
        let members = restore_member_incarnations(&self.repository, &self.plan)
            .map_err(|_| MetadataReplicaError::Source)?;
        let membership = self
            .repository
            .partition_membership()?
            .ok_or(MetadataReplicaError::Source)?;
        let evidence = match &command {
            MembershipTransitionCommand::PromoteLearner { evidence, .. } => {
                self.entry(evidence.committed_position.index)
            }
            MembershipTransitionCommand::AdmitLearner { .. }
            | MembershipTransitionCommand::RemoveMember { .. }
            | MembershipTransitionCommand::FinaliseStable { .. } => None,
        };
        crate::membership::validate_transition(
            &self.plan,
            &members,
            membership.active_voters(),
            membership.admitted_learners(),
            membership.retiring_members(),
            &command,
            evidence,
        )
        .map_err(|_| MetadataReplicaError::InvalidPage)?;
        let next = match command {
            MembershipTransitionCommand::AdmitLearner { joint_plan, .. }
            | MembershipTransitionCommand::PromoteLearner { joint_plan, .. }
            | MembershipTransitionCommand::RemoveMember { joint_plan, .. } => {
                ActiveQuorumPlan::Joint(joint_plan)
            }
            MembershipTransitionCommand::FinaliseStable { plan } => ActiveQuorumPlan::Stable(plan),
        };
        self.repository.persist_consensus_mutation(
            self.plan.membership_epoch(),
            &DurableMutation {
                vote_state: None,
                truncate_from: None,
                append: vec![],
                membership_epoch: Some(next.membership_epoch()),
                quorum_plan: Some(DurableQuorumPlan {
                    active_plan: next.clone(),
                    activated_position: entry.position,
                }),
            },
            now,
        )?;
        self.plan = next;
        Ok(())
    }
}

fn verify_frontier(
    cursor: MetadataReplicaCursor,
    entry: Option<&LogEntry>,
) -> Result<(), MetadataReplicaError> {
    let matches = if cursor.applied == LogPosition::GENESIS {
        cursor.applied_digest == [0; 32]
    } else {
        entry.is_some_and(|entry| {
            entry.position == cursor.applied && entry.entry_digest() == cursor.applied_digest
        })
    };
    if matches {
        Ok(())
    } else {
        Err(MetadataReplicaError::StaleCursor)
    }
}

fn validate_page(page: &MetadataReplicaPage) -> Result<(), MetadataReplicaError> {
    if page.entries.len() > MAXIMUM_METADATA_REPLICA_ENTRIES || page.after.membership_epoch == 0 {
        return Err(MetadataReplicaError::InvalidPage);
    }
    let mut position = page.after.applied;
    let mut bytes = 0_usize;
    for (offset, entry) in page.entries.iter().enumerate() {
        entry
            .validate()
            .map_err(|_| MetadataReplicaError::InvalidPage)?;
        bytes = bytes
            .checked_add(entry.command.len())
            .ok_or(MetadataReplicaError::InvalidPage)?;
        if bytes > MAXIMUM_METADATA_REPLICA_BYTES
            || entry.position.term < position.term
            || position.index.checked_add(1) != Some(entry.position.index)
        {
            return Err(MetadataReplicaError::InvalidPage);
        }
        match entry.command_version {
            version if is_supported_metadata_command_version(version) => {
                let decoded =
                    decode_authoritative_entry_for_version(entry.command_version, &entry.command)
                        .map_err(|_| MetadataReplicaError::InvalidPage)?;
                if decoded.context.operation_id() != entry.operation_id {
                    return Err(MetadataReplicaError::InvalidPage);
                }
            }
            MEMBERSHIP_COMMAND_VERSION if offset + 1 == page.entries.len() => {
                MembershipTransitionCommand::decode(&entry.command)
                    .map_err(|_| MetadataReplicaError::InvalidPage)?;
            }
            _ if entry.is_term_confirmation() => {}
            _ => return Err(MetadataReplicaError::InvalidPage),
        }
        position = entry.position;
    }
    Ok(())
}

/// Closed non-secret history replication failures.
#[derive(Debug, Error)]
pub enum MetadataReplicaError {
    /// The bounded metadata owner queue is full, stopped or did not respond by its deadline.
    #[error("metadata replica source is unavailable")]
    Unavailable,
    /// The local node belongs in the ordinary consensus runtime, not a passive consumer.
    #[error("metadata replica requires a non-member runtime")]
    LocalMember,
    /// The authenticated supplier is not a current-incarnation voter in the replica's phase.
    #[error("metadata replica source is not authorised")]
    Source,
    /// Cursor cannot extend the installed exact history/phase.
    #[error("metadata replica cursor requires refresh")]
    StaleCursor,
    /// Page bounds, command bytes or transition semantics are invalid.
    #[error("metadata replica page is invalid")]
    InvalidPage,
    /// An interrupted durable operation requires reopening the owning database.
    #[error("metadata replica must reopen after application failure")]
    ReloadRequired,
    /// Durable consensus adapter refused a mutation or stored state.
    #[error("metadata replica persistence failed")]
    Persistence(#[from] ConsensusStoreError),
    /// Typed metadata application rejected a command or database operation.
    #[error("metadata replica command application failed")]
    Repository(#[from] RepositoryError),
}
