// SPDX-License-Identifier: GPL-2.0-only

//! Atomic SQLite persistence adapter for the deterministic consensus core.

use meshspan_consensus::{
    CoreError, DurableCoreState, DurableMutation, LogEntry, LogPosition, QuorumPlanRecordError,
};
use meshspan_domain::{NodeId, OperationId, UnixMicros};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;

use crate::PartitionDatabase;

const COMMAND_ENTRY_KIND: i64 = 1;
const MAXIMUM_RECOVERED_LOG_ENTRIES: usize = 1_000_000;
const MAXIMUM_RECOVERED_LOG_BYTES: u64 = 512 * 1_024 * 1_024;

/// Replaceable durable boundary consumed by a consensus driver.
pub trait PartitionConsensusPersistence {
    /// Loads exact durable vote, log and applied state for one membership epoch.
    ///
    /// # Errors
    ///
    /// Fails closed when persisted state violates any identity, bound or digest invariant.
    fn load_consensus_state(
        &self,
        membership_epoch: u64,
    ) -> Result<DurableCoreState, ConsensusStoreError>;

    /// Atomically applies one core persistence effect.
    ///
    /// # Errors
    ///
    /// Rejects malformed, stale, discontinuous or committed-tail mutations.
    fn persist_consensus_mutation(
        &mut self,
        membership_epoch: u64,
        mutation: &DurableMutation,
        persisted_at: UnixMicros,
    ) -> Result<(), ConsensusStoreError>;
}

impl PartitionConsensusPersistence for super::AuthoritativeRepository {
    fn load_consensus_state(
        &self,
        membership_epoch: u64,
    ) -> Result<DurableCoreState, ConsensusStoreError> {
        Self::load_consensus_state(self, membership_epoch)
    }

    fn persist_consensus_mutation(
        &mut self,
        membership_epoch: u64,
        mutation: &DurableMutation,
        persisted_at: UnixMicros,
    ) -> Result<(), ConsensusStoreError> {
        Self::persist_consensus_mutation(self, membership_epoch, mutation, persisted_at)
    }
}

/// Closed persistence-adapter failure categories.
#[derive(Debug, Error)]
pub enum ConsensusStoreError {
    /// SQLite rejected the transaction or read.
    #[error("consensus persistence database operation failed")]
    Sqlite(#[from] rusqlite::Error),
    /// A core log entry failed its independent semantic validation.
    #[error("consensus persistence entry is invalid")]
    Core(#[from] CoreError),
    /// Stored bytes or relational state violate the consensus durability contract.
    #[error("durable consensus state is corrupt")]
    CorruptState,
    /// The requested mutation is stale, discontinuous or otherwise invalid.
    #[error("durable consensus mutation is invalid")]
    InvalidMutation,
    /// The database is bound to another active membership epoch.
    #[error("durable consensus membership epoch does not match")]
    MembershipEpochMismatch,
    /// Recovery bounds require a verified snapshot before more log growth.
    #[error("durable consensus recovery bound is exhausted")]
    RecoveryBoundExceeded,
    /// Deterministic interruption used only by crash-boundary tests.
    #[error("injected consensus persistence interruption")]
    InjectedFault,
    /// No bootstrap quorum plan was installed before consensus admission.
    #[error("durable consensus quorum plan is missing")]
    MissingQuorumPlan,
    /// Active quorum plan state or transition contradicts durable consensus history.
    #[error("durable consensus quorum plan is invalid")]
    InvalidQuorumPlan,
    /// Canonical quorum plan bytes are malformed or cannot reproduce a safe proof.
    #[error("durable consensus quorum plan record is invalid")]
    QuorumPlanRecord(#[from] QuorumPlanRecordError),
}

pub(super) fn load_state(
    database: &PartitionDatabase,
    membership_epoch: u64,
) -> Result<DurableCoreState, ConsensusStoreError> {
    if membership_epoch == 0 {
        return Err(ConsensusStoreError::MembershipEpochMismatch);
    }
    let partition_id = database.partition_id().as_bytes();
    super::quorum_plan::verify_epoch(database.connection(), &partition_id, membership_epoch)?;
    load_state_from_connection(database.connection(), &partition_id, membership_epoch)
}

pub(super) fn persist_mutation(
    database: &mut PartitionDatabase,
    membership_epoch: u64,
    mutation: &DurableMutation,
    persisted_at: UnixMicros,
) -> Result<(), ConsensusStoreError> {
    persist_mutation_with_failpoint(
        database,
        membership_epoch,
        mutation,
        persisted_at,
        StoreFailpoint::None,
    )
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StoreFailpoint {
    None,
    BeforeCommit,
}

fn persist_mutation_with_failpoint(
    database: &mut PartitionDatabase,
    membership_epoch: u64,
    mutation: &DurableMutation,
    persisted_at: UnixMicros,
    failpoint: StoreFailpoint,
) -> Result<(), ConsensusStoreError> {
    if membership_epoch == 0
        || (mutation.vote_state.is_none()
            && mutation.truncate_from.is_none()
            && mutation.append.is_empty()
            && mutation.membership_epoch.is_none()
            && mutation.quorum_plan.is_none())
        || mutation.membership_epoch.is_some() != mutation.quorum_plan.is_some()
        || mutation.quorum_plan.as_ref().is_some_and(|plan| {
            plan.active_plan.membership_epoch() != mutation.membership_epoch.unwrap_or_default()
        })
    {
        return Err(ConsensusStoreError::InvalidMutation);
    }
    validate_mutation_entries(mutation)?;
    let partition_id = database.partition_id().as_bytes();
    let transaction = database
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    super::quorum_plan::verify_epoch(&transaction, &partition_id, membership_epoch)?;
    persist_vote(
        &transaction,
        &partition_id,
        membership_epoch,
        mutation,
        persisted_at,
    )?;
    persist_log(&transaction, mutation)?;
    if let Some(plan) = &mutation.quorum_plan {
        super::quorum_plan::persist(&transaction, &partition_id, plan, persisted_at)?;
    }
    if failpoint == StoreFailpoint::BeforeCommit {
        return Err(ConsensusStoreError::InjectedFault);
    }
    transaction.commit()?;
    Ok(())
}

fn load_state_from_connection(
    connection: &Connection,
    partition_id: &[u8; 16],
    membership_epoch: u64,
) -> Result<DurableCoreState, ConsensusStoreError> {
    let vote = connection
        .query_row(
            "SELECT partition_id, current_term, voted_for_node_id, membership_epoch
             FROM consensus_vote WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let (current_term, voted_for) = match vote {
        Some((stored_partition, term, voted_for, epoch)) => {
            if stored_partition.as_slice() != partition_id
                || positive_u64(epoch)? != membership_epoch
            {
                return Err(ConsensusStoreError::MembershipEpochMismatch);
            }
            let term = nonnegative_u64(term)?;
            let voted_for = voted_for.as_deref().map(node_id).transpose()?;
            if term == 0 && voted_for.is_some() {
                return Err(ConsensusStoreError::CorruptState);
            }
            (term, voted_for)
        }
        None => (0, None),
    };
    let log = load_log(connection)?;
    if current_term == 0 && !log.is_empty() {
        return Err(ConsensusStoreError::CorruptState);
    }
    let (applied_index, applied_term): (i64, i64) = connection.query_row(
        "SELECT last_log_index, last_log_term FROM applied_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let applied_index = nonnegative_u64(applied_index)?;
    let applied_term = nonnegative_u64(applied_term)?;
    if applied_index > 0
        && log
            .get(to_usize(applied_index - 1)?)
            .is_none_or(|entry| entry.position.term != applied_term)
    {
        return Err(ConsensusStoreError::CorruptState);
    }
    let state = DurableCoreState {
        current_term,
        voted_for,
        log,
        applied_index,
    };
    validate_recovered_state(&state)?;
    Ok(state)
}

fn load_log(connection: &Connection) -> Result<Vec<LogEntry>, ConsensusStoreError> {
    let maximum_rows = i64::try_from(MAXIMUM_RECOVERED_LOG_ENTRIES + 1)
        .map_err(|_| ConsensusStoreError::RecoveryBoundExceeded)?;
    let mut statement = connection.prepare(
        "SELECT log_index, term, entry_kind, entry_version, payload, payload_digest
         FROM consensus_log ORDER BY log_index LIMIT ?1",
    )?;
    let rows = statement.query_map([maximum_rows], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
        ))
    })?;
    let mut log = Vec::new();
    let mut total_bytes = 0_u64;
    for row in rows {
        if log.len() == MAXIMUM_RECOVERED_LOG_ENTRIES {
            return Err(ConsensusStoreError::RecoveryBoundExceeded);
        }
        let (index, term, kind, version, payload, stored_digest) = row?;
        total_bytes = total_bytes
            .checked_add(
                u64::try_from(payload.len())
                    .map_err(|_| ConsensusStoreError::RecoveryBoundExceeded)?,
            )
            .ok_or(ConsensusStoreError::RecoveryBoundExceeded)?;
        if total_bytes > MAXIMUM_RECOVERED_LOG_BYTES
            || kind != COMMAND_ENTRY_KIND
            || payload.len() < 16
        {
            return Err(ConsensusStoreError::CorruptState);
        }
        let operation_id = operation_id(&payload[..16])?;
        let entry = LogEntry::new(
            LogPosition {
                term: positive_u64(term)?,
                index: positive_u64(index)?,
            },
            operation_id,
            u16::try_from(version).map_err(|_| ConsensusStoreError::CorruptState)?,
            payload[16..].to_vec(),
        )?;
        if stored_digest.as_slice() != entry.entry_digest() {
            return Err(ConsensusStoreError::CorruptState);
        }
        log.push(entry);
    }
    Ok(log)
}

fn persist_vote(
    transaction: &Transaction<'_>,
    partition_id: &[u8; 16],
    membership_epoch: u64,
    mutation: &DurableMutation,
    persisted_at: UnixMicros,
) -> Result<(), ConsensusStoreError> {
    let target_epoch = mutation.membership_epoch.unwrap_or(membership_epoch);
    if target_epoch != membership_epoch && target_epoch != membership_epoch.saturating_add(1) {
        return Err(ConsensusStoreError::MembershipEpochMismatch);
    }
    let stored = transaction
        .query_row(
            "SELECT partition_id, current_term, voted_for_node_id, membership_epoch
             FROM consensus_vote WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    if let Some((stored_partition, stored_term, stored_vote, stored_epoch)) = &stored {
        if stored_partition.as_slice() != partition_id
            || positive_u64(*stored_epoch)? != membership_epoch
        {
            return Err(ConsensusStoreError::MembershipEpochMismatch);
        }
        if let Some((term, voted_for)) = mutation.vote_state {
            let current_term = nonnegative_u64(*stored_term)?;
            let current_vote = stored_vote.as_deref().map(node_id).transpose()?;
            if term < current_term || (term == current_term && voted_for != current_vote) {
                return Err(ConsensusStoreError::InvalidMutation);
            }
        }
    } else if mutation.vote_state.is_none() {
        return Err(ConsensusStoreError::InvalidMutation);
    }
    if let Some((term, voted_for)) = mutation.vote_state {
        if term == 0 {
            return Err(ConsensusStoreError::InvalidMutation);
        }
        transaction.execute(
            "INSERT INTO consensus_vote(
                singleton, partition_id, current_term, voted_for_node_id, membership_epoch,
                persisted_at
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(singleton) DO UPDATE SET
                current_term = excluded.current_term,
                voted_for_node_id = excluded.voted_for_node_id,
                membership_epoch = excluded.membership_epoch,
                persisted_at = excluded.persisted_at",
            params![
                partition_id.as_slice(),
                to_i64(term)?,
                voted_for.map(|node| node.as_bytes().to_vec()),
                to_i64(target_epoch)?,
                persisted_at.get(),
            ],
        )?;
    } else if mutation.membership_epoch.is_some() {
        let changed = transaction.execute(
            "UPDATE consensus_vote
             SET membership_epoch = ?1, persisted_at = ?2
             WHERE singleton = 1",
            params![to_i64(target_epoch)?, persisted_at.get()],
        )?;
        if changed != 1 {
            return Err(ConsensusStoreError::InvalidMutation);
        }
    }
    Ok(())
}

fn persist_log(
    transaction: &Transaction<'_>,
    mutation: &DurableMutation,
) -> Result<(), ConsensusStoreError> {
    let applied_index: i64 = transaction.query_row(
        "SELECT last_log_index FROM applied_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let applied_index = nonnegative_u64(applied_index)?;
    if let Some(truncate_from) = mutation.truncate_from {
        if truncate_from == 0 || truncate_from <= applied_index {
            return Err(ConsensusStoreError::InvalidMutation);
        }
        let last_index = read_last_log_index(transaction)?;
        if truncate_from > last_index.saturating_add(1) {
            return Err(ConsensusStoreError::InvalidMutation);
        }
        transaction.execute(
            "DELETE FROM consensus_log WHERE log_index >= ?1",
            [to_i64(truncate_from)?],
        )?;
    }
    let mut expected_index = read_last_log_index(transaction)?
        .checked_add(1)
        .ok_or(ConsensusStoreError::InvalidMutation)?;
    let mut previous_term = read_last_log_term(transaction)?;
    for entry in &mutation.append {
        if entry.position.index != expected_index || entry.position.term < previous_term {
            return Err(ConsensusStoreError::InvalidMutation);
        }
        let mut payload = Vec::with_capacity(16 + entry.command.len());
        payload.extend_from_slice(&entry.operation_id.as_bytes());
        payload.extend_from_slice(&entry.command);
        transaction.execute(
            "INSERT INTO consensus_log(
                log_index, term, entry_kind, entry_version, payload, payload_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                to_i64(entry.position.index)?,
                to_i64(entry.position.term)?,
                COMMAND_ENTRY_KIND,
                i64::from(entry.command_version),
                payload,
                entry.entry_digest().as_slice(),
            ],
        )?;
        expected_index = expected_index
            .checked_add(1)
            .ok_or(ConsensusStoreError::InvalidMutation)?;
        previous_term = entry.position.term;
    }
    let (entry_count, byte_count): (i64, i64) = transaction.query_row(
        "SELECT count(*), coalesce(sum(length(payload)), 0) FROM consensus_log",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if nonnegative_u64(entry_count)?
        > u64::try_from(MAXIMUM_RECOVERED_LOG_ENTRIES)
            .map_err(|_| ConsensusStoreError::RecoveryBoundExceeded)?
        || nonnegative_u64(byte_count)? > MAXIMUM_RECOVERED_LOG_BYTES
    {
        return Err(ConsensusStoreError::RecoveryBoundExceeded);
    }
    Ok(())
}

fn validate_mutation_entries(mutation: &DurableMutation) -> Result<(), ConsensusStoreError> {
    let mut previous: Option<&LogEntry> = None;
    for entry in &mutation.append {
        let rebuilt = LogEntry::new(
            entry.position,
            entry.operation_id,
            entry.command_version,
            entry.command.clone(),
        )?;
        if rebuilt != *entry
            || previous.is_some_and(|prior| {
                entry.position.index != prior.position.index.saturating_add(1)
                    || entry.position.term < prior.position.term
            })
        {
            return Err(ConsensusStoreError::InvalidMutation);
        }
        previous = Some(entry);
    }
    Ok(())
}

fn validate_recovered_state(state: &DurableCoreState) -> Result<(), ConsensusStoreError> {
    let mut expected = 1_u64;
    let mut previous_term = 0_u64;
    for entry in &state.log {
        if entry.position.index != expected
            || entry.position.term < previous_term
            || entry.position.term > state.current_term
        {
            return Err(ConsensusStoreError::CorruptState);
        }
        expected = expected
            .checked_add(1)
            .ok_or(ConsensusStoreError::CorruptState)?;
        previous_term = entry.position.term;
    }
    if state.applied_index >= expected {
        return Err(ConsensusStoreError::CorruptState);
    }
    Ok(())
}

fn read_last_log_index(transaction: &Transaction<'_>) -> Result<u64, ConsensusStoreError> {
    let value: i64 = transaction.query_row(
        "SELECT coalesce(max(log_index), 0) FROM consensus_log",
        [],
        |row| row.get(0),
    )?;
    nonnegative_u64(value)
}

fn read_last_log_term(transaction: &Transaction<'_>) -> Result<u64, ConsensusStoreError> {
    let value: Option<i64> = transaction
        .query_row(
            "SELECT term FROM consensus_log ORDER BY log_index DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    value.map_or(Ok(0), positive_u64)
}

fn operation_id(bytes: &[u8]) -> Result<OperationId, ConsensusStoreError> {
    let exact: [u8; 16] = bytes
        .try_into()
        .map_err(|_| ConsensusStoreError::CorruptState)?;
    OperationId::from_bytes(exact).map_err(|_| ConsensusStoreError::CorruptState)
}

fn node_id(bytes: &[u8]) -> Result<NodeId, ConsensusStoreError> {
    let exact: [u8; 16] = bytes
        .try_into()
        .map_err(|_| ConsensusStoreError::CorruptState)?;
    NodeId::from_bytes(exact).map_err(|_| ConsensusStoreError::CorruptState)
}

fn to_i64(value: u64) -> Result<i64, ConsensusStoreError> {
    i64::try_from(value).map_err(|_| ConsensusStoreError::InvalidMutation)
}

fn to_usize(value: u64) -> Result<usize, ConsensusStoreError> {
    usize::try_from(value).map_err(|_| ConsensusStoreError::CorruptState)
}

fn nonnegative_u64(value: i64) -> Result<u64, ConsensusStoreError> {
    u64::try_from(value).map_err(|_| ConsensusStoreError::CorruptState)
}

fn positive_u64(value: i64) -> Result<u64, ConsensusStoreError> {
    let value = nonnegative_u64(value)?;
    if value == 0 {
        Err(ConsensusStoreError::CorruptState)
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use meshspan_consensus::{
        ActiveQuorumPlan, DurableMutation, DurableQuorumPlan, JointQuorumPlan, LogEntry,
        LogPosition, compile_plan, flat_plan,
    };
    use meshspan_domain::{NodeId, OperationId, PartitionId, QuorumPlanId, UnixMicros};
    use rusqlite::params;
    use tempfile::tempdir;

    use super::{
        ConsensusStoreError, StoreFailpoint, load_state, persist_mutation,
        persist_mutation_with_failpoint,
    };
    use crate::PartitionDatabase;

    #[test]
    fn vote_and_log_mutation_survive_exact_restart() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("partition.sqlite3");
        let partition_id = PartitionId::from_bytes([1; 16])?;
        let voter = NodeId::from_bytes([2; 16])?;
        let entry = entry(1, 1, 3, b"command")?;
        let mutation = DurableMutation {
            vote_state: Some((1, Some(voter))),
            truncate_from: None,
            append: vec![entry.clone()],
            membership_epoch: None,
            quorum_plan: None,
        };
        let mut database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
        initialise_plan(&mut database, voter, 1)?;
        persist_mutation(&mut database, 1, &mutation, UnixMicros::new(2))?;
        assert_eq!(
            load_state(&database, 1)?,
            meshspan_consensus::DurableCoreState {
                current_term: 1,
                voted_for: Some(voter),
                log: vec![entry],
                applied_index: 0,
            }
        );
        drop(database);

        let reopened = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(3))?;
        assert_eq!(load_state(&reopened, 1)?.current_term, 1);
        Ok(())
    }

    #[test]
    fn interrupted_replacement_keeps_the_complete_old_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("partition.sqlite3");
        let partition_id = PartitionId::from_bytes([4; 16])?;
        let mut database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
        initialise_plan(&mut database, NodeId::from_bytes([44; 16])?, 1)?;
        persist_mutation(
            &mut database,
            1,
            &DurableMutation {
                vote_state: Some((1, None)),
                truncate_from: None,
                append: vec![entry(1, 1, 5, b"old")?],
                membership_epoch: None,
                quorum_plan: None,
            },
            UnixMicros::new(2),
        )?;
        let interrupted = persist_mutation_with_failpoint(
            &mut database,
            1,
            &DurableMutation {
                vote_state: Some((2, None)),
                truncate_from: Some(1),
                append: vec![entry(2, 1, 6, b"new")?],
                membership_epoch: None,
                quorum_plan: None,
            },
            UnixMicros::new(3),
            StoreFailpoint::BeforeCommit,
        );
        assert!(matches!(
            interrupted,
            Err(ConsensusStoreError::InjectedFault)
        ));
        let recovered = load_state(&database, 1)?;
        assert_eq!(recovered.current_term, 1);
        assert_eq!(recovered.log[0].command, b"old");
        Ok(())
    }

    #[test]
    fn stale_epoch_and_digest_corruption_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("partition.sqlite3");
        let partition_id = PartitionId::from_bytes([7; 16])?;
        let mut database = PartitionDatabase::open(&file_path, partition_id, UnixMicros::new(1))?;
        initialise_plan(&mut database, NodeId::from_bytes([77; 16])?, 1)?;
        persist_mutation(
            &mut database,
            1,
            &DurableMutation {
                vote_state: Some((1, None)),
                truncate_from: None,
                append: vec![entry(1, 1, 8, b"valid")?],
                membership_epoch: None,
                quorum_plan: None,
            },
            UnixMicros::new(2),
        )?;
        assert!(matches!(
            load_state(&database, 2),
            Err(ConsensusStoreError::MembershipEpochMismatch)
        ));
        database.connection_mut().execute(
            "UPDATE consensus_log SET payload_digest = zeroblob(32) WHERE log_index = 1",
            [],
        )?;
        assert!(matches!(
            load_state(&database, 1),
            Err(ConsensusStoreError::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn interrupted_joint_transition_retains_the_complete_stable_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = membership_fixture()?;
        assert!(matches!(
            persist_mutation_with_failpoint(
                &mut fixture.database,
                1,
                &fixture.joint_mutation,
                UnixMicros::new(4),
                StoreFailpoint::BeforeCommit,
            ),
            Err(ConsensusStoreError::InjectedFault)
        ));
        assert!(matches!(
            super::super::quorum_plan::load(&fixture.database)?,
            Some(ActiveQuorumPlan::Stable(_))
        ));
        let retained = load_state(&fixture.database, 1)?;
        assert_eq!(retained.current_term, 4);
        assert_eq!(retained.applied_index, 0);
        Ok(())
    }

    #[test]
    fn bootstrap_plan_refuses_existing_consensus_history() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let partition_id = PartitionId::from_bytes([16; 16])?;
        let voter = NodeId::from_bytes([17; 16])?;
        let mut database = PartitionDatabase::open(
            &directory.path().join("partition.sqlite3"),
            partition_id,
            UnixMicros::new(1),
        )?;
        database.connection_mut().execute(
            "INSERT INTO consensus_vote(
                singleton, partition_id, current_term, voted_for_node_id,
                membership_epoch, persisted_at
             ) VALUES (1, ?1, 1, ?2, 1, 2)",
            params![
                partition_id.as_bytes().as_slice(),
                voter.as_bytes().as_slice()
            ],
        )?;
        let plan = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([18; 16])?,
            1,
            BTreeSet::from([voter]),
            BTreeSet::new(),
        )?)?;
        assert!(matches!(
            super::super::quorum_plan::initialise(&mut database, &plan, UnixMicros::new(3)),
            Err(ConsensusStoreError::MissingQuorumPlan)
        ));
        Ok(())
    }

    #[test]
    fn joint_and_stable_plan_history_recovers_and_rejects_corruption()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = membership_fixture()?;
        persist_mutation(
            &mut fixture.database,
            1,
            &fixture.joint_mutation,
            UnixMicros::new(5),
        )?;
        assert!(matches!(
            super::super::quorum_plan::load(&fixture.database)?,
            Some(ActiveQuorumPlan::Joint(_))
        ));
        persist_mutation(
            &mut fixture.database,
            2,
            &DurableMutation {
                vote_state: None,
                truncate_from: None,
                append: vec![entry(4, 2, 15, b"leave-joint")?],
                membership_epoch: None,
                quorum_plan: None,
            },
            UnixMicros::new(6),
        )?;
        let stable_mutation = DurableMutation {
            vote_state: None,
            truncate_from: None,
            append: Vec::new(),
            membership_epoch: Some(2),
            quorum_plan: Some(DurableQuorumPlan {
                active_plan: ActiveQuorumPlan::Stable(Box::new(fixture.new_plan.clone())),
                activated_position: LogPosition { term: 4, index: 2 },
            }),
        };
        assert!(matches!(
            persist_mutation_with_failpoint(
                &mut fixture.database,
                2,
                &stable_mutation,
                UnixMicros::new(7),
                StoreFailpoint::BeforeCommit,
            ),
            Err(ConsensusStoreError::InjectedFault)
        ));
        assert!(matches!(
            super::super::quorum_plan::load(&fixture.database)?,
            Some(ActiveQuorumPlan::Joint(_))
        ));
        let joint_state = load_state(&fixture.database, 2)?;
        assert_eq!(joint_state.current_term, 4);
        assert_eq!(joint_state.applied_index, 1);
        persist_mutation(
            &mut fixture.database,
            2,
            &stable_mutation,
            UnixMicros::new(8),
        )?;

        let recovered = load_state(&fixture.database, 2)?;
        assert_eq!(recovered.current_term, 4);
        assert_eq!(recovered.voted_for, Some(fixture.voter));
        assert_eq!(recovered.applied_index, 2);
        assert!(matches!(
            super::super::quorum_plan::load(&fixture.database)?,
            Some(ActiveQuorumPlan::Stable(_))
        ));
        let history_rows: i64 = fixture.database.connection().query_row(
            "SELECT count(*) FROM consensus_quorum_plans",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(history_rows, 2);
        assert!(matches!(
            load_state(&fixture.database, 1),
            Err(ConsensusStoreError::MembershipEpochMismatch)
        ));
        fixture.database.connection_mut().execute(
            "UPDATE consensus_quorum_plans SET proof_digest = zeroblob(32) WHERE log_index = 2",
            [],
        )?;
        assert!(matches!(
            super::super::quorum_plan::load(&fixture.database),
            Err(ConsensusStoreError::InvalidQuorumPlan)
        ));
        fixture.database.connection_mut().execute(
            "UPDATE consensus_quorum_plans
             SET proof_digest = (
                SELECT proof_digest FROM consensus_active_quorum_plan WHERE singleton = 1
             ) WHERE log_index = 2",
            [],
        )?;
        fixture.database.connection_mut().execute(
            "UPDATE consensus_active_quorum_plan SET canonical_plan = x'00' WHERE singleton = 1",
            [],
        )?;
        assert!(matches!(
            super::super::quorum_plan::load(&fixture.database),
            Err(ConsensusStoreError::QuorumPlanRecord(_))
        ));
        Ok(())
    }

    struct MembershipFixture {
        _directory: tempfile::TempDir,
        database: PartitionDatabase,
        voter: NodeId,
        new_plan: meshspan_consensus::CompiledQuorumPlan,
        joint_mutation: DurableMutation,
    }

    fn membership_fixture() -> Result<MembershipFixture, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let partition_id = PartitionId::from_bytes([9; 16])?;
        let voter = NodeId::from_bytes([10; 16])?;
        let learner = NodeId::from_bytes([11; 16])?;
        let mut database = PartitionDatabase::open(
            &directory.path().join("partition.sqlite3"),
            partition_id,
            UnixMicros::new(1),
        )?;
        let old = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([12; 16])?,
            1,
            BTreeSet::from([voter]),
            BTreeSet::from([learner]),
        )?)?;
        super::super::quorum_plan::initialise(&mut database, &old, UnixMicros::new(2))?;
        persist_mutation(
            &mut database,
            1,
            &DurableMutation {
                vote_state: Some((4, Some(voter))),
                truncate_from: None,
                append: vec![entry(4, 1, 13, b"enter-joint")?],
                membership_epoch: None,
                quorum_plan: None,
            },
            UnixMicros::new(3),
        )?;
        let new_plan = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([14; 16])?,
            2,
            BTreeSet::from([voter, learner]),
            BTreeSet::new(),
        )?)?;
        let joint = JointQuorumPlan::new(old, new_plan.clone())?;
        Ok(MembershipFixture {
            _directory: directory,
            database,
            voter,
            new_plan,
            joint_mutation: DurableMutation {
                vote_state: None,
                truncate_from: None,
                append: Vec::new(),
                membership_epoch: Some(2),
                quorum_plan: Some(DurableQuorumPlan {
                    active_plan: ActiveQuorumPlan::Joint(Box::new(joint)),
                    activated_position: LogPosition { term: 4, index: 1 },
                }),
            },
        })
    }

    fn initialise_plan(
        database: &mut PartitionDatabase,
        voter: NodeId,
        epoch: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let plan = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([u8::try_from(epoch)?; 16])?,
            epoch,
            BTreeSet::from([voter]),
            BTreeSet::new(),
        )?)?;
        super::super::quorum_plan::initialise(database, &plan, UnixMicros::new(1))?;
        Ok(())
    }

    fn entry(
        term: u64,
        index: u64,
        operation_byte: u8,
        command: &[u8],
    ) -> Result<LogEntry, Box<dyn std::error::Error>> {
        Ok(LogEntry::new(
            LogPosition { term, index },
            OperationId::from_bytes([operation_byte; 16])?,
            1,
            command.to_vec(),
        )?)
    }
}
