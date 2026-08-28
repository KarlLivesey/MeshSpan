// SPDX-License-Identifier: GPL-2.0-only

//! Atomic active quorum-plan bootstrap, transition history and hostile-state recovery.

use meshspan_consensus::{ActiveQuorumPlan, CompiledQuorumPlan, DurableQuorumPlan, LogPosition};
use meshspan_domain::UnixMicros;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::consensus::ConsensusStoreError;
use crate::PartitionDatabase;

const RECORD_VERSION: i64 = 1;
const STABLE_PHASE: i64 = 1;
const JOINT_PHASE: i64 = 2;

pub(super) fn initialise(
    database: &mut PartitionDatabase,
    plan: &CompiledQuorumPlan,
    updated_at: UnixMicros,
) -> Result<ActiveQuorumPlan, ConsensusStoreError> {
    let active = ActiveQuorumPlan::Stable(Box::new(plan.clone()));
    let canonical = active.encode()?;
    let partition_id = database.partition_id().as_bytes();
    let transaction = database
        .connection_mut()
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    let already_initialised = load_from_connection(&transaction, &partition_id)?;
    if already_initialised.is_none() && has_consensus_history(&transaction)? {
        return Err(ConsensusStoreError::MissingQuorumPlan);
    }
    transaction.execute(
        "INSERT OR IGNORE INTO consensus_active_quorum_plan(
            singleton, partition_id, phase_kind, membership_epoch, record_version,
            canonical_plan, proof_digest, activated_log_index, activated_log_term, updated_at
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, 0, 0, ?7)",
        params![
            partition_id.as_slice(),
            STABLE_PHASE,
            to_i64(active.membership_epoch())?,
            RECORD_VERSION,
            canonical,
            active.proof_digest().as_slice(),
            updated_at.get(),
        ],
    )?;
    let stored = load_from_connection(&transaction, &partition_id)?
        .ok_or(ConsensusStoreError::MissingQuorumPlan)?;
    if stored != active {
        return Err(ConsensusStoreError::InvalidQuorumPlan);
    }
    transaction.commit()?;
    Ok(stored)
}

pub(super) fn load(
    database: &PartitionDatabase,
) -> Result<Option<ActiveQuorumPlan>, ConsensusStoreError> {
    let partition_id = database.partition_id().as_bytes();
    load_from_connection(database.connection(), &partition_id)
}

pub(super) fn persist(
    transaction: &Transaction<'_>,
    partition_id: &[u8; 16],
    durable: &DurableQuorumPlan,
    updated_at: UnixMicros,
) -> Result<(), ConsensusStoreError> {
    if durable.activated_position == LogPosition::GENESIS {
        return Err(ConsensusStoreError::InvalidQuorumPlan);
    }
    let current = load_from_connection(transaction, partition_id)?
        .ok_or(ConsensusStoreError::MissingQuorumPlan)?;
    if !valid_successor(&current, &durable.active_plan) {
        return Err(ConsensusStoreError::InvalidQuorumPlan);
    }
    verify_transition_entry(transaction, durable.activated_position)?;
    let canonical = durable.active_plan.encode()?;
    let phase = phase_kind(&durable.active_plan);
    let changed = transaction.execute(
        "UPDATE consensus_active_quorum_plan
         SET phase_kind = ?1, membership_epoch = ?2, record_version = ?3,
             canonical_plan = ?4, proof_digest = ?5, activated_log_index = ?6,
             activated_log_term = ?7, updated_at = ?8
         WHERE singleton = 1 AND partition_id = ?9",
        params![
            phase,
            to_i64(durable.active_plan.membership_epoch())?,
            RECORD_VERSION,
            canonical,
            durable.active_plan.proof_digest().as_slice(),
            to_i64(durable.activated_position.index)?,
            to_i64(durable.activated_position.term)?,
            updated_at.get(),
            partition_id.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(ConsensusStoreError::InvalidQuorumPlan);
    }
    transaction.execute(
        "INSERT INTO consensus_quorum_plans(
            log_index, membership_epoch, plan_version, canonical_plan, proof_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            to_i64(durable.activated_position.index)?,
            to_i64(durable.active_plan.membership_epoch())?,
            RECORD_VERSION,
            durable.active_plan.encode()?,
            durable.active_plan.proof_digest().as_slice(),
        ],
    )?;
    Ok(())
}

pub(super) fn verify_epoch(
    connection: &Connection,
    partition_id: &[u8; 16],
    membership_epoch: u64,
) -> Result<(), ConsensusStoreError> {
    let active = load_from_connection(connection, partition_id)?
        .ok_or(ConsensusStoreError::MissingQuorumPlan)?;
    if active.membership_epoch() == membership_epoch {
        Ok(())
    } else {
        Err(ConsensusStoreError::MembershipEpochMismatch)
    }
}

fn load_from_connection(
    connection: &Connection,
    partition_id: &[u8; 16],
) -> Result<Option<ActiveQuorumPlan>, ConsensusStoreError> {
    let row = connection
        .query_row(
            "SELECT partition_id, phase_kind, membership_epoch, record_version,
                    canonical_plan, proof_digest, activated_log_index, activated_log_term
             FROM consensus_active_quorum_plan WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((stored_partition, phase, epoch, version, canonical, digest, index, term)) = row
    else {
        return Ok(None);
    };
    let active = ActiveQuorumPlan::decode(&canonical)?;
    let position = valid_stored_header(&StoredHeader {
        expected_partition: partition_id,
        stored_partition: &stored_partition,
        phase,
        epoch,
        version,
        digest: &digest,
        index,
        term,
        active: &active,
    })?;
    if position != LogPosition::GENESIS {
        verify_transition_entry(connection, position)?;
        verify_transition_history(connection, position, &active)?;
    }
    Ok(Some(active))
}

struct StoredHeader<'a> {
    expected_partition: &'a [u8; 16],
    stored_partition: &'a [u8],
    phase: i64,
    epoch: i64,
    version: i64,
    digest: &'a [u8],
    index: i64,
    term: i64,
    active: &'a ActiveQuorumPlan,
}

fn valid_stored_header(header: &StoredHeader<'_>) -> Result<LogPosition, ConsensusStoreError> {
    let position = LogPosition {
        index: nonnegative_u64(header.index)?,
        term: nonnegative_u64(header.term)?,
    };
    if header.stored_partition != header.expected_partition
        || header.phase != phase_kind(header.active)
        || positive_u64(header.epoch)? != header.active.membership_epoch()
        || header.version != RECORD_VERSION
        || header.digest != header.active.proof_digest()
        || ((position.index == 0) != (position.term == 0))
    {
        Err(ConsensusStoreError::InvalidQuorumPlan)
    } else {
        Ok(position)
    }
}

fn verify_transition_entry(
    connection: &Connection,
    position: LogPosition,
) -> Result<(), ConsensusStoreError> {
    let found = connection
        .query_row(
            "SELECT 1 FROM consensus_log WHERE log_index = ?1 AND term = ?2 LIMIT 1",
            params![to_i64(position.index)?, to_i64(position.term)?],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if found {
        Ok(())
    } else {
        Err(ConsensusStoreError::InvalidQuorumPlan)
    }
}

fn verify_transition_history(
    connection: &Connection,
    position: LogPosition,
    active: &ActiveQuorumPlan,
) -> Result<(), ConsensusStoreError> {
    let row = connection
        .query_row(
            "SELECT membership_epoch, plan_version, canonical_plan, proof_digest
             FROM consensus_quorum_plans WHERE log_index = ?1",
            [to_i64(position.index)?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((epoch, version, canonical, digest)) = row else {
        return Err(ConsensusStoreError::InvalidQuorumPlan);
    };
    if positive_u64(epoch)? != active.membership_epoch()
        || version != RECORD_VERSION
        || canonical != active.encode()?
        || digest.as_slice() != active.proof_digest()
    {
        Err(ConsensusStoreError::InvalidQuorumPlan)
    } else {
        Ok(())
    }
}

fn has_consensus_history(connection: &Connection) -> Result<bool, ConsensusStoreError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM consensus_vote
             UNION ALL SELECT 1 FROM consensus_log
             LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(exists)
}

fn valid_successor(current: &ActiveQuorumPlan, next: &ActiveQuorumPlan) -> bool {
    match (current, next) {
        (ActiveQuorumPlan::Stable(old), ActiveQuorumPlan::Joint(joint)) => {
            old.as_ref() == joint.old_plan()
        }
        (ActiveQuorumPlan::Joint(joint), ActiveQuorumPlan::Stable(new)) => {
            joint.new_plan() == new.as_ref()
        }
        _ => false,
    }
}

const fn phase_kind(active: &ActiveQuorumPlan) -> i64 {
    match active {
        ActiveQuorumPlan::Stable(_) => STABLE_PHASE,
        ActiveQuorumPlan::Joint(_) => JOINT_PHASE,
    }
}

fn to_i64(value: u64) -> Result<i64, ConsensusStoreError> {
    i64::try_from(value).map_err(|_| ConsensusStoreError::InvalidQuorumPlan)
}

fn positive_u64(value: i64) -> Result<u64, ConsensusStoreError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ConsensusStoreError::InvalidQuorumPlan)
}

fn nonnegative_u64(value: i64) -> Result<u64, ConsensusStoreError> {
    u64::try_from(value).map_err(|_| ConsensusStoreError::InvalidQuorumPlan)
}
