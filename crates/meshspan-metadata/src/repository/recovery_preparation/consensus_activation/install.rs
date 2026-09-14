// SPDX-License-Identifier: GPL-2.0-only

//! One transaction installs a replacement epoch while retaining its root-authorised origin.

use super::{Activation, Error};
use crate::repository::apply::to_i64;
use meshspan_consensus::ActiveQuorumPlan;
use rusqlite::{Transaction, params};

pub(super) fn apply(transaction: &Transaction<'_>, activation: &Activation) -> Result<(), Error> {
    let source = activation.permission.claims().authorization.claims();
    let revision = to_i64(activation.revision.get())?;
    let epoch = to_i64(activation.plan.quorum.membership_epoch())?;
    let partition = activation.plan.partition_id.as_bytes();
    transaction.execute(
        "DELETE FROM consensus_log WHERE log_index > ?1",
        [to_i64(source.source_log_index)?],
    )?;
    let changed = transaction.execute(
        "UPDATE consensus_vote SET current_term = ?1, voted_for_node_id = NULL,
        membership_epoch = ?2, persisted_at = ?3 WHERE singleton = 1 AND partition_id = ?4",
        params![
            to_i64(activation.initial_term)?,
            epoch,
            activation.activated_at.get(),
            partition.as_slice()
        ],
    )?;
    if changed != 1 {
        return Err(Error::CorruptState);
    }
    install_members(transaction, activation)?;
    let changed = transaction.execute("UPDATE consensus_active_quorum_plan SET phase_kind = 1, membership_epoch = ?1,
        record_version = 1, canonical_plan = ?2, proof_digest = ?3, activated_log_index = ?4,
        activated_log_term = ?5, updated_at = ?6, activation_kind = 2 WHERE singleton = 1 AND partition_id = ?7",
        params![epoch, activation.plan.quorum.encode().map_err(|_| Error::CorruptState)?, activation.plan.quorum.proof_digest().as_slice(),
            to_i64(source.source_log_index)?, to_i64(source.source_log_term)?, activation.activated_at.get(), partition.as_slice()])?;
    if changed != 1 {
        return Err(Error::CorruptState);
    }
    let changed = transaction.execute("UPDATE applied_state SET state_revision = ?1
        WHERE singleton = 1 AND partition_id = ?2 AND state_revision = ?3 AND last_log_index = ?4 AND last_log_term = ?5",
        params![revision, partition.as_slice(), to_i64(source.source_revision.get())?, to_i64(source.source_log_index)?, to_i64(source.source_log_term)?])?;
    if changed != 1 {
        return Err(Error::CorruptState);
    }
    transaction.execute("INSERT INTO partition_recovery_consensus_activation
        (singleton, preparation, permission, previous_plan, initial_term, applied_revision, activated_at)
        VALUES (1, 1, ?1, ?2, ?3, ?4, ?5)", params![activation.permission.encode().map_err(|_| Error::CorruptState)?,
            activation.previous_plan.encode().map_err(|_| Error::CorruptState)?, to_i64(activation.initial_term)?, revision, activation.activated_at.get()])?;
    Ok(())
}

fn install_members(transaction: &Transaction<'_>, activation: &Activation) -> Result<(), Error> {
    let ActiveQuorumPlan::Stable(plan) = &activation.plan.quorum else {
        return Err(Error::InvalidCommand);
    };
    let partition = activation.plan.partition_id.as_bytes();
    let epoch = to_i64(plan.spec().membership_epoch)?;
    let revision = to_i64(activation.revision.get())?;
    // This is the current membership projection, not its history. The previous plan is
    // retained in the immutable recovery activation; removed nodes are already retired.
    // Leaving them here as retiring would falsely require an ordinary joint transition.
    transaction.execute(
        "DELETE FROM partition_voters WHERE partition_id = ?1",
        [partition.as_slice()],
    )?;
    for (members, role, state) in [(&plan.spec().voters, 1, 1), (&plan.spec().learners, 2, 2)] {
        for node in members {
            transaction.execute("INSERT INTO partition_voters
                (partition_id, node_id, membership_revision, member_role, state, revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(partition_id, node_id) DO UPDATE SET membership_revision = excluded.membership_revision,
                member_role = excluded.member_role, state = excluded.state, revision = excluded.revision",
                params![partition.as_slice(), node.as_bytes().as_slice(), epoch, role, state, revision])?;
        }
    }
    let changed = transaction.execute(
        "UPDATE metadata_partitions SET current_membership_revision = ?1, revision = ?2
        WHERE partition_id = ?3 AND state = 1 AND current_membership_revision = ?4",
        params![
            epoch,
            revision,
            partition.as_slice(),
            to_i64(activation.previous_plan.membership_epoch())?
        ],
    )?;
    if changed != 1 {
        return Err(Error::CorruptState);
    }
    Ok(())
}
