// SPDX-License-Identifier: GPL-2.0-only

//! SQL ownership of pending frontiers and frozen convergence applications.

use meshspan_domain::{NamespaceCommitId, OperationId, PrincipalId, UnixMicros, VolumeId};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::NamespaceConvergenceJob;
use crate::publication::{decode_identifier, from_i64, to_i64};
use crate::{NamespaceReconciliationApplication, PublicationError};

const FRONTIER_PAGE: usize = 63;
type StoredJob = (
    Option<Vec<u8>>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
);

pub(super) fn load(
    connection: &Connection,
    volume: VolumeId,
) -> Result<Option<NamespaceConvergenceJob>, PublicationError> {
    let stored: Option<StoredJob> = connection.query_row(
        "SELECT expected_commit_id, selected_commit_id, merge_required, operation_id,
                merge_commit_id, actor_principal_id, retain_history, retention_policy_sequence, created_at
         FROM namespace_convergence_jobs WHERE volume_id = ?1",
        [volume.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?)),
    ).optional()?;
    stored.map(|row| {
        let heads = select_heads(connection, "SELECT namespace_commit_id FROM namespace_convergence_job_heads WHERE volume_id = ?1 ORDER BY namespace_commit_id LIMIT 64", volume)?;
        if heads.is_empty() || heads.len() > FRONTIER_PAGE { return Err(PublicationError::Corrupt); }
        Ok(NamespaceConvergenceJob {
            volume_id: volume,
            expected: row.0.map(|bytes| decode_identifier(&bytes, NamespaceCommitId::from_bytes)).transpose()?,
            selected: decode_identifier(&row.1, NamespaceCommitId::from_bytes)?,
            merge_required: boolean(row.2)?,
            application: NamespaceReconciliationApplication {
                operation_id: decode_identifier(&row.3, OperationId::from_bytes)?,
                namespace_commit_id: decode_identifier(&row.4, NamespaceCommitId::from_bytes)?,
                created_by: decode_identifier(&row.5, PrincipalId::from_bytes)?,
                retain_superseded_history: boolean(row.6)?,
                retention_policy_sequence: from_i64(row.7)?,
                created_at: UnixMicros::new(row.8),
            },
            heads,
        })
    }).transpose()
}

pub(super) fn frontier(
    connection: &Connection,
    volume: VolumeId,
) -> Result<Vec<NamespaceCommitId>, PublicationError> {
    select_heads(
        connection,
        "SELECT namespace_commit_id FROM namespace_convergence_frontier WHERE volume_id = ?1 ORDER BY namespace_commit_id LIMIT 63",
        volume,
    )
}

pub(super) fn save(
    connection: &mut Connection,
    job: &NamespaceConvergenceJob,
) -> Result<(), PublicationError> {
    let application = job.application;
    if application.retention_policy_sequence == 0
        || job.heads.is_empty()
        || job.heads.len() > FRONTIER_PAGE
    {
        return Err(PublicationError::InvalidInput);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO namespace_convergence_jobs(volume_id, expected_commit_id, selected_commit_id,
             merge_required, operation_id, merge_commit_id, actor_principal_id, retain_history,
             retention_policy_sequence, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![job.volume_id.as_bytes().as_slice(), job.expected.map(NamespaceCommitId::as_bytes).as_ref().map(<[u8; 16]>::as_slice),
            job.selected.as_bytes().as_slice(), i64::from(job.merge_required), application.operation_id.as_bytes().as_slice(),
            application.namespace_commit_id.as_bytes().as_slice(), application.created_by.as_bytes().as_slice(),
            i64::from(application.retain_superseded_history), to_i64(application.retention_policy_sequence)?, application.created_at.get()],
    )?;
    for head in &job.heads {
        transaction.execute("INSERT INTO namespace_convergence_job_heads(volume_id, namespace_commit_id) VALUES (?1, ?2)",
            params![job.volume_id.as_bytes().as_slice(), head.as_bytes().as_slice()])?;
    }
    transaction.commit()?;
    Ok(())
}

pub(super) fn require_exact(
    connection: &Connection,
    job: &NamespaceConvergenceJob,
) -> Result<(), PublicationError> {
    if load(connection, job.volume_id)?.as_ref() == Some(job) {
        Ok(())
    } else {
        Err(PublicationError::OperationConflict)
    }
}

pub(super) fn prune(
    connection: &Connection,
    volume: VolumeId,
    included: NamespaceCommitId,
) -> Result<(), PublicationError> {
    connection.execute(
        "WITH RECURSIVE included(namespace_commit_id) AS (
             SELECT ?2 UNION SELECT p.parent_commit_id FROM namespace_commit_parents p
             JOIN included i ON p.namespace_commit_id = i.namespace_commit_id
         ) DELETE FROM namespace_convergence_frontier WHERE volume_id = ?1
           AND namespace_commit_id IN (SELECT namespace_commit_id FROM included)",
        params![volume.as_bytes().as_slice(), included.as_bytes().as_slice()],
    )?;
    Ok(())
}

fn select_heads(
    connection: &Connection,
    sql: &str,
    volume: VolumeId,
) -> Result<Vec<NamespaceCommitId>, PublicationError> {
    let mut statement = connection.prepare(sql)?;
    let rows = statement.query_map([volume.as_bytes().as_slice()], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;
    rows.map(|row| decode_identifier(&row?, NamespaceCommitId::from_bytes))
        .collect()
}

fn boolean(value: i64) -> Result<bool, PublicationError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(PublicationError::Corrupt),
    }
}
