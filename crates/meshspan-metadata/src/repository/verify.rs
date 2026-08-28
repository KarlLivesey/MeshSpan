// SPDX-License-Identifier: GPL-2.0-only

//! Bounded relational checks for invariants SQLite cannot express declaratively.

use rusqlite::params;

use super::{PageLimit, RepositoryError};
use crate::PartitionDatabase;

/// Closed domain invariant failures returned by the repository verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvariantKind {
    /// A live namespace object has no active user/group owner.
    ObjectWithoutActiveOwner,
    /// A volume does not have exactly one root namespace object.
    InvalidVolumeRoot,
    /// A converged volume-head sequence has a gap or does not name its exact predecessor.
    InvalidVolumeHeadHistory,
    /// A completed operation lacks a complete exact result representation.
    IncompleteOperationResult,
    /// A direct group edge is absent from the materialised closure.
    MissingDirectGroupClosure,
    /// The authoritative partition has no active voter record.
    PartitionWithoutActiveVoter,
}

/// One bounded invariant failure and its exact persisted subject identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvariantFinding {
    /// Failed invariant.
    pub kind: InvariantKind,
    /// Exact offending record identity.
    pub subject_id: [u8; 16],
}

/// Complete-or-truncated invariant scan result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvariantReport {
    /// Bounded findings.
    pub findings: Vec<InvariantFinding>,
    /// True when at least one additional finding exists beyond the requested limit.
    pub truncated: bool,
}

pub(super) fn check_invariants(
    database: &PartitionDatabase,
    limit: PageLimit,
) -> Result<InvariantReport, RepositoryError> {
    database.check_integrity()?;
    let sql_limit = i64::try_from(
        limit
            .get()
            .checked_add(1)
            .ok_or(RepositoryError::InvalidPageLimit)?,
    )
    .map_err(|_| RepositoryError::InvalidPageLimit)?;
    let mut findings = Vec::with_capacity(limit.get().saturating_add(1));
    collect(
        database,
        "SELECT n.object_id
         FROM namespace_objects n
         WHERE n.state = 1 AND NOT EXISTS(
             SELECT 1 FROM object_owners oo
             JOIN principals p ON p.principal_id = oo.owner_principal_id
             WHERE oo.owner_set_id = n.owner_set_id AND p.state = 1
         )
         ORDER BY n.object_id LIMIT ?1",
        sql_limit,
        InvariantKind::ObjectWithoutActiveOwner,
        &mut findings,
        limit.get(),
    )?;
    collect(
        database,
        "SELECT v.volume_id FROM volumes v
         WHERE (SELECT COUNT(*) FROM namespace_objects n
                WHERE n.volume_id = v.volume_id AND n.parent_object_id IS NULL) <> 1
         ORDER BY v.volume_id LIMIT ?1",
        sql_limit,
        InvariantKind::InvalidVolumeRoot,
        &mut findings,
        limit.get(),
    )?;
    collect(
        database,
        "SELECT operation_id FROM operations
         WHERE completed_at IS NOT NULL AND (
             committed_log_index IS NULL OR result_kind IS NULL OR result_version IS NULL
             OR result_payload IS NULL OR result_digest IS NULL
         )
         ORDER BY operation_id LIMIT ?1",
        sql_limit,
        InvariantKind::IncompleteOperationResult,
        &mut findings,
        limit.get(),
    )?;
    collect_volume_head_findings(database, sql_limit, &mut findings, limit.get())?;
    collect(
        database,
        "SELECT gm.containing_group_id FROM group_memberships gm
         WHERE NOT EXISTS(
             SELECT 1 FROM group_closure gc
             WHERE gc.containing_group_id = gm.containing_group_id
               AND gc.member_principal_id = gm.member_principal_id
               AND gc.minimum_depth = 1 AND gc.path_count >= 1
         )
         ORDER BY gm.containing_group_id, gm.member_principal_id LIMIT ?1",
        sql_limit,
        InvariantKind::MissingDirectGroupClosure,
        &mut findings,
        limit.get(),
    )?;
    collect(
        database,
        "SELECT partition_id FROM metadata_partitions mp
         WHERE NOT EXISTS(
             SELECT 1 FROM partition_voters pv
             WHERE pv.partition_id = mp.partition_id AND pv.state = 1
         )
         ORDER BY partition_id LIMIT ?1",
        sql_limit,
        InvariantKind::PartitionWithoutActiveVoter,
        &mut findings,
        limit.get(),
    )?;
    let truncated = findings.len() > limit.get();
    findings.truncate(limit.get());
    Ok(InvariantReport {
        findings,
        truncated,
    })
}

fn collect_volume_head_findings(
    database: &PartitionDatabase,
    sql_limit: i64,
    findings: &mut Vec<InvariantFinding>,
    maximum: usize,
) -> Result<(), RepositoryError> {
    collect(
        database,
        "SELECT volume_id FROM (
             SELECT volume_id, head_sequence, previous_namespace_commit_id,
                    row_number() OVER (
                        PARTITION BY volume_id ORDER BY head_sequence
                    ) AS expected_sequence,
                    lag(namespace_commit_id) OVER (
                        PARTITION BY volume_id ORDER BY head_sequence
                    ) AS expected_previous
             FROM volume_head_transitions
         )
         WHERE head_sequence <> expected_sequence
            OR (head_sequence > 1 AND previous_namespace_commit_id <> expected_previous)
         ORDER BY volume_id LIMIT ?1",
        sql_limit,
        InvariantKind::InvalidVolumeHeadHistory,
        findings,
        maximum,
    )
}

fn collect(
    database: &PartitionDatabase,
    sql: &str,
    limit: i64,
    kind: InvariantKind,
    findings: &mut Vec<InvariantFinding>,
    maximum: usize,
) -> Result<(), RepositoryError> {
    if findings.len() > maximum {
        return Ok(());
    }
    let mut statement = database.connection().prepare(sql)?;
    let rows = statement.query_map(params![limit], |row| row.get::<_, Vec<u8>>(0))?;
    for row in rows {
        findings.push(InvariantFinding {
            kind,
            subject_id: row?
                .as_slice()
                .try_into()
                .map_err(|_| RepositoryError::CorruptState)?,
        });
        if findings.len() > maximum {
            break;
        }
    }
    Ok(())
}
