// SPDX-License-Identifier: GPL-2.0-only

//! Revision-bound authoritative roots for guarded namespace reachability scans.

use meshspan_domain::{NamespaceCommitId, ObjectRevisionId, Revision, SnapshotId, VolumeId};
use rusqlite::params;

use super::{PageLimit, RepositoryError};
use crate::PartitionDatabase;

/// Authority record that explains why one immutable namespace root remains retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedNamespaceRootSource {
    /// The latest globally converged volume head.
    ConvergedHead(VolumeId),
    /// One active or expiring user snapshot.
    Snapshot(SnapshotId),
}

/// One immutable namespace root retained at an exact metadata revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedNamespaceRoot {
    /// Record that retains this root.
    pub source: RetainedNamespaceRootSource,
    /// Immutable namespace commit selected by the retaining record.
    pub namespace_commit_id: NamespaceCommitId,
    /// Immutable directory root selected by the namespace commit.
    pub root_object_revision_id: ObjectRevisionId,
}

/// Stable seek cursor for revision-bound retained-root enumeration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedNamespaceRootCursor {
    source_kind: u8,
    source_id: [u8; 16],
}

/// One page from a complete root set that is valid only at `catalogue_revision`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedNamespaceRootPage {
    /// Exact authoritative revision shared by every page in this scan.
    pub catalogue_revision: Revision,
    /// Stable root records in source-kind and source-identity order.
    pub roots: Vec<RetainedNamespaceRoot>,
    /// Cursor for another page, absent only when the root set is complete.
    pub next: Option<RetainedNamespaceRootCursor>,
}

pub(super) fn retained_roots(
    database: &PartitionDatabase,
    volume_id: VolumeId,
    catalogue_revision: Revision,
    after: Option<RetainedNamespaceRootCursor>,
    limit: PageLimit,
) -> Result<RetainedNamespaceRootPage, RepositoryError> {
    if catalogue_revision == Revision::ZERO || current_revision(database)? != catalogue_revision {
        return Err(RepositoryError::StaleRevision);
    }
    let (after_kind, after_id) = after.map_or((0_u8, [0; 16]), |cursor| {
        (cursor.source_kind, cursor.source_id)
    });
    let row_limit = i64::try_from(
        limit
            .get()
            .checked_add(1)
            .ok_or(RepositoryError::InvalidPageLimit)?,
    )
    .map_err(|_| RepositoryError::InvalidPageLimit)?;
    let mut statement = database.connection().prepare(
        "WITH roots(source_kind, source_id, namespace_commit_id, root_object_revision_id) AS (
            SELECT 1, volume_id, namespace_commit_id, root_object_revision_id
            FROM volume_head_transitions h
            WHERE h.volume_id = ?1 AND h.head_sequence = (
                SELECT max(current.head_sequence) FROM volume_head_transitions current
                WHERE current.volume_id = ?1
            )
            UNION ALL
            SELECT 2, snapshot_id, namespace_commit_id, root_object_revision_id
            FROM volume_snapshots WHERE volume_id = ?1 AND state IN (1, 2)
         )
         SELECT source_kind, source_id, namespace_commit_id, root_object_revision_id
         FROM roots WHERE (source_kind, source_id) > (?2, ?3)
         ORDER BY source_kind, source_id LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            volume_id.as_bytes().as_slice(),
            i64::from(after_kind),
            after_id.as_slice(),
            row_limit,
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        },
    )?;
    let mut decoded = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        let row = row?;
        decoded.push(decode_root(volume_id, &row)?);
    }
    let next = if decoded.len() > limit.get() {
        let last = decoded
            .get(limit.get() - 1)
            .ok_or(RepositoryError::CorruptState)?;
        Some(cursor(*last))
    } else {
        None
    };
    decoded.truncate(limit.get());
    if after.is_none()
        && !decoded
            .iter()
            .any(|root| root.source == RetainedNamespaceRootSource::ConvergedHead(volume_id))
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(RetainedNamespaceRootPage {
        catalogue_revision,
        roots: decoded,
        next,
    })
}

fn current_revision(database: &PartitionDatabase) -> Result<Revision, RepositoryError> {
    let revision: i64 = database.connection().query_row(
        "SELECT state_revision FROM applied_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let revision = u64::try_from(revision).map_err(|_| RepositoryError::CorruptState)?;
    if revision == 0 {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(Revision::new(revision))
    }
}

fn decode_root(
    volume_id: VolumeId,
    stored: &(i64, Vec<u8>, Vec<u8>, Vec<u8>),
) -> Result<RetainedNamespaceRoot, RepositoryError> {
    let source_id = exact_array(&stored.1)?;
    let source = match stored.0 {
        1 => {
            let stored_volume =
                VolumeId::from_bytes(source_id).map_err(|_| RepositoryError::CorruptState)?;
            if stored_volume != volume_id {
                return Err(RepositoryError::CorruptState);
            }
            RetainedNamespaceRootSource::ConvergedHead(stored_volume)
        }
        2 => RetainedNamespaceRootSource::Snapshot(
            SnapshotId::from_bytes(source_id).map_err(|_| RepositoryError::CorruptState)?,
        ),
        _ => return Err(RepositoryError::CorruptState),
    };
    Ok(RetainedNamespaceRoot {
        source,
        namespace_commit_id: NamespaceCommitId::from_bytes(exact_array(&stored.2)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        root_object_revision_id: ObjectRevisionId::from_bytes(exact_array(&stored.3)?)
            .map_err(|_| RepositoryError::CorruptState)?,
    })
}

fn cursor(root: RetainedNamespaceRoot) -> RetainedNamespaceRootCursor {
    match root.source {
        RetainedNamespaceRootSource::ConvergedHead(volume_id) => RetainedNamespaceRootCursor {
            source_kind: 1,
            source_id: volume_id.as_bytes(),
        },
        RetainedNamespaceRootSource::Snapshot(snapshot_id) => RetainedNamespaceRootCursor {
            source_kind: 2,
            source_id: snapshot_id.as_bytes(),
        },
    }
}

fn exact_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], RepositoryError> {
    bytes.try_into().map_err(|_| RepositoryError::CorruptState)
}
