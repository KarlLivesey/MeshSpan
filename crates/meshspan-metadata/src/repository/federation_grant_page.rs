// SPDX-License-Identifier: GPL-2.0-only

//! Index-aligned, stable-revision paging for complete bilateral federation grants.

use meshspan_domain::{FederationGrantId, FederationRelationshipId, Revision};
use rusqlite::params;

use super::federation_grant_cursor::FederationGrantCursor;
use super::federation_grant_evidence::{FederationGrantRecord, load_verified};
use super::query::{Page, PageLimit, sql_limit};
use super::{RepositoryError, apply, federation_query};
use crate::PartitionDatabase;

pub(super) fn grants_by_relationship(
    database: &PartitionDatabase,
    relationship_id: FederationRelationshipId,
    after_revision: Revision,
    snapshot_revision: Revision,
    after: Option<FederationGrantCursor>,
    limit: PageLimit,
) -> Result<Page<FederationGrantRecord, FederationGrantCursor>, RepositoryError> {
    validate_snapshot(
        database,
        relationship_id,
        after_revision,
        snapshot_revision,
        after,
    )?;
    let candidates = load_candidates(
        database,
        relationship_id,
        after_revision,
        snapshot_revision,
        after,
        limit,
    )?;
    verified_page(
        database,
        relationship_id,
        after_revision,
        snapshot_revision,
        limit,
        &candidates,
    )
}

fn load_candidates(
    database: &PartitionDatabase,
    relationship_id: FederationRelationshipId,
    after_revision: Revision,
    snapshot_revision: Revision,
    after: Option<FederationGrantCursor>,
    limit: PageLimit,
) -> Result<Vec<(Vec<u8>, i64)>, RepositoryError> {
    let (record_revision, grant_id) = after.map_or((after_revision, [0; 16]), |cursor| {
        (cursor.record_revision(), cursor.grant_id().as_bytes())
    });
    let mut statement = database.connection().prepare(
        "SELECT grant_id, revision FROM federation_grants
         WHERE relationship_id = ?1
           AND revision > ?2 AND revision <= ?3
           AND (revision > ?4 OR (revision = ?4 AND grant_id > ?5))
         ORDER BY revision, grant_id LIMIT ?6",
    )?;
    statement
        .query_map(
            params![
                relationship_id.as_bytes().as_slice(),
                to_i64(after_revision.get())?,
                to_i64(snapshot_revision.get())?,
                to_i64(record_revision.get())?,
                grant_id.as_slice(),
                sql_limit(limit)?,
            ],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )?
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn verified_page(
    database: &PartitionDatabase,
    relationship_id: FederationRelationshipId,
    after_revision: Revision,
    snapshot_revision: Revision,
    limit: PageLimit,
    candidates: &[(Vec<u8>, i64)],
) -> Result<Page<FederationGrantRecord, FederationGrantCursor>, RepositoryError> {
    let has_next = candidates.len() > limit.get();
    let mut items = Vec::with_capacity(candidates.len().min(limit.get()));
    for (grant_bytes, stored_revision) in candidates.iter().take(limit.get()) {
        let grant_id = parse_grant(grant_bytes)?;
        let revision = Revision::new(positive(*stored_revision)?);
        let record =
            load_verified(database.connection(), grant_id)?.ok_or(RepositoryError::CorruptState)?;
        if record.grant.relationship_id() != relationship_id || record.revision != revision {
            return Err(RepositoryError::CorruptState);
        }
        items.push(record);
    }
    let next = if has_next {
        Some(next_cursor(
            &items,
            relationship_id,
            after_revision,
            snapshot_revision,
        )?)
    } else {
        None
    };
    Ok(Page { items, next })
}

fn next_cursor(
    items: &[FederationGrantRecord],
    relationship_id: FederationRelationshipId,
    after_revision: Revision,
    snapshot_revision: Revision,
) -> Result<FederationGrantCursor, RepositoryError> {
    let last = items.last().ok_or(RepositoryError::CorruptState)?;
    FederationGrantCursor::new(
        relationship_id,
        after_revision,
        snapshot_revision,
        last.revision,
        last.grant.grant_id(),
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn validate_snapshot(
    database: &PartitionDatabase,
    relationship_id: FederationRelationshipId,
    after_revision: Revision,
    snapshot_revision: Revision,
    cursor: Option<FederationGrantCursor>,
) -> Result<(), RepositoryError> {
    if after_revision > snapshot_revision
        || apply::read_current_revision(database)? != snapshot_revision
        || federation_query::relationship(database, relationship_id)?.is_none()
    {
        return Err(RepositoryError::StaleRevision);
    }
    if let Some(cursor) = cursor
        && (cursor.relationship_id() != relationship_id
            || cursor.after_revision() != after_revision
            || cursor.snapshot_revision() != snapshot_revision)
    {
        return Err(RepositoryError::StaleRevision);
    }
    Ok(())
}

fn parse_grant(value: &[u8]) -> Result<FederationGrantId, RepositoryError> {
    FederationGrantId::from_bytes(
        value
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn positive(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::CorruptState)
}

fn to_i64(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}
