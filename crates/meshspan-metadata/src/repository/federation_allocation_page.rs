// SPDX-License-Identifier: GPL-2.0-only

//! Indexed discovery of currently authorised allocations, without reserving capacity.

use super::{
    AuthoritativeRepository, FederationStorageAllocationAuthority,
    FederationStorageAuthorityRequest, Page, PageLimit, RepositoryError,
    federation_storage_allocation, federation_storage_lease,
};
use meshspan_domain::{
    FederationGrantId, FederationPolicy, FederationRelationshipId, FederationStorageAllocationId,
    MeshId, Revision, UnixMicros,
};
use rusqlite::params;

pub(super) const CANDIDATES_SQL: &str =
    "SELECT l.valid_from, l.valid_until, l.allocation_id FROM federation_storage_authority l
     JOIN federation_storage_allocations a USING(allocation_id)
     WHERE l.grant_id = ?1 AND a.state = 1 AND l.valid_from <= ?2 AND l.valid_until > ?2
       AND a.maximum_bytes >= ?3 AND (l.valid_from, l.valid_until, l.allocation_id) > (?4, ?5, ?6)
     ORDER BY l.valid_from, l.valid_until, l.allocation_id LIMIT ?7";

/// Ordering key matching the current grant/interval/allocation authority index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationAllocationCursor {
    /// Allocation interval start, not request observation time.
    pub valid_from: UnixMicros,
    /// Allocation interval end.
    pub valid_until: UnixMicros,
    /// Stable allocation identity breaking interval ties.
    pub allocation_id: FederationStorageAllocationId,
}

/// One authenticated peer's bounded query within an exact committed revision.
#[derive(Clone, Copy, Debug)]
pub struct FederationAllocationQuery {
    /// Locally approved relationship.
    pub relationship_id: FederationRelationshipId,
    /// Certificate-authenticated consumer swarm.
    pub remote_mesh_id: MeshId,
    /// Storage grant obtained through signed authority discovery.
    pub grant_id: FederationGrantId,
    /// Required size of one complete object; this is not a reservation.
    pub required_bytes: u64,
    /// Current mesh time used to exclude expired authority.
    pub observed_at: UnixMicros,
    /// Exact current revision; a changed revision invalidates continuation.
    pub snapshot_revision: Revision,
    /// Last candidate visited, including candidates whose node became ineligible.
    pub after: Option<FederationAllocationCursor>,
    /// Maximum candidates examined, independent of total grant size.
    pub limit: PageLimit,
}

impl AuthoritativeRepository {
    /// Discovers currently usable quota allocations under one peer-owned storage grant.
    /// Each result passes the same current authority checks as capability admission.
    /// Neither quota ceilings nor discovery prove free space or successful provider IO.
    ///
    /// # Errors
    /// Rejects stale revisions, wrong peer/grant, malformed cursors and corrupt records.
    pub fn federation_storage_allocations_page(
        &self,
        query: FederationAllocationQuery,
    ) -> Result<
        Page<FederationStorageAllocationAuthority, FederationAllocationCursor>,
        RepositoryError,
    > {
        self.validate_allocation_query(query)?;
        let candidates = self.allocation_candidates(query)?;
        let has_next = candidates.len() > query.limit.get();
        let mut items = Vec::new();
        let mut last = None;
        for cursor in candidates.into_iter().take(query.limit.get()) {
            let record = self
                .federation_storage_allocation(cursor.allocation_id)?
                .ok_or(RepositoryError::CorruptState)?;
            let allocation = record.allocation;
            let lease = federation_storage_lease::load(
                self.database.connection(),
                allocation.allocation_id(),
            )?;
            if lease.valid_from != cursor.valid_from || lease.valid_until != cursor.valid_until {
                return Err(RepositoryError::CorruptState);
            }
            if let Some(authority) = federation_storage_allocation::active_authority(
                &self.database,
                FederationStorageAuthorityRequest {
                    relationship_id: query.relationship_id,
                    remote_mesh_id: query.remote_mesh_id,
                    provider_node_id: allocation.provider_node_id(),
                    allocation_id: allocation.allocation_id(),
                    grant_id: query.grant_id,
                    target_id: allocation.target_id(),
                    target_generation: allocation.target_generation(),
                    requested_bytes: query.required_bytes,
                    observed_at: query.observed_at,
                },
            )? {
                items.push(authority);
            }
            last = Some(cursor);
        }
        // Monotonically increasing revisions detect concurrent commits without holding a
        // read transaction beyond this bounded synchronous operation.
        if self.current_revision()? != query.snapshot_revision {
            return Err(RepositoryError::StaleRevision);
        }
        Ok(Page {
            items,
            next: if has_next { last } else { None },
        })
    }

    fn validate_allocation_query(
        &self,
        query: FederationAllocationQuery,
    ) -> Result<(), RepositoryError> {
        if self.current_revision()? != query.snapshot_revision {
            return Err(RepositoryError::StaleRevision);
        }
        if query.required_bytes == 0
            || query.required_bytes > i64::MAX.unsigned_abs()
            || query.after.is_some_and(|cursor| {
                cursor.valid_from.get() <= 0 || cursor.valid_until <= cursor.valid_from
            })
        {
            return Err(RepositoryError::InvalidCommand);
        }
        let grant = self
            .active_federation_grant(query.grant_id)?
            .ok_or(RepositoryError::InvalidCommand)?;
        if grant.grant.relationship_id() != query.relationship_id
            || grant.grant.recipient_mesh_id() != query.remote_mesh_id
            || !matches!(grant.grant.policy(), FederationPolicy::Storage(_))
            || query.observed_at < grant.grant.valid_from()
            || grant
                .grant
                .valid_until()
                .is_some_and(|until| query.observed_at >= until)
        {
            return Err(RepositoryError::InvalidCommand);
        }
        Ok(())
    }

    fn allocation_candidates(
        &self,
        query: FederationAllocationQuery,
    ) -> Result<Vec<FederationAllocationCursor>, RepositoryError> {
        let (start, end, id) = query.after.map_or((0, 0, [0; 16]), |cursor| {
            (
                cursor.valid_from.get(),
                cursor.valid_until.get(),
                cursor.allocation_id.as_bytes(),
            )
        });
        let mut statement = self.database.connection().prepare(CANDIDATES_SQL)?;
        let rows = statement.query_map(
            params![
                query.grant_id.as_bytes().as_slice(),
                query.observed_at.get(),
                i64::try_from(query.required_bytes).map_err(|_| RepositoryError::InvalidCommand)?,
                start,
                end,
                id.as_slice(),
                super::query::sql_limit(query.limit)?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (start, end, id) = row?;
            Ok(FederationAllocationCursor {
                valid_from: UnixMicros::new(start),
                valid_until: UnixMicros::new(end),
                allocation_id: FederationStorageAllocationId::from_bytes(
                    id.as_slice()
                        .try_into()
                        .map_err(|_| RepositoryError::CorruptState)?,
                )
                .map_err(|_| RepositoryError::CorruptState)?,
            })
        })
        .collect()
    }
}
