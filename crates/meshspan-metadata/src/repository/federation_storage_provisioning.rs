// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, read-only planning of storage quota; consensus remains the sole allocation writer.

use super::{AuthoritativeRepository, FederationGrantRecord, Page, PageLimit, RepositoryError};
use crate::{IssueFederationStorageAllocation, StorageTargetProviderContext};
use meshspan_domain::{
    FederationGrantId, FederationPolicy, FederationStorageAllocation,
    FederationStorageAllocationId, Revision, UnixMicros, uuid_v8,
};
use rusqlite::params;

const MAXIMUM_ALLOCATIONS: usize = 4096;

pub(super) const GRANTS_SQL: &str = "SELECT grant_id FROM federation_grants
     WHERE authority_mesh_id = ?1 AND resource_kind = 4 AND volume_id IS NULL
       AND object_id IS NULL AND state = 1 AND grant_id > ?2
     ORDER BY grant_id LIMIT ?3";

/// One allocation proposal fenced against all metadata read while planning it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageAllocationProposal {
    /// Existing typed allocation command; planning never commits it implicitly.
    pub command: IssueFederationStorageAllocation,
    /// Required command-context revision, protecting target/grant races at application.
    pub expected_revision: Revision,
}

struct AllocationBudget {
    available_bytes: u64,
    target_sequence: u64,
}

impl AuthoritativeRepository {
    /// Visits approved, locally owned storage grants in bounded ID order.
    /// Empty filtered pages may still have a continuation. This is not capacity admission.
    ///
    /// # Errors
    /// Rejects corrupt authority, invalid page bounds and database failure.
    pub fn federation_storage_grants_for_provisioning(
        &self,
        after: Option<FederationGrantId>,
        limit: PageLimit,
        now: UnixMicros,
    ) -> Result<Page<FederationGrantRecord, FederationGrantId>, RepositoryError> {
        let Some(mesh) = self.local_mesh_id()? else {
            return Ok(Page {
                items: Vec::new(),
                next: None,
            });
        };
        let mut statement = self.database.connection().prepare(GRANTS_SQL)?;
        let ids = statement
            .query_map(
                params![
                    mesh.as_bytes().as_slice(),
                    after
                        .map_or([0; 16], FederationGrantId::as_bytes)
                        .as_slice(),
                    super::query::sql_limit(limit)?
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let has_next = ids.len() > limit.get();
        let mut last = None;
        let mut items = Vec::new();
        for bytes in ids.into_iter().take(limit.get()) {
            let id = FederationGrantId::from_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| RepositoryError::CorruptState)?,
            )
            .map_err(|_| RepositoryError::CorruptState)?;
            last = Some(id);
            if let Some(record) = self.active_federation_grant(id)?
                && record.grant.issuer_mesh_id() == mesh
                && record.grant.valid_from() <= now
                && record.grant.valid_until().is_none_or(|until| now < until)
            {
                items.push(record);
            }
        }
        Ok(Page {
            items,
            next: if has_next { last } else { None },
        })
    }

    /// Plans at most one quota slice for an eligible, freshly observed provider target.
    /// Existing allocations (including revoked/expired ones) retain their budget unless
    /// signed seals release unused allowance. A target with an unsealed allocation is not
    /// allocated again; sealed history produces a distinct, restart-stable successor ID.
    /// `maximum_bytes` is advisory free capacity, not a reservation or durability promise.
    ///
    /// # Errors
    /// Rejects corrupt accounting, stale target policy and concurrent metadata changes.
    pub fn federation_storage_allocation_proposal(
        &self,
        grant_id: FederationGrantId,
        target: StorageTargetProviderContext,
        maximum_bytes: u64,
        now: UnixMicros,
    ) -> Result<Option<FederationStorageAllocationProposal>, RepositoryError> {
        let revision = self.current_revision()?;
        let Some(current) =
            self.storage_target_provider_context(target.node_id, target.target_id)?
        else {
            return Ok(None);
        };
        if current.generation != target.generation
            || current.policy_revision != target.policy_revision
            || current.usage_limit != target.usage_limit
            || current.mesh_id != target.mesh_id
        {
            return Err(RepositoryError::StaleRevision);
        }
        let Some(record) = self.active_federation_grant(grant_id)? else {
            return Ok(None);
        };
        let grant = &record.grant;
        let FederationPolicy::Storage(policy) = grant.policy() else {
            return Ok(None);
        };
        if grant.issuer_mesh_id() != target.mesh_id
            || now < grant.valid_from()
            || grant.valid_until().is_some_and(|until| now >= until)
        {
            return Ok(None);
        }
        let Some(budget) =
            self.unallocated_storage_quota(grant_id, target, policy.maximum_storage_bytes())?
        else {
            return Ok(None);
        };
        let bytes = maximum_bytes
            .min(budget.available_bytes)
            .min(i64::MAX.unsigned_abs());
        if bytes == 0 {
            return Ok(None);
        }
        let allocation = FederationStorageAllocation::new(
            allocation_id(grant_id, target, budget.target_sequence)?,
            grant_id,
            target.node_id,
            target.target_id,
            target.generation,
            bytes,
            grant.valid_from(),
            grant.valid_until().unwrap_or(UnixMicros::new(i64::MAX)),
        )
        .map_err(|_| RepositoryError::InvalidCommand)?;
        if self.current_revision()? != revision {
            return Err(RepositoryError::StaleRevision);
        }
        Ok(Some(FederationStorageAllocationProposal {
            command: IssueFederationStorageAllocation {
                allocation,
                expected_grant_revision: record.revision,
            },
            expected_revision: revision,
        }))
    }

    fn unallocated_storage_quota(
        &self,
        grant: FederationGrantId,
        target: StorageTargetProviderContext,
        ceiling: u64,
    ) -> Result<Option<AllocationBudget>, RepositoryError> {
        let mut statement = self.database.connection().prepare(
            "SELECT COALESCE(s.ceiling_bytes, a.maximum_bytes), a.target_id, a.target_generation,
             s.allocation_id IS NOT NULL
             FROM federation_storage_authority l JOIN federation_storage_allocations a USING(allocation_id)
             LEFT JOIN federation_storage_seals s USING(allocation_id)
             WHERE l.grant_id = ?1 ORDER BY l.allocation_id LIMIT ?2")?;
        let rows = statement.query_map(
            params![
                grant.as_bytes().as_slice(),
                i64::try_from(MAXIMUM_ALLOCATIONS + 1)
                    .map_err(|_| RepositoryError::CapacityExceeded)?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, bool>(3)?,
                ))
            },
        )?;
        let mut allocated = 0_u128;
        let mut count = 0;
        let mut unsealed_target = false;
        let mut target_sequence = 0;
        for row in rows {
            let (bytes, id, generation, sealed) = row?;
            let bytes = u64::try_from(bytes)
                .ok()
                .ok_or(RepositoryError::CorruptState)?;
            allocated += u128::from(bytes);
            count += 1;
            if id == target.target_id.as_bytes()
                && u64::try_from(generation).ok() == Some(target.generation)
            {
                target_sequence += 1;
                unsealed_target |= !sealed;
            }
        }
        if unsealed_target || count >= MAXIMUM_ALLOCATIONS {
            return Ok(None);
        }
        Ok(Some(AllocationBudget {
            available_bytes: u64::try_from(u128::from(ceiling).saturating_sub(allocated))
                .map_err(|_| RepositoryError::CorruptState)?,
            target_sequence,
        }))
    }
}

fn allocation_id(
    grant: FederationGrantId,
    target: StorageTargetProviderContext,
    target_sequence: u64,
) -> Result<FederationStorageAllocationId, RepositoryError> {
    let mut hash = blake3::Hasher::new();
    hash.update(if target_sequence == 0 {
        b"meshspan.federation.automatic-storage-allocation.v1"
    } else {
        b"meshspan.federation.automatic-storage-allocation.v2"
    });
    hash.update(&grant.as_bytes());
    hash.update(&target.target_id.as_bytes());
    hash.update(&target.generation.to_be_bytes());
    if target_sequence > 0 {
        hash.update(&target_sequence.to_be_bytes());
    }
    FederationStorageAllocationId::from_bytes(uuid_v8(
        hash.finalize().as_bytes()[..16]
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    ))
    .map_err(|_| RepositoryError::CorruptState)
}
