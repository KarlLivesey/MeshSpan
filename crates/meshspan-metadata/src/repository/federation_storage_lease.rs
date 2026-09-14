// SPDX-License-Identifier: GPL-2.0-only

//! Renewable permission projection over immutable physical storage allocations.

use super::{RepositoryError, apply::to_i64};
use meshspan_domain::{
    FederationGrantId, FederationStorageAllocation, FederationStorageAllocationId, Revision,
    UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

pub(super) struct StorageLease {
    pub(super) grant_id: FederationGrantId,
    pub(super) valid_from: UnixMicros,
    pub(super) valid_until: UnixMicros,
    pub(super) write_limit_bytes: u64,
}

pub(super) fn load(
    connection: &Connection,
    allocation: FederationStorageAllocationId,
) -> Result<StorageLease, RepositoryError> {
    let row = connection
        .query_row(
            "SELECT l.grant_id, l.valid_from, l.valid_until,
        CASE WHEN s.allocation_id IS NULL THEN l.write_limit_bytes ELSE 0 END
        FROM federation_storage_authority l LEFT JOIN federation_storage_seals s USING(allocation_id)
        WHERE l.allocation_id = ?1",
            [allocation.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::CorruptState)?;
    if row.1 <= 0 || row.2 <= row.1 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(StorageLease {
        grant_id: FederationGrantId::from_bytes(
            row.0
                .try_into()
                .map_err(|_| RepositoryError::CorruptState)?,
        )
        .map_err(|_| RepositoryError::CorruptState)?,
        valid_from: UnixMicros::new(row.1),
        valid_until: UnixMicros::new(row.2),
        write_limit_bytes: u64::try_from(row.3).map_err(|_| RepositoryError::CorruptState)?,
    })
}

pub(super) fn issue(
    transaction: &Transaction<'_>,
    allocation: FederationStorageAllocation,
    revision: Revision,
) -> Result<(), RepositoryError> {
    transaction.execute("INSERT INTO federation_storage_authority
        (allocation_id,grant_id,valid_from,valid_until,write_limit_bytes,revision) VALUES(?1,?2,?3,?4,?5,?6)",
        params![allocation.allocation_id().as_bytes().as_slice(), allocation.grant_id().as_bytes().as_slice(),
            allocation.valid_from().get(), allocation.valid_until().get(), to_i64(allocation.maximum_bytes())?,
            to_i64(revision.get())?])?;
    Ok(())
}

pub(super) fn replace(
    transaction: &Transaction<'_>,
    command: &crate::ReplaceFederationGrant,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let meshspan_domain::FederationPolicy::Storage(policy) = command.grant.policy() else {
        return Ok(());
    };
    super::federation_storage_seal::verify_grant_seals(transaction, command.predecessor_grant_id)?;
    let predecessor_until: Option<i64> = transaction.query_row(
        "SELECT valid_until FROM federation_grants WHERE grant_id = ?1",
        [command.predecessor_grant_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    let mut query = transaction.prepare("SELECT l.allocation_id, l.valid_from, l.valid_until,
        COALESCE(s.ceiling_bytes, a.maximum_bytes), s.allocation_id IS NOT NULL
        FROM federation_storage_authority l JOIN federation_storage_allocations a USING(allocation_id)
        LEFT JOIN federation_storage_seals s USING(allocation_id)
        WHERE l.grant_id = ?1 ORDER BY l.allocation_id LIMIT 4097")?;
    let rows = query
        .query_map(
            [command.predecessor_grant_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, bool>(4)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > 4096 {
        return Err(RepositoryError::CapacityExceeded);
    }
    let mut remaining = policy.maximum_storage_bytes();
    // Sealed retained charges precede new-write allowances regardless of allocation ID order.
    for row in &rows {
        if row.4 {
            remaining = remaining
                .saturating_sub(u64::try_from(row.3).map_err(|_| RepositoryError::CorruptState)?);
        }
    }
    for (allocation, start, end, maximum, sealed) in rows {
        let maximum = u64::try_from(maximum).map_err(|_| RepositoryError::CorruptState)?;
        let write_limit = if sealed { 0 } else { maximum.min(remaining) };
        if !sealed {
            remaining = remaining.saturating_sub(maximum);
        }
        let until = command
            .grant
            .valid_until()
            .map_or(i64::MAX, UnixMicros::get);
        // Only a grant-bound expiry follows renewal. Independent allocation deadlines
        // stay fixed; admission separately intersects them with the current grant interval.
        let end = if Some(end) == predecessor_until {
            until
        } else {
            end
        };
        transaction.execute(
            "UPDATE federation_storage_authority SET grant_id=?1, valid_from=?2,
            valid_until=?3, write_limit_bytes=?4, revision=?5 WHERE allocation_id=?6",
            params![
                command.grant.grant_id().as_bytes().as_slice(),
                start,
                end,
                to_i64(write_limit)?,
                to_i64(revision.get())?,
                allocation
            ],
        )?;
    }
    Ok(())
}
