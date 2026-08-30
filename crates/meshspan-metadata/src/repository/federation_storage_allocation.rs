// SPDX-License-Identifier: GPL-2.0-only

//! Replicated disjoint allocation of bilateral federation storage quota.

use meshspan_domain::{
    FederationGrantId, FederationPolicy, FederationResourceScope, FederationStorageAllocation,
    FederationStorageAllocationId, NodeId, Revision, TargetId, UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{
    EntityKind, EntityReference, FederationGrantState, RepositoryError, federation_grant_evidence,
};
use crate::{
    AuthoritativeCommand, CommandContext, IssueFederationStorageAllocation,
    RevokeFederationStorageAllocation,
};

const ACTIVE: i64 = 1;
const REVOKED: i64 = 2;
const MAXIMUM_ALLOCATIONS_PER_GRANT: usize = 4_096;
const MAXIMUM_REASON_BYTES: usize = 512;

/// Durable lifecycle of one immutable allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationStorageAllocationState {
    /// The allocation may be consumed while its grant and interval remain current.
    Active,
    /// New capability issuance is permanently fenced.
    Revoked,
}

/// Complete authoritative allocation and lifecycle evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationStorageAllocationRecord {
    /// Immutable disjoint quota slice.
    pub allocation: FederationStorageAllocation,
    /// Current lifecycle state.
    pub state: FederationStorageAllocationState,
    /// Authoritative issuance instant.
    pub issued_at: UnixMicros,
    /// Authoritative revocation instant, when revoked.
    pub revoked_at: Option<UnixMicros>,
    /// Bounded revocation explanation, when revoked.
    pub revocation_reason: Option<String>,
    /// Latest authoritative record revision.
    pub revision: Revision,
}

pub(super) fn is_command(command: &AuthoritativeCommand) -> bool {
    matches!(
        command,
        AuthoritativeCommand::IssueFederationStorageAllocation(_)
            | AuthoritativeCommand::RevokeFederationStorageAllocation(_)
    )
}

pub(super) fn execute(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    match command {
        AuthoritativeCommand::IssueFederationStorageAllocation(value) => {
            issue(transaction, context, *value, revision)
        }
        AuthoritativeCommand::RevokeFederationStorageAllocation(value) => {
            revoke(transaction, context, value, revision)
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

pub(super) fn load(
    connection: &Connection,
    allocation_id: FederationStorageAllocationId,
) -> Result<Option<FederationStorageAllocationRecord>, RepositoryError> {
    let row = connection
        .query_row(
            "SELECT grant_id, provider_node_id, target_id, target_generation,
                    maximum_bytes, valid_from, valid_until, state, issued_at,
                    revoked_at, revocation_reason, revision
             FROM federation_storage_allocations WHERE allocation_id = ?1",
            [allocation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            },
        )
        .optional()?;
    row.map(|row| decode_record(allocation_id, row)).transpose()
}

fn issue(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: IssueFederationStorageAllocation,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let allocation = command.allocation;
    let grant = federation_grant_evidence::load_verified(transaction, allocation.grant_id())?
        .ok_or(RepositoryError::InvalidCommand)?;
    let policy = validate_grant_and_target(transaction, allocation, command, &grant)?;
    prove_disjoint_capacity(transaction, allocation, policy.maximum_storage_bytes())?;
    transaction.execute(
        "INSERT INTO federation_storage_allocations(
            allocation_id, grant_id, provider_node_id, target_id, target_generation,
            maximum_bytes, valid_from, valid_until, state, issued_at, revoked_at,
            revocation_reason, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, NULL, NULL, ?10)",
        params![
            allocation.allocation_id().as_bytes().as_slice(),
            allocation.grant_id().as_bytes().as_slice(),
            allocation.provider_node_id().as_bytes().as_slice(),
            allocation.target_id().as_bytes().as_slice(),
            to_i64(allocation.target_generation())?,
            to_i64(allocation.maximum_bytes())?,
            allocation.valid_from().get(),
            allocation.valid_until().get(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(reference(allocation.allocation_id()))
}

fn validate_grant_and_target(
    transaction: &Transaction<'_>,
    allocation: FederationStorageAllocation,
    command: IssueFederationStorageAllocation,
    record: &super::FederationGrantRecord,
) -> Result<meshspan_domain::StorageFederationPolicy, RepositoryError> {
    let FederationPolicy::Storage(policy) = record.grant.policy() else {
        return Err(RepositoryError::InvalidCommand);
    };
    let FederationResourceScope::StorageCapacity { provider_mesh_id } = record.grant.resource()
    else {
        return Err(RepositoryError::InvalidCommand);
    };
    let local_mesh_id = local_mesh(transaction)?;
    let valid = record.state == FederationGrantState::Active
        && record.revision == command.expected_grant_revision
        && relationship_permits_storage(transaction, record.grant.relationship_id())?
        && provider_mesh_id == local_mesh_id
        && allocation.valid_from() >= record.grant.valid_from()
        && record
            .grant
            .valid_until()
            .is_none_or(|until| allocation.valid_until() <= until)
        && allocation.maximum_bytes() <= policy.maximum_storage_bytes()
        && provider_node_is_eligible(transaction, allocation.provider_node_id())?;
    if valid {
        Ok(policy)
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn relationship_permits_storage(
    transaction: &Transaction<'_>,
    relationship_id: meshspan_domain::FederationRelationshipId,
) -> Result<bool, RepositoryError> {
    transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM federation_relationships
                WHERE relationship_id = ?1 AND state IN (2, 3)
            )",
            [relationship_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .map(|exists| exists == 1)
        .map_err(Into::into)
}

fn prove_disjoint_capacity(
    transaction: &Transaction<'_>,
    allocation: FederationStorageAllocation,
    grant_limit: u64,
) -> Result<(), RepositoryError> {
    let mut statement = transaction.prepare(
        "SELECT maximum_bytes, valid_from, valid_until
         FROM federation_storage_allocations
         WHERE grant_id = ?1 AND state = 1
           AND valid_from < ?2 AND valid_until > ?3
         ORDER BY valid_from, valid_until, allocation_id
         LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            allocation.grant_id().as_bytes().as_slice(),
            allocation.valid_until().get(),
            allocation.valid_from().get(),
            i64::try_from(MAXIMUM_ALLOCATIONS_PER_GRANT + 1)
                .map_err(|_| RepositoryError::CapacityExceeded)?,
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;
    let mut intervals = Vec::new();
    for row in rows {
        let row = row?;
        intervals.push((
            positive(row.0)?,
            UnixMicros::new(row.1),
            UnixMicros::new(row.2),
        ));
    }
    if intervals.len() > MAXIMUM_ALLOCATIONS_PER_GRANT {
        return Err(RepositoryError::CapacityExceeded);
    }
    intervals.push((
        allocation.maximum_bytes(),
        allocation.valid_from(),
        allocation.valid_until(),
    ));
    if maximum_concurrent_bytes(&intervals)? <= u128::from(grant_limit) {
        Ok(())
    } else {
        Err(RepositoryError::CapacityExceeded)
    }
}

fn maximum_concurrent_bytes(
    intervals: &[(u64, UnixMicros, UnixMicros)],
) -> Result<u128, RepositoryError> {
    let mut events = Vec::with_capacity(intervals.len().saturating_mul(2));
    for (bytes, start, end) in intervals {
        if start.get() <= 0 || end <= start || *bytes == 0 {
            return Err(RepositoryError::CorruptState);
        }
        events.push((end.get(), false, *bytes));
        events.push((start.get(), true, *bytes));
    }
    events.sort_unstable_by_key(|event| (event.0, event.1));
    let mut current = 0_u128;
    let mut maximum = 0_u128;
    for (_, starts, bytes) in events {
        if starts {
            current = current
                .checked_add(u128::from(bytes))
                .ok_or(RepositoryError::CapacityExceeded)?;
            maximum = maximum.max(current);
        } else {
            current = current
                .checked_sub(u128::from(bytes))
                .ok_or(RepositoryError::CorruptState)?;
        }
    }
    Ok(maximum)
}

fn revoke(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RevokeFederationStorageAllocation,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.reason.is_empty() || command.reason.len() > MAXIMUM_REASON_BYTES {
        return Err(RepositoryError::InvalidCommand);
    }
    let changed = transaction.execute(
        "UPDATE federation_storage_allocations
         SET state = 2, revoked_at = ?1, revocation_reason = ?2, revision = ?3
         WHERE allocation_id = ?4 AND state = 1 AND revision = ?5",
        params![
            context.occurred_at.get(),
            command.reason,
            to_i64(revision.get())?,
            command.allocation_id.as_bytes().as_slice(),
            to_i64(command.expected_allocation_revision.get())?,
        ],
    )?;
    if changed == 1 {
        Ok(reference(command.allocation_id))
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn local_mesh(transaction: &Transaction<'_>) -> Result<meshspan_domain::MeshId, RepositoryError> {
    let bytes = transaction.query_row("SELECT mesh_id FROM meshes LIMIT 1", [], |row| {
        row.get::<_, Vec<u8>>(0)
    })?;
    meshspan_domain::MeshId::from_bytes(exact(bytes)?).map_err(|_| RepositoryError::CorruptState)
}

fn provider_node_is_eligible(
    transaction: &Transaction<'_>,
    node_id: NodeId,
) -> Result<bool, RepositoryError> {
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM nodes WHERE node_id = ?1 AND state IN (1, 2))",
            [node_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .map(|exists| exists == 1)
        .map_err(Into::into)
}

type StoredAllocationRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    Option<i64>,
    Option<String>,
    i64,
);

fn decode_record(
    allocation_id: FederationStorageAllocationId,
    row: StoredAllocationRow,
) -> Result<FederationStorageAllocationRecord, RepositoryError> {
    let allocation = FederationStorageAllocation::new(
        allocation_id,
        FederationGrantId::from_bytes(exact(row.0)?).map_err(|_| RepositoryError::CorruptState)?,
        NodeId::from_bytes(exact(row.1)?).map_err(|_| RepositoryError::CorruptState)?,
        TargetId::from_bytes(exact(row.2)?).map_err(|_| RepositoryError::CorruptState)?,
        positive(row.3)?,
        positive(row.4)?,
        UnixMicros::new(row.5),
        UnixMicros::new(row.6),
    )
    .map_err(|_| RepositoryError::CorruptState)?;
    let state = match row.7 {
        ACTIVE => FederationStorageAllocationState::Active,
        REVOKED => FederationStorageAllocationState::Revoked,
        _ => return Err(RepositoryError::CorruptState),
    };
    let valid_lifecycle = match state {
        FederationStorageAllocationState::Active => row.9.is_none() && row.10.is_none(),
        FederationStorageAllocationState::Revoked => row.9.is_some() && row.10.is_some(),
    };
    let valid_times = row.8 > 0 && row.9.is_none_or(|revoked_at| revoked_at >= row.8);
    if !valid_lifecycle || !valid_times || row.10.as_ref().is_some_and(String::is_empty) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(FederationStorageAllocationRecord {
        allocation,
        state,
        issued_at: UnixMicros::new(row.8),
        revoked_at: row.9.map(UnixMicros::new),
        revocation_reason: row.10,
        revision: Revision::new(positive(row.11)?),
    })
}

fn reference(allocation_id: FederationStorageAllocationId) -> EntityReference {
    EntityReference {
        kind: EntityKind::FederationStorageAllocation,
        id: allocation_id.as_bytes(),
    }
}

fn positive(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::CorruptState)
}

fn exact<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], RepositoryError> {
    bytes.try_into().map_err(|_| RepositoryError::CorruptState)
}
