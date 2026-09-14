// SPDX-License-Identifier: GPL-2.0-only

//! Verify provider-owned fences before reducing replicated allocation accounting.

use super::{
    EntityKind, EntityReference, RepositoryError, apply::to_i64, federation_storage_allocation,
};
use crate::{FederationStorageCapacitySeal, RecordFederationStorageSeal};
use ed25519_dalek::{Signature, VerifyingKey};
use meshspan_domain::{
    FederationGrantId, FederationStorageAllocationId, MeshId, NodeId, Revision, TargetId,
    UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};

pub(super) const GRANT_SEALS_SQL: &str = "SELECT s.allocation_id,s.provider_node_id,s.node_incarnation,
    s.key_generation,s.ceiling_bytes,s.sequence,s.sealed_at,s.signature,
    a.target_id,a.target_generation,a.maximum_bytes,k.verifying_key,a.provider_node_id
    FROM federation_storage_authority l JOIN federation_storage_seals s USING(allocation_id)
    JOIN federation_storage_allocations a USING(allocation_id)
    LEFT JOIN cleanup_attestation_keys k ON k.node_id=s.provider_node_id AND k.generation=s.key_generation
    WHERE l.grant_id=?1 ORDER BY l.allocation_id LIMIT 4097";

pub(super) fn record(
    tx: &Transaction<'_>,
    value: &RecordFederationStorageSeal,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let seal = value.seal;
    let allocation = federation_storage_allocation::load(tx, seal.allocation_id)?
        .ok_or(RepositoryError::InvalidCommand)?
        .allocation;
    let mesh: Vec<u8> = tx.query_row("SELECT mesh_id FROM meshes LIMIT 1", [], |row| row.get(0))?;
    if mesh != value.provider_mesh_id.as_bytes()
        || allocation.provider_node_id() != seal.provider_node_id
        || allocation.target_id() != seal.target_id
        || allocation.target_generation() != seal.target_generation
        || seal.ceiling_bytes > allocation.maximum_bytes()
        || seal.sequence == 0
        || seal.sealed_at.get() <= 0
    {
        return Err(RepositoryError::InvalidCommand);
    }
    verify_provider(tx, value)?;
    let previous = tx.query_row("SELECT ceiling_bytes, sequence, signature FROM federation_storage_seals WHERE allocation_id=?1",
        [seal.allocation_id.as_bytes().as_slice()], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?)))
        .optional()?;
    if let Some((ceiling, sequence, signature)) = previous {
        if ceiling == to_i64(seal.ceiling_bytes)?
            && sequence == to_i64(seal.sequence)?
            && signature == value.signature
        {
            return Ok(reference(value));
        }
        if ceiling <= to_i64(seal.ceiling_bytes)? || sequence >= to_i64(seal.sequence)? {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    tx.execute("INSERT INTO federation_storage_seals
        (allocation_id,provider_node_id,node_incarnation,key_generation,ceiling_bytes,sequence,sealed_at,signature,revision)
        VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
        ON CONFLICT(allocation_id) DO UPDATE SET node_incarnation=excluded.node_incarnation,
        key_generation=excluded.key_generation,ceiling_bytes=excluded.ceiling_bytes,sequence=excluded.sequence,
        sealed_at=excluded.sealed_at,signature=excluded.signature,revision=excluded.revision",
        params![seal.allocation_id.as_bytes().as_slice(), seal.provider_node_id.as_bytes().as_slice(),
            to_i64(value.node_incarnation)?, to_i64(value.key_generation)?, to_i64(seal.ceiling_bytes)?,
            to_i64(seal.sequence)?, seal.sealed_at.get(), value.signature.as_slice(), to_i64(revision.get())?])?;
    Ok(reference(value))
}

fn verify_provider(
    tx: &Transaction<'_>,
    value: &RecordFederationStorageSeal,
) -> Result<(), RepositoryError> {
    let key: Vec<u8> = tx
        .query_row(
            "SELECT k.verifying_key FROM cleanup_attestation_keys k
        JOIN nodes n ON n.node_id=k.node_id WHERE k.node_id=?1 AND k.generation=?2 AND k.state=1
        AND n.current_incarnation=?3 AND n.state=2",
            params![
                value.seal.provider_node_id.as_bytes().as_slice(),
                to_i64(value.key_generation)?,
                to_i64(value.node_incarnation)?
            ],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    let key = VerifyingKey::from_bytes(&key.try_into().map_err(|_| RepositoryError::CorruptState)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    key.verify_strict(
        &value.signing_payload(),
        &Signature::from_bytes(&value.signature),
    )
    .map_err(|_| RepositoryError::InvalidCommand)
}

/// Revalidate stored evidence before it can authorise additional write allowance.
/// Historical keys need not remain active: the permanent local fence survives rotation.
pub(super) fn verify_grant_seals(
    connection: &Connection,
    grant: FederationGrantId,
) -> Result<(), RepositoryError> {
    let mesh: Vec<u8> =
        connection.query_row("SELECT mesh_id FROM meshes LIMIT 1", [], |row| row.get(0))?;
    let mesh = MeshId::from_bytes(mesh.try_into().map_err(|_| RepositoryError::CorruptState)?)
        .map_err(|_| RepositoryError::CorruptState)?;
    let mut query = connection.prepare(GRANT_SEALS_SQL)?;
    let mut rows = query.query([grant.as_bytes().as_slice()])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        count += 1;
        if count > 4096 {
            return Err(RepositoryError::CapacityExceeded);
        }
        verify_stored_seal(row, mesh)?;
    }
    Ok(())
}

fn verify_stored_seal(row: &Row<'_>, mesh: MeshId) -> Result<(), RepositoryError> {
    let value = RecordFederationStorageSeal {
        provider_mesh_id: mesh,
        seal: FederationStorageCapacitySeal {
            allocation_id: FederationStorageAllocationId::from_bytes(blob(row, 0)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            provider_node_id: NodeId::from_bytes(blob(row, 1)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            target_id: TargetId::from_bytes(blob(row, 8)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            target_generation: positive(row, 9)?,
            ceiling_bytes: u64::try_from(row.get::<_, i64>(4)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            sequence: positive(row, 5)?,
            sealed_at: UnixMicros::new(row.get(6)?),
        },
        node_incarnation: positive(row, 2)?,
        key_generation: positive(row, 3)?,
        signature: blob(row, 7)?,
    };
    if value.seal.sealed_at.get() <= 0
        || value.seal.ceiling_bytes > positive(row, 10)?
        || value.seal.provider_node_id.as_bytes() != blob::<16>(row, 12)?
    {
        return Err(RepositoryError::CorruptState);
    }
    let key =
        VerifyingKey::from_bytes(&blob(row, 11)?).map_err(|_| RepositoryError::CorruptState)?;
    key.verify_strict(
        &value.signing_payload(),
        &Signature::from_bytes(&value.signature),
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn blob<const N: usize>(row: &Row<'_>, index: usize) -> Result<[u8; N], RepositoryError> {
    row.get::<_, Option<Vec<u8>>>(index)?
        .ok_or(RepositoryError::CorruptState)?
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)
}

fn positive(row: &Row<'_>, index: usize) -> Result<u64, RepositoryError> {
    u64::try_from(row.get::<_, i64>(index)?)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::CorruptState)
}

const fn reference(value: &RecordFederationStorageSeal) -> EntityReference {
    EntityReference {
        kind: EntityKind::FederationStorageAllocation,
        id: value.seal.allocation_id.as_bytes(),
    }
}
