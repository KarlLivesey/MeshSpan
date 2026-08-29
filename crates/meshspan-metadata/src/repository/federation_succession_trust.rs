// SPDX-License-Identifier: GPL-2.0-only

//! Relationship-party, epoch and rotating-signing-identity verification.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use meshspan_domain::{FederationRelationshipId, MeshId};
use rusqlite::{Connection, OptionalExtension, params};

use super::RepositoryError;
use super::apply::to_i64;

const RELATIONSHIP_ACTIVE: i64 = 2;
const RELATIONSHIP_RESTRICTED: i64 = 3;

#[derive(Clone, Copy)]
pub(super) struct Relationship {
    pub(super) local_mesh_id: MeshId,
    remote_mesh_id: MeshId,
    state: i64,
    authority_epoch: u64,
}

pub(super) fn validate_common(
    connection: &Connection,
    relationship_id: FederationRelationshipId,
    retiring_mesh_id: MeshId,
    successor_mesh_id: MeshId,
    authority_epoch: u64,
    succession_epoch: u64,
) -> Result<Relationship, RepositoryError> {
    if retiring_mesh_id == successor_mesh_id || authority_epoch == 0 || succession_epoch == 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    let relationship = relationship(connection, relationship_id)?;
    let pair_matches = (relationship.local_mesh_id == retiring_mesh_id
        && relationship.remote_mesh_id == successor_mesh_id)
        || (relationship.local_mesh_id == successor_mesh_id
            && relationship.remote_mesh_id == retiring_mesh_id);
    if !pair_matches
        || !matches!(
            relationship.state,
            RELATIONSHIP_ACTIVE | RELATIONSHIP_RESTRICTED
        )
        || relationship.authority_epoch != authority_epoch
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(relationship)
}

pub(super) fn relationship(
    connection: &Connection,
    relationship_id: FederationRelationshipId,
) -> Result<Relationship, RepositoryError> {
    let row = connection
        .query_row(
            "SELECT local_mesh_id, remote_mesh_id, state, authority_epoch
             FROM federation_relationships WHERE relationship_id = ?1",
            [relationship_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    Ok(Relationship {
        local_mesh_id: parse_mesh(&row.0)?,
        remote_mesh_id: parse_mesh(&row.1)?,
        state: row.2,
        authority_epoch: positive(row.3)?,
    })
}

pub(super) fn verify_side_signature(
    connection: &Connection,
    relationship_id: FederationRelationshipId,
    signer_mesh_id: MeshId,
    generation: u64,
    payload: &[u8],
    signature: [u8; 64],
    require_active_key: bool,
) -> Result<(), RepositoryError> {
    if generation == 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    let relation = relationship(connection, relationship_id)?;
    let owner = if signer_mesh_id == relation.local_mesh_id {
        1
    } else if signer_mesh_id == relation.remote_mesh_id {
        2
    } else {
        return Err(RepositoryError::InvalidCommand);
    };
    let identity: (Vec<u8>, i64) = connection
        .query_row(
            "SELECT verifying_key, state FROM federation_trust_identities
             WHERE relationship_id = ?1 AND identity_owner = ?2 AND generation = ?3",
            params![
                relationship_id.as_bytes().as_slice(),
                owner,
                to_i64(generation)?,
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    if (require_active_key && identity.1 != 1) || !matches!(identity.1, 1 | 2) {
        return Err(RepositoryError::InvalidCommand);
    }
    let key = VerifyingKey::from_bytes(
        &identity
            .0
            .as_slice()
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)?;
    key.verify(payload, &Signature::from_bytes(&signature))
        .map_err(|_| RepositoryError::InvalidCommand)
}

fn parse_mesh(value: &[u8]) -> Result<MeshId, RepositoryError> {
    MeshId::from_bytes(
        value
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn positive(value: i64) -> Result<u64, RepositoryError> {
    let value = u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?;
    if value == 0 {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(value)
    }
}
