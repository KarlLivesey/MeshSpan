// SPDX-License-Identifier: GPL-2.0-only

//! Durable succession reconstruction and independent signed-evidence verification.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{FederationRelationshipId, FederationSuccessionId, MeshId, Revision};
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use super::RepositoryError;
use super::federation_succession_graph::{
    MAXIMUM_ANCESTRY_EDGES, ensure_graph_acyclic, load_ancestry,
};
use super::federation_succession_trust::verify_side_signature;
use crate::{
    AcceptFederationSuccessor, ActivateFederationSuccessor, DesignateFederationSuccessor,
    FederationSuccessionEdge, PartitionDatabase,
};

pub(super) const MAXIMUM_REASON_BYTES: usize = 1_024;
pub(super) const SUCCESSION_DESIGNATED: i64 = 1;
pub(super) const SUCCESSION_ACCEPTED: i64 = 2;
pub(super) const SUCCESSION_ACTIVE: i64 = 3;
pub(super) const SUCCESSION_REVOKED: i64 = 4;

/// Current validated recovery succession for one retiring swarm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationSuccessionRecord {
    /// Stable designation identity.
    pub succession_id: FederationSuccessionId,
    /// Relationship carrying the two-sided proof.
    pub relationship_id: FederationRelationshipId,
    /// Permanently replaced authority.
    pub retiring_mesh_id: MeshId,
    /// Pre-authorised replacement authority.
    pub successor_mesh_id: MeshId,
    /// Exact relationship epoch binding the proof.
    pub relationship_authority_epoch: u64,
    /// Monotonic succession epoch.
    pub succession_epoch: u64,
    /// Whether the proof is designated, accepted, active or revoked.
    pub state: FederationSuccessionState,
    /// Last local authoritative revision.
    pub revision: Revision,
}

/// Closed durable succession lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationSuccessionState {
    /// Retiring swarm has nominated a successor.
    Designated,
    /// Successor has signed exact acceptance.
    Accepted,
    /// Local successor has activated recovery and fenced the retired swarm.
    Active,
    /// Retiring swarm cancelled the dormant designation.
    Revoked,
}

#[derive(Clone)]
pub(super) struct StoredSuccession {
    pub(super) record: FederationSuccessionRecord,
    pub(super) designation_digest: [u8; 32],
    designation_signer_generation: u64,
    designation_signature: [u8; 64],
    pub(super) acceptance_digest: Option<[u8; 32]>,
    acceptance_signer_generation: Option<u64>,
    acceptance_signature: Option<[u8; 64]>,
    activation_digest: Option<[u8; 32]>,
}

pub(super) fn load_succession(
    connection: &Connection,
    succession_id: FederationSuccessionId,
) -> Result<StoredSuccession, RepositoryError> {
    let row = connection
        .query_row(
            "SELECT relationship_id, retiring_mesh_id, successor_mesh_id,
                    relationship_authority_epoch, succession_epoch, designation_digest,
                    designation_signer_generation, designation_signature,
                    acceptance_digest, acceptance_signer_generation, acceptance_signature,
                    activation_digest, state, revision
             FROM federation_ownership_successions WHERE succession_id = ?1",
            [succession_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<Vec<u8>>>(10)?,
                    row.get::<_, Option<Vec<u8>>>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    Ok(StoredSuccession {
        record: FederationSuccessionRecord {
            succession_id,
            relationship_id: parse_relationship(&row.0)?,
            retiring_mesh_id: parse_mesh(&row.1)?,
            successor_mesh_id: parse_mesh(&row.2)?,
            relationship_authority_epoch: positive(row.3)?,
            succession_epoch: positive(row.4)?,
            state: parse_state(row.12)?,
            revision: Revision::new(positive(row.13)?),
        },
        designation_digest: parse_digest(&row.5)?,
        designation_signer_generation: positive(row.6)?,
        designation_signature: parse_signature(&row.7)?,
        acceptance_digest: row.8.as_deref().map(parse_digest).transpose()?,
        acceptance_signer_generation: row.9.map(positive).transpose()?,
        acceptance_signature: row.10.as_deref().map(parse_signature).transpose()?,
        activation_digest: row.11.as_deref().map(parse_digest).transpose()?,
    })
}

pub(super) fn active_for_retiring(
    database: &PartitionDatabase,
    retiring_mesh_id: MeshId,
) -> Result<Option<FederationSuccessionRecord>, RepositoryError> {
    let id: Option<Vec<u8>> = database
        .connection()
        .query_row(
            "SELECT succession_id FROM federation_ownership_successions
             WHERE retiring_mesh_id = ?1 AND state = 3",
            [retiring_mesh_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    id.map(|value| {
        let id = FederationSuccessionId::from_bytes(
            value
                .as_slice()
                .try_into()
                .map_err(|_| RepositoryError::CorruptState)?,
        )
        .map_err(|_| RepositoryError::CorruptState)?;
        let stored = load_succession(database.connection(), id)?;
        verify_active_evidence(database.connection(), &stored)?;
        Ok(stored.record)
    })
    .transpose()
}

pub(super) fn verify_designation_evidence(
    connection: &Connection,
    stored: &StoredSuccession,
) -> Result<Vec<FederationSuccessionEdge>, RepositoryError> {
    let ancestry = load_ancestry(connection, stored.record.succession_id)?;
    let designation = DesignateFederationSuccessor {
        succession_id: stored.record.succession_id,
        relationship_id: stored.record.relationship_id,
        retiring_mesh_id: stored.record.retiring_mesh_id,
        successor_mesh_id: stored.record.successor_mesh_id,
        expected_authority_epoch: stored.record.relationship_authority_epoch,
        succession_epoch: stored.record.succession_epoch,
        ancestry: BoundedItems::new(ancestry.clone(), MAXIMUM_ANCESTRY_EDGES)
            .map_err(|_| RepositoryError::CorruptState)?,
        signer_generation: stored.designation_signer_generation,
        signature: stored.designation_signature,
    };
    if payload_digest(&designation.signing_payload()) != stored.designation_digest {
        return Err(RepositoryError::CorruptState);
    }
    verify_side_signature(
        connection,
        stored.record.relationship_id,
        stored.record.retiring_mesh_id,
        designation.signer_generation,
        &designation.signing_payload(),
        designation.signature,
        false,
    )
    .map_err(|_| RepositoryError::CorruptState)?;
    Ok(ancestry)
}

pub(super) fn verify_signed_agreement(
    connection: &Connection,
    stored: &StoredSuccession,
) -> Result<(Vec<FederationSuccessionEdge>, [u8; 32]), RepositoryError> {
    let ancestry = verify_designation_evidence(connection, stored)?;
    let acceptance_digest = stored
        .acceptance_digest
        .ok_or(RepositoryError::CorruptState)?;
    let acceptance = AcceptFederationSuccessor {
        succession_id: stored.record.succession_id,
        relationship_id: stored.record.relationship_id,
        retiring_mesh_id: stored.record.retiring_mesh_id,
        successor_mesh_id: stored.record.successor_mesh_id,
        expected_authority_epoch: stored.record.relationship_authority_epoch,
        succession_epoch: stored.record.succession_epoch,
        designation_digest: stored.designation_digest,
        signer_generation: stored
            .acceptance_signer_generation
            .ok_or(RepositoryError::CorruptState)?,
        signature: stored
            .acceptance_signature
            .ok_or(RepositoryError::CorruptState)?,
    };
    if payload_digest(&acceptance.signing_payload()) != acceptance_digest {
        return Err(RepositoryError::CorruptState);
    }
    verify_side_signature(
        connection,
        stored.record.relationship_id,
        stored.record.successor_mesh_id,
        acceptance.signer_generation,
        &acceptance.signing_payload(),
        acceptance.signature,
        false,
    )
    .map_err(|_| RepositoryError::CorruptState)?;
    Ok((ancestry, acceptance_digest))
}

fn verify_active_evidence(
    connection: &Connection,
    stored: &StoredSuccession,
) -> Result<(), RepositoryError> {
    let (ancestry, acceptance_digest) = verify_signed_agreement(connection, stored)?;
    verify_activation_event(connection, stored, acceptance_digest)?;
    ensure_graph_acyclic(connection, None, &ancestry).map_err(|_| RepositoryError::CorruptState)
}

fn verify_activation_event(
    connection: &Connection,
    stored: &StoredSuccession,
    acceptance_digest: [u8; 32],
) -> Result<(), RepositoryError> {
    let mut statement = connection.prepare(
        "SELECT event_kind, event_digest, reason
         FROM federation_ownership_succession_events
         WHERE succession_id = ?1 ORDER BY event_sequence",
    )?;
    let rows = statement
        .query_map([stored.record.succession_id.as_bytes().as_slice()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != 3
        || rows[0].0 != 1
        || rows[1].0 != 2
        || rows[2].0 != 3
        || parse_digest(&rows[0].1)? != stored.designation_digest
        || parse_digest(&rows[1].1)? != acceptance_digest
    {
        return Err(RepositoryError::CorruptState);
    }
    let reason = rows[2].2.clone().ok_or(RepositoryError::CorruptState)?;
    validate_reason(&reason).map_err(|_| RepositoryError::CorruptState)?;
    let command = ActivateFederationSuccessor {
        succession_id: stored.record.succession_id,
        relationship_id: stored.record.relationship_id,
        retiring_mesh_id: stored.record.retiring_mesh_id,
        successor_mesh_id: stored.record.successor_mesh_id,
        expected_authority_epoch: stored.record.relationship_authority_epoch,
        succession_epoch: stored.record.succession_epoch,
        designation_digest: stored.designation_digest,
        acceptance_digest,
        reason,
    };
    let recomputed = activation_digest(&command);
    if stored.activation_digest == Some(recomputed) && parse_digest(&rows[2].1)? == recomputed {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

pub(super) fn activation_digest(command: &ActivateFederationSuccessor) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.federation.successor-activation.v1");
    digest.update(command.succession_id.as_bytes());
    digest.update(command.relationship_id.as_bytes());
    digest.update(command.retiring_mesh_id.as_bytes());
    digest.update(command.successor_mesh_id.as_bytes());
    digest.update(command.expected_authority_epoch.to_be_bytes());
    digest.update(command.succession_epoch.to_be_bytes());
    digest.update(command.designation_digest);
    digest.update(command.acceptance_digest);
    digest.update(
        u64::try_from(command.reason.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(command.reason.as_bytes());
    digest.finalize().into()
}

pub(super) fn validate_reason(reason: &str) -> Result<(), RepositoryError> {
    if reason.is_empty()
        || reason.len() > MAXIMUM_REASON_BYTES
        || reason.chars().any(char::is_control)
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

pub(super) const fn state_code(state: FederationSuccessionState) -> i64 {
    match state {
        FederationSuccessionState::Designated => SUCCESSION_DESIGNATED,
        FederationSuccessionState::Accepted => SUCCESSION_ACCEPTED,
        FederationSuccessionState::Active => SUCCESSION_ACTIVE,
        FederationSuccessionState::Revoked => SUCCESSION_REVOKED,
    }
}

fn payload_digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

fn parse_state(value: i64) -> Result<FederationSuccessionState, RepositoryError> {
    match value {
        SUCCESSION_DESIGNATED => Ok(FederationSuccessionState::Designated),
        SUCCESSION_ACCEPTED => Ok(FederationSuccessionState::Accepted),
        SUCCESSION_ACTIVE => Ok(FederationSuccessionState::Active),
        SUCCESSION_REVOKED => Ok(FederationSuccessionState::Revoked),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_mesh(value: &[u8]) -> Result<MeshId, RepositoryError> {
    MeshId::from_bytes(
        value
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn parse_relationship(value: &[u8]) -> Result<FederationRelationshipId, RepositoryError> {
    FederationRelationshipId::from_bytes(
        value
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn parse_digest(value: &[u8]) -> Result<[u8; 32], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn parse_signature(value: &[u8]) -> Result<[u8; 64], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn positive(value: i64) -> Result<u64, RepositoryError> {
    let value = u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?;
    if value == 0 {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(value)
    }
}
