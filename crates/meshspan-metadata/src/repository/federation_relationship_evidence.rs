// SPDX-License-Identifier: GPL-2.0-only

//! Evidence-complete validation of one persisted federation relationship.

use ed25519_dalek::{Signature, VerifyingKey};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{FederationGraph, FederationRelationshipKind, MeshId, PrincipalId};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use super::RepositoryError;
use super::federation_query::{FederationRelationshipRecord, FederationRelationshipState};
use crate::{
    FederationGovernanceDirection, FederationGovernanceEdge, FederationGovernanceProof,
    FederationIdentityOwner, PartitionDatabase,
};

const MAXIMUM_ANCESTRY_EDGES: usize = 64;

#[derive(Clone, Debug)]
struct RelationshipEvent {
    authority_epoch: u64,
    sequence: u64,
    kind: i64,
    prior_state: Option<i64>,
    resulting_state: i64,
    revision: u64,
}

pub(super) fn verify(
    database: &PartitionDatabase,
    relationship: &FederationRelationshipRecord,
) -> Result<(), RepositoryError> {
    verify_events(database, relationship)?;
    verify_identity_histories(database, relationship)?;
    verify_governance_evidence(database, relationship)
}

fn verify_events(
    database: &PartitionDatabase,
    relationship: &FederationRelationshipRecord,
) -> Result<(), RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT authority_epoch, event_sequence, event_kind, prior_state,
                resulting_state, changed_by, revision
         FROM federation_relationship_events WHERE relationship_id = ?1
         ORDER BY authority_epoch, event_sequence",
    )?;
    let events = statement
        .query_map(
            [relationship.relationship_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )?
        .map(|row| {
            let row = row?;
            parse_principal(&row.5)?;
            Ok(RelationshipEvent {
                authority_epoch: positive(row.0)?,
                sequence: positive(row.1)?,
                kind: row.2,
                prior_state: row.3,
                resulting_state: row.4,
                revision: positive(row.6)?,
            })
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    let first = events.first().ok_or(RepositoryError::CorruptState)?;
    if first.authority_epoch != 1
        || first.sequence != 1
        || first.kind != 1
        || first.prior_state.is_some()
        || first.resulting_state != state_code(FederationRelationshipState::Proposed)
    {
        return Err(RepositoryError::CorruptState);
    }
    let mut previous = first;
    for event in events.iter().skip(1) {
        let sequence_is_valid = if event.authority_epoch == previous.authority_epoch {
            previous.authority_epoch == 1
                && previous.sequence == 1
                && event.sequence == 2
                && event.kind == 2
        } else {
            event.authority_epoch > previous.authority_epoch && event.sequence == 1
        };
        if !sequence_is_valid
            || event.prior_state != Some(previous.resulting_state)
            || !valid_event_kind(event.kind, event.prior_state, event.resulting_state)
            || event.revision <= previous.revision
        {
            return Err(RepositoryError::CorruptState);
        }
        previous = event;
    }
    let latest = events.last().ok_or(RepositoryError::CorruptState)?;
    if latest.authority_epoch != relationship.authority_epoch
        || latest.resulting_state != state_code(relationship.state)
        || latest.revision != relationship.revision.get()
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(())
}

fn valid_event_kind(kind: i64, prior: Option<i64>, resulting: i64) -> bool {
    matches!(
        (kind, prior, resulting),
        (1, None, 1)
            | (2, Some(1), 2)
            | (3, Some(2 | 3), 3)
            | (4, Some(3), 2)
            | (5, Some(1..=3), 4)
            | (6, Some(4), 5)
    )
}

fn verify_identity_histories(
    database: &PartitionDatabase,
    relationship: &FederationRelationshipRecord,
) -> Result<(), RepositoryError> {
    for owner in [
        FederationIdentityOwner::Local,
        FederationIdentityOwner::Remote,
    ] {
        let mut statement = database.connection().prepare(
            "SELECT generation, certificate_fingerprint, verifying_key,
                    valid_from, valid_until, state, retired_at, revision
             FROM federation_trust_identities
             WHERE relationship_id = ?1 AND identity_owner = ?2
             ORDER BY generation",
        )?;
        let rows = statement
            .query_map(
                params![
                    relationship.relationship_id.as_bytes().as_slice(),
                    owner.code()
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        verify_one_identity_history(relationship.state, &rows)?;
    }
    Ok(())
}

#[allow(
    clippy::type_complexity,
    reason = "the tuple mirrors one narrow persisted trust-identity row"
)]
fn verify_one_identity_history(
    state: FederationRelationshipState,
    rows: &[(i64, Vec<u8>, Vec<u8>, i64, i64, i64, Option<i64>, i64)],
) -> Result<(), RepositoryError> {
    if state == FederationRelationshipState::Proposed {
        return if rows.is_empty() {
            Ok(())
        } else {
            Err(RepositoryError::CorruptState)
        };
    }
    let terminal_state = match state {
        FederationRelationshipState::Active | FederationRelationshipState::Restricted => 1,
        FederationRelationshipState::Revoked | FederationRelationshipState::Retired => 3,
        FederationRelationshipState::Proposed => unreachable!(),
    };
    let last = rows.last().ok_or(RepositoryError::CorruptState)?;
    let mut previous_generation = 0;
    for (index, row) in rows.iter().enumerate() {
        let generation = positive(row.0)?;
        let expected_state = if index + 1 == rows.len() {
            terminal_state
        } else {
            2
        };
        if generation <= previous_generation
            || row.1.len() != 32
            || row.2.len() != 32
            || row.4 <= row.3
            || row.5 != expected_state
            || (row.5 == 1) == row.6.is_some()
            || positive(row.7).is_err()
        {
            return Err(RepositoryError::CorruptState);
        }
        previous_generation = generation;
    }
    if last.5 != terminal_state {
        return Err(RepositoryError::CorruptState);
    }
    Ok(())
}

fn verify_governance_evidence(
    database: &PartitionDatabase,
    relationship: &FederationRelationshipRecord,
) -> Result<(), RepositoryError> {
    if relationship.kind == FederationRelationshipKind::Horizontal {
        return require_no_governance_rows(database, relationship);
    }
    if relationship.state == FederationRelationshipState::Proposed {
        return require_no_governance_rows(database, relationship);
    }
    let edge = load_governance_edge(database, relationship)?;
    let (expected_parent, expected_child) = expected_governance_edge(relationship)?;
    let expected_state = if matches!(
        relationship.state,
        FederationRelationshipState::Active | FederationRelationshipState::Restricted
    ) {
        1
    } else {
        2
    };
    if edge.0 != expected_parent || edge.1 != expected_child || edge.2 != expected_state {
        return Err(RepositoryError::CorruptState);
    }
    verify_governance_proof(database, relationship, expected_parent, expected_child)
}

fn require_no_governance_rows(
    database: &PartitionDatabase,
    relationship: &FederationRelationshipRecord,
) -> Result<(), RepositoryError> {
    let count: i64 = database.connection().query_row(
        "SELECT
            (SELECT count(*) FROM federation_governance_edges WHERE relationship_id = ?1)
          + (SELECT count(*) FROM federation_governance_proofs WHERE relationship_id = ?1)
          + (SELECT count(*) FROM federation_governance_proof_edges WHERE relationship_id = ?1)",
        [relationship.relationship_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if count == 0 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn load_governance_edge(
    database: &PartitionDatabase,
    relationship: &FederationRelationshipRecord,
) -> Result<(MeshId, MeshId, i64), RepositoryError> {
    database
        .connection()
        .query_row(
            "SELECT parent_mesh_id, child_mesh_id, state
             FROM federation_governance_edges WHERE relationship_id = ?1",
            [relationship.relationship_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::CorruptState)
        .and_then(|row| Ok((parse_mesh(&row.0)?, parse_mesh(&row.1)?, row.2)))
}

fn expected_governance_edge(
    relationship: &FederationRelationshipRecord,
) -> Result<(MeshId, MeshId), RepositoryError> {
    match relationship.governance_direction {
        FederationGovernanceDirection::LocalGovernsRemote => {
            Ok((relationship.local_mesh_id, relationship.remote_mesh_id))
        }
        FederationGovernanceDirection::RemoteGovernsLocal => {
            Ok((relationship.remote_mesh_id, relationship.local_mesh_id))
        }
        FederationGovernanceDirection::None => Err(RepositoryError::CorruptState),
    }
}

fn verify_governance_proof(
    database: &PartitionDatabase,
    relationship: &FederationRelationshipRecord,
    proposed_parent: MeshId,
    proposed_child: MeshId,
) -> Result<(), RepositoryError> {
    let header = database
        .connection()
        .query_row(
            "SELECT remote_authority_epoch, edge_count, proof_digest,
                    signer_generation, signature
             FROM federation_governance_proofs WHERE relationship_id = ?1",
            [relationship.relationship_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::CorruptState)?;
    let ancestry = load_proof_edges(database, relationship)?;
    let edge_count = usize::try_from(header.1).map_err(|_| RepositoryError::CorruptState)?;
    if edge_count != ancestry.len() || header.2.len() != 32 || header.4.len() != 64 {
        return Err(RepositoryError::CorruptState);
    }
    validate_ancestry(relationship, &ancestry, proposed_parent, proposed_child)?;
    let proof = FederationGovernanceProof {
        remote_authority_epoch: positive(header.0)?,
        ancestry: BoundedItems::new(ancestry, MAXIMUM_ANCESTRY_EDGES)
            .map_err(|_| RepositoryError::CorruptState)?,
        signer_generation: positive(header.3)?,
        signature: header
            .4
            .as_slice()
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    };
    let payload = proof.signing_payload(
        relationship.relationship_id,
        relationship.local_mesh_id,
        relationship.remote_mesh_id,
        relationship.governance_direction,
    );
    let computed_digest: [u8; 32] = Sha256::digest(&payload).into();
    if header.2.as_slice() != computed_digest {
        return Err(RepositoryError::CorruptState);
    }
    let verifying_key = load_remote_verifying_key(database, relationship, proof.signer_generation)?;
    verifying_key
        .verify_strict(&payload, &Signature::from_bytes(&proof.signature))
        .map_err(|_| RepositoryError::CorruptState)
}

fn load_proof_edges(
    database: &PartitionDatabase,
    relationship: &FederationRelationshipRecord,
) -> Result<Vec<FederationGovernanceEdge>, RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT edge_sequence, parent_mesh_id, child_mesh_id
         FROM federation_governance_proof_edges WHERE relationship_id = ?1
         ORDER BY edge_sequence LIMIT 66",
    )?;
    let rows = statement
        .query_map(
            [relationship.relationship_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > MAXIMUM_ANCESTRY_EDGES {
        return Err(RepositoryError::CorruptState);
    }
    rows.into_iter()
        .enumerate()
        .map(|(expected, row)| {
            if usize::try_from(row.0).map_err(|_| RepositoryError::CorruptState)? != expected {
                return Err(RepositoryError::CorruptState);
            }
            Ok(FederationGovernanceEdge {
                parent_mesh_id: parse_mesh(&row.1)?,
                child_mesh_id: parse_mesh(&row.2)?,
            })
        })
        .collect()
}

fn validate_ancestry(
    relationship: &FederationRelationshipRecord,
    ancestry: &[FederationGovernanceEdge],
    proposed_parent: MeshId,
    proposed_child: MeshId,
) -> Result<(), RepositoryError> {
    if relationship.governance_direction == FederationGovernanceDirection::LocalGovernsRemote
        && !ancestry.is_empty()
    {
        return Err(RepositoryError::CorruptState);
    }
    if relationship.governance_direction == FederationGovernanceDirection::RemoteGovernsLocal {
        if ancestry
            .first()
            .is_some_and(|first| first.child_mesh_id != relationship.remote_mesh_id)
        {
            return Err(RepositoryError::CorruptState);
        }
        for pair in ancestry.windows(2) {
            if pair[1].child_mesh_id != pair[0].parent_mesh_id {
                return Err(RepositoryError::CorruptState);
            }
        }
    }
    let mut graph = FederationGraph::new();
    for edge in ancestry {
        graph
            .add_governance(edge.parent_mesh_id, edge.child_mesh_id)
            .map_err(|_| RepositoryError::CorruptState)?;
    }
    graph
        .add_governance(proposed_parent, proposed_child)
        .map_err(|_| RepositoryError::CorruptState)
}

fn load_remote_verifying_key(
    database: &PartitionDatabase,
    relationship: &FederationRelationshipRecord,
    generation: u64,
) -> Result<VerifyingKey, RepositoryError> {
    let key: Vec<u8> = database
        .connection()
        .query_row(
            "SELECT verifying_key FROM federation_trust_identities
             WHERE relationship_id = ?1 AND identity_owner = 2 AND generation = ?2",
            params![
                relationship.relationship_id.as_bytes().as_slice(),
                i64::try_from(generation).map_err(|_| RepositoryError::CorruptState)?
            ],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(RepositoryError::CorruptState)?;
    VerifyingKey::from_bytes(
        &key.as_slice()
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

const fn state_code(state: FederationRelationshipState) -> i64 {
    match state {
        FederationRelationshipState::Proposed => 1,
        FederationRelationshipState::Active => 2,
        FederationRelationshipState::Restricted => 3,
        FederationRelationshipState::Revoked => 4,
        FederationRelationshipState::Retired => 5,
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

fn parse_principal(value: &[u8]) -> Result<PrincipalId, RepositoryError> {
    PrincipalId::from_bytes(
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
