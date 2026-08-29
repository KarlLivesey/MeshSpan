// SPDX-License-Identifier: GPL-2.0-only

//! Two-sided recovery-succession transitions and acyclic authority fencing.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{FederationRelationshipId, FederationSuccessionId, MeshId, Revision};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    AcceptFederationSuccessor, ActivateFederationSuccessor, AuthoritativeCommand, CommandContext,
    DesignateFederationSuccessor, FederationSuccessionEdge, PartitionDatabase,
    RevokeFederationSuccessorDesignation,
};

const MAXIMUM_ANCESTRY_EDGES: usize = 64;
const MAXIMUM_REASON_BYTES: usize = 1_024;
const RELATIONSHIP_ACTIVE: i64 = 2;
const RELATIONSHIP_RESTRICTED: i64 = 3;
const SUCCESSION_DESIGNATED: i64 = 1;
const SUCCESSION_ACCEPTED: i64 = 2;
const SUCCESSION_ACTIVE: i64 = 3;
const SUCCESSION_REVOKED: i64 = 4;

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

#[derive(Clone, Copy)]
struct Relationship {
    local_mesh_id: MeshId,
    remote_mesh_id: MeshId,
    state: i64,
    authority_epoch: u64,
}

#[derive(Clone)]
struct StoredSuccession {
    record: FederationSuccessionRecord,
    designation_digest: [u8; 32],
    designation_signer_generation: u64,
    designation_signature: [u8; 64],
    acceptance_digest: Option<[u8; 32]>,
    acceptance_signer_generation: Option<u64>,
    acceptance_signature: Option<[u8; 64]>,
    activation_digest: Option<[u8; 32]>,
}

pub(super) fn is_command(command: &AuthoritativeCommand) -> bool {
    matches!(
        command,
        AuthoritativeCommand::DesignateFederationSuccessor(_)
            | AuthoritativeCommand::AcceptFederationSuccessor(_)
            | AuthoritativeCommand::ActivateFederationSuccessor(_)
            | AuthoritativeCommand::RevokeFederationSuccessorDesignation(_)
    )
}

pub(super) fn execute(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let succession_id = match command {
        AuthoritativeCommand::DesignateFederationSuccessor(value) => {
            designate(transaction, context, value, revision)?;
            value.succession_id
        }
        AuthoritativeCommand::AcceptFederationSuccessor(value) => {
            accept(transaction, context, *value, revision)?;
            value.succession_id
        }
        AuthoritativeCommand::ActivateFederationSuccessor(value) => {
            activate(transaction, context, value, revision)?;
            value.succession_id
        }
        AuthoritativeCommand::RevokeFederationSuccessorDesignation(value) => {
            revoke(transaction, context, value, revision)?;
            value.succession_id
        }
        _ => return Err(RepositoryError::InvalidCommand),
    };
    Ok(EntityReference {
        kind: EntityKind::FederationSuccession,
        id: succession_id.as_bytes(),
    })
}

fn designate(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &DesignateFederationSuccessor,
    revision: Revision,
) -> Result<(), RepositoryError> {
    validate_common(
        transaction,
        command.relationship_id,
        command.retiring_mesh_id,
        command.successor_mesh_id,
        command.expected_authority_epoch,
        command.succession_epoch,
    )?;
    if command.ancestry.len() > MAXIMUM_ANCESTRY_EDGES || command.signer_generation == 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    verify_ancestry(transaction, command)?;
    verify_side_signature(
        transaction,
        command.relationship_id,
        command.retiring_mesh_id,
        command.signer_generation,
        &command.signing_payload(),
        command.signature,
        true,
    )?;
    require_next_epoch(
        transaction,
        command.retiring_mesh_id,
        command.succession_epoch,
    )?;
    let designation_digest: [u8; 32] = Sha256::digest(command.signing_payload()).into();
    transaction.execute(
        "INSERT INTO federation_ownership_successions(
            succession_id, relationship_id, retiring_mesh_id, successor_mesh_id,
            relationship_authority_epoch, succession_epoch, designation_digest,
            designation_signer_generation, designation_signature, state,
            designated_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            command.succession_id.as_bytes().as_slice(),
            command.relationship_id.as_bytes().as_slice(),
            command.retiring_mesh_id.as_bytes().as_slice(),
            command.successor_mesh_id.as_bytes().as_slice(),
            to_i64(command.expected_authority_epoch)?,
            to_i64(command.succession_epoch)?,
            designation_digest.as_slice(),
            to_i64(command.signer_generation)?,
            command.signature.as_slice(),
            SUCCESSION_DESIGNATED,
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    persist_ancestry(transaction, command, revision)?;
    insert_event(
        transaction,
        context,
        command.succession_id,
        1,
        1,
        None,
        SUCCESSION_DESIGNATED,
        designation_digest,
        None,
        revision,
    )
}

fn accept(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: AcceptFederationSuccessor,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let stored = require_transition(transaction, command.succession_id, SUCCESSION_DESIGNATED)?;
    validate_common(
        transaction,
        command.relationship_id,
        command.retiring_mesh_id,
        command.successor_mesh_id,
        command.expected_authority_epoch,
        command.succession_epoch,
    )?;
    require_exact(
        &stored,
        command.relationship_id,
        command.retiring_mesh_id,
        command.successor_mesh_id,
        command.expected_authority_epoch,
        command.succession_epoch,
        command.designation_digest,
    )?;
    verify_designation_evidence(transaction, &stored)?;
    if command.signer_generation == 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    verify_side_signature(
        transaction,
        command.relationship_id,
        command.successor_mesh_id,
        command.signer_generation,
        &command.signing_payload(),
        command.signature,
        true,
    )?;
    let acceptance_digest: [u8; 32] = Sha256::digest(command.signing_payload()).into();
    update_acceptance(transaction, context, command, acceptance_digest, revision)?;
    insert_event(
        transaction,
        context,
        command.succession_id,
        2,
        2,
        Some(SUCCESSION_DESIGNATED),
        SUCCESSION_ACCEPTED,
        acceptance_digest,
        None,
        revision,
    )
}

fn activate(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ActivateFederationSuccessor,
    revision: Revision,
) -> Result<(), RepositoryError> {
    validate_reason(&command.reason)?;
    let stored = require_transition(transaction, command.succession_id, SUCCESSION_ACCEPTED)?;
    validate_common(
        transaction,
        command.relationship_id,
        command.retiring_mesh_id,
        command.successor_mesh_id,
        command.expected_authority_epoch,
        command.succession_epoch,
    )?;
    require_exact(
        &stored,
        command.relationship_id,
        command.retiring_mesh_id,
        command.successor_mesh_id,
        command.expected_authority_epoch,
        command.succession_epoch,
        command.designation_digest,
    )?;
    if stored.acceptance_digest != Some(command.acceptance_digest) {
        return Err(RepositoryError::InvalidCommand);
    }
    verify_signed_agreement(transaction, &stored)?;
    let relationship = relationship(transaction, command.relationship_id)?;
    if relationship.local_mesh_id != command.successor_mesh_id {
        return Err(RepositoryError::InvalidCommand);
    }
    ensure_active_graph_acyclic(
        transaction,
        command.retiring_mesh_id,
        command.successor_mesh_id,
    )?;
    let activation_digest = activation_digest(command);
    let changed = transaction.execute(
        "UPDATE federation_ownership_successions
         SET state = ?1, activation_digest = ?2, activated_at = ?3, revision = ?4
         WHERE succession_id = ?5 AND state = ?6",
        params![
            SUCCESSION_ACTIVE,
            activation_digest.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.succession_id.as_bytes().as_slice(),
            SUCCESSION_ACCEPTED,
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    insert_event(
        transaction,
        context,
        command.succession_id,
        3,
        3,
        Some(SUCCESSION_ACCEPTED),
        SUCCESSION_ACTIVE,
        activation_digest,
        Some(&command.reason),
        revision,
    )
}

fn revoke(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RevokeFederationSuccessorDesignation,
    revision: Revision,
) -> Result<(), RepositoryError> {
    validate_reason(&command.reason)?;
    let stored = load_succession(transaction, command.succession_id)?;
    validate_common(
        transaction,
        command.relationship_id,
        command.retiring_mesh_id,
        command.successor_mesh_id,
        command.expected_authority_epoch,
        command.succession_epoch,
    )?;
    if !matches!(
        stored.record.state,
        FederationSuccessionState::Designated | FederationSuccessionState::Accepted
    ) {
        return Err(RepositoryError::InvalidCommand);
    }
    require_exact(
        &stored,
        command.relationship_id,
        command.retiring_mesh_id,
        command.successor_mesh_id,
        command.expected_authority_epoch,
        command.succession_epoch,
        command.designation_digest,
    )?;
    verify_designation_evidence(transaction, &stored)?;
    verify_side_signature(
        transaction,
        command.relationship_id,
        command.retiring_mesh_id,
        command.signer_generation,
        &command.signing_payload(),
        command.signature,
        true,
    )?;
    let prior_state = state_code(stored.record.state);
    let sequence = if prior_state == SUCCESSION_DESIGNATED {
        2
    } else {
        3
    };
    let event_digest: [u8; 32] = Sha256::digest(command.signing_payload()).into();
    let changed = transaction.execute(
        "UPDATE federation_ownership_successions
         SET state = ?1, revoked_at = ?2, revision = ?3
         WHERE succession_id = ?4 AND state = ?5",
        params![
            SUCCESSION_REVOKED,
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.succession_id.as_bytes().as_slice(),
            prior_state,
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    insert_event(
        transaction,
        context,
        command.succession_id,
        sequence,
        4,
        Some(prior_state),
        SUCCESSION_REVOKED,
        event_digest,
        Some(&command.reason),
        revision,
    )
}

fn validate_common(
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

fn relationship(
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

fn verify_side_signature(
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
             WHERE relationship_id = ?1 AND identity_owner = ?2
               AND generation = ?3",
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

fn require_next_epoch(
    connection: &Connection,
    retiring_mesh_id: MeshId,
    epoch: u64,
) -> Result<(), RepositoryError> {
    let current: i64 = connection.query_row(
        "SELECT coalesce(max(succession_epoch), 0)
         FROM federation_ownership_successions WHERE retiring_mesh_id = ?1",
        [retiring_mesh_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if positive_or_zero(current)?.checked_add(1) == Some(epoch) {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn verify_ancestry(
    connection: &Connection,
    command: &DesignateFederationSuccessor,
) -> Result<(), RepositoryError> {
    let ancestry = command.ancestry.as_slice();
    if ancestry
        .first()
        .is_some_and(|edge| edge.successor_mesh_id != command.retiring_mesh_id)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    for edge in ancestry {
        if edge.retiring_mesh_id == edge.successor_mesh_id
            || edge.retiring_mesh_id == command.successor_mesh_id
            || edge.successor_mesh_id == command.successor_mesh_id
        {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    for pair in ancestry.windows(2) {
        if pair[1].successor_mesh_id != pair[0].retiring_mesh_id {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    ensure_graph_acyclic(
        connection,
        Some((command.retiring_mesh_id, command.successor_mesh_id)),
        ancestry,
    )
}

fn ensure_active_graph_acyclic(
    connection: &Connection,
    retiring_mesh_id: MeshId,
    successor_mesh_id: MeshId,
) -> Result<(), RepositoryError> {
    ensure_graph_acyclic(connection, Some((retiring_mesh_id, successor_mesh_id)), &[])
}

fn ensure_graph_acyclic(
    connection: &Connection,
    proposed: Option<(MeshId, MeshId)>,
    presented: &[FederationSuccessionEdge],
) -> Result<(), RepositoryError> {
    let mut edges = BTreeMap::new();
    let mut statement = connection.prepare(
        "SELECT retiring_mesh_id, successor_mesh_id
         FROM federation_ownership_successions WHERE state = 3 ORDER BY retiring_mesh_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let row = row?;
        insert_edge(&mut edges, parse_mesh(&row.0)?, parse_mesh(&row.1)?)?;
    }
    for edge in presented {
        insert_edge(&mut edges, edge.retiring_mesh_id, edge.successor_mesh_id)?;
    }
    if let Some((retiring, successor)) = proposed {
        insert_edge(&mut edges, retiring, successor)?;
    }
    for start in edges.keys().copied() {
        let mut visited = BTreeSet::new();
        let mut current = start;
        while let Some(next) = edges.get(&current).copied() {
            if !visited.insert(current) {
                return Err(RepositoryError::InvalidCommand);
            }
            current = next;
        }
    }
    Ok(())
}

fn insert_edge(
    edges: &mut BTreeMap<MeshId, MeshId>,
    retiring: MeshId,
    successor: MeshId,
) -> Result<(), RepositoryError> {
    if retiring == successor
        || edges
            .insert(retiring, successor)
            .is_some_and(|existing| existing != successor)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn require_transition(
    connection: &Connection,
    succession_id: FederationSuccessionId,
    expected_state: i64,
) -> Result<StoredSuccession, RepositoryError> {
    let stored = load_succession(connection, succession_id)?;
    if state_code(stored.record.state) == expected_state {
        Ok(stored)
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "exact transition proof has seven independent fences"
)]
fn require_exact(
    stored: &StoredSuccession,
    relationship_id: FederationRelationshipId,
    retiring_mesh_id: MeshId,
    successor_mesh_id: MeshId,
    authority_epoch: u64,
    succession_epoch: u64,
    designation_digest: [u8; 32],
) -> Result<(), RepositoryError> {
    let record = stored.record;
    if record.relationship_id == relationship_id
        && record.retiring_mesh_id == retiring_mesh_id
        && record.successor_mesh_id == successor_mesh_id
        && record.relationship_authority_epoch == authority_epoch
        && record.succession_epoch == succession_epoch
        && stored.designation_digest == designation_digest
    {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn update_acceptance(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: AcceptFederationSuccessor,
    acceptance_digest: [u8; 32],
    revision: Revision,
) -> Result<(), RepositoryError> {
    let changed = transaction.execute(
        "UPDATE federation_ownership_successions
         SET state = ?1, acceptance_digest = ?2, acceptance_signer_generation = ?3,
             acceptance_signature = ?4, accepted_at = ?5, revision = ?6
         WHERE succession_id = ?7 AND state = ?8",
        params![
            SUCCESSION_ACCEPTED,
            acceptance_digest.as_slice(),
            to_i64(command.signer_generation)?,
            command.signature.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.succession_id.as_bytes().as_slice(),
            SUCCESSION_DESIGNATED,
        ],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn persist_ancestry(
    transaction: &Transaction<'_>,
    command: &DesignateFederationSuccessor,
    revision: Revision,
) -> Result<(), RepositoryError> {
    for (sequence, edge) in command.ancestry.as_slice().iter().enumerate() {
        transaction.execute(
            "INSERT INTO federation_ownership_succession_ancestry(
                succession_id, edge_sequence, retiring_mesh_id, successor_mesh_id, revision
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                command.succession_id.as_bytes().as_slice(),
                to_i64(u64::try_from(sequence).map_err(|_| RepositoryError::CapacityExceeded)?)?,
                edge.retiring_mesh_id.as_bytes().as_slice(),
                edge.successor_mesh_id.as_bytes().as_slice(),
                to_i64(revision.get())?,
            ],
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "immutable lifecycle event names every proof field"
)]
fn insert_event(
    transaction: &Transaction<'_>,
    context: CommandContext,
    succession_id: FederationSuccessionId,
    sequence: u64,
    kind: i64,
    prior_state: Option<i64>,
    resulting_state: i64,
    event_digest: [u8; 32],
    reason: Option<&str>,
    revision: Revision,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "INSERT INTO federation_ownership_succession_events(
            succession_id, event_sequence, event_kind, prior_state, resulting_state,
            event_digest, reason, changed_by, changed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            succession_id.as_bytes().as_slice(),
            to_i64(sequence)?,
            kind,
            prior_state,
            resulting_state,
            event_digest.as_slice(),
            reason,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn activation_digest(command: &ActivateFederationSuccessor) -> [u8; 32] {
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

fn validate_reason(reason: &str) -> Result<(), RepositoryError> {
    if reason.is_empty()
        || reason.len() > MAXIMUM_REASON_BYTES
        || reason.chars().any(char::is_control)
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn load_succession(
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

fn verify_active_evidence(
    connection: &Connection,
    stored: &StoredSuccession,
) -> Result<(), RepositoryError> {
    let (ancestry, acceptance_digest) = verify_signed_agreement(connection, stored)?;
    verify_activation_event(connection, stored, acceptance_digest)?;
    ensure_graph_acyclic(connection, None, &ancestry).map_err(|_| RepositoryError::CorruptState)
}

fn verify_signed_agreement(
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

fn verify_designation_evidence(
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

fn load_ancestry(
    connection: &Connection,
    succession_id: FederationSuccessionId,
) -> Result<Vec<FederationSuccessionEdge>, RepositoryError> {
    let mut statement = connection.prepare(
        "SELECT edge_sequence, retiring_mesh_id, successor_mesh_id
         FROM federation_ownership_succession_ancestry
         WHERE succession_id = ?1 ORDER BY edge_sequence",
    )?;
    let rows = statement.query_map([succession_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut ancestry = Vec::new();
    for (expected, row) in rows.enumerate() {
        let row = row?;
        if positive_or_zero(row.0)?
            != u64::try_from(expected).map_err(|_| RepositoryError::CorruptState)?
        {
            return Err(RepositoryError::CorruptState);
        }
        ancestry.push(FederationSuccessionEdge {
            retiring_mesh_id: parse_mesh(&row.1)?,
            successor_mesh_id: parse_mesh(&row.2)?,
        });
    }
    Ok(ancestry)
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

const fn state_code(state: FederationSuccessionState) -> i64 {
    match state {
        FederationSuccessionState::Designated => SUCCESSION_DESIGNATED,
        FederationSuccessionState::Accepted => SUCCESSION_ACCEPTED,
        FederationSuccessionState::Active => SUCCESSION_ACTIVE,
        FederationSuccessionState::Revoked => SUCCESSION_REVOKED,
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

fn positive_or_zero(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}
