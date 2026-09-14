// SPDX-License-Identifier: GPL-2.0-only

//! Atomic consumption/proposal and retained public connection material for autonomous swarms.

use super::{EntityReference, RepositoryError, apply::to_i64};
use crate::{
    AuthoritativeCommand, CommandContext, FederationGovernanceDirection,
    FederationPairingInvitationState, PrepareFederationConnection, ProposeFederationRelationship,
};
use meshspan_domain::{
    FederationRelationshipId, FederationRelationshipKind, MeshId, OperationId, PrincipalId,
    Revision, UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

/// Durable input to the separate approval and connection-reconciliation steps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationPairingConnectionRecord {
    /// Exact signed peers and original invitation binding.
    pub connection: PrepareFederationConnection,
    /// Local administrator authorising this side.
    pub prepared_by: PrincipalId,
    /// Exact preparation operation, distinct from subsequent approval.
    pub operation_id: OperationId,
    /// Original preparation time.
    pub prepared_at: UnixMicros,
    /// Original preparation revision; approval advances the relationship independently.
    pub revision: Revision,
}

pub(super) fn prepare(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &PrepareFederationConnection,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate(value, context.occurred_at).map_err(|_| RepositoryError::InvalidCommand)?;
    let local_mesh: Vec<u8> =
        transaction.query_row("SELECT mesh_id FROM meshes", [], |row| row.get(0))?;
    if local_mesh != value.local.peer.mesh_id.as_bytes() {
        return Err(RepositoryError::InvalidCommand);
    }
    let local_node: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM nodes n JOIN node_roles r ON n.node_id = r.node_id
          WHERE n.node_id = ?1 AND n.state = 2 AND n.retired_at IS NULL AND r.role_code = 2)",
        [value.local.peer.node_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if !local_node {
        return Err(RepositoryError::InvalidCommand);
    }
    if let Some(expected) = value.expected_invitation_revision {
        let invitation = super::federation_pairing::load(transaction, value.relationship_id)?
            .ok_or(RepositoryError::InvalidCommand)?;
        if invitation.state != FederationPairingInvitationState::Open
            || invitation.revision != expected
            || invitation.issued_by != context.actor_principal_id
            || invitation.mesh_id != value.inviting_mesh_id
            || invitation.invitation.issuing_node_id != value.local.peer.node_id
            || invitation.invitation.material_verifier != value.material_verifier
            || context.occurred_at.get() < invitation.issued_at.get()
            || context.occurred_at.get() >= invitation.invitation.expires_at.get()
        {
            return Err(RepositoryError::InvalidCommand);
        }
    } else {
        let intent = super::federation_connection_intent::load(transaction, value.relationship_id)?
            .ok_or(RepositoryError::InvalidCommand)?;
        if intent.actor_id != context.actor_principal_id
            || intent.intent.local != value.local
            || intent.intent.inviting_mesh_id != value.inviting_mesh_id
            || intent.intent.material_verifier != value.material_verifier
            || intent.intent.remote_endpoint != value.remote.peer.endpoint
            || context.occurred_at.get() < intent.started_at.get()
            || context.occurred_at.get() >= intent.intent.expires_at.get()
        {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    let result = super::federation_relationship::execute(
        transaction,
        context,
        &AuthoritativeCommand::ProposeFederationRelationship(ProposeFederationRelationship {
            relationship_id: value.relationship_id,
            remote_mesh_id: value.remote.peer.mesh_id,
            remote_name: value.remote.peer.name.clone(),
            kind: FederationRelationshipKind::Horizontal,
            governance_direction: FederationGovernanceDirection::None,
        }),
        revision,
    )?;
    transaction.execute("INSERT INTO federation_pairing_connections(relationship_id, inviting_mesh_id,
        material_verifier, consumed_invitation_revision, local_node_id, local_peer, remote_peer,
        prepared_by, preparation_operation_id, prepared_at, revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![value.relationship_id.as_bytes().as_slice(), value.inviting_mesh_id.as_bytes().as_slice(),
            value.material_verifier.as_slice(), value.expected_invitation_revision.map(|revision| to_i64(revision.get())).transpose()?,
            value.local.peer.node_id.as_bytes().as_slice(), encode(&value.local)?, encode(&value.remote)?,
            context.actor_principal_id.as_bytes().as_slice(), context.operation_id.as_bytes().as_slice(), context.occurred_at.get(), to_i64(revision.get())?])?;
    Ok(result)
}

pub(super) fn load(
    connection: &Connection,
    id: FederationRelationshipId,
) -> Result<Option<FederationPairingConnectionRecord>, RepositoryError> {
    let stored = connection.query_row("SELECT inviting_mesh_id, material_verifier, consumed_invitation_revision,
        local_peer, remote_peer, prepared_by, preparation_operation_id, prepared_at, revision, local_node_id
        FROM federation_pairing_connections WHERE relationship_id = ?1", [id.as_bytes().as_slice()],
        |row| Ok(Stored { inviter: row.get(0)?, verifier: row.get(1)?, consumed: row.get(2)?, local: row.get(3)?, remote: row.get(4)?,
            actor: row.get(5)?, operation: row.get(6)?, at: row.get(7)?, revision: row.get(8)?, node: row.get(9)? })).optional()?;
    stored.map(|row| decode(id, row)).transpose()
}

pub(super) fn page(
    connection: &Connection,
    node: meshspan_domain::NodeId,
    after: Option<FederationRelationshipId>,
    limit: super::PageLimit,
) -> Result<super::Page<FederationPairingConnectionRecord, FederationRelationshipId>, RepositoryError>
{
    if !eligible_node(connection, node)? {
        return Ok(super::Page {
            items: Vec::new(),
            next: None,
        });
    }
    let mut statement = connection.prepare(
        "SELECT c.relationship_id FROM federation_pairing_connections c
         JOIN federation_relationships r ON c.relationship_id = r.relationship_id
         WHERE c.local_node_id = ?1 AND c.relationship_id > ?2 AND r.state IN (2, 3)
         ORDER BY c.relationship_id LIMIT ?3",
    )?;
    let ids = statement
        .query_map(
            params![
                node.as_bytes().as_slice(),
                after
                    .map_or([0; 16], FederationRelationshipId::as_bytes)
                    .as_slice(),
                to_i64((limit.get() + 1) as u64)?
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let more = ids.len() > limit.get();
    let mut items = Vec::with_capacity(limit.get().min(ids.len()));
    for id in ids.into_iter().take(limit.get()) {
        let id = FederationRelationshipId::from_bytes(exact(id)?)
            .map_err(|_| RepositoryError::CorruptState)?;
        let record = load(connection, id)?.ok_or(RepositoryError::CorruptState)?;
        if record.connection.local.peer.node_id != node {
            return Err(RepositoryError::CorruptState);
        }
        items.push(record);
    }
    let next = if more {
        items.last().map(|record| record.connection.relationship_id)
    } else {
        None
    };
    Ok(super::Page { items, next })
}

pub(super) fn hosted(
    connection: &Connection,
    node: meshspan_domain::NodeId,
    id: FederationRelationshipId,
) -> Result<Option<FederationPairingConnectionRecord>, RepositoryError> {
    if !eligible_node(connection, node)? {
        return Ok(None);
    }
    Ok(load(connection, id)?.filter(|record| record.connection.local.peer.node_id == node))
}

fn eligible_node(
    connection: &Connection,
    node: meshspan_domain::NodeId,
) -> Result<bool, RepositoryError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM nodes n JOIN node_roles r ON n.node_id = r.node_id
        WHERE n.node_id = ?1 AND n.state = 2 AND n.retired_at IS NULL AND r.role_code = 2)",
        [node.as_bytes().as_slice()],
        |row| row.get(0),
    )?)
}

struct Stored {
    inviter: Vec<u8>,
    verifier: Vec<u8>,
    consumed: Option<i64>,
    local: Vec<u8>,
    remote: Vec<u8>,
    actor: Vec<u8>,
    operation: Vec<u8>,
    at: i64,
    revision: i64,
    node: Vec<u8>,
}

fn decode(
    id: FederationRelationshipId,
    row: Stored,
) -> Result<FederationPairingConnectionRecord, RepositoryError> {
    let record = FederationPairingConnectionRecord {
        connection: PrepareFederationConnection {
            relationship_id: id,
            inviting_mesh_id: MeshId::from_bytes(exact(row.inviter)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            material_verifier: exact(row.verifier)?,
            expected_invitation_revision: row.consumed.map(revision).transpose()?,
            local: crate::decode_federation_pairing_peer(&row.local)
                .map_err(|_| RepositoryError::CorruptState)?,
            remote: crate::decode_federation_pairing_peer(&row.remote)
                .map_err(|_| RepositoryError::CorruptState)?,
        },
        prepared_by: PrincipalId::from_bytes(exact(row.actor)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        operation_id: OperationId::from_bytes(exact(row.operation)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        prepared_at: UnixMicros::new(row.at),
        revision: revision(row.revision)?,
    };
    if row.node != record.connection.local.peer.node_id.as_bytes() {
        return Err(RepositoryError::CorruptState);
    }
    validate(&record.connection, record.prepared_at)?;
    Ok(record)
}

fn validate(value: &PrepareFederationConnection, now: UnixMicros) -> Result<(), RepositoryError> {
    if value.local.peer.mesh_id == value.remote.peer.mesh_id
        || value.local.peer.verifying_key == value.remote.peer.verifying_key
        || value.local.peer.trust_identity().certificate_fingerprint
            == value.remote.peer.trust_identity().certificate_fingerprint
        || !value.local.verify(
            value.relationship_id,
            value.inviting_mesh_id,
            value.material_verifier,
            now,
        )
        || !value.remote.verify(
            value.relationship_id,
            value.inviting_mesh_id,
            value.material_verifier,
            now,
        )
        || value.inviting_mesh_id
            != if value.expected_invitation_revision.is_some() {
                value.local.peer.mesh_id
            } else {
                value.remote.peer.mesh_id
            }
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(())
}

fn encode(peer: &crate::SignedFederationPairingPeer) -> Result<Vec<u8>, RepositoryError> {
    crate::encode_federation_pairing_peer(peer).map_err(|_| RepositoryError::InvalidCommand)
}

fn exact<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], RepositoryError> {
    bytes.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn revision(value: i64) -> Result<Revision, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .map(Revision::new)
        .ok_or(RepositoryError::CorruptState)
}
