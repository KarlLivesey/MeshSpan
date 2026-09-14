// SPDX-License-Identifier: GPL-2.0-only

//! Replicated invitation issuance and cancellation, independent of peer membership.

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    AuthoritativeCommand, CancelFederationPairingInvitation, CommandContext,
    IssueFederationPairingInvitation,
};
use meshspan_domain::{
    FederationPairingIssuance, FederationRelationshipId, MeshId, NodeId, OperationId, PrincipalId,
    Revision, UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

/// Retained invitation state. Expiry is evaluated from the original deadline, not another write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationPairingInvitationState {
    /// Pending connection material; no peer authority exists yet.
    Open,
    /// Explicitly withdrawn by a current administrator.
    Cancelled,
    /// Material was consumed atomically with a retained relationship proposal.
    Consumed,
}

/// Public issuance evidence used to reproduce the exact code after a lost response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationPairingInvitationRecord {
    /// Swarm issuing the material.
    pub mesh_id: MeshId,
    /// Original approving administrator.
    pub issued_by: PrincipalId,
    /// Original API operation, retained independently of cancellation.
    pub issuance_operation_id: OperationId,
    /// Original issuance time.
    pub issued_at: UnixMicros,
    /// Immutable original public command fields.
    pub invitation: IssueFederationPairingInvitation,
    /// Current availability of the connection material.
    pub state: FederationPairingInvitationState,
    /// Current committed record revision.
    pub revision: Revision,
}

pub(super) fn is_command(command: &AuthoritativeCommand) -> bool {
    matches!(
        command,
        AuthoritativeCommand::IssueFederationPairingInvitation(_)
            | AuthoritativeCommand::CancelFederationPairingInvitation(_)
            | AuthoritativeCommand::PrepareFederationConnection(_)
            | AuthoritativeCommand::BeginFederationConnection(_)
    )
}

pub(super) fn execute(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    match command {
        AuthoritativeCommand::BeginFederationConnection(value) => {
            super::federation_connection_intent::begin(transaction, context, value, revision)
        }
        AuthoritativeCommand::PrepareFederationConnection(value) => {
            super::federation_pairing_connection::prepare(transaction, context, value, revision)
        }
        AuthoritativeCommand::IssueFederationPairingInvitation(value) => {
            issue(transaction, context, value, revision)
        }
        AuthoritativeCommand::CancelFederationPairingInvitation(value) => {
            cancel(transaction, value, revision)
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

fn issue(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &IssueFederationPairingInvitation,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let mesh: Vec<u8> =
        transaction.query_row("SELECT mesh_id FROM meshes", [], |row| row.get(0))?;
    let mesh_id = MeshId::from_bytes(exact(mesh)?).map_err(|_| RepositoryError::CorruptState)?;
    validate(
        mesh_id,
        context.actor_principal_id,
        context.operation_id,
        context.occurred_at,
        value,
    )
    .map_err(|_| RepositoryError::InvalidCommand)?;
    let eligible: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM nodes n JOIN node_roles r ON r.node_id = n.node_id
          WHERE n.node_id = ?1 AND n.state = 2 AND n.retired_at IS NULL
            AND r.role_code = 2) AND EXISTS(SELECT 1 FROM secret_generations
          WHERE secret_kind = 3 AND secret_id = ?2 AND generation = ?3)
          AND NOT EXISTS(SELECT 1 FROM federation_relationships WHERE relationship_id = ?4)",
        params![
            value.issuing_node_id.as_bytes().as_slice(),
            mesh_id.as_bytes().as_slice(),
            to_i64(value.issuance_key_generation)?,
            value.relationship_id.as_bytes().as_slice()
        ],
        |row| row.get(0),
    )?;
    if !eligible {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO federation_pairing_invitations(relationship_id, mesh_id, issuing_node_id,
          issued_by, issuance_operation_id, issuance_key_generation, material_verifier, endpoint,
          certificate_fingerprint, issued_at, expires_at, state, revision)
          VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1, ?12)",
        params![
            value.relationship_id.as_bytes().as_slice(),
            mesh_id.as_bytes().as_slice(),
            value.issuing_node_id.as_bytes().as_slice(),
            context.actor_principal_id.as_bytes().as_slice(),
            context.operation_id.as_bytes().as_slice(),
            to_i64(value.issuance_key_generation)?,
            value.material_verifier.as_slice(),
            value.endpoint,
            value.certificate_fingerprint.as_slice(),
            context.occurred_at.get(),
            value.expires_at.get(),
            to_i64(revision.get())?
        ],
    )?;
    Ok(reference(value.relationship_id))
}

fn cancel(
    transaction: &Transaction<'_>,
    value: &CancelFederationPairingInvitation,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if value.reason.trim().is_empty()
        || value.reason.len() > 512
        || value.reason.chars().any(char::is_control)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let current =
        load(transaction, value.relationship_id)?.ok_or(RepositoryError::InvalidCommand)?;
    if current.state != FederationPairingInvitationState::Open
        || current.revision != value.expected_invitation_revision
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let changed = transaction.execute(
        "UPDATE federation_pairing_invitations SET state = 3, cancellation_reason = ?1, revision = ?2
          WHERE relationship_id = ?3 AND state = 1 AND revision = ?4
            AND NOT EXISTS(SELECT 1 FROM federation_relationships WHERE relationship_id = ?3)",
        params![value.reason, to_i64(revision.get())?, value.relationship_id.as_bytes().as_slice(),
            to_i64(value.expected_invitation_revision.get())?],
    )?;
    if changed != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(reference(value.relationship_id))
}

pub(super) fn load(
    connection: &Connection,
    relationship_id: FederationRelationshipId,
) -> Result<Option<FederationPairingInvitationRecord>, RepositoryError> {
    let stored = connection.query_row(
        "SELECT mesh_id, issued_by, issuance_operation_id, issuing_node_id, issuance_key_generation,
            material_verifier, endpoint, certificate_fingerprint, issued_at, expires_at, state, revision,
            cancellation_reason, EXISTS(SELECT 1 FROM federation_pairing_connections WHERE relationship_id = ?1)
            FROM federation_pairing_invitations WHERE relationship_id = ?1",
        [relationship_id.as_bytes().as_slice()],
        |row| Ok(StoredInvitation {
            mesh: row.get(0)?, principal: row.get(1)?, operation: row.get(2)?, node: row.get(3)?,
            key_generation: row.get(4)?, verifier: row.get(5)?, endpoint: row.get(6)?, certificate: row.get(7)?,
            issued_at: row.get(8)?, expires_at: row.get(9)?, state: row.get(10)?, revision: row.get(11)?,
            cancellation_reason: row.get(12)?, consumed: row.get(13)?,
        }),
    ).optional()?;
    stored.map(|row| decode(relationship_id, row)).transpose()
}

struct StoredInvitation {
    mesh: Vec<u8>,
    principal: Vec<u8>,
    operation: Vec<u8>,
    node: Vec<u8>,
    key_generation: i64,
    verifier: Vec<u8>,
    endpoint: String,
    certificate: Vec<u8>,
    issued_at: i64,
    expires_at: i64,
    state: i64,
    revision: i64,
    cancellation_reason: Option<String>,
    consumed: bool,
}

fn decode(
    relationship_id: FederationRelationshipId,
    row: StoredInvitation,
) -> Result<FederationPairingInvitationRecord, RepositoryError> {
    let invalid = |_| RepositoryError::CorruptState;
    let state = match (row.state, row.cancellation_reason, row.consumed) {
        (1, None, false) => FederationPairingInvitationState::Open,
        (1, None, true) => FederationPairingInvitationState::Consumed,
        (3, Some(reason), false)
            if !reason.trim().is_empty()
                && reason.len() <= 512
                && !reason.chars().any(char::is_control) =>
        {
            FederationPairingInvitationState::Cancelled
        }
        _ => return Err(RepositoryError::CorruptState),
    };
    let record = FederationPairingInvitationRecord {
        mesh_id: MeshId::from_bytes(exact(row.mesh)?).map_err(invalid)?,
        issued_by: PrincipalId::from_bytes(exact(row.principal)?).map_err(invalid)?,
        issuance_operation_id: OperationId::from_bytes(exact(row.operation)?).map_err(invalid)?,
        issued_at: UnixMicros::new(row.issued_at),
        invitation: IssueFederationPairingInvitation {
            relationship_id,
            issuing_node_id: NodeId::from_bytes(exact(row.node)?).map_err(invalid)?,
            issuance_key_generation: positive(row.key_generation)?,
            material_verifier: exact(row.verifier)?,
            endpoint: row.endpoint,
            certificate_fingerprint: exact(row.certificate)?,
            expires_at: UnixMicros::new(row.expires_at),
        },
        state,
        revision: Revision::new(positive(row.revision)?),
    };
    validate(
        record.mesh_id,
        record.issued_by,
        record.issuance_operation_id,
        record.issued_at,
        &record.invitation,
    )?;
    Ok(record)
}

fn validate(
    mesh_id: MeshId,
    principal_id: PrincipalId,
    operation_id: OperationId,
    issued_at: UnixMicros,
    value: &IssueFederationPairingInvitation,
) -> Result<(), RepositoryError> {
    FederationPairingIssuance {
        mesh_id,
        principal_id,
        operation_id,
        issued_at,
        expires_at: value.expires_at,
        endpoint: &value.endpoint,
        certificate_fingerprint: value.certificate_fingerprint,
    }
    .validate()
    .map_err(|_| RepositoryError::CorruptState)?;
    if value.material_verifier == [0; 32] || value.issuance_key_generation == 0 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(())
}

fn exact<const N: usize>(value: Vec<u8>) -> Result<[u8; N], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn positive(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::CorruptState)
}

const fn reference(relationship_id: FederationRelationshipId) -> EntityReference {
    EntityReference {
        kind: EntityKind::FederationPairingInvitation,
        id: relationship_id.as_bytes(),
    }
}
