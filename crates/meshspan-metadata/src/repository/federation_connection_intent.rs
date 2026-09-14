// SPDX-License-Identifier: GPL-2.0-only

//! Exact outbound intent retained before the peer can consume its invitation.

use super::{EntityKind, EntityReference, RepositoryError, apply::to_i64};
use crate::{BeginFederationConnection, CommandContext};
use meshspan_domain::{
    FederationRelationshipId, MeshId, OperationId, PrincipalId, Revision, UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

/// Immutable local input to a retryable outbound pairing attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationConnectionIntentRecord {
    /// Exact public input; the caller must present the matching secret again on retry.
    pub intent: BeginFederationConnection,
    /// Administrator who authorised this attempt.
    pub actor_id: PrincipalId,
    /// Original local operation.
    pub operation_id: OperationId,
    /// Original admission time, retained for exact command replay.
    pub started_at: UnixMicros,
    /// Committed intent revision; not relationship approval.
    pub revision: Revision,
}

pub(super) fn begin(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &BeginFederationConnection,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate(value, context.occurred_at).map_err(|_| RepositoryError::InvalidCommand)?;
    let eligible: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM meshes WHERE mesh_id = ?1)
         AND EXISTS(SELECT 1 FROM nodes n JOIN node_roles r ON n.node_id = r.node_id
           WHERE n.node_id = ?2 AND n.state = 2 AND n.retired_at IS NULL AND r.role_code = 2)
         AND NOT EXISTS(SELECT 1 FROM federation_relationships WHERE relationship_id = ?3)",
        params![
            value.local.peer.mesh_id.as_bytes().as_slice(),
            value.local.peer.node_id.as_bytes().as_slice(),
            value.relationship_id.as_bytes().as_slice()
        ],
        |row| row.get(0),
    )?;
    if !eligible {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO federation_connection_intents(relationship_id, operation_id, actor_id, node_id,
          inviting_mesh_id, material_verifier, remote_endpoint, certificate_fingerprint, expires_at,
          local_peer, started_at, revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![value.relationship_id.as_bytes().as_slice(), context.operation_id.as_bytes().as_slice(),
            context.actor_principal_id.as_bytes().as_slice(), value.local.peer.node_id.as_bytes().as_slice(),
            value.inviting_mesh_id.as_bytes().as_slice(), value.material_verifier.as_slice(), value.remote_endpoint,
            value.certificate_fingerprint.as_slice(), value.expires_at.get(),
            crate::encode_federation_pairing_peer(&value.local).map_err(|_| RepositoryError::InvalidCommand)?,
            context.occurred_at.get(), to_i64(revision.get())?],
    )?;
    Ok(EntityReference {
        kind: EntityKind::FederationPairingInvitation,
        id: value.relationship_id.as_bytes(),
    })
}

pub(super) fn load(
    connection: &Connection,
    id: FederationRelationshipId,
) -> Result<Option<FederationConnectionIntentRecord>, RepositoryError> {
    let stored = connection
        .query_row(
            "SELECT operation_id, actor_id, node_id, inviting_mesh_id, material_verifier,
          remote_endpoint, certificate_fingerprint, expires_at, local_peer, started_at, revision
          FROM federation_connection_intents WHERE relationship_id = ?1",
            [id.as_bytes().as_slice()],
            |row| {
                Ok(Stored {
                    operation: row.get(0)?,
                    actor: row.get(1)?,
                    node: row.get(2)?,
                    inviter: row.get(3)?,
                    verifier: row.get(4)?,
                    endpoint: row.get(5)?,
                    fingerprint: row.get(6)?,
                    expires: row.get(7)?,
                    local: row.get(8)?,
                    at: row.get(9)?,
                    revision: row.get(10)?,
                })
            },
        )
        .optional()?;
    stored.map(|value| decode(id, value)).transpose()
}

struct Stored {
    operation: Vec<u8>,
    actor: Vec<u8>,
    node: Vec<u8>,
    inviter: Vec<u8>,
    verifier: Vec<u8>,
    endpoint: String,
    fingerprint: Vec<u8>,
    expires: i64,
    local: Vec<u8>,
    at: i64,
    revision: i64,
}

fn decode(
    id: FederationRelationshipId,
    stored: Stored,
) -> Result<FederationConnectionIntentRecord, RepositoryError> {
    let record = FederationConnectionIntentRecord {
        intent: BeginFederationConnection {
            relationship_id: id,
            inviting_mesh_id: MeshId::from_bytes(exact(stored.inviter)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            material_verifier: exact(stored.verifier)?,
            remote_endpoint: stored.endpoint,
            certificate_fingerprint: exact(stored.fingerprint)?,
            expires_at: UnixMicros::new(stored.expires),
            local: crate::decode_federation_pairing_peer(&stored.local)
                .map_err(|_| RepositoryError::CorruptState)?,
        },
        actor_id: PrincipalId::from_bytes(exact(stored.actor)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        operation_id: OperationId::from_bytes(exact(stored.operation)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        started_at: UnixMicros::new(stored.at),
        revision: Revision::new(
            u64::try_from(stored.revision).map_err(|_| RepositoryError::CorruptState)?,
        ),
    };
    if record.revision.get() == 0 || stored.node != record.intent.local.peer.node_id.as_bytes() {
        return Err(RepositoryError::CorruptState);
    }
    validate(&record.intent, record.started_at)?;
    Ok(record)
}

fn validate(value: &BeginFederationConnection, now: UnixMicros) -> Result<(), RepositoryError> {
    if now.get() < 0
        || value.local.peer.mesh_id == value.inviting_mesh_id
        || value.certificate_fingerprint == [0; 32]
        || !meshspan_domain::is_valid_federation_endpoint(&value.remote_endpoint)
        || value.expires_at.get() <= now.get()
        || value.expires_at.get().saturating_sub(now.get()) > 3_600_000_000
        || !value.local.verify(
            value.relationship_id,
            value.inviting_mesh_id,
            value.material_verifier,
            now,
        )
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(())
}

fn exact<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], RepositoryError> {
    bytes.try_into().map_err(|_| RepositoryError::CorruptState)
}
