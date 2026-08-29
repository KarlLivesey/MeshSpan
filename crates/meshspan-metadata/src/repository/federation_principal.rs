// SPDX-License-Identifier: GPL-2.0-only

//! Signed monotonic home-swarm principal projection persistence and typed reads.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use meshspan_domain::{FederatedPrincipal, FederationRelationshipId, MeshId, Revision};
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    AuthoritativeCommand, CommandContext, FederatedPrincipalKind, FederatedPrincipalState,
    PartitionDatabase, RecordName, UpsertFederatedPrincipalProjection,
};

const RELATIONSHIP_ACTIVE: i64 = 2;
const RELATIONSHIP_RESTRICTED: i64 = 3;
const REMOTE_IDENTITY_OWNER: i64 = 2;

/// Current remote principal state plus the exact signed home-swarm revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederatedPrincipalProjectionRecord {
    /// Direct relationship carrying this projection.
    pub relationship_id: FederationRelationshipId,
    /// Globally qualified remote principal.
    pub principal: FederatedPrincipal,
    /// User, group or service.
    pub kind: FederatedPrincipalKind,
    /// Display-only name.
    pub display_name: String,
    /// Canonical home-swarm name.
    pub canonical_name: String,
    /// Current home-swarm lifecycle.
    pub state: FederatedPrincipalState,
    /// Strictly monotonic home-swarm revision.
    pub identity_revision: u64,
    /// Exact relationship authority epoch carrying the statement.
    pub authority_epoch: u64,
    /// Last local authoritative revision.
    pub revision: Revision,
}

pub(super) fn is_command(command: &AuthoritativeCommand) -> bool {
    matches!(
        command,
        AuthoritativeCommand::UpsertFederatedPrincipalProjection(_)
    )
}

pub(super) fn execute(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    match command {
        AuthoritativeCommand::UpsertFederatedPrincipalProjection(value) => {
            upsert(transaction, context, value, revision)
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

fn upsert(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &UpsertFederatedPrincipalProjection,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_statement(transaction, command)?;
    let current_revision = current_identity_revision(transaction, command)?;
    if current_revision.is_some_and(|current| command.identity_revision <= current) {
        return Err(RepositoryError::InvalidCommand);
    }
    let statement_digest: [u8; 32] = Sha256::digest(command.signing_payload()).into();
    insert_history(transaction, context, command, statement_digest, revision)?;
    upsert_current(transaction, context, command, statement_digest, revision)?;
    Ok(EntityReference {
        kind: EntityKind::FederatedPrincipalProjection,
        id: command.principal_id.as_bytes(),
    })
}

fn validate_statement(
    transaction: &Transaction<'_>,
    command: &UpsertFederatedPrincipalProjection,
) -> Result<(), RepositoryError> {
    if command.identity_revision == 0
        || command.authority_epoch == 0
        || command.signer_generation == 0
    {
        return Err(RepositoryError::InvalidCommand);
    }
    verify_relationship(transaction, command)?;
    verify_signature(transaction, command, true)
}

fn verify_relationship(
    connection: &rusqlite::Connection,
    command: &UpsertFederatedPrincipalProjection,
) -> Result<(), RepositoryError> {
    let relationship = connection
        .query_row(
            "SELECT remote_mesh_id, state, authority_epoch
             FROM federation_relationships WHERE relationship_id = ?1",
            [command.relationship_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    if !matches!(
        relationship.1,
        RELATIONSHIP_ACTIVE | RELATIONSHIP_RESTRICTED
    ) || positive(relationship.2)? != command.authority_epoch
        || parse_mesh(&relationship.0)? != command.home_mesh_id
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn verify_signature(
    connection: &rusqlite::Connection,
    command: &UpsertFederatedPrincipalProjection,
    require_active_key: bool,
) -> Result<(), RepositoryError> {
    let identity: (Vec<u8>, i64) = connection
        .query_row(
            "SELECT verifying_key, state FROM federation_trust_identities
             WHERE relationship_id = ?1 AND identity_owner = ?2 AND generation = ?3",
            params![
                command.relationship_id.as_bytes().as_slice(),
                REMOTE_IDENTITY_OWNER,
                to_i64(command.signer_generation)?,
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    if (require_active_key && identity.1 != 1) || !matches!(identity.1, 1 | 2) {
        return Err(RepositoryError::InvalidCommand);
    }
    let verifying_key = VerifyingKey::from_bytes(
        &identity
            .0
            .as_slice()
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)?;
    verifying_key
        .verify(
            &command.signing_payload(),
            &Signature::from_bytes(&command.signature),
        )
        .map_err(|_| RepositoryError::InvalidCommand)
}

fn current_identity_revision(
    transaction: &Transaction<'_>,
    command: &UpsertFederatedPrincipalProjection,
) -> Result<Option<u64>, RepositoryError> {
    transaction
        .query_row(
            "SELECT identity_revision FROM federation_principal_projections
             WHERE relationship_id = ?1 AND home_mesh_id = ?2 AND principal_id = ?3",
            params![
                command.relationship_id.as_bytes().as_slice(),
                command.home_mesh_id.as_bytes().as_slice(),
                command.principal_id.as_bytes().as_slice(),
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(positive)
        .transpose()
}

fn insert_history(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &UpsertFederatedPrincipalProjection,
    statement_digest: [u8; 32],
    revision: Revision,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "INSERT INTO federation_principal_projection_history(
            relationship_id, home_mesh_id, principal_id, identity_revision,
            principal_kind, display_name, canonical_name, state, authority_epoch,
            statement_digest, signer_generation, signature, accepted_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            command.relationship_id.as_bytes().as_slice(),
            command.home_mesh_id.as_bytes().as_slice(),
            command.principal_id.as_bytes().as_slice(),
            to_i64(command.identity_revision)?,
            command.kind.code(),
            command.name.display(),
            command.name.canonical(),
            command.state.code(),
            to_i64(command.authority_epoch)?,
            statement_digest.as_slice(),
            to_i64(command.signer_generation)?,
            command.signature.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn upsert_current(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &UpsertFederatedPrincipalProjection,
    statement_digest: [u8; 32],
    revision: Revision,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "INSERT INTO federation_principal_projections(
            relationship_id, home_mesh_id, principal_id, principal_kind,
            display_name, canonical_name, state, identity_revision, authority_epoch,
            projection_digest, observed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(relationship_id, home_mesh_id, principal_id) DO UPDATE SET
            principal_kind = excluded.principal_kind,
            display_name = excluded.display_name,
            canonical_name = excluded.canonical_name,
            state = excluded.state,
            identity_revision = excluded.identity_revision,
            authority_epoch = excluded.authority_epoch,
            projection_digest = excluded.projection_digest,
            observed_at = excluded.observed_at,
            revision = excluded.revision",
        params![
            command.relationship_id.as_bytes().as_slice(),
            command.home_mesh_id.as_bytes().as_slice(),
            command.principal_id.as_bytes().as_slice(),
            command.kind.code(),
            command.name.display(),
            command.name.canonical(),
            command.state.code(),
            to_i64(command.identity_revision)?,
            to_i64(command.authority_epoch)?,
            statement_digest.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

pub(super) fn projection(
    database: &PartitionDatabase,
    relationship_id: FederationRelationshipId,
    principal: FederatedPrincipal,
) -> Result<Option<FederatedPrincipalProjectionRecord>, RepositoryError> {
    let row = database
        .connection()
        .query_row(
            "SELECT principal_kind, display_name, canonical_name, state,
                    identity_revision, authority_epoch, projection_digest, revision
             FROM federation_principal_projections
             WHERE relationship_id = ?1 AND home_mesh_id = ?2 AND principal_id = ?3",
            params![
                relationship_id.as_bytes().as_slice(),
                principal.home_mesh_id().as_bytes().as_slice(),
                principal.principal_id().as_bytes().as_slice(),
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?;
    row.map(|row| {
        let record = FederatedPrincipalProjectionRecord {
            relationship_id,
            principal,
            kind: parse_kind(row.0)?,
            display_name: row.1,
            canonical_name: row.2,
            state: parse_state(row.3)?,
            identity_revision: positive(row.4)?,
            authority_epoch: positive(row.5)?,
            revision: Revision::new(positive(row.7)?),
        };
        verify_current_history(database, &record, &row.6)?;
        Ok(record)
    })
    .transpose()
}

fn verify_current_history(
    database: &PartitionDatabase,
    record: &FederatedPrincipalProjectionRecord,
    projection_digest: &[u8],
) -> Result<(), RepositoryError> {
    let history: Option<(Vec<u8>, i64, Vec<u8>)> = database
        .connection()
        .query_row(
            "SELECT statement_digest, signer_generation, signature
             FROM federation_principal_projection_history
             WHERE relationship_id = ?1 AND home_mesh_id = ?2
               AND principal_id = ?3 AND identity_revision = ?4",
            params![
                record.relationship_id.as_bytes().as_slice(),
                record.principal.home_mesh_id().as_bytes().as_slice(),
                record.principal.principal_id().as_bytes().as_slice(),
                to_i64(record.identity_revision)?,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((history_digest, signer_generation, signature)) = history else {
        return Err(RepositoryError::CorruptState);
    };
    let name = RecordName::new(&record.display_name).map_err(|_| RepositoryError::CorruptState)?;
    if name.canonical() != record.canonical_name {
        return Err(RepositoryError::CorruptState);
    }
    let command = UpsertFederatedPrincipalProjection {
        relationship_id: record.relationship_id,
        home_mesh_id: record.principal.home_mesh_id(),
        principal_id: record.principal.principal_id(),
        kind: record.kind,
        name,
        state: record.state,
        identity_revision: record.identity_revision,
        authority_epoch: record.authority_epoch,
        signer_generation: positive(signer_generation)?,
        signature: signature
            .as_slice()
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    };
    let recomputed: [u8; 32] = Sha256::digest(command.signing_payload()).into();
    if projection_digest != recomputed || history_digest.as_slice() != recomputed {
        return Err(RepositoryError::CorruptState);
    }
    verify_relationship(database.connection(), &command)
        .and_then(|()| verify_signature(database.connection(), &command, false))
        .map_err(|_| RepositoryError::CorruptState)
}

fn parse_kind(value: i64) -> Result<FederatedPrincipalKind, RepositoryError> {
    match value {
        1 => Ok(FederatedPrincipalKind::User),
        2 => Ok(FederatedPrincipalKind::Group),
        3 => Ok(FederatedPrincipalKind::Service),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_state(value: i64) -> Result<FederatedPrincipalState, RepositoryError> {
    match value {
        1 => Ok(FederatedPrincipalState::Active),
        2 => Ok(FederatedPrincipalState::Suspended),
        3 => Ok(FederatedPrincipalState::Retired),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_mesh(value: &[u8]) -> Result<MeshId, RepositoryError> {
    let bytes = value
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    MeshId::from_bytes(bytes).map_err(|_| RepositoryError::CorruptState)
}

fn positive(value: i64) -> Result<u64, RepositoryError> {
    let value = u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?;
    if value == 0 {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(value)
    }
}
