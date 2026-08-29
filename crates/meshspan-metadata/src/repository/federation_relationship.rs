// SPDX-License-Identifier: GPL-2.0-only

//! Atomic relationship lifecycle, governance validation and public identity rotation.

use meshspan_domain::{
    FederationGraph, FederationRelationshipId, FederationRelationshipKind, MeshId, Revision,
};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    ApproveFederationRelationship, AuthoritativeCommand, CommandContext,
    FederationGovernanceDirection, FederationIdentityOwner, FederationTrustIdentity,
    ProposeFederationRelationship, RecoverFederationRelationship, RestrictFederationRelationship,
    RetireFederationRelationship, RevokeFederationRelationship, RotateFederationTrustIdentity,
};

const RELATIONSHIP_PROPOSED: u8 = 1;
const RELATIONSHIP_ACTIVE: u8 = 2;
const RELATIONSHIP_RESTRICTED: u8 = 3;
const RELATIONSHIP_REVOKED: u8 = 4;
const RELATIONSHIP_RETIRED: u8 = 5;
const MAXIMUM_REASON_BYTES: usize = 512;

#[derive(Clone, Copy)]
struct RelationshipState {
    relationship_id: FederationRelationshipId,
    local_mesh_id: MeshId,
    remote_mesh_id: MeshId,
    kind: FederationRelationshipKind,
    direction: FederationGovernanceDirection,
    state: u8,
    authority_epoch: u64,
}

pub(super) fn is_command(command: &AuthoritativeCommand) -> bool {
    matches!(
        command,
        AuthoritativeCommand::ProposeFederationRelationship(_)
            | AuthoritativeCommand::ApproveFederationRelationship(_)
            | AuthoritativeCommand::RotateFederationTrustIdentity(_)
            | AuthoritativeCommand::RestrictFederationRelationship(_)
            | AuthoritativeCommand::RecoverFederationRelationship(_)
            | AuthoritativeCommand::RevokeFederationRelationship(_)
            | AuthoritativeCommand::RetireFederationRelationship(_)
    )
}

pub(super) fn execute(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    match command {
        AuthoritativeCommand::ProposeFederationRelationship(value) => {
            propose(transaction, context, value, revision)
        }
        AuthoritativeCommand::ApproveFederationRelationship(value) => {
            approve(transaction, context, *value, revision)
        }
        AuthoritativeCommand::RotateFederationTrustIdentity(value) => {
            rotate_identity(transaction, context, *value, revision)
        }
        AuthoritativeCommand::RestrictFederationRelationship(value) => {
            restrict(transaction, context, value, revision)
        }
        AuthoritativeCommand::RecoverFederationRelationship(value) => {
            recover(transaction, context, value, revision)
        }
        AuthoritativeCommand::RevokeFederationRelationship(value) => {
            revoke(transaction, context, value, revision)
        }
        AuthoritativeCommand::RetireFederationRelationship(value) => {
            retire(transaction, context, value, revision)
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

fn propose(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ProposeFederationRelationship,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_direction(command.kind, command.governance_direction)?;
    let local_mesh_id = local_mesh_id(transaction)?;
    if local_mesh_id == command.remote_mesh_id {
        return Err(RepositoryError::InvalidCommand);
    }
    let relationship = command.relationship_id.as_bytes();
    transaction.execute(
        "INSERT INTO federation_relationships(
            relationship_id, local_mesh_id, remote_mesh_id, relationship_kind,
            governance_direction, state, authority_epoch, remote_display_name,
            proposed_at, approved_at, restricted_at, revoked_at, retired_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, 1, 1, ?6, ?7,
                   NULL, NULL, NULL, NULL, ?8)",
        params![
            relationship.as_slice(),
            local_mesh_id.as_bytes().as_slice(),
            command.remote_mesh_id.as_bytes().as_slice(),
            relationship_kind_code(command.kind),
            command.governance_direction.code(),
            command.remote_name.display(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    insert_event(
        transaction,
        context,
        command.relationship_id,
        1,
        1,
        None,
        RELATIONSHIP_PROPOSED,
        None,
        revision,
    )?;
    Ok(relationship_reference(command.relationship_id))
}

fn approve(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: ApproveFederationRelationship,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let relationship = load_relationship(transaction, command.relationship_id)?;
    require_state_epoch(
        relationship,
        RELATIONSHIP_PROPOSED,
        command.expected_authority_epoch,
    )?;
    validate_identity_pair(context.occurred_at.get(), command)?;
    insert_identity(
        transaction,
        command.relationship_id,
        FederationIdentityOwner::Local,
        command.local_identity,
        revision,
    )?;
    insert_identity(
        transaction,
        command.relationship_id,
        FederationIdentityOwner::Remote,
        command.remote_identity,
        revision,
    )?;
    if relationship.kind == FederationRelationshipKind::Governance {
        insert_governance_edge(transaction, context, relationship, revision)?;
    }
    let updated = transaction.execute(
        "UPDATE federation_relationships
         SET state = 2, approved_at = ?1, revision = ?2
         WHERE relationship_id = ?3 AND state = 1 AND authority_epoch = ?4",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.relationship_id.as_bytes().as_slice(),
            to_i64(command.expected_authority_epoch)?,
        ],
    )?;
    require_one(updated)?;
    insert_event(
        transaction,
        context,
        command.relationship_id,
        relationship.authority_epoch,
        2,
        Some(RELATIONSHIP_PROPOSED),
        RELATIONSHIP_ACTIVE,
        None,
        revision,
    )?;
    Ok(relationship_reference(command.relationship_id))
}

fn rotate_identity(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: RotateFederationTrustIdentity,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let relationship = load_relationship(transaction, command.relationship_id)?;
    if !matches!(
        relationship.state,
        RELATIONSHIP_ACTIVE | RELATIONSHIP_RESTRICTED
    ) || relationship.authority_epoch != command.expected_authority_epoch
    {
        return Err(RepositoryError::InvalidCommand);
    }
    validate_identity(context.occurred_at.get(), command.identity)?;
    let maximum_generation: i64 = transaction.query_row(
        "SELECT coalesce(max(generation), 0) FROM federation_trust_identities
         WHERE relationship_id = ?1 AND identity_owner = ?2",
        params![
            command.relationship_id.as_bytes().as_slice(),
            command.owner.code()
        ],
        |row| row.get(0),
    )?;
    if command.identity.generation
        <= u64::try_from(maximum_generation).map_err(|_| RepositoryError::CorruptState)?
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let retired = transaction.execute(
        "UPDATE federation_trust_identities
         SET state = 2, retired_at = ?1, revision = ?2
         WHERE relationship_id = ?3 AND identity_owner = ?4 AND state = 1",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.relationship_id.as_bytes().as_slice(),
            command.owner.code(),
        ],
    )?;
    require_one(retired)?;
    insert_identity(
        transaction,
        command.relationship_id,
        command.owner,
        command.identity,
        revision,
    )?;
    Ok(EntityReference {
        kind: EntityKind::FederationTrustIdentity,
        id: command.relationship_id.as_bytes(),
    })
}

fn restrict(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RestrictFederationRelationship,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    transition(
        transaction,
        context,
        command.relationship_id,
        command.expected_authority_epoch,
        command.authority_epoch,
        &[RELATIONSHIP_ACTIVE, RELATIONSHIP_RESTRICTED],
        RELATIONSHIP_RESTRICTED,
        &command.reason,
        "restricted_at = ?1",
        revision,
    )
}

fn recover(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RecoverFederationRelationship,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    transition(
        transaction,
        context,
        command.relationship_id,
        command.expected_authority_epoch,
        command.authority_epoch,
        &[RELATIONSHIP_RESTRICTED],
        RELATIONSHIP_ACTIVE,
        &command.reason,
        "restricted_at = NULL",
        revision,
    )
}

fn revoke(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RevokeFederationRelationship,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let entity = transition(
        transaction,
        context,
        command.relationship_id,
        command.expected_authority_epoch,
        command.authority_epoch,
        &[RELATIONSHIP_ACTIVE, RELATIONSHIP_RESTRICTED],
        RELATIONSHIP_REVOKED,
        &command.reason,
        "revoked_at = ?1",
        revision,
    )?;
    transaction.execute(
        "UPDATE federation_governance_edges
         SET state = 2, revoked_at = ?1, revision = ?2
         WHERE relationship_id = ?3 AND state = 1",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.relationship_id.as_bytes().as_slice()
        ],
    )?;
    transaction.execute(
        "UPDATE federation_trust_identities
         SET state = 3, retired_at = ?1, revision = ?2
         WHERE relationship_id = ?3 AND state = 1",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.relationship_id.as_bytes().as_slice()
        ],
    )?;
    Ok(entity)
}

fn retire(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RetireFederationRelationship,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    transition(
        transaction,
        context,
        command.relationship_id,
        command.expected_authority_epoch,
        command.authority_epoch,
        &[RELATIONSHIP_REVOKED],
        RELATIONSHIP_RETIRED,
        &command.reason,
        "retired_at = ?1",
        revision,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "one transition explicitly binds its complete fenced state change"
)]
fn transition(
    transaction: &Transaction<'_>,
    context: CommandContext,
    relationship_id: FederationRelationshipId,
    expected_epoch: u64,
    next_epoch: u64,
    allowed_states: &[u8],
    next_state: u8,
    reason: &str,
    timestamp_assignment: &str,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_reason(reason)?;
    let relationship = load_relationship(transaction, relationship_id)?;
    if relationship.authority_epoch != expected_epoch
        || next_epoch <= expected_epoch
        || !allowed_states.contains(&relationship.state)
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let sql = format!(
        "UPDATE federation_relationships
         SET state = ?2, authority_epoch = ?3, {timestamp_assignment}, revision = ?4
         WHERE relationship_id = ?5 AND state = ?6 AND authority_epoch = ?7"
    );
    let updated = transaction.execute(
        &sql,
        params![
            context.occurred_at.get(),
            next_state,
            to_i64(next_epoch)?,
            to_i64(revision.get())?,
            relationship_id.as_bytes().as_slice(),
            relationship.state,
            to_i64(expected_epoch)?,
        ],
    )?;
    require_one(updated)?;
    insert_event(
        transaction,
        context,
        relationship_id,
        next_epoch,
        1,
        Some(relationship.state),
        next_state,
        Some(reason),
        revision,
    )?;
    Ok(relationship_reference(relationship_id))
}

fn insert_identity(
    transaction: &Transaction<'_>,
    relationship_id: FederationRelationshipId,
    owner: FederationIdentityOwner,
    identity: FederationTrustIdentity,
    revision: Revision,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "INSERT INTO federation_trust_identities(
            relationship_id, identity_owner, generation, certificate_fingerprint,
            verifying_key, valid_from, valid_until, state, retired_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, NULL, ?8)",
        params![
            relationship_id.as_bytes().as_slice(),
            owner.code(),
            to_i64(identity.generation)?,
            identity.certificate_fingerprint.as_slice(),
            identity.verifying_key.as_slice(),
            identity.valid_from.get(),
            identity.valid_until.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn insert_governance_edge(
    transaction: &Transaction<'_>,
    context: CommandContext,
    relationship: RelationshipState,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let (parent, child) = match relationship.direction {
        FederationGovernanceDirection::LocalGovernsRemote => {
            (relationship.local_mesh_id, relationship.remote_mesh_id)
        }
        FederationGovernanceDirection::RemoteGovernsLocal => {
            (relationship.remote_mesh_id, relationship.local_mesh_id)
        }
        FederationGovernanceDirection::None => return Err(RepositoryError::CorruptState),
    };
    validate_governance_graph(transaction, parent, child)?;
    transaction.execute(
        "INSERT INTO federation_governance_edges(
            relationship_id, parent_mesh_id, child_mesh_id, authority_epoch,
            state, activated_at, revoked_at, revision
         ) VALUES (?1, ?2, ?3, ?4, 1, ?5, NULL, ?6)",
        params![
            relationship.relationship_id.as_bytes().as_slice(),
            parent.as_bytes().as_slice(),
            child.as_bytes().as_slice(),
            to_i64(relationship.authority_epoch)?,
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn validate_governance_graph(
    transaction: &Transaction<'_>,
    proposed_parent: MeshId,
    proposed_child: MeshId,
) -> Result<(), RepositoryError> {
    let mut graph = FederationGraph::new();
    let mut statement = transaction.prepare(
        "SELECT parent_mesh_id, child_mesh_id FROM federation_governance_edges
         WHERE state = 1 ORDER BY child_mesh_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let (parent, child) = row?;
        graph
            .add_governance(parse_mesh_id(&parent)?, parse_mesh_id(&child)?)
            .map_err(|_| RepositoryError::CorruptState)?;
    }
    graph
        .add_governance(proposed_parent, proposed_child)
        .map_err(|_| RepositoryError::InvalidCommand)
}

#[allow(
    clippy::too_many_arguments,
    reason = "immutable lifecycle evidence explicitly names every transition dimension"
)]
fn insert_event(
    transaction: &Transaction<'_>,
    context: CommandContext,
    relationship_id: FederationRelationshipId,
    authority_epoch: u64,
    event_sequence: u64,
    prior_state: Option<u8>,
    resulting_state: u8,
    reason: Option<&str>,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let event_kind = match (prior_state, resulting_state) {
        (None, RELATIONSHIP_PROPOSED) => 1,
        (Some(RELATIONSHIP_PROPOSED), RELATIONSHIP_ACTIVE) => 2,
        (Some(RELATIONSHIP_ACTIVE | RELATIONSHIP_RESTRICTED), RELATIONSHIP_RESTRICTED) => 3,
        (Some(RELATIONSHIP_RESTRICTED), RELATIONSHIP_ACTIVE) => 4,
        (Some(RELATIONSHIP_ACTIVE | RELATIONSHIP_RESTRICTED), RELATIONSHIP_REVOKED) => 5,
        (Some(RELATIONSHIP_REVOKED), RELATIONSHIP_RETIRED) => 6,
        _ => return Err(RepositoryError::InvalidCommand),
    };
    transaction.execute(
        "INSERT INTO federation_relationship_events(
            relationship_id, authority_epoch, event_sequence, event_kind,
            prior_state, resulting_state, reason, changed_by, changed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            relationship_id.as_bytes().as_slice(),
            to_i64(authority_epoch)?,
            to_i64(event_sequence)?,
            event_kind,
            prior_state,
            resulting_state,
            reason,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn load_relationship(
    transaction: &Transaction<'_>,
    relationship_id: FederationRelationshipId,
) -> Result<RelationshipState, RepositoryError> {
    let row = transaction
        .query_row(
            "SELECT local_mesh_id, remote_mesh_id, relationship_kind,
                    governance_direction, state, authority_epoch
             FROM federation_relationships WHERE relationship_id = ?1",
            [relationship_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    Ok(RelationshipState {
        relationship_id,
        local_mesh_id: parse_mesh_id(&row.0)?,
        remote_mesh_id: parse_mesh_id(&row.1)?,
        kind: parse_kind(row.2)?,
        direction: parse_direction(row.3)?,
        state: u8::try_from(row.4).map_err(|_| RepositoryError::CorruptState)?,
        authority_epoch: u64::try_from(row.5).map_err(|_| RepositoryError::CorruptState)?,
    })
}

fn local_mesh_id(transaction: &Transaction<'_>) -> Result<MeshId, RepositoryError> {
    let mut statement =
        transaction.prepare("SELECT mesh_id FROM meshes ORDER BY mesh_id LIMIT 2")?;
    let rows = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    parse_mesh_id(&rows[0])
}

fn validate_direction(
    kind: FederationRelationshipKind,
    direction: FederationGovernanceDirection,
) -> Result<(), RepositoryError> {
    match (kind, direction) {
        (FederationRelationshipKind::Horizontal, FederationGovernanceDirection::None)
        | (
            FederationRelationshipKind::Governance,
            FederationGovernanceDirection::LocalGovernsRemote
            | FederationGovernanceDirection::RemoteGovernsLocal,
        ) => Ok(()),
        _ => Err(RepositoryError::InvalidCommand),
    }
}

fn validate_identity_pair(
    now: i64,
    command: ApproveFederationRelationship,
) -> Result<(), RepositoryError> {
    validate_identity(now, command.local_identity)?;
    validate_identity(now, command.remote_identity)?;
    if command.local_identity.certificate_fingerprint
        == command.remote_identity.certificate_fingerprint
        || command.local_identity.verifying_key == command.remote_identity.verifying_key
    {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(())
}

fn validate_identity(now: i64, identity: FederationTrustIdentity) -> Result<(), RepositoryError> {
    if identity.generation == 0
        || identity.certificate_fingerprint == [0; 32]
        || identity.verifying_key == [0; 32]
        || identity.valid_from.get() > now
        || identity.valid_until.get() <= now
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn validate_reason(reason: &str) -> Result<(), RepositoryError> {
    if reason.trim().is_empty()
        || reason.len() > MAXIMUM_REASON_BYTES
        || reason.chars().any(char::is_control)
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn require_state_epoch(
    relationship: RelationshipState,
    state: u8,
    epoch: u64,
) -> Result<(), RepositoryError> {
    if relationship.state == state && relationship.authority_epoch == epoch {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn require_one(changed: usize) -> Result<(), RepositoryError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

const fn relationship_kind_code(kind: FederationRelationshipKind) -> u8 {
    match kind {
        FederationRelationshipKind::Horizontal => 1,
        FederationRelationshipKind::Governance => 2,
    }
}

fn parse_kind(value: i64) -> Result<FederationRelationshipKind, RepositoryError> {
    match value {
        1 => Ok(FederationRelationshipKind::Horizontal),
        2 => Ok(FederationRelationshipKind::Governance),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_direction(value: i64) -> Result<FederationGovernanceDirection, RepositoryError> {
    match value {
        0 => Ok(FederationGovernanceDirection::None),
        1 => Ok(FederationGovernanceDirection::LocalGovernsRemote),
        2 => Ok(FederationGovernanceDirection::RemoteGovernsLocal),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_mesh_id(value: &[u8]) -> Result<MeshId, RepositoryError> {
    let bytes = value
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    MeshId::from_bytes(bytes).map_err(|_| RepositoryError::CorruptState)
}

fn relationship_reference(relationship_id: FederationRelationshipId) -> EntityReference {
    EntityReference {
        kind: EntityKind::FederationRelationship,
        id: relationship_id.as_bytes(),
    }
}
