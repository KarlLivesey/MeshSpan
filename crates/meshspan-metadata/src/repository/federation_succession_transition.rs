// SPDX-License-Identifier: GPL-2.0-only

//! Two-sided recovery-succession transitions and acyclic authority fencing.

use meshspan_domain::{FederationRelationshipId, FederationSuccessionId, MeshId, Revision};
use rusqlite::{Connection, Transaction, params};
use sha2::{Digest, Sha256};

use super::apply::to_i64;
use super::federation_succession_evidence::{
    FederationSuccessionState, SUCCESSION_ACCEPTED, SUCCESSION_ACTIVE, SUCCESSION_DESIGNATED,
    SUCCESSION_REVOKED, StoredSuccession, activation_digest, load_succession, state_code,
    validate_reason, verify_designation_evidence, verify_signed_agreement,
};
use super::federation_succession_graph::{
    MAXIMUM_ANCESTRY_EDGES, ensure_active_graph_acyclic, persist_ancestry, verify_ancestry,
};
use super::federation_succession_trust::{relationship, validate_common, verify_side_signature};
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    AcceptFederationSuccessor, ActivateFederationSuccessor, AuthoritativeCommand, CommandContext,
    DesignateFederationSuccessor, RevokeFederationSuccessorDesignation,
};

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

fn positive_or_zero(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}
