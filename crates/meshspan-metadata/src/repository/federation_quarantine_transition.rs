// SPDX-License-Identifier: GPL-2.0-only

//! Atomic lifecycle transitions for federated mutation quarantine.

use meshspan_domain::{
    FederatedMutationAdmission, MeshId, QuarantineId, QuarantineReason, Revision,
};
use rusqlite::{Transaction, params};
use sha2::{Digest, Sha256};

use super::apply::to_i64;
use super::federation_quarantine::FederationQuarantineState;
use super::federation_quarantine_codec::{reason_code, resource_columns};
use super::federation_quarantine_evidence::load_verified_required;
use super::federation_succession_trust::verify_side_signature;
use super::{RepositoryError, federation_grant};
use crate::{
    AuthoritativeCommand, CommandContext, FederationQuarantineResolution,
    ResolveFederatedMutationQuarantine, RetainFederatedMutationQuarantine,
    SurfaceFederatedMutationQuarantine,
};

const MAXIMUM_REASON_BYTES: usize = 1_024;
pub(super) const QUARANTINE_RETAINED: i64 = 1;
pub(super) const QUARANTINE_SURFACED: i64 = 2;
pub(super) const QUARANTINE_RESTORED: i64 = 3;
pub(super) const QUARANTINE_DISCARDED: i64 = 4;

pub(super) fn execute(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AuthoritativeCommand,
    revision: Revision,
) -> Result<QuarantineId, RepositoryError> {
    match command {
        AuthoritativeCommand::RetainFederatedMutationQuarantine(value) => {
            retain(transaction, context, value, revision)?;
            Ok(value.quarantine_id)
        }
        AuthoritativeCommand::SurfaceFederatedMutationQuarantine(value) => {
            surface(transaction, context, *value, revision)?;
            Ok(value.quarantine_id)
        }
        AuthoritativeCommand::ResolveFederatedMutationQuarantine(value) => {
            resolve(transaction, context, value, revision)?;
            Ok(value.quarantine_id)
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

fn retain(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RetainFederatedMutationQuarantine,
    revision: Revision,
) -> Result<(), RepositoryError> {
    if command.source_operation_id == context.operation_id
        || command.signer_generation == 0
        || command.evidence.accepted_at() > context.occurred_at
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let reason = classify_for_command(transaction, command.evidence)?;
    let signer_mesh_id = command.evidence.subject().home_mesh_id();
    verify_side_signature(
        transaction,
        command.evidence.relationship_id(),
        signer_mesh_id,
        command.signer_generation,
        &command.signing_payload(),
        command.signature,
        false,
    )?;
    let acknowledgement_digest: [u8; 32] = Sha256::digest(command.signing_payload()).into();
    insert_quarantine(
        transaction,
        command,
        reason,
        acknowledgement_digest,
        revision,
    )?;
    insert_acknowledgement(
        transaction,
        command,
        signer_mesh_id,
        acknowledgement_digest,
        revision,
    )?;
    insert_event(
        transaction,
        context,
        command.quarantine_id,
        EventTransition::RETAINED,
        None,
        revision,
    )
}

fn classify_for_command(
    transaction: &Transaction<'_>,
    evidence: meshspan_domain::FederatedMutationEvidence,
) -> Result<QuarantineReason, RepositoryError> {
    match federation_grant::classify_persisted_mutation(transaction, evidence)? {
        FederatedMutationAdmission::Quarantined(reason) => Ok(reason),
        FederatedMutationAdmission::Admitted => Err(RepositoryError::InvalidCommand),
    }
}

fn insert_quarantine(
    transaction: &Transaction<'_>,
    command: &RetainFederatedMutationQuarantine,
    reason: QuarantineReason,
    acknowledgement_digest: [u8; 32],
    revision: Revision,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "INSERT INTO federation_quarantine(
            quarantine_id, relationship_id, operation_id, grant_id,
            subject_home_mesh_id, subject_principal_id, accepted_at, reason_kind,
            payload_digest, acknowledgement_digest, state, surfaced_at, resolved_at,
            resolution_kind, resolution_operation_id, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                   NULL, NULL, NULL, NULL, ?12)",
        params![
            command.quarantine_id.as_bytes().as_slice(),
            command.evidence.relationship_id().as_bytes().as_slice(),
            command.source_operation_id.as_bytes().as_slice(),
            command.evidence.grant_id().as_bytes().as_slice(),
            command
                .evidence
                .subject()
                .home_mesh_id()
                .as_bytes()
                .as_slice(),
            command
                .evidence
                .subject()
                .principal_id()
                .as_bytes()
                .as_slice(),
            command.evidence.accepted_at().get(),
            reason_code(reason),
            command.payload_digest.as_slice(),
            acknowledgement_digest.as_slice(),
            QUARANTINE_RETAINED,
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn insert_acknowledgement(
    transaction: &Transaction<'_>,
    command: &RetainFederatedMutationQuarantine,
    signer_mesh_id: MeshId,
    acknowledgement_digest: [u8; 32],
    revision: Revision,
) -> Result<(), RepositoryError> {
    let (kind, authority, volume, object) = resource_columns(command.evidence.resource());
    let recomputed: [u8; 32] = Sha256::digest(command.signing_payload()).into();
    if acknowledgement_digest != recomputed {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO federation_quarantine_acknowledgements(
            quarantine_id, signer_mesh_id, signer_generation, signature, authority_epoch,
            required_rights, storage_bytes, resource_kind, authority_mesh_id,
            volume_id, object_id, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            command.quarantine_id.as_bytes().as_slice(),
            signer_mesh_id.as_bytes().as_slice(),
            to_i64(command.signer_generation)?,
            command.signature.as_slice(),
            to_i64(command.evidence.authority_epoch())?,
            i64::from(command.evidence.required_rights().bits()),
            to_i64(command.evidence.storage_bytes())?,
            kind,
            authority.as_bytes().as_slice(),
            volume,
            object,
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

fn surface(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: SurfaceFederatedMutationQuarantine,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let stored = load_verified_required(transaction, command.quarantine_id)?;
    if stored.record.source_operation_id != command.source_operation_id
        || stored.record.state != FederationQuarantineState::Retained
    {
        return Err(RepositoryError::InvalidCommand);
    }
    require_one(transaction.execute(
        "UPDATE federation_quarantine
         SET state = ?1, surfaced_at = ?2, revision = ?3
         WHERE quarantine_id = ?4 AND operation_id = ?5 AND state = ?6",
        params![
            QUARANTINE_SURFACED,
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.quarantine_id.as_bytes().as_slice(),
            command.source_operation_id.as_bytes().as_slice(),
            QUARANTINE_RETAINED,
        ],
    )?)?;
    insert_event(
        transaction,
        context,
        command.quarantine_id,
        EventTransition::SURFACED,
        None,
        revision,
    )
}

fn resolve(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ResolveFederatedMutationQuarantine,
    revision: Revision,
) -> Result<(), RepositoryError> {
    validate_reason(&command.reason)?;
    let stored = load_verified_required(transaction, command.quarantine_id)?;
    if stored.record.source_operation_id != command.source_operation_id
        || stored.record.state != FederationQuarantineState::Surfaced
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let transition = EventTransition::resolution(command.resolution);
    require_one(transaction.execute(
        "UPDATE federation_quarantine
         SET state = ?1, resolved_at = ?2, resolution_kind = ?3,
             resolution_operation_id = ?4, revision = ?5
         WHERE quarantine_id = ?6 AND operation_id = ?7 AND state = ?8",
        params![
            transition.resulting_state,
            context.occurred_at.get(),
            command.resolution.code(),
            context.operation_id.as_bytes().as_slice(),
            to_i64(revision.get())?,
            command.quarantine_id.as_bytes().as_slice(),
            command.source_operation_id.as_bytes().as_slice(),
            QUARANTINE_SURFACED,
        ],
    )?)?;
    insert_event(
        transaction,
        context,
        command.quarantine_id,
        transition,
        Some(&command.reason),
        revision,
    )
}

#[derive(Clone, Copy)]
struct EventTransition {
    sequence: u64,
    kind: i64,
    prior_state: Option<i64>,
    resulting_state: i64,
}

impl EventTransition {
    const RETAINED: Self = Self {
        sequence: 1,
        kind: 1,
        prior_state: None,
        resulting_state: QUARANTINE_RETAINED,
    };
    const SURFACED: Self = Self {
        sequence: 2,
        kind: 2,
        prior_state: Some(QUARANTINE_RETAINED),
        resulting_state: QUARANTINE_SURFACED,
    };

    const fn resolution(resolution: FederationQuarantineResolution) -> Self {
        match resolution {
            FederationQuarantineResolution::Restore => Self {
                sequence: 3,
                kind: 3,
                prior_state: Some(QUARANTINE_SURFACED),
                resulting_state: QUARANTINE_RESTORED,
            },
            FederationQuarantineResolution::RestoreAsCopy => Self {
                sequence: 3,
                kind: 4,
                prior_state: Some(QUARANTINE_SURFACED),
                resulting_state: QUARANTINE_RESTORED,
            },
            FederationQuarantineResolution::Discard => Self {
                sequence: 3,
                kind: 5,
                prior_state: Some(QUARANTINE_SURFACED),
                resulting_state: QUARANTINE_DISCARDED,
            },
        }
    }
}

fn insert_event(
    transaction: &Transaction<'_>,
    context: CommandContext,
    quarantine_id: QuarantineId,
    transition: EventTransition,
    reason: Option<&str>,
    revision: Revision,
) -> Result<(), RepositoryError> {
    transaction.execute(
        "INSERT INTO federation_quarantine_events(
            quarantine_id, event_sequence, event_kind, prior_state, resulting_state,
            reason, changed_by, changed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            quarantine_id.as_bytes().as_slice(),
            to_i64(transition.sequence)?,
            transition.kind,
            transition.prior_state,
            transition.resulting_state,
            reason,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
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

fn require_one(changed: usize) -> Result<(), RepositoryError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}
