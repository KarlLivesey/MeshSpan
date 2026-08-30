// SPDX-License-Identifier: GPL-2.0-only

//! Reconstruction and independent verification of persisted quarantine proof chains.

use meshspan_domain::{
    FederatedMutationAcknowledgement, FederatedMutationAdmission, FederatedMutationEvidence,
    FederatedPrincipal, MeshId, QuarantineId, Revision, UnixMicros,
};
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use super::federation_quarantine::{FederationQuarantineRecord, FederationQuarantineState};
use super::federation_quarantine_codec::{
    nonnegative, parse_digest, parse_grant, parse_mesh, parse_operation, parse_principal,
    parse_reason, parse_relationship, parse_resolution, parse_resource, parse_rights,
    parse_signature, positive,
};
use super::federation_quarantine_transition::{
    QUARANTINE_DISCARDED, QUARANTINE_RESTORED, QUARANTINE_RETAINED, QUARANTINE_SURFACED,
};
use super::{RepositoryError, federation_mutation_admission};
use crate::{FederationQuarantineResolution, RetainFederatedMutationQuarantine};

pub(super) struct StoredQuarantine {
    pub(super) record: FederationQuarantineRecord,
    acknowledgement_digest: [u8; 32],
    signer_mesh_id: MeshId,
    signer_generation: u64,
    signature: [u8; 64],
    initial_revision: Revision,
    surfaced_at: Option<UnixMicros>,
    resolved_at: Option<UnixMicros>,
    resolution_operation_present: bool,
}

struct BaseRow {
    relationship_id: Vec<u8>,
    operation_id: Vec<u8>,
    grant_id: Vec<u8>,
    subject_home_mesh_id: Vec<u8>,
    subject_principal_id: Vec<u8>,
    accepted_at: i64,
    reason_kind: i64,
    payload_digest: Vec<u8>,
    acknowledgement_digest: Vec<u8>,
    state: i64,
    surfaced_at: Option<i64>,
    resolved_at: Option<i64>,
    resolution_kind: Option<i64>,
    resolution_operation_id: Option<Vec<u8>>,
    revision: i64,
}

struct AcknowledgementRow {
    signer_mesh_id: Vec<u8>,
    signer_generation: i64,
    signature: Vec<u8>,
    authority_epoch: i64,
    required_rights: i64,
    storage_bytes: i64,
    resource_kind: i64,
    authority_mesh_id: Vec<u8>,
    volume_id: Option<Vec<u8>>,
    object_id: Option<Vec<u8>>,
    revision: i64,
}

#[derive(Debug, Eq, PartialEq)]
struct EventRow {
    sequence: i64,
    kind: i64,
    prior_state: Option<i64>,
    resulting_state: i64,
    reason: Option<String>,
    changed_by: Vec<u8>,
    changed_at: i64,
    revision: i64,
}

pub(super) fn load_verified(
    connection: &Connection,
    quarantine_id: QuarantineId,
) -> Result<Option<StoredQuarantine>, RepositoryError> {
    let Some(stored) = load(connection, quarantine_id)? else {
        return Ok(None);
    };
    verify_stored(connection, &stored)?;
    Ok(Some(stored))
}

pub(super) fn load_verified_required(
    connection: &Connection,
    quarantine_id: QuarantineId,
) -> Result<StoredQuarantine, RepositoryError> {
    load_verified(connection, quarantine_id)?.ok_or(RepositoryError::InvalidCommand)
}

fn load(
    connection: &Connection,
    quarantine_id: QuarantineId,
) -> Result<Option<StoredQuarantine>, RepositoryError> {
    let Some(base) = load_base(connection, quarantine_id)? else {
        return Ok(None);
    };
    let acknowledgement =
        load_acknowledgement(connection, quarantine_id)?.ok_or(RepositoryError::CorruptState)?;
    build_stored(quarantine_id, &base, &acknowledgement).map(Some)
}

fn load_base(
    connection: &Connection,
    quarantine_id: QuarantineId,
) -> Result<Option<BaseRow>, RepositoryError> {
    connection
        .query_row(
            "SELECT relationship_id, operation_id, grant_id, subject_home_mesh_id,
                    subject_principal_id, accepted_at, reason_kind, payload_digest,
                    acknowledgement_digest, state, surfaced_at, resolved_at,
                    resolution_kind, resolution_operation_id, revision
             FROM federation_quarantine WHERE quarantine_id = ?1",
            [quarantine_id.as_bytes().as_slice()],
            |row| {
                Ok(BaseRow {
                    relationship_id: row.get(0)?,
                    operation_id: row.get(1)?,
                    grant_id: row.get(2)?,
                    subject_home_mesh_id: row.get(3)?,
                    subject_principal_id: row.get(4)?,
                    accepted_at: row.get(5)?,
                    reason_kind: row.get(6)?,
                    payload_digest: row.get(7)?,
                    acknowledgement_digest: row.get(8)?,
                    state: row.get(9)?,
                    surfaced_at: row.get(10)?,
                    resolved_at: row.get(11)?,
                    resolution_kind: row.get(12)?,
                    resolution_operation_id: row.get(13)?,
                    revision: row.get(14)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn load_acknowledgement(
    connection: &Connection,
    quarantine_id: QuarantineId,
) -> Result<Option<AcknowledgementRow>, RepositoryError> {
    connection
        .query_row(
            "SELECT signer_mesh_id, signer_generation, signature, authority_epoch,
                    required_rights, storage_bytes, resource_kind, authority_mesh_id,
                    volume_id, object_id, revision
             FROM federation_quarantine_acknowledgements WHERE quarantine_id = ?1",
            [quarantine_id.as_bytes().as_slice()],
            |row| {
                Ok(AcknowledgementRow {
                    signer_mesh_id: row.get(0)?,
                    signer_generation: row.get(1)?,
                    signature: row.get(2)?,
                    authority_epoch: row.get(3)?,
                    required_rights: row.get(4)?,
                    storage_bytes: row.get(5)?,
                    resource_kind: row.get(6)?,
                    authority_mesh_id: row.get(7)?,
                    volume_id: row.get(8)?,
                    object_id: row.get(9)?,
                    revision: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn build_stored(
    quarantine_id: QuarantineId,
    base: &BaseRow,
    acknowledgement: &AcknowledgementRow,
) -> Result<StoredQuarantine, RepositoryError> {
    let evidence = FederatedMutationEvidence::new_relayed(
        parse_grant(&base.grant_id)?,
        parse_relationship(&base.relationship_id)?,
        FederatedPrincipal::new(
            parse_mesh(&base.subject_home_mesh_id)?,
            parse_principal(&base.subject_principal_id)?,
        ),
        parse_mesh(&acknowledgement.signer_mesh_id)?,
        parse_resource(
            acknowledgement.resource_kind,
            &acknowledgement.authority_mesh_id,
            acknowledgement.volume_id.as_deref(),
            acknowledgement.object_id.as_deref(),
        )?,
        positive(acknowledgement.authority_epoch)?,
        UnixMicros::new(base.accepted_at),
        parse_rights(acknowledgement.required_rights)?,
        nonnegative(acknowledgement.storage_bytes)?,
    );
    let state = parse_state(base.state)?;
    let resolution = base.resolution_kind.map(parse_resolution).transpose()?;
    let current_revision = Revision::new(positive(base.revision)?);
    let initial_revision = Revision::new(positive(acknowledgement.revision)?);
    verify_lifecycle_shape(
        state,
        resolution,
        base.surfaced_at,
        base.resolved_at,
        base.resolution_operation_id.as_deref(),
        initial_revision,
        current_revision,
    )?;
    Ok(StoredQuarantine {
        record: FederationQuarantineRecord {
            quarantine_id,
            source_operation_id: parse_operation(&base.operation_id)?,
            evidence,
            reason: parse_reason(base.reason_kind)?,
            payload_digest: parse_digest(&base.payload_digest)?,
            state,
            resolution,
            revision: current_revision,
        },
        acknowledgement_digest: parse_digest(&base.acknowledgement_digest)?,
        signer_mesh_id: parse_mesh(&acknowledgement.signer_mesh_id)?,
        signer_generation: positive(acknowledgement.signer_generation)?,
        signature: parse_signature(&acknowledgement.signature)?,
        initial_revision,
        surfaced_at: base.surfaced_at.map(UnixMicros::new),
        resolved_at: base.resolved_at.map(UnixMicros::new),
        resolution_operation_present: base.resolution_operation_id.is_some(),
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the durable lifecycle tuple is verified as one indivisible state machine shape"
)]
fn verify_lifecycle_shape(
    state: FederationQuarantineState,
    resolution: Option<FederationQuarantineResolution>,
    surfaced_at: Option<i64>,
    resolved_at: Option<i64>,
    resolution_operation: Option<&[u8]>,
    initial_revision: Revision,
    current_revision: Revision,
) -> Result<(), RepositoryError> {
    if resolution_operation.is_some_and(|value| value.len() != 16) {
        return Err(RepositoryError::CorruptState);
    }
    let valid = match state {
        FederationQuarantineState::Retained => {
            surfaced_at.is_none()
                && resolved_at.is_none()
                && resolution.is_none()
                && resolution_operation.is_none()
                && current_revision == initial_revision
        }
        FederationQuarantineState::Surfaced => {
            surfaced_at.is_some()
                && resolved_at.is_none()
                && resolution.is_none()
                && resolution_operation.is_none()
                && current_revision.get() > initial_revision.get()
        }
        FederationQuarantineState::Restored => {
            surfaced_at.is_some()
                && resolved_at.is_some()
                && matches!(
                    resolution,
                    Some(
                        FederationQuarantineResolution::Restore
                            | FederationQuarantineResolution::RestoreAsCopy
                    )
                )
                && resolution_operation.is_some()
                && current_revision.get() > initial_revision.get()
        }
        FederationQuarantineState::Discarded => {
            surfaced_at.is_some()
                && resolved_at.is_some()
                && resolution == Some(FederationQuarantineResolution::Discard)
                && resolution_operation.is_some()
                && current_revision.get() > initial_revision.get()
        }
    };
    if valid {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn verify_stored(
    connection: &Connection,
    stored: &StoredQuarantine,
) -> Result<(), RepositoryError> {
    if stored.signer_mesh_id != stored.record.evidence.accepting_mesh_id() {
        return Err(RepositoryError::CorruptState);
    }
    let command = RetainFederatedMutationQuarantine {
        quarantine_id: stored.record.quarantine_id,
        acknowledgement: FederatedMutationAcknowledgement {
            source_operation_id: stored.record.source_operation_id,
            evidence: stored.record.evidence,
            payload_digest: stored.record.payload_digest,
            signer_generation: stored.signer_generation,
            signature: stored.signature,
        },
    };
    let admission = federation_mutation_admission::classify(connection, &command.acknowledgement)
        .map_err(|_| RepositoryError::CorruptState)?;
    if admission != FederatedMutationAdmission::Quarantined(stored.record.reason) {
        return Err(RepositoryError::CorruptState);
    }
    let digest: [u8; 32] = Sha256::digest(command.acknowledgement.signing_payload()).into();
    if digest != stored.acknowledgement_digest {
        return Err(RepositoryError::CorruptState);
    }
    verify_events(connection, stored)
}

fn verify_events(
    connection: &Connection,
    stored: &StoredQuarantine,
) -> Result<(), RepositoryError> {
    let mut statement = connection.prepare(
        "SELECT event_sequence, event_kind, prior_state, resulting_state, reason,
                changed_by, changed_at, revision
         FROM federation_quarantine_events
         WHERE quarantine_id = ?1 ORDER BY event_sequence",
    )?;
    let events = statement
        .query_map([stored.record.quarantine_id.as_bytes().as_slice()], |row| {
            Ok(EventRow {
                sequence: row.get(0)?,
                kind: row.get(1)?,
                prior_state: row.get(2)?,
                resulting_state: row.get(3)?,
                reason: row.get(4)?,
                changed_by: row.get(5)?,
                changed_at: row.get(6)?,
                revision: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    validate_events(stored, &events)
}

fn validate_events(stored: &StoredQuarantine, events: &[EventRow]) -> Result<(), RepositoryError> {
    let expected_count = match stored.record.state {
        FederationQuarantineState::Retained => 1,
        FederationQuarantineState::Surfaced => 2,
        FederationQuarantineState::Restored | FederationQuarantineState::Discarded => 3,
    };
    if events.len() != expected_count || !is_retention_event(stored, &events[0]) {
        return Err(RepositoryError::CorruptState);
    }
    if expected_count >= 2 && !is_surface_event(stored, &events[1]) {
        return Err(RepositoryError::CorruptState);
    }
    if expected_count == 3 && !is_resolution_event(stored, &events[2]) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(())
}

fn is_retention_event(stored: &StoredQuarantine, event: &EventRow) -> bool {
    event.sequence == 1
        && event.kind == 1
        && event.prior_state.is_none()
        && event.resulting_state == QUARANTINE_RETAINED
        && event.reason.is_none()
        && event.changed_by.len() == 16
        && event.changed_at >= stored.record.evidence.accepted_at().get()
        && u64::try_from(event.revision).ok() == Some(stored.initial_revision.get())
}

fn is_surface_event(stored: &StoredQuarantine, event: &EventRow) -> bool {
    event.sequence == 2
        && event.kind == 2
        && event.prior_state == Some(QUARANTINE_RETAINED)
        && event.resulting_state == QUARANTINE_SURFACED
        && event.reason.is_none()
        && event.changed_by.len() == 16
        && Some(event.changed_at) == stored.surfaced_at.map(UnixMicros::get)
        && event.changed_at >= stored.record.evidence.accepted_at().get()
        && event.revision > i64::try_from(stored.initial_revision.get()).unwrap_or(i64::MAX)
        && event.revision <= i64::try_from(stored.record.revision.get()).unwrap_or(i64::MIN)
}

fn is_resolution_event(stored: &StoredQuarantine, event: &EventRow) -> bool {
    let Some(resolution) = stored.record.resolution else {
        return false;
    };
    let (kind, resulting_state) = match resolution {
        FederationQuarantineResolution::Restore => (3, QUARANTINE_RESTORED),
        FederationQuarantineResolution::RestoreAsCopy => (4, QUARANTINE_RESTORED),
        FederationQuarantineResolution::Discard => (5, QUARANTINE_DISCARDED),
    };
    event.sequence == 3
        && event.kind == kind
        && event.prior_state == Some(QUARANTINE_SURFACED)
        && event.resulting_state == resulting_state
        && event.reason.as_deref().is_some_and(valid_reason)
        && event.changed_by.len() == 16
        && Some(event.changed_at) == stored.resolved_at.map(UnixMicros::get)
        && stored
            .surfaced_at
            .is_some_and(|time| event.changed_at >= time.get())
        && u64::try_from(event.revision).ok() == Some(stored.record.revision.get())
        && stored.resolution_operation_present
}

fn valid_reason(reason: &str) -> bool {
    !reason.is_empty() && reason.len() <= 1_024 && !reason.chars().any(char::is_control)
}

fn parse_state(value: i64) -> Result<FederationQuarantineState, RepositoryError> {
    match value {
        QUARANTINE_RETAINED => Ok(FederationQuarantineState::Retained),
        QUARANTINE_SURFACED => Ok(FederationQuarantineState::Surfaced),
        QUARANTINE_RESTORED => Ok(FederationQuarantineState::Restored),
        QUARANTINE_DISCARDED => Ok(FederationQuarantineState::Discarded),
        _ => Err(RepositoryError::CorruptState),
    }
}
