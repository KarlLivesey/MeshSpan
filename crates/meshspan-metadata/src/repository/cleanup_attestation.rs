// SPDX-License-Identifier: GPL-2.0-only

//! Signed, incarnation-fenced coverage for version-cleanup proposals.

use ed25519_dalek::{Signature, VerifyingKey};
use meshspan_domain::{OperationId, Revision};
use rusqlite::{OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{
    AttestVersionCleanup, CommandContext, PartitionDatabase, RegisterCleanupAttestationKey,
    VersionCleanupAttestation,
};

const KEY_ACTIVE: i64 = 1;
const PROPOSAL_PENDING: i64 = 1;
const PARTICIPANT_PENDING: i64 = 1;
const PARTICIPANT_ATTESTED: i64 = 2;
const UNREACHABLE_STATE_CODE: u8 = 4;

/// Aggregate durable attestation coverage for one cleanup proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupAttestationProgress {
    /// Replicated cleanup proposal identity.
    pub cleanup_operation_id: OperationId,
    /// Immutable number of node incarnations required by the proposal.
    pub required: u64,
    /// Number of exact participants carrying verified signed attestations.
    pub attested: u64,
}

impl VersionCleanupAttestationProgress {
    /// Reports whether every snapshotted participant has attested.
    #[must_use]
    pub const fn complete(self) -> bool {
        self.required > 0 && self.required == self.attested
    }
}

pub(super) fn register_key(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: RegisterCleanupAttestationKey,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if command.generation == 0 || VerifyingKey::from_bytes(&command.verifying_key).is_err() {
        return Err(RepositoryError::InvalidCommand);
    }
    let node = command.node_id.as_bytes();
    let incarnation: Option<i64> = transaction
        .query_row(
            "SELECT current_incarnation FROM nodes
             WHERE node_id = ?1 AND state IN (1, 2)",
            [node.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if incarnation
        .and_then(|value| u64::try_from(value).ok())
        .is_none()
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let current_generation: i64 = transaction.query_row(
        "SELECT coalesce(max(generation), 0)
         FROM cleanup_attestation_keys WHERE node_id = ?1",
        [node.as_slice()],
        |row| row.get(0),
    )?;
    if command.generation
        <= u64::try_from(current_generation).map_err(|_| RepositoryError::CorruptState)?
    {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "UPDATE cleanup_attestation_keys
         SET state = 2, retired_at = ?1, revision = ?2
         WHERE node_id = ?3 AND state = 1",
        params![
            context.occurred_at.get(),
            to_i64(revision.get())?,
            node.as_slice()
        ],
    )?;
    transaction.execute(
        "INSERT INTO cleanup_attestation_keys(
            node_id, generation, verifying_key, state, created_at, retired_at, revision
         ) VALUES (?1, ?2, ?3, 1, ?4, NULL, ?5)",
        params![
            node.as_slice(),
            to_i64(command.generation)?,
            command.verifying_key.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?
        ],
    )?;
    Ok(EntityReference {
        kind: EntityKind::CleanupAttestationKey,
        id: node,
    })
}

pub(super) fn attest(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &AttestVersionCleanup,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let attestation = &command.attestation;
    validate_attestation_input(context, attestation)?;
    validate_participant(transaction, attestation)?;
    validate_scan_result(attestation)?;
    verify_signature(transaction, attestation)?;

    let changed = transaction.execute(
        "UPDATE version_cleanup_participants SET
            state = ?1, attestation_operation_id = ?2, key_generation = ?3,
            scan_operation_id = ?4, scan_request_digest = ?5,
            reachability_subject_digest = ?6, local_roots_digest = ?7,
            scan_result_digest = ?8, signature = ?9,
            attested_at = ?10, revision = ?11
         WHERE cleanup_operation_id = ?12 AND node_id = ?13
           AND node_incarnation = ?14 AND state = ?15",
        params![
            PARTICIPANT_ATTESTED,
            context.operation_id.as_bytes().as_slice(),
            to_i64(attestation.key_generation)?,
            attestation.scan_operation_id.as_bytes().as_slice(),
            attestation.scan_request_digest.as_slice(),
            attestation.reachability_subject_digest.as_slice(),
            attestation.local_roots_digest.as_slice(),
            attestation.scan_result_digest.as_slice(),
            attestation.signature.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
            attestation.cleanup_operation_id.as_bytes().as_slice(),
            attestation.node_id.as_bytes().as_slice(),
            to_i64(attestation.node_incarnation)?,
            PARTICIPANT_PENDING,
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::StaleRevision);
    }
    Ok(EntityReference {
        kind: EntityKind::VersionCleanup,
        id: attestation.cleanup_operation_id.as_bytes(),
    })
}

pub(super) fn progress(
    database: &PartitionDatabase,
    cleanup_operation_id: OperationId,
) -> Result<Option<VersionCleanupAttestationProgress>, RepositoryError> {
    let cleanup = cleanup_operation_id.as_bytes();
    let stored: Option<(Option<i64>, i64, i64)> = database
        .connection()
        .query_row(
            "SELECT i.required_attestation_count,
                    count(p.node_id),
                    coalesce(sum(CASE WHEN p.state = 2 THEN 1 ELSE 0 END), 0)
             FROM version_cleanup_intents i
             LEFT JOIN version_cleanup_participants p
               ON p.cleanup_operation_id = i.cleanup_operation_id
             WHERE i.cleanup_operation_id = ?1
             GROUP BY i.cleanup_operation_id",
            [cleanup.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((required, participant_count, attested)) = stored else {
        return Ok(None);
    };
    let required = positive(required.ok_or(RepositoryError::CorruptState)?)?;
    let participant_count = positive(participant_count)?;
    let attested = non_negative(attested)?;
    if required != participant_count || attested > required {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Some(VersionCleanupAttestationProgress {
        cleanup_operation_id,
        required,
        attested,
    }))
}

fn validate_attestation_input(
    context: CommandContext,
    attestation: &VersionCleanupAttestation,
) -> Result<(), RepositoryError> {
    if attestation.cleanup_revision == Revision::ZERO
        || attestation.node_incarnation == 0
        || attestation.key_generation == 0
        || attestation.scan_request_digest == [0; 32]
        || attestation.reachability_subject_digest == [0; 32]
        || attestation.local_roots_digest == [0; 32]
        || attestation.scan_result_digest == [0; 32]
        || context.operation_id == attestation.cleanup_operation_id
        || context.operation_id == attestation.scan_operation_id
        || attestation.cleanup_operation_id == attestation.scan_operation_id
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn validate_participant(
    transaction: &Transaction<'_>,
    attestation: &VersionCleanupAttestation,
) -> Result<(), RepositoryError> {
    let cleanup = attestation.cleanup_operation_id.as_bytes();
    let node = attestation.node_id.as_bytes();
    let stored: Option<(i64, i64, i64, Vec<u8>, i64, i64)> = transaction
        .query_row(
            "SELECT p.node_incarnation, p.state, i.revision, i.reachability_subject_digest,
                    i.state, n.current_incarnation
             FROM version_cleanup_participants p
             JOIN version_cleanup_intents i
               ON i.cleanup_operation_id = p.cleanup_operation_id
             JOIN nodes n ON n.node_id = p.node_id
             WHERE p.cleanup_operation_id = ?1 AND p.node_id = ?2
               AND n.state IN (1, 2)",
            params![cleanup.as_slice(), node.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((
        required_incarnation,
        participant_state,
        cleanup_revision,
        subject,
        proposal_state,
        current_incarnation,
    )) = stored
    else {
        return Err(RepositoryError::InvalidCommand);
    };
    if participant_state != PARTICIPANT_PENDING
        || proposal_state != PROPOSAL_PENDING
        || positive(required_incarnation)? != attestation.node_incarnation
        || positive(current_incarnation)? != attestation.node_incarnation
        || positive(cleanup_revision)? != attestation.cleanup_revision.get()
        || subject.as_slice() != attestation.reachability_subject_digest
    {
        return Err(RepositoryError::StaleRevision);
    }
    Ok(())
}

fn validate_scan_result(attestation: &VersionCleanupAttestation) -> Result<(), RepositoryError> {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.version-reachability-result.v1\0");
    digest.update(&attestation.scan_operation_id.as_bytes());
    digest.update(&attestation.scan_request_digest);
    digest.update(&attestation.local_roots_digest);
    digest.update(&[UNREACHABLE_STATE_CODE]);
    if <[u8; 32]>::from(digest.finalize()) == attestation.scan_result_digest {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn verify_signature(
    transaction: &Transaction<'_>,
    attestation: &VersionCleanupAttestation,
) -> Result<(), RepositoryError> {
    let node = attestation.node_id.as_bytes();
    let key: Vec<u8> = transaction
        .query_row(
            "SELECT verifying_key FROM cleanup_attestation_keys
             WHERE node_id = ?1 AND generation = ?2 AND state = ?3",
            params![
                node.as_slice(),
                to_i64(attestation.key_generation)?,
                KEY_ACTIVE
            ],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key.try_into().map_err(|_| RepositoryError::CorruptState)?)
            .map_err(|_| RepositoryError::CorruptState)?;
    verifying_key
        .verify_strict(
            &attestation.signing_digest(),
            &Signature::from_bytes(&attestation.signature),
        )
        .map_err(|_| RepositoryError::InvalidCommand)
}

fn positive(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::CorruptState)
}

fn non_negative(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}
