// SPDX-License-Identifier: GPL-2.0-only

//! Signed, incarnation-fenced coverage for version-cleanup proposals.

use ed25519_dalek::{Signature, VerifyingKey};
use meshspan_domain::{NodeId, OperationId, Revision};
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

/// One independently signature-verified participant scan used for local root retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupParticipant {
    /// Replicated cleanup proposal identity.
    pub cleanup_operation_id: OperationId,
    /// Exact participating gateway node.
    pub node_id: NodeId,
    /// Snapshotted process incarnation.
    pub node_incarnation: u64,
    /// Exact local durable scan whose fence remains active.
    pub scan_operation_id: OperationId,
    /// Common operation-independent cleanup subject.
    pub reachability_subject_digest: [u8; 32],
    /// Digest of the participant's unchanged local roots.
    pub local_roots_digest: [u8; 32],
    /// Signed terminal unreachable result digest.
    pub scan_result_digest: [u8; 32],
    /// Replicated revision that committed this attestation.
    pub revision: Revision,
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

pub(super) fn participant(
    database: &PartitionDatabase,
    cleanup_operation_id: OperationId,
    node_id: NodeId,
) -> Result<Option<VersionCleanupParticipant>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT i.revision, i.reachability_subject_digest,
                    p.node_incarnation, p.key_generation, p.scan_operation_id,
                    p.scan_request_digest, p.reachability_subject_digest,
                    p.local_roots_digest, p.scan_result_digest, p.signature,
                    keys.verifying_key, p.revision
             FROM version_cleanup_intents i
             JOIN version_cleanup_participants p
               ON p.cleanup_operation_id = i.cleanup_operation_id
             JOIN cleanup_attestation_keys keys
               ON keys.node_id = p.node_id AND keys.generation = p.key_generation
             WHERE i.cleanup_operation_id = ?1 AND p.node_id = ?2 AND p.state = ?3",
            params![
                cleanup_operation_id.as_bytes().as_slice(),
                node_id.as_bytes().as_slice(),
                PARTICIPANT_ATTESTED,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    StoredCompleteAttestation {
                        node_id: node_id.as_bytes().to_vec(),
                        node_incarnation: row.get(2)?,
                        key_generation: row.get(3)?,
                        scan_operation_id: row.get(4)?,
                        scan_request_digest: row.get(5)?,
                        subject_digest: row.get(6)?,
                        local_roots_digest: row.get(7)?,
                        scan_result_digest: row.get(8)?,
                        signature: row.get(9)?,
                        verifying_key: row.get(10)?,
                    },
                    row.get::<_, i64>(11)?,
                ))
            },
        )
        .optional()?;
    let Some((cleanup_revision, subject_digest, stored, revision)) = stored else {
        return Ok(None);
    };
    let cleanup_revision = Revision::new(positive(cleanup_revision)?);
    let subject_digest = array(&subject_digest)?;
    validate_stored_attestation(
        cleanup_operation_id,
        cleanup_revision,
        subject_digest,
        &stored,
    )
    .map_err(|_| RepositoryError::CorruptState)?;
    Ok(Some(VersionCleanupParticipant {
        cleanup_operation_id,
        node_id,
        node_incarnation: positive(stored.node_incarnation)?,
        scan_operation_id: OperationId::from_bytes(array(&stored.scan_operation_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        reachability_subject_digest: subject_digest,
        local_roots_digest: array(&stored.local_roots_digest)?,
        scan_result_digest: array(&stored.scan_result_digest)?,
        revision: Revision::new(positive(revision)?),
    }))
}

pub(super) fn validate_complete(
    transaction: &Transaction<'_>,
    cleanup_operation_id: OperationId,
    cleanup_revision: Revision,
    subject_digest: [u8; 32],
) -> Result<(), RepositoryError> {
    let required: i64 = transaction
        .query_row(
            "SELECT required_attestation_count FROM version_cleanup_intents
             WHERE cleanup_operation_id = ?1 AND revision = ?2
               AND reachability_subject_digest = ?3 AND state = ?4",
            params![
                cleanup_operation_id.as_bytes().as_slice(),
                to_i64(cleanup_revision.get())?,
                subject_digest.as_slice(),
                PROPOSAL_PENDING,
            ],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(RepositoryError::StaleRevision)?;
    let required = positive(required)?;
    if super::version_cleanup::current_participant_count(transaction)? != required {
        return Err(RepositoryError::StaleRevision);
    }

    let mut statement = transaction.prepare(
        "SELECT p.node_id, p.node_incarnation, p.key_generation,
                p.scan_operation_id, p.scan_request_digest,
                p.reachability_subject_digest, p.local_roots_digest,
                p.scan_result_digest, p.signature, keys.verifying_key
         FROM version_cleanup_participants p
         JOIN nodes n ON n.node_id = p.node_id
         JOIN cleanup_attestation_keys keys
           ON keys.node_id = p.node_id AND keys.generation = p.key_generation
         WHERE p.cleanup_operation_id = ?1 AND p.state = ?2
           AND n.state IN (1, 2) AND n.current_incarnation = p.node_incarnation
           AND keys.state = ?3
           AND (
             EXISTS(
               SELECT 1 FROM node_roles nr
               WHERE nr.node_id = n.node_id AND nr.role_code = 2
             )
             OR (
               NOT EXISTS(SELECT 1 FROM node_roles nr WHERE nr.node_id = n.node_id)
               AND EXISTS(
                 SELECT 1 FROM partition_voters pv
                 WHERE pv.node_id = n.node_id AND pv.state IN (1, 2)
               )
             )
           )
         ORDER BY p.node_id",
    )?;
    let rows = statement.query_map(
        params![
            cleanup_operation_id.as_bytes().as_slice(),
            PARTICIPANT_ATTESTED,
            KEY_ACTIVE,
        ],
        |row| {
            Ok(StoredCompleteAttestation {
                node_id: row.get(0)?,
                node_incarnation: row.get(1)?,
                key_generation: row.get(2)?,
                scan_operation_id: row.get(3)?,
                scan_request_digest: row.get(4)?,
                subject_digest: row.get(5)?,
                local_roots_digest: row.get(6)?,
                scan_result_digest: row.get(7)?,
                signature: row.get(8)?,
                verifying_key: row.get(9)?,
            })
        },
    )?;
    let mut verified = 0_u64;
    for row in rows {
        validate_stored_attestation(
            cleanup_operation_id,
            cleanup_revision,
            subject_digest,
            &row?,
        )?;
        verified = verified
            .checked_add(1)
            .ok_or(RepositoryError::CapacityExceeded)?;
    }
    if verified == required {
        Ok(())
    } else {
        Err(RepositoryError::StaleRevision)
    }
}

struct StoredCompleteAttestation {
    node_id: Vec<u8>,
    node_incarnation: i64,
    key_generation: i64,
    scan_operation_id: Vec<u8>,
    scan_request_digest: Vec<u8>,
    subject_digest: Vec<u8>,
    local_roots_digest: Vec<u8>,
    scan_result_digest: Vec<u8>,
    signature: Vec<u8>,
    verifying_key: Vec<u8>,
}

fn validate_stored_attestation(
    cleanup_operation_id: OperationId,
    cleanup_revision: Revision,
    subject_digest: [u8; 32],
    stored: &StoredCompleteAttestation,
) -> Result<(), RepositoryError> {
    let attestation = VersionCleanupAttestation {
        cleanup_operation_id,
        cleanup_revision,
        node_id: meshspan_domain::NodeId::from_bytes(array(&stored.node_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        node_incarnation: positive(stored.node_incarnation)?,
        key_generation: positive(stored.key_generation)?,
        scan_operation_id: OperationId::from_bytes(array(&stored.scan_operation_id)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        scan_request_digest: array(&stored.scan_request_digest)?,
        reachability_subject_digest: array(&stored.subject_digest)?,
        local_roots_digest: array(&stored.local_roots_digest)?,
        scan_result_digest: array(&stored.scan_result_digest)?,
        signature: array(&stored.signature)?,
    };
    if attestation.reachability_subject_digest != subject_digest {
        return Err(RepositoryError::CorruptState);
    }
    validate_scan_result(&attestation)?;
    verify_with_key(&attestation, &stored.verifying_key)
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
    verify_with_key(attestation, &key)
}

fn verify_with_key(
    attestation: &VersionCleanupAttestation,
    key: &[u8],
) -> Result<(), RepositoryError> {
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

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], RepositoryError> {
    bytes.try_into().map_err(|_| RepositoryError::CorruptState)
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
