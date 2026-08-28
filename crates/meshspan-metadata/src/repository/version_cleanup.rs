// SPDX-License-Identifier: GPL-2.0-only

//! Revision-fenced replicated proposals for unreachable-version cleanup.

use meshspan_domain::{
    ContentManifestId, FileVersionId, OperationId, Revision, UnixMicros, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::reachability::retained_root_summary;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, PartitionDatabase, ProposeVersionCleanup};

const UNREACHABLE_STATE_CODE: u8 = 4;

/// One replicated cleanup intent admitted from an exact terminal reachability proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionCleanupIntent {
    /// Replicated cleanup operation identity.
    pub cleanup_operation_id: OperationId,
    /// Volume whose root set was exhausted.
    pub volume_id: VolumeId,
    /// Historical immutable version approved for cleanup.
    pub version_id: FileVersionId,
    /// Content manifest selected by the version.
    pub manifest_id: ContentManifestId,
    /// Durable filesystem scan that produced the proof.
    pub source_scan_operation_id: OperationId,
    /// Digest binding the scan candidate, retention selection and root authority.
    pub scan_request_digest: [u8; 32],
    /// Operation-independent digest shared by every scan of the exact cleanup subject.
    pub reachability_subject_digest: [u8; 32],
    /// Exact current retention-policy sequence used by selection.
    pub retention_policy_sequence: u64,
    /// Metadata revision at which the retained-root set was complete.
    pub reachability_revision: Revision,
    /// Complete number of metadata-authoritative retained roots.
    pub retained_root_count: u64,
    /// Digest of the complete retained-root set.
    pub retained_root_digest: [u8; 32],
    /// Digest of unchanged local branch and lifecycle roots.
    pub local_roots_digest: [u8; 32],
    /// Terminal unreachable proof digest.
    pub proof_result_digest: [u8; 32],
    /// Exact number of node incarnations required to attest before final cleanup authority.
    pub required_attestation_count: u64,
    /// Authoritative intent creation instant.
    pub proposed_at: UnixMicros,
    /// Replicated revision that created this intent.
    pub revision: Revision,
}

pub(super) fn propose(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: ProposeVersionCleanup,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_input(context, command)?;
    validate_policy(transaction, command)?;
    let (root_count, root_digest) = retained_root_summary(
        transaction,
        command.volume_id,
        command.reachability_revision,
    )?;
    if root_count != command.retained_root_count || root_digest != command.retained_root_digest {
        return Err(RepositoryError::StaleRevision);
    }
    if terminal_result_digest(command) != command.proof_result_digest {
        return Err(RepositoryError::InvalidCommand);
    }
    let required_attestation_count = required_participant_count(transaction)?;
    if required_attestation_count == 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO version_cleanup_intents(
            cleanup_operation_id, volume_id, version_id, manifest_id,
            source_scan_operation_id, scan_request_digest, retention_policy_sequence,
            reachability_revision, retained_root_count, retained_root_digest,
            local_roots_digest, proof_result_digest, state, proposed_at,
            completed_at, revision, required_attestation_count,
            reachability_subject_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1, ?13, NULL, ?14, ?15, ?16)",
        params![
            context.operation_id.as_bytes().as_slice(),
            command.volume_id.as_bytes().as_slice(),
            command.version_id.as_bytes().as_slice(),
            command.manifest_id.as_bytes().as_slice(),
            command.source_scan_operation_id.as_bytes().as_slice(),
            command.scan_request_digest.as_slice(),
            to_i64(command.retention_policy_sequence)?,
            to_i64(command.reachability_revision.get())?,
            to_i64(command.retained_root_count)?,
            command.retained_root_digest.as_slice(),
            command.local_roots_digest.as_slice(),
            command.proof_result_digest.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
            to_i64(required_attestation_count)?,
            command.reachability_subject_digest.as_slice(),
        ],
    )?;
    let participant_rows = transaction.execute(
        "INSERT INTO version_cleanup_participants(
            cleanup_operation_id, node_id, node_incarnation, state,
            attestation_operation_id, key_generation, scan_operation_id,
            scan_request_digest, local_roots_digest, scan_result_digest,
            signature, attested_at, revision
         )
         SELECT ?1, n.node_id, n.current_incarnation, 1,
                NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?2
         FROM nodes n
         WHERE n.state IN (1, 2) AND (
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
         )",
        params![
            context.operation_id.as_bytes().as_slice(),
            to_i64(revision.get())?
        ],
    )?;
    if u64::try_from(participant_rows).ok() != Some(required_attestation_count) {
        return Err(RepositoryError::CorruptState);
    }
    Ok(EntityReference {
        kind: EntityKind::VersionCleanup,
        id: context.operation_id.as_bytes(),
    })
}

pub(super) fn load(
    database: &PartitionDatabase,
    operation_id: OperationId,
) -> Result<Option<VersionCleanupIntent>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT volume_id, version_id, manifest_id, source_scan_operation_id,
                    scan_request_digest, retention_policy_sequence, reachability_revision,
                    retained_root_count, retained_root_digest, local_roots_digest,
                    proof_result_digest, state, proposed_at, completed_at, revision,
                    required_attestation_count, reachability_subject_digest
             FROM version_cleanup_intents WHERE cleanup_operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, Option<i64>>(15)?,
                    row.get::<_, Option<Vec<u8>>>(16)?,
                ))
            },
        )
        .optional()?;
    stored
        .as_ref()
        .map(|row| decode(operation_id, row))
        .transpose()
}

type StoredIntent = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Option<i64>,
    i64,
    Option<i64>,
    Option<Vec<u8>>,
);

fn decode(
    operation_id: OperationId,
    row: &StoredIntent,
) -> Result<VersionCleanupIntent, RepositoryError> {
    if row.11 != 1 || row.13.is_some() || parse_u64(row.7)? == 0 {
        return Err(RepositoryError::CorruptState);
    }
    let intent = VersionCleanupIntent {
        cleanup_operation_id: operation_id,
        volume_id: volume(&row.0)?,
        version_id: version(&row.1)?,
        manifest_id: manifest(&row.2)?,
        source_scan_operation_id: operation(&row.3)?,
        scan_request_digest: array(&row.4)?,
        reachability_subject_digest: row
            .16
            .as_deref()
            .map(array)
            .transpose()?
            .ok_or(RepositoryError::CorruptState)?,
        retention_policy_sequence: parse_positive(row.5)?,
        reachability_revision: revision(row.6)?,
        retained_root_count: parse_positive(row.7)?,
        retained_root_digest: array(&row.8)?,
        local_roots_digest: array(&row.9)?,
        proof_result_digest: array(&row.10)?,
        required_attestation_count: row
            .15
            .map(parse_positive)
            .transpose()?
            .ok_or(RepositoryError::CorruptState)?,
        proposed_at: UnixMicros::new(row.12),
        revision: revision(row.14)?,
    };
    let command = ProposeVersionCleanup {
        volume_id: intent.volume_id,
        version_id: intent.version_id,
        manifest_id: intent.manifest_id,
        source_scan_operation_id: intent.source_scan_operation_id,
        scan_request_digest: intent.scan_request_digest,
        reachability_subject_digest: intent.reachability_subject_digest,
        retention_policy_sequence: intent.retention_policy_sequence,
        reachability_revision: intent.reachability_revision,
        retained_root_count: intent.retained_root_count,
        retained_root_digest: intent.retained_root_digest,
        local_roots_digest: intent.local_roots_digest,
        proof_result_digest: intent.proof_result_digest,
    };
    if terminal_result_digest(command) != intent.proof_result_digest {
        return Err(RepositoryError::CorruptState);
    }
    Ok(intent)
}

fn required_participant_count(connection: &Connection) -> Result<u64, RepositoryError> {
    let count: i64 = connection.query_row(
        "SELECT count(*)
         FROM nodes n
         WHERE n.state IN (1, 2) AND (
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
         )",
        [],
        |row| row.get(0),
    )?;
    parse_u64(count)
}

fn validate_input(
    context: CommandContext,
    command: ProposeVersionCleanup,
) -> Result<(), RepositoryError> {
    if context.expected_revision != Some(command.reachability_revision)
        || command.reachability_revision == Revision::ZERO
        || command.retention_policy_sequence == 0
        || command.retained_root_count == 0
        || command.scan_request_digest == [0; 32]
        || command.reachability_subject_digest == [0; 32]
        || command.retained_root_digest == [0; 32]
        || command.local_roots_digest == [0; 32]
        || command.proof_result_digest == [0; 32]
        || context.operation_id == command.source_scan_operation_id
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

fn validate_policy(
    connection: &Connection,
    command: ProposeVersionCleanup,
) -> Result<(), RepositoryError> {
    let (latest, count): (Option<i64>, i64) = connection.query_row(
        "SELECT max(policy_sequence), count(*)
         FROM version_retention_policy_revisions WHERE volume_id = ?1",
        [command.volume_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let latest = latest
        .map(parse_positive)
        .transpose()?
        .ok_or(RepositoryError::InvalidCommand)?;
    if latest != parse_u64(count)? || latest != command.retention_policy_sequence {
        Err(RepositoryError::StaleRetentionPolicy)
    } else {
        Ok(())
    }
}

fn terminal_result_digest(command: ProposeVersionCleanup) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.version-reachability-result.v1\0");
    digest.update(&command.source_scan_operation_id.as_bytes());
    digest.update(&command.scan_request_digest);
    digest.update(&command.local_roots_digest);
    digest.update(&[UNREACHABLE_STATE_CODE]);
    digest.finalize().into()
}

fn parse_positive(value: i64) -> Result<u64, RepositoryError> {
    let value = parse_u64(value)?;
    if value == 0 {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(value)
    }
}

fn revision(value: i64) -> Result<Revision, RepositoryError> {
    parse_positive(value).map(Revision::new)
}

fn parse_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], RepositoryError> {
    bytes.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn volume(bytes: &[u8]) -> Result<VolumeId, RepositoryError> {
    VolumeId::from_bytes(array(bytes)?).map_err(|_| RepositoryError::CorruptState)
}

fn version(bytes: &[u8]) -> Result<FileVersionId, RepositoryError> {
    FileVersionId::from_bytes(array(bytes)?).map_err(|_| RepositoryError::CorruptState)
}

fn manifest(bytes: &[u8]) -> Result<ContentManifestId, RepositoryError> {
    ContentManifestId::from_bytes(array(bytes)?).map_err(|_| RepositoryError::CorruptState)
}

fn operation(bytes: &[u8]) -> Result<OperationId, RepositoryError> {
    OperationId::from_bytes(array(bytes)?).map_err(|_| RepositoryError::CorruptState)
}
