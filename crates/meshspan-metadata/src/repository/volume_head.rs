// SPDX-License-Identifier: GPL-2.0-only

//! Replicated globally converged volume-head compare-and-swap and evidence history.

use meshspan_contracts::namespace_reconciliation_result_digest;
use meshspan_domain::{
    NamespaceCommitId, ObjectRevisionId, OperationId, Revision, UnixMicros, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError, namespace};
use crate::{CommandContext, CommitConvergedVolumeHead, ConvergedHeadEvidence, PartitionDatabase};

/// Exact replicated head and local durability evidence currently selected for one volume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConvergedVolumeHead {
    /// Volume whose authoritative head this is.
    pub volume_id: VolumeId,
    /// Current globally converged immutable namespace commit.
    pub namespace_commit_id: NamespaceCommitId,
    /// Root object revision selected by the namespace commit.
    pub root_object_revision_id: ObjectRevisionId,
    /// Exact local publication or reconciliation evidence accepted for this transition.
    pub evidence: ConvergedHeadEvidence,
    /// Per-volume monotonic head-transition sequence.
    pub sequence: u64,
    /// Replicated metadata operation that committed this transition.
    pub metadata_operation_id: OperationId,
    /// Authoritative commit instant from the replicated command.
    pub committed_at: UnixMicros,
    /// Replicated state revision created by the transition.
    pub revision: Revision,
}

pub(super) fn commit(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CommitConvergedVolumeHead,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let volume = command.volume_id.as_bytes();
    let active: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM volumes WHERE volume_id = ?1 AND state = 1)",
        [volume.as_slice()],
        |row| row.get(0),
    )?;
    if active != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    let current = load_current_row(transaction, command.volume_id)?;
    let current_commit = current.as_ref().map(|row| row.namespace_commit_id);
    if current_commit != command.expected_namespace_commit_id {
        return Err(RepositoryError::StaleVolumeHead);
    }
    if command.expected_namespace_commit_id == Some(command.namespace_commit_id)
        || matches!(
            command.evidence,
            ConvergedHeadEvidence::Reconciliation { .. }
        ) && current.is_none()
    {
        return Err(RepositoryError::InvalidCommand);
    }
    validate_evidence(command)?;
    let sequence = current.map_or(Ok(1_u64), |row| {
        row.sequence
            .checked_add(1)
            .ok_or(RepositoryError::CapacityExceeded)
    })?;
    insert_transition(transaction, context, command, revision, sequence)?;
    namespace::update_namespace_revision(transaction, revision)?;
    Ok(EntityReference {
        kind: EntityKind::Volume,
        id: volume,
    })
}

fn validate_evidence(command: &CommitConvergedVolumeHead) -> Result<(), RepositoryError> {
    let ConvergedHeadEvidence::Reconciliation {
        operation_id,
        request_digest,
        causal_plan_digest,
        replay_plan_digest,
        result_digest,
    } = command.evidence
    else {
        return Ok(());
    };
    let expected = namespace_reconciliation_result_digest(
        operation_id,
        command.namespace_commit_id,
        request_digest,
        causal_plan_digest,
        replay_plan_digest,
        command.root_object_revision_id,
    );
    if result_digest == expected {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

struct CurrentHeadRow {
    namespace_commit_id: NamespaceCommitId,
    sequence: u64,
}

fn load_current_row(
    transaction: &Transaction<'_>,
    volume_id: VolumeId,
) -> Result<Option<CurrentHeadRow>, RepositoryError> {
    let current = transaction
        .query_row(
            "SELECT namespace_commit_id, head_sequence
             FROM volume_head_transitions WHERE volume_id = ?1
             ORDER BY head_sequence DESC LIMIT 1",
            [volume_id.as_bytes().as_slice()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?
        .map(|(commit, sequence)| {
            Ok::<CurrentHeadRow, RepositoryError>(CurrentHeadRow {
                namespace_commit_id: decode_identifier(&commit, NamespaceCommitId::from_bytes)?,
                sequence: parse_u64(sequence)?,
            })
        })
        .transpose()?;
    validate_history(
        transaction,
        volume_id,
        current.as_ref().map(|row| row.sequence),
    )?;
    Ok(current)
}

fn validate_history(
    connection: &Connection,
    volume_id: VolumeId,
    latest: Option<u64>,
) -> Result<(), RepositoryError> {
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM volume_head_transitions WHERE volume_id = ?1",
        [volume_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    let broken: i64 = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM (
                 SELECT head_sequence, previous_namespace_commit_id,
                        row_number() OVER (ORDER BY head_sequence) AS expected_sequence,
                        lag(namespace_commit_id) OVER (ORDER BY head_sequence) AS expected_previous
                 FROM volume_head_transitions WHERE volume_id = ?1
             )
             WHERE head_sequence <> expected_sequence
                OR (head_sequence > 1 AND previous_namespace_commit_id <> expected_previous)
         )",
        [volume_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if latest.unwrap_or(0) == parse_u64(count)? && broken == 0 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn insert_transition(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &CommitConvergedVolumeHead,
    revision: Revision,
    sequence: u64,
) -> Result<(), RepositoryError> {
    let (kind, source_operation, request, causal, replay, result) =
        evidence_fields(command.evidence);
    let previous = command
        .expected_namespace_commit_id
        .map(NamespaceCommitId::as_bytes);
    transaction.execute(
        "INSERT INTO volume_head_transitions(
            volume_id, head_sequence, previous_namespace_commit_id, namespace_commit_id,
            root_object_revision_id, evidence_kind, source_operation_id, source_request_digest,
            causal_plan_digest, replay_plan_digest, source_result_digest, metadata_operation_id,
            committed_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            command.volume_id.as_bytes().as_slice(),
            to_i64(sequence)?,
            previous.as_ref().map(<[u8; 16]>::as_slice),
            command.namespace_commit_id.as_bytes().as_slice(),
            command.root_object_revision_id.as_bytes().as_slice(),
            kind,
            source_operation.as_bytes().as_slice(),
            request.as_slice(),
            causal.as_ref().map(<[u8; 32]>::as_slice),
            replay.as_ref().map(<[u8; 32]>::as_slice),
            result.as_slice(),
            context.operation_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(())
}

type EvidenceFields = (
    u8,
    OperationId,
    [u8; 32],
    Option<[u8; 32]>,
    Option<[u8; 32]>,
    [u8; 32],
);

const fn evidence_fields(evidence: ConvergedHeadEvidence) -> EvidenceFields {
    match evidence {
        ConvergedHeadEvidence::Publication {
            operation_id,
            request_digest,
            result_digest,
        } => (1, operation_id, request_digest, None, None, result_digest),
        ConvergedHeadEvidence::Reconciliation {
            operation_id,
            request_digest,
            causal_plan_digest,
            replay_plan_digest,
            result_digest,
        } => (
            2,
            operation_id,
            request_digest,
            Some(causal_plan_digest),
            Some(replay_plan_digest),
            result_digest,
        ),
    }
}

type StoredHead = (
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
    i64,
);

pub(super) fn load(
    database: &PartitionDatabase,
    volume_id: VolumeId,
) -> Result<Option<ConvergedVolumeHead>, RepositoryError> {
    let stored: Option<StoredHead> = database
        .connection()
        .query_row(
            "SELECT namespace_commit_id, root_object_revision_id, evidence_kind,
                    source_operation_id, source_request_digest, causal_plan_digest,
                    replay_plan_digest, source_result_digest, head_sequence,
                    metadata_operation_id, committed_at, revision
             FROM volume_head_transitions WHERE volume_id = ?1
             ORDER BY head_sequence DESC LIMIT 1",
            [volume_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let sequence = parse_u64(stored.8)?;
    validate_history(database.connection(), volume_id, Some(sequence))?;
    decode_head(volume_id, sequence, &stored).map(Some)
}

fn decode_head(
    volume_id: VolumeId,
    sequence: u64,
    stored: &StoredHead,
) -> Result<ConvergedVolumeHead, RepositoryError> {
    let operation_id = decode_identifier(&stored.3, OperationId::from_bytes)?;
    let request_digest = decode_digest(&stored.4)?;
    let result_digest = decode_digest(&stored.7)?;
    let evidence = match (stored.2, stored.5.as_deref(), stored.6.as_deref()) {
        (1, None, None) => ConvergedHeadEvidence::Publication {
            operation_id,
            request_digest,
            result_digest,
        },
        (2, Some(causal), Some(replay)) => ConvergedHeadEvidence::Reconciliation {
            operation_id,
            request_digest,
            causal_plan_digest: decode_digest(causal)?,
            replay_plan_digest: decode_digest(replay)?,
            result_digest,
        },
        _ => return Err(RepositoryError::CorruptState),
    };
    Ok(ConvergedVolumeHead {
        volume_id,
        namespace_commit_id: decode_identifier(&stored.0, NamespaceCommitId::from_bytes)?,
        root_object_revision_id: decode_identifier(&stored.1, ObjectRevisionId::from_bytes)?,
        evidence,
        sequence,
        metadata_operation_id: decode_identifier(&stored.9, OperationId::from_bytes)?,
        committed_at: UnixMicros::new(stored.10),
        revision: Revision::new(parse_u64(stored.11)?),
    })
}

fn decode_identifier<T>(
    bytes: &[u8],
    constructor: fn([u8; 16]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, RepositoryError> {
    constructor(
        bytes
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn decode_digest(bytes: &[u8]) -> Result<[u8; 32], RepositoryError> {
    bytes.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn parse_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}
