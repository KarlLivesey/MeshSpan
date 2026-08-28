// SPDX-License-Identifier: GPL-2.0-only

//! Prepared whole-volume snapshot restore and post-consensus local activation.

use meshspan_contracts::namespace_snapshot_restore_result_digest;
use meshspan_domain::{NamespaceCommitId, OperationId, SnapshotId, UnixMicros};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::digest::snapshot_restore_request;
use super::repository::{
    StoredCommit, load_commit, load_head, load_object_revision, load_reconciliation_commit,
    persist_stored_commit,
};
use super::{NamespaceFaultPoint, inject};
use crate::publication::{
    BranchNamespaceHead, PublicationDisposition, PublicationError, SnapshotRestorePublication,
    SnapshotRestoreReceipt, copy_array, decode_identifier, to_i64,
};

type StoredReceipt = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

pub(super) fn prepare(
    connection: &mut Connection,
    publication: SnapshotRestorePublication,
    fault: Option<NamespaceFaultPoint>,
) -> Result<SnapshotRestoreReceipt, PublicationError> {
    validate_distinct_identities(publication)?;
    let request_digest = snapshot_restore_request(publication);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(receipt) = load_receipt_raw(
        &transaction,
        publication.operation_id,
        PublicationDisposition::Replayed,
    )? {
        return if receipt.request_digest == request_digest {
            Ok(receipt)
        } else {
            Err(PublicationError::OperationConflict)
        };
    }
    reject_operation_collision(&transaction, publication.operation_id)?;
    validate_source_state(&transaction, publication)?;

    persist_stored_commit(
        &transaction,
        &StoredCommit {
            commit_id: publication.namespace_commit_id,
            branch_id: publication.branch_id,
            volume_id: publication.volume_id,
            root_object_id: publication.root_object_id,
            root_object_revision_id: publication.root_object_revision_id,
            parent_id: Some(publication.expected_namespace_commit_id),
            created_by: publication.created_by,
            operation_id: publication.operation_id,
            created_at: publication.created_at,
        },
        request_digest,
    )?;
    inject(fault, NamespaceFaultPoint::SnapshotRestoreCommit)?;
    let receipt = persist_receipt(&transaction, publication, request_digest)?;
    inject(fault, NamespaceFaultPoint::SnapshotRestoreOperation)?;
    transaction.commit()?;
    Ok(receipt)
}

pub(super) fn activate(
    connection: &mut Connection,
    supplied: SnapshotRestoreReceipt,
    activated_at: UnixMicros,
) -> Result<BranchNamespaceHead, PublicationError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let durable = load_receipt_raw(
        &transaction,
        supplied.operation_id,
        PublicationDisposition::Replayed,
    )?
    .ok_or(PublicationError::InvalidInput)?;
    if !same_outcome(durable, supplied) {
        return Err(PublicationError::OperationConflict);
    }
    let commit = load_commit(&transaction, durable.namespace_commit_id)?;
    if commit.operation_id != durable.operation_id
        || commit.parent_id != Some(durable.expected_namespace_commit_id)
        || commit.root_object_revision_id != durable.root_object_revision_id
        || commit.created_at.get() > activated_at.get()
    {
        return Err(PublicationError::Corrupt);
    }
    let current = load_head(&transaction, commit.branch_id, commit.volume_id)?
        .ok_or(PublicationError::StaleHead)?;
    let sequence = if current.namespace_commit_id == durable.namespace_commit_id {
        current.sequence
    } else if current.namespace_commit_id == durable.expected_namespace_commit_id {
        let next = current
            .sequence
            .checked_add(1)
            .ok_or(PublicationError::InvalidInput)?;
        let changed = transaction.execute(
            "UPDATE branch_namespace_heads SET namespace_commit_id = ?1, head_sequence = ?2
             WHERE branch_id = ?3 AND volume_id = ?4
               AND namespace_commit_id = ?5 AND head_sequence = ?6",
            params![
                durable.namespace_commit_id.as_bytes().as_slice(),
                to_i64(next)?,
                commit.branch_id.as_bytes().as_slice(),
                commit.volume_id.as_bytes().as_slice(),
                durable.expected_namespace_commit_id.as_bytes().as_slice(),
                to_i64(current.sequence)?,
            ],
        )?;
        if changed != 1 {
            return Err(PublicationError::StaleHead);
        }
        next
    } else {
        return Err(PublicationError::StaleHead);
    };
    transaction.execute(
        "UPDATE namespace_snapshot_restore_operations
         SET activated_at = COALESCE(activated_at, ?1) WHERE operation_id = ?2",
        params![
            activated_at.get(),
            durable.operation_id.as_bytes().as_slice()
        ],
    )?;
    transaction.commit()?;
    Ok(BranchNamespaceHead {
        branch_id: commit.branch_id,
        volume_id: commit.volume_id,
        namespace_commit_id: durable.namespace_commit_id,
        sequence,
    })
}

pub(super) fn load_receipt(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<SnapshotRestoreReceipt>, PublicationError> {
    let Some(receipt) = load_receipt_raw(connection, operation_id, disposition)? else {
        return Ok(None);
    };
    let commit = load_commit(connection, receipt.namespace_commit_id)?;
    if commit.operation_id != operation_id
        || commit.parent_id != Some(receipt.expected_namespace_commit_id)
        || commit.root_object_revision_id != receipt.root_object_revision_id
    {
        return Err(PublicationError::Corrupt);
    }
    validate_receipt_source(connection, receipt, commit.volume_id, commit.root_object_id)?;
    Ok(Some(receipt))
}

pub(super) fn verify_head(
    connection: &Connection,
    volume_id: meshspan_domain::VolumeId,
    supplied: SnapshotRestoreReceipt,
) -> Result<crate::publication::VerifiedSnapshotRestoreHead, PublicationError> {
    let durable = load_receipt(
        connection,
        supplied.operation_id,
        PublicationDisposition::Replayed,
    )?
    .ok_or(PublicationError::InvalidInput)?;
    if !same_outcome(durable, supplied) {
        return Err(PublicationError::OperationConflict);
    }
    let commit = load_commit(connection, durable.namespace_commit_id)?;
    if commit.volume_id != volume_id {
        return Err(PublicationError::InvalidInput);
    }
    Ok(crate::publication::VerifiedSnapshotRestoreHead::new(
        durable, volume_id,
    ))
}

pub(super) fn validate_receipt_source(
    connection: &Connection,
    receipt: SnapshotRestoreReceipt,
    volume_id: meshspan_domain::VolumeId,
    root_object_id: meshspan_domain::ObjectId,
) -> Result<(), PublicationError> {
    let stored: (Vec<u8>, Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT volume_id, root_object_id, root_object_revision_id
         FROM namespace_commits WHERE namespace_commit_id = ?1",
        [receipt.snapshot_namespace_commit_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if stored.0.as_slice() == volume_id.as_bytes()
        && stored.1.as_slice() == root_object_id.as_bytes()
        && stored.2.as_slice() == receipt.root_object_revision_id.as_bytes()
    {
        Ok(())
    } else {
        Err(PublicationError::Corrupt)
    }
}

pub(super) fn load_receipt_raw(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<SnapshotRestoreReceipt>, PublicationError> {
    let stored: Option<StoredReceipt> = connection
        .query_row(
            "SELECT request_digest, snapshot_id, snapshot_namespace_commit_id,
                    expected_namespace_commit_id, namespace_commit_id,
                    root_object_revision_id, result_digest
             FROM namespace_snapshot_restore_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .optional()?;
    stored
        .map(|stored| decode_receipt(operation_id, disposition, &stored))
        .transpose()
}

fn validate_distinct_identities(
    publication: SnapshotRestorePublication,
) -> Result<(), PublicationError> {
    if publication.namespace_commit_id == publication.expected_namespace_commit_id
        || publication.namespace_commit_id == publication.snapshot_namespace_commit_id
    {
        Err(PublicationError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_source_state(
    transaction: &Transaction<'_>,
    publication: SnapshotRestorePublication,
) -> Result<(), PublicationError> {
    let current = load_head(transaction, publication.branch_id, publication.volume_id)?
        .ok_or(PublicationError::StaleHead)?;
    if current.namespace_commit_id != publication.expected_namespace_commit_id {
        return Err(PublicationError::StaleHead);
    }
    let expected =
        load_reconciliation_commit(transaction, publication.expected_namespace_commit_id)?
            .ok_or(PublicationError::Corrupt)?;
    let snapshot =
        load_reconciliation_commit(transaction, publication.snapshot_namespace_commit_id)?
            .ok_or(PublicationError::InvalidInput)?;
    if expected.branch_id != publication.branch_id
        || expected.volume_id != publication.volume_id
        || expected.root_object_id != publication.root_object_id
        || snapshot.volume_id != publication.volume_id
        || snapshot.root_object_id != publication.root_object_id
        || snapshot.root_object_revision_id != publication.root_object_revision_id
    {
        return Err(PublicationError::InvalidInput);
    }
    let root = load_object_revision(transaction, publication.root_object_revision_id)?;
    if root.volume_id != publication.volume_id
        || root.object_id != publication.root_object_id
        || root.kind != 1
        || root.directory_root.is_none()
        || root.file_version_id.is_some()
    {
        return Err(PublicationError::Corrupt);
    }
    Ok(())
}

fn reject_operation_collision(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
) -> Result<(), PublicationError> {
    let collision: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM namespace_publication_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM directory_publication_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM namespace_reconciliation_operations WHERE operation_id = ?1)",
        [operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if collision == 0 {
        Ok(())
    } else {
        Err(PublicationError::OperationConflict)
    }
}

fn persist_receipt(
    transaction: &Transaction<'_>,
    publication: SnapshotRestorePublication,
    request_digest: [u8; 32],
) -> Result<SnapshotRestoreReceipt, PublicationError> {
    let result_digest = namespace_snapshot_restore_result_digest(
        publication.operation_id,
        request_digest,
        publication.snapshot_id,
        publication.snapshot_namespace_commit_id,
        publication.expected_namespace_commit_id,
        publication.namespace_commit_id,
        publication.root_object_revision_id,
    );
    transaction.execute(
        "INSERT INTO namespace_snapshot_restore_operations(
            operation_id, request_digest, snapshot_id, snapshot_namespace_commit_id,
            expected_namespace_commit_id, namespace_commit_id, root_object_revision_id,
            result_digest, prepared_at, activated_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
        params![
            publication.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            publication.snapshot_id.as_bytes().as_slice(),
            publication
                .snapshot_namespace_commit_id
                .as_bytes()
                .as_slice(),
            publication
                .expected_namespace_commit_id
                .as_bytes()
                .as_slice(),
            publication.namespace_commit_id.as_bytes().as_slice(),
            publication.root_object_revision_id.as_bytes().as_slice(),
            result_digest.as_slice(),
            publication.created_at.get(),
        ],
    )?;
    Ok(SnapshotRestoreReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id: publication.operation_id,
        request_digest,
        snapshot_id: publication.snapshot_id,
        snapshot_namespace_commit_id: publication.snapshot_namespace_commit_id,
        expected_namespace_commit_id: publication.expected_namespace_commit_id,
        namespace_commit_id: publication.namespace_commit_id,
        root_object_revision_id: publication.root_object_revision_id,
        result_digest,
    })
}

fn decode_receipt(
    operation_id: OperationId,
    disposition: PublicationDisposition,
    stored: &StoredReceipt,
) -> Result<SnapshotRestoreReceipt, PublicationError> {
    let receipt = SnapshotRestoreReceipt {
        disposition,
        operation_id,
        request_digest: copy_array(&stored.0)?,
        snapshot_id: decode_identifier(&stored.1, SnapshotId::from_bytes)?,
        snapshot_namespace_commit_id: decode_identifier(&stored.2, NamespaceCommitId::from_bytes)?,
        expected_namespace_commit_id: decode_identifier(&stored.3, NamespaceCommitId::from_bytes)?,
        namespace_commit_id: decode_identifier(&stored.4, NamespaceCommitId::from_bytes)?,
        root_object_revision_id: decode_identifier(
            &stored.5,
            meshspan_domain::ObjectRevisionId::from_bytes,
        )?,
        result_digest: copy_array(&stored.6)?,
    };
    let expected = namespace_snapshot_restore_result_digest(
        receipt.operation_id,
        receipt.request_digest,
        receipt.snapshot_id,
        receipt.snapshot_namespace_commit_id,
        receipt.expected_namespace_commit_id,
        receipt.namespace_commit_id,
        receipt.root_object_revision_id,
    );
    if expected == receipt.result_digest {
        Ok(receipt)
    } else {
        Err(PublicationError::Corrupt)
    }
}

fn same_outcome(left: SnapshotRestoreReceipt, right: SnapshotRestoreReceipt) -> bool {
    left.operation_id == right.operation_id
        && left.request_digest == right.request_digest
        && left.snapshot_id == right.snapshot_id
        && left.snapshot_namespace_commit_id == right.snapshot_namespace_commit_id
        && left.expected_namespace_commit_id == right.expected_namespace_commit_id
        && left.namespace_commit_id == right.namespace_commit_id
        && left.root_object_revision_id == right.root_object_revision_id
        && left.result_digest == right.result_digest
}
