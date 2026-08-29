// SPDX-License-Identifier: GPL-2.0-only

//! Durable idempotency receipt for one logical namespace removal.

use meshspan_domain::{NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::super::digest::unlink_result;
use crate::publication::{copy_array, decode_identifier, from_i64, to_i64};
use crate::{
    DirectoryEntryKind, NamespaceUnlinkPublication, NamespaceUnlinkReceipt, PublicationDisposition,
    PublicationError,
};

type StoredReceipt = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, Vec<u8>);

pub(in crate::publication) fn persist(
    transaction: &Transaction<'_>,
    publication: &NamespaceUnlinkPublication,
    request_digest: [u8; 32],
    head_sequence: u64,
) -> Result<NamespaceUnlinkReceipt, PublicationError> {
    let result_digest = unlink_result(
        publication.operation_id,
        request_digest,
        publication.expected_object_id,
        publication.expected_object_revision_id,
        publication.expected_kind,
        publication.namespace_commit_id,
        head_sequence,
    );
    transaction.execute(
        "INSERT INTO namespace_unlink_operations(
            operation_id, request_digest, namespace_commit_id, object_id,
            object_revision_id, object_kind, head_sequence, result_digest, committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            publication.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            publication.namespace_commit_id.as_bytes().as_slice(),
            publication.expected_object_id.as_bytes().as_slice(),
            publication
                .expected_object_revision_id
                .as_bytes()
                .as_slice(),
            kind_code(publication.expected_kind),
            to_i64(head_sequence)?,
            result_digest.as_slice(),
            publication.created_at.get(),
        ],
    )?;
    Ok(NamespaceUnlinkReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id: publication.operation_id,
        request_digest,
        object_id: publication.expected_object_id,
        object_revision_id: publication.expected_object_revision_id,
        object_kind: publication.expected_kind,
        namespace_commit_id: publication.namespace_commit_id,
        head_sequence,
        result_digest,
    })
}

pub(in crate::publication) fn load(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<NamespaceUnlinkReceipt>, PublicationError> {
    let stored: Option<StoredReceipt> = connection
        .query_row(
            "SELECT request_digest, namespace_commit_id, object_id, object_revision_id,
                    object_kind, head_sequence, result_digest
             FROM namespace_unlink_operations WHERE operation_id = ?1",
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
        .as_ref()
        .map(|stored| decode(operation_id, disposition, stored))
        .transpose()
}

fn decode(
    operation_id: OperationId,
    disposition: PublicationDisposition,
    stored: &StoredReceipt,
) -> Result<NamespaceUnlinkReceipt, PublicationError> {
    let receipt = NamespaceUnlinkReceipt {
        disposition,
        operation_id,
        request_digest: copy_array(&stored.0)?,
        namespace_commit_id: decode_identifier(&stored.1, NamespaceCommitId::from_bytes)?,
        object_id: decode_identifier(&stored.2, ObjectId::from_bytes)?,
        object_revision_id: decode_identifier(&stored.3, ObjectRevisionId::from_bytes)?,
        object_kind: decode_kind(stored.4)?,
        head_sequence: from_i64(stored.5)?,
        result_digest: copy_array(&stored.6)?,
    };
    let expected = unlink_result(
        receipt.operation_id,
        receipt.request_digest,
        receipt.object_id,
        receipt.object_revision_id,
        receipt.object_kind,
        receipt.namespace_commit_id,
        receipt.head_sequence,
    );
    if receipt.result_digest == expected {
        Ok(receipt)
    } else {
        Err(PublicationError::Corrupt)
    }
}

const fn kind_code(kind: DirectoryEntryKind) -> u8 {
    match kind {
        DirectoryEntryKind::Directory => 1,
        DirectoryEntryKind::File => 2,
    }
}

const fn decode_kind(kind: i64) -> Result<DirectoryEntryKind, PublicationError> {
    match kind {
        1 => Ok(DirectoryEntryKind::Directory),
        2 => Ok(DirectoryEntryKind::File),
        _ => Err(PublicationError::Corrupt),
    }
}
