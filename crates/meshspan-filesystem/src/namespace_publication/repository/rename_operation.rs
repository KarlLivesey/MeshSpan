// SPDX-License-Identifier: GPL-2.0-only

//! Durable idempotency receipt for one two-path namespace rename.

use meshspan_domain::{NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::super::digest::rename_result;
use crate::publication::{copy_array, decode_identifier, from_i64, to_i64};
use crate::{
    NamespaceRenamePublication, NamespaceRenameReceipt, PublicationDisposition, PublicationError,
};

type StoredReceipt = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>);

pub(in crate::publication) fn persist(
    transaction: &Transaction<'_>,
    publication: &NamespaceRenamePublication,
    request_digest: [u8; 32],
    head_sequence: u64,
) -> Result<NamespaceRenameReceipt, PublicationError> {
    let result_digest = rename_result(
        publication.operation_id,
        request_digest,
        publication.expected_object_id,
        publication.expected_object_revision_id,
        publication.namespace_commit_id,
        head_sequence,
    );
    transaction.execute(
        "INSERT INTO namespace_rename_operations(
            operation_id, request_digest, namespace_commit_id, object_id,
            object_revision_id, head_sequence, result_digest, committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            publication.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            publication.namespace_commit_id.as_bytes().as_slice(),
            publication.expected_object_id.as_bytes().as_slice(),
            publication
                .expected_object_revision_id
                .as_bytes()
                .as_slice(),
            to_i64(head_sequence)?,
            result_digest.as_slice(),
            publication.created_at.get(),
        ],
    )?;
    Ok(NamespaceRenameReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id: publication.operation_id,
        request_digest,
        object_id: publication.expected_object_id,
        object_revision_id: publication.expected_object_revision_id,
        namespace_commit_id: publication.namespace_commit_id,
        head_sequence,
        result_digest,
    })
}

pub(in crate::publication) fn load(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<NamespaceRenameReceipt>, PublicationError> {
    let stored: Option<StoredReceipt> = connection
        .query_row(
            "SELECT request_digest, namespace_commit_id, object_id, object_revision_id,
                    head_sequence, result_digest
             FROM namespace_rename_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
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
    stored
        .as_ref()
        .map(|stored| decode(operation_id, disposition, stored))
        .transpose()
}

fn decode(
    operation_id: OperationId,
    disposition: PublicationDisposition,
    stored: &StoredReceipt,
) -> Result<NamespaceRenameReceipt, PublicationError> {
    let receipt = NamespaceRenameReceipt {
        disposition,
        operation_id,
        request_digest: copy_array(&stored.0)?,
        namespace_commit_id: decode_identifier(&stored.1, NamespaceCommitId::from_bytes)?,
        object_id: decode_identifier(&stored.2, ObjectId::from_bytes)?,
        object_revision_id: decode_identifier(&stored.3, ObjectRevisionId::from_bytes)?,
        head_sequence: from_i64(stored.4)?,
        result_digest: copy_array(&stored.5)?,
    };
    let expected = rename_result(
        receipt.operation_id,
        receipt.request_digest,
        receipt.object_id,
        receipt.object_revision_id,
        receipt.namespace_commit_id,
        receipt.head_sequence,
    );
    if receipt.result_digest == expected {
        Ok(receipt)
    } else {
        Err(PublicationError::Corrupt)
    }
}
