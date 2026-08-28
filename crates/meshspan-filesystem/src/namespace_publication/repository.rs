// SPDX-License-Identifier: GPL-2.0-only

//! Durable namespace commit, object-revision, head and operation-receipt repository.

use meshspan_domain::{
    BranchId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::digest::{
    commit as commit_digest, commit_fields as commit_digest_fields,
    directory_result as directory_result_digest, file_result as result_digest,
    object_revision as object_revision_digest,
};
use super::{DirectoryRevisionResult, NamespaceIntent};
use crate::publication::{copy_array, decode_identifier, from_i64, to_i64};
use crate::{
    BranchNamespaceHead, DirectoryNodeDigest, DirectoryPublication, DirectoryPublicationReceipt,
    NamespacePublicationReceipt, PublicationDisposition, PublicationError, RootFilePublication,
};

pub(in crate::publication) fn load_head(
    connection: &Connection,
    branch_id: BranchId,
    volume_id: VolumeId,
) -> Result<Option<BranchNamespaceHead>, PublicationError> {
    let stored: Option<(Vec<u8>, i64)> = connection
        .query_row(
            "SELECT namespace_commit_id, head_sequence
             FROM branch_namespace_heads WHERE branch_id = ?1 AND volume_id = ?2",
            params![
                branch_id.as_bytes().as_slice(),
                volume_id.as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    stored
        .map(|(commit, sequence)| {
            let head = BranchNamespaceHead {
                branch_id,
                volume_id,
                namespace_commit_id: decode_identifier(&commit, NamespaceCommitId::from_bytes)?,
                sequence: from_i64(sequence)?,
            };
            let selected = load_commit(connection, head.namespace_commit_id)?;
            if selected.branch_id == branch_id && selected.volume_id == volume_id {
                Ok(head)
            } else {
                Err(PublicationError::Corrupt)
            }
        })
        .transpose()
}

pub(in crate::publication) fn load_file_operation(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<NamespacePublicationReceipt>, PublicationError> {
    let receipt = load_file_operation_raw(connection, operation_id, disposition)?;
    if let Some(receipt) = receipt {
        let commit = load_commit(connection, receipt.namespace_commit_id)?;
        if commit.operation_id == operation_id {
            Ok(Some(receipt))
        } else {
            Err(PublicationError::Corrupt)
        }
    } else {
        Ok(None)
    }
}

pub(super) fn load_file_operation_raw(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<NamespacePublicationReceipt>, PublicationError> {
    let stored: Option<StoredReceipt> = connection
        .query_row(
            "SELECT request_digest, namespace_commit_id, file_version_id,
                    head_sequence, result_digest
             FROM namespace_publication_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    stored
        .map(|values| decode_file_receipt(operation_id, disposition, &values))
        .transpose()
}

pub(in crate::publication) fn load_directory_operation(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<DirectoryPublicationReceipt>, PublicationError> {
    let receipt = load_directory_operation_raw(connection, operation_id, disposition)?;
    if let Some(receipt) = receipt {
        let commit = load_commit(connection, receipt.namespace_commit_id)?;
        if commit.operation_id == operation_id {
            Ok(Some(receipt))
        } else {
            Err(PublicationError::Corrupt)
        }
    } else {
        Ok(None)
    }
}

pub(super) fn load_directory_operation_raw(
    connection: &Connection,
    operation_id: OperationId,
    disposition: PublicationDisposition,
) -> Result<Option<DirectoryPublicationReceipt>, PublicationError> {
    let stored: Option<StoredDirectoryReceipt> = connection
        .query_row(
            "SELECT request_digest, namespace_commit_id, directory_object_revision_id,
                    head_sequence, result_digest
             FROM directory_publication_operations WHERE operation_id = ?1",
            [operation_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    stored
        .map(|values| decode_directory_receipt(operation_id, disposition, &values))
        .transpose()
}

pub(super) struct StoredCommit {
    pub(super) commit_id: NamespaceCommitId,
    pub(super) branch_id: BranchId,
    pub(super) volume_id: VolumeId,
    pub(super) root_object_id: ObjectId,
    pub(super) root_object_revision_id: ObjectRevisionId,
    pub(super) parent_id: Option<NamespaceCommitId>,
    pub(super) created_by: meshspan_domain::PrincipalId,
    pub(super) operation_id: OperationId,
    pub(super) created_at: meshspan_domain::UnixMicros,
}

pub(super) fn load_commit(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Result<StoredCommit, PublicationError> {
    type StoredCommitColumns = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        Vec<u8>,
    );
    let stored: StoredCommitColumns = connection.query_row(
        "SELECT branch_id, volume_id, root_object_id, root_object_revision_id,
                created_by, publication_operation_id, created_at, commit_digest
         FROM namespace_commits WHERE namespace_commit_id = ?1",
        [commit_id.as_bytes().as_slice()],
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
            ))
        },
    )?;
    let commit = StoredCommit {
        commit_id,
        branch_id: decode_identifier(&stored.0, BranchId::from_bytes)?,
        volume_id: decode_identifier(&stored.1, VolumeId::from_bytes)?,
        root_object_id: decode_identifier(&stored.2, ObjectId::from_bytes)?,
        root_object_revision_id: decode_identifier(&stored.3, ObjectRevisionId::from_bytes)?,
        parent_id: load_single_parent(connection, commit_id)?,
        created_by: decode_identifier(&stored.4, meshspan_domain::PrincipalId::from_bytes)?,
        operation_id: decode_identifier(&stored.5, OperationId::from_bytes)?,
        created_at: meshspan_domain::UnixMicros::new(stored.6),
    };
    let request_digest = load_commit_request_digest(connection, commit.operation_id, commit_id)?;
    if copy_array(&stored.7)? == commit_digest_fields(&commit, request_digest) {
        Ok(commit)
    } else {
        Err(PublicationError::Corrupt)
    }
}

pub(in crate::publication) fn load_reconciliation_commit(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Result<Option<crate::ReconciliationCommit>, PublicationError> {
    let exists: i64 = connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM namespace_commits WHERE namespace_commit_id = ?1
         )",
        [commit_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if exists == 0 {
        return Ok(None);
    }
    let commit = load_commit(connection, commit_id)?;
    let request_digest =
        load_commit_request_digest(connection, commit.operation_id, commit.commit_id)?;
    Ok(Some(crate::ReconciliationCommit {
        commit_id: commit.commit_id,
        branch_id: commit.branch_id,
        volume_id: commit.volume_id,
        root_object_id: commit.root_object_id,
        root_object_revision_id: commit.root_object_revision_id,
        parents: commit.parent_id.into_iter().collect(),
        operation_id: commit.operation_id,
        request_digest,
    }))
}

fn load_commit_request_digest(
    connection: &Connection,
    operation_id: OperationId,
    commit_id: NamespaceCommitId,
) -> Result<[u8; 32], PublicationError> {
    let file = load_file_operation_raw(connection, operation_id, PublicationDisposition::Replayed)?;
    let directory =
        load_directory_operation_raw(connection, operation_id, PublicationDisposition::Replayed)?;
    match (file, directory) {
        (Some(receipt), None) if receipt.namespace_commit_id == commit_id => {
            Ok(receipt.request_digest)
        }
        (None, Some(receipt)) if receipt.namespace_commit_id == commit_id => {
            Ok(receipt.request_digest)
        }
        _ => Err(PublicationError::Corrupt),
    }
}

fn load_single_parent(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Result<Option<NamespaceCommitId>, PublicationError> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM namespace_commit_parents WHERE namespace_commit_id = ?1",
        [commit_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if count > 1 {
        return Err(PublicationError::Corrupt);
    }
    connection
        .query_row(
            "SELECT parent_commit_id FROM namespace_commit_parents
             WHERE namespace_commit_id = ?1 AND parent_ordinal = 0",
            [commit_id.as_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map(|bytes| decode_identifier(&bytes, NamespaceCommitId::from_bytes))
        .transpose()
}

#[derive(Clone, Copy)]
pub(super) struct ObjectRevisionInsert {
    pub(super) revision_id: ObjectRevisionId,
    pub(super) volume_id: VolumeId,
    pub(super) object_id: ObjectId,
    pub(super) kind: u8,
    pub(super) prior_revision_id: Option<ObjectRevisionId>,
    pub(super) directory_root: Option<DirectoryNodeDigest>,
    pub(super) file_version_id: Option<FileVersionId>,
    pub(super) created_by: meshspan_domain::PrincipalId,
    pub(super) created_at: meshspan_domain::UnixMicros,
}

pub(super) fn persist_object_revision(
    transaction: &Transaction<'_>,
    revision: ObjectRevisionInsert,
) -> Result<(), PublicationError> {
    let digest = object_revision_digest(&revision);
    let collision: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM object_revisions WHERE object_revision_id = ?1)",
        [revision.revision_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if collision != 0 {
        return Err(PublicationError::OperationConflict);
    }
    let prior = revision.prior_revision_id.map(ObjectRevisionId::as_bytes);
    let directory = revision.directory_root.map(DirectoryNodeDigest::as_bytes);
    let version = revision.file_version_id.map(FileVersionId::as_bytes);
    transaction.execute(
        "INSERT INTO object_revisions(
            object_revision_id, volume_id, object_id, object_kind, prior_revision_id,
            directory_root_digest, file_version_id, revision_digest, created_by, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            revision.revision_id.as_bytes().as_slice(),
            revision.volume_id.as_bytes().as_slice(),
            revision.object_id.as_bytes().as_slice(),
            revision.kind,
            prior.as_ref().map(<[u8; 16]>::as_slice),
            directory.as_ref().map(<[u8; 32]>::as_slice),
            version.as_ref().map(<[u8; 16]>::as_slice),
            digest.as_slice(),
            revision.created_by.as_bytes().as_slice(),
            revision.created_at.get()
        ],
    )?;
    Ok(())
}

pub(super) fn load_object_revision(
    transaction: &Transaction<'_>,
    revision_id: ObjectRevisionId,
) -> Result<ObjectRevisionInsert, PublicationError> {
    type StoredObjectRevision = (
        Vec<u8>,
        Vec<u8>,
        i64,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
        i64,
    );
    let stored: StoredObjectRevision = transaction.query_row(
        "SELECT volume_id, object_id, object_kind, prior_revision_id,
                directory_root_digest, file_version_id, revision_digest, created_by, created_at
         FROM object_revisions WHERE object_revision_id = ?1",
        [revision_id.as_bytes().as_slice()],
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
            ))
        },
    )?;
    let revision = ObjectRevisionInsert {
        revision_id,
        volume_id: decode_identifier(&stored.0, VolumeId::from_bytes)?,
        object_id: decode_identifier(&stored.1, ObjectId::from_bytes)?,
        kind: u8::try_from(stored.2).map_err(|_| PublicationError::Corrupt)?,
        prior_revision_id: decode_optional(stored.3.as_deref(), ObjectRevisionId::from_bytes)?,
        directory_root: stored
            .4
            .as_deref()
            .map(|bytes| copy_array(bytes).map(DirectoryNodeDigest::from_bytes))
            .transpose()?,
        file_version_id: decode_optional(stored.5.as_deref(), FileVersionId::from_bytes)?,
        created_by: decode_identifier(&stored.7, meshspan_domain::PrincipalId::from_bytes)?,
        created_at: meshspan_domain::UnixMicros::new(stored.8),
    };
    if copy_array(&stored.6)? == object_revision_digest(&revision) {
        Ok(revision)
    } else {
        Err(PublicationError::Corrupt)
    }
}

fn decode_optional<T, E>(
    stored: Option<&[u8]>,
    constructor: impl FnOnce([u8; 16]) -> Result<T, E>,
) -> Result<Option<T>, PublicationError> {
    stored
        .map(|bytes| decode_identifier(bytes, constructor))
        .transpose()
}

pub(super) fn persist_directory_path_revisions(
    transaction: &Transaction<'_>,
    volume_id: VolumeId,
    created_by: meshspan_domain::PrincipalId,
    created_at: meshspan_domain::UnixMicros,
    directories: &[DirectoryRevisionResult],
) -> Result<(), PublicationError> {
    for directory in directories {
        persist_object_revision(
            transaction,
            ObjectRevisionInsert {
                revision_id: directory.new_revision_id,
                volume_id,
                object_id: directory.object_id,
                kind: 1,
                prior_revision_id: directory.prior_revision_id,
                directory_root: Some(directory.directory_root),
                file_version_id: None,
                created_by,
                created_at,
            },
        )?;
    }
    Ok(())
}

pub(super) fn persist_commit(
    transaction: &Transaction<'_>,
    intent: NamespaceIntent<'_>,
    request_digest: [u8; 32],
) -> Result<(), PublicationError> {
    let collision: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM namespace_commits WHERE namespace_commit_id = ?1)",
        [intent.commit_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if collision != 0 {
        return Err(PublicationError::OperationConflict);
    }
    let digest = commit_digest(intent, request_digest);
    transaction.execute(
        "INSERT INTO namespace_commits(
            namespace_commit_id, branch_id, volume_id, root_object_id,
            root_object_revision_id, created_by, publication_operation_id,
            created_at, commit_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            intent.commit_id.as_bytes().as_slice(),
            intent.branch_id.as_bytes().as_slice(),
            intent.volume_id.as_bytes().as_slice(),
            intent.root_object_id.as_bytes().as_slice(),
            intent.root_revision_id.as_bytes().as_slice(),
            intent.created_by.as_bytes().as_slice(),
            intent.operation_id.as_bytes().as_slice(),
            intent.created_at.get(),
            digest.as_slice()
        ],
    )?;
    if let Some(parent) = intent.expected_commit_id {
        transaction.execute(
            "INSERT INTO namespace_commit_parents(
                namespace_commit_id, parent_ordinal, parent_commit_id
             ) VALUES (?1, 0, ?2)",
            params![
                intent.commit_id.as_bytes().as_slice(),
                parent.as_bytes().as_slice()
            ],
        )?;
    }
    Ok(())
}

pub(super) fn advance_namespace_head(
    transaction: &Transaction<'_>,
    intent: NamespaceIntent<'_>,
    previous_sequence: u64,
) -> Result<u64, PublicationError> {
    let sequence = previous_sequence
        .checked_add(1)
        .ok_or(PublicationError::InvalidInput)?;
    let changed = if let Some(expected) = intent.expected_commit_id {
        transaction.execute(
            "UPDATE branch_namespace_heads SET namespace_commit_id = ?1, head_sequence = ?2
             WHERE branch_id = ?3 AND volume_id = ?4
               AND namespace_commit_id = ?5 AND head_sequence = ?6",
            params![
                intent.commit_id.as_bytes().as_slice(),
                to_i64(sequence)?,
                intent.branch_id.as_bytes().as_slice(),
                intent.volume_id.as_bytes().as_slice(),
                expected.as_bytes().as_slice(),
                to_i64(previous_sequence)?
            ],
        )?
    } else {
        transaction.execute(
            "INSERT INTO branch_namespace_heads(
                branch_id, volume_id, namespace_commit_id, head_sequence
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                intent.branch_id.as_bytes().as_slice(),
                intent.volume_id.as_bytes().as_slice(),
                intent.commit_id.as_bytes().as_slice(),
                to_i64(sequence)?
            ],
        )?
    };
    if changed == 1 {
        Ok(sequence)
    } else {
        Err(PublicationError::StaleHead)
    }
}

pub(super) fn persist_file_operation(
    transaction: &Transaction<'_>,
    publication: &RootFilePublication,
    request_digest: [u8; 32],
    head_sequence: u64,
) -> Result<NamespacePublicationReceipt, PublicationError> {
    let digest = result_digest(
        publication.file.operation_id,
        request_digest,
        publication.file.version_id,
        publication.namespace_commit_id,
        head_sequence,
    );
    transaction.execute(
        "INSERT INTO namespace_publication_operations(
            operation_id, request_digest, namespace_commit_id, file_version_id,
            head_sequence, result_digest, committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            publication.file.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            publication.namespace_commit_id.as_bytes().as_slice(),
            publication.file.version_id.as_bytes().as_slice(),
            to_i64(head_sequence)?,
            digest.as_slice(),
            publication.file.created_at.get()
        ],
    )?;
    Ok(NamespacePublicationReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id: publication.file.operation_id,
        request_digest,
        file_version_id: publication.file.version_id,
        namespace_commit_id: publication.namespace_commit_id,
        head_sequence,
        result_digest: digest,
    })
}

pub(super) fn persist_directory_operation(
    transaction: &Transaction<'_>,
    publication: &DirectoryPublication,
    request_digest: [u8; 32],
    head_sequence: u64,
) -> Result<DirectoryPublicationReceipt, PublicationError> {
    let digest = directory_result_digest(
        publication.operation_id,
        request_digest,
        publication.directory_object_revision_id,
        publication.namespace_commit_id,
        head_sequence,
    );
    transaction.execute(
        "INSERT INTO directory_publication_operations(
            operation_id, request_digest, namespace_commit_id, directory_object_revision_id,
            head_sequence, result_digest, committed_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            publication.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            publication.namespace_commit_id.as_bytes().as_slice(),
            publication
                .directory_object_revision_id
                .as_bytes()
                .as_slice(),
            to_i64(head_sequence)?,
            digest.as_slice(),
            publication.created_at.get()
        ],
    )?;
    Ok(DirectoryPublicationReceipt {
        disposition: PublicationDisposition::Applied,
        operation_id: publication.operation_id,
        request_digest,
        directory_object_revision_id: publication.directory_object_revision_id,
        namespace_commit_id: publication.namespace_commit_id,
        head_sequence,
        result_digest: digest,
    })
}

type StoredReceipt = (Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>);
type StoredDirectoryReceipt = (Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>);

fn decode_file_receipt(
    operation_id: OperationId,
    disposition: PublicationDisposition,
    stored: &StoredReceipt,
) -> Result<NamespacePublicationReceipt, PublicationError> {
    let request_digest = copy_array(&stored.0)?;
    let namespace_commit_id = decode_identifier(&stored.1, NamespaceCommitId::from_bytes)?;
    let file_version_id = decode_identifier(&stored.2, FileVersionId::from_bytes)?;
    let head_sequence = from_i64(stored.3)?;
    let digest = copy_array(&stored.4)?;
    if digest
        != result_digest(
            operation_id,
            request_digest,
            file_version_id,
            namespace_commit_id,
            head_sequence,
        )
    {
        return Err(PublicationError::Corrupt);
    }
    Ok(NamespacePublicationReceipt {
        disposition,
        operation_id,
        request_digest,
        file_version_id,
        namespace_commit_id,
        head_sequence,
        result_digest: digest,
    })
}

fn decode_directory_receipt(
    operation_id: OperationId,
    disposition: PublicationDisposition,
    stored: &StoredDirectoryReceipt,
) -> Result<DirectoryPublicationReceipt, PublicationError> {
    let request_digest = copy_array(&stored.0)?;
    let namespace_commit_id = decode_identifier(&stored.1, NamespaceCommitId::from_bytes)?;
    let revision_id = decode_identifier(&stored.2, ObjectRevisionId::from_bytes)?;
    let head_sequence = from_i64(stored.3)?;
    let digest = copy_array(&stored.4)?;
    if digest
        != directory_result_digest(
            operation_id,
            request_digest,
            revision_id,
            namespace_commit_id,
            head_sequence,
        )
    {
        return Err(PublicationError::Corrupt);
    }
    Ok(DirectoryPublicationReceipt {
        disposition,
        operation_id,
        request_digest,
        directory_object_revision_id: revision_id,
        namespace_commit_id,
        head_sequence,
        result_digest: digest,
    })
}
