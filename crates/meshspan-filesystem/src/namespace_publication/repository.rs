// SPDX-License-Identifier: GPL-2.0-only

//! Durable namespace commit, object-revision, head and operation-receipt repository.

#[path = "repository/deletion_intent.rs"]
mod deletion_intent;
#[path = "repository/rename_intent.rs"]
mod rename_intent;
#[path = "repository/rename_operation.rs"]
pub(super) mod rename_operation;
#[path = "repository/unlink_operation.rs"]
pub(super) mod unlink_operation;

use meshspan_domain::{
    BranchId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::digest::{
    MergeCommitDigest, commit_fields as commit_digest_fields,
    directory_result as directory_result_digest, file_result as result_digest,
    merge_commit as merge_commit_digest, object_revision as object_revision_digest,
};
use super::{DirectoryRevisionResult, NamespaceIntent};
use crate::publication::{copy_array, decode_identifier, from_i64, to_i64};
use crate::{
    BranchMutation, BranchMutationIntent, BranchNamespaceHead, DirectoryNodeDigest,
    DirectoryPublication, DirectoryPublicationReceipt, NamespaceComponent, NamespacePath,
    NamespacePublicationReceipt, PublicationDisposition, PublicationError,
    ReconciliationCommitPayload, RootFilePublication,
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
            if selected.volume_id == volume_id {
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
    let parents = load_parents(connection, commit_id)?;
    if parents.len() >= 2 {
        return load_merge_reconciliation_commit(connection, commit_id, parents).map(Some);
    }
    let commit = load_commit(connection, commit_id)?;
    let request_digest =
        load_commit_request_digest(connection, commit.operation_id, commit.commit_id)?;
    if let Some(restore) = super::snapshot_restore::load_receipt_raw(
        connection,
        commit.operation_id,
        PublicationDisposition::Replayed,
    )? {
        if restore.namespace_commit_id != commit.commit_id
            || restore.expected_namespace_commit_id
                != commit.parent_id.ok_or(PublicationError::Corrupt)?
            || restore.root_object_revision_id != commit.root_object_revision_id
        {
            return Err(PublicationError::Corrupt);
        }
        super::snapshot_restore::validate_receipt_source(
            connection,
            restore,
            commit.volume_id,
            commit.root_object_id,
        )?;
        return Ok(Some(crate::ReconciliationCommit {
            commit_id: commit.commit_id,
            branch_id: commit.branch_id,
            volume_id: commit.volume_id,
            root_object_id: commit.root_object_id,
            root_object_revision_id: commit.root_object_revision_id,
            parents,
            operation_id: commit.operation_id,
            request_digest,
            payload: ReconciliationCommitPayload::Restore {
                snapshot_id: restore.snapshot_id,
                snapshot_namespace_commit_id: restore.snapshot_namespace_commit_id,
            },
        }));
    }
    let intent_digest = load_branch_intent(connection, commit.commit_id)?
        .ok_or(PublicationError::Corrupt)?
        .digest();
    if load_imported_commit_evidence(connection, commit.commit_id)
        .is_some_and(|(_, imported_intent_digest)| imported_intent_digest != intent_digest)
    {
        return Err(PublicationError::Corrupt);
    }
    Ok(Some(crate::ReconciliationCommit {
        commit_id: commit.commit_id,
        branch_id: commit.branch_id,
        volume_id: commit.volume_id,
        root_object_id: commit.root_object_id,
        root_object_revision_id: commit.root_object_revision_id,
        parents,
        operation_id: commit.operation_id,
        request_digest,
        payload: ReconciliationCommitPayload::Mutation { intent_digest },
    }))
}

fn load_merge_reconciliation_commit(
    connection: &Connection,
    commit_id: NamespaceCommitId,
    parents: Vec<NamespaceCommitId>,
) -> Result<crate::ReconciliationCommit, PublicationError> {
    type Stored = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        Vec<u8>,
    );
    let stored: Stored = connection.query_row(
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
    let branch_id = decode_identifier(&stored.0, BranchId::from_bytes)?;
    let volume_id = decode_identifier(&stored.1, VolumeId::from_bytes)?;
    let root_object_id = decode_identifier(&stored.2, ObjectId::from_bytes)?;
    let root_object_revision_id = decode_identifier(&stored.3, ObjectRevisionId::from_bytes)?;
    let created_by = decode_identifier(&stored.4, meshspan_domain::PrincipalId::from_bytes)?;
    let operation_id = decode_identifier(&stored.5, OperationId::from_bytes)?;
    let created_at = meshspan_domain::UnixMicros::new(stored.6);
    let receipt = super::reconciliation_apply::load_receipt(
        connection,
        operation_id,
        PublicationDisposition::Replayed,
    )?
    .ok_or(PublicationError::Corrupt)?;
    if receipt.namespace_commit_id != commit_id
        || receipt.root_object_revision_id != root_object_revision_id
    {
        return Err(PublicationError::Corrupt);
    }
    let digest = merge_commit_digest(&MergeCommitDigest {
        commit_id,
        branch_id,
        volume_id,
        root_object_id,
        root_revision_id: root_object_revision_id,
        parents: &parents,
        created_by,
        operation_id,
        created_at,
        request_digest: receipt.request_digest,
        replay_digest: receipt.replay_plan_digest,
    });
    if copy_array(&stored.7)? != digest {
        return Err(PublicationError::Corrupt);
    }
    Ok(crate::ReconciliationCommit {
        commit_id,
        branch_id,
        volume_id,
        root_object_id,
        root_object_revision_id,
        parents,
        operation_id,
        request_digest: receipt.request_digest,
        payload: ReconciliationCommitPayload::Merge {
            replay_digest: receipt.replay_plan_digest,
        },
    })
}

pub(super) fn persist_file_intent(
    transaction: &Transaction<'_>,
    publication: &RootFilePublication,
) -> Result<(), PublicationError> {
    persist_branch_intent(
        transaction,
        &BranchMutationIntent {
            commit_id: publication.namespace_commit_id,
            path: publication.path.path().clone(),
            ancestors: publication.path.ancestors().to_vec(),
            object_id: publication.file.object_id,
            object_revision_id: publication.file_object_revision_id,
            prior_object_revision_id: publication.expected_file_object_revision_id,
            entry_generation: publication.entry_generation,
            mutation: BranchMutation::File {
                version_id: publication.file.version_id,
            },
            rename: None,
        },
    )
}

pub(super) fn persist_directory_intent(
    transaction: &Transaction<'_>,
    publication: &DirectoryPublication,
) -> Result<(), PublicationError> {
    persist_branch_intent(
        transaction,
        &BranchMutationIntent {
            commit_id: publication.namespace_commit_id,
            path: publication.path.path().clone(),
            ancestors: publication.path.ancestors().to_vec(),
            object_id: publication.directory_object_id,
            object_revision_id: publication.directory_object_revision_id,
            prior_object_revision_id: None,
            entry_generation: publication.entry_generation,
            mutation: BranchMutation::CreateDirectory,
            rename: None,
        },
    )
}

pub(in crate::publication) fn persist_branch_intent(
    transaction: &Transaction<'_>,
    intent: &BranchMutationIntent,
) -> Result<(), PublicationError> {
    rename_intent::validate_shape(intent)?;
    deletion_intent::validate_shape(intent)?;
    let (kind, version_id) = match intent.mutation {
        BranchMutation::File { version_id } | BranchMutation::DeleteFile { version_id } => {
            (1_u8, Some(version_id.as_bytes()))
        }
        BranchMutation::CreateDirectory | BranchMutation::DeleteDirectory => (2, None),
    };
    let prior = intent
        .prior_object_revision_id
        .map(ObjectRevisionId::as_bytes);
    transaction.execute(
        "INSERT INTO namespace_commit_intents(
            namespace_commit_id, intent_kind, object_id, object_revision_id,
            prior_object_revision_id, file_version_id, entry_generation, path_depth,
            intent_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            intent.commit_id.as_bytes().as_slice(),
            kind,
            intent.object_id.as_bytes().as_slice(),
            intent.object_revision_id.as_bytes().as_slice(),
            prior.as_ref().map(<[u8; 16]>::as_slice),
            version_id.as_ref().map(<[u8; 16]>::as_slice),
            to_i64(intent.entry_generation)?,
            to_i64(
                u64::try_from(intent.path.components().len())
                    .map_err(|_| PublicationError::InvalidInput)?
            )?,
            intent.digest().as_slice(),
        ],
    )?;
    for (ordinal, component) in intent.path.components().iter().enumerate() {
        transaction.execute(
            "INSERT INTO namespace_commit_path_components(
                namespace_commit_id, component_ordinal, display_name, canonical_name
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                intent.commit_id.as_bytes().as_slice(),
                to_i64(u64::try_from(ordinal).map_err(|_| PublicationError::InvalidInput)?)?,
                component.display(),
                component.canonical(),
            ],
        )?;
    }
    for (ordinal, ancestor) in intent.ancestors.iter().enumerate() {
        transaction.execute(
            "INSERT INTO namespace_commit_intent_ancestors(
                namespace_commit_id, ancestor_ordinal, object_id, prior_revision_id,
                resulting_revision_id
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                intent.commit_id.as_bytes().as_slice(),
                to_i64(u64::try_from(ordinal).map_err(|_| PublicationError::InvalidInput)?)?,
                ancestor.object_id().as_bytes().as_slice(),
                ancestor.expected_revision_id().as_bytes().as_slice(),
                ancestor.new_revision_id().as_bytes().as_slice(),
            ],
        )?;
    }
    if let Some(rename) = &intent.rename {
        rename_intent::persist(transaction, intent.commit_id, rename)?;
    }
    deletion_intent::persist(transaction, intent)?;
    Ok(())
}

type StoredBranchIntent = (
    i64,
    Vec<u8>,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    i64,
    i64,
    Vec<u8>,
);

pub(in crate::publication) fn load_branch_intent(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Result<Option<BranchMutationIntent>, PublicationError> {
    let stored: Option<StoredBranchIntent> = connection
        .query_row(
            "SELECT intent_kind, object_id, object_revision_id, prior_object_revision_id,
                    file_version_id, entry_generation, path_depth, intent_digest
             FROM namespace_commit_intents WHERE namespace_commit_id = ?1",
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
        )
        .optional()?;
    stored
        .as_ref()
        .map(|stored| decode_branch_intent(connection, commit_id, stored))
        .transpose()
}

fn decode_branch_intent(
    connection: &Connection,
    commit_id: NamespaceCommitId,
    stored: &StoredBranchIntent,
) -> Result<BranchMutationIntent, PublicationError> {
    let path_depth = usize::try_from(from_i64(stored.6)?).map_err(|_| PublicationError::Corrupt)?;
    let mut statement = connection.prepare(
        "SELECT component_ordinal, display_name, canonical_name
         FROM namespace_commit_path_components
         WHERE namespace_commit_id = ?1 ORDER BY component_ordinal",
    )?;
    let rows = statement.query_map([commit_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut components = Vec::new();
    for row in rows {
        let (ordinal, display, canonical) = row?;
        if usize::try_from(from_i64(ordinal)?) != Ok(components.len()) {
            return Err(PublicationError::Corrupt);
        }
        components.push(
            NamespaceComponent::from_stored(&display, &canonical)
                .map_err(|_| PublicationError::Corrupt)?,
        );
    }
    if components.len() != path_depth {
        return Err(PublicationError::Corrupt);
    }
    let version = decode_optional(stored.4.as_deref(), FileVersionId::from_bytes)?;
    let deleted = deletion_intent::exists(connection, commit_id)?;
    let mutation = match (stored.0, version, deleted) {
        (1, Some(version_id), false) => BranchMutation::File { version_id },
        (2, None, false) => BranchMutation::CreateDirectory,
        (1, Some(version_id), true) => BranchMutation::DeleteFile { version_id },
        (2, None, true) => BranchMutation::DeleteDirectory,
        _ => return Err(PublicationError::Corrupt),
    };
    let rename = rename_intent::load(connection, commit_id)?;
    let intent = BranchMutationIntent {
        commit_id,
        path: NamespacePath::from_stored_components(components)
            .map_err(|_| PublicationError::Corrupt)?,
        ancestors: load_intent_ancestors(connection, commit_id, path_depth)?,
        object_id: decode_identifier(&stored.1, ObjectId::from_bytes)?,
        object_revision_id: decode_identifier(&stored.2, ObjectRevisionId::from_bytes)?,
        prior_object_revision_id: decode_optional(
            stored.3.as_deref(),
            ObjectRevisionId::from_bytes,
        )?,
        entry_generation: from_i64(stored.5)?,
        mutation,
        rename,
    };
    validate_loaded_intent(connection, &intent)?;
    if copy_array(&stored.7)? == intent.digest() {
        Ok(intent)
    } else {
        Err(PublicationError::Corrupt)
    }
}

fn load_intent_ancestors(
    connection: &Connection,
    commit_id: NamespaceCommitId,
    path_depth: usize,
) -> Result<Vec<crate::DirectoryRevisionTransition>, PublicationError> {
    let mut statement = connection.prepare(
        "SELECT ancestor_ordinal, object_id, prior_revision_id, resulting_revision_id
         FROM namespace_commit_intent_ancestors
         WHERE namespace_commit_id = ?1 ORDER BY ancestor_ordinal",
    )?;
    let rows = statement.query_map([commit_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
        ))
    })?;
    let mut ancestors = Vec::new();
    for row in rows {
        let (ordinal, object, prior, resulting) = row?;
        if usize::try_from(from_i64(ordinal)?) != Ok(ancestors.len()) {
            return Err(PublicationError::Corrupt);
        }
        ancestors.push(
            crate::DirectoryRevisionTransition::new(
                decode_identifier(&object, ObjectId::from_bytes)?,
                decode_identifier(&prior, ObjectRevisionId::from_bytes)?,
                decode_identifier(&resulting, ObjectRevisionId::from_bytes)?,
            )
            .map_err(|_| PublicationError::Corrupt)?,
        );
    }
    if ancestors.len().checked_add(1) == Some(path_depth) {
        Ok(ancestors)
    } else {
        Err(PublicationError::Corrupt)
    }
}

fn validate_loaded_intent(
    connection: &Connection,
    intent: &BranchMutationIntent,
) -> Result<(), PublicationError> {
    rename_intent::validate_shape(intent).map_err(|_| PublicationError::Corrupt)?;
    deletion_intent::validate_shape(intent).map_err(|_| PublicationError::Corrupt)?;
    let commit = load_commit(connection, intent.commit_id)?;
    let revision = load_object_revision(connection, intent.object_revision_id)?;
    let valid_kind = match intent.mutation {
        BranchMutation::File { version_id } | BranchMutation::DeleteFile { version_id } => {
            revision.kind == 2
                && revision.directory_root.is_none()
                && revision.file_version_id == Some(version_id)
        }
        BranchMutation::CreateDirectory => {
            revision.kind == 1
                && revision.directory_root.is_some()
                && revision.file_version_id.is_none()
                && (intent.rename.is_some() || intent.prior_object_revision_id.is_none())
        }
        BranchMutation::DeleteDirectory => {
            revision.kind == 1
                && revision.directory_root.is_some()
                && revision.file_version_id.is_none()
        }
    };
    if commit.volume_id != revision.volume_id
        || revision.object_id != intent.object_id
        || revision.prior_revision_id != intent.prior_object_revision_id
        || !valid_kind
    {
        return Err(PublicationError::Corrupt);
    }
    for ancestor in &intent.ancestors {
        validate_directory_transition(connection, commit.volume_id, *ancestor)?;
    }
    if let Some(rename) = &intent.rename {
        rename_intent::validate_loaded(connection, &commit, rename)?;
    }
    deletion_intent::validate_loaded(connection, &commit, intent)?;
    Ok(())
}

pub(super) fn validate_directory_transition(
    connection: &Connection,
    volume_id: VolumeId,
    ancestor: crate::DirectoryRevisionTransition,
) -> Result<(), PublicationError> {
    let prior = load_object_revision(connection, ancestor.expected_revision_id())?;
    let resulting = load_object_revision(connection, ancestor.new_revision_id())?;
    if prior.volume_id != volume_id
        || resulting.volume_id != volume_id
        || prior.object_id != ancestor.object_id()
        || resulting.object_id != ancestor.object_id()
        || prior.kind != 1
        || resulting.kind != 1
        || prior.directory_root.is_none()
        || resulting.directory_root.is_none()
        || prior.file_version_id.is_some()
        || resulting.file_version_id.is_some()
        || resulting.prior_revision_id != Some(ancestor.expected_revision_id())
    {
        return Err(PublicationError::Corrupt);
    }
    Ok(())
}

fn load_commit_request_digest(
    connection: &Connection,
    operation_id: OperationId,
    commit_id: NamespaceCommitId,
) -> Result<[u8; 32], PublicationError> {
    let file = load_file_operation_raw(connection, operation_id, PublicationDisposition::Replayed)?;
    let directory =
        load_directory_operation_raw(connection, operation_id, PublicationDisposition::Replayed)?;
    let restore = super::snapshot_restore::load_receipt_raw(
        connection,
        operation_id,
        PublicationDisposition::Replayed,
    )?;
    let rename =
        rename_operation::load(connection, operation_id, PublicationDisposition::Replayed)?;
    let unlink =
        unlink_operation::load(connection, operation_id, PublicationDisposition::Replayed)?;
    match (file, directory, restore, rename, unlink) {
        (Some(receipt), None, None, None, None) if receipt.namespace_commit_id == commit_id => {
            Ok(receipt.request_digest)
        }
        (None, Some(receipt), None, None, None) if receipt.namespace_commit_id == commit_id => {
            Ok(receipt.request_digest)
        }
        (None, None, Some(receipt), None, None) if receipt.namespace_commit_id == commit_id => {
            Ok(receipt.request_digest)
        }
        (None, None, None, Some(receipt), None) if receipt.namespace_commit_id == commit_id => {
            Ok(receipt.request_digest)
        }
        (None, None, None, None, Some(receipt)) if receipt.namespace_commit_id == commit_id => {
            Ok(receipt.request_digest)
        }
        (None, None, None, None, None) => load_imported_commit_evidence(connection, commit_id)
            .map(|evidence| evidence.0)
            .ok_or(PublicationError::Corrupt),
        _ => Err(PublicationError::Corrupt),
    }
}

fn load_imported_commit_evidence(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Option<([u8; 32], [u8; 32])> {
    let stored: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT request_digest, intent_digest, evidence_digest
             FROM imported_namespace_commit_evidence WHERE namespace_commit_id = ?1",
            [commit_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .ok()?;
    let (request, intent, evidence) = stored?;
    let request_digest = copy_array(&request).ok()?;
    let intent_digest = copy_array(&intent).ok()?;
    let evidence_digest = copy_array(&evidence).ok()?;
    (super::transfer::imported_evidence_digest(commit_id, request_digest, intent_digest)
        == evidence_digest)
        .then_some((request_digest, intent_digest))
}

fn load_single_parent(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Result<Option<NamespaceCommitId>, PublicationError> {
    let parents = load_parents(connection, commit_id)?;
    if parents.len() > 1 {
        return Err(PublicationError::Corrupt);
    }
    Ok(parents.into_iter().next())
}

fn load_parents(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Result<Vec<NamespaceCommitId>, PublicationError> {
    let mut statement = connection.prepare(
        "SELECT parent_ordinal, parent_commit_id FROM namespace_commit_parents
         WHERE namespace_commit_id = ?1 ORDER BY parent_ordinal",
    )?;
    let mut rows = statement.query([commit_id.as_bytes().as_slice()])?;
    let mut parents = Vec::new();
    while let Some(row) = rows.next()? {
        let ordinal: i64 = row.get(0)?;
        if ordinal != i64::try_from(parents.len()).map_err(|_| PublicationError::Corrupt)? {
            return Err(PublicationError::Corrupt);
        }
        let bytes: Vec<u8> = row.get(1)?;
        parents.push(decode_identifier(&bytes, NamespaceCommitId::from_bytes)?);
    }
    Ok(parents)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::publication) struct ObjectRevisionInsert {
    pub(in crate::publication) revision_id: ObjectRevisionId,
    pub(in crate::publication) volume_id: VolumeId,
    pub(in crate::publication) object_id: ObjectId,
    pub(in crate::publication) kind: u8,
    pub(in crate::publication) prior_revision_id: Option<ObjectRevisionId>,
    pub(in crate::publication) directory_root: Option<DirectoryNodeDigest>,
    pub(in crate::publication) file_version_id: Option<FileVersionId>,
    pub(in crate::publication) created_by: meshspan_domain::PrincipalId,
    pub(in crate::publication) created_at: meshspan_domain::UnixMicros,
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
    transaction: &Connection,
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
    persist_stored_commit(
        transaction,
        &StoredCommit {
            commit_id: intent.commit_id,
            branch_id: intent.branch_id,
            volume_id: intent.volume_id,
            root_object_id: intent.root_object_id,
            root_object_revision_id: intent.root_revision_id,
            parent_id: intent.expected_commit_id,
            created_by: intent.created_by,
            operation_id: intent.operation_id,
            created_at: intent.created_at,
        },
        request_digest,
    )
}

pub(super) fn persist_stored_commit(
    transaction: &Transaction<'_>,
    commit: &StoredCommit,
    request_digest: [u8; 32],
) -> Result<(), PublicationError> {
    let collision: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM namespace_commits WHERE namespace_commit_id = ?1)",
        [commit.commit_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if collision != 0 {
        return Err(PublicationError::OperationConflict);
    }
    let digest = commit_digest_fields(commit, request_digest);
    transaction.execute(
        "INSERT INTO namespace_commits(
            namespace_commit_id, branch_id, volume_id, root_object_id,
            root_object_revision_id, created_by, publication_operation_id,
            created_at, commit_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            commit.commit_id.as_bytes().as_slice(),
            commit.branch_id.as_bytes().as_slice(),
            commit.volume_id.as_bytes().as_slice(),
            commit.root_object_id.as_bytes().as_slice(),
            commit.root_object_revision_id.as_bytes().as_slice(),
            commit.created_by.as_bytes().as_slice(),
            commit.operation_id.as_bytes().as_slice(),
            commit.created_at.get(),
            digest.as_slice()
        ],
    )?;
    if let Some(parent) = commit.parent_id {
        transaction.execute(
            "INSERT INTO namespace_commit_parents(
                namespace_commit_id, parent_ordinal, parent_commit_id
             ) VALUES (?1, 0, ?2)",
            params![
                commit.commit_id.as_bytes().as_slice(),
                parent.as_bytes().as_slice()
            ],
        )?;
    }
    Ok(())
}

pub(super) fn stored_commit_digest(commit: &StoredCommit, request_digest: [u8; 32]) -> [u8; 32] {
    commit_digest_fields(commit, request_digest)
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
