// SPDX-License-Identifier: GPL-2.0-only

//! Immutable handle-flush plans that survive content/namespace cross-database interruption.

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, HandleId, NamespaceCommitId, NodeId, ObjectId,
    ObjectRevisionId, OperationId, PrincipalId, Revision, StageId, VolumeId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::path;
use super::state::{ActiveHandle, load_active};
use super::{
    CreateDisposition, HandleError, array, expire_stale_handles, identifier, load_revision,
    lookup_entry, to_i64, validate_open_lineage,
};
use crate::commit_service::commit_request_digest;
use crate::{
    DirectoryEntryKind, DirectoryRevisionTransition, FilesystemHandleFlushRequest,
    ManifestPublication, NamespaceComponent, NamespacePath, NamespacePublicationPath,
    PublishedContentReference, RootFileCommitRequest, StageCompletionRequest,
};
use crate::{PublicationError, RootFilePublication};

const MAXIMUM_SQLITE_INTEGER: u64 = 9_223_372_036_854_775_807;

#[derive(Clone)]
struct CurrentPath {
    path: NamespacePath,
    namespace_commit: NamespaceCommitId,
    root_object: ObjectId,
    root_revision: ObjectRevisionId,
    file_revision: ObjectRevisionId,
    version: FileVersionId,
    entry_generation: u64,
    ancestors: Vec<CurrentAncestor>,
}

#[derive(Clone, Copy)]
struct CurrentAncestor {
    object: ObjectId,
    revision: ObjectRevisionId,
}

struct FlushPlan {
    commit: RootFileCommitRequest,
    expected_root_revision: ObjectRevisionId,
}

type StoredBaseContent = (
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
);

struct ProgressAdvance {
    handle: HandleId,
    handle_fence: u64,
    stage_sequence: u64,
    expected_version: FileVersionId,
    expected_file_revision: ObjectRevisionId,
}

struct StoredPlan {
    request_digest: Vec<u8>,
    handle: Vec<u8>,
    handle_fence: i64,
    principal: Vec<u8>,
    authorization_revision: i64,
    gateway: Vec<u8>,
    stage_sequence: i64,
    final_length: i64,
    sparse: i64,
    retain_history: i64,
    retention_sequence: i64,
    manifest_format: i64,
    content_authorization: i64,
    content_deadline: i64,
    planned_at: i64,
    branch: Vec<u8>,
    volume: Vec<u8>,
    object: Vec<u8>,
    expected_version: Vec<u8>,
    version: Vec<u8>,
    manifest: Vec<u8>,
    expected_namespace_commit: Vec<u8>,
    expected_file_revision: Vec<u8>,
    file_revision: Vec<u8>,
    root_object: Vec<u8>,
    expected_root_revision: Vec<u8>,
    root_revision: Vec<u8>,
    namespace_commit: Vec<u8>,
    entry_generation: i64,
    path_depth: i64,
    result_digest: Vec<u8>,
}

pub(crate) fn prepare(
    connection: &mut Connection,
    request: FilesystemHandleFlushRequest,
) -> Result<RootFileCommitRequest, HandleError> {
    validate_request(request)?;
    let request_digest = flush_request_digest(request);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(plan) = load_plan(&transaction, request)? {
        return Ok(plan.commit);
    }
    reject_operation_collision(&transaction, request.operation_id)?;
    expire_stale_handles(&transaction, request.observed_at)?;
    let handle = load_active(&transaction, request.handle_id, request.observed_at)?;
    validate_authority(request, &handle)?;
    let path = path::load(&transaction, request.handle_id)?;
    let current = resolve_current_path(&transaction, &handle, path)?;
    let (expected_file_revision, expected_version, committed_sequence) =
        load_progress(&transaction, &handle)?;
    if current.file_revision != expected_file_revision
        || current.version != expected_version
        || request.expected_stage_sequence <= committed_sequence
    {
        return Err(HandleError::StaleHandle);
    }
    let plan = build_plan(request, &handle, current)?;
    persist_plan(&transaction, request, request_digest, &plan)?;
    transaction.commit()?;
    Ok(plan.commit)
}

pub(crate) fn base_content(
    connection: &Connection,
    handle_id: HandleId,
) -> Result<Option<PublishedContentReference>, HandleError> {
    type StoredHandle = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let stored: StoredHandle = connection.query_row(
        "SELECT create_disposition, opened_version_id, branch_id, volume_id, object_id
         FROM open_handles WHERE handle_id = ?1",
        [handle_id.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    let disposition =
        CreateDisposition::from_code(u8::try_from(stored.0).map_err(|_| HandleError::Corrupt)?)?;
    if disposition.truncates_existing() {
        return Ok(None);
    }
    let version_id = identifier(&stored.1, FileVersionId::from_bytes)?;
    let content: StoredBaseContent = connection.query_row(
        "SELECT v.publication_operation_id, m.manifest_id, m.format_version,
                m.logical_length, m.content_digest, m.root_digest,
                v.logical_length, v.content_digest, v.volume_id
         FROM file_versions v
         JOIN content_manifests m USING(manifest_id)
         WHERE v.version_id = ?1 AND v.object_id = ?2",
        params![version_id.as_bytes().as_slice(), stored.4.as_slice()],
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
    if content.3 != content.6 || content.4 != content.7 || content.8 != stored.3 {
        return Err(HandleError::Corrupt);
    }
    let format_version = u16::try_from(content.2).map_err(|_| HandleError::Corrupt)?;
    let logical_length = u64::try_from(content.3).map_err(|_| HandleError::Corrupt)?;
    if format_version == 0 {
        return Err(HandleError::Corrupt);
    }
    Ok(Some(PublishedContentReference {
        publication_operation_id: identifier(&content.0, OperationId::from_bytes)?,
        manifest: ManifestPublication {
            manifest_id: identifier(&content.1, ContentManifestId::from_bytes)?,
            format_version,
            logical_length,
            content_digest: array(&content.4)?,
            root_digest: array(&content.5)?,
        },
    }))
}

pub(crate) fn committed_stage_sequence(
    connection: &Connection,
    handle_id: HandleId,
) -> Result<u64, HandleError> {
    let stored: Option<i64> = connection
        .query_row(
            "SELECT committed_stage_sequence FROM handle_flush_progress WHERE handle_id = ?1",
            [handle_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    stored.map_or(Ok(0), |sequence| {
        u64::try_from(sequence).map_err(|_| HandleError::Corrupt)
    })
}

pub(crate) fn advance_progress(
    transaction: &Transaction<'_>,
    publication: &RootFilePublication,
) -> Result<(), PublicationError> {
    let Some(advance) = load_progress_advance(transaction, publication)? else {
        return Ok(());
    };
    validate_live_progress_fence(transaction, &advance)?;
    persist_progress_advance(transaction, publication, &advance)
}

fn load_progress_advance(
    transaction: &Transaction<'_>,
    publication: &RootFilePublication,
) -> Result<Option<ProgressAdvance>, PublicationError> {
    type Stored = (
        Vec<u8>,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    );
    let stored: Option<Stored> = transaction
        .query_row(
            "SELECT handle_id, handle_fence, stage_sequence, branch_id, volume_id, object_id,
                    expected_version_id, version_id, namespace_commit_id,
                    expected_file_object_revision_id, file_object_revision_id,
                    root_object_revision_id
             FROM handle_flush_plans WHERE operation_id = ?1",
            [publication.file.operation_id.as_bytes().as_slice()],
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
    let handle_id = publication_identifier(&stored.0, HandleId::from_bytes)?;
    let handle_fence = u64::try_from(stored.1).map_err(|_| PublicationError::Corrupt)?;
    let stage_sequence = u64::try_from(stored.2).map_err(|_| PublicationError::Corrupt)?;
    let expected_version = publication_identifier(&stored.6, FileVersionId::from_bytes)?;
    let expected_file_revision = publication_identifier(&stored.9, ObjectRevisionId::from_bytes)?;
    let exact = stored.3.as_slice() == publication.file.branch_id.as_bytes()
        && stored.4.as_slice() == publication.file.volume_id.as_bytes()
        && stored.5.as_slice() == publication.file.object_id.as_bytes()
        && stored.7.as_slice() == publication.file.version_id.as_bytes()
        && stored.8.as_slice() == publication.namespace_commit_id.as_bytes()
        && stored.10.as_slice() == publication.file_object_revision_id.as_bytes()
        && stored.11.as_slice() == publication.root_object_revision_id.as_bytes()
        && publication.file.expected_current_version_id == Some(expected_version)
        && publication.expected_file_object_revision_id == Some(expected_file_revision);
    if handle_fence == 0 || stage_sequence == 0 || !exact {
        return Err(PublicationError::Corrupt);
    }
    Ok(Some(ProgressAdvance {
        handle: handle_id,
        handle_fence,
        stage_sequence,
        expected_version,
        expected_file_revision,
    }))
}

fn validate_live_progress_fence(
    transaction: &Transaction<'_>,
    advance: &ProgressAdvance,
) -> Result<(), PublicationError> {
    let live_fence: Option<i64> = transaction
        .query_row(
            "SELECT handle_fence FROM open_handles WHERE handle_id = ?1 AND state = 1",
            [advance.handle.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if live_fence.and_then(|value| u64::try_from(value).ok()) == Some(advance.handle_fence) {
        Ok(())
    } else {
        Err(PublicationError::StaleHead)
    }
}

fn persist_progress_advance(
    transaction: &Transaction<'_>,
    publication: &RootFilePublication,
    advance: &ProgressAdvance,
) -> Result<(), PublicationError> {
    let prior: Option<(Vec<u8>, Vec<u8>, i64)> = transaction
        .query_row(
            "SELECT object_revision_id, version_id, committed_stage_sequence
             FROM handle_flush_progress WHERE handle_id = ?1",
            [advance.handle.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((revision, version, sequence)) = prior {
        if revision.as_slice() != advance.expected_file_revision.as_bytes()
            || version.as_slice() != advance.expected_version.as_bytes()
            || u64::try_from(sequence).map_err(|_| PublicationError::Corrupt)?
                >= advance.stage_sequence
        {
            return Err(PublicationError::StaleHead);
        }
        transaction.execute(
            "UPDATE handle_flush_progress SET namespace_commit_id = ?1,
                    object_revision_id = ?2, version_id = ?3,
                    committed_stage_sequence = ?4, flush_operation_id = ?5
             WHERE handle_id = ?6",
            params![
                publication.namespace_commit_id.as_bytes().as_slice(),
                publication.file_object_revision_id.as_bytes().as_slice(),
                publication.file.version_id.as_bytes().as_slice(),
                to_i64(advance.stage_sequence).map_err(|_| PublicationError::InvalidInput)?,
                publication.file.operation_id.as_bytes().as_slice(),
                advance.handle.as_bytes().as_slice(),
            ],
        )?;
    } else {
        let opened: (Vec<u8>, Vec<u8>) = transaction.query_row(
            "SELECT object_revision_id, opened_version_id FROM open_handles
             WHERE handle_id = ?1",
            [advance.handle.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if opened.0.as_slice() != advance.expected_file_revision.as_bytes()
            || opened.1.as_slice() != advance.expected_version.as_bytes()
        {
            return Err(PublicationError::StaleHead);
        }
        transaction.execute(
            "INSERT INTO handle_flush_progress(
                handle_id, namespace_commit_id, object_revision_id, version_id,
                committed_stage_sequence, flush_operation_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                advance.handle.as_bytes().as_slice(),
                publication.namespace_commit_id.as_bytes().as_slice(),
                publication.file_object_revision_id.as_bytes().as_slice(),
                publication.file.version_id.as_bytes().as_slice(),
                to_i64(advance.stage_sequence).map_err(|_| PublicationError::InvalidInput)?,
                publication.file.operation_id.as_bytes().as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn publication_identifier<T>(
    bytes: &[u8],
    constructor: impl FnOnce([u8; 16]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, PublicationError> {
    let exact = bytes.try_into().map_err(|_| PublicationError::Corrupt)?;
    constructor(exact).map_err(|_| PublicationError::Corrupt)
}

fn validate_request(request: FilesystemHandleFlushRequest) -> Result<(), HandleError> {
    if request.handle_fence == 0
        || request.authorization_revision == Revision::ZERO
        || request.expected_stage_sequence == 0
        || request.final_length > MAXIMUM_SQLITE_INTEGER
        || request.retention_policy_sequence == 0
        || request.retention_policy_sequence > MAXIMUM_SQLITE_INTEGER
        || request.manifest_format_version == 0
        || request.content_authorization_revision == Revision::ZERO
        || request.content_deadline <= request.observed_at
    {
        Err(HandleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn validate_authority(
    request: FilesystemHandleFlushRequest,
    handle: &ActiveHandle,
) -> Result<(), HandleError> {
    if handle.fence != request.handle_fence
        || handle.principal != request.principal_id
        || handle.gateway != request.gateway_node_id
        || handle.authorization_revision != request.authorization_revision
        || request.content_deadline > handle.lease_expires_at
    {
        return Err(HandleError::StaleHandle);
    }
    if handle.desired_access.writes() {
        Ok(())
    } else {
        Err(HandleError::InvalidInput)
    }
}

fn load_progress(
    connection: &Connection,
    handle: &ActiveHandle,
) -> Result<(ObjectRevisionId, FileVersionId, u64), HandleError> {
    type Stored = (Vec<u8>, Vec<u8>, Vec<u8>, i64);
    let stored: Option<Stored> = connection
        .query_row(
            "SELECT namespace_commit_id, object_revision_id, version_id,
                    committed_stage_sequence
             FROM handle_flush_progress WHERE handle_id = ?1",
            [handle.handle.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((namespace, revision, version, sequence)) = stored else {
        return Ok((handle.object_revision, handle.version, 0));
    };
    let namespace = identifier(&namespace, NamespaceCommitId::from_bytes)?;
    let revision = identifier(&revision, ObjectRevisionId::from_bytes)?;
    let version = identifier(&version, FileVersionId::from_bytes)?;
    validate_open_lineage(
        connection,
        handle.branch,
        handle.volume,
        namespace,
        handle.object,
        revision,
        version,
    )?;
    let sequence = u64::try_from(sequence).map_err(|_| HandleError::Corrupt)?;
    if sequence == 0 {
        Err(HandleError::Corrupt)
    } else {
        Ok((revision, version, sequence))
    }
}

fn resolve_current_path(
    connection: &Connection,
    handle: &ActiveHandle,
    path: NamespacePath,
) -> Result<CurrentPath, HandleError> {
    type StoredHead = (Vec<u8>, Vec<u8>, Vec<u8>);
    let (commit, root_object, root_revision): StoredHead = connection.query_row(
        "SELECT h.namespace_commit_id, c.root_object_id, c.root_object_revision_id
         FROM branch_namespace_heads h
         JOIN namespace_commits c USING(namespace_commit_id)
         WHERE h.branch_id = ?1 AND h.volume_id = ?2",
        params![
            handle.branch.as_bytes().as_slice(),
            handle.volume.as_bytes().as_slice()
        ],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let namespace_commit = identifier(&commit, NamespaceCommitId::from_bytes)?;
    let root_object = identifier(&root_object, ObjectId::from_bytes)?;
    let root_revision = identifier(&root_revision, ObjectRevisionId::from_bytes)?;
    let mut selected_object = root_object;
    let mut selected_revision = root_revision;
    let mut ancestors = Vec::with_capacity(path.components().len().saturating_sub(1));
    for (index, component) in path.components().iter().enumerate() {
        let revision = load_revision(connection, selected_revision)?;
        if revision.volume_id != handle.volume
            || revision.object_id != selected_object
            || revision.kind != DirectoryEntryKind::Directory
        {
            return Err(HandleError::Corrupt);
        }
        let entry = lookup_entry(
            connection,
            revision.directory_root.ok_or(HandleError::Corrupt)?,
            component,
        )?
        .ok_or(HandleError::StaleHandle)?;
        if index + 1 == path.components().len() {
            if entry.kind() != DirectoryEntryKind::File || entry.object_id() != handle.object {
                return Err(HandleError::StaleHandle);
            }
            let file = load_revision(connection, entry.object_revision_id())?;
            let version = file.file_version_id.ok_or(HandleError::Corrupt)?;
            if file.volume_id != handle.volume
                || file.object_id != handle.object
                || file.kind != DirectoryEntryKind::File
            {
                return Err(HandleError::Corrupt);
            }
            return Ok(CurrentPath {
                path,
                namespace_commit,
                root_object,
                root_revision,
                file_revision: entry.object_revision_id(),
                version,
                entry_generation: entry.generation(),
                ancestors,
            });
        }
        if entry.kind() != DirectoryEntryKind::Directory {
            return Err(HandleError::StaleHandle);
        }
        ancestors.push(CurrentAncestor {
            object: entry.object_id(),
            revision: entry.object_revision_id(),
        });
        selected_object = entry.object_id();
        selected_revision = entry.object_revision_id();
    }
    Err(HandleError::Corrupt)
}

fn build_plan(
    request: FilesystemHandleFlushRequest,
    handle: &ActiveHandle,
    current: CurrentPath,
) -> Result<FlushPlan, HandleError> {
    let ancestors = current
        .ancestors
        .iter()
        .enumerate()
        .map(|(index, ancestor)| {
            DirectoryRevisionTransition::new(
                ancestor.object,
                ancestor.revision,
                derive_revision(request.operation_id, b"ancestor", index)?,
            )
            .map_err(|_| HandleError::InvalidInput)
        })
        .collect::<Result<Vec<_>, HandleError>>()?;
    let expected_root_revision = current.root_revision;
    let commit = RootFileCommitRequest {
        completion: StageCompletionRequest {
            operation_id: request.operation_id,
            stage_id: StageId::from_bytes(request.handle_id.as_bytes())
                .map_err(|_| HandleError::InvalidInput)?,
            stage_fence: request.handle_fence,
            expected_sequence: request.expected_stage_sequence,
            final_length: request.final_length,
            sparse: request.sparse,
            observed_at: request.observed_at,
        },
        branch_id: handle.branch,
        volume_id: handle.volume,
        object_id: handle.object,
        expected_current_version_id: Some(current.version),
        version_id: derive_version(request.operation_id)?,
        retain_superseded_history: request.retain_superseded_history,
        retention_policy_sequence: request.retention_policy_sequence,
        manifest_id: derive_manifest(request.operation_id)?,
        manifest_format_version: request.manifest_format_version,
        content_authorization_revision: request.content_authorization_revision,
        content_deadline: request.content_deadline,
        root_object_id: current.root_object,
        expected_namespace_commit_id: Some(current.namespace_commit),
        expected_file_object_revision_id: Some(current.file_revision),
        file_object_revision_id: derive_revision(request.operation_id, b"file", 0)?,
        root_object_revision_id: derive_revision(request.operation_id, b"root", 0)?,
        namespace_commit_id: derive_commit(request.operation_id)?,
        path: NamespacePublicationPath::new(current.path, ancestors)
            .map_err(|_| HandleError::InvalidInput)?,
        entry_generation: current.entry_generation,
        created_by: request.principal_id,
        created_at: request.observed_at,
    };
    Ok(FlushPlan {
        commit,
        expected_root_revision,
    })
}

fn persist_plan(
    transaction: &Transaction<'_>,
    request: FilesystemHandleFlushRequest,
    request_digest: [u8; 32],
    plan: &FlushPlan,
) -> Result<(), HandleError> {
    let commit = &plan.commit;
    let result_digest = plan_result_digest(request_digest, plan);
    transaction.execute(
        "INSERT INTO handle_flush_plans(
            operation_id, request_digest, handle_id, handle_fence, principal_id,
            authorization_revision, gateway_node_id, stage_sequence, final_length, sparse,
            retain_superseded_history, retention_policy_sequence, manifest_format_version,
            content_authorization_revision, content_deadline, planned_at, branch_id, volume_id,
            object_id, expected_version_id, version_id, manifest_id,
            expected_namespace_commit_id, expected_file_object_revision_id,
            file_object_revision_id, root_object_id, expected_root_object_revision_id,
            root_object_revision_id, namespace_commit_id, entry_generation, path_depth,
            result_digest
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
            ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31,
            ?32
         )",
        params![
            request.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            request.handle_id.as_bytes().as_slice(),
            to_i64(request.handle_fence)?,
            request.principal_id.as_bytes().as_slice(),
            to_i64(request.authorization_revision.get())?,
            request.gateway_node_id.as_bytes().as_slice(),
            to_i64(request.expected_stage_sequence)?,
            to_i64(request.final_length)?,
            request.sparse,
            request.retain_superseded_history,
            to_i64(request.retention_policy_sequence)?,
            request.manifest_format_version,
            to_i64(request.content_authorization_revision.get())?,
            request.content_deadline.get(),
            request.observed_at.get(),
            commit.branch_id.as_bytes().as_slice(),
            commit.volume_id.as_bytes().as_slice(),
            commit.object_id.as_bytes().as_slice(),
            commit
                .expected_current_version_id
                .ok_or(HandleError::Corrupt)?
                .as_bytes()
                .as_slice(),
            commit.version_id.as_bytes().as_slice(),
            commit.manifest_id.as_bytes().as_slice(),
            commit
                .expected_namespace_commit_id
                .ok_or(HandleError::Corrupt)?
                .as_bytes()
                .as_slice(),
            commit
                .expected_file_object_revision_id
                .ok_or(HandleError::Corrupt)?
                .as_bytes()
                .as_slice(),
            commit.file_object_revision_id.as_bytes().as_slice(),
            commit.root_object_id.as_bytes().as_slice(),
            plan.expected_root_revision.as_bytes().as_slice(),
            commit.root_object_revision_id.as_bytes().as_slice(),
            commit.namespace_commit_id.as_bytes().as_slice(),
            to_i64(commit.entry_generation)?,
            i64::try_from(commit.path.path().components().len())
                .map_err(|_| HandleError::InvalidInput)?,
            result_digest.as_slice(),
        ],
    )?;
    persist_plan_path(transaction, request.operation_id, commit.path.path())?;
    for (ordinal, ancestor) in commit.path.ancestors().iter().enumerate() {
        transaction.execute(
            "INSERT INTO handle_flush_plan_ancestors(
                operation_id, ancestor_ordinal, object_id, expected_revision_id,
                new_revision_id
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                request.operation_id.as_bytes().as_slice(),
                i64::try_from(ordinal).map_err(|_| HandleError::InvalidInput)?,
                ancestor.object_id().as_bytes().as_slice(),
                ancestor.expected_revision_id().as_bytes().as_slice(),
                ancestor.new_revision_id().as_bytes().as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn persist_plan_path(
    transaction: &Transaction<'_>,
    operation_id: OperationId,
    path: &NamespacePath,
) -> Result<(), HandleError> {
    for (ordinal, component) in path.components().iter().enumerate() {
        transaction.execute(
            "INSERT INTO handle_flush_plan_path_components(
                operation_id, component_ordinal, display_name, canonical_name
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                operation_id.as_bytes().as_slice(),
                i64::try_from(ordinal).map_err(|_| HandleError::InvalidInput)?,
                component.display(),
                component.canonical(),
            ],
        )?;
    }
    Ok(())
}

fn load_plan(
    connection: &Connection,
    request: FilesystemHandleFlushRequest,
) -> Result<Option<FlushPlan>, HandleError> {
    let stored: Option<StoredPlan> = connection
        .query_row(
            "SELECT request_digest, handle_id, handle_fence, principal_id,
                    authorization_revision, gateway_node_id, stage_sequence, final_length,
                    sparse, retain_superseded_history, retention_policy_sequence,
                    manifest_format_version, content_authorization_revision, content_deadline,
                    planned_at, branch_id, volume_id, object_id, expected_version_id, version_id,
                    manifest_id, expected_namespace_commit_id,
                    expected_file_object_revision_id, file_object_revision_id, root_object_id,
                    expected_root_object_revision_id, root_object_revision_id,
                    namespace_commit_id, entry_generation, path_depth, result_digest
             FROM handle_flush_plans WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredPlan {
                    request_digest: row.get(0)?,
                    handle: row.get(1)?,
                    handle_fence: row.get(2)?,
                    principal: row.get(3)?,
                    authorization_revision: row.get(4)?,
                    gateway: row.get(5)?,
                    stage_sequence: row.get(6)?,
                    final_length: row.get(7)?,
                    sparse: row.get(8)?,
                    retain_history: row.get(9)?,
                    retention_sequence: row.get(10)?,
                    manifest_format: row.get(11)?,
                    content_authorization: row.get(12)?,
                    content_deadline: row.get(13)?,
                    planned_at: row.get(14)?,
                    branch: row.get(15)?,
                    volume: row.get(16)?,
                    object: row.get(17)?,
                    expected_version: row.get(18)?,
                    version: row.get(19)?,
                    manifest: row.get(20)?,
                    expected_namespace_commit: row.get(21)?,
                    expected_file_revision: row.get(22)?,
                    file_revision: row.get(23)?,
                    root_object: row.get(24)?,
                    expected_root_revision: row.get(25)?,
                    root_revision: row.get(26)?,
                    namespace_commit: row.get(27)?,
                    entry_generation: row.get(28)?,
                    path_depth: row.get(29)?,
                    result_digest: row.get(30)?,
                })
            },
        )
        .optional()?;
    stored
        .as_ref()
        .map(|stored| decode_plan(connection, request, stored))
        .transpose()
}

fn decode_plan(
    connection: &Connection,
    request: FilesystemHandleFlushRequest,
    stored: &StoredPlan,
) -> Result<FlushPlan, HandleError> {
    validate_stored_request(request, stored)?;
    let path_depth = usize::try_from(stored.path_depth).map_err(|_| HandleError::Corrupt)?;
    let path = load_plan_path(connection, request.operation_id, path_depth)?;
    let ancestors = load_plan_ancestors(connection, request.operation_id, path_depth)?;
    let commit = RootFileCommitRequest {
        completion: StageCompletionRequest {
            operation_id: request.operation_id,
            stage_id: StageId::from_bytes(request.handle_id.as_bytes())
                .map_err(|_| HandleError::Corrupt)?,
            stage_fence: request.handle_fence,
            expected_sequence: request.expected_stage_sequence,
            final_length: request.final_length,
            sparse: request.sparse,
            observed_at: request.observed_at,
        },
        branch_id: identifier(&stored.branch, BranchId::from_bytes)?,
        volume_id: identifier(&stored.volume, VolumeId::from_bytes)?,
        object_id: identifier(&stored.object, ObjectId::from_bytes)?,
        expected_current_version_id: Some(identifier(
            &stored.expected_version,
            FileVersionId::from_bytes,
        )?),
        version_id: identifier(&stored.version, FileVersionId::from_bytes)?,
        retain_superseded_history: request.retain_superseded_history,
        retention_policy_sequence: request.retention_policy_sequence,
        manifest_id: identifier(&stored.manifest, ContentManifestId::from_bytes)?,
        manifest_format_version: request.manifest_format_version,
        content_authorization_revision: request.content_authorization_revision,
        content_deadline: request.content_deadline,
        root_object_id: identifier(&stored.root_object, ObjectId::from_bytes)?,
        expected_namespace_commit_id: Some(identifier(
            &stored.expected_namespace_commit,
            NamespaceCommitId::from_bytes,
        )?),
        expected_file_object_revision_id: Some(identifier(
            &stored.expected_file_revision,
            ObjectRevisionId::from_bytes,
        )?),
        file_object_revision_id: identifier(&stored.file_revision, ObjectRevisionId::from_bytes)?,
        root_object_revision_id: identifier(&stored.root_revision, ObjectRevisionId::from_bytes)?,
        namespace_commit_id: identifier(&stored.namespace_commit, NamespaceCommitId::from_bytes)?,
        path: NamespacePublicationPath::new(path, ancestors).map_err(|_| HandleError::Corrupt)?,
        entry_generation: u64::try_from(stored.entry_generation)
            .map_err(|_| HandleError::Corrupt)?,
        created_by: request.principal_id,
        created_at: request.observed_at,
    };
    let plan = FlushPlan {
        commit,
        expected_root_revision: identifier(
            &stored.expected_root_revision,
            ObjectRevisionId::from_bytes,
        )?,
    };
    let result_digest = array(&stored.result_digest)?;
    if result_digest == plan_result_digest(flush_request_digest(request), &plan) {
        Ok(plan)
    } else {
        Err(HandleError::Corrupt)
    }
}

fn validate_stored_request(
    request: FilesystemHandleFlushRequest,
    stored: &StoredPlan,
) -> Result<(), HandleError> {
    let stored_digest = array(&stored.request_digest)?;
    let expected_digest = flush_request_digest(request);
    let matches = identifier(&stored.handle, HandleId::from_bytes)? == request.handle_id
        && u64::try_from(stored.handle_fence) == Ok(request.handle_fence)
        && identifier(&stored.principal, PrincipalId::from_bytes)? == request.principal_id
        && u64::try_from(stored.authorization_revision) == Ok(request.authorization_revision.get())
        && identifier(&stored.gateway, NodeId::from_bytes)? == request.gateway_node_id
        && u64::try_from(stored.stage_sequence) == Ok(request.expected_stage_sequence)
        && u64::try_from(stored.final_length) == Ok(request.final_length)
        && stored.sparse == i64::from(request.sparse)
        && stored.retain_history == i64::from(request.retain_superseded_history)
        && u64::try_from(stored.retention_sequence) == Ok(request.retention_policy_sequence)
        && u16::try_from(stored.manifest_format) == Ok(request.manifest_format_version)
        && u64::try_from(stored.content_authorization)
            == Ok(request.content_authorization_revision.get())
        && stored.content_deadline == request.content_deadline.get()
        && stored.planned_at == request.observed_at.get();
    match (matches, stored_digest == expected_digest) {
        (true, true) => Ok(()),
        (true, false) | (false, true) => Err(HandleError::Corrupt),
        (false, false) => Err(HandleError::OperationConflict),
    }
}

fn load_plan_path(
    connection: &Connection,
    operation_id: OperationId,
    expected_depth: usize,
) -> Result<NamespacePath, HandleError> {
    let mut statement = connection.prepare(
        "SELECT component_ordinal, display_name, canonical_name
         FROM handle_flush_plan_path_components
         WHERE operation_id = ?1 ORDER BY component_ordinal",
    )?;
    let rows = statement.query_map([operation_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut components = Vec::with_capacity(expected_depth);
    for row in rows {
        let (ordinal, display, canonical) = row?;
        if usize::try_from(ordinal) != Ok(components.len()) {
            return Err(HandleError::Corrupt);
        }
        components.push(
            NamespaceComponent::from_stored(&display, &canonical)
                .map_err(|_| HandleError::Corrupt)?,
        );
    }
    if components.len() != expected_depth {
        return Err(HandleError::Corrupt);
    }
    NamespacePath::from_stored_components(components).map_err(|_| HandleError::Corrupt)
}

fn load_plan_ancestors(
    connection: &Connection,
    operation_id: OperationId,
    path_depth: usize,
) -> Result<Vec<DirectoryRevisionTransition>, HandleError> {
    let mut statement = connection.prepare(
        "SELECT ancestor_ordinal, object_id, expected_revision_id, new_revision_id
         FROM handle_flush_plan_ancestors
         WHERE operation_id = ?1 ORDER BY ancestor_ordinal",
    )?;
    let rows = statement.query_map([operation_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
        ))
    })?;
    let expected = path_depth.checked_sub(1).ok_or(HandleError::Corrupt)?;
    let mut ancestors = Vec::with_capacity(expected);
    for row in rows {
        let (ordinal, object, prior, next) = row?;
        if usize::try_from(ordinal) != Ok(ancestors.len()) {
            return Err(HandleError::Corrupt);
        }
        ancestors.push(
            DirectoryRevisionTransition::new(
                identifier(&object, ObjectId::from_bytes)?,
                identifier(&prior, ObjectRevisionId::from_bytes)?,
                identifier(&next, ObjectRevisionId::from_bytes)?,
            )
            .map_err(|_| HandleError::Corrupt)?,
        );
    }
    if ancestors.len() == expected {
        Ok(ancestors)
    } else {
        Err(HandleError::Corrupt)
    }
}

fn reject_operation_collision(
    connection: &Connection,
    operation_id: OperationId,
) -> Result<(), HandleError> {
    let collision: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM namespace_publication_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM directory_publication_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM namespace_reconciliation_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM namespace_snapshot_restore_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM namespace_rename_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM namespace_unlink_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM range_locks WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM handle_mutation_operations WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM handle_write_admissions WHERE operation_id = ?1)",
        [operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if collision == 0 {
        Ok(())
    } else {
        Err(HandleError::OperationConflict)
    }
}

fn flush_request_digest(request: FilesystemHandleFlushRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.handle-flush-request.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.handle_id.as_bytes());
    digest.update(&request.handle_fence.to_be_bytes());
    digest.update(&request.principal_id.as_bytes());
    digest.update(&request.authorization_revision.get().to_be_bytes());
    digest.update(&request.gateway_node_id.as_bytes());
    digest.update(&request.expected_stage_sequence.to_be_bytes());
    digest.update(&request.final_length.to_be_bytes());
    digest.update(&[u8::from(request.sparse)]);
    digest.update(&[u8::from(request.retain_superseded_history)]);
    digest.update(&request.retention_policy_sequence.to_be_bytes());
    digest.update(&request.manifest_format_version.to_be_bytes());
    digest.update(&request.content_authorization_revision.get().to_be_bytes());
    digest.update(&request.content_deadline.get().to_be_bytes());
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.finalize().into()
}

fn plan_result_digest(request_digest: [u8; 32], plan: &FlushPlan) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.handle-flush-plan.v1\0");
    digest.update(&request_digest);
    digest.update(&commit_request_digest(&plan.commit));
    digest.update(&plan.expected_root_revision.as_bytes());
    digest.finalize().into()
}

fn derive_version(operation_id: OperationId) -> Result<FileVersionId, HandleError> {
    FileVersionId::from_bytes(derive(operation_id, b"version", 0))
        .map_err(|_| HandleError::InvalidInput)
}

fn derive_manifest(operation_id: OperationId) -> Result<ContentManifestId, HandleError> {
    ContentManifestId::from_bytes(derive(operation_id, b"manifest", 0))
        .map_err(|_| HandleError::InvalidInput)
}

fn derive_commit(operation_id: OperationId) -> Result<NamespaceCommitId, HandleError> {
    NamespaceCommitId::from_bytes(derive(operation_id, b"commit", 0))
        .map_err(|_| HandleError::InvalidInput)
}

fn derive_revision(
    operation_id: OperationId,
    purpose: &[u8],
    ordinal: usize,
) -> Result<ObjectRevisionId, HandleError> {
    let ordinal = u64::try_from(ordinal).map_err(|_| HandleError::InvalidInput)?;
    ObjectRevisionId::from_bytes(derive(operation_id, purpose, ordinal))
        .map_err(|_| HandleError::InvalidInput)
}

fn derive(operation_id: OperationId, purpose: &[u8], ordinal: u64) -> [u8; 16] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.handle-flush-identity.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&(purpose.len() as u64).to_be_bytes());
    digest.update(purpose);
    digest.update(&ordinal.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    meshspan_domain::uuid_v8(bytes)
}
