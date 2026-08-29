// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe planning for one semantic namespace unlink.

use meshspan_domain::{
    BranchId, FileVersionId, HandleId, NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId,
    PrincipalId, UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{
    AdapterUnlinkRequest, DirectoryEntryKind, DirectoryRevisionTransition, HandleError,
    NamespacePublicationPath, NamespaceUnlinkAuthority, NamespaceUnlinkPublication,
};

struct CurrentTarget {
    namespace_commit: NamespaceCommitId,
    root_object: ObjectId,
    object: ObjectId,
    revision: ObjectRevisionId,
    kind: DirectoryEntryKind,
    version: Option<FileVersionId>,
    generation: u64,
    ancestors: Vec<CurrentAncestor>,
}

#[derive(Clone, Copy)]
struct CurrentAncestor {
    object: ObjectId,
    revision: ObjectRevisionId,
}

struct StoredPlan {
    request_digest: Vec<u8>,
    branch: Vec<u8>,
    volume: Vec<u8>,
    root_object: Vec<u8>,
    expected_commit: Vec<u8>,
    object: Vec<u8>,
    revision: Vec<u8>,
    kind: i64,
    version: Option<Vec<u8>>,
    generation: i64,
    root_revision: Vec<u8>,
    commit: Vec<u8>,
    handle: Option<Vec<u8>>,
    created_by: Vec<u8>,
    created_at: i64,
    path_depth: i64,
    result_digest: Vec<u8>,
}

pub(crate) fn target(
    connection: &Connection,
    branch_id: BranchId,
    request: &AdapterUnlinkRequest,
) -> Result<ObjectId, HandleError> {
    validate_request(request)?;
    let request_digest = request_digest(branch_id, request);
    if let Some(plan) = load_plan(connection, branch_id, request, request_digest)? {
        return Ok(plan.expected_object_id);
    }
    Ok(resolve_current(connection, branch_id, request)?.object)
}

pub(crate) fn prepare(
    connection: &mut Connection,
    branch_id: BranchId,
    request: &AdapterUnlinkRequest,
    created_by: PrincipalId,
    expected_object: ObjectId,
) -> Result<NamespaceUnlinkPublication, HandleError> {
    validate_request(request)?;
    let request_digest = request_digest(branch_id, request);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(plan) = load_plan(&transaction, branch_id, request, request_digest)? {
        if plan.created_by == created_by && plan.expected_object_id == expected_object {
            return Ok(plan);
        }
        return Err(HandleError::OperationConflict);
    }
    reject_operation_collision(&transaction, request.operation_id)?;
    let current = resolve_current(&transaction, branch_id, request)?;
    if current.object != expected_object {
        return Err(HandleError::StaleHandle);
    }
    let plan = build_plan(branch_id, request, created_by, &current)?;
    persist_plan(&transaction, request_digest, &plan)?;
    transaction.commit()?;
    Ok(plan)
}

fn validate_request(request: &AdapterUnlinkRequest) -> Result<(), HandleError> {
    if request.path.components().is_empty() {
        Err(HandleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn resolve_current(
    connection: &Connection,
    branch_id: BranchId,
    request: &AdapterUnlinkRequest,
) -> Result<CurrentTarget, HandleError> {
    type StoredHead = (Vec<u8>, Vec<u8>, Vec<u8>);
    let stored: Option<StoredHead> = connection
        .query_row(
            "SELECT h.namespace_commit_id, c.root_object_id, c.root_object_revision_id
             FROM branch_namespace_heads h JOIN namespace_commits c USING(namespace_commit_id)
             WHERE h.branch_id = ?1 AND h.volume_id = ?2",
            params![
                branch_id.as_bytes().as_slice(),
                request.volume_id.as_bytes().as_slice()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((commit, root_object, root_revision)) = stored else {
        return Err(HandleError::NotFound);
    };
    let namespace_commit = identifier(&commit, NamespaceCommitId::from_bytes)?;
    let root_object = identifier(&root_object, ObjectId::from_bytes)?;
    let mut selected_object = root_object;
    let mut selected_revision = identifier(&root_revision, ObjectRevisionId::from_bytes)?;
    let mut ancestors = Vec::with_capacity(request.path.components().len().saturating_sub(1));
    for (index, component) in request.path.components().iter().enumerate() {
        let parent = crate::handles::load_revision(connection, selected_revision)?;
        if parent.volume_id != request.volume_id
            || parent.object_id != selected_object
            || parent.kind != DirectoryEntryKind::Directory
        {
            return Err(HandleError::Corrupt);
        }
        let entry = crate::handles::lookup_entry(
            connection,
            parent.directory_root.ok_or(HandleError::Corrupt)?,
            component,
        )?
        .ok_or(HandleError::NotFound)?;
        if index + 1 == request.path.components().len() {
            let target = crate::handles::load_revision(connection, entry.object_revision_id())?;
            if target.volume_id != request.volume_id
                || target.object_id != entry.object_id()
                || target.kind != entry.kind()
            {
                return Err(HandleError::Corrupt);
            }
            return Ok(CurrentTarget {
                namespace_commit,
                root_object,
                object: entry.object_id(),
                revision: entry.object_revision_id(),
                kind: entry.kind(),
                version: target.file_version_id,
                generation: entry.generation(),
                ancestors,
            });
        }
        if entry.kind() != DirectoryEntryKind::Directory {
            return Err(HandleError::NotFound);
        }
        ancestors.push(CurrentAncestor {
            object: entry.object_id(),
            revision: entry.object_revision_id(),
        });
        selected_object = entry.object_id();
        selected_revision = entry.object_revision_id();
    }
    Err(HandleError::InvalidInput)
}

fn build_plan(
    branch_id: BranchId,
    request: &AdapterUnlinkRequest,
    created_by: PrincipalId,
    current: &CurrentTarget,
) -> Result<NamespaceUnlinkPublication, HandleError> {
    let ancestors = current
        .ancestors
        .iter()
        .enumerate()
        .map(|(ordinal, ancestor)| {
            DirectoryRevisionTransition::new(
                ancestor.object,
                ancestor.revision,
                derive_revision(request.operation_id, b"ancestor", ordinal)?,
            )
            .map_err(|_| HandleError::InvalidInput)
        })
        .collect::<Result<Vec<_>, HandleError>>()?;
    Ok(NamespaceUnlinkPublication {
        operation_id: request.operation_id,
        branch_id,
        volume_id: request.volume_id,
        root_object_id: current.root_object,
        expected_namespace_commit_id: current.namespace_commit,
        expected_object_id: current.object,
        expected_object_revision_id: current.revision,
        expected_kind: current.kind,
        expected_file_version_id: current.version,
        expected_entry_generation: current.generation,
        path: NamespacePublicationPath::new(request.path.clone(), ancestors)
            .map_err(|_| HandleError::InvalidInput)?,
        root_object_revision_id: derive_revision(request.operation_id, b"root", 0)?,
        namespace_commit_id: derive_commit(request.operation_id)?,
        authority: NamespaceUnlinkAuthority::Direct {
            requesting_handle_id: request.requesting_handle_id,
        },
        created_by,
        created_at: request.observed_at,
    })
}

fn persist_plan(
    transaction: &Transaction<'_>,
    request_digest: [u8; 32],
    plan: &NamespaceUnlinkPublication,
) -> Result<(), HandleError> {
    let result_digest = plan_digest(request_digest, plan);
    transaction.execute(
        "INSERT INTO adapter_unlink_plans(
            operation_id, request_digest, branch_id, volume_id, root_object_id,
            expected_namespace_commit_id, expected_object_id, expected_object_revision_id,
            expected_kind, expected_file_version_id, expected_entry_generation,
            root_object_revision_id, namespace_commit_id, requesting_handle_id, created_by,
            created_at, path_depth, result_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                   ?16, ?17, ?18)",
        params![
            plan.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            plan.branch_id.as_bytes().as_slice(),
            plan.volume_id.as_bytes().as_slice(),
            plan.root_object_id.as_bytes().as_slice(),
            plan.expected_namespace_commit_id.as_bytes().as_slice(),
            plan.expected_object_id.as_bytes().as_slice(),
            plan.expected_object_revision_id.as_bytes().as_slice(),
            kind_code(plan.expected_kind),
            plan.expected_file_version_id
                .map(FileVersionId::as_bytes)
                .as_ref()
                .map(<[u8; 16]>::as_slice),
            to_i64(plan.expected_entry_generation)?,
            plan.root_object_revision_id.as_bytes().as_slice(),
            plan.namespace_commit_id.as_bytes().as_slice(),
            requesting_handle(plan)
                .map(HandleId::as_bytes)
                .as_ref()
                .map(<[u8; 16]>::as_slice),
            plan.created_by.as_bytes().as_slice(),
            plan.created_at.get(),
            i64::try_from(plan.path.path().components().len())
                .map_err(|_| HandleError::InvalidInput)?,
            result_digest.as_slice(),
        ],
    )?;
    for (ordinal, ancestor) in plan.path.ancestors().iter().enumerate() {
        transaction.execute(
            "INSERT INTO adapter_unlink_plan_ancestors(
                operation_id, ancestor_ordinal, object_id, expected_revision_id, new_revision_id
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                plan.operation_id.as_bytes().as_slice(),
                i64::try_from(ordinal).map_err(|_| HandleError::InvalidInput)?,
                ancestor.object_id().as_bytes().as_slice(),
                ancestor.expected_revision_id().as_bytes().as_slice(),
                ancestor.new_revision_id().as_bytes().as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn load_plan(
    connection: &Connection,
    branch_id: BranchId,
    request: &AdapterUnlinkRequest,
    request_digest: [u8; 32],
) -> Result<Option<NamespaceUnlinkPublication>, HandleError> {
    let stored: Option<StoredPlan> = connection
        .query_row(
            "SELECT request_digest, branch_id, volume_id, root_object_id,
                    expected_namespace_commit_id, expected_object_id, expected_object_revision_id,
                    expected_kind, expected_file_version_id, expected_entry_generation,
                    root_object_revision_id, namespace_commit_id, requesting_handle_id, created_by,
                    created_at, path_depth, result_digest
             FROM adapter_unlink_plans WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredPlan {
                    request_digest: row.get(0)?,
                    branch: row.get(1)?,
                    volume: row.get(2)?,
                    root_object: row.get(3)?,
                    expected_commit: row.get(4)?,
                    object: row.get(5)?,
                    revision: row.get(6)?,
                    kind: row.get(7)?,
                    version: row.get(8)?,
                    generation: row.get(9)?,
                    root_revision: row.get(10)?,
                    commit: row.get(11)?,
                    handle: row.get(12)?,
                    created_by: row.get(13)?,
                    created_at: row.get(14)?,
                    path_depth: row.get(15)?,
                    result_digest: row.get(16)?,
                })
            },
        )
        .optional()?;
    stored
        .map(|stored| decode_plan(connection, branch_id, request, request_digest, &stored))
        .transpose()
}

fn decode_plan(
    connection: &Connection,
    branch_id: BranchId,
    request: &AdapterUnlinkRequest,
    request_digest: [u8; 32],
    stored: &StoredPlan,
) -> Result<NamespaceUnlinkPublication, HandleError> {
    if stored.request_digest.as_slice() != request_digest
        || stored.branch.as_slice() != branch_id.as_bytes()
        || stored.volume.as_slice() != request.volume_id.as_bytes()
        || stored.created_at != request.observed_at.get()
        || usize::try_from(stored.path_depth) != Ok(request.path.components().len())
    {
        return Err(HandleError::OperationConflict);
    }
    let plan = NamespaceUnlinkPublication {
        operation_id: request.operation_id,
        branch_id,
        volume_id: request.volume_id,
        root_object_id: identifier(&stored.root_object, ObjectId::from_bytes)?,
        expected_namespace_commit_id: identifier(
            &stored.expected_commit,
            NamespaceCommitId::from_bytes,
        )?,
        expected_object_id: identifier(&stored.object, ObjectId::from_bytes)?,
        expected_object_revision_id: identifier(&stored.revision, ObjectRevisionId::from_bytes)?,
        expected_kind: decode_kind(stored.kind)?,
        expected_file_version_id: stored
            .version
            .as_deref()
            .map(|value| identifier(value, FileVersionId::from_bytes))
            .transpose()?,
        expected_entry_generation: u64::try_from(stored.generation)
            .map_err(|_| HandleError::Corrupt)?,
        path: NamespacePublicationPath::new(
            request.path.clone(),
            load_ancestors(
                connection,
                request.operation_id,
                request.path.components().len(),
            )?,
        )
        .map_err(|_| HandleError::Corrupt)?,
        root_object_revision_id: identifier(&stored.root_revision, ObjectRevisionId::from_bytes)?,
        namespace_commit_id: identifier(&stored.commit, NamespaceCommitId::from_bytes)?,
        authority: NamespaceUnlinkAuthority::Direct {
            requesting_handle_id: stored
                .handle
                .as_deref()
                .map(|value| identifier(value, HandleId::from_bytes))
                .transpose()?,
        },
        created_by: identifier(&stored.created_by, PrincipalId::from_bytes)?,
        created_at: UnixMicros::new(stored.created_at),
    };
    let shape_matches = request.requesting_handle_id == requesting_handle(&plan)
        && ((plan.expected_kind == DirectoryEntryKind::File)
            == plan.expected_file_version_id.is_some());
    if shape_matches && stored.result_digest.as_slice() == plan_digest(request_digest, &plan) {
        Ok(plan)
    } else {
        Err(HandleError::Corrupt)
    }
}

fn load_ancestors(
    connection: &Connection,
    operation_id: OperationId,
    path_depth: usize,
) -> Result<Vec<DirectoryRevisionTransition>, HandleError> {
    let expected = path_depth.checked_sub(1).ok_or(HandleError::Corrupt)?;
    let mut statement = connection.prepare(
        "SELECT ancestor_ordinal, object_id, expected_revision_id, new_revision_id
         FROM adapter_unlink_plan_ancestors
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
             OR EXISTS(SELECT 1 FROM adapter_directory_plans WHERE operation_id = ?1)
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

fn request_digest(branch_id: BranchId, request: &AdapterUnlinkRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.adapter-unlink-request.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&branch_id.as_bytes());
    digest.update(&request.volume_id.as_bytes());
    digest.update(&(request.path.components().len() as u64).to_be_bytes());
    for component in request.path.components() {
        update_text(&mut digest, component.display());
        update_text(&mut digest, component.canonical());
    }
    update_optional_identifier(
        &mut digest,
        request.requesting_handle_id.map(HandleId::as_bytes),
    );
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.finalize().into()
}

fn plan_digest(request_digest: [u8; 32], plan: &NamespaceUnlinkPublication) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.adapter-unlink-plan.v1\0");
    digest.update(&request_digest);
    digest.update(&plan.root_object_id.as_bytes());
    digest.update(&plan.expected_namespace_commit_id.as_bytes());
    digest.update(&plan.expected_object_id.as_bytes());
    digest.update(&plan.expected_object_revision_id.as_bytes());
    digest.update(&[kind_byte(plan.expected_kind)]);
    update_optional_identifier(
        &mut digest,
        plan.expected_file_version_id.map(FileVersionId::as_bytes),
    );
    digest.update(&plan.expected_entry_generation.to_be_bytes());
    digest.update(&plan.root_object_revision_id.as_bytes());
    digest.update(&plan.namespace_commit_id.as_bytes());
    update_optional_identifier(&mut digest, requesting_handle(plan).map(HandleId::as_bytes));
    digest.update(&plan.created_by.as_bytes());
    digest.update(&plan.created_at.get().to_be_bytes());
    for ancestor in plan.path.ancestors() {
        digest.update(&ancestor.object_id().as_bytes());
        digest.update(&ancestor.expected_revision_id().as_bytes());
        digest.update(&ancestor.new_revision_id().as_bytes());
    }
    digest.finalize().into()
}

fn requesting_handle(plan: &NamespaceUnlinkPublication) -> Option<HandleId> {
    match plan.authority {
        NamespaceUnlinkAuthority::Direct {
            requesting_handle_id,
        } => requesting_handle_id,
        NamespaceUnlinkAuthority::DeleteOnClose { .. } => None,
    }
}

const fn kind_code(kind: DirectoryEntryKind) -> i64 {
    match kind {
        DirectoryEntryKind::Directory => 1,
        DirectoryEntryKind::File => 2,
    }
}

const fn kind_byte(kind: DirectoryEntryKind) -> u8 {
    match kind {
        DirectoryEntryKind::Directory => 1,
        DirectoryEntryKind::File => 2,
    }
}

fn decode_kind(value: i64) -> Result<DirectoryEntryKind, HandleError> {
    match value {
        1 => Ok(DirectoryEntryKind::Directory),
        2 => Ok(DirectoryEntryKind::File),
        _ => Err(HandleError::Corrupt),
    }
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
    ObjectRevisionId::from_bytes(derive(
        operation_id,
        purpose,
        u64::try_from(ordinal).map_err(|_| HandleError::InvalidInput)?,
    ))
    .map_err(|_| HandleError::InvalidInput)
}

fn derive(operation_id: OperationId, purpose: &[u8], ordinal: u64) -> [u8; 16] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.adapter-unlink-identity.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&(purpose.len() as u64).to_be_bytes());
    digest.update(purpose);
    digest.update(&ordinal.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    if bytes == [0; 16] {
        bytes[15] = 1;
    }
    bytes
}

fn update_text(digest: &mut blake3::Hasher, value: &str) {
    digest.update(&(value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn update_optional_identifier(digest: &mut blake3::Hasher, value: Option<[u8; 16]>) {
    digest.update(&[u8::from(value.is_some())]);
    if let Some(value) = value {
        digest.update(&value);
    }
}

fn identifier<const N: usize, T>(
    bytes: &[u8],
    decode: impl FnOnce([u8; N]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, HandleError> {
    decode(bytes.try_into().map_err(|_| HandleError::Corrupt)?).map_err(|_| HandleError::Corrupt)
}

fn to_i64(value: u64) -> Result<i64, HandleError> {
    i64::try_from(value).map_err(|_| HandleError::InvalidInput)
}
