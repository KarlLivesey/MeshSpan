// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe intermediate-root planning for one semantic namespace rename.

use meshspan_domain::{
    BranchId, HandleId, NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId, PrincipalId,
    UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::resolution::{self, ResolvedNamespacePath};
use crate::{
    AdapterRenameRequest, DirectoryEntryKind, DirectoryRevisionTransition, HandleError,
    NamespacePath, NamespacePublicationPath, NamespaceRenamePublication,
};

/// Exact stable authority targets resolved before either rename grant is requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RenameTargets {
    pub(crate) source_object: ObjectId,
    pub(crate) target_parent_object: ObjectId,
}

struct CurrentRename {
    source: ResolvedNamespacePath,
    target: ResolvedNamespacePath,
    same_canonical_path: bool,
}

struct StoredPlan {
    request_digest: Vec<u8>,
    branch: Vec<u8>,
    volume: Vec<u8>,
    root_object: Vec<u8>,
    expected_commit: Vec<u8>,
    object: Vec<u8>,
    object_revision: Vec<u8>,
    source_generation: i64,
    intermediate_root: Vec<u8>,
    target_generation: i64,
    root_revision: Vec<u8>,
    commit: Vec<u8>,
    handle: Option<Vec<u8>>,
    source_object: Vec<u8>,
    target_parent: Vec<u8>,
    created_by: Vec<u8>,
    created_at: i64,
    source_depth: i64,
    target_depth: i64,
    result_digest: Vec<u8>,
}

pub(crate) fn targets(
    connection: &Connection,
    branch_id: BranchId,
    request: &AdapterRenameRequest,
) -> Result<RenameTargets, HandleError> {
    validate_request(request)?;
    let request_digest = request_digest(branch_id, request);
    if let Some(plan) = load_plan(connection, branch_id, request, request_digest)? {
        return Ok(plan_targets(&plan));
    }
    current_targets(&resolve_current(connection, branch_id, request)?)
}

pub(crate) fn prepare(
    connection: &mut Connection,
    branch_id: BranchId,
    request: &AdapterRenameRequest,
    created_by: PrincipalId,
    expected_targets: RenameTargets,
) -> Result<NamespaceRenamePublication, HandleError> {
    validate_request(request)?;
    let request_digest = request_digest(branch_id, request);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(plan) = load_plan(&transaction, branch_id, request, request_digest)? {
        if plan.created_by == created_by && plan_targets(&plan) == expected_targets {
            return Ok(plan);
        }
        return Err(HandleError::OperationConflict);
    }
    reject_operation_collision(&transaction, request.operation_id)?;
    let current = resolve_current(&transaction, branch_id, request)?;
    if current_targets(&current)? != expected_targets {
        return Err(HandleError::StaleHandle);
    }
    let plan = build_plan(branch_id, request, created_by, &current)?;
    persist_plan(&transaction, request_digest, &plan, expected_targets)?;
    transaction.commit()?;
    Ok(plan)
}

fn validate_request(request: &AdapterRenameRequest) -> Result<(), HandleError> {
    if request.source.components().is_empty()
        || request.target.components().is_empty()
        || request.source == request.target
    {
        Err(HandleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn resolve_current(
    connection: &Connection,
    branch_id: BranchId,
    request: &AdapterRenameRequest,
) -> Result<CurrentRename, HandleError> {
    let source = resolution::resolve(connection, branch_id, request.volume_id, &request.source)?;
    let source_leaf = source.leaf.ok_or(HandleError::NotFound)?;
    let same_canonical_path = canonical_path_eq(&request.source, &request.target);
    if source_leaf.kind == DirectoryEntryKind::Directory
        && canonical_descendant(&request.source, &request.target)
    {
        return Err(HandleError::InvalidInput);
    }
    let target = resolution::resolve(connection, branch_id, request.volume_id, &request.target)?;
    if source.namespace_commit != target.namespace_commit
        || source.root_object != target.root_object
    {
        return Err(HandleError::Corrupt);
    }
    if let Some(target_leaf) = target.leaf {
        let same_entry = same_canonical_path
            && target_leaf.object == source_leaf.object
            && target_leaf.revision == source_leaf.revision
            && target_leaf.generation == source_leaf.generation;
        if !same_entry {
            return Err(HandleError::AlreadyExists);
        }
    }
    Ok(CurrentRename {
        source,
        target,
        same_canonical_path,
    })
}

fn current_targets(current: &CurrentRename) -> Result<RenameTargets, HandleError> {
    Ok(RenameTargets {
        source_object: current.source.leaf.ok_or(HandleError::Corrupt)?.object,
        target_parent_object: current.target.parent_object,
    })
}

fn build_plan(
    branch_id: BranchId,
    request: &AdapterRenameRequest,
    created_by: PrincipalId,
    current: &CurrentRename,
) -> Result<NamespaceRenamePublication, HandleError> {
    let source_leaf = current.source.leaf.ok_or(HandleError::Corrupt)?;
    let source_ancestors = current
        .source
        .ancestors
        .iter()
        .enumerate()
        .map(|(ordinal, ancestor)| {
            DirectoryRevisionTransition::new(
                ancestor.object,
                ancestor.revision,
                derive_revision(request.operation_id, b"source-ancestor", ordinal)?,
            )
            .map_err(|_| HandleError::InvalidInput)
        })
        .collect::<Result<Vec<_>, HandleError>>()?;
    let target_ancestors = current
        .target
        .ancestors
        .iter()
        .enumerate()
        .map(|(ordinal, ancestor)| {
            let expected_revision = source_ancestors
                .iter()
                .find(|source| source.object_id() == ancestor.object)
                .map_or(ancestor.revision, |source| source.new_revision_id());
            DirectoryRevisionTransition::new(
                ancestor.object,
                expected_revision,
                derive_revision(request.operation_id, b"target-ancestor", ordinal)?,
            )
            .map_err(|_| HandleError::InvalidInput)
        })
        .collect::<Result<Vec<_>, HandleError>>()?;
    Ok(NamespaceRenamePublication {
        operation_id: request.operation_id,
        branch_id,
        volume_id: request.volume_id,
        root_object_id: current.source.root_object,
        expected_namespace_commit_id: current.source.namespace_commit,
        expected_object_id: source_leaf.object,
        expected_object_revision_id: source_leaf.revision,
        expected_source_entry_generation: source_leaf.generation,
        source: NamespacePublicationPath::new(request.source.clone(), source_ancestors)
            .map_err(|_| HandleError::InvalidInput)?,
        intermediate_root_object_revision_id: derive_revision(
            request.operation_id,
            b"intermediate-root",
            0,
        )?,
        target: NamespacePublicationPath::new(request.target.clone(), target_ancestors)
            .map_err(|_| HandleError::InvalidInput)?,
        target_entry_generation: if current.same_canonical_path {
            source_leaf.generation
        } else {
            derive_generation(request.operation_id)
        },
        root_object_revision_id: derive_revision(request.operation_id, b"root", 0)?,
        namespace_commit_id: derive_commit(request.operation_id)?,
        requesting_handle_id: request.requesting_handle_id,
        created_by,
        created_at: request.observed_at,
    })
}

fn persist_plan(
    transaction: &Transaction<'_>,
    request_digest: [u8; 32],
    plan: &NamespaceRenamePublication,
    targets: RenameTargets,
) -> Result<(), HandleError> {
    let result_digest = plan_digest(request_digest, plan, targets);
    transaction.execute(
        "INSERT INTO adapter_rename_plans(
            operation_id, request_digest, branch_id, volume_id, root_object_id,
            expected_namespace_commit_id, expected_object_id, expected_object_revision_id,
            expected_source_entry_generation, intermediate_root_object_revision_id,
            target_entry_generation, root_object_revision_id, namespace_commit_id,
            requesting_handle_id, source_object_id, target_parent_object_id, created_by,
            created_at, source_path_depth, target_path_depth, result_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                   ?16, ?17, ?18, ?19, ?20, ?21)",
        params![
            plan.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            plan.branch_id.as_bytes().as_slice(),
            plan.volume_id.as_bytes().as_slice(),
            plan.root_object_id.as_bytes().as_slice(),
            plan.expected_namespace_commit_id.as_bytes().as_slice(),
            plan.expected_object_id.as_bytes().as_slice(),
            plan.expected_object_revision_id.as_bytes().as_slice(),
            to_i64(plan.expected_source_entry_generation)?,
            plan.intermediate_root_object_revision_id
                .as_bytes()
                .as_slice(),
            to_i64(plan.target_entry_generation)?,
            plan.root_object_revision_id.as_bytes().as_slice(),
            plan.namespace_commit_id.as_bytes().as_slice(),
            plan.requesting_handle_id
                .map(HandleId::as_bytes)
                .as_ref()
                .map(<[u8; 16]>::as_slice),
            targets.source_object.as_bytes().as_slice(),
            targets.target_parent_object.as_bytes().as_slice(),
            plan.created_by.as_bytes().as_slice(),
            plan.created_at.get(),
            path_depth(plan.source.path())?,
            path_depth(plan.target.path())?,
            result_digest.as_slice(),
        ],
    )?;
    persist_ancestors(
        transaction,
        "adapter_rename_plan_source_ancestors",
        plan.operation_id,
        plan.source.ancestors(),
    )?;
    persist_ancestors(
        transaction,
        "adapter_rename_plan_target_ancestors",
        plan.operation_id,
        plan.target.ancestors(),
    )
}

fn persist_ancestors(
    transaction: &Transaction<'_>,
    table: &str,
    operation_id: OperationId,
    ancestors: &[DirectoryRevisionTransition],
) -> Result<(), HandleError> {
    let sql = format!(
        "INSERT INTO {table}(
            operation_id, ancestor_ordinal, object_id, expected_revision_id, new_revision_id
         ) VALUES (?1, ?2, ?3, ?4, ?5)"
    );
    let mut statement = transaction.prepare(&sql)?;
    for (ordinal, ancestor) in ancestors.iter().enumerate() {
        statement.execute(params![
            operation_id.as_bytes().as_slice(),
            i64::try_from(ordinal).map_err(|_| HandleError::InvalidInput)?,
            ancestor.object_id().as_bytes().as_slice(),
            ancestor.expected_revision_id().as_bytes().as_slice(),
            ancestor.new_revision_id().as_bytes().as_slice(),
        ])?;
    }
    Ok(())
}

fn load_plan(
    connection: &Connection,
    branch_id: BranchId,
    request: &AdapterRenameRequest,
    request_digest: [u8; 32],
) -> Result<Option<NamespaceRenamePublication>, HandleError> {
    let stored: Option<StoredPlan> = connection
        .query_row(
            "SELECT request_digest, branch_id, volume_id, root_object_id,
                    expected_namespace_commit_id, expected_object_id,
                    expected_object_revision_id, expected_source_entry_generation,
                    intermediate_root_object_revision_id, target_entry_generation,
                    root_object_revision_id, namespace_commit_id, requesting_handle_id,
                    source_object_id, target_parent_object_id, created_by, created_at,
                    source_path_depth, target_path_depth, result_digest
             FROM adapter_rename_plans WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredPlan {
                    request_digest: row.get(0)?,
                    branch: row.get(1)?,
                    volume: row.get(2)?,
                    root_object: row.get(3)?,
                    expected_commit: row.get(4)?,
                    object: row.get(5)?,
                    object_revision: row.get(6)?,
                    source_generation: row.get(7)?,
                    intermediate_root: row.get(8)?,
                    target_generation: row.get(9)?,
                    root_revision: row.get(10)?,
                    commit: row.get(11)?,
                    handle: row.get(12)?,
                    source_object: row.get(13)?,
                    target_parent: row.get(14)?,
                    created_by: row.get(15)?,
                    created_at: row.get(16)?,
                    source_depth: row.get(17)?,
                    target_depth: row.get(18)?,
                    result_digest: row.get(19)?,
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
    request: &AdapterRenameRequest,
    request_digest: [u8; 32],
    stored: &StoredPlan,
) -> Result<NamespaceRenamePublication, HandleError> {
    if stored.request_digest.as_slice() != request_digest
        || stored.branch.as_slice() != branch_id.as_bytes()
        || stored.volume.as_slice() != request.volume_id.as_bytes()
        || stored.created_at != request.observed_at.get()
        || usize::try_from(stored.source_depth) != Ok(request.source.components().len())
        || usize::try_from(stored.target_depth) != Ok(request.target.components().len())
    {
        return Err(HandleError::OperationConflict);
    }
    let plan = NamespaceRenamePublication {
        operation_id: request.operation_id,
        branch_id,
        volume_id: request.volume_id,
        root_object_id: identifier(&stored.root_object, ObjectId::from_bytes)?,
        expected_namespace_commit_id: identifier(
            &stored.expected_commit,
            NamespaceCommitId::from_bytes,
        )?,
        expected_object_id: identifier(&stored.object, ObjectId::from_bytes)?,
        expected_object_revision_id: identifier(
            &stored.object_revision,
            ObjectRevisionId::from_bytes,
        )?,
        expected_source_entry_generation: positive(stored.source_generation)?,
        source: NamespacePublicationPath::new(
            request.source.clone(),
            load_ancestors(
                connection,
                "adapter_rename_plan_source_ancestors",
                request.operation_id,
                request.source.components().len(),
            )?,
        )
        .map_err(|_| HandleError::Corrupt)?,
        intermediate_root_object_revision_id: identifier(
            &stored.intermediate_root,
            ObjectRevisionId::from_bytes,
        )?,
        target: NamespacePublicationPath::new(
            request.target.clone(),
            load_ancestors(
                connection,
                "adapter_rename_plan_target_ancestors",
                request.operation_id,
                request.target.components().len(),
            )?,
        )
        .map_err(|_| HandleError::Corrupt)?,
        target_entry_generation: positive(stored.target_generation)?,
        root_object_revision_id: identifier(&stored.root_revision, ObjectRevisionId::from_bytes)?,
        namespace_commit_id: identifier(&stored.commit, NamespaceCommitId::from_bytes)?,
        requesting_handle_id: stored
            .handle
            .as_deref()
            .map(|value| identifier(value, HandleId::from_bytes))
            .transpose()?,
        created_by: identifier(&stored.created_by, PrincipalId::from_bytes)?,
        created_at: UnixMicros::new(stored.created_at),
    };
    let targets = RenameTargets {
        source_object: identifier(&stored.source_object, ObjectId::from_bytes)?,
        target_parent_object: identifier(&stored.target_parent, ObjectId::from_bytes)?,
    };
    let input_matches = request.requesting_handle_id == plan.requesting_handle_id
        && targets.source_object == plan.expected_object_id;
    if input_matches
        && stored.result_digest.as_slice() == plan_digest(request_digest, &plan, targets)
    {
        Ok(plan)
    } else {
        Err(HandleError::Corrupt)
    }
}

fn load_ancestors(
    connection: &Connection,
    table: &str,
    operation_id: OperationId,
    path_depth: usize,
) -> Result<Vec<DirectoryRevisionTransition>, HandleError> {
    let expected = path_depth.checked_sub(1).ok_or(HandleError::Corrupt)?;
    let sql = format!(
        "SELECT ancestor_ordinal, object_id, expected_revision_id, new_revision_id
         FROM {table} WHERE operation_id = ?1 ORDER BY ancestor_ordinal"
    );
    let mut statement = connection.prepare(&sql)?;
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
             OR EXISTS(SELECT 1 FROM adapter_unlink_plans WHERE operation_id = ?1)
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

fn request_digest(branch_id: BranchId, request: &AdapterRenameRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.adapter-rename-request.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&branch_id.as_bytes());
    digest.update(&request.volume_id.as_bytes());
    update_path(&mut digest, &request.source);
    update_path(&mut digest, &request.target);
    update_optional_identifier(
        &mut digest,
        request.requesting_handle_id.map(HandleId::as_bytes),
    );
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.finalize().into()
}

fn plan_digest(
    request_digest: [u8; 32],
    plan: &NamespaceRenamePublication,
    targets: RenameTargets,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.adapter-rename-plan.v1\0");
    digest.update(&request_digest);
    digest.update(&plan.root_object_id.as_bytes());
    digest.update(&plan.expected_namespace_commit_id.as_bytes());
    digest.update(&plan.expected_object_id.as_bytes());
    digest.update(&plan.expected_object_revision_id.as_bytes());
    digest.update(&plan.expected_source_entry_generation.to_be_bytes());
    digest.update(&plan.intermediate_root_object_revision_id.as_bytes());
    digest.update(&plan.target_entry_generation.to_be_bytes());
    digest.update(&plan.root_object_revision_id.as_bytes());
    digest.update(&plan.namespace_commit_id.as_bytes());
    update_optional_identifier(
        &mut digest,
        plan.requesting_handle_id.map(HandleId::as_bytes),
    );
    digest.update(&targets.source_object.as_bytes());
    digest.update(&targets.target_parent_object.as_bytes());
    digest.update(&plan.created_by.as_bytes());
    digest.update(&plan.created_at.get().to_be_bytes());
    update_transitions(&mut digest, plan.source.ancestors());
    update_transitions(&mut digest, plan.target.ancestors());
    digest.finalize().into()
}

fn plan_targets(plan: &NamespaceRenamePublication) -> RenameTargets {
    RenameTargets {
        source_object: plan.expected_object_id,
        target_parent_object: plan
            .target
            .ancestors()
            .last()
            .map_or(plan.root_object_id, |ancestor| ancestor.object_id()),
    }
}

fn canonical_path_eq(left: &NamespacePath, right: &NamespacePath) -> bool {
    left.components().len() == right.components().len()
        && left
            .components()
            .iter()
            .zip(right.components())
            .all(|(left, right)| left.canonical() == right.canonical())
}

fn canonical_descendant(source: &NamespacePath, target: &NamespacePath) -> bool {
    source.components().len() < target.components().len()
        && source
            .components()
            .iter()
            .zip(target.components())
            .all(|(source, target)| source.canonical() == target.canonical())
}

fn derive_generation(operation_id: OperationId) -> u64 {
    let bytes = derive(operation_id, b"generation", 0);
    let mut generation = [0_u8; 8];
    generation.copy_from_slice(&bytes[..8]);
    super::entry_generation_from_hash(generation)
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
    digest.update(b"meshspan.filesystem.adapter-rename-identity.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&(purpose.len() as u64).to_be_bytes());
    digest.update(purpose);
    digest.update(&ordinal.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    meshspan_domain::uuid_v8(bytes)
}

fn update_path(digest: &mut blake3::Hasher, path: &NamespacePath) {
    digest.update(&(path.components().len() as u64).to_be_bytes());
    for component in path.components() {
        update_text(digest, component.display());
        update_text(digest, component.canonical());
    }
}

fn update_transitions(digest: &mut blake3::Hasher, values: &[DirectoryRevisionTransition]) {
    digest.update(&(values.len() as u64).to_be_bytes());
    for value in values {
        digest.update(&value.object_id().as_bytes());
        digest.update(&value.expected_revision_id().as_bytes());
        digest.update(&value.new_revision_id().as_bytes());
    }
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

fn path_depth(path: &NamespacePath) -> Result<i64, HandleError> {
    i64::try_from(path.components().len()).map_err(|_| HandleError::InvalidInput)
}

fn positive(value: i64) -> Result<u64, HandleError> {
    let value = u64::try_from(value).map_err(|_| HandleError::Corrupt)?;
    if value == 0 {
        Err(HandleError::Corrupt)
    } else {
        Ok(value)
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
