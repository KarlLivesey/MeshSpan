// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe daemon planning for semantic connector namespace mutations.

#[path = "namespace_planning/create_file.rs"]
pub(crate) mod create_file;
#[path = "namespace_planning/rename.rs"]
pub(crate) mod rename;
#[path = "namespace_planning/resolution.rs"]
mod resolution;
#[path = "namespace_planning/unlink.rs"]
pub(crate) mod unlink;
#[path = "namespace_planning/upload_commit.rs"]
pub(crate) mod upload_commit;

use meshspan_domain::{
    BranchId, NamespaceCommitId, ObjectId, ObjectRevisionId, OperationId, PrincipalId, UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::{
    AdapterCreateDirectoryRequest, DirectoryPublication, DirectoryRevisionTransition, HandleError,
    NamespacePath, NamespacePublicationPath, UploadDisposition,
};

const MAX_SAFE_ENTRY_GENERATION: u64 = 9_007_199_254_740_991;

pub(super) const fn entry_generation_from_hash(bytes: [u8; 8]) -> u64 {
    (u64::from_be_bytes(bytes) % MAX_SAFE_ENTRY_GENERATION) + 1
}

pub(crate) fn upload_authority_target(
    connection: &Connection,
    branch_id: BranchId,
    volume_id: meshspan_domain::VolumeId,
    path: &NamespacePath,
    disposition: UploadDisposition,
) -> Result<ObjectId, HandleError> {
    let current = resolution::resolve(connection, branch_id, volume_id, path)?;
    match (disposition, current.leaf) {
        (UploadDisposition::CreateNew, None) => Ok(current.parent_object),
        (UploadDisposition::CreateNew, Some(_)) => Err(HandleError::AlreadyExists),
        (_, None) => Err(HandleError::NotFound),
        (_, Some(leaf)) if leaf.kind != crate::DirectoryEntryKind::File => {
            Err(HandleError::NotFound)
        }
        (UploadDisposition::ReplaceIfVersion(expected), Some(leaf))
            if leaf.version != Some(expected) =>
        {
            Err(HandleError::StaleHandle)
        }
        (_, Some(leaf)) if leaf.version.is_none() => Err(HandleError::Corrupt),
        (_, Some(leaf)) => Ok(leaf.object),
    }
}

struct StoredPlan {
    request_digest: Vec<u8>,
    branch: Vec<u8>,
    volume: Vec<u8>,
    root_object: Vec<u8>,
    expected_commit: Option<Vec<u8>>,
    directory_object: Vec<u8>,
    directory_revision: Vec<u8>,
    root_revision: Vec<u8>,
    commit: Vec<u8>,
    generation: i64,
    parent_object: Vec<u8>,
    created_by: Vec<u8>,
    created_at: i64,
    path_depth: i64,
    result_digest: Vec<u8>,
}

pub(crate) fn directory_parent(
    connection: &Connection,
    branch_id: BranchId,
    request: &AdapterCreateDirectoryRequest,
) -> Result<ObjectId, HandleError> {
    validate_request(request)?;
    let request_digest = request_digest(branch_id, request);
    if let Some(plan) = load_plan(connection, branch_id, request, request_digest)? {
        return Ok(publication_parent(&plan));
    }
    Ok(resolve_current(connection, branch_id, request)?.parent_object)
}

pub(crate) fn prepare_directory(
    connection: &mut Connection,
    branch_id: BranchId,
    request: &AdapterCreateDirectoryRequest,
    created_by: PrincipalId,
    expected_parent: ObjectId,
) -> Result<DirectoryPublication, HandleError> {
    validate_request(request)?;
    let request_digest = request_digest(branch_id, request);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(plan) = load_plan(&transaction, branch_id, request, request_digest)? {
        if plan.created_by == created_by && publication_parent(&plan) == expected_parent {
            return Ok(plan);
        }
        return Err(HandleError::OperationConflict);
    }
    reject_operation_collision(&transaction, request.operation_id)?;
    let current = resolve_current_or_initial(&transaction, branch_id, request, expected_parent)?;
    if current.parent_object != expected_parent {
        return Err(HandleError::StaleHandle);
    }
    let plan = build_plan(branch_id, request, created_by, &current)?;
    persist_plan(&transaction, request_digest, &plan, expected_parent)?;
    transaction.commit()?;
    Ok(plan)
}

fn validate_request(request: &AdapterCreateDirectoryRequest) -> Result<(), HandleError> {
    if request.path.components().is_empty() {
        Err(HandleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn resolve_current(
    connection: &Connection,
    branch_id: BranchId,
    request: &AdapterCreateDirectoryRequest,
) -> Result<resolution::ResolvedNamespacePath, HandleError> {
    let current = resolution::resolve(connection, branch_id, request.volume_id, &request.path)?;
    if current.leaf.is_some() {
        Err(HandleError::AlreadyExists)
    } else {
        Ok(current)
    }
}

fn resolve_current_or_initial(
    connection: &Connection,
    branch_id: BranchId,
    request: &AdapterCreateDirectoryRequest,
    root_object: ObjectId,
) -> Result<resolution::ResolvedNamespacePath, HandleError> {
    let current = resolution::resolve_or_initial(
        connection,
        branch_id,
        request.volume_id,
        &request.path,
        root_object,
    )?;
    if current.leaf.is_some() {
        Err(HandleError::AlreadyExists)
    } else {
        Ok(current)
    }
}

fn build_plan(
    branch_id: BranchId,
    request: &AdapterCreateDirectoryRequest,
    created_by: PrincipalId,
    current: &resolution::ResolvedNamespacePath,
) -> Result<DirectoryPublication, HandleError> {
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
    Ok(DirectoryPublication {
        operation_id: request.operation_id,
        branch_id,
        volume_id: request.volume_id,
        root_object_id: current.root_object,
        expected_namespace_commit_id: current.namespace_commit,
        directory_object_id: derive_object(request.operation_id)?,
        directory_object_revision_id: derive_revision(request.operation_id, b"directory", 0)?,
        root_object_revision_id: derive_revision(request.operation_id, b"root", 0)?,
        namespace_commit_id: derive_commit(request.operation_id)?,
        path: NamespacePublicationPath::new(request.path.clone(), ancestors)
            .map_err(|_| HandleError::InvalidInput)?,
        entry_generation: derive_generation(request.operation_id),
        created_by,
        created_at: request.observed_at,
    })
}

fn persist_plan(
    transaction: &Transaction<'_>,
    request_digest: [u8; 32],
    plan: &DirectoryPublication,
    parent_object: ObjectId,
) -> Result<(), HandleError> {
    let result_digest = plan_digest(request_digest, plan, parent_object);
    let expected_commit = plan
        .expected_namespace_commit_id
        .map(NamespaceCommitId::as_bytes);
    transaction.execute(
        "INSERT INTO adapter_directory_plans(
            operation_id, request_digest, branch_id, volume_id, root_object_id,
            expected_namespace_commit_id, directory_object_id, directory_object_revision_id,
            root_object_revision_id, namespace_commit_id, entry_generation, parent_object_id,
            created_by, created_at, path_depth, result_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            plan.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            plan.branch_id.as_bytes().as_slice(),
            plan.volume_id.as_bytes().as_slice(),
            plan.root_object_id.as_bytes().as_slice(),
            expected_commit.as_ref().map(<[u8; 16]>::as_slice),
            plan.directory_object_id.as_bytes().as_slice(),
            plan.directory_object_revision_id.as_bytes().as_slice(),
            plan.root_object_revision_id.as_bytes().as_slice(),
            plan.namespace_commit_id.as_bytes().as_slice(),
            to_i64(plan.entry_generation)?,
            parent_object.as_bytes().as_slice(),
            plan.created_by.as_bytes().as_slice(),
            plan.created_at.get(),
            i64::try_from(plan.path.path().components().len())
                .map_err(|_| HandleError::InvalidInput)?,
            result_digest.as_slice(),
        ],
    )?;
    for (ordinal, ancestor) in plan.path.ancestors().iter().enumerate() {
        transaction.execute(
            "INSERT INTO adapter_directory_plan_ancestors(
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
    request: &AdapterCreateDirectoryRequest,
    request_digest: [u8; 32],
) -> Result<Option<DirectoryPublication>, HandleError> {
    let stored: Option<StoredPlan> = connection
        .query_row(
            "SELECT request_digest, branch_id, volume_id, root_object_id,
                    expected_namespace_commit_id, directory_object_id,
                    directory_object_revision_id, root_object_revision_id, namespace_commit_id,
                    entry_generation, parent_object_id, created_by, created_at, path_depth,
                    result_digest
             FROM adapter_directory_plans WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredPlan {
                    request_digest: row.get(0)?,
                    branch: row.get(1)?,
                    volume: row.get(2)?,
                    root_object: row.get(3)?,
                    expected_commit: row.get(4)?,
                    directory_object: row.get(5)?,
                    directory_revision: row.get(6)?,
                    root_revision: row.get(7)?,
                    commit: row.get(8)?,
                    generation: row.get(9)?,
                    parent_object: row.get(10)?,
                    created_by: row.get(11)?,
                    created_at: row.get(12)?,
                    path_depth: row.get(13)?,
                    result_digest: row.get(14)?,
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
    request: &AdapterCreateDirectoryRequest,
    request_digest: [u8; 32],
    stored: &StoredPlan,
) -> Result<DirectoryPublication, HandleError> {
    if stored.request_digest.as_slice() != request_digest
        || stored.branch.as_slice() != branch_id.as_bytes()
        || stored.volume.as_slice() != request.volume_id.as_bytes()
        || stored.created_at != request.observed_at.get()
        || usize::try_from(stored.path_depth) != Ok(request.path.components().len())
    {
        return Err(HandleError::OperationConflict);
    }
    let ancestors = load_ancestors(
        connection,
        request.operation_id,
        request.path.components().len(),
    )?;
    let plan = DirectoryPublication {
        operation_id: request.operation_id,
        branch_id,
        volume_id: request.volume_id,
        root_object_id: identifier(&stored.root_object, ObjectId::from_bytes)?,
        expected_namespace_commit_id: stored
            .expected_commit
            .as_deref()
            .map(|bytes| identifier(bytes, NamespaceCommitId::from_bytes))
            .transpose()?,
        directory_object_id: identifier(&stored.directory_object, ObjectId::from_bytes)?,
        directory_object_revision_id: identifier(
            &stored.directory_revision,
            ObjectRevisionId::from_bytes,
        )?,
        root_object_revision_id: identifier(&stored.root_revision, ObjectRevisionId::from_bytes)?,
        namespace_commit_id: identifier(&stored.commit, NamespaceCommitId::from_bytes)?,
        path: NamespacePublicationPath::new(request.path.clone(), ancestors)
            .map_err(|_| HandleError::Corrupt)?,
        entry_generation: u64::try_from(stored.generation).map_err(|_| HandleError::Corrupt)?,
        created_by: identifier(&stored.created_by, PrincipalId::from_bytes)?,
        created_at: UnixMicros::new(stored.created_at),
    };
    let parent = identifier(&stored.parent_object, ObjectId::from_bytes)?;
    if stored.result_digest.as_slice() == plan_digest(request_digest, &plan, parent) {
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
         FROM adapter_directory_plan_ancestors
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
             OR EXISTS(SELECT 1 FROM adapter_unlink_plans WHERE operation_id = ?1)
             OR EXISTS(SELECT 1 FROM adapter_rename_plans WHERE operation_id = ?1)
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

fn request_digest(branch_id: BranchId, request: &AdapterCreateDirectoryRequest) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.adapter-create-directory-request.v1\0");
    digest.update(&request.operation_id.as_bytes());
    digest.update(&branch_id.as_bytes());
    digest.update(&request.volume_id.as_bytes());
    digest.update(&(request.path.components().len() as u64).to_be_bytes());
    for component in request.path.components() {
        update_text(&mut digest, component.display());
        update_text(&mut digest, component.canonical());
    }
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.finalize().into()
}

fn plan_digest(
    request_digest: [u8; 32],
    plan: &DirectoryPublication,
    parent: ObjectId,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.adapter-create-directory-plan.v1\0");
    digest.update(&request_digest);
    digest.update(&plan.root_object_id.as_bytes());
    digest.update(
        &plan
            .expected_namespace_commit_id
            .map_or([0; 16], NamespaceCommitId::as_bytes),
    );
    digest.update(&plan.directory_object_id.as_bytes());
    digest.update(&plan.directory_object_revision_id.as_bytes());
    digest.update(&plan.root_object_revision_id.as_bytes());
    digest.update(&plan.namespace_commit_id.as_bytes());
    digest.update(&plan.entry_generation.to_be_bytes());
    digest.update(&parent.as_bytes());
    digest.update(&plan.created_by.as_bytes());
    digest.update(&plan.created_at.get().to_be_bytes());
    for ancestor in plan.path.ancestors() {
        digest.update(&ancestor.object_id().as_bytes());
        digest.update(&ancestor.expected_revision_id().as_bytes());
        digest.update(&ancestor.new_revision_id().as_bytes());
    }
    digest.finalize().into()
}

fn publication_parent(plan: &DirectoryPublication) -> ObjectId {
    plan.path
        .ancestors()
        .last()
        .map_or(plan.root_object_id, |ancestor| ancestor.object_id())
}

fn derive_object(operation_id: OperationId) -> Result<ObjectId, HandleError> {
    ObjectId::from_bytes(derive(operation_id, b"object", 0)).map_err(|_| HandleError::InvalidInput)
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

fn derive_generation(operation_id: OperationId) -> u64 {
    let bytes = derive(operation_id, b"generation", 0);
    let mut generation = [0_u8; 8];
    generation.copy_from_slice(&bytes[..8]);
    entry_generation_from_hash(generation)
}

fn derive(operation_id: OperationId, purpose: &[u8], ordinal: u64) -> [u8; 16] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.adapter-directory-identity.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&(purpose.len() as u64).to_be_bytes());
    digest.update(purpose);
    digest.update(&ordinal.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    meshspan_domain::uuid_v8(bytes)
}

fn update_text(digest: &mut blake3::Hasher, value: &str) {
    digest.update(&(value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn identifier<const N: usize, T>(
    bytes: &[u8],
    decode: impl FnOnce([u8; N]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, HandleError> {
    let bytes = bytes.try_into().map_err(|_| HandleError::Corrupt)?;
    decode(bytes).map_err(|_| HandleError::Corrupt)
}

fn to_i64(value: u64) -> Result<i64, HandleError> {
    i64::try_from(value).map_err(|_| HandleError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{
        AssuranceLevel, AuthenticationService, ContentManifestId, FileVersionId, NodeId, Revision,
        Rights, VolumeId,
    };
    use rusqlite::params;
    use tempfile::tempdir;

    use super::*;
    use crate::{
        AdapterCreateFileRequest, AdapterRenameRequest, AdapterUnlinkRequest, CreateDisposition,
        FilePublication, FilesystemAccessContext, FilesystemAdapterPolicy,
        FilesystemAuthorityGrant, HandleAccess, HandleShare, ManifestPublication, NamespaceLimits,
        NamespacePath, NamespacePublicationPath, RootFilePublication, VersionPublicationStore,
    };

    #[test]
    fn derived_entry_generations_are_positive_json_safe_integers() {
        assert_eq!(entry_generation_from_hash([0; 8]), 1);
        assert_eq!(
            entry_generation_from_hash([u8::MAX; 8]),
            (u64::MAX % MAX_SAFE_ENTRY_GENERATION) + 1
        );
        assert!(entry_generation_from_hash([u8::MAX; 8]) <= MAX_SAFE_ENTRY_GENERATION);
    }

    #[test]
    fn nested_directory_plan_restarts_exactly_and_detects_corruption()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = tempdir()?;
        let mut store = VersionPublicationStore::open(state.path(), UnixMicros::new(1))?;
        let seed = seed_publication()?;
        store.publish_root_file(&seed)?;

        let first = request(30, ["Archive"])?;
        let root = store.adapter_directory_parent(seed.file.branch_id, &first)?;
        let first_plan = store.prepare_adapter_directory(
            seed.file.branch_id,
            &first,
            seed.file.created_by,
            root,
        )?;
        store.create_directory(&first_plan)?;

        let nested = request(31, ["Archive", "2026"])?;
        let parent = store.adapter_directory_parent(seed.file.branch_id, &nested)?;
        assert_eq!(parent, first_plan.directory_object_id);
        let planned = store.prepare_adapter_directory(
            seed.file.branch_id,
            &nested,
            seed.file.created_by,
            parent,
        )?;
        assert_eq!(planned.path.ancestors().len(), 1);
        drop(store);

        let mut reopened = VersionPublicationStore::open(state.path(), UnixMicros::new(3))?;
        assert_eq!(
            reopened.prepare_adapter_directory(
                seed.file.branch_id,
                &nested,
                seed.file.created_by,
                parent,
            )?,
            planned
        );
        let changed = AdapterCreateDirectoryRequest {
            path: NamespacePath::from_components(
                ["Archive", "different"],
                NamespaceLimits::PORTABLE,
            )?,
            ..nested.clone()
        };
        assert!(matches!(
            reopened.adapter_directory_parent(seed.file.branch_id, &changed),
            Err(HandleError::OperationConflict)
        ));
        reopened.test_connection().execute(
            "UPDATE adapter_directory_plans SET result_digest = zeroblob(32)
             WHERE operation_id = ?1",
            params![nested.operation_id.as_bytes().as_slice()],
        )?;
        assert!(matches!(
            reopened.adapter_directory_parent(seed.file.branch_id, &nested),
            Err(HandleError::Corrupt)
        ));
        Ok(())
    }

    #[test]
    fn unlink_plan_binds_the_exact_file_and_fails_closed_when_tampered()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = tempdir()?;
        let seed = seed_publication()?;
        let mut store = VersionPublicationStore::open(state.path(), UnixMicros::new(1))?;
        store.publish_root_file(&seed)?;
        let request = AdapterUnlinkRequest {
            operation_id: OperationId::from_bytes([40; 16])?,
            volume_id: seed.file.volume_id,
            path: seed.path.path().clone(),
            requesting_handle_id: None,
            observed_at: UnixMicros::new(2),
        };
        let target = store.adapter_unlink_target(seed.file.branch_id, &request)?;
        assert_eq!(target, seed.file.object_id);
        let planned = store.prepare_adapter_unlink(
            seed.file.branch_id,
            &request,
            seed.file.created_by,
            target,
        )?;
        assert_eq!(
            planned.expected_object_revision_id,
            seed.file_object_revision_id
        );
        assert_eq!(planned.expected_file_version_id, Some(seed.file.version_id));
        drop(store);

        let mut reopened = VersionPublicationStore::open(state.path(), UnixMicros::new(3))?;
        assert_eq!(
            reopened.prepare_adapter_unlink(
                seed.file.branch_id,
                &request,
                seed.file.created_by,
                target,
            )?,
            planned
        );
        reopened.test_connection().execute(
            "UPDATE adapter_unlink_plans SET expected_object_id = ?1
             WHERE operation_id = ?2",
            params![&[99_u8; 16], request.operation_id.as_bytes().as_slice()],
        )?;
        assert!(matches!(
            reopened.adapter_unlink_target(seed.file.branch_id, &request),
            Err(HandleError::Corrupt)
        ));
        Ok(())
    }

    #[test]
    fn rename_plan_uses_the_intermediate_shared_ancestor_and_rejects_cycles()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = tempdir()?;
        let seed = seed_publication()?;
        let mut store = VersionPublicationStore::open(state.path(), UnixMicros::new(1))?;
        store.publish_root_file(&seed)?;
        create_path(
            &mut store,
            seed.file.branch_id,
            seed.file.created_by,
            50,
            ["a"],
        )?;
        create_path(
            &mut store,
            seed.file.branch_id,
            seed.file.created_by,
            51,
            ["a", "b"],
        )?;
        create_path(
            &mut store,
            seed.file.branch_id,
            seed.file.created_by,
            52,
            ["a", "c"],
        )?;

        let request = rename_request(53, ["a", "b"], ["a", "c", "moved"])?;
        let targets = store.adapter_rename_targets(seed.file.branch_id, &request)?;
        let plan = store.prepare_adapter_rename(
            seed.file.branch_id,
            &request,
            seed.file.created_by,
            targets,
        )?;
        assert_eq!(plan.source.ancestors().len(), 1);
        assert_eq!(plan.target.ancestors().len(), 2);
        assert_eq!(
            plan.target.ancestors()[0].expected_revision_id(),
            plan.source.ancestors()[0].new_revision_id()
        );
        store.rename_namespace(&plan)?;

        let case_change = rename_request(54, ["a", "c", "moved"], ["a", "c", "MOVED"])?;
        let targets = store.adapter_rename_targets(seed.file.branch_id, &case_change)?;
        let case_plan = store.prepare_adapter_rename(
            seed.file.branch_id,
            &case_change,
            seed.file.created_by,
            targets,
        )?;
        assert_eq!(
            case_plan.target_entry_generation,
            case_plan.expected_source_entry_generation
        );
        store.rename_namespace(&case_plan)?;

        let cycle = rename_request(55, ["a", "c"], ["a", "c", "MOVED", "inside"])?;
        assert!(matches!(
            store.adapter_rename_targets(seed.file.branch_id, &cycle),
            Err(HandleError::InvalidInput)
        ));
        drop(store);

        let mut reopened = VersionPublicationStore::open(state.path(), UnixMicros::new(70))?;
        assert_eq!(
            reopened.prepare_adapter_rename(
                seed.file.branch_id,
                &case_change,
                seed.file.created_by,
                targets,
            )?,
            case_plan
        );
        reopened.test_connection().execute(
            "UPDATE adapter_rename_plans SET target_parent_object_id = ?1
             WHERE operation_id = ?2",
            params![&[99_u8; 16], case_change.operation_id.as_bytes().as_slice()],
        )?;
        assert!(matches!(
            reopened.adapter_rename_targets(seed.file.branch_id, &case_change),
            Err(HandleError::Corrupt)
        ));
        Ok(())
    }

    #[test]
    fn file_create_plan_freezes_admitted_authority_and_policy_across_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = tempdir()?;
        let seed = seed_publication()?;
        let mut store = VersionPublicationStore::open(state.path(), UnixMicros::new(1))?;
        store.publish_root_file(&seed)?;
        let context = access_context()?;
        let request = AdapterCreateFileRequest {
            operation_id: OperationId::from_bytes([60; 16])?,
            handle_id: meshspan_domain::HandleId::from_bytes([61; 16])?,
            volume_id: seed.file.volume_id,
            path: NamespacePath::from_components(["new"], NamespaceLimits::PORTABLE)?,
            create_disposition: CreateDisposition::OpenOrCreate,
            desired_access: HandleAccess::new(true, true, false)?,
            share_access: HandleShare::new(true, true, false),
            delete_on_close: false,
            maximum_stage_bytes: Some(1_024),
            lease_expires_at: UnixMicros::new(100),
            content_deadline: UnixMicros::new(90),
            observed_at: context.now,
        };
        let target = store.adapter_file_create_target(seed.file.branch_id, context, &request)?;
        let grant = create_grant(
            context,
            seed.file.volume_id,
            target.object_id,
            Revision::new(1),
        )?;
        let policy = FilesystemAdapterPolicy::new(true, 1, 1)?;
        let plan = store.prepare_adapter_file_create(
            seed.file.branch_id,
            context,
            &request,
            policy,
            grant,
            target,
        )?;
        drop(store);

        let mut reopened = VersionPublicationStore::open(state.path(), UnixMicros::new(3))?;
        let changed_grant = create_grant(
            context,
            seed.file.volume_id,
            target.object_id,
            Revision::new(2),
        )?;
        let changed_policy = FilesystemAdapterPolicy::new(false, 2, 2)?;
        let replay = reopened.prepare_adapter_file_create(
            seed.file.branch_id,
            context,
            &request,
            changed_policy,
            changed_grant,
            target,
        )?;
        assert_eq!(replay, plan);
        assert_eq!(replay.open.handle.authorization_revision, Revision::new(1));
        assert!(replay.initial_file.retain_superseded_history);
        assert_eq!(replay.initial_file.retention_policy_sequence, 1);
        assert_eq!(replay.initial_file.manifest_format_version, 1);
        reopened.test_connection().execute(
            "UPDATE adapter_file_create_plans SET object_id = ?1 WHERE operation_id = ?2",
            params![&[99_u8; 16], request.operation_id.as_bytes().as_slice()],
        )?;
        assert!(matches!(
            reopened.adapter_file_create_target(seed.file.branch_id, context, &request),
            Err(HandleError::Corrupt)
        ));
        Ok(())
    }

    #[test]
    fn open_or_create_plan_binds_an_existing_file_across_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = tempdir()?;
        let seed = seed_publication()?;
        let mut store = VersionPublicationStore::open(state.path(), UnixMicros::new(1))?;
        store.publish_root_file(&seed)?;
        let context = access_context()?;
        let request = AdapterCreateFileRequest {
            operation_id: OperationId::from_bytes([62; 16])?,
            handle_id: meshspan_domain::HandleId::from_bytes([63; 16])?,
            volume_id: seed.file.volume_id,
            path: NamespacePath::from_components(["seed"], NamespaceLimits::PORTABLE)?,
            create_disposition: CreateDisposition::OpenOrCreate,
            desired_access: HandleAccess::new(true, false, false)?,
            share_access: HandleShare::new(true, true, true),
            delete_on_close: false,
            maximum_stage_bytes: None,
            lease_expires_at: UnixMicros::new(100),
            content_deadline: UnixMicros::new(90),
            observed_at: context.now,
        };
        let target = store.adapter_file_create_target(seed.file.branch_id, context, &request)?;
        assert_eq!(target.object_id, seed.file.object_id);
        assert_eq!(target.existing_object_id, Some(seed.file.object_id));
        let grant = create_grant(
            context,
            seed.file.volume_id,
            target.object_id,
            Revision::new(1),
        )?;
        let plan = store.prepare_adapter_file_create(
            seed.file.branch_id,
            context,
            &request,
            FilesystemAdapterPolicy::new(true, 1, 1)?,
            grant,
            target,
        )?;
        assert_eq!(
            plan.open.handle.create_disposition,
            CreateDisposition::OpenOrCreate
        );
        drop(store);

        let mut reopened = VersionPublicationStore::open(state.path(), UnixMicros::new(3))?;
        assert_eq!(
            reopened.adapter_file_create_target(seed.file.branch_id, context, &request)?,
            target
        );
        assert_eq!(
            reopened.prepare_adapter_file_create(
                seed.file.branch_id,
                context,
                &request,
                FilesystemAdapterPolicy::new(false, 2, 2)?,
                grant,
                target,
            )?,
            plan
        );
        let conflicting = AdapterCreateFileRequest {
            create_disposition: CreateDisposition::CreateNew,
            ..request.clone()
        };
        assert!(matches!(
            reopened.adapter_file_create_target(seed.file.branch_id, context, &conflicting),
            Err(HandleError::OperationConflict)
        ));
        let create_new = AdapterCreateFileRequest {
            operation_id: OperationId::from_bytes([64; 16])?,
            handle_id: meshspan_domain::HandleId::from_bytes([65; 16])?,
            ..conflicting
        };
        assert!(matches!(
            reopened.adapter_file_create_target(seed.file.branch_id, context, &create_new),
            Err(HandleError::AlreadyExists)
        ));
        let invalid_overwrite = AdapterCreateFileRequest {
            operation_id: OperationId::from_bytes([66; 16])?,
            handle_id: meshspan_domain::HandleId::from_bytes([67; 16])?,
            create_disposition: CreateDisposition::OverwriteOrCreate,
            ..request.clone()
        };
        assert!(matches!(
            reopened.adapter_file_create_target(seed.file.branch_id, context, &invalid_overwrite),
            Err(HandleError::InvalidInput)
        ));
        reopened.test_connection().execute(
            "UPDATE adapter_file_create_plans SET expected_existing_object_id = ?1
             WHERE operation_id = ?2",
            params![&[99_u8; 16], request.operation_id.as_bytes().as_slice()],
        )?;
        assert!(matches!(
            reopened.adapter_file_create_target(seed.file.branch_id, context, &request),
            Err(HandleError::Corrupt)
        ));
        Ok(())
    }

    fn access_context() -> Result<FilesystemAccessContext, Box<dyn std::error::Error>> {
        Ok(FilesystemAccessContext {
            authentication_service: AuthenticationService::Https,
            credential_digest: [40; 32],
            required_assurance: AssuranceLevel::SingleFactor,
            gateway_node_id: NodeId::from_bytes([19; 16])?,
            gateway_incarnation: 1,
            now: UnixMicros::new(10),
        })
    }

    fn create_grant(
        context: FilesystemAccessContext,
        volume_id: VolumeId,
        parent: ObjectId,
        identity_revision: Revision,
    ) -> Result<FilesystemAuthorityGrant, Box<dyn std::error::Error>> {
        Ok(FilesystemAuthorityGrant {
            principal_id: PrincipalId::from_bytes([18; 16])?,
            gateway_node_id: context.gateway_node_id,
            gateway_incarnation: context.gateway_incarnation,
            volume_id,
            object_id: parent,
            requested_rights: Rights::CREATE_CHILD,
            identity_revision,
            namespace_revision: Revision::new(1),
            object_revision: Revision::new(1),
            gateway_revision: Revision::new(1),
            expires_at: UnixMicros::new(200),
            evidence_digest: [42; 32],
        })
    }

    fn create_path<const N: usize>(
        store: &mut VersionPublicationStore,
        branch_id: BranchId,
        principal_id: PrincipalId,
        operation: u8,
        components: [&str; N],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let request = AdapterCreateDirectoryRequest {
            operation_id: OperationId::from_bytes([operation; 16])?,
            volume_id: VolumeId::from_bytes([12; 16])?,
            path: NamespacePath::from_components(components, NamespaceLimits::PORTABLE)?,
            observed_at: UnixMicros::new(i64::from(operation)),
        };
        let parent = store.adapter_directory_parent(branch_id, &request)?;
        let plan = store.prepare_adapter_directory(branch_id, &request, principal_id, parent)?;
        store.create_directory(&plan)?;
        Ok(())
    }

    fn rename_request<const S: usize, const T: usize>(
        operation: u8,
        source: [&str; S],
        target: [&str; T],
    ) -> Result<AdapterRenameRequest, Box<dyn std::error::Error>> {
        Ok(AdapterRenameRequest {
            operation_id: OperationId::from_bytes([operation; 16])?,
            volume_id: VolumeId::from_bytes([12; 16])?,
            source: NamespacePath::from_components(source, NamespaceLimits::PORTABLE)?,
            target: NamespacePath::from_components(target, NamespaceLimits::PORTABLE)?,
            requesting_handle_id: None,
            observed_at: UnixMicros::new(i64::from(operation)),
        })
    }

    fn request<const N: usize>(
        operation: u8,
        components: [&str; N],
    ) -> Result<AdapterCreateDirectoryRequest, Box<dyn std::error::Error>> {
        Ok(AdapterCreateDirectoryRequest {
            operation_id: OperationId::from_bytes([operation; 16])?,
            volume_id: VolumeId::from_bytes([12; 16])?,
            path: NamespacePath::from_components(components, NamespaceLimits::PORTABLE)?,
            observed_at: UnixMicros::new(2),
        })
    }

    fn seed_publication() -> Result<RootFilePublication, Box<dyn std::error::Error>> {
        Ok(RootFilePublication {
            file: FilePublication {
                operation_id: OperationId::from_bytes([1; 16])?,
                branch_id: BranchId::from_bytes([11; 16])?,
                volume_id: VolumeId::from_bytes([12; 16])?,
                object_id: ObjectId::from_bytes([13; 16])?,
                expected_current_version_id: None,
                version_id: FileVersionId::from_bytes([14; 16])?,
                parent_version_id: None,
                retain_superseded_history: true,
                retention_policy_sequence: 1,
                manifest: ManifestPublication {
                    manifest_id: ContentManifestId::from_bytes([15; 16])?,
                    format_version: 1,
                    logical_length: 0,
                    content_digest: blake3::hash(&[]).into(),
                    root_digest: [17; 32],
                },
                created_by: PrincipalId::from_bytes([18; 16])?,
                created_at: UnixMicros::new(1),
            },
            root_object_id: ObjectId::from_bytes([2; 16])?,
            expected_namespace_commit_id: None,
            expected_file_object_revision_id: None,
            file_object_revision_id: ObjectRevisionId::from_bytes([3; 16])?,
            root_object_revision_id: ObjectRevisionId::from_bytes([4; 16])?,
            namespace_commit_id: NamespaceCommitId::from_bytes([5; 16])?,
            path: NamespacePublicationPath::new(
                NamespacePath::from_components(["seed"], NamespaceLimits::PORTABLE)?,
                Vec::new(),
            )?,
            entry_generation: 1,
        })
    }
}
