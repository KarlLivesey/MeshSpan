// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe daemon planning for atomic semantic file creation.

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId,
    OperationId, PrincipalId, Revision, StageId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::resolution;
use crate::{
    AdapterCreateFileRequest, CreateDisposition, DirectoryRevisionTransition,
    FilesystemAccessContext, FilesystemAdapterPolicy, FilesystemAuthorityGrant,
    FilesystemHandleCreateRequest, FilesystemHandleOpenRequest, HandleError, NamespacePath,
    NamespacePublicationPath, OpenHandleRequest, RootFileCommitRequest, StageCompletionRequest,
};

struct StoredPlan {
    request_digest: Vec<u8>,
    branch: Vec<u8>,
    volume: Vec<u8>,
    handle: Vec<u8>,
    principal: Vec<u8>,
    authorization_revision: i64,
    gateway: Vec<u8>,
    gateway_incarnation: i64,
    retain_history: i64,
    retention_sequence: i64,
    manifest_format: i64,
    creation_operation: Vec<u8>,
    object: Vec<u8>,
    version: Vec<u8>,
    manifest: Vec<u8>,
    root_object: Vec<u8>,
    expected_commit: Vec<u8>,
    file_revision: Vec<u8>,
    root_revision: Vec<u8>,
    commit: Vec<u8>,
    generation: i64,
    parent: Vec<u8>,
    created_at: i64,
    path_depth: i64,
    result_digest: Vec<u8>,
    create_disposition: i64,
    expected_existing_object: Option<Vec<u8>>,
}

struct LoadedPlan {
    request: FilesystemHandleCreateRequest,
    expected_existing_object: Option<ObjectId>,
}

#[derive(Clone, Copy)]
struct DecodedPlanHeader {
    create_disposition: CreateDisposition,
    expected_existing_object: Option<ObjectId>,
    authorization_revision: Revision,
    policy: FilesystemAdapterPolicy,
    principal: PrincipalId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileCreateAuthorityTarget {
    pub(crate) object_id: ObjectId,
    pub(crate) existing_object_id: Option<ObjectId>,
}

pub(crate) fn authority_target(
    connection: &Connection,
    branch_id: BranchId,
    context: FilesystemAccessContext,
    request: &AdapterCreateFileRequest,
) -> Result<FileCreateAuthorityTarget, HandleError> {
    validate_request(context, request)?;
    let request_digest = request_digest(branch_id, context, request);
    if let Some(plan) = load_plan(connection, branch_id, context, request, request_digest)? {
        return Ok(target_from_plan(&plan));
    }
    target_from_resolution(&resolve_current(connection, branch_id, request)?, request)
}

pub(crate) fn prepare(
    connection: &mut Connection,
    branch_id: BranchId,
    context: FilesystemAccessContext,
    request: &AdapterCreateFileRequest,
    policy: FilesystemAdapterPolicy,
    grant: FilesystemAuthorityGrant,
    expected_target: FileCreateAuthorityTarget,
) -> Result<FilesystemHandleCreateRequest, HandleError> {
    validate_request(context, request)?;
    let request_digest = request_digest(branch_id, context, request);
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(plan) = load_plan(&transaction, branch_id, context, request, request_digest)? {
        if plan.request.open.handle.principal_id == grant.principal_id
            && target_from_plan(&plan) == expected_target
        {
            return Ok(plan.request);
        }
        return Err(HandleError::OperationConflict);
    }
    reject_operation_collision(&transaction, request.operation_id)?;
    let current = resolve_current(&transaction, branch_id, request)?;
    if target_from_resolution(&current, request)? != expected_target {
        return Err(HandleError::StaleHandle);
    }
    let plan = build_plan(branch_id, context, request, policy, grant, &current)?;
    persist_plan(
        &transaction,
        request_digest,
        context,
        policy,
        &plan,
        current.parent_object,
        expected_target.existing_object_id,
    )?;
    transaction.commit()?;
    Ok(plan)
}

fn validate_request(
    context: FilesystemAccessContext,
    request: &AdapterCreateFileRequest,
) -> Result<(), HandleError> {
    let stage_shape = request.desired_access.writes() == request.maximum_stage_bytes.is_some();
    let creation_capable = matches!(
        request.create_disposition,
        CreateDisposition::CreateNew
            | CreateDisposition::OpenOrCreate
            | CreateDisposition::OverwriteOrCreate
    );
    if context.now != request.observed_at
        || context.gateway_incarnation == 0
        || context.credential_digest == [0; 32]
        || request.path.components().is_empty()
        || request.lease_expires_at <= request.observed_at
        || request.content_deadline <= request.observed_at
        || request.content_deadline > request.lease_expires_at
        || !stage_shape
        || !creation_capable
        || request.create_disposition.truncates_existing() && !request.desired_access.writes()
        || request.delete_on_close && !request.desired_access.deletes()
    {
        Err(HandleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn resolve_current(
    connection: &Connection,
    branch_id: BranchId,
    request: &AdapterCreateFileRequest,
) -> Result<resolution::ResolvedNamespacePath, HandleError> {
    resolution::resolve(connection, branch_id, request.volume_id, &request.path)
}

fn target_from_resolution(
    current: &resolution::ResolvedNamespacePath,
    request: &AdapterCreateFileRequest,
) -> Result<FileCreateAuthorityTarget, HandleError> {
    let existing_object_id = match (request.create_disposition, current.leaf) {
        (CreateDisposition::CreateNew, Some(_)) => return Err(HandleError::AlreadyExists),
        (_, Some(leaf)) if leaf.kind != crate::DirectoryEntryKind::File => {
            return Err(HandleError::AlreadyExists);
        }
        (_, Some(leaf)) if leaf.version.is_none() => return Err(HandleError::Corrupt),
        (_, Some(leaf)) => Some(leaf.object),
        (_, None) => None,
    };
    Ok(FileCreateAuthorityTarget {
        object_id: existing_object_id.unwrap_or(current.parent_object),
        existing_object_id,
    })
}

fn build_plan(
    branch_id: BranchId,
    context: FilesystemAccessContext,
    request: &AdapterCreateFileRequest,
    policy: FilesystemAdapterPolicy,
    grant: FilesystemAuthorityGrant,
    current: &resolution::ResolvedNamespacePath,
) -> Result<FilesystemHandleCreateRequest, HandleError> {
    let creation_operation = derive_operation(request.operation_id, b"creation")?;
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
    Ok(FilesystemHandleCreateRequest {
        open: FilesystemHandleOpenRequest {
            handle: OpenHandleRequest {
                operation_id: request.operation_id,
                handle_id: request.handle_id,
                branch_id,
                volume_id: request.volume_id,
                path: request.path.clone(),
                principal_id: grant.principal_id,
                authorization_revision: grant.identity_revision,
                gateway_node_id: context.gateway_node_id,
                desired_access: request.desired_access,
                share_access: request.share_access,
                create_disposition: request.create_disposition,
                delete_on_close: request.delete_on_close,
                lease_expires_at: request.lease_expires_at,
                opened_at: request.observed_at,
            },
            maximum_stage_bytes: request.maximum_stage_bytes,
        },
        initial_file: RootFileCommitRequest {
            completion: StageCompletionRequest {
                operation_id: creation_operation,
                stage_id: StageId::from_bytes(request.handle_id.as_bytes())
                    .map_err(|_| HandleError::InvalidInput)?,
                stage_fence: 1,
                expected_sequence: 0,
                final_length: 0,
                sparse: false,
                observed_at: request.observed_at,
            },
            branch_id,
            volume_id: request.volume_id,
            object_id: derive_object(request.operation_id)?,
            expected_current_version_id: None,
            version_id: derive_version(request.operation_id)?,
            retain_superseded_history: policy.retain_superseded_history,
            retention_policy_sequence: policy.retention_policy_sequence,
            manifest_id: derive_manifest(request.operation_id)?,
            manifest_format_version: policy.manifest_format_version,
            content_authorization_revision: grant.identity_revision,
            content_deadline: request.content_deadline,
            root_object_id: current.root_object,
            expected_namespace_commit_id: Some(current.namespace_commit),
            expected_file_object_revision_id: None,
            file_object_revision_id: derive_revision(request.operation_id, b"file", 0)?,
            root_object_revision_id: derive_revision(request.operation_id, b"root", 0)?,
            namespace_commit_id: derive_commit(request.operation_id)?,
            path: NamespacePublicationPath::new(request.path.clone(), ancestors)
                .map_err(|_| HandleError::InvalidInput)?,
            entry_generation: derive_generation(request.operation_id),
            created_by: grant.principal_id,
            created_at: request.observed_at,
        },
    })
}

fn persist_plan(
    transaction: &Transaction<'_>,
    request_digest: [u8; 32],
    context: FilesystemAccessContext,
    policy: FilesystemAdapterPolicy,
    plan: &FilesystemHandleCreateRequest,
    parent: ObjectId,
    expected_existing_object: Option<ObjectId>,
) -> Result<(), HandleError> {
    let open = &plan.open.handle;
    let file = &plan.initial_file;
    let result_digest = plan_digest(
        request_digest,
        context.gateway_incarnation,
        plan,
        parent,
        expected_existing_object,
    );
    transaction.execute(
        "INSERT INTO adapter_file_create_plans(
            operation_id, request_digest, branch_id, volume_id, handle_id, principal_id,
            authorization_revision, gateway_node_id, gateway_incarnation,
            retain_superseded_history, retention_policy_sequence, manifest_format_version,
            creation_operation_id, object_id, version_id, manifest_id, root_object_id,
            expected_namespace_commit_id, file_object_revision_id, root_object_revision_id,
            namespace_commit_id, entry_generation, parent_object_id, created_at, path_depth,
            result_digest, create_disposition, expected_existing_object_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                   ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
                   ?27, ?28)",
        params![
            open.operation_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            open.branch_id.as_bytes().as_slice(),
            open.volume_id.as_bytes().as_slice(),
            open.handle_id.as_bytes().as_slice(),
            open.principal_id.as_bytes().as_slice(),
            to_i64(open.authorization_revision.get())?,
            open.gateway_node_id.as_bytes().as_slice(),
            to_i64(context.gateway_incarnation)?,
            policy.retain_superseded_history,
            to_i64(policy.retention_policy_sequence)?,
            policy.manifest_format_version,
            file.completion.operation_id.as_bytes().as_slice(),
            file.object_id.as_bytes().as_slice(),
            file.version_id.as_bytes().as_slice(),
            file.manifest_id.as_bytes().as_slice(),
            file.root_object_id.as_bytes().as_slice(),
            file.expected_namespace_commit_id
                .ok_or(HandleError::Corrupt)?
                .as_bytes()
                .as_slice(),
            file.file_object_revision_id.as_bytes().as_slice(),
            file.root_object_revision_id.as_bytes().as_slice(),
            file.namespace_commit_id.as_bytes().as_slice(),
            to_i64(file.entry_generation)?,
            parent.as_bytes().as_slice(),
            file.created_at.get(),
            path_depth(&open.path)?,
            result_digest.as_slice(),
            i64::from(open.create_disposition.code()),
            expected_existing_object.map(ObjectId::as_bytes),
        ],
    )?;
    let mut statement = transaction.prepare(
        "INSERT INTO adapter_file_create_plan_ancestors(
            operation_id, ancestor_ordinal, object_id, expected_revision_id, new_revision_id
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for (ordinal, ancestor) in file.path.ancestors().iter().enumerate() {
        statement.execute(params![
            open.operation_id.as_bytes().as_slice(),
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
    context: FilesystemAccessContext,
    request: &AdapterCreateFileRequest,
    request_digest: [u8; 32],
) -> Result<Option<LoadedPlan>, HandleError> {
    let stored: Option<StoredPlan> = connection
        .query_row(
            "SELECT request_digest, branch_id, volume_id, handle_id, principal_id,
                    authorization_revision, gateway_node_id, gateway_incarnation,
                    retain_superseded_history, retention_policy_sequence, manifest_format_version,
                    creation_operation_id, object_id, version_id, manifest_id, root_object_id,
                    expected_namespace_commit_id, file_object_revision_id, root_object_revision_id,
                    namespace_commit_id, entry_generation, parent_object_id, created_at, path_depth,
                    result_digest, create_disposition, expected_existing_object_id
             FROM adapter_file_create_plans WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| {
                Ok(StoredPlan {
                    request_digest: row.get(0)?,
                    branch: row.get(1)?,
                    volume: row.get(2)?,
                    handle: row.get(3)?,
                    principal: row.get(4)?,
                    authorization_revision: row.get(5)?,
                    gateway: row.get(6)?,
                    gateway_incarnation: row.get(7)?,
                    retain_history: row.get(8)?,
                    retention_sequence: row.get(9)?,
                    manifest_format: row.get(10)?,
                    creation_operation: row.get(11)?,
                    object: row.get(12)?,
                    version: row.get(13)?,
                    manifest: row.get(14)?,
                    root_object: row.get(15)?,
                    expected_commit: row.get(16)?,
                    file_revision: row.get(17)?,
                    root_revision: row.get(18)?,
                    commit: row.get(19)?,
                    generation: row.get(20)?,
                    parent: row.get(21)?,
                    created_at: row.get(22)?,
                    path_depth: row.get(23)?,
                    result_digest: row.get(24)?,
                    create_disposition: row.get(25)?,
                    expected_existing_object: row.get(26)?,
                })
            },
        )
        .optional()?;
    stored
        .map(|stored| {
            decode_plan(
                connection,
                branch_id,
                context,
                request,
                request_digest,
                &stored,
            )
        })
        .transpose()
}

fn decode_plan(
    connection: &Connection,
    branch_id: BranchId,
    context: FilesystemAccessContext,
    request: &AdapterCreateFileRequest,
    request_digest: [u8; 32],
    stored: &StoredPlan,
) -> Result<LoadedPlan, HandleError> {
    let header = decode_plan_header(branch_id, context, request, request_digest, stored)?;
    let plan = reconstruct_plan(connection, branch_id, context, request, stored, header)?;
    let parent = identifier(&stored.parent, ObjectId::from_bytes)?;
    if stored.result_digest.as_slice()
        != plan_digest(
            request_digest,
            context.gateway_incarnation,
            &plan,
            parent,
            header.expected_existing_object,
        )
    {
        return Err(HandleError::Corrupt);
    }
    Ok(LoadedPlan {
        request: plan,
        expected_existing_object: header.expected_existing_object,
    })
}

fn decode_plan_header(
    branch_id: BranchId,
    context: FilesystemAccessContext,
    request: &AdapterCreateFileRequest,
    request_digest: [u8; 32],
    stored: &StoredPlan,
) -> Result<DecodedPlanHeader, HandleError> {
    let create_disposition = CreateDisposition::from_code(
        u8::try_from(stored.create_disposition).map_err(|_| HandleError::Corrupt)?,
    )?;
    let expected_existing_object = stored
        .expected_existing_object
        .as_deref()
        .map(|value| identifier(value, ObjectId::from_bytes))
        .transpose()?;
    if stored.request_digest.as_slice() != request_digest
        || stored.branch.as_slice() != branch_id.as_bytes()
        || stored.volume.as_slice() != request.volume_id.as_bytes()
        || stored.handle.as_slice() != request.handle_id.as_bytes()
        || stored.gateway.as_slice() != context.gateway_node_id.as_bytes()
        || positive(stored.gateway_incarnation)? != context.gateway_incarnation
        || stored.created_at != request.observed_at.get()
        || usize::try_from(stored.path_depth) != Ok(request.path.components().len())
        || create_disposition != request.create_disposition
        || create_disposition == CreateDisposition::CreateNew && expected_existing_object.is_some()
    {
        return Err(HandleError::OperationConflict);
    }
    let authorization_revision = revision(stored.authorization_revision)?;
    let policy = FilesystemAdapterPolicy {
        retain_superseded_history: decode_bool(stored.retain_history)?,
        retention_policy_sequence: positive(stored.retention_sequence)?,
        manifest_format_version: u16::try_from(stored.manifest_format)
            .map_err(|_| HandleError::Corrupt)?,
    };
    let principal = identifier(&stored.principal, PrincipalId::from_bytes)?;
    Ok(DecodedPlanHeader {
        create_disposition,
        expected_existing_object,
        authorization_revision,
        policy,
        principal,
    })
}

fn reconstruct_plan(
    connection: &Connection,
    branch_id: BranchId,
    context: FilesystemAccessContext,
    request: &AdapterCreateFileRequest,
    stored: &StoredPlan,
    header: DecodedPlanHeader,
) -> Result<FilesystemHandleCreateRequest, HandleError> {
    Ok(FilesystemHandleCreateRequest {
        open: FilesystemHandleOpenRequest {
            handle: OpenHandleRequest {
                operation_id: request.operation_id,
                handle_id: request.handle_id,
                branch_id,
                volume_id: request.volume_id,
                path: request.path.clone(),
                principal_id: header.principal,
                authorization_revision: header.authorization_revision,
                gateway_node_id: context.gateway_node_id,
                desired_access: request.desired_access,
                share_access: request.share_access,
                create_disposition: header.create_disposition,
                delete_on_close: request.delete_on_close,
                lease_expires_at: request.lease_expires_at,
                opened_at: request.observed_at,
            },
            maximum_stage_bytes: request.maximum_stage_bytes,
        },
        initial_file: RootFileCommitRequest {
            completion: StageCompletionRequest {
                operation_id: identifier(&stored.creation_operation, OperationId::from_bytes)?,
                stage_id: StageId::from_bytes(request.handle_id.as_bytes())
                    .map_err(|_| HandleError::Corrupt)?,
                stage_fence: 1,
                expected_sequence: 0,
                final_length: 0,
                sparse: false,
                observed_at: request.observed_at,
            },
            branch_id,
            volume_id: request.volume_id,
            object_id: identifier(&stored.object, ObjectId::from_bytes)?,
            expected_current_version_id: None,
            version_id: identifier(&stored.version, FileVersionId::from_bytes)?,
            retain_superseded_history: header.policy.retain_superseded_history,
            retention_policy_sequence: header.policy.retention_policy_sequence,
            manifest_id: identifier(&stored.manifest, ContentManifestId::from_bytes)?,
            manifest_format_version: header.policy.manifest_format_version,
            content_authorization_revision: header.authorization_revision,
            content_deadline: request.content_deadline,
            root_object_id: identifier(&stored.root_object, ObjectId::from_bytes)?,
            expected_namespace_commit_id: Some(identifier(
                &stored.expected_commit,
                NamespaceCommitId::from_bytes,
            )?),
            expected_file_object_revision_id: None,
            file_object_revision_id: identifier(
                &stored.file_revision,
                ObjectRevisionId::from_bytes,
            )?,
            root_object_revision_id: identifier(
                &stored.root_revision,
                ObjectRevisionId::from_bytes,
            )?,
            namespace_commit_id: identifier(&stored.commit, NamespaceCommitId::from_bytes)?,
            path: NamespacePublicationPath::new(
                request.path.clone(),
                load_ancestors(
                    connection,
                    request.operation_id,
                    request.path.components().len(),
                )?,
            )
            .map_err(|_| HandleError::Corrupt)?,
            entry_generation: positive(stored.generation)?,
            created_by: header.principal,
            created_at: request.observed_at,
        },
    })
}

fn load_ancestors(
    connection: &Connection,
    operation_id: OperationId,
    path_depth: usize,
) -> Result<Vec<DirectoryRevisionTransition>, HandleError> {
    let expected = path_depth.checked_sub(1).ok_or(HandleError::Corrupt)?;
    let mut statement = connection.prepare(
        "SELECT ancestor_ordinal, object_id, expected_revision_id, new_revision_id
         FROM adapter_file_create_plan_ancestors
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
          OR EXISTS(SELECT 1 FROM namespace_rename_operations WHERE operation_id = ?1)
          OR EXISTS(SELECT 1 FROM namespace_unlink_operations WHERE operation_id = ?1)
          OR EXISTS(SELECT 1 FROM adapter_directory_plans WHERE operation_id = ?1)
          OR EXISTS(SELECT 1 FROM adapter_unlink_plans WHERE operation_id = ?1)
          OR EXISTS(SELECT 1 FROM adapter_rename_plans WHERE operation_id = ?1)
          OR EXISTS(SELECT 1 FROM handle_mutation_operations WHERE operation_id = ?1)",
        [operation_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if collision == 0 {
        Ok(())
    } else {
        Err(HandleError::OperationConflict)
    }
}

fn request_digest(
    branch_id: BranchId,
    context: FilesystemAccessContext,
    request: &AdapterCreateFileRequest,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    if request.create_disposition == CreateDisposition::CreateNew {
        digest.update(b"meshspan.filesystem.adapter-create-file-request.v1\0");
    } else {
        digest.update(b"meshspan.filesystem.adapter-create-file-request.v2\0");
        digest.update(&[request.create_disposition.code()]);
    }
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.handle_id.as_bytes());
    digest.update(&branch_id.as_bytes());
    digest.update(&request.volume_id.as_bytes());
    update_path(&mut digest, &request.path);
    digest.update(&access_bytes(request));
    digest.update(&share_bytes(request));
    digest.update(&[u8::from(request.delete_on_close)]);
    update_optional_u64(&mut digest, request.maximum_stage_bytes);
    digest.update(&request.lease_expires_at.get().to_be_bytes());
    digest.update(&request.content_deadline.get().to_be_bytes());
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.update(&context.gateway_node_id.as_bytes());
    digest.update(&context.gateway_incarnation.to_be_bytes());
    digest.finalize().into()
}

fn plan_digest(
    request_digest: [u8; 32],
    gateway_incarnation: u64,
    plan: &FilesystemHandleCreateRequest,
    parent: ObjectId,
    expected_existing_object: Option<ObjectId>,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.adapter-create-file-plan.v1\0");
    digest.update(&request_digest);
    digest.update(&plan.open.handle.principal_id.as_bytes());
    digest.update(&plan.open.handle.authorization_revision.get().to_be_bytes());
    digest.update(&gateway_incarnation.to_be_bytes());
    let file = &plan.initial_file;
    digest.update(&file.completion.operation_id.as_bytes());
    digest.update(&file.object_id.as_bytes());
    digest.update(&file.version_id.as_bytes());
    digest.update(&file.manifest_id.as_bytes());
    digest.update(&[u8::from(file.retain_superseded_history)]);
    digest.update(&file.retention_policy_sequence.to_be_bytes());
    digest.update(&file.manifest_format_version.to_be_bytes());
    digest.update(&file.root_object_id.as_bytes());
    digest.update(
        &file
            .expected_namespace_commit_id
            .map_or([0; 16], NamespaceCommitId::as_bytes),
    );
    digest.update(&file.file_object_revision_id.as_bytes());
    digest.update(&file.root_object_revision_id.as_bytes());
    digest.update(&file.namespace_commit_id.as_bytes());
    digest.update(&file.entry_generation.to_be_bytes());
    digest.update(&parent.as_bytes());
    if plan.open.handle.create_disposition != CreateDisposition::CreateNew {
        digest.update(&expected_existing_object.map_or([0; 16], ObjectId::as_bytes));
    }
    update_transitions(&mut digest, file.path.ancestors());
    digest.finalize().into()
}

fn publication_parent(file: &RootFileCommitRequest) -> ObjectId {
    file.path
        .ancestors()
        .last()
        .map_or(file.root_object_id, |value| value.object_id())
}

fn target_from_plan(plan: &LoadedPlan) -> FileCreateAuthorityTarget {
    FileCreateAuthorityTarget {
        object_id: plan
            .expected_existing_object
            .unwrap_or_else(|| publication_parent(&plan.request.initial_file)),
        existing_object_id: plan.expected_existing_object,
    }
}

fn access_bytes(request: &AdapterCreateFileRequest) -> [u8; 3] {
    [
        u8::from(request.desired_access.reads()),
        u8::from(request.desired_access.writes()),
        u8::from(request.desired_access.deletes()),
    ]
}

fn share_bytes(request: &AdapterCreateFileRequest) -> [u8; 3] {
    [
        u8::from(request.share_access.permits_read()),
        u8::from(request.share_access.permits_write()),
        u8::from(request.share_access.permits_delete()),
    ]
}

fn derive_operation(operation_id: OperationId, purpose: &[u8]) -> Result<OperationId, HandleError> {
    OperationId::from_bytes(derive(operation_id, purpose, 0)).map_err(|_| HandleError::InvalidInput)
}
fn derive_object(id: OperationId) -> Result<ObjectId, HandleError> {
    ObjectId::from_bytes(derive(id, b"object", 0)).map_err(|_| HandleError::InvalidInput)
}
fn derive_version(id: OperationId) -> Result<FileVersionId, HandleError> {
    FileVersionId::from_bytes(derive(id, b"version", 0)).map_err(|_| HandleError::InvalidInput)
}
fn derive_manifest(id: OperationId) -> Result<ContentManifestId, HandleError> {
    ContentManifestId::from_bytes(derive(id, b"manifest", 0)).map_err(|_| HandleError::InvalidInput)
}
fn derive_commit(id: OperationId) -> Result<NamespaceCommitId, HandleError> {
    NamespaceCommitId::from_bytes(derive(id, b"commit", 0)).map_err(|_| HandleError::InvalidInput)
}
fn derive_revision(
    id: OperationId,
    purpose: &[u8],
    ordinal: usize,
) -> Result<ObjectRevisionId, HandleError> {
    ObjectRevisionId::from_bytes(derive(
        id,
        purpose,
        u64::try_from(ordinal).map_err(|_| HandleError::InvalidInput)?,
    ))
    .map_err(|_| HandleError::InvalidInput)
}
fn derive_generation(id: OperationId) -> u64 {
    let bytes = derive(id, b"generation", 0);
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[..8]);
    (u64::from_be_bytes(value) & i64::MAX as u64).max(1)
}
fn derive(id: OperationId, purpose: &[u8], ordinal: u64) -> [u8; 16] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.adapter-create-file-identity.v1\0");
    digest.update(&id.as_bytes());
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

fn update_path(digest: &mut blake3::Hasher, path: &NamespacePath) {
    digest.update(&(path.components().len() as u64).to_be_bytes());
    for value in path.components() {
        update_text(digest, value.display());
        update_text(digest, value.canonical());
    }
}
fn update_text(digest: &mut blake3::Hasher, value: &str) {
    digest.update(&(value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}
fn update_optional_u64(digest: &mut blake3::Hasher, value: Option<u64>) {
    digest.update(&[u8::from(value.is_some())]);
    if let Some(value) = value {
        digest.update(&value.to_be_bytes());
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
fn decode_bool(value: i64) -> Result<bool, HandleError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(HandleError::Corrupt),
    }
}
fn revision(value: i64) -> Result<Revision, HandleError> {
    let value = positive(value)?;
    let revision = Revision::new(value);
    if revision == Revision::ZERO {
        Err(HandleError::Corrupt)
    } else {
        Ok(revision)
    }
}
fn positive(value: i64) -> Result<u64, HandleError> {
    let value = u64::try_from(value).map_err(|_| HandleError::Corrupt)?;
    if value == 0 {
        Err(HandleError::Corrupt)
    } else {
        Ok(value)
    }
}
fn path_depth(path: &NamespacePath) -> Result<i64, HandleError> {
    i64::try_from(path.components().len()).map_err(|_| HandleError::InvalidInput)
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
