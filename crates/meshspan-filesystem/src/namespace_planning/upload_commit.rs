// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe planning for atomic resumable-upload publication.

#[path = "upload_commit/codec.rs"]
mod codec;

use meshspan_domain::{BranchId, ObjectId, ObjectRevisionId, OperationId};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::resolution;
use crate::{
    AdapterUploadCommitRequest, DirectoryEntryKind, DirectoryRevisionTransition,
    FilesystemAdapterPolicy, FilesystemAuthorityGrant, HandleError, NamespacePublicationPath,
    RootFileCommitRequest, StageCompletionRequest, UploadDisposition, UploadSession,
};

pub(crate) fn prepare(
    connection: &mut Connection,
    branch_id: BranchId,
    session: &UploadSession,
    request: AdapterUploadCommitRequest,
    policy: FilesystemAdapterPolicy,
    grant: FilesystemAuthorityGrant,
) -> Result<RootFileCommitRequest, HandleError> {
    validate(branch_id, session, request, policy, grant)?;
    let request_digest = request_digest(branch_id, session, request, policy, grant);
    if let Some(plan) = load(connection, session, request, request_digest)? {
        return Ok(plan);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(plan) = load(&transaction, session, request, request_digest)? {
        return Ok(plan);
    }
    reject_collision(&transaction, session, request.operation_id)?;
    let current = resolution::resolve_or_initial(
        &transaction,
        branch_id,
        session.volume_id,
        &session.path,
        grant.object_id,
    )?;
    let plan = build(branch_id, session, request, policy, grant, &current)?;
    let encoded = codec::encode(&plan)?;
    let result_digest = result_digest(request_digest, &encoded);
    transaction.execute(
        "INSERT INTO upload_publication_plans(
            operation_id, upload_id, request_digest, encoded_plan, result_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            request.operation_id.as_bytes().as_slice(),
            session.upload_id.as_bytes().as_slice(),
            request_digest.as_slice(),
            encoded,
            result_digest.as_slice(),
        ],
    )?;
    transaction.commit()?;
    Ok(plan)
}

fn validate(
    branch_id: BranchId,
    session: &UploadSession,
    request: AdapterUploadCommitRequest,
    policy: FilesystemAdapterPolicy,
    grant: FilesystemAuthorityGrant,
) -> Result<(), HandleError> {
    if request.upload_id != session.upload_id
        || request.stage_fence == 0
        || request.final_length > session.maximum_bytes
        || request.observed_at >= session.expires_at
        || request.content_deadline <= request.observed_at
        || grant.principal_id != session.principal_id
        || grant.volume_id != session.volume_id
        || grant.object_id != session.authority_object_id
        || grant.identity_revision == meshspan_domain::Revision::ZERO
        || grant.expires_at <= request.observed_at
        || policy.retention_policy_sequence == 0
        || policy.manifest_format_version == 0
        || branch_id.as_bytes() == [0; 16]
    {
        Err(HandleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn build(
    branch_id: BranchId,
    session: &UploadSession,
    request: AdapterUploadCommitRequest,
    policy: FilesystemAdapterPolicy,
    grant: FilesystemAuthorityGrant,
    current: &resolution::ResolvedNamespacePath,
) -> Result<RootFileCommitRequest, HandleError> {
    let target = resolve_target(session, current)?;
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
    Ok(RootFileCommitRequest {
        completion: StageCompletionRequest {
            operation_id: request.operation_id,
            stage_id: session.stage_id,
            stage_fence: request.stage_fence,
            expected_sequence: request.expected_sequence,
            final_length: request.final_length,
            sparse: request.sparse,
            observed_at: request.observed_at,
        },
        branch_id,
        volume_id: session.volume_id,
        object_id: target.object_id,
        expected_current_version_id: target.expected_version,
        version_id: derive_identifier(request.operation_id, b"version", 0, |bytes| {
            meshspan_domain::FileVersionId::from_bytes(bytes)
        })?,
        retain_superseded_history: policy.retain_superseded_history,
        retention_policy_sequence: policy.retention_policy_sequence,
        manifest_id: derive_identifier(request.operation_id, b"manifest", 0, |bytes| {
            meshspan_domain::ContentManifestId::from_bytes(bytes)
        })?,
        manifest_format_version: policy.manifest_format_version,
        content_authorization_revision: grant.identity_revision,
        content_deadline: request.content_deadline,
        root_object_id: current.root_object,
        expected_namespace_commit_id: current.namespace_commit,
        expected_file_object_revision_id: target.expected_revision,
        file_object_revision_id: derive_revision(request.operation_id, b"file", 0)?,
        root_object_revision_id: derive_revision(request.operation_id, b"root", 0)?,
        namespace_commit_id: derive_identifier(request.operation_id, b"commit", 0, |bytes| {
            meshspan_domain::NamespaceCommitId::from_bytes(bytes)
        })?,
        path: NamespacePublicationPath::new(session.path.clone(), ancestors)
            .map_err(|_| HandleError::InvalidInput)?,
        entry_generation: target.entry_generation,
        created_by: grant.principal_id,
        created_at: request.observed_at,
    })
}

#[derive(Clone, Copy)]
struct PublicationTarget {
    object_id: ObjectId,
    expected_version: Option<meshspan_domain::FileVersionId>,
    expected_revision: Option<ObjectRevisionId>,
    entry_generation: u64,
}

fn resolve_target(
    session: &UploadSession,
    current: &resolution::ResolvedNamespacePath,
) -> Result<PublicationTarget, HandleError> {
    match (session.disposition, current.leaf) {
        (UploadDisposition::CreateNew, None)
            if current.parent_object == session.authority_object_id =>
        {
            Ok(PublicationTarget {
                object_id: derive_identifier(
                    session.begin_operation_id,
                    b"object",
                    0,
                    ObjectId::from_bytes,
                )?,
                expected_version: None,
                expected_revision: None,
                entry_generation: derive_generation(session.begin_operation_id),
            })
        }
        (UploadDisposition::CreateNew, _) => Err(HandleError::AlreadyExists),
        (_, None) => Err(HandleError::NotFound),
        (_, Some(leaf)) if leaf.kind != DirectoryEntryKind::File => Err(HandleError::NotFound),
        (_, Some(leaf)) if leaf.object != session.authority_object_id => {
            Err(HandleError::StaleHandle)
        }
        (UploadDisposition::ReplaceIfVersion(expected), Some(leaf))
            if leaf.version != Some(expected) =>
        {
            Err(HandleError::StaleHandle)
        }
        (_, Some(leaf)) => Ok(PublicationTarget {
            object_id: leaf.object,
            expected_version: Some(leaf.version.ok_or(HandleError::Corrupt)?),
            expected_revision: Some(leaf.revision),
            entry_generation: leaf.generation,
        }),
    }
}

fn load(
    connection: &Connection,
    session: &UploadSession,
    request: AdapterUploadCommitRequest,
    request_digest: [u8; 32],
) -> Result<Option<RootFileCommitRequest>, HandleError> {
    type Stored = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    let stored: Option<Stored> = connection
        .query_row(
            "SELECT upload_id, request_digest, encoded_plan, result_digest
             FROM upload_publication_plans WHERE operation_id = ?1",
            [request.operation_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((upload, digest, encoded, result)) = stored else {
        return Ok(None);
    };
    if upload.as_slice() != session.upload_id.as_bytes()
        || digest.as_slice() != request_digest
        || result.as_slice() != result_digest(request_digest, &encoded)
    {
        return Err(HandleError::OperationConflict);
    }
    codec::decode(&encoded, session.path.clone()).map(Some)
}

fn reject_collision(
    connection: &Connection,
    session: &UploadSession,
    operation_id: OperationId,
) -> Result<(), HandleError> {
    let collision: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM upload_publication_plans WHERE upload_id = ?1)
          OR EXISTS(SELECT 1 FROM namespace_publication_operations WHERE operation_id = ?2)
          OR EXISTS(SELECT 1 FROM handle_mutation_operations WHERE operation_id = ?2)
          OR EXISTS(SELECT 1 FROM namespace_rename_operations WHERE operation_id = ?2)
          OR EXISTS(SELECT 1 FROM namespace_unlink_operations WHERE operation_id = ?2)",
        params![
            session.upload_id.as_bytes().as_slice(),
            operation_id.as_bytes().as_slice()
        ],
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
    session: &UploadSession,
    request: AdapterUploadCommitRequest,
    policy: FilesystemAdapterPolicy,
    grant: FilesystemAuthorityGrant,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.upload-publication-plan.v1\0");
    digest.update(&branch_id.as_bytes());
    digest.update(&session.upload_id.as_bytes());
    digest.update(&session.stage_id.as_bytes());
    digest.update(&session.authority_object_id.as_bytes());
    digest.update(&request.operation_id.as_bytes());
    digest.update(&request.stage_fence.to_be_bytes());
    digest.update(&request.expected_sequence.to_be_bytes());
    digest.update(&request.final_length.to_be_bytes());
    digest.update(&[u8::from(request.sparse)]);
    if let Some(expected) = request.expected_content_digest {
        digest.update(&[1]);
        digest.update(&expected);
    } else {
        digest.update(&[0]);
    }
    digest.update(&request.content_deadline.get().to_be_bytes());
    digest.update(&request.observed_at.get().to_be_bytes());
    digest.update(&[u8::from(policy.retain_superseded_history)]);
    digest.update(&policy.retention_policy_sequence.to_be_bytes());
    digest.update(&policy.manifest_format_version.to_be_bytes());
    digest.update(&grant.principal_id.as_bytes());
    digest.update(&grant.identity_revision.get().to_be_bytes());
    digest.finalize().into()
}

fn result_digest(request_digest: [u8; 32], encoded: &[u8]) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.upload-publication-result.v1\0");
    digest.update(&request_digest);
    digest.update(encoded);
    digest.finalize().into()
}

fn derive_revision(
    operation_id: OperationId,
    purpose: &[u8],
    ordinal: usize,
) -> Result<ObjectRevisionId, HandleError> {
    derive_identifier(
        operation_id,
        purpose,
        u64::try_from(ordinal).map_err(|_| HandleError::InvalidInput)?,
        ObjectRevisionId::from_bytes,
    )
}

fn derive_identifier<T>(
    operation_id: OperationId,
    purpose: &[u8],
    ordinal: u64,
    constructor: impl FnOnce([u8; 16]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, HandleError> {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.upload-publication-identity.v1\0");
    digest.update(&operation_id.as_bytes());
    digest.update(&(purpose.len() as u64).to_be_bytes());
    digest.update(purpose);
    digest.update(&ordinal.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    constructor(meshspan_domain::uuid_v8(bytes)).map_err(|_| HandleError::InvalidInput)
}

fn derive_generation(operation_id: OperationId) -> u64 {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.upload-publication-generation.v1\0");
    digest.update(&operation_id.as_bytes());
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest.finalize().as_bytes()[..8]);
    super::entry_generation_from_hash(bytes)
}
