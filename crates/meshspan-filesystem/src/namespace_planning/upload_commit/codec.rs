// SPDX-License-Identifier: GPL-2.0-only

//! Exact bounded binary storage for a prepared upload publication plan.

use meshspan_domain::{
    BranchId, ContentManifestId, FileVersionId, NamespaceCommitId, ObjectId, ObjectRevisionId,
    OperationId, PrincipalId, Revision, StageId, UnixMicros, VolumeId,
};

use crate::{
    DirectoryRevisionTransition, HandleError, NamespacePath, NamespacePublicationPath,
    RootFileCommitRequest, StageCompletionRequest,
};

const MAGIC: &[u8; 8] = b"MSUPL001";
const MAXIMUM_PLAN_BYTES: usize = 131_072;

pub(super) fn encode(plan: &RootFileCommitRequest) -> Result<Vec<u8>, HandleError> {
    let mut bytes = Vec::with_capacity(512 + plan.path.ancestors().len() * 48);
    bytes.extend_from_slice(MAGIC);
    put_id(&mut bytes, plan.completion.operation_id.as_bytes());
    put_id(&mut bytes, plan.completion.stage_id.as_bytes());
    put_u64(&mut bytes, plan.completion.stage_fence);
    put_u64(&mut bytes, plan.completion.expected_sequence);
    put_u64(&mut bytes, plan.completion.final_length);
    bytes.push(u8::from(plan.completion.sparse));
    put_i64(&mut bytes, plan.completion.observed_at.get());
    put_id(&mut bytes, plan.branch_id.as_bytes());
    put_id(&mut bytes, plan.volume_id.as_bytes());
    put_id(&mut bytes, plan.object_id.as_bytes());
    put_optional_id(
        &mut bytes,
        plan.expected_current_version_id
            .map(FileVersionId::as_bytes),
    );
    put_id(&mut bytes, plan.version_id.as_bytes());
    bytes.push(u8::from(plan.retain_superseded_history));
    put_u64(&mut bytes, plan.retention_policy_sequence);
    put_id(&mut bytes, plan.manifest_id.as_bytes());
    bytes.extend_from_slice(&plan.manifest_format_version.to_be_bytes());
    put_u64(&mut bytes, plan.content_authorization_revision.get());
    put_i64(&mut bytes, plan.content_deadline.get());
    put_id(&mut bytes, plan.root_object_id.as_bytes());
    put_optional_id(
        &mut bytes,
        plan.expected_namespace_commit_id
            .map(NamespaceCommitId::as_bytes),
    );
    put_optional_id(
        &mut bytes,
        plan.expected_file_object_revision_id
            .map(ObjectRevisionId::as_bytes),
    );
    put_id(&mut bytes, plan.file_object_revision_id.as_bytes());
    put_id(&mut bytes, plan.root_object_revision_id.as_bytes());
    put_id(&mut bytes, plan.namespace_commit_id.as_bytes());
    put_u64(&mut bytes, plan.entry_generation);
    put_id(&mut bytes, plan.created_by.as_bytes());
    put_i64(&mut bytes, plan.created_at.get());
    let count =
        u16::try_from(plan.path.ancestors().len()).map_err(|_| HandleError::InvalidInput)?;
    bytes.extend_from_slice(&count.to_be_bytes());
    for transition in plan.path.ancestors() {
        put_id(&mut bytes, transition.object_id().as_bytes());
        put_id(&mut bytes, transition.expected_revision_id().as_bytes());
        put_id(&mut bytes, transition.new_revision_id().as_bytes());
    }
    if bytes.len() > MAXIMUM_PLAN_BYTES {
        Err(HandleError::InvalidInput)
    } else {
        Ok(bytes)
    }
}

pub(super) fn decode(
    bytes: &[u8],
    path: NamespacePath,
) -> Result<RootFileCommitRequest, HandleError> {
    if bytes.len() > MAXIMUM_PLAN_BYTES {
        return Err(HandleError::Corrupt);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(8)? != MAGIC {
        return Err(HandleError::Corrupt);
    }
    let completion = StageCompletionRequest {
        operation_id: cursor.identifier(OperationId::from_bytes)?,
        stage_id: cursor.identifier(StageId::from_bytes)?,
        stage_fence: cursor.positive_u64()?,
        expected_sequence: cursor.u64()?,
        final_length: cursor.u64()?,
        sparse: cursor.boolean()?,
        observed_at: UnixMicros::new(cursor.i64()?),
    };
    let branch_id = cursor.identifier(BranchId::from_bytes)?;
    let volume_id = cursor.identifier(VolumeId::from_bytes)?;
    let object_id = cursor.identifier(ObjectId::from_bytes)?;
    let expected_current_version_id = cursor.optional_identifier(FileVersionId::from_bytes)?;
    let version_id = cursor.identifier(FileVersionId::from_bytes)?;
    let retain_superseded_history = cursor.boolean()?;
    let retention_policy_sequence = cursor.positive_u64()?;
    let manifest_id = cursor.identifier(ContentManifestId::from_bytes)?;
    let manifest_format_version = cursor.u16()?;
    if manifest_format_version == 0 {
        return Err(HandleError::Corrupt);
    }
    let content_authorization_revision = Revision::new(cursor.positive_u64()?);
    let content_deadline = UnixMicros::new(cursor.i64()?);
    let root_object_id = cursor.identifier(ObjectId::from_bytes)?;
    let expected_namespace_commit_id = cursor.optional_identifier(NamespaceCommitId::from_bytes)?;
    let expected_file_object_revision_id =
        cursor.optional_identifier(ObjectRevisionId::from_bytes)?;
    let file_object_revision_id = cursor.identifier(ObjectRevisionId::from_bytes)?;
    let root_object_revision_id = cursor.identifier(ObjectRevisionId::from_bytes)?;
    let namespace_commit_id = cursor.identifier(NamespaceCommitId::from_bytes)?;
    let entry_generation = cursor.positive_u64()?;
    let created_by = cursor.identifier(PrincipalId::from_bytes)?;
    let created_at = UnixMicros::new(cursor.i64()?);
    let count = usize::from(cursor.u16()?);
    if count != path.components().len().saturating_sub(1) {
        return Err(HandleError::Corrupt);
    }
    let ancestors = (0..count)
        .map(|_| {
            DirectoryRevisionTransition::new(
                cursor.identifier(ObjectId::from_bytes)?,
                cursor.identifier(ObjectRevisionId::from_bytes)?,
                cursor.identifier(ObjectRevisionId::from_bytes)?,
            )
            .map_err(|_| HandleError::Corrupt)
        })
        .collect::<Result<Vec<_>, HandleError>>()?;
    if !cursor.finished() {
        return Err(HandleError::Corrupt);
    }
    Ok(RootFileCommitRequest {
        completion,
        branch_id,
        volume_id,
        object_id,
        expected_current_version_id,
        version_id,
        retain_superseded_history,
        retention_policy_sequence,
        manifest_id,
        manifest_format_version,
        content_authorization_revision,
        content_deadline,
        root_object_id,
        expected_namespace_commit_id,
        expected_file_object_revision_id,
        file_object_revision_id,
        root_object_revision_id,
        namespace_commit_id,
        path: NamespacePublicationPath::new(path, ancestors).map_err(|_| HandleError::Corrupt)?,
        entry_generation,
        created_by,
        created_at,
    })
}

fn put_id(destination: &mut Vec<u8>, value: [u8; 16]) {
    destination.extend_from_slice(&value);
}

fn put_optional_id(destination: &mut Vec<u8>, value: Option<[u8; 16]>) {
    if let Some(value) = value {
        destination.push(1);
        put_id(destination, value);
    } else {
        destination.push(0);
    }
}

fn put_u64(destination: &mut Vec<u8>, value: u64) {
    destination.extend_from_slice(&value.to_be_bytes());
}

fn put_i64(destination: &mut Vec<u8>, value: i64) {
    destination.extend_from_slice(&value.to_be_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], HandleError> {
        let end = self
            .offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(HandleError::Corrupt)?;
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn identifier<T>(
        &mut self,
        constructor: impl FnOnce([u8; 16]) -> Result<T, meshspan_domain::IdentifierError>,
    ) -> Result<T, HandleError> {
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(self.take(16)?);
        constructor(bytes).map_err(|_| HandleError::Corrupt)
    }

    fn optional_identifier<T>(
        &mut self,
        constructor: impl FnOnce([u8; 16]) -> Result<T, meshspan_domain::IdentifierError>,
    ) -> Result<Option<T>, HandleError> {
        match self.take(1)?[0] {
            0 => Ok(None),
            1 => self.identifier(constructor).map(Some),
            _ => Err(HandleError::Corrupt),
        }
    }

    fn u16(&mut self) -> Result<u16, HandleError> {
        let mut bytes = [0_u8; 2];
        bytes.copy_from_slice(self.take(2)?);
        Ok(u16::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, HandleError> {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(bytes))
    }

    fn positive_u64(&mut self) -> Result<u64, HandleError> {
        match self.u64()? {
            0 => Err(HandleError::Corrupt),
            value => Ok(value),
        }
    }

    fn i64(&mut self) -> Result<i64, HandleError> {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(self.take(8)?);
        Ok(i64::from_be_bytes(bytes))
    }

    fn boolean(&mut self) -> Result<bool, HandleError> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(HandleError::Corrupt),
        }
    }

    const fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
