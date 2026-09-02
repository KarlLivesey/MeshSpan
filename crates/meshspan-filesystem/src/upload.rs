// SPDX-License-Identifier: GPL-2.0-only

//! Protocol-neutral resumable upload identities and lifecycle contracts.

use meshspan_contracts::BoundedBytes;
use meshspan_domain::{
    FileVersionId, ObjectId, OperationId, PrincipalId, Revision, StageId, UnixMicros, UploadId,
    VolumeId,
};
use std::ops::Range;

use crate::{
    Checkpoint, NamespacePath, NamespacePublicationReceipt, RootFileCommitRequest, StageWrite,
    StageWriteOutcome,
};

/// Connector-supplied upload creation intent before current authority is resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterUploadBeginRequest {
    /// Stable client idempotency identity.
    pub operation_id: OperationId,
    /// Deterministic opaque upload identity derived from the operation.
    pub upload_id: UploadId,
    /// Deterministic private stage identity distinct from the upload identity.
    pub stage_id: StageId,
    /// Selected logical volume.
    pub volume_id: VolumeId,
    /// Canonical destination path.
    pub path: NamespacePath,
    /// Final namespace precondition.
    pub disposition: UploadDisposition,
    /// Hard logical-byte ceiling.
    pub maximum_bytes: u64,
    /// Exclusive upload expiry.
    pub expires_at: UnixMicros,
    /// Authoritative creation instant.
    pub observed_at: UnixMicros,
}

/// Connector-supplied upload write before current authority is resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterUploadWriteRequest {
    /// Selected upload.
    pub upload_id: UploadId,
    /// Independently idempotent range operation.
    pub operation_id: OperationId,
    /// Exact writer fence.
    pub stage_fence: u64,
    /// First replaced logical byte.
    pub offset: u64,
    /// Already bounded hostile bytes.
    pub bytes: BoundedBytes,
    /// Caller-declared BLAKE3 digest independently verified by the stage.
    pub digest: [u8; 32],
    /// Authoritative attempt instant.
    pub observed_at: UnixMicros,
}

/// Connector-supplied upload-state query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterUploadStatusRequest {
    /// Selected upload.
    pub upload_id: UploadId,
    /// Authoritative query instant.
    pub observed_at: UnixMicros,
}

/// Connector-supplied bounded upload-range query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterUploadRangePageRequest {
    /// Selected upload.
    pub upload_id: UploadId,
    /// Exact pinned checkpoint on continuation pages.
    pub expected_sequence: Option<u64>,
    /// Exclusive prior range start.
    pub after_start: Option<u64>,
    /// Positive page bound.
    pub limit: u16,
    /// Authoritative query instant.
    pub observed_at: UnixMicros,
}

/// Connector-supplied upload abandonment intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterUploadAbortRequest {
    /// Stable client idempotency identity.
    pub operation_id: OperationId,
    /// Selected upload.
    pub upload_id: UploadId,
    /// Exact writer fence.
    pub stage_fence: u64,
    /// Authoritative attempt instant.
    pub observed_at: UnixMicros,
}

/// Connector-supplied exact publication barrier for one upload checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterUploadCommitRequest {
    /// Stable publication operation identity.
    pub operation_id: OperationId,
    /// Selected upload.
    pub upload_id: UploadId,
    /// Exact writer fence.
    pub stage_fence: u64,
    /// Exact selected checkpoint sequence.
    pub expected_sequence: u64,
    /// Exact logical file length.
    pub final_length: u64,
    /// Whether uncovered ranges are intentional logical zeroes.
    pub sparse: bool,
    /// Optional independently verified complete-content digest.
    pub expected_content_digest: Option<[u8; 32]>,
    /// Exclusive deadline for new content-provider work.
    pub content_deadline: UnixMicros,
    /// Authoritative publication instant.
    pub observed_at: UnixMicros,
}

/// Namespace precondition applied when an upload is eventually published.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadDisposition {
    /// Publication succeeds only when the destination does not exist.
    CreateNew,
    /// Publication replaces exactly one immutable current version.
    ReplaceIfVersion(FileVersionId),
    /// Publication replaces whichever version is current at commit time.
    ReplaceCurrent,
}

impl UploadDisposition {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::CreateNew => 1,
            Self::ReplaceIfVersion(_) => 2,
            Self::ReplaceCurrent => 3,
        }
    }

    pub(crate) const fn expected_version(self) -> Option<FileVersionId> {
        match self {
            Self::ReplaceIfVersion(version) => Some(version),
            Self::CreateNew | Self::ReplaceCurrent => None,
        }
    }
}

/// Complete durable intent for one private resumable upload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadBeginRequest {
    /// Stable idempotency identity for session creation.
    pub operation_id: OperationId,
    /// Opaque public upload identity.
    pub upload_id: UploadId,
    /// Private write-stage identity, independently derived from the upload identity.
    pub stage_id: StageId,
    /// Logical volume containing the destination.
    pub volume_id: VolumeId,
    /// Stable destination object or parent against which every operation is reauthorised.
    pub authority_object_id: ObjectId,
    /// Canonical bounded logical destination path.
    pub path: NamespacePath,
    /// Authenticated principal creating the upload.
    pub principal_id: PrincipalId,
    /// Exact permission revision admitted at creation.
    pub authorization_revision: Revision,
    /// Destination publication precondition.
    pub disposition: UploadDisposition,
    /// Hard maximum logical bytes reserved for this upload.
    pub maximum_bytes: u64,
    /// Session creation instant.
    pub created_at: UnixMicros,
    /// Exclusive inactivity/authority deadline.
    pub expires_at: UnixMicros,
}

/// Public durable lifecycle state of a resumable upload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadState {
    /// The private stage exists and accepts correctly fenced writes.
    Active,
    /// Publication has started and no further ranges are accepted.
    Committing,
    /// Exact immutable content and namespace publication completed.
    Committed,
    /// The upload was abandoned and can never publish.
    Aborted,
}

/// Durable upload identity and authority returned to connector implementations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadSession {
    /// Stable idempotency identity that created this session.
    pub begin_operation_id: OperationId,
    /// Opaque upload identity.
    pub upload_id: UploadId,
    /// Private stage identity.
    pub stage_id: StageId,
    /// Current positive writer fence.
    pub stage_fence: u64,
    /// Logical volume containing the destination.
    pub volume_id: VolumeId,
    /// Stable destination object or parent selected when the upload began.
    pub authority_object_id: ObjectId,
    /// Canonical destination path.
    pub path: NamespacePath,
    /// Principal owning this upload session.
    pub principal_id: PrincipalId,
    /// Exact permission revision admitted at creation.
    pub authorization_revision: Revision,
    /// Publication precondition.
    pub disposition: UploadDisposition,
    /// Hard logical-byte ceiling.
    pub maximum_bytes: u64,
    /// Current durable lifecycle state.
    pub state: UploadState,
    /// Creation instant.
    pub created_at: UnixMicros,
    /// Exclusive session deadline.
    pub expires_at: UnixMicros,
    /// Stable namespace object published by a completed upload.
    pub committed_object_id: Option<ObjectId>,
    /// Immutable file version published by a completed upload.
    pub committed_version_id: Option<FileVersionId>,
}

/// One independently idempotent bounded range write to a private upload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadWriteRequest {
    /// Upload receiving the private bytes.
    pub upload_id: UploadId,
    /// Authenticated principal; an upload identifier alone never grants authority.
    pub principal_id: PrincipalId,
    /// Currently revalidated permission revision.
    pub authorization_revision: Revision,
    /// Exact immutable range operation.
    pub operation_id: OperationId,
    /// Current upload fence.
    pub stage_fence: u64,
    /// First logical byte replaced by this range.
    pub offset: u64,
    /// Already bounded hostile input.
    pub bytes: BoundedBytes,
    /// Caller-supplied digest, independently verified by the stage service.
    pub digest: [u8; 32],
    /// Authoritative attempt instant.
    pub observed_at: UnixMicros,
}

impl UploadWriteRequest {
    pub(crate) fn stage_write(&self) -> StageWrite {
        StageWrite {
            operation_id: self.operation_id,
            stage_fence: self.stage_fence,
            offset: self.offset,
            bytes: self.bytes.clone(),
            digest: self.digest,
        }
    }
}

/// Durable range-write outcome and exact resumable checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadWriteReceipt {
    /// Whether bytes were applied or an exact retry was resolved.
    pub outcome: StageWriteOutcome,
    /// Exact checkpoint after the write.
    pub checkpoint: Checkpoint,
}

/// Authorised query for resumable upload state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadStatusRequest {
    /// Upload being queried.
    pub upload_id: UploadId,
    /// Authenticated owning principal.
    pub principal_id: PrincipalId,
    /// Currently revalidated permission revision.
    pub authorization_revision: Revision,
    /// Authoritative query instant.
    pub observed_at: UnixMicros,
}

/// Exact durable lifecycle and range coverage needed to resume an upload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadStatusReceipt {
    /// Durable upload identity, destination and lifecycle state.
    pub session: UploadSession,
    /// Exact sorted range coverage and current mutation sequence.
    pub checkpoint: Checkpoint,
}

/// Authorised bounded query over one upload's exact range index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadRangePageRequest {
    /// Upload being queried.
    pub upload_id: UploadId,
    /// Authenticated owning principal.
    pub principal_id: PrincipalId,
    /// Currently revalidated permission revision.
    pub authorization_revision: Revision,
    /// First page omits this; continuations pin the returned exact checkpoint.
    pub expected_sequence: Option<u64>,
    /// Exclusive start continuation returned by the preceding page.
    pub after_start: Option<u64>,
    /// Positive page bound no larger than 256.
    pub limit: u16,
    /// Authoritative query instant.
    pub observed_at: UnixMicros,
}

/// One bounded page of exact merged range coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadRangePageReceipt {
    /// Selected upload.
    pub upload_id: UploadId,
    /// Exact checkpoint represented by every page in this traversal.
    pub checkpoint_sequence: u64,
    /// Sorted, non-overlapping, non-adjacent coverage.
    pub ranges: Vec<Range<u64>>,
    /// Start of the last returned range, or none at the end.
    pub next_after_start: Option<u64>,
}

/// Explicit atomic publication of one complete private upload checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadCommitRequest {
    /// Stable publication operation identity.
    pub operation_id: OperationId,
    /// Upload whose private bytes are selected.
    pub upload_id: UploadId,
    /// Authenticated owning principal.
    pub principal_id: PrincipalId,
    /// Currently revalidated permission revision.
    pub authorization_revision: Revision,
    /// Exact current upload fence.
    pub stage_fence: u64,
    /// Exact checkpoint selected; later writes make the request stale.
    pub expected_sequence: u64,
    /// Exact resulting logical length.
    pub final_length: u64,
    /// Whether uncovered ranges are explicit logical zeroes.
    pub sparse: bool,
    /// Optional independently verified BLAKE3 digest of the complete logical byte stream.
    pub expected_content_digest: Option<[u8; 32]>,
    /// Complete pre-authorised namespace and immutable-content plan.
    pub publication: RootFileCommitRequest,
    /// Authoritative commit instant.
    pub observed_at: UnixMicros,
}

/// Durable result of one atomic upload publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadCommitReceipt {
    /// Terminal upload state with published object/version identities.
    pub session: UploadSession,
    /// Exact namespace publication receipt, applied or replayed.
    pub publication: NamespacePublicationReceipt,
    /// Immutable receipt evidence and honest durability scope for this successful publication.
    pub acknowledgement: crate::PublicationAcknowledgement,
}

/// Idempotent request to abandon one unpublished upload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadAbortRequest {
    /// Stable abort operation identity.
    pub operation_id: OperationId,
    /// Upload being abandoned.
    pub upload_id: UploadId,
    /// Authenticated owning principal.
    pub principal_id: PrincipalId,
    /// Currently revalidated permission revision.
    pub authorization_revision: Revision,
    /// Current upload fence.
    pub stage_fence: u64,
    /// Authoritative attempt instant.
    pub observed_at: UnixMicros,
}
