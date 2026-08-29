// SPDX-License-Identifier: GPL-2.0-only

//! Protocol-neutral namespace, staging, permissions and copy-on-write filesystem semantics.

mod cleanup_cancellation;
mod cleanup_fence;
mod cleanup_retirement;
mod commit_service;
mod content_catalog;
mod content_crypto;
mod content_key;
mod content_publisher;
mod content_reader;
mod directory;
mod handle_io;
mod handles;
mod name;
mod publication;
mod reachability;
mod reconciliation;
mod stage_store;
mod staging;
mod version_retention;

pub use cleanup_cancellation::{
    VersionCleanupCancellationAuthority, VersionCleanupCancellationError,
    VersionCleanupCancellationReceipt,
};
pub use cleanup_retirement::{
    VersionCleanupRetirementAuthority, VersionCleanupRetirementError,
    VersionCleanupRetirementReceipt,
};
pub use commit_service::{
    ContentPublicationError, ContentPublicationRequest, DurableContentPublisher,
    FilesystemCommitError, FilesystemCommitService, RootFileCommitRequest,
};
pub use content_catalog::{
    CommittedShardInventory, CommittedShardPage, ContentCatalogError, DurableContentCatalog,
    PendingContentChunkPage, PreparedContentChunk, PreparedContentLayout,
};
pub use content_crypto::{
    ContentChunkCipher, ContentChunkLimits, ContentCryptoError, ContentEncryptionKey,
    EncryptedContentChunk,
};
pub use content_key::{
    ContentKeyEnvelopeCipher, ContentKeyError, VolumeKeyEncryptionKey, WrappedContentKey,
    rewrap_content_key,
};
pub use content_publisher::{
    DurableContentSink, UnprotectedContentAccess, UnprotectedContentPublisher,
};
pub use content_reader::{
    ContentReadError, ContentReadRequest, DurableContentReader, PublishedContentReference,
};
pub use directory::{
    DirectoryEntry, DirectoryEntryKind, DirectoryMutation, DirectoryNodeDigest,
    DirectoryNodeRecord, DirectoryTrie, DirectoryTrieError,
};
pub use handle_io::{
    FilesystemHandleCloseReceipt, FilesystemHandleCloseRequest, FilesystemHandleCreateReceipt,
    FilesystemHandleCreateRequest, FilesystemHandleFlushRequest, FilesystemHandleOpenRequest,
    FilesystemHandleWriteReceipt, FilesystemHandleWriteRequest, HandleIoError,
};
pub use handles::{
    ByteRange, CloseHandleOutcome, CloseHandleReceipt, CloseHandleRequest, CreateDisposition,
    HandleAccess, HandleError, HandleLeaseReceipt, HandleLeaseRequest, HandleShare,
    HandleWriteAdmissionReceipt, HandleWriteAdmissionRequest, LockRangeReceipt, LockRangeRequest,
    OpenHandleReceipt, OpenHandleRequest, RangeLockKind, UnlockRangeReceipt, UnlockRangeRequest,
};
pub use name::{
    CompatibilityProfile, NamespaceComponent, NamespaceLimits, NamespaceNameError, NamespacePath,
};
pub use publication::{
    BranchNamespaceHead, DirectoryPublication, DirectoryPublicationReceipt,
    DirectoryRevisionTransition, FilePublication, ManifestPublication, NamespacePublicationPath,
    NamespacePublicationReceipt, NamespaceReconciliationApplication,
    NamespaceReconciliationReceipt, PublicationDisposition, PublicationError, PublicationPathError,
    RootFilePublication, SnapshotRestorePublication, SnapshotRestoreReceipt,
    VerifiedReconciliationHead, VerifiedSnapshotRestoreHead, VersionPublicationStore,
};
pub use reachability::{
    ReachabilityRoot, ReachabilityRootPage, ReachabilityRootSource, VersionReachabilityError,
    VersionReachabilityProgress, VersionReachabilityScanRequest, VersionReachabilityState,
    VersionUnreachableProof, reachability_root_digest, reachability_root_set_digest,
    reachability_subject_digest,
};
pub use reconciliation::{
    BranchMutation, BranchMutationIntent, BranchRenameIntent, NamespaceReplayAction,
    NamespaceReplayBase, NamespaceReplayDisposition, NamespaceReplayEntry, NamespaceReplayPlan,
    PreparedNamespaceReconciliation, ReconciliationCommit, ReconciliationCommitPayload,
    ReconciliationError, ReconciliationFrontier, ReconciliationLimits, ReconciliationPlan,
    ReconciliationStoreError, plan_namespace_replay, plan_reconciliation,
};
pub use stage_store::{
    CompletedStage, DurableStageStore, StageCompletionRequest, StageLeaseReceipt,
    StageLeaseRequest, StageRegistration, StageStoreError,
};
pub use staging::{Checkpoint, StageOverlay, StageWrite, StageWriteError, StageWriteOutcome};
pub use version_retention::{
    VersionReclaimMode, VersionRetentionCandidate, VersionRetentionCandidatePage,
    VersionRetentionCandidateReason, VersionRetentionCursor, VersionRetentionError,
    VersionRetentionPageLimit, VersionRetentionPressure, VersionRetentionSelectionPolicy,
};
