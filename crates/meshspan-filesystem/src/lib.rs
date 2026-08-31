// SPDX-License-Identifier: GPL-2.0-only

//! Protocol-neutral namespace, staging, permissions and copy-on-write filesystem semantics.

mod adapter;
mod authority;
mod cleanup_cancellation;
mod cleanup_fence;
mod cleanup_retirement;
mod commit_service;
mod content_catalog;
mod content_crypto;
mod content_key;
mod content_key_transit;
mod content_publisher;
mod content_reader;
mod content_transfer;
mod directory;
mod handle_io;
mod handles;
mod name;
mod namespace_planning;
mod namespace_query;
mod publication;
mod reachability;
mod reconciliation;
mod stage_store;
mod staging;
mod version_retention;

pub use adapter::{
    AdapterCloseFileRequest, AdapterCreateDirectoryRequest, AdapterCreateFileRequest,
    AdapterFlushFileRequest, AdapterLeaseRequest, AdapterListRequest, AdapterLockRequest,
    AdapterOpenFileRequest, AdapterReadFileRequest, AdapterRenameRequest, AdapterStatRequest,
    AdapterUnlinkRequest, AdapterUnlockRequest, AdapterWriteFileRequest, BoundFilesystemAdapter,
    FilesystemAdapterConfigurationError, FilesystemAdapterPolicy, FilesystemFileAdapter,
};
pub use authority::{
    AuthorisedFilesystemError, AuthorisedFilesystemService, FilesystemAccessAuthority,
    FilesystemAccessContext, FilesystemAuthorityGrant, FilesystemAuthorityRequest,
};
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
    CommittedContentLayoutTransfer, CommittedShardInventory, CommittedShardPage,
    ContentCatalogError, DurableContentCatalog, PendingContentChunkPage, PreparedContentChunk,
    PreparedContentLayout,
};
pub use content_crypto::{
    ContentChunkCipher, ContentChunkLimits, ContentCryptoError, ContentEncryptionKey,
    EncryptedContentChunk,
};
pub use content_key::{
    ContentKeyEnvelopeCipher, ContentKeyError, VolumeKeyEncryptionKey, WrappedContentKey,
    rewrap_content_key,
};
pub use content_key_transit::{
    ContentKeyTransitCipher, ContentKeyTransitError, TransitWrappedContentKey,
};
pub use content_publisher::{
    DurableContentSink, UnprotectedContentAccess, UnprotectedContentPublisher,
};
pub use content_reader::{
    ContentReadError, ContentReadRequest, DurableContentReader, PublishedContentReference,
};
pub use content_transfer::{
    ContentLayoutChunk, ContentLayoutTransferError, ContentLayoutTransferHeader,
    ContentLayoutTransferPage, MAXIMUM_CONTENT_LAYOUT_PAGE_ITEMS,
};
pub use directory::{
    DirectoryEntry, DirectoryEntryKind, DirectoryMutation, DirectoryNodeDigest,
    DirectoryNodeRecord, DirectoryTrie, DirectoryTrieError,
};
pub use handle_io::{
    FilesystemHandleCloseReceipt, FilesystemHandleCloseRequest, FilesystemHandleCreateReceipt,
    FilesystemHandleCreateRequest, FilesystemHandleFlushRequest, FilesystemHandleOpenRequest,
    FilesystemHandleReadReceipt, FilesystemHandleReadRequest, FilesystemHandleWriteReceipt,
    FilesystemHandleWriteRequest, HandleIoError, HandleReadError,
};
pub use handles::{
    ByteRange, CloseHandleOutcome, CloseHandleReceipt, CloseHandleRequest, CreateDisposition,
    HandleAccess, HandleAuthorityTarget, HandleError, HandleLeaseReceipt, HandleLeaseRequest,
    HandleShare, HandleWriteAdmissionReceipt, HandleWriteAdmissionRequest, LockRangeReceipt,
    LockRangeRequest, OpenHandleReceipt, OpenHandleRequest, RangeLockKind, ReadyNamespaceDelete,
    ReadyNamespaceDeletePage, UnlockRangeReceipt, UnlockRangeRequest,
};
pub use name::{
    CompatibilityProfile, NamespaceComponent, NamespaceLimits, NamespaceNameError, NamespacePath,
};
pub use namespace_query::{
    DirectoryListCursor, NamespaceListEntry, NamespaceListPage, NamespaceListRequest,
    NamespaceObjectStat, NamespaceQueryError, NamespaceStatRequest,
};
pub use publication::{
    BranchNamespaceHead, DirectoryPublication, DirectoryPublicationReceipt,
    DirectoryRevisionTransition, FederatedNamespaceMutationProposal, FilePublication,
    ManifestPublication, NamespaceHistoryBundle, NamespaceHistoryCommitRecord,
    NamespaceHistoryImmutableKind, NamespaceHistoryImmutableRecord, NamespaceHistoryImport,
    NamespaceHistoryLimits, NamespaceHistoryMutationAuthority, NamespaceHistoryMutationDecision,
    NamespaceHistoryObjectRequest, NamespaceHistoryPage, NamespaceHistoryPageRequest,
    NamespaceHistoryReceiveCompletion, NamespaceHistoryReceivePreparation,
    NamespaceHistoryReceiveRequest, NamespaceHistoryReceiveStatus, NamespaceHistoryRecordError,
    NamespacePublicationPath, NamespacePublicationReceipt, NamespaceReconciliationApplication,
    NamespaceReconciliationReceipt, NamespaceRenamePublication, NamespaceRenameReceipt,
    NamespaceUnlinkAuthority, NamespaceUnlinkPublication, NamespaceUnlinkReceipt,
    PublicationDisposition, PublicationError, PublicationPathError, RootFilePublication,
    SnapshotRestorePublication, SnapshotRestoreReceipt, VerifiedReconciliationHead,
    VerifiedSnapshotRestoreHead, VersionPublicationStore,
};
pub use reachability::{
    ReachabilityRoot, ReachabilityRootPage, ReachabilityRootSource, VersionReachabilityError,
    VersionReachabilityProgress, VersionReachabilityScanRequest, VersionReachabilityState,
    VersionUnreachableProof, reachability_root_digest, reachability_root_set_digest,
    reachability_subject_digest,
};
pub use reconciliation::{
    BranchMutation, BranchMutationIntent, BranchRenameIntent, NamespaceReplayAction,
    NamespaceReplayBase, NamespaceReplayDisposition, NamespaceReplayEffect, NamespaceReplayEntry,
    NamespaceReplayPlan, NamespaceReplayRemoval, PreparedNamespaceReconciliation,
    ReconciliationCommit, ReconciliationCommitPayload, ReconciliationError, ReconciliationFrontier,
    ReconciliationLimits, ReconciliationPlan, ReconciliationStoreError, plan_namespace_replay,
    plan_reconciliation,
};
pub use stage_store::{
    CompletedStage, DurableStageStore, MAXIMUM_STAGE_READ_BYTES, StageAbortReceipt,
    StageAbortRequest, StageCompletionRequest, StageLeaseReceipt, StageLeaseRequest,
    StageRangeReadRequest, StageRegistration, StageStoreError,
};
pub use staging::{Checkpoint, StageOverlay, StageWrite, StageWriteError, StageWriteOutcome};
pub use version_retention::{
    VersionReclaimMode, VersionRetentionCandidate, VersionRetentionCandidatePage,
    VersionRetentionCandidateReason, VersionRetentionCursor, VersionRetentionError,
    VersionRetentionPageLimit, VersionRetentionPressure, VersionRetentionSelectionPolicy,
};
