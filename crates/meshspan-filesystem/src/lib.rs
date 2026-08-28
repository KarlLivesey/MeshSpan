// SPDX-License-Identifier: GPL-2.0-only

//! Protocol-neutral namespace, staging, permissions and copy-on-write filesystem semantics.

mod commit_service;
mod content_catalog;
mod content_crypto;
mod content_key;
mod content_publisher;
mod directory;
mod name;
mod publication;
mod reconciliation;
mod stage_store;
mod staging;

pub use commit_service::{
    ContentPublicationError, ContentPublicationRequest, DurableContentPublisher,
    FilesystemCommitError, FilesystemCommitService, RootFileCommitRequest,
};
pub use content_catalog::{
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
pub use content_publisher::{
    DurableContentSink, UnprotectedContentPublisher, UnprotectedContentTarget,
};
pub use directory::{
    DirectoryEntry, DirectoryEntryKind, DirectoryMutation, DirectoryNodeDigest,
    DirectoryNodeRecord, DirectoryTrie, DirectoryTrieError,
};
pub use name::{
    CompatibilityProfile, NamespaceComponent, NamespaceLimits, NamespaceNameError, NamespacePath,
};
pub use publication::{
    BranchNamespaceHead, DirectoryPublication, DirectoryPublicationReceipt,
    DirectoryRevisionTransition, FilePublication, ManifestPublication, NamespacePublicationPath,
    NamespacePublicationReceipt, PublicationDisposition, PublicationError, PublicationPathError,
    RootFilePublication, VersionPublicationStore,
};
pub use reconciliation::{
    BranchMutation, BranchMutationIntent, NamespaceReplayAction, NamespaceReplayBase,
    NamespaceReplayDisposition, NamespaceReplayEntry, NamespaceReplayPlan,
    PreparedNamespaceReconciliation, ReconciliationCommit, ReconciliationCommitPayload,
    ReconciliationError, ReconciliationFrontier, ReconciliationLimits, ReconciliationPlan,
    ReconciliationStoreError, plan_namespace_replay, plan_reconciliation,
};
pub use stage_store::{
    CompletedStage, DurableStageStore, StageCompletionRequest, StageRegistration, StageStoreError,
};
pub use staging::{Checkpoint, StageOverlay, StageWrite, StageWriteError, StageWriteOutcome};
