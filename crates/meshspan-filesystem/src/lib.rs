// SPDX-License-Identifier: GPL-2.0-only

//! Protocol-neutral namespace, staging, permissions and copy-on-write filesystem semantics.

mod commit_service;
mod content_crypto;
mod directory;
mod name;
mod publication;
mod stage_store;
mod staging;

pub use commit_service::{
    ContentPublicationError, ContentPublicationRequest, DurableContentPublisher,
    FilesystemCommitError, FilesystemCommitService, RootFileCommitRequest,
};
pub use content_crypto::{
    ContentChunkCipher, ContentChunkLimits, ContentCryptoError, ContentEncryptionKey,
    EncryptedContentChunk,
};
pub use directory::{
    DirectoryEntry, DirectoryEntryKind, DirectoryMutation, DirectoryNodeDigest,
    DirectoryNodeRecord, DirectoryTrie, DirectoryTrieError,
};
pub use name::{
    CompatibilityProfile, NamespaceComponent, NamespaceLimits, NamespaceNameError, NamespacePath,
};
pub use publication::{
    BranchNamespaceHead, FilePublication, ManifestPublication, NamespacePublicationReceipt,
    PublicationDisposition, PublicationError, RootFilePublication, VersionPublicationStore,
};
pub use stage_store::{
    CompletedStage, DurableStageStore, StageCompletionRequest, StageRegistration, StageStoreError,
};
pub use staging::{Checkpoint, StageOverlay, StageWrite, StageWriteError, StageWriteOutcome};
