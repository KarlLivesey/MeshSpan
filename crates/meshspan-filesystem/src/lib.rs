// SPDX-License-Identifier: GPL-2.0-only

//! Protocol-neutral namespace, staging, permissions and copy-on-write filesystem semantics.

mod directory;
mod name;
mod publication;
mod stage_store;
mod staging;

pub use directory::{
    DirectoryEntry, DirectoryEntryKind, DirectoryMutation, DirectoryNodeDigest,
    DirectoryNodeRecord, DirectoryTrie, DirectoryTrieError,
};
pub use name::{
    CompatibilityProfile, NamespaceComponent, NamespaceLimits, NamespaceNameError, NamespacePath,
};
pub use publication::{
    BranchFileHead, FilePublication, ManifestPublication, PublicationDisposition, PublicationError,
    PublicationReceipt, VersionPublicationStore,
};
pub use stage_store::{DurableStageStore, StageRegistration, StageStoreError};
pub use staging::{Checkpoint, StageOverlay, StageWrite, StageWriteError, StageWriteOutcome};
