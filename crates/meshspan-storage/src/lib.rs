// SPDX-License-Identifier: GPL-2.0-only

//! Capability-scoped registered-folder storage for immutable `MeshSpan` shards.

mod config;
mod folder;
mod journal;
mod marker;
mod pack;
mod provider;
mod shard;

pub use config::{HeadlessStorageConfig, StorageConfigError, UsageLimit};
pub use folder::{FolderRegistration, RegisteredFolder, StorageFolderError};
pub use journal::{
    CapacityObservation, CapacityPolicy, DurablePackEvidence, DurableTombstoneEvidence,
    JournalCapacity, JournalPutRequest, JournalTombstoneRequest, PendingPut, PendingPutPage,
    PendingTombstone, PendingTombstonePage, PreparePutResult, PrepareTombstoneResult,
    ReserveCapacityRequest, ScrubCheckpoint, TargetJournal, TargetJournalError,
};
pub use marker::{MarkerFingerprint, TargetMarker};
pub use provider::{
    FolderShardStore, FolderShardStoreError, RecoveryPage, StoragePermitVerifier,
    TombstoneRecoveryPage,
};
