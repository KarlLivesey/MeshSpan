// SPDX-License-Identifier: GPL-2.0-only

//! Capability-scoped registered-folder storage for immutable `MeshSpan` shards.

mod config;
mod folder;
mod journal;
mod marker;

pub use config::{HeadlessStorageConfig, StorageConfigError, UsageLimit};
pub use folder::{FolderRegistration, RegisteredFolder, StorageFolderError};
pub use journal::{
    CapacityObservation, CapacityPolicy, JournalCapacity, ReserveCapacityRequest, TargetJournal,
    TargetJournalError,
};
pub use marker::{MarkerFingerprint, TargetMarker};

use meshspan_domain::{EntropyError, RandomSource};

/// Operating-system cryptographic entropy for production marker and permit material.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperatingSystemRandom;

impl RandomSource for OperatingSystemRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(destination).map_err(|_| EntropyError)
    }
}
