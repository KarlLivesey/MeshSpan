// SPDX-License-Identifier: GPL-2.0-only

//! Protocol-neutral namespace, staging, permissions and copy-on-write filesystem semantics.

mod name;
mod stage_store;
mod staging;

pub use name::{
    CompatibilityProfile, NamespaceComponent, NamespaceLimits, NamespaceNameError, NamespacePath,
};
pub use stage_store::{DurableStageStore, StageRegistration, StageStoreError};
pub use staging::{Checkpoint, StageOverlay, StageWrite, StageWriteError, StageWriteOutcome};
