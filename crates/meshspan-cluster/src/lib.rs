// SPDX-License-Identifier: GPL-2.0-only

//! Runtime composition boundary for deterministic consensus, metadata persistence and QUIC.

mod cleanup;
mod convergence;
mod driver;
mod membership;
mod node_runtime;
mod retention;
mod status;
mod wire;

#[cfg(test)]
mod convergence_tests;
#[cfg(test)]
mod handoff_tests;

pub use cleanup::{
    CleanupAttestationError, CleanupPermitError, version_cleanup_attestation,
    version_cleanup_proposal, version_cleanup_removal_permit,
};
pub use convergence::{reconciliation_head_command, snapshot_restore_head_command};
pub use driver::{ClusterDriverError, DriverEffect, PartitionConsensusDriver, ScopedProposal};
pub use node_runtime::{NodeRuntimeError, run_stage_three_node};
pub use retention::version_retention_selection_policy;
pub use status::{
    AvailabilityError, AvailabilityReason, AvailabilityState, NodePresence, PartitionAvailability,
    PartitionStatusInput, PresenceError, PresenceRegistry, PresenceRole, PresenceUpdate,
    evaluate_partition_availability,
};
pub use wire::{ConsensusWireError, decode_consensus_message, encode_consensus_message};
