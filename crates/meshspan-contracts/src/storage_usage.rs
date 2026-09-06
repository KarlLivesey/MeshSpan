// SPDX-License-Identifier: GPL-2.0-only

//! Target accounting observations, separate from admission and physical free-space authority.

use crate::ContractError;

/// Fixed-cardinality aggregate usage gauges; byte values are accounting, not physical free space.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageUsageMetric {
    /// Age since the beginning of the last usage sampling pass.
    Age(std::time::Duration),
    /// Targets successfully sampled in that pass.
    SampledTargets(u64),
    /// Open targets whose usage could not be sampled in that pass.
    UnavailableTargets(u64),
    /// Sum of accounted committed shard and backup payload bytes.
    CommittedBytes(u64),
    /// Sum of active reservations; not all holds necessarily consume physical bytes yet.
    ReservedBytes(u64),
    /// Sum of configured ceilings, which can overlap on shared physical devices.
    ConfiguredLimitBytes(u64),
    /// Sum of configured repair headroom, not occupied space.
    RepairReserveBytes(u64),
}

/// One target's current accounting, not a reservation or available-space promise.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StorageUsageObservation {
    /// Accounted committed shard and backup payload bytes; excludes filesystem/pack overhead.
    pub committed_bytes: u64,
    /// Active shard and backup holds, including work whose publication outcome is unknown.
    pub reserved_bytes: u64,
    /// Configured target ceiling. Several targets may share its backing physical space.
    pub configured_limit_bytes: u64,
    /// Configured headroom reserved for repair, not already occupied bytes.
    pub repair_reserve_bytes: u64,
}

/// Replaceable synchronous target observation boundary, invoked only by an IO worker.
pub trait StorageUsageSource {
    /// Reads bounded target accounting and configuration without changing reservations.
    ///
    /// # Errors
    /// Returns unavailable or invalid evidence on lock contention, IO or accounting failure.
    /// Callers must not replace a failed observation with zero, or sum filesystem free space
    /// across targets without establishing whether their backing devices overlap.
    fn observe_usage(&self) -> Result<StorageUsageObservation, ContractError>;
}
