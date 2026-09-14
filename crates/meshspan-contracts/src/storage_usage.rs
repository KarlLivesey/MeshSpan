// SPDX-License-Identifier: GPL-2.0-only

//! Target accounting observations, separate from admission and physical free-space authority.

use crate::ContractError;

/// Fixed-cardinality aggregate usage gauges; byte values are accounting, not physical free space.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageUsageMetric {
    /// Targets whose pack extent and reusable-page evidence was sampled.
    SampledPackTargets(u64),
    /// Targets without pack evidence; absence is not a zero-byte pack.
    UnavailablePackTargets(u64),
    /// Logical database extent including metadata; excludes WAL and filesystem allocation overhead.
    PackDatabaseBytes(u64),
    /// Free pages reusable inside the pack database, not bytes returned to the host filesystem.
    PackReusableBytes(u64),
    /// Distinct local mounted filesystems sampled, not independent disks or storage pools.
    SampledFilesystems(u64),
    /// Targets without filesystem evidence, including unsupported providers.
    UnavailableFilesystemTargets(u64),
    /// Sum of mounted-filesystem capacities, counted once per filesystem, not per folder.
    FilesystemTotalBytes(u64),
    /// Sum of filesystem space available to this process, not MeshSpan-owned free quota.
    FilesystemAvailableBytes(u64),
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
    /// Optional provider-owned pack evidence, independent of quota and filesystem free space.
    pub pack: Option<PackSpaceObservation>,
    /// Optional mounted-filesystem evidence; absence never means zero space.
    pub filesystem: Option<FilesystemSpaceObservation>,
    /// Accounted committed shard and backup payload bytes; excludes filesystem/pack overhead.
    pub committed_bytes: u64,
    /// Active shard and backup holds, including work whose publication outcome is unknown.
    pub reserved_bytes: u64,
    /// Configured target ceiling. Several targets may share its backing physical space.
    pub configured_limit_bytes: u64,
    /// Configured headroom reserved for repair, not already occupied bytes.
    pub repair_reserve_bytes: u64,
}

/// Coherent extent and free-page accounting for this target's pack databases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackSpaceObservation {
    /// Logical database page extent, including schema/index/operation metadata but excluding WAL.
    pub database_bytes: u64,
    /// Free-list pages available for reuse by the database; never a host free-space claim.
    pub reusable_bytes: u64,
}

/// Host-local filesystem evidence from an already-open provider capability.
///
/// Identity is valid only within this host and sampling pass. Different filesystems may
/// share a thin-provisioned pool; these numbers do not establish independent physical capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemSpaceObservation {
    /// Opaque host-local mounted-filesystem identity, never exported as a public label.
    pub identity: u64,
    /// Filesystem-reported capacity, including space occupied by other applications.
    pub total_bytes: u64,
    /// Filesystem-reported bytes available to the daemon's credentials.
    pub available_bytes: u64,
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
