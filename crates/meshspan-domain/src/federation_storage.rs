// SPDX-License-Identifier: GPL-2.0-only

//! Disjoint storage-capacity allocations beneath one bilateral federation grant.

use thiserror::Error;

use crate::{FederationGrantId, FederationStorageAllocationId, NodeId, TargetId, UnixMicros};

/// Closed semantic action carried by one federated storage capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationStorageAction {
    /// Persist a new immutable shard.
    Put,
    /// Read one existing immutable shard.
    Get,
    /// Verify one existing immutable shard.
    Scrub,
    /// Persist a replacement shard during healing.
    Repair,
    /// Make one shard logically unreachable.
    Retire,
    /// Physically reclaim one already-retired shard.
    Reclaim,
}

impl FederationStorageAction {
    /// Returns whether this action can increase durable byte usage.
    #[must_use]
    pub const fn reserves_capacity(self) -> bool {
        matches!(self, Self::Put | Self::Repair)
    }

    /// Returns the stable persistence code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Put => 1,
            Self::Get => 2,
            Self::Scrub => 3,
            Self::Repair => 4,
            Self::Retire => 5,
            Self::Reclaim => 6,
        }
    }

    /// Parses the stable persistence code.
    ///
    /// # Errors
    ///
    /// Rejects zero and unknown future action codes.
    pub const fn from_code(code: u8) -> Result<Self, FederationStorageActionError> {
        match code {
            1 => Ok(Self::Put),
            2 => Ok(Self::Get),
            3 => Ok(Self::Scrub),
            4 => Ok(Self::Repair),
            5 => Ok(Self::Retire),
            6 => Ok(Self::Reclaim),
            _ => Err(FederationStorageActionError),
        }
    }
}

/// Unknown federated storage action code.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("federated storage action is invalid")]
pub struct FederationStorageActionError;

/// One immutable quota slice assigned to one exact provider node and target incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationStorageAllocation {
    allocation_id: FederationStorageAllocationId,
    grant_id: FederationGrantId,
    provider_node_id: NodeId,
    target_id: TargetId,
    target_generation: u64,
    maximum_bytes: u64,
    valid_from: UnixMicros,
    valid_until: UnixMicros,
}

impl FederationStorageAllocation {
    /// Constructs one exact allocation without assuming that its grant or target exists.
    ///
    /// # Errors
    ///
    /// Rejects zero generations/capacity and empty or reversed validity intervals.
    #[allow(
        clippy::too_many_arguments,
        reason = "a quota allocation must bind every independent authority dimension explicitly"
    )]
    pub const fn new(
        allocation_id: FederationStorageAllocationId,
        grant_id: FederationGrantId,
        provider_node_id: NodeId,
        target_id: TargetId,
        target_generation: u64,
        maximum_bytes: u64,
        valid_from: UnixMicros,
        valid_until: UnixMicros,
    ) -> Result<Self, FederationStorageAllocationError> {
        if target_generation == 0 || maximum_bytes == 0 {
            return Err(FederationStorageAllocationError::InvalidCapacity);
        }
        if valid_from.get() <= 0 || valid_until.get() <= valid_from.get() {
            return Err(FederationStorageAllocationError::InvalidInterval);
        }
        Ok(Self {
            allocation_id,
            grant_id,
            provider_node_id,
            target_id,
            target_generation,
            maximum_bytes,
            valid_from,
            valid_until,
        })
    }

    /// Returns the stable allocation identity.
    #[must_use]
    pub const fn allocation_id(self) -> FederationStorageAllocationId {
        self.allocation_id
    }

    /// Returns the exact bilateral storage grant supplying this quota.
    #[must_use]
    pub const fn grant_id(self) -> FederationGrantId {
        self.grant_id
    }

    /// Returns the sole provider node allowed to consume this disjoint slice.
    #[must_use]
    pub const fn provider_node_id(self) -> NodeId {
        self.provider_node_id
    }

    /// Returns the exact target identity.
    #[must_use]
    pub const fn target_id(self) -> TargetId {
        self.target_id
    }

    /// Returns the exact target incarnation fence.
    #[must_use]
    pub const fn target_generation(self) -> u64 {
        self.target_generation
    }

    /// Returns the maximum bytes this allocation may have reserved or durable.
    #[must_use]
    pub const fn maximum_bytes(self) -> u64 {
        self.maximum_bytes
    }

    /// Returns the first authorised instant, inclusive.
    #[must_use]
    pub const fn valid_from(self) -> UnixMicros {
        self.valid_from
    }

    /// Returns the first unauthorised instant, exclusive.
    #[must_use]
    pub const fn valid_until(self) -> UnixMicros {
        self.valid_until
    }

    /// Reports whether this allocation is currently usable.
    #[must_use]
    pub const fn is_valid_at(self, now: UnixMicros) -> bool {
        now.get() >= self.valid_from.get() && now.get() < self.valid_until.get()
    }
}

/// Invalid immutable federation storage allocation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FederationStorageAllocationError {
    /// Target generation and capacity must both be positive.
    #[error("federation storage allocation capacity is invalid")]
    InvalidCapacity,
    /// Validity must be a positive non-empty half-open interval.
    #[error("federation storage allocation interval is invalid")]
    InvalidInterval,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_binds_one_target_incarnation_and_half_open_interval()
    -> Result<(), Box<dyn std::error::Error>> {
        let allocation = FederationStorageAllocation::new(
            FederationStorageAllocationId::from_bytes([1; 16])?,
            FederationGrantId::from_bytes([2; 16])?,
            NodeId::from_bytes([3; 16])?,
            TargetId::from_bytes([4; 16])?,
            5,
            6,
            UnixMicros::new(7),
            UnixMicros::new(9),
        )?;
        assert!(!allocation.is_valid_at(UnixMicros::new(6)));
        assert!(allocation.is_valid_at(UnixMicros::new(7)));
        assert!(allocation.is_valid_at(UnixMicros::new(8)));
        assert!(!allocation.is_valid_at(UnixMicros::new(9)));
        assert_eq!(allocation.target_generation(), 5);
        assert_eq!(allocation.maximum_bytes(), 6);
        Ok(())
    }

    #[test]
    fn allocation_rejects_zero_capacity_generation_and_empty_time()
    -> Result<(), Box<dyn std::error::Error>> {
        let allocation_id = FederationStorageAllocationId::from_bytes([1; 16])?;
        let grant_id = FederationGrantId::from_bytes([2; 16])?;
        let node_id = NodeId::from_bytes([3; 16])?;
        let target_id = TargetId::from_bytes([4; 16])?;
        let fixture = |generation, bytes, from, until| {
            FederationStorageAllocation::new(
                allocation_id,
                grant_id,
                node_id,
                target_id,
                generation,
                bytes,
                UnixMicros::new(from),
                UnixMicros::new(until),
            )
        };
        assert_eq!(
            fixture(0, 1, 1, 2),
            Err(FederationStorageAllocationError::InvalidCapacity)
        );
        assert_eq!(
            fixture(1, 0, 1, 2),
            Err(FederationStorageAllocationError::InvalidCapacity)
        );
        assert_eq!(
            fixture(1, 1, 2, 2),
            Err(FederationStorageAllocationError::InvalidInterval)
        );
        Ok(())
    }
}
