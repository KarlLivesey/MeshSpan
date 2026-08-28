// SPDX-License-Identifier: GPL-2.0-only

//! Incarnation-fenced presence and honest metadata-partition availability status.

mod availability;
mod presence;

pub use availability::{
    AvailabilityError, AvailabilityReason, AvailabilityState, PartitionAvailability,
    PartitionStatusInput, evaluate_partition_availability,
};
pub use presence::{NodePresence, PresenceError, PresenceRegistry, PresenceRole, PresenceUpdate};
