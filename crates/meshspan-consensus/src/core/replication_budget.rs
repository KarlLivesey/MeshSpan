// SPDX-License-Identifier: GPL-2.0-only

//! Explicit transport allocation limits supplied by the outer runtime.

use super::types::{CoreError, MAXIMUM_APPEND_COMMAND_BYTES};

/// A peer's framed replication limit, including a conservative cost per entry.
///
/// The transport owner supplies this policy from authenticated capability evidence. It is
/// volatile and does not alter durable consensus records or quorum membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplicationBatchBudget {
    pub(super) max_bytes: usize,
    pub(super) entry_overhead: usize,
}

impl ReplicationBatchBudget {
    /// Constructs a budget able to carry at least one command byte.
    ///
    /// # Errors
    ///
    /// Rejects a budget consumed entirely by entry framing.
    pub fn new(max_bytes: usize, entry_overhead: usize) -> Result<Self, CoreError> {
        if max_bytes <= entry_overhead {
            return Err(CoreError::InvalidConfiguration);
        }
        Ok(Self {
            max_bytes,
            entry_overhead,
        })
    }

    /// Returns whether a single command fits both this peer's frame and core byte limits.
    #[must_use]
    pub fn permits_command(self, command_bytes: usize) -> bool {
        command_bytes <= MAXIMUM_APPEND_COMMAND_BYTES
            && command_bytes
                .checked_add(self.entry_overhead)
                .is_some_and(|bytes| bytes <= self.max_bytes)
    }
}

impl Default for ReplicationBatchBudget {
    fn default() -> Self {
        Self {
            max_bytes: MAXIMUM_APPEND_COMMAND_BYTES,
            entry_overhead: 0,
        }
    }
}
