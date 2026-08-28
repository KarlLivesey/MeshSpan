// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic fenced scope handoff with exactly zero or one write authority.

use thiserror::Error;

use crate::{PartitionId, Revision, ScopeId};

/// Exact source fence that the destination must install before activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffEvidence {
    /// Last authoritative state revision included by the source.
    pub frozen_revision: Revision,
    /// Digest of the exact state image at the fence.
    pub snapshot_digest: [u8; 32],
}

/// Persistent state of one scope-to-partition route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteState {
    /// One partition owns converged writes.
    Active,
    /// Destination is catching up while the source remains the only writer.
    Preparing {
        /// Proposed destination partition.
        destination: PartitionId,
    },
    /// Source is fenced and the destination is not yet active; no converged writer exists.
    Frozen {
        /// Proposed destination partition.
        destination: PartitionId,
        /// Exact state installed by the destination before activation.
        evidence: HandoffEvidence,
    },
}

/// One catalogue-owned route and its monotonic fencing epochs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScopeRoute {
    scope_id: ScopeId,
    source_partition: PartitionId,
    ownership_epoch: u64,
    routing_epoch: u64,
    state: RouteState,
}

impl ScopeRoute {
    /// Creates an initially active route.
    ///
    /// # Errors
    ///
    /// Rejects zero epochs.
    pub const fn new(
        scope_id: ScopeId,
        partition_id: PartitionId,
        ownership_epoch: u64,
        routing_epoch: u64,
    ) -> Result<Self, RouteError> {
        if ownership_epoch == 0 || routing_epoch == 0 {
            return Err(RouteError::InvalidTransition);
        }
        Ok(Self {
            scope_id,
            source_partition: partition_id,
            ownership_epoch,
            routing_epoch,
            state: RouteState::Active,
        })
    }

    /// Begins catch-up at a different destination under a newer catalogue routing epoch.
    ///
    /// # Errors
    ///
    /// Rejects a nested handoff, same partition or non-increasing routing epoch.
    pub fn begin_handoff(
        &mut self,
        destination: PartitionId,
        routing_epoch: u64,
    ) -> Result<(), RouteError> {
        if !matches!(self.state, RouteState::Active)
            || destination.as_bytes() == self.source_partition.as_bytes()
            || routing_epoch <= self.routing_epoch
        {
            return Err(RouteError::InvalidTransition);
        }
        self.routing_epoch = routing_epoch;
        self.state = RouteState::Preparing { destination };
        Ok(())
    }

    /// Fences the source after its exact final state is durable.
    ///
    /// # Errors
    ///
    /// Rejects stale epochs, blank evidence or a state other than preparation.
    pub fn freeze(
        &mut self,
        routing_epoch: u64,
        evidence: HandoffEvidence,
    ) -> Result<(), RouteError> {
        let RouteState::Preparing { destination } = self.state else {
            return Err(RouteError::InvalidTransition);
        };
        if routing_epoch != self.routing_epoch
            || evidence.frozen_revision.get() == 0
            || is_zero_digest(evidence.snapshot_digest)
        {
            return Err(RouteError::InvalidTransition);
        }
        self.state = RouteState::Frozen {
            destination,
            evidence,
        };
        Ok(())
    }

    /// Activates the destination only after it presents the exact committed source fence.
    ///
    /// # Errors
    ///
    /// Rejects stale epochs, wrong destination/evidence and ownership-epoch exhaustion.
    pub fn activate(
        &mut self,
        destination: PartitionId,
        routing_epoch: u64,
        installed: HandoffEvidence,
    ) -> Result<(), RouteError> {
        let RouteState::Frozen {
            destination: expected_destination,
            evidence,
        } = self.state
        else {
            return Err(RouteError::InvalidTransition);
        };
        if destination.as_bytes() != expected_destination.as_bytes()
            || routing_epoch != self.routing_epoch
            || installed.frozen_revision.get() != evidence.frozen_revision.get()
            || installed.snapshot_digest != evidence.snapshot_digest
        {
            return Err(RouteError::InvalidTransition);
        }
        let Some(ownership_epoch) = self.ownership_epoch.checked_add(1) else {
            return Err(RouteError::Exhausted);
        };
        self.source_partition = destination;
        self.ownership_epoch = ownership_epoch;
        self.state = RouteState::Active;
        Ok(())
    }

    /// Cancels a handoff under a newer catalogue epoch and restores the source as sole writer.
    ///
    /// # Errors
    ///
    /// Rejects an active route or non-increasing epoch.
    pub fn abort(&mut self, routing_epoch: u64) -> Result<(), RouteError> {
        if matches!(self.state, RouteState::Active) || routing_epoch <= self.routing_epoch {
            return Err(RouteError::InvalidTransition);
        }
        self.routing_epoch = routing_epoch;
        self.state = RouteState::Active;
        Ok(())
    }

    /// Returns whether this exact partition and routing epoch may accept converged writes.
    #[must_use]
    pub fn permits_write(&self, partition_id: PartitionId, routing_epoch: u64) -> bool {
        let source_may_write = matches!(
            self.state,
            RouteState::Active | RouteState::Preparing { .. }
        );
        source_may_write
            && routing_epoch == self.routing_epoch
            && partition_id.as_bytes() == self.source_partition.as_bytes()
    }

    /// Returns the stable routed scope.
    #[must_use]
    pub const fn scope_id(&self) -> ScopeId {
        self.scope_id
    }

    /// Returns the current sole owner, or the fenced source while no writer exists.
    #[must_use]
    pub const fn source_partition(&self) -> PartitionId {
        self.source_partition
    }

    /// Returns the monotonic authority epoch.
    #[must_use]
    pub const fn ownership_epoch(&self) -> u64 {
        self.ownership_epoch
    }

    /// Returns the catalogue routing epoch that callers must present.
    #[must_use]
    pub const fn routing_epoch(&self) -> u64 {
        self.routing_epoch
    }

    /// Returns the current handoff state.
    #[must_use]
    pub const fn state(&self) -> RouteState {
        self.state
    }
}

/// Closed route transition failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RouteError {
    /// State, identity, epoch or evidence does not match the next legal transition.
    #[error("scope route transition is invalid")]
    InvalidTransition,
    /// A monotonic route counter cannot advance.
    #[error("scope route epoch is exhausted")]
    Exhausted,
}

const fn is_zero_digest(digest: [u8; 32]) -> bool {
    let mut index = 0;
    while index < digest.len() {
        if digest[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_never_has_two_write_authorities() -> Result<(), Box<dyn std::error::Error>> {
        let source = partition(1)?;
        let destination = partition(2)?;
        let mut route = ScopeRoute::new(ScopeId::from_bytes([3; 16])?, source, 1, 1)?;
        assert_only_writer(&route, Some(source), source, destination);

        route.begin_handoff(destination, 2)?;
        assert_only_writer(&route, Some(source), source, destination);
        let evidence = HandoffEvidence {
            frozen_revision: Revision::new(9),
            snapshot_digest: [4; 32],
        };
        route.freeze(2, evidence)?;
        assert_only_writer(&route, None, source, destination);
        assert_eq!(
            route.activate(
                destination,
                2,
                HandoffEvidence {
                    snapshot_digest: [5; 32],
                    ..evidence
                }
            ),
            Err(RouteError::InvalidTransition)
        );
        route.activate(destination, 2, evidence)?;
        assert_only_writer(&route, Some(destination), source, destination);
        assert_eq!(route.ownership_epoch(), 2);
        Ok(())
    }

    #[test]
    fn abort_uses_a_new_fence_before_source_writes_resume() -> Result<(), Box<dyn std::error::Error>>
    {
        let source = partition(6)?;
        let destination = partition(7)?;
        let mut route = ScopeRoute::new(ScopeId::from_bytes([8; 16])?, source, 3, 10)?;
        route.begin_handoff(destination, 11)?;
        route.freeze(
            11,
            HandoffEvidence {
                frozen_revision: Revision::new(12),
                snapshot_digest: [9; 32],
            },
        )?;
        assert_eq!(route.abort(11), Err(RouteError::InvalidTransition));
        route.abort(12)?;
        assert_only_writer(&route, Some(source), source, destination);
        assert_eq!(route.ownership_epoch(), 3);
        Ok(())
    }

    fn assert_only_writer(
        route: &ScopeRoute,
        expected: Option<PartitionId>,
        source: PartitionId,
        destination: PartitionId,
    ) {
        let writers: Vec<PartitionId> = [source, destination]
            .into_iter()
            .filter(|partition| route.permits_write(*partition, route.routing_epoch()))
            .collect();
        assert_eq!(writers.as_slice(), expected.as_slice());
        assert!(!route.permits_write(source, route.routing_epoch().saturating_sub(1)));
    }

    fn partition(value: u8) -> Result<PartitionId, Box<dyn std::error::Error>> {
        Ok(PartitionId::from_bytes([value; 16])?)
    }
}
