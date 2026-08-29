// SPDX-License-Identifier: GPL-2.0-only

//! Root-owned metadata scopes which may be safely delegated to directly routed Raft groups.

use thiserror::Error;

use crate::{HandoffEvidence, PartitionId, RouteError, ScopeId, ScopeRoute, UnixMicros};

const MAXIMUM_VOTERS_PER_GROUP: u8 = 9;

/// Metadata operation family whose ownership may be routed independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataOperationFamily {
    /// Permanent swarm identity, node enrolment, federation trust and delegation directory.
    RootControl,
    /// Users, groups, ownership and identity lifecycle.
    Identity,
    /// Authentication methods, sessions and throttling.
    Authentication,
    /// Volume or explicit subtree namespace state.
    Namespace,
    /// Desired component and policy configuration.
    Configuration,
    /// Durable audit/event history.
    Audit,
    /// Storage inventory and lifecycle catalogue.
    StorageCatalogue,
    /// Durable background work ownership.
    Work,
}

impl MetadataOperationFamily {
    const fn code(self) -> u8 {
        match self {
            Self::RootControl => 1,
            Self::Identity => 2,
            Self::Authentication => 3,
            Self::Namespace => 4,
            Self::Configuration => 5,
            Self::Audit => 6,
            Self::StorageCatalogue => 7,
            Self::Work => 8,
        }
    }
}

/// Stable identifier-key interval owned by one routed metadata scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataKeyRange {
    /// The complete key space for this operation family.
    All,
    /// A non-empty inclusive/exclusive interval over canonical 128-bit keys.
    Bounded {
        /// First key owned by the scope.
        start_inclusive: [u8; 16],
        /// First key not owned by the scope.
        end_exclusive: [u8; 16],
    },
}

impl MetadataKeyRange {
    /// Constructs a non-empty bounded key interval.
    ///
    /// # Errors
    ///
    /// Rejects reversed or empty ranges.
    pub const fn bounded(
        start_inclusive: [u8; 16],
        end_exclusive: [u8; 16],
    ) -> Result<Self, DelegationError> {
        if !less_than(start_inclusive, end_exclusive) {
            return Err(DelegationError::InvalidKeyRange);
        }
        Ok(Self::Bounded {
            start_inclusive,
            end_exclusive,
        })
    }

    /// Reports whether one canonical key belongs to this interval.
    #[must_use]
    pub fn contains(self, key: [u8; 16]) -> bool {
        match self {
            Self::All => true,
            Self::Bounded {
                start_inclusive,
                end_exclusive,
            } => start_inclusive <= key && key < end_exclusive,
        }
    }
}

/// One independently routable operation-family/key-range scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegatedMetadataScope {
    scope_id: ScopeId,
    family: MetadataOperationFamily,
    key_range: MetadataKeyRange,
}

impl DelegatedMetadataScope {
    /// Constructs a scope which may leave the permanent root group.
    ///
    /// # Errors
    ///
    /// Rejects delegation of the root-control family itself.
    pub const fn new(
        scope_id: ScopeId,
        family: MetadataOperationFamily,
        key_range: MetadataKeyRange,
    ) -> Result<Self, DelegationError> {
        if matches!(family, MetadataOperationFamily::RootControl) {
            return Err(DelegationError::RootControlCannotMove);
        }
        Ok(Self {
            scope_id,
            family,
            key_range,
        })
    }

    /// Returns the stable routing scope.
    #[must_use]
    pub const fn scope_id(self) -> ScopeId {
        self.scope_id
    }

    /// Returns the independently routed operation family.
    #[must_use]
    pub const fn family(self) -> MetadataOperationFamily {
        self.family
    }

    /// Returns the exact owned key interval.
    #[must_use]
    pub const fn key_range(self) -> MetadataKeyRange {
        self.key_range
    }
}

/// Bound evidence that enough eligible membership and measured load justify proposing a group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegationAdmission {
    eligible_member_count: u32,
    planned_voter_count: u8,
    quorum_plan_digest: [u8; 32],
    load_evidence_digest: [u8; 32],
    measured_at: UnixMicros,
}

impl DelegationAdmission {
    /// Constructs admission evidence without inventing an automatic split threshold.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive voters, insufficient eligible members or blank evidence.
    pub const fn new(
        eligible_member_count: u32,
        planned_voter_count: u8,
        quorum_plan_digest: [u8; 32],
        load_evidence_digest: [u8; 32],
        measured_at: UnixMicros,
    ) -> Result<Self, DelegationError> {
        if planned_voter_count == 0
            || planned_voter_count > MAXIMUM_VOTERS_PER_GROUP
            || eligible_member_count < planned_voter_count as u32
        {
            return Err(DelegationError::InsufficientEligibleMembers);
        }
        if is_zero_digest(quorum_plan_digest) || is_zero_digest(load_evidence_digest) {
            return Err(DelegationError::MissingAdmissionEvidence);
        }
        Ok(Self {
            eligible_member_count,
            planned_voter_count,
            quorum_plan_digest,
            load_evidence_digest,
            measured_at,
        })
    }

    /// Returns the eligible member count observed by admission authority.
    #[must_use]
    pub const fn eligible_member_count(self) -> u32 {
        self.eligible_member_count
    }

    /// Returns the voter count bound by the proved destination plan.
    #[must_use]
    pub const fn planned_voter_count(self) -> u8 {
        self.planned_voter_count
    }

    /// Returns the exact proved quorum-plan digest.
    #[must_use]
    pub const fn quorum_plan_digest(self) -> [u8; 32] {
        self.quorum_plan_digest
    }

    /// Returns opaque capacity-normalised load evidence for later independent verification.
    #[must_use]
    pub const fn load_evidence_digest(self) -> [u8; 32] {
        self.load_evidence_digest
    }

    /// Returns when the bound observations were measured.
    #[must_use]
    pub const fn measured_at(self) -> UnixMicros {
        self.measured_at
    }
}

/// Root-authorised route for one delegatable metadata scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootDelegatedRoute {
    root_partition_id: PartitionId,
    scope: DelegatedMetadataScope,
    route: ScopeRoute,
    pending_admission: Option<DelegationAdmission>,
}

impl RootDelegatedRoute {
    /// Creates an initially root-owned route using the same handoff model as every later split.
    ///
    /// # Errors
    ///
    /// Rejects invalid zero epochs.
    pub const fn new(
        root_partition_id: PartitionId,
        scope: DelegatedMetadataScope,
        ownership_epoch: u64,
        routing_epoch: u64,
    ) -> Result<Self, DelegationError> {
        let route = match ScopeRoute::new(
            scope.scope_id(),
            root_partition_id,
            ownership_epoch,
            routing_epoch,
        ) {
            Ok(route) => route,
            Err(error) => return Err(DelegationError::Route(error)),
        };
        Ok(Self {
            root_partition_id,
            scope,
            route,
            pending_admission: None,
        })
    }

    /// Restores one exact durable directory entry after independently checking its shape.
    ///
    /// # Errors
    ///
    /// Rejects a route for another scope, a root-control scope, or admission evidence whose
    /// presence does not exactly match an in-progress handoff.
    pub const fn restore(
        root_partition_id: PartitionId,
        scope: DelegatedMetadataScope,
        route: ScopeRoute,
        pending_admission: Option<DelegationAdmission>,
    ) -> Result<Self, DelegationError> {
        if matches!(scope.family(), MetadataOperationFamily::RootControl) {
            return Err(DelegationError::RootControlCannotMove);
        }
        if !same_identifier(scope.scope_id().as_bytes(), route.scope_id().as_bytes()) {
            return Err(DelegationError::InvalidRestoredState);
        }
        let handoff_in_progress = !matches!(route.state(), crate::RouteState::Active);
        if handoff_in_progress != pending_admission.is_some() {
            return Err(DelegationError::InvalidRestoredState);
        }
        Ok(Self {
            root_partition_id,
            scope,
            route,
            pending_admission,
        })
    }

    /// Begins learner catch-up at an admitted destination group.
    ///
    /// # Errors
    ///
    /// Rejects a stale/nested handoff or an already-active destination.
    pub fn begin_delegation(
        &mut self,
        destination: PartitionId,
        routing_epoch: u64,
        admission: DelegationAdmission,
    ) -> Result<(), DelegationError> {
        self.route.begin_handoff(destination, routing_epoch)?;
        self.pending_admission = Some(admission);
        Ok(())
    }

    /// Fences the current owner at the exact durable state installed by the destination.
    ///
    /// # Errors
    ///
    /// Rejects missing admission or any underlying route mismatch.
    pub fn freeze(
        &mut self,
        routing_epoch: u64,
        evidence: HandoffEvidence,
    ) -> Result<(), DelegationError> {
        if self.pending_admission.is_none() {
            return Err(DelegationError::MissingAdmissionEvidence);
        }
        self.route.freeze(routing_epoch, evidence)?;
        Ok(())
    }

    /// Activates the new sole owner after exact fence verification.
    ///
    /// # Errors
    ///
    /// Rejects missing admission or any underlying route mismatch.
    pub fn activate(
        &mut self,
        destination: PartitionId,
        routing_epoch: u64,
        installed: HandoffEvidence,
    ) -> Result<(), DelegationError> {
        if self.pending_admission.is_none() {
            return Err(DelegationError::MissingAdmissionEvidence);
        }
        self.route.activate(destination, routing_epoch, installed)?;
        self.pending_admission = None;
        Ok(())
    }

    /// Aborts a pending delegation under a newer route fence.
    ///
    /// # Errors
    ///
    /// Rejects an active route or stale epoch.
    pub fn abort(&mut self, routing_epoch: u64) -> Result<(), DelegationError> {
        self.route.abort(routing_epoch)?;
        self.pending_admission = None;
        Ok(())
    }

    /// Reports whether the exact group and route epoch may accept converged writes.
    #[must_use]
    pub fn permits_write(&self, partition_id: PartitionId, routing_epoch: u64) -> bool {
        self.route.permits_write(partition_id, routing_epoch)
    }

    /// Returns the permanent root group, independently of current delegated ownership.
    #[must_use]
    pub const fn root_partition_id(self) -> PartitionId {
        self.root_partition_id
    }

    /// Returns the exact operation-family/key-range scope.
    #[must_use]
    pub const fn scope(self) -> DelegatedMetadataScope {
        self.scope
    }

    /// Returns the current sole-owner/handoff route.
    #[must_use]
    pub const fn route(self) -> ScopeRoute {
        self.route
    }

    /// Returns bound split admission while a handoff is pending.
    #[must_use]
    pub const fn pending_admission(self) -> Option<DelegationAdmission> {
        self.pending_admission
    }

    /// Encodes scope, root, route and admission evidence for signatures and durable digests.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        let route = self.route.signing_payload();
        let mut payload = Vec::with_capacity(180 + route.len());
        payload.extend_from_slice(b"meshspan.root-delegated-route.v1\0");
        payload.extend_from_slice(&self.root_partition_id.as_bytes());
        payload.extend_from_slice(&self.scope.scope_id().as_bytes());
        payload.push(self.scope.family().code());
        encode_key_range(&mut payload, self.scope.key_range());
        payload.extend_from_slice(&route);
        encode_admission(&mut payload, self.pending_admission);
        payload
    }
}

/// Invalid metadata delegation scope, admission or handoff.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DelegationError {
    /// Root-control state must remain on the permanent root group.
    #[error("root-control metadata cannot be delegated")]
    RootControlCannotMove,
    /// A bounded key range is empty or reversed.
    #[error("metadata delegation key range is invalid")]
    InvalidKeyRange,
    /// The proposed destination cannot form the declared voter set.
    #[error("metadata delegation has insufficient eligible members")]
    InsufficientEligibleMembers,
    /// Quorum-plan or capacity-normalised load evidence is absent.
    #[error("metadata delegation admission evidence is missing")]
    MissingAdmissionEvidence,
    /// Persisted scope, route and admission records do not describe one valid directory state.
    #[error("metadata delegation durable state is inconsistent")]
    InvalidRestoredState,
    /// The underlying sole-owner route rejected a stale or unsafe transition.
    #[error("metadata delegation route transition failed")]
    Route(#[from] RouteError),
}

const fn same_identifier(left: [u8; 16], right: [u8; 16]) -> bool {
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn less_than(left: [u8; 16], right: [u8; 16]) -> bool {
    let mut index = 0;
    while index < left.len() {
        if left[index] < right[index] {
            return true;
        }
        if left[index] > right[index] {
            return false;
        }
        index += 1;
    }
    false
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

fn encode_key_range(payload: &mut Vec<u8>, key_range: MetadataKeyRange) {
    match key_range {
        MetadataKeyRange::All => payload.push(1),
        MetadataKeyRange::Bounded {
            start_inclusive,
            end_exclusive,
        } => {
            payload.push(2);
            payload.extend_from_slice(&start_inclusive);
            payload.extend_from_slice(&end_exclusive);
        }
    }
}

fn encode_admission(payload: &mut Vec<u8>, admission: Option<DelegationAdmission>) {
    let Some(admission) = admission else {
        payload.push(0);
        return;
    };
    payload.push(1);
    payload.extend_from_slice(&admission.eligible_member_count().to_be_bytes());
    payload.push(admission.planned_voter_count());
    payload.extend_from_slice(&admission.quorum_plan_digest());
    payload.extend_from_slice(&admission.load_evidence_digest());
    payload.extend_from_slice(&admission.measured_at().get().to_be_bytes());
}

#[cfg(test)]
#[path = "partitioning_tests.rs"]
mod tests;
