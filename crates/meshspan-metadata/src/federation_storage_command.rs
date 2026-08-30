// SPDX-License-Identifier: GPL-2.0-only

//! Typed authoritative allocation and revocation of disjoint federated storage quota.

use meshspan_domain::{FederationStorageAllocation, FederationStorageAllocationId, Revision};

use crate::command::CanonicalDigest;

/// Assigns one immutable slice of a storage grant to one provider node and target incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssueFederationStorageAllocation {
    /// Complete immutable node-local quota slice.
    pub allocation: FederationStorageAllocation,
    /// Exact grant revision from which this slice was derived.
    pub expected_grant_revision: Revision,
}

/// Revokes one live allocation without deleting its authority evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeFederationStorageAllocation {
    /// Exact allocation being fenced.
    pub allocation_id: FederationStorageAllocationId,
    /// Exact allocation revision expected by the caller.
    pub expected_allocation_revision: Revision,
    /// Bounded audit explanation.
    pub reason: String,
}

impl IssueFederationStorageAllocation {
    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        let allocation = self.allocation;
        digest.bytes(b"issue-federation-storage-allocation");
        digest.identifier(allocation.allocation_id().as_bytes());
        digest.identifier(allocation.grant_id().as_bytes());
        digest.identifier(allocation.provider_node_id().as_bytes());
        digest.identifier(allocation.target_id().as_bytes());
        digest.unsigned(allocation.target_generation());
        digest.unsigned(allocation.maximum_bytes());
        digest.signed(allocation.valid_from().get());
        digest.signed(allocation.valid_until().get());
        digest.unsigned(self.expected_grant_revision.get());
    }
}

impl RevokeFederationStorageAllocation {
    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"revoke-federation-storage-allocation");
        digest.identifier(self.allocation_id.as_bytes());
        digest.unsigned(self.expected_allocation_revision.get());
        digest.bytes(self.reason.as_bytes());
    }
}
