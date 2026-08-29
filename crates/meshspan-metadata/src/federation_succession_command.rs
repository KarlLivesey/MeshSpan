// SPDX-License-Identifier: GPL-2.0-only

//! Signed, two-sided pre-authorisation for recovery of a permanently lost swarm.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{FederationRelationshipId, FederationSuccessionId, MeshId};

use crate::command::CanonicalDigest;

/// One already-active ownership succession edge, ordered towards the authority root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationSuccessionEdge {
    /// Authority which was permanently replaced.
    pub retiring_mesh_id: MeshId,
    /// Pre-authorised authority which replaced it.
    pub successor_mesh_id: MeshId,
}

/// Retiring swarm's signed pre-authorisation of exactly one successor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesignateFederationSuccessor {
    /// Stable designation identity.
    pub succession_id: FederationSuccessionId,
    /// Direct relationship between the two autonomous swarms.
    pub relationship_id: FederationRelationshipId,
    /// Authority which may later be declared permanently lost.
    pub retiring_mesh_id: MeshId,
    /// Only swarm pre-authorised to recover the retired authority.
    pub successor_mesh_id: MeshId,
    /// Exact relationship fence under which both sides agree.
    pub expected_authority_epoch: u64,
    /// Monotonic succession epoch for the retiring swarm.
    pub succession_epoch: u64,
    /// Retiring swarm's complete active predecessor chain, nearest edge first.
    pub ancestry: BoundedItems<FederationSuccessionEdge>,
    /// Retiring side's exact federation identity generation.
    pub signer_generation: u64,
    /// Retiring side's Ed25519 signature over [`Self::signing_payload`].
    pub signature: [u8; 64],
}

impl DesignateFederationSuccessor {
    /// Returns canonical bytes signed by the retiring swarm.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = common_payload(
            b"meshspan.federation.successor-designation.v1",
            self.succession_id,
            self.relationship_id,
            self.retiring_mesh_id,
            self.successor_mesh_id,
            self.expected_authority_epoch,
            self.succession_epoch,
        );
        payload.extend_from_slice(
            &u64::try_from(self.ancestry.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for edge in self.ancestry.as_slice() {
            payload.extend_from_slice(&edge.retiring_mesh_id.as_bytes());
            payload.extend_from_slice(&edge.successor_mesh_id.as_bytes());
        }
        payload.extend_from_slice(&self.signer_generation.to_be_bytes());
        payload
    }

    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"designate-federation-successor");
        digest.bytes(&self.signing_payload());
        digest.bytes(&self.signature);
    }
}

/// Successor swarm's signed acceptance of an exact immutable designation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptFederationSuccessor {
    /// Existing designation identity.
    pub succession_id: FederationSuccessionId,
    /// Direct relationship carrying the agreement.
    pub relationship_id: FederationRelationshipId,
    /// Authority which signed the designation.
    pub retiring_mesh_id: MeshId,
    /// Swarm accepting recovery responsibility.
    pub successor_mesh_id: MeshId,
    /// Exact relationship authority fence.
    pub expected_authority_epoch: u64,
    /// Exact succession epoch.
    pub succession_epoch: u64,
    /// SHA-256 of the retiring swarm's signed designation payload.
    pub designation_digest: [u8; 32],
    /// Successor side's exact federation identity generation.
    pub signer_generation: u64,
    /// Successor side's Ed25519 signature over [`Self::signing_payload`].
    pub signature: [u8; 64],
}

impl AcceptFederationSuccessor {
    /// Returns canonical bytes signed by the successor swarm.
    #[must_use]
    pub fn signing_payload(self) -> Vec<u8> {
        let mut payload = common_payload(
            b"meshspan.federation.successor-acceptance.v1",
            self.succession_id,
            self.relationship_id,
            self.retiring_mesh_id,
            self.successor_mesh_id,
            self.expected_authority_epoch,
            self.succession_epoch,
        );
        payload.extend_from_slice(&self.designation_digest);
        payload.extend_from_slice(&self.signer_generation.to_be_bytes());
        payload
    }

    pub(crate) fn update_digest(self, digest: &mut CanonicalDigest) {
        digest.bytes(b"accept-federation-successor");
        digest.bytes(&self.signing_payload());
        digest.bytes(&self.signature);
    }
}

/// Explicit local recovery decision activating an already two-sided succession.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivateFederationSuccessor {
    /// Accepted designation identity.
    pub succession_id: FederationSuccessionId,
    /// Direct relationship carrying the agreement.
    pub relationship_id: FederationRelationshipId,
    /// Permanently lost authority being fenced.
    pub retiring_mesh_id: MeshId,
    /// Local successor taking authority.
    pub successor_mesh_id: MeshId,
    /// Exact relationship authority fence.
    pub expected_authority_epoch: u64,
    /// Exact succession epoch.
    pub succession_epoch: u64,
    /// Exact designation payload digest.
    pub designation_digest: [u8; 32],
    /// Exact acceptance payload digest.
    pub acceptance_digest: [u8; 32],
    /// Bounded human audit explanation for declaring permanent loss.
    pub reason: String,
}

/// Retiring swarm's signed cancellation before a successor becomes active.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeFederationSuccessorDesignation {
    /// Existing designation identity.
    pub succession_id: FederationSuccessionId,
    /// Direct relationship carrying the agreement.
    pub relationship_id: FederationRelationshipId,
    /// Authority which originally designated the successor.
    pub retiring_mesh_id: MeshId,
    /// Designated successor whose dormant authority is cancelled.
    pub successor_mesh_id: MeshId,
    /// Exact relationship authority fence.
    pub expected_authority_epoch: u64,
    /// Exact succession epoch.
    pub succession_epoch: u64,
    /// Exact immutable designation payload digest.
    pub designation_digest: [u8; 32],
    /// Retiring side's current federation identity generation.
    pub signer_generation: u64,
    /// Bounded audit explanation.
    pub reason: String,
    /// Retiring side's Ed25519 signature over [`Self::signing_payload`].
    pub signature: [u8; 64],
}

impl RevokeFederationSuccessorDesignation {
    /// Returns canonical bytes signed by the retiring swarm.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = common_payload(
            b"meshspan.federation.successor-revocation.v1",
            self.succession_id,
            self.relationship_id,
            self.retiring_mesh_id,
            self.successor_mesh_id,
            self.expected_authority_epoch,
            self.succession_epoch,
        );
        payload.extend_from_slice(&self.designation_digest);
        append_bytes(&mut payload, self.reason.as_bytes());
        payload.extend_from_slice(&self.signer_generation.to_be_bytes());
        payload
    }

    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"revoke-federation-successor-designation");
        digest.bytes(&self.signing_payload());
        digest.bytes(&self.signature);
    }
}

impl ActivateFederationSuccessor {
    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"activate-federation-successor");
        digest.identifier(self.succession_id.as_bytes());
        digest.identifier(self.relationship_id.as_bytes());
        digest.identifier(self.retiring_mesh_id.as_bytes());
        digest.identifier(self.successor_mesh_id.as_bytes());
        digest.unsigned(self.expected_authority_epoch);
        digest.unsigned(self.succession_epoch);
        digest.bytes(&self.designation_digest);
        digest.bytes(&self.acceptance_digest);
        digest.bytes(self.reason.as_bytes());
    }
}

fn common_payload(
    domain: &[u8],
    succession_id: FederationSuccessionId,
    relationship_id: FederationRelationshipId,
    retiring_mesh_id: MeshId,
    successor_mesh_id: MeshId,
    authority_epoch: u64,
    succession_epoch: u64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(144);
    payload.extend_from_slice(domain);
    payload.extend_from_slice(&succession_id.as_bytes());
    payload.extend_from_slice(&relationship_id.as_bytes());
    payload.extend_from_slice(&retiring_mesh_id.as_bytes());
    payload.extend_from_slice(&successor_mesh_id.as_bytes());
    payload.extend_from_slice(&authority_epoch.to_be_bytes());
    payload.extend_from_slice(&succession_epoch.to_be_bytes());
    payload
}

fn append_bytes(payload: &mut Vec<u8>, value: &[u8]) {
    payload.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    payload.extend_from_slice(value);
}
