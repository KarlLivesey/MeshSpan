// SPDX-License-Identifier: GPL-2.0-only

//! Signed provider accounting evidence preceding unused-quota reassignment.

use crate::{FederationStorageCapacitySeal, command::CanonicalDigest};
use meshspan_domain::MeshId;

/// Commits a provider-local seal, not permission to delete retained data.
/// The registered node attestation key signs a distinct capacity-seal domain;
/// a cleanup signature cannot substitute for this evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordFederationStorageSeal {
    /// Swarm which owns the allocation and its authoritative accounting.
    pub provider_mesh_id: MeshId,
    /// Durable local fence including all unresolved reservations.
    pub seal: FederationStorageCapacitySeal,
    /// Current admitted process incarnation of the provider.
    pub node_incarnation: u64,
    /// Current registered node cleanup-attestation key generation.
    pub key_generation: u64,
    /// Ed25519 signature over `signing_payload`.
    pub signature: [u8; 64],
}

impl RecordFederationStorageSeal {
    /// Canonical domain-separated bytes signed only after durable local sealing.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(192);
        bytes.extend_from_slice(b"meshspan.federation.storage-capacity-seal.v1\0");
        for id in [
            self.provider_mesh_id.as_bytes(),
            self.seal.allocation_id.as_bytes(),
            self.seal.provider_node_id.as_bytes(),
            self.seal.target_id.as_bytes(),
        ] {
            bytes.extend_from_slice(&id);
        }
        for value in [
            self.seal.target_generation,
            self.seal.ceiling_bytes,
            self.seal.sequence,
            self.node_incarnation,
            self.key_generation,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&self.seal.sealed_at.get().to_be_bytes());
        bytes
    }

    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(&self.signing_payload());
        digest.bytes(&self.signature);
    }
}
