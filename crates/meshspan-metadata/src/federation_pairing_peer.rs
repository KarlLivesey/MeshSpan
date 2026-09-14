// SPDX-License-Identifier: GPL-2.0-only

//! Public, possession-proved identity and routing for one side of a pairing.

use crate::{FederationTrustIdentity, RecordName, command::CanonicalDigest};
use ed25519_dalek::{Signature, VerifyingKey};
use meshspan_domain::{FederationRelationshipId, MeshId, NodeId, UnixMicros};
use sha2::{Digest, Sha256};

/// Public node-owned identity offered to a specific other swarm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationPairingPeer {
    /// Autonomous swarm, never a local consensus member.
    pub mesh_id: MeshId,
    /// Node retaining the private federation identity.
    pub node_id: NodeId,
    /// Display name only, never an authority identifier.
    pub name: RecordName,
    /// HTTPS origin; the dedicated federation QUIC listener uses the same UDP address/port.
    pub endpoint: String,
    /// Exact public TLS leaf, pinned independently of the issuing public HTTPS certificate.
    pub certificate_der: Vec<u8>,
    /// Public Ed25519 identity used by the existing federation protocol.
    pub verifying_key: [u8; 32],
    /// Inclusive identity validity.
    pub valid_from: UnixMicros,
    /// Exclusive identity expiry.
    pub valid_until: UnixMicros,
}

/// Proof of possession bound to one invitation and exact peer description.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedFederationPairingPeer {
    /// Public identity and route covered by the proof.
    pub peer: FederationPairingPeer,
    /// Ed25519 signature, never a user or node enrolment credential.
    pub signature: [u8; 64],
}

impl FederationPairingPeer {
    /// Returns the exact domain-separated statement signed during pairing.
    #[must_use]
    pub fn pairing_digest(
        &self,
        relationship: FederationRelationshipId,
        inviter: MeshId,
        verifier: [u8; 32],
    ) -> [u8; 32] {
        let mut digest = CanonicalDigest::new(b"meshspan.federation.pairing.peer.v1");
        digest.identifier(relationship.as_bytes());
        digest.identifier(inviter.as_bytes());
        digest.bytes(&verifier);
        self.update_digest(&mut digest);
        digest.finish()
    }

    /// Projects the public identity into the established relationship's existing generation model.
    #[must_use]
    pub fn trust_identity(&self) -> FederationTrustIdentity {
        FederationTrustIdentity {
            generation: 1,
            certificate_fingerprint: Sha256::digest(&self.certificate_der).into(),
            verifying_key: self.verifying_key,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
        }
    }

    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.identifier(self.mesh_id.as_bytes());
        digest.identifier(self.node_id.as_bytes());
        digest.bytes(self.name.display().as_bytes());
        digest.bytes(self.endpoint.as_bytes());
        digest.bytes(&self.certificate_der);
        digest.bytes(&self.verifying_key);
        digest.signed(self.valid_from.get());
        digest.signed(self.valid_until.get());
    }
}

impl SignedFederationPairingPeer {
    /// Verifies the key holder's exact invitation-scoped statement and its current lifetime.
    #[must_use]
    pub fn verify(
        &self,
        relationship: FederationRelationshipId,
        inviter: MeshId,
        verifier: [u8; 32],
        now: UnixMicros,
    ) -> bool {
        let peer = &self.peer;
        if peer.valid_from.get() < 0
            || now.get() < peer.valid_from.get()
            || now.get() >= peer.valid_until.get()
            || peer.certificate_der.len() > 16 * 1024
            || peer.certificate_der.len() < 64
            || peer.certificate_der.first() != Some(&0x30)
            || verifier == [0; 32]
            || peer.endpoint.len() > 512
        {
            return false;
        }
        let Ok(key) = VerifyingKey::from_bytes(&peer.verifying_key) else {
            return false;
        };
        if key.is_weak() {
            return false;
        }
        if !meshspan_domain::is_valid_federation_endpoint(&peer.endpoint) {
            return false;
        }
        key.verify_strict(
            &federation_pairing_signing_message(peer.pairing_digest(
                relationship,
                inviter,
                verifier,
            )),
            &Signature::from_bytes(&self.signature),
        )
        .is_ok()
    }
}

/// Domain-separated bytes consumed by the node-local signing capability.
#[must_use]
pub fn federation_pairing_signing_message(digest: [u8; 32]) -> Vec<u8> {
    let mut message = b"meshspan.federation.pairing.signature.v1\0".to_vec();
    message.extend_from_slice(&digest);
    message
}
