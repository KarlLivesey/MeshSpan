// SPDX-License-Identifier: GPL-2.0-only

//! Administrator-approved, short-lived federation invitation records.

use crate::command::CanonicalDigest;
use meshspan_domain::{FederationRelationshipId, MeshId, NodeId, Revision, UnixMicros};

/// Retains a manager's exact outbound pairing intent before any remote side effect.
/// This grants no relationship or data authority and stores no invitation secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginFederationConnection {
    /// Relationship reserved by the remote invitation.
    pub relationship_id: FederationRelationshipId,
    /// Independent swarm that issued the invitation.
    pub inviting_mesh_id: MeshId,
    /// Verifier of the complete invitation, including its secret.
    pub material_verifier: [u8; 32],
    /// Pinned remote HTTPS origin.
    pub remote_endpoint: String,
    /// Exact remote HTTPS leaf fingerprint from the invitation.
    pub certificate_fingerprint: [u8; 32],
    /// Invitation's exclusive deadline.
    pub expires_at: UnixMicros,
    /// Immutable signed local peer sent on every retry.
    pub local: crate::SignedFederationPairingPeer,
}

impl BeginFederationConnection {
    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"begin-federation-connection-v1");
        digest.identifier(self.relationship_id.as_bytes());
        digest.identifier(self.inviting_mesh_id.as_bytes());
        digest.bytes(&self.material_verifier);
        digest.bytes(self.remote_endpoint.as_bytes());
        digest.bytes(&self.certificate_fingerprint);
        digest.signed(self.expires_at.get());
        self.local.peer.update_digest(digest);
        digest.bytes(&self.local.signature);
    }
}

/// Commits the two possession-proved sides and creates a horizontal relationship proposal.
/// Approval remains a distinct subsequent revision in the existing lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareFederationConnection {
    /// Exact invitation-reserved relationship.
    pub relationship_id: FederationRelationshipId,
    /// Swarm whose administrator issued the invitation.
    pub inviting_mesh_id: MeshId,
    /// Verifier binding both signed peers to the same invitation.
    pub material_verifier: [u8; 32],
    /// Required on the inviting side, absent on the accepting side.
    pub expected_invitation_revision: Option<Revision>,
    /// This node's signed public identity and endpoint.
    pub local: crate::SignedFederationPairingPeer,
    /// Other node's signed public identity and endpoint.
    pub remote: crate::SignedFederationPairingPeer,
}

impl PrepareFederationConnection {
    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"prepare-federation-connection-v1");
        digest.identifier(self.relationship_id.as_bytes());
        digest.identifier(self.inviting_mesh_id.as_bytes());
        digest.bytes(&self.material_verifier);
        digest.optional_revision(self.expected_invitation_revision);
        for signed in [&self.local, &self.remote] {
            signed.peer.update_digest(digest);
            digest.bytes(&signed.signature);
        }
    }
}

/// Records only a verifier and routing public data; never stores the connection secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueFederationPairingInvitation {
    /// Reserved relationship identity carried in the invitation.
    pub relationship_id: FederationRelationshipId,
    /// Gateway whose HTTPS certificate is pinned by the invitation.
    pub issuing_node_id: NodeId,
    /// Exact protected authentication-root generation used for reproducible issuance.
    pub issuance_key_generation: u64,
    /// Verifier of the complete canonical material, including its secret.
    pub material_verifier: [u8; 32],
    /// Exact pinned HTTPS origin, without a path, query or credentials.
    pub endpoint: String,
    /// SHA-256 of the issuing gateway's exact HTTPS leaf certificate.
    pub certificate_fingerprint: [u8; 32],
    /// Exclusive deadline, no more than one hour after the command's issuance instant.
    pub expires_at: UnixMicros,
}

/// Cancels unused material without changing any established relationship.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelFederationPairingInvitation {
    /// Exact outstanding invitation.
    pub relationship_id: FederationRelationshipId,
    /// Revision observed before cancellation.
    pub expected_invitation_revision: Revision,
    /// Human audit explanation.
    pub reason: String,
}

impl IssueFederationPairingInvitation {
    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"issue-federation-pairing-invitation-v1");
        digest.identifier(self.relationship_id.as_bytes());
        digest.identifier(self.issuing_node_id.as_bytes());
        digest.unsigned(self.issuance_key_generation);
        digest.bytes(&self.material_verifier);
        digest.bytes(self.endpoint.as_bytes());
        digest.bytes(&self.certificate_fingerprint);
        digest.signed(self.expires_at.get());
    }
}

impl CancelFederationPairingInvitation {
    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"cancel-federation-pairing-invitation-v1");
        digest.identifier(self.relationship_id.as_bytes());
        digest.unsigned(self.expected_invitation_revision.get());
        digest.bytes(self.reason.as_bytes());
    }
}
