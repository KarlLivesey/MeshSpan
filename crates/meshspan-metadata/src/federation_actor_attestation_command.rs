// SPDX-License-Identifier: GPL-2.0-only

//! Signed home-swarm actor lifecycle attestations used by federation admission.

use meshspan_domain::{FederationRelationshipId, MeshId, PrincipalId};

use crate::{RecordName, command::CanonicalDigest};

/// Closed remote principal families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederatedActorKind {
    /// Interactive or service user.
    User,
    /// Nested identity group.
    Group,
    /// Non-interactive service principal.
    Service,
}

impl FederatedActorKind {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::User => 1,
            Self::Group => 2,
            Self::Service => 3,
        }
    }
}

/// Closed home-swarm actor lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederatedActorState {
    /// May authenticate and receive authority.
    Active,
    /// Temporarily disabled by its home swarm.
    Suspended,
    /// Terminal historical identity.
    Retired,
}

impl FederatedActorState {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Active => 1,
            Self::Suspended => 2,
            Self::Retired => 3,
        }
    }
}

/// One signed, monotonic remote-actor lifecycle statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordFederatedActorAttestation {
    /// Direct relationship carrying the statement.
    pub relationship_id: FederationRelationshipId,
    /// Autonomous swarm which owns and authenticates the principal.
    pub home_mesh_id: MeshId,
    /// Principal identity inside its home swarm.
    pub principal_id: PrincipalId,
    /// User, group or service.
    pub kind: FederatedActorKind,
    /// Display/canonical names supplied by the home swarm.
    pub name: RecordName,
    /// Current home-swarm lifecycle.
    pub state: FederatedActorState,
    /// Strictly monotonic home-swarm identity revision.
    pub identity_revision: u64,
    /// Exact current federation authority epoch.
    pub authority_epoch: u64,
    /// Remote trust-identity generation which signed the statement.
    pub signer_generation: u64,
    /// Ed25519 signature over `signing_payload`.
    pub signature: [u8; 64],
}

impl RecordFederatedActorAttestation {
    /// Returns canonical bytes signed by the home swarm.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(160);
        payload.extend_from_slice(b"meshspan.federation.actor-attestation.v1");
        payload.extend_from_slice(&self.relationship_id.as_bytes());
        payload.extend_from_slice(&self.home_mesh_id.as_bytes());
        payload.extend_from_slice(&self.principal_id.as_bytes());
        payload.push(self.kind.code());
        append_bytes(&mut payload, self.name.display().as_bytes());
        append_bytes(&mut payload, self.name.canonical().as_bytes());
        payload.push(self.state.code());
        payload.extend_from_slice(&self.identity_revision.to_be_bytes());
        payload.extend_from_slice(&self.authority_epoch.to_be_bytes());
        payload.extend_from_slice(&self.signer_generation.to_be_bytes());
        payload
    }

    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"upsert-federated-actor-attestation");
        digest.bytes(&self.signing_payload());
        digest.bytes(&self.signature);
    }
}

fn append_bytes(payload: &mut Vec<u8>, value: &[u8]) {
    payload.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    payload.extend_from_slice(value);
}
