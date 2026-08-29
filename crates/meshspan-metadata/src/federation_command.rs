// SPDX-License-Identifier: GPL-2.0-only

//! Typed authoritative commands for one federation relationship lifecycle.

use meshspan_domain::{FederationRelationshipId, FederationRelationshipKind, MeshId, UnixMicros};

use crate::{RecordName, command::CanonicalDigest};

/// Which side of a relationship controls one public trust identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationIdentityOwner {
    /// This swarm's presented identity.
    Local,
    /// The autonomous peer's presented identity.
    Remote,
}

impl FederationIdentityOwner {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Local => 1,
            Self::Remote => 2,
        }
    }
}

/// Direction of bounded governance from this swarm's local perspective.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationGovernanceDirection {
    /// Horizontal peers; neither governs the other.
    None,
    /// This swarm governs the remote swarm within delegated authority.
    LocalGovernsRemote,
    /// The remote swarm governs this swarm within delegated authority.
    RemoteGovernsLocal,
}

impl FederationGovernanceDirection {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::LocalGovernsRemote => 1,
            Self::RemoteGovernsLocal => 2,
        }
    }
}

/// One bounded public identity; its private key never enters replicated metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationTrustIdentity {
    /// Monotonic generation controlled independently by the identity owner.
    pub generation: u64,
    /// SHA-256 fingerprint of the exact presented certificate.
    pub certificate_fingerprint: [u8; 32],
    /// Ed25519 verification key used for signed federation envelopes.
    pub verifying_key: [u8; 32],
    /// First valid authoritative instant, inclusive.
    pub valid_from: UnixMicros,
    /// Expiry authoritative instant, exclusive.
    pub valid_until: UnixMicros,
}

/// Starts an inactive, mutually identifiable relationship proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposeFederationRelationship {
    /// Stable relationship identity.
    pub relationship_id: FederationRelationshipId,
    /// Autonomous peer swarm identity.
    pub remote_mesh_id: MeshId,
    /// Human-facing peer name, never used as authority.
    pub remote_name: RecordName,
    /// Horizontal or hierarchical relationship class.
    pub kind: FederationRelationshipKind,
    /// Governance direction, which must agree with `kind`.
    pub governance_direction: FederationGovernanceDirection,
}

/// Activates a proposal and atomically installs both initial trust identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApproveFederationRelationship {
    /// Existing proposed relationship.
    pub relationship_id: FederationRelationshipId,
    /// Expected current authority epoch.
    pub expected_authority_epoch: u64,
    /// This swarm's initial public identity.
    pub local_identity: FederationTrustIdentity,
    /// Remote swarm's independently verified public identity.
    pub remote_identity: FederationTrustIdentity,
}

/// Replaces one side's active public identity without losing verification history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RotateFederationTrustIdentity {
    /// Existing approved relationship.
    pub relationship_id: FederationRelationshipId,
    /// Expected current relationship authority epoch.
    pub expected_authority_epoch: u64,
    /// Side whose identity is rotating.
    pub owner: FederationIdentityOwner,
    /// Strictly newer public identity.
    pub identity: FederationTrustIdentity,
}

/// Narrows an active relationship and fences every older authority envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestrictFederationRelationship {
    /// Existing active or already restricted relationship.
    pub relationship_id: FederationRelationshipId,
    /// Exact epoch being replaced.
    pub expected_authority_epoch: u64,
    /// Strictly newer epoch.
    pub authority_epoch: u64,
    /// Bounded audit explanation.
    pub reason: String,
}

/// Restores a restricted relationship under a strictly newer authority fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverFederationRelationship {
    /// Existing restricted relationship.
    pub relationship_id: FederationRelationshipId,
    /// Exact epoch being replaced.
    pub expected_authority_epoch: u64,
    /// Strictly newer epoch.
    pub authority_epoch: u64,
    /// Bounded audit explanation.
    pub reason: String,
}

/// Immediately revokes a proposal or live relationship at a newer epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeFederationRelationship {
    /// Existing non-retired relationship.
    pub relationship_id: FederationRelationshipId,
    /// Exact epoch being replaced.
    pub expected_authority_epoch: u64,
    /// Strictly newer epoch.
    pub authority_epoch: u64,
    /// Bounded audit explanation.
    pub reason: String,
}

/// Retires already revoked relationship metadata without deleting history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetireFederationRelationship {
    /// Existing revoked relationship.
    pub relationship_id: FederationRelationshipId,
    /// Exact current authority epoch.
    pub expected_authority_epoch: u64,
    /// Strictly newer final fence.
    pub authority_epoch: u64,
    /// Bounded audit explanation.
    pub reason: String,
}

macro_rules! update_digest {
    ($type:ty, $tag:literal, |$value:ident, $digest:ident| $body:block) => {
        impl $type {
            pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
                let $value = self;
                let $digest = digest;
                $digest.bytes($tag);
                $body
            }
        }
    };
}

update_digest!(
    ProposeFederationRelationship,
    b"propose-federation-relationship",
    |value, digest| {
        digest.identifier(value.relationship_id.as_bytes());
        digest.identifier(value.remote_mesh_id.as_bytes());
        digest.name(&value.remote_name);
        digest.byte(match value.kind {
            FederationRelationshipKind::Horizontal => 1,
            FederationRelationshipKind::Governance => 2,
        });
        digest.byte(value.governance_direction.code());
    }
);
update_digest!(
    ApproveFederationRelationship,
    b"approve-federation-relationship",
    |value, digest| {
        digest.identifier(value.relationship_id.as_bytes());
        digest.unsigned(value.expected_authority_epoch);
        digest.trust_identity(value.local_identity);
        digest.trust_identity(value.remote_identity);
    }
);
update_digest!(
    RotateFederationTrustIdentity,
    b"rotate-federation-trust-identity",
    |value, digest| {
        digest.identifier(value.relationship_id.as_bytes());
        digest.unsigned(value.expected_authority_epoch);
        digest.byte(value.owner.code());
        digest.trust_identity(value.identity);
    }
);

macro_rules! relationship_transition_digest {
    ($type:ty, $tag:literal, $new_epoch:expr) => {
        update_digest!($type, $tag, |value, digest| {
            digest.identifier(value.relationship_id.as_bytes());
            digest.unsigned(value.expected_authority_epoch);
            if $new_epoch {
                digest.unsigned(value.authority_epoch);
            }
            digest.bytes(value.reason.as_bytes());
        });
    };
}

relationship_transition_digest!(RestrictFederationRelationship, b"restrict-federation", true);
relationship_transition_digest!(RecoverFederationRelationship, b"recover-federation", true);
relationship_transition_digest!(RevokeFederationRelationship, b"revoke-federation", true);
relationship_transition_digest!(RetireFederationRelationship, b"retire-federation", true);
