// SPDX-License-Identifier: GPL-2.0-only

//! Typed commands for immutable, invisible federated mutation quarantine.

use meshspan_domain::{
    FederatedMutationEvidence, FederationResourceScope, OperationId, QuarantineId,
};

use crate::command::CanonicalDigest;

/// Retains one remote-acknowledged mutation which authoritative replay classifies as inadmissible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainFederatedMutationQuarantine {
    /// Stable quarantine identity.
    pub quarantine_id: QuarantineId,
    /// Remote operation identity which produced the immutable payload.
    pub source_operation_id: OperationId,
    /// Exact untrusted historical grant-use evidence, reclassified by the repository.
    pub evidence: FederatedMutationEvidence,
    /// Digest of the immutable branch/object payload retained outside the namespace.
    pub payload_digest: [u8; 32],
    /// Accepting swarm trust-identity generation which signed the acknowledgement.
    pub signer_generation: u64,
    /// Accepting swarm Ed25519 signature over [`Self::signing_payload`].
    pub signature: [u8; 64],
}

impl RetainFederatedMutationQuarantine {
    /// Returns the canonical acknowledgement bytes signed by the accepting swarm.
    #[must_use]
    pub fn signing_payload(self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(224);
        payload.extend_from_slice(b"meshspan.federation.quarantine-acknowledgement.v1");
        payload.extend_from_slice(&self.quarantine_id.as_bytes());
        payload.extend_from_slice(&self.source_operation_id.as_bytes());
        append_evidence(&mut payload, self.evidence);
        payload.extend_from_slice(&self.payload_digest);
        payload.extend_from_slice(&self.signer_generation.to_be_bytes());
        payload
    }

    pub(crate) fn update_digest(self, digest: &mut CanonicalDigest) {
        digest.bytes(b"retain-federated-mutation-quarantine");
        digest.bytes(&self.signing_payload());
        digest.bytes(&self.signature);
    }
}

/// Marks retained quarantine as visible to authorised recovery administration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceFederatedMutationQuarantine {
    /// Existing retained quarantine identity.
    pub quarantine_id: QuarantineId,
    /// Exact source operation used as a substitution fence.
    pub source_operation_id: OperationId,
}

impl SurfaceFederatedMutationQuarantine {
    pub(crate) fn update_digest(self, digest: &mut CanonicalDigest) {
        digest.bytes(b"surface-federated-mutation-quarantine");
        digest.identifier(self.quarantine_id.as_bytes());
        digest.identifier(self.source_operation_id.as_bytes());
    }
}

/// Authorised terminal recovery choice after quarantine has been surfaced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationQuarantineResolution {
    /// Reapply the immutable mutation as a newly authorised operation.
    Restore,
    /// Preserve current namespace state and publish recovered content as a logical copy.
    RestoreAsCopy,
    /// Retain the audit proof but permit payload reclamation.
    Discard,
}

impl FederationQuarantineResolution {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Restore => 1,
            Self::RestoreAsCopy => 2,
            Self::Discard => 3,
        }
    }
}

/// Resolves surfaced quarantine without directly publishing or erasing content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveFederatedMutationQuarantine {
    /// Existing surfaced quarantine identity.
    pub quarantine_id: QuarantineId,
    /// Exact source operation used as a substitution fence.
    pub source_operation_id: OperationId,
    /// Recovery action authorised for later filesystem execution.
    pub resolution: FederationQuarantineResolution,
    /// Bounded human audit explanation.
    pub reason: String,
}

impl ResolveFederatedMutationQuarantine {
    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"resolve-federated-mutation-quarantine");
        digest.identifier(self.quarantine_id.as_bytes());
        digest.identifier(self.source_operation_id.as_bytes());
        digest.byte(self.resolution.code());
        digest.bytes(self.reason.as_bytes());
    }
}

fn append_evidence(payload: &mut Vec<u8>, evidence: FederatedMutationEvidence) {
    payload.extend_from_slice(&evidence.grant_id().as_bytes());
    payload.extend_from_slice(&evidence.relationship_id().as_bytes());
    payload.extend_from_slice(&evidence.subject().home_mesh_id().as_bytes());
    payload.extend_from_slice(&evidence.subject().principal_id().as_bytes());
    append_resource(payload, evidence.resource());
    payload.extend_from_slice(&evidence.authority_epoch().to_be_bytes());
    payload.extend_from_slice(&evidence.accepted_at().get().to_be_bytes());
    payload.extend_from_slice(&evidence.required_rights().bits().to_be_bytes());
    payload.extend_from_slice(&evidence.storage_bytes().to_be_bytes());
}

fn append_resource(payload: &mut Vec<u8>, resource: FederationResourceScope) {
    match resource {
        FederationResourceScope::Volume {
            owner_mesh_id,
            volume_id,
        } => {
            payload.push(1);
            payload.extend_from_slice(&owner_mesh_id.as_bytes());
            payload.extend_from_slice(&volume_id.as_bytes());
        }
        FederationResourceScope::Subtree {
            owner_mesh_id,
            volume_id,
            root_object_id,
        } => {
            payload.push(2);
            payload.extend_from_slice(&owner_mesh_id.as_bytes());
            payload.extend_from_slice(&volume_id.as_bytes());
            payload.extend_from_slice(&root_object_id.as_bytes());
        }
        FederationResourceScope::File {
            owner_mesh_id,
            volume_id,
            object_id,
        } => {
            payload.push(3);
            payload.extend_from_slice(&owner_mesh_id.as_bytes());
            payload.extend_from_slice(&volume_id.as_bytes());
            payload.extend_from_slice(&object_id.as_bytes());
        }
        FederationResourceScope::StorageCapacity { provider_mesh_id } => {
            payload.push(4);
            payload.extend_from_slice(&provider_mesh_id.as_bytes());
        }
    }
}
