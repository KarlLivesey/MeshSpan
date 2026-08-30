// SPDX-License-Identifier: GPL-2.0-only

//! Signed acknowledgement of one remotely accepted federated mutation.

use crate::{FederatedMutationEvidence, FederationResourceScope, OperationId};

/// Durable proof that a principal's home swarm accepted one exact immutable mutation.
///
/// The signature binds the complete grant-use evidence to the source operation and immutable
/// payload. The receiving swarm must still classify the evidence against its retained authority
/// history and validate that the payload actually exercises the declared rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederatedMutationAcknowledgement {
    /// Remote operation identity which produced the immutable payload.
    pub source_operation_id: OperationId,
    /// Exact historical grant-use evidence observed by the accepting swarm.
    pub evidence: FederatedMutationEvidence,
    /// Digest of the complete immutable mutation payload.
    pub payload_digest: [u8; 32],
    /// Accepting swarm trust-identity generation which signed this acknowledgement.
    pub signer_generation: u64,
    /// Accepting swarm Ed25519 signature over [`Self::signing_payload`].
    pub signature: [u8; 64],
}

impl FederatedMutationAcknowledgement {
    /// Returns the canonical bytes signed by the accepting swarm.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(224);
        payload.extend_from_slice(b"meshspan.federation.mutation-acknowledgement.v1");
        payload.extend_from_slice(&self.source_operation_id.as_bytes());
        append_evidence(&mut payload, self.evidence);
        payload.extend_from_slice(&self.payload_digest);
        payload.extend_from_slice(&self.signer_generation.to_be_bytes());
        payload
    }
}

fn append_evidence(payload: &mut Vec<u8>, evidence: FederatedMutationEvidence) {
    payload.extend_from_slice(&evidence.grant_id().as_bytes());
    payload.extend_from_slice(&evidence.relationship_id().as_bytes());
    payload.extend_from_slice(&evidence.actor().home_mesh_id().as_bytes());
    payload.extend_from_slice(&evidence.actor().principal_id().as_bytes());
    payload.extend_from_slice(&evidence.accepting_mesh_id().as_bytes());
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
