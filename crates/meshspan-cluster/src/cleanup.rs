// SPDX-License-Identifier: GPL-2.0-only

//! Exact boundary from durable filesystem reachability evidence to a replicated cleanup proposal.

use ed25519_dalek::{Signer, SigningKey};
use meshspan_domain::{NodeId, OperationId, Revision};
use meshspan_filesystem::VersionUnreachableProof;
use meshspan_metadata::{
    AttestVersionCleanup, AuthoritativeCommand, ProposeVersionCleanup, VersionCleanupAttestation,
};

/// Stable local construction failures before a cleanup attestation enters consensus.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum CleanupAttestationError {
    /// Cleanup revision, node incarnation and key generation must all be positive.
    #[error("cleanup attestation fence is invalid")]
    InvalidFence,
}

/// Converts one terminal unreachable proof without dropping or inventing proposal fields.
#[must_use]
pub const fn version_cleanup_proposal(proof: VersionUnreachableProof) -> AuthoritativeCommand {
    AuthoritativeCommand::ProposeVersionCleanup(ProposeVersionCleanup {
        volume_id: proof.volume_id,
        version_id: proof.version_id,
        manifest_id: proof.manifest_id,
        manifest_root_digest: proof.manifest_root_digest,
        source_scan_operation_id: proof.operation_id,
        scan_request_digest: proof.scan_request_digest,
        reachability_subject_digest: proof.subject_digest,
        retention_policy_sequence: proof.retention_policy_sequence,
        reachability_revision: proof.metadata_revision,
        retained_root_count: proof.root_count,
        retained_root_digest: proof.root_digest,
        local_roots_digest: proof.local_roots_digest,
        proof_result_digest: proof.result_digest,
    })
}

/// Signs one node's exact terminal scan as an incarnation-fenced cleanup attestation.
///
/// # Errors
///
/// Rejects zero cleanup revisions, node incarnations and signing-key generations.
pub fn version_cleanup_attestation(
    proof: VersionUnreachableProof,
    cleanup_operation_id: OperationId,
    cleanup_revision: Revision,
    node_id: NodeId,
    node_incarnation: u64,
    key_generation: u64,
    signing_key: &SigningKey,
) -> Result<AuthoritativeCommand, CleanupAttestationError> {
    if cleanup_revision == Revision::ZERO || node_incarnation == 0 || key_generation == 0 {
        return Err(CleanupAttestationError::InvalidFence);
    }
    let mut attestation = VersionCleanupAttestation {
        cleanup_operation_id,
        cleanup_revision,
        node_id,
        node_incarnation,
        key_generation,
        scan_operation_id: proof.operation_id,
        scan_request_digest: proof.scan_request_digest,
        reachability_subject_digest: proof.subject_digest,
        local_roots_digest: proof.local_roots_digest,
        scan_result_digest: proof.result_digest,
        signature: [0; 64],
    };
    attestation.signature = signing_key.sign(&attestation.signing_digest()).to_bytes();
    Ok(AuthoritativeCommand::AttestVersionCleanup(
        AttestVersionCleanup { attestation },
    ))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
    use meshspan_domain::{
        ContentManifestId, FileVersionId, NodeId, OperationId, Revision, VolumeId,
    };
    use meshspan_filesystem::VersionUnreachableProof;
    use meshspan_metadata::AuthoritativeCommand;

    use super::{version_cleanup_attestation, version_cleanup_proposal};

    #[test]
    fn every_unreachable_proof_field_crosses_the_proposal_boundary_exactly()
    -> Result<(), Box<dyn std::error::Error>> {
        let proof = VersionUnreachableProof {
            operation_id: OperationId::from_bytes([1; 16])?,
            volume_id: VolumeId::from_bytes([2; 16])?,
            version_id: FileVersionId::from_bytes([3; 16])?,
            manifest_id: ContentManifestId::from_bytes([4; 16])?,
            manifest_root_digest: [19; 32],
            scan_request_digest: [5; 32],
            subject_digest: [12; 32],
            retention_policy_sequence: 6,
            metadata_revision: Revision::new(7),
            root_count: 8,
            root_digest: [9; 32],
            local_roots_digest: [10; 32],
            result_digest: [11; 32],
        };
        let AuthoritativeCommand::ProposeVersionCleanup(command) = version_cleanup_proposal(proof)
        else {
            return Err("wrong cleanup command".into());
        };
        assert_eq!(command.volume_id, proof.volume_id);
        assert_eq!(command.version_id, proof.version_id);
        assert_eq!(command.manifest_id, proof.manifest_id);
        assert_eq!(command.manifest_root_digest, proof.manifest_root_digest);
        assert_eq!(command.source_scan_operation_id, proof.operation_id);
        assert_eq!(command.scan_request_digest, proof.scan_request_digest);
        assert_eq!(command.reachability_subject_digest, proof.subject_digest);
        assert_eq!(
            command.retention_policy_sequence,
            proof.retention_policy_sequence
        );
        assert_eq!(command.reachability_revision, proof.metadata_revision);
        assert_eq!(command.retained_root_count, proof.root_count);
        assert_eq!(command.retained_root_digest, proof.root_digest);
        assert_eq!(command.local_roots_digest, proof.local_roots_digest);
        assert_eq!(command.proof_result_digest, proof.result_digest);
        Ok(())
    }

    #[test]
    fn every_local_proof_field_is_signed_into_the_node_attestation()
    -> Result<(), Box<dyn std::error::Error>> {
        let proof = proof()?;
        let signing_key = SigningKey::from_bytes(&[13; 32]);
        let command = version_cleanup_attestation(
            proof,
            OperationId::from_bytes([14; 16])?,
            Revision::new(15),
            NodeId::from_bytes([16; 16])?,
            17,
            18,
            &signing_key,
        )?;
        let AuthoritativeCommand::AttestVersionCleanup(command) = command else {
            return Err("wrong cleanup attestation command".into());
        };
        let attestation = command.attestation;
        assert_eq!(attestation.scan_operation_id, proof.operation_id);
        assert_eq!(attestation.scan_request_digest, proof.scan_request_digest);
        assert_eq!(
            attestation.reachability_subject_digest,
            proof.subject_digest
        );
        assert_eq!(attestation.local_roots_digest, proof.local_roots_digest);
        assert_eq!(attestation.scan_result_digest, proof.result_digest);
        VerifyingKey::from(&signing_key).verify_strict(
            &attestation.signing_digest(),
            &Signature::from_bytes(&attestation.signature),
        )?;
        Ok(())
    }

    fn proof() -> Result<VersionUnreachableProof, meshspan_domain::IdentifierError> {
        Ok(VersionUnreachableProof {
            operation_id: OperationId::from_bytes([1; 16])?,
            volume_id: VolumeId::from_bytes([2; 16])?,
            version_id: FileVersionId::from_bytes([3; 16])?,
            manifest_id: ContentManifestId::from_bytes([4; 16])?,
            manifest_root_digest: [19; 32],
            scan_request_digest: [5; 32],
            subject_digest: [12; 32],
            retention_policy_sequence: 6,
            metadata_revision: Revision::new(7),
            root_count: 8,
            root_digest: [9; 32],
            local_roots_digest: [10; 32],
            result_digest: [11; 32],
        })
    }
}
