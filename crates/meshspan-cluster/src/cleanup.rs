// SPDX-License-Identifier: GPL-2.0-only

//! Exact boundary from durable filesystem reachability evidence to a replicated cleanup proposal.

use meshspan_filesystem::VersionUnreachableProof;
use meshspan_metadata::{AuthoritativeCommand, ProposeVersionCleanup};

/// Converts one terminal unreachable proof without dropping or inventing proposal fields.
#[must_use]
pub const fn version_cleanup_proposal(proof: VersionUnreachableProof) -> AuthoritativeCommand {
    AuthoritativeCommand::ProposeVersionCleanup(ProposeVersionCleanup {
        volume_id: proof.volume_id,
        version_id: proof.version_id,
        manifest_id: proof.manifest_id,
        source_scan_operation_id: proof.operation_id,
        scan_request_digest: proof.scan_request_digest,
        retention_policy_sequence: proof.retention_policy_sequence,
        reachability_revision: proof.metadata_revision,
        retained_root_count: proof.root_count,
        retained_root_digest: proof.root_digest,
        local_roots_digest: proof.local_roots_digest,
        proof_result_digest: proof.result_digest,
    })
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{ContentManifestId, FileVersionId, OperationId, Revision, VolumeId};
    use meshspan_filesystem::VersionUnreachableProof;
    use meshspan_metadata::AuthoritativeCommand;

    use super::version_cleanup_proposal;

    #[test]
    fn every_unreachable_proof_field_crosses_the_proposal_boundary_exactly()
    -> Result<(), Box<dyn std::error::Error>> {
        let proof = VersionUnreachableProof {
            operation_id: OperationId::from_bytes([1; 16])?,
            volume_id: VolumeId::from_bytes([2; 16])?,
            version_id: FileVersionId::from_bytes([3; 16])?,
            manifest_id: ContentManifestId::from_bytes([4; 16])?,
            scan_request_digest: [5; 32],
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
        assert_eq!(command.source_scan_operation_id, proof.operation_id);
        assert_eq!(command.scan_request_digest, proof.scan_request_digest);
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
}
