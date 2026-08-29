// SPDX-License-Identifier: GPL-2.0-only

//! Exact boundary from durable filesystem reachability evidence to a replicated cleanup proposal.

use ed25519_dalek::{Signer, SigningKey};
use meshspan_contracts::{RemovalPermit, StoragePermitMacKey, removal_permit_mac};
use meshspan_domain::{DurationMicros, MeshId, NodeId, OperationId, Revision, UnixMicros};
use meshspan_filesystem::VersionUnreachableProof;
use meshspan_metadata::{
    AttestVersionCleanup, AuthoritativeCommand, IssueVersionCleanupPermit,
    MAXIMUM_VERSION_CLEANUP_PERMIT_LIFETIME, ProposeVersionCleanup, VersionCleanupAttestation,
    VersionCleanupPermitAuthority,
};

/// Stable local construction failures before a cleanup attestation enters consensus.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum CleanupAttestationError {
    /// Cleanup revision, node incarnation and key generation must all be positive.
    #[error("cleanup attestation fence is invalid")]
    InvalidFence,
}

/// Stable local rejection before a removal-permit attempt enters consensus.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum CleanupPermitError {
    /// The attempt sequence, epoch, operation identity or lifetime is not current and bounded.
    #[error("cleanup removal-permit authority is invalid")]
    InvalidAuthority,
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
        retained_root_set_digest: proof.root_set_digest,
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

/// Constructs and MACs one exact short-lived permit attempt from repository-issued authority.
///
/// The returned command remains inert until its exact catalogue revision is committed. A lost
/// response is resolved through the metadata operation record instead of regenerating authority.
///
/// # Errors
///
/// Rejects zero or stale epochs, invalid operation identity, zero/excessive lifetime and overflow.
pub fn version_cleanup_removal_permit(
    authority: VersionCleanupPermitAuthority,
    mesh_id: MeshId,
    permit_operation_id: OperationId,
    authority_epoch: u64,
    issued_at: UnixMicros,
    lifetime: DurationMicros,
    key: &StoragePermitMacKey,
) -> Result<AuthoritativeCommand, CleanupPermitError> {
    if authority_epoch == 0
        || authority_epoch < authority.previous_authority_epoch
        || lifetime.get() == 0
        || lifetime > MAXIMUM_VERSION_CLEANUP_PERMIT_LIFETIME
        || permit_operation_id == authority.cleanup_operation_id
        || (authority.attempt_sequence == 1
            && permit_operation_id != authority.item.removal_operation_id)
        || (authority_epoch == authority.previous_authority_epoch
            && authority
                .previous_expires_at
                .is_some_and(|expires_at| expires_at > issued_at))
    {
        return Err(CleanupPermitError::InvalidAuthority);
    }
    let expires_at = issued_at
        .checked_add(lifetime)
        .ok_or(CleanupPermitError::InvalidAuthority)?;
    let mut permit = RemovalPermit {
        operation_id: permit_operation_id,
        mesh_id,
        target_id: authority.item.target_id,
        shard: authority.item.shard,
        target_generation: authority.item.target_generation,
        authority_epoch,
        catalogue_revision: authority.issue_revision,
        expires_at,
        permit_digest: [0; 32],
    };
    permit.permit_digest = removal_permit_mac(key, permit);
    Ok(AuthoritativeCommand::IssueVersionCleanupPermit(
        IssueVersionCleanupPermit {
            cleanup_operation_id: authority.cleanup_operation_id,
            inventory_sealed_revision: authority.inventory_sealed_revision,
            item_index: authority.item.item_index,
            attempt_sequence: authority.attempt_sequence,
            permit,
        },
    ))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
    use meshspan_contracts::{ShardIdentity, StoragePermitMacKey, verify_removal_permit_mac};
    use meshspan_domain::{
        ContentManifestId, DurationMicros, FileVersionId, MeshId, NodeId, OperationId, Revision,
        TargetId, UnixMicros, VolumeId,
    };
    use meshspan_filesystem::VersionUnreachableProof;
    use meshspan_metadata::{
        AuthoritativeCommand, VersionCleanupItem, VersionCleanupPermitAuthority,
    };

    use super::{
        CleanupPermitError, version_cleanup_attestation, version_cleanup_proposal,
        version_cleanup_removal_permit,
    };

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
            root_set_digest: [10; 32],
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
        assert_eq!(command.retained_root_set_digest, proof.root_set_digest);
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

    #[test]
    fn removal_permit_binds_exact_authority_and_rejects_unsafe_renewal()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = permit_authority()?;
        let key = StoragePermitMacKey::from_bytes([30; 32])?;
        let command = version_cleanup_removal_permit(
            authority,
            MeshId::from_bytes([31; 16])?,
            authority.item.removal_operation_id,
            5,
            UnixMicros::new(1_000),
            DurationMicros::new(60_000_000),
            &key,
        )?;
        let AuthoritativeCommand::IssueVersionCleanupPermit(command) = command else {
            return Err("wrong permit command".into());
        };
        assert_eq!(command.cleanup_operation_id, authority.cleanup_operation_id);
        assert_eq!(
            command.inventory_sealed_revision,
            authority.inventory_sealed_revision
        );
        assert_eq!(command.permit.catalogue_revision, authority.issue_revision);
        assert_eq!(command.permit.shard, authority.item.shard);
        assert_eq!(command.permit.target_id, authority.item.target_id);
        assert!(verify_removal_permit_mac(&key, command.permit));

        let mut renewing = authority;
        renewing.attempt_sequence = 2;
        renewing.previous_authority_epoch = 5;
        renewing.previous_expires_at = Some(UnixMicros::new(2_000));
        assert_eq!(
            version_cleanup_removal_permit(
                renewing,
                MeshId::from_bytes([31; 16])?,
                OperationId::from_bytes([32; 16])?,
                5,
                UnixMicros::new(1_500),
                DurationMicros::new(1),
                &key,
            ),
            Err(CleanupPermitError::InvalidAuthority)
        );
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
            root_set_digest: [10; 32],
            local_roots_digest: [10; 32],
            result_digest: [11; 32],
        })
    }

    fn permit_authority() -> Result<VersionCleanupPermitAuthority, Box<dyn std::error::Error>> {
        Ok(VersionCleanupPermitAuthority {
            cleanup_operation_id: OperationId::from_bytes([20; 16])?,
            inventory_sealed_revision: Revision::new(21),
            item: VersionCleanupItem {
                item_index: 0,
                removal_operation_id: OperationId::from_bytes([22; 16])?,
                shard: ShardIdentity {
                    manifest_digest: [23; 32],
                    stripe_index: 24,
                    shard_index: 25,
                    generation: 26,
                },
                target_id: TargetId::from_bytes([27; 16])?,
                target_generation: 28,
                revision: Revision::new(29),
            },
            issue_revision: Revision::new(30),
            attempt_sequence: 1,
            previous_authority_epoch: 0,
            previous_expires_at: None,
        })
    }
}
