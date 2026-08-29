// SPDX-License-Identifier: GPL-2.0-only

//! Exact boundary from durable filesystem reachability evidence to a replicated cleanup proposal.

use ed25519_dalek::{Signer, SigningKey};
use meshspan_contracts::{
    RemovalPermit, StoragePermitMacKey, TombstoneReceipt, removal_permit_mac,
    tombstone_receipt_digest,
};
use meshspan_domain::{DurationMicros, MeshId, NodeId, OperationId, Revision, UnixMicros};
use meshspan_filesystem::{VersionCleanupRetirementAuthority, VersionUnreachableProof};
use meshspan_metadata::{
    AttestVersionCleanup, AuthoritativeCommand, CompleteVersionCleanupItem,
    IssueVersionCleanupPermit, MAXIMUM_VERSION_CLEANUP_PERMIT_LIFETIME, ProposeVersionCleanup,
    VersionCleanupAttestation, VersionCleanupCompletion, VersionCleanupIntent,
    VersionCleanupParticipant, VersionCleanupPermitAttempt, VersionCleanupPermitAuthority,
    VersionCleanupState,
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

/// Stable rejection before a provider tombstone result enters consensus.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum CleanupCompletionError {
    /// The receipt, seal or authenticated reporter does not match exact committed authority.
    #[error("cleanup tombstone completion authority is invalid")]
    InvalidAuthority,
}

/// Stable rejection before replicated completion becomes local permanent retirement authority.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum CleanupRetirementAuthorityError {
    /// Intent, participant and terminal completion do not form one exact completed cleanup.
    #[error("cleanup retirement authority is inconsistent")]
    Inconsistent,
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

/// Converts one exact provider receipt into a replicated item-completion command.
///
/// The caller obtains the reporter identity from the authenticated transport peer, never from
/// message claims. The metadata state machine independently repeats every identity and digest
/// check.
///
/// # Errors
///
/// Rejects a zero seal/incarnation or any receipt field not derived from the committed attempt.
pub fn version_cleanup_tombstone_completion(
    inventory_sealed_revision: Revision,
    attempt: VersionCleanupPermitAttempt,
    receipt: TombstoneReceipt,
    reporter_node_id: NodeId,
    reporter_incarnation: u64,
) -> Result<AuthoritativeCommand, CleanupCompletionError> {
    let permit = attempt.permit;
    if inventory_sealed_revision == Revision::ZERO
        || reporter_incarnation == 0
        || receipt.operation_id != permit.operation_id
        || receipt.shard != permit.shard
        || receipt.target_id != permit.target_id
        || receipt.target_generation != permit.target_generation
        || receipt.permit_digest != permit.permit_digest
        || receipt.tombstone_digest != tombstone_receipt_digest(permit)
    {
        return Err(CleanupCompletionError::InvalidAuthority);
    }
    Ok(AuthoritativeCommand::CompleteVersionCleanupItem(
        CompleteVersionCleanupItem {
            cleanup_operation_id: attempt.cleanup_operation_id,
            inventory_sealed_revision,
            item_index: attempt.item_index,
            permit_attempt_sequence: attempt.attempt_sequence,
            receipt,
            reporter_node_id,
            reporter_incarnation,
        },
    ))
}

/// Joins replicated intent, signed local participant and terminal completion without weakening
/// any identity before permanent gateway application.
///
/// # Errors
///
/// Rejects non-authorised intent state, cross-cleanup substitution, subject mismatch, incomplete
/// ordering or a local application time before replicated completion.
pub fn version_cleanup_retirement_authority(
    retirement_operation_id: OperationId,
    intent: VersionCleanupIntent,
    participant: VersionCleanupParticipant,
    completion: VersionCleanupCompletion,
    retired_at: UnixMicros,
) -> Result<VersionCleanupRetirementAuthority, CleanupRetirementAuthorityError> {
    let Some(authorisation_revision) = intent.terminal_revision else {
        return Err(CleanupRetirementAuthorityError::Inconsistent);
    };
    let Some(authorised_at) = intent.authorised_at else {
        return Err(CleanupRetirementAuthorityError::Inconsistent);
    };
    if intent.state != VersionCleanupState::Authorised
        || participant.cleanup_operation_id != intent.cleanup_operation_id
        || participant.reachability_subject_digest != intent.reachability_subject_digest
        || completion.cleanup_operation_id != intent.cleanup_operation_id
        || completion.completed_item_count == 0
        || completion.completion_digest == [0; 32]
        || completion.revision <= authorisation_revision
        || completion.completed_at < authorised_at
        || retired_at < completion.completed_at
    {
        return Err(CleanupRetirementAuthorityError::Inconsistent);
    }
    Ok(VersionCleanupRetirementAuthority {
        retirement_operation_id,
        cleanup_operation_id: intent.cleanup_operation_id,
        source_scan_operation_id: participant.scan_operation_id,
        reachability_subject_digest: intent.reachability_subject_digest,
        completed_item_count: completion.completed_item_count,
        completion_digest: completion.completion_digest,
        completion_operation_id: completion.completion_operation_id,
        completion_revision: completion.revision,
        completed_at: completion.completed_at,
        retired_at,
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
    use meshspan_contracts::{
        ShardIdentity, StoragePermitMacKey, TombstoneReceipt, tombstone_receipt_digest,
        verify_removal_permit_mac,
    };
    use meshspan_domain::{
        ContentManifestId, DurationMicros, FileVersionId, MeshId, NodeId, OperationId, Revision,
        TargetId, UnixMicros, VolumeId,
    };
    use meshspan_filesystem::VersionUnreachableProof;
    use meshspan_metadata::{
        AuthoritativeCommand, VersionCleanupItem, VersionCleanupPermitAttempt,
        VersionCleanupPermitAuthority, VersionCleanupState,
    };

    use super::{
        CleanupCompletionError, CleanupPermitError, CleanupRetirementAuthorityError,
        version_cleanup_attestation, version_cleanup_proposal, version_cleanup_removal_permit,
        version_cleanup_retirement_authority, version_cleanup_tombstone_completion,
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

    #[test]
    fn tombstone_completion_accepts_only_the_exact_committed_attempt()
    -> Result<(), Box<dyn std::error::Error>> {
        let authority = permit_authority()?;
        let key = StoragePermitMacKey::from_bytes([30; 32])?;
        let AuthoritativeCommand::IssueVersionCleanupPermit(issue) =
            version_cleanup_removal_permit(
                authority,
                MeshId::from_bytes([31; 16])?,
                authority.item.removal_operation_id,
                5,
                UnixMicros::new(1_000),
                DurationMicros::new(60_000_000),
                &key,
            )?
        else {
            return Err("wrong permit command".into());
        };
        let attempt = VersionCleanupPermitAttempt {
            cleanup_operation_id: issue.cleanup_operation_id,
            item_index: issue.item_index,
            attempt_sequence: issue.attempt_sequence,
            permit: issue.permit,
            issue_operation_id: OperationId::from_bytes([33; 16])?,
            issued_at: UnixMicros::new(1_000),
            revision: issue.permit.catalogue_revision,
        };
        let mut receipt = TombstoneReceipt {
            operation_id: issue.permit.operation_id,
            shard: issue.permit.shard,
            target_id: issue.permit.target_id,
            target_generation: issue.permit.target_generation,
            permit_digest: issue.permit.permit_digest,
            tombstone_digest: tombstone_receipt_digest(issue.permit),
        };
        let command = version_cleanup_tombstone_completion(
            issue.inventory_sealed_revision,
            attempt,
            receipt,
            NodeId::from_bytes([34; 16])?,
            6,
        )?;
        let AuthoritativeCommand::CompleteVersionCleanupItem(command) = command else {
            return Err("wrong completion command".into());
        };
        assert_eq!(command.receipt, receipt);
        assert_eq!(command.permit_attempt_sequence, attempt.attempt_sequence);

        receipt.tombstone_digest[0] ^= 1;
        assert_eq!(
            version_cleanup_tombstone_completion(
                issue.inventory_sealed_revision,
                attempt,
                receipt,
                NodeId::from_bytes([34; 16])?,
                6,
            ),
            Err(CleanupCompletionError::InvalidAuthority)
        );
        Ok(())
    }

    #[test]
    fn terminal_completion_joins_each_signed_participant_into_local_retirement()
    -> Result<(), Box<dyn std::error::Error>> {
        let cleanup_operation_id = OperationId::from_bytes([40; 16])?;
        let subject_digest = [41; 32];
        let intent = meshspan_metadata::VersionCleanupIntent {
            cleanup_operation_id,
            volume_id: VolumeId::from_bytes([42; 16])?,
            version_id: FileVersionId::from_bytes([43; 16])?,
            manifest_id: ContentManifestId::from_bytes([44; 16])?,
            manifest_root_digest: [45; 32],
            source_scan_operation_id: OperationId::from_bytes([46; 16])?,
            scan_request_digest: [47; 32],
            reachability_subject_digest: subject_digest,
            retention_policy_sequence: 1,
            reachability_revision: Revision::new(2),
            retained_root_count: 1,
            retained_root_digest: [48; 32],
            retained_root_set_digest: [49; 32],
            local_roots_digest: [50; 32],
            proof_result_digest: [51; 32],
            required_attestation_count: 2,
            proposed_at: UnixMicros::new(100),
            revision: Revision::new(3),
            state: VersionCleanupState::Authorised,
            terminal_operation_id: Some(OperationId::from_bytes([52; 16])?),
            terminal_revision: Some(Revision::new(4)),
            authorised_at: Some(UnixMicros::new(110)),
            cancelled_at: None,
        };
        let participant = meshspan_metadata::VersionCleanupParticipant {
            cleanup_operation_id,
            node_id: NodeId::from_bytes([53; 16])?,
            node_incarnation: 1,
            scan_operation_id: OperationId::from_bytes([54; 16])?,
            reachability_subject_digest: subject_digest,
            local_roots_digest: [55; 32],
            scan_result_digest: [56; 32],
            revision: Revision::new(3),
        };
        let completion = meshspan_metadata::VersionCleanupCompletion {
            cleanup_operation_id,
            completed_item_count: 6,
            completion_digest: [57; 32],
            completion_operation_id: OperationId::from_bytes([58; 16])?,
            completed_at: UnixMicros::new(120),
            revision: Revision::new(5),
        };
        let authority = version_cleanup_retirement_authority(
            OperationId::from_bytes([59; 16])?,
            intent,
            participant,
            completion,
            UnixMicros::new(121),
        )?;
        assert_eq!(
            authority.source_scan_operation_id,
            participant.scan_operation_id
        );
        assert_eq!(authority.completion_digest, completion.completion_digest);

        let mut substituted = participant;
        substituted.reachability_subject_digest[0] ^= 1;
        assert_eq!(
            version_cleanup_retirement_authority(
                OperationId::from_bytes([59; 16])?,
                intent,
                substituted,
                completion,
                UnixMicros::new(121),
            ),
            Err(CleanupRetirementAuthorityError::Inconsistent)
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
