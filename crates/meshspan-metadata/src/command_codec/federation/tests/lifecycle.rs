// SPDX-License-Identifier: GPL-2.0-only

//! Wire coverage for recipient permissions, signed actors, succession and reconciliation.

use super::{assert_round_trip_and_bounds, context};
use crate::*;
use meshspan_contracts::BoundedItems;
use meshspan_domain::*;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn recipient_assignment_and_activation_commands_preserve_all_fields() -> TestResult<()> {
    let assignment_id = FederationAssignmentId::from_bytes([4; 16])?;
    let activation_id = ActivationId::from_bytes([5; 16])?;
    let principal_id = PrincipalId::from_bytes([6; 16])?;
    let policy_id = ActivationPolicyId::from_bytes([7; 16])?;
    let commands = [
        AuthoritativeCommand::CreateFederationGrantAssignment(CreateFederationGrantAssignment {
            assignment_id,
            grant_id: FederationGrantId::from_bytes([8; 16])?,
            subject_principal_id: principal_id,
            rights: Rights::ALL,
            valid_from: Some(UnixMicros::new(100)),
            valid_until: Some(UnixMicros::new(200)),
            activation_policy_id: Some(policy_id),
        }),
        AuthoritativeCommand::RevokeFederationGrantAssignment(RevokeFederationGrantAssignment {
            assignment_id,
            reason: "Remove local access".into(),
        }),
        AuthoritativeCommand::ActivateFederationGrantAssignment(
            ActivateFederationGrantAssignment {
                activation_id,
                principal_id,
                assignment_id,
                policy_id,
                reason: "Recover document".into(),
                duration: DurationMicros::new(90),
                session_expires_at: UnixMicros::new(200),
                assurance: AssuranceLevel::RecentStepUp,
                authentication_digest: [9; 32],
            },
        ),
        AuthoritativeCommand::RevokeFederationGrantAssignmentActivation(
            RevokeFederationGrantAssignmentActivation {
                activation_id,
                principal_id,
                reason: "End recovery".into(),
            },
        ),
    ];
    for (command, kind) in commands.iter().zip(103_u16..=106) {
        check_kind(command, kind)?;
    }
    Ok(())
}

#[test]
fn home_actor_statement_preserves_signature_and_lifecycle() -> TestResult<()> {
    for kind in [
        FederatedActorKind::User,
        FederatedActorKind::Group,
        FederatedActorKind::Service,
    ] {
        for state in [
            FederatedActorState::Active,
            FederatedActorState::Suspended,
            FederatedActorState::Retired,
        ] {
            let value = RecordFederatedActorAttestation {
                relationship_id: FederationRelationshipId::from_bytes([4; 16])?,
                home_mesh_id: MeshId::from_bytes([5; 16])?,
                principal_id: PrincipalId::from_bytes([6; 16])?,
                kind,
                name: RecordName::new("Équipe")?,
                state,
                identity_revision: 7,
                authority_epoch: 8,
                signer_generation: 9,
                signature: [10; 64],
            };
            check_kind(
                &AuthoritativeCommand::RecordFederatedActorAttestation(value),
                107,
            )?;
        }
    }
    Ok(())
}

#[test]
fn two_sided_succession_preserves_exact_signed_fences() -> TestResult<()> {
    let succession_id = FederationSuccessionId::from_bytes([4; 16])?;
    let relationship_id = FederationRelationshipId::from_bytes([5; 16])?;
    let retiring_mesh_id = MeshId::from_bytes([6; 16])?;
    let successor_mesh_id = MeshId::from_bytes([7; 16])?;
    let commands = [
        AuthoritativeCommand::DesignateFederationSuccessor(DesignateFederationSuccessor {
            succession_id,
            relationship_id,
            retiring_mesh_id,
            successor_mesh_id,
            expected_authority_epoch: 8,
            succession_epoch: 9,
            ancestry: BoundedItems::new(
                vec![FederationSuccessionEdge {
                    retiring_mesh_id: MeshId::from_bytes([10; 16])?,
                    successor_mesh_id: retiring_mesh_id,
                }],
                1,
            )?,
            signer_generation: 11,
            signature: [12; 64],
        }),
        AuthoritativeCommand::AcceptFederationSuccessor(AcceptFederationSuccessor {
            succession_id,
            relationship_id,
            retiring_mesh_id,
            successor_mesh_id,
            expected_authority_epoch: 8,
            succession_epoch: 9,
            designation_digest: [13; 32],
            signer_generation: 14,
            signature: [15; 64],
        }),
        AuthoritativeCommand::ActivateFederationSuccessor(ActivateFederationSuccessor {
            succession_id,
            relationship_id,
            retiring_mesh_id,
            successor_mesh_id,
            expected_authority_epoch: 8,
            succession_epoch: 9,
            designation_digest: [13; 32],
            acceptance_digest: [16; 32],
            reason: "Explicit recovery".into(),
        }),
        AuthoritativeCommand::RevokeFederationSuccessorDesignation(
            RevokeFederationSuccessorDesignation {
                succession_id,
                relationship_id,
                retiring_mesh_id,
                successor_mesh_id,
                expected_authority_epoch: 8,
                succession_epoch: 9,
                designation_digest: [13; 32],
                signer_generation: 14,
                reason: "Cancel dormant recovery".into(),
                signature: [17; 64],
            },
        ),
    ];
    for (command, kind) in commands.iter().zip(108_u16..=111) {
        check_kind(command, kind)?;
    }
    Ok(())
}

#[test]
fn reconciliation_preserves_original_actor_and_distinct_accepting_relay() -> TestResult<()> {
    let owner_mesh_id = MeshId::from_bytes([4; 16])?;
    let volume_id = VolumeId::from_bytes([5; 16])?;
    let object_id = ObjectId::from_bytes([6; 16])?;
    let resources = [
        FederationResourceScope::Volume {
            owner_mesh_id,
            volume_id,
        },
        FederationResourceScope::Subtree {
            owner_mesh_id,
            volume_id,
            root_object_id: object_id,
        },
        FederationResourceScope::File {
            owner_mesh_id,
            volume_id,
            object_id,
        },
        FederationResourceScope::StorageCapacity {
            provider_mesh_id: owner_mesh_id,
        },
    ];
    for resource in resources {
        let acknowledgement = acknowledgement(resource)?;
        let quarantine_id = QuarantineId::from_bytes([19; 16])?;
        check_kind(
            &AuthoritativeCommand::RetainFederatedMutationQuarantine(
                RetainFederatedMutationQuarantine {
                    quarantine_id,
                    acknowledgement,
                },
            ),
            112,
        )?;
        check_kind(
            &AuthoritativeCommand::AdmitFederatedMutation(AdmitFederatedMutation {
                namespace_commit_id: NamespaceCommitId::from_bytes([20; 16])?,
                acknowledgement,
            }),
            113,
        )?;
        check_kind(
            &AuthoritativeCommand::SurfaceFederatedMutationQuarantine(
                SurfaceFederatedMutationQuarantine {
                    quarantine_id,
                    source_operation_id: acknowledgement.source_operation_id,
                },
            ),
            114,
        )?;
        for resolution in [
            FederationQuarantineResolution::Restore,
            FederationQuarantineResolution::RestoreAsCopy,
            FederationQuarantineResolution::Discard,
        ] {
            check_kind(
                &AuthoritativeCommand::ResolveFederatedMutationQuarantine(
                    ResolveFederatedMutationQuarantine {
                        quarantine_id,
                        source_operation_id: acknowledgement.source_operation_id,
                        resolution,
                        reason: "Authorised recovery".into(),
                    },
                ),
                115,
            )?;
        }
    }
    Ok(())
}

fn acknowledgement(
    resource: FederationResourceScope,
) -> TestResult<FederatedMutationAcknowledgement> {
    Ok(FederatedMutationAcknowledgement {
        source_operation_id: OperationId::from_bytes([7; 16])?,
        evidence: FederatedMutationEvidence::new_relayed(
            FederationGrantId::from_bytes([8; 16])?,
            FederationRelationshipId::from_bytes([9; 16])?,
            FederatedPrincipal::new(
                MeshId::from_bytes([10; 16])?,
                PrincipalId::from_bytes([11; 16])?,
            ),
            MeshId::from_bytes([12; 16])?,
            resource,
            13,
            UnixMicros::new(1400),
            Rights::ALL,
            1500,
        ),
        payload_digest: [16; 32],
        signer_generation: 17,
        signature: [18; 64],
    })
}

fn check_kind(command: &AuthoritativeCommand, kind: u16) -> TestResult<()> {
    let context = context()?;
    let bytes = encode_authoritative_command(context, command)?;
    // Four magic bytes, three identifiers, timestamp and absent revision precede the kind.
    assert_eq!(&bytes[61..63], &kind.to_be_bytes());
    assert_round_trip_and_bounds(context, command)
}
