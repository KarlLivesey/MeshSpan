// SPDX-License-Identifier: GPL-2.0-only

use ed25519_dalek::{Signer, SigningKey};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, FederatedMutationAdmission, FederatedMutationEvidence, FederatedPrincipal,
    FederationAccess, FederationGrant, FederationGrantId, FederationPolicy,
    FederationRelationshipId, FederationRelationshipKind, FederationResourceScope, HostId, MeshId,
    NamespaceFederationPolicy, NodeId, OperationId, PartitionId, PrincipalId, QuarantineReason,
    Revision, Rights, RoleId, UnixMicros, VolumeId,
};
use tempfile::tempdir;

use super::{AuthoritativeRepository, LogPosition, RepositoryError};
use crate::{
    ApproveFederationRelationship, AuthoritativeCommand, BootstrapMesh, CommandContext,
    FederatedMutationAcknowledgement, FederatedPrincipalKind, FederatedPrincipalState,
    FederationGovernanceDirection, FederationGrantRestriction, FederationTrustIdentity,
    IssueFederationGrant, PartitionDatabase, ProposeFederationRelationship, RecordName,
    RevokeFederationGrant, UpsertFederatedPrincipalProjection,
};

#[test]
fn signed_remote_mutations_use_retained_authority_and_current_principal_state()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let mut repository = fixture.repository;
    prepare(&mut repository, fixture.ids, &fixture.remote_key)?;

    let admitted = acknowledgement(
        fixture.ids,
        Rights::TRAVERSE.union(Rights::WRITE_DATA),
        20,
        &fixture.remote_key,
    )?;
    assert_eq!(
        repository.classify_federated_mutation_acknowledgement(&admitted)?,
        FederatedMutationAdmission::Admitted
    );
    reject_substituted_acknowledgement(&repository, &admitted);

    let outside_rights = acknowledgement(fixture.ids, Rights::DELETE, 20, &fixture.remote_key)?;
    assert_eq!(
        repository.classify_federated_mutation_acknowledgement(&outside_rights)?,
        FederatedMutationAdmission::Quarantined(QuarantineReason::OutsideRights)
    );

    apply(
        &mut repository,
        6,
        context(70, fixture.ids.administrator, 71, 30, 5)?,
        &AuthoritativeCommand::RevokeFederationGrant(RevokeFederationGrant {
            grant_id: fixture.ids.grant,
            expected_authority_epoch: 1,
            reason: "Remote write authority withdrawn".to_owned(),
        }),
    )?;
    assert_eq!(
        repository.classify_federated_mutation_acknowledgement(&admitted)?,
        FederatedMutationAdmission::Admitted
    );
    let after_revocation = acknowledgement(
        fixture.ids,
        Rights::TRAVERSE.union(Rights::WRITE_DATA),
        31,
        &fixture.remote_key,
    )?;
    assert_eq!(
        repository.classify_federated_mutation_acknowledgement(&after_revocation)?,
        FederatedMutationAdmission::Quarantined(QuarantineReason::Revoked)
    );

    let suspended = signed_projection(
        fixture.ids,
        FederatedPrincipalState::Suspended,
        2,
        &fixture.remote_key,
    )?;
    apply(
        &mut repository,
        7,
        context(72, fixture.ids.administrator, 73, 32, 6)?,
        &AuthoritativeCommand::UpsertFederatedPrincipalProjection(suspended),
    )?;
    assert_eq!(
        repository.classify_federated_mutation_acknowledgement(&admitted)?,
        FederatedMutationAdmission::Quarantined(QuarantineReason::PrincipalInactive)
    );
    Ok(())
}

fn reject_substituted_acknowledgement(
    repository: &AuthoritativeRepository,
    admitted: &FederatedMutationAcknowledgement,
) {
    let mut forged = *admitted;
    forged.payload_digest[0] ^= 1;
    assert!(matches!(
        repository.classify_federated_mutation_acknowledgement(&forged),
        Err(RepositoryError::InvalidCommand)
    ));
    let mut wrong_signature = *admitted;
    wrong_signature.signature[0] ^= 1;
    assert!(matches!(
        repository.classify_federated_mutation_acknowledgement(&wrong_signature),
        Err(RepositoryError::InvalidCommand)
    ));
}

fn prepare(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
    remote_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        1,
        context(10, ids.administrator, 11, 1, 0)?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: ids.local_mesh,
            mesh_name: RecordName::new("Local swarm")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([12; 16])?,
            host_id: HostId::from_bytes([13; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([14; 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        }),
    )?;
    apply(
        repository,
        2,
        context(15, ids.administrator, 16, 2, 1)?,
        &AuthoritativeCommand::ProposeFederationRelationship(ProposeFederationRelationship {
            relationship_id: ids.relationship,
            remote_mesh_id: ids.remote_mesh,
            remote_name: RecordName::new("Remote swarm")?,
            kind: FederationRelationshipKind::Horizontal,
            governance_direction: FederationGovernanceDirection::None,
        }),
    )?;
    apply(
        repository,
        3,
        context(17, ids.administrator, 18, 3, 2)?,
        &AuthoritativeCommand::ApproveFederationRelationship(ApproveFederationRelationship {
            relationship_id: ids.relationship,
            expected_authority_epoch: 1,
            local_identity: identity(19, &SigningKey::from_bytes(&[20; 32])),
            remote_identity: identity(21, remote_key),
            governance_proof: None,
        }),
    )?;
    apply(
        repository,
        4,
        context(22, ids.administrator, 23, 4, 3)?,
        &AuthoritativeCommand::UpsertFederatedPrincipalProjection(signed_projection(
            ids,
            FederatedPrincipalState::Active,
            1,
            remote_key,
        )?),
    )?;
    let policy = FederationPolicy::Namespace(NamespaceFederationPolicy::new(
        FederationAccess::new(Rights::TRAVERSE.union(Rights::WRITE_DATA), false),
        None,
    ));
    let grant = FederationGrant::new(
        ids.grant,
        ids.relationship,
        FederatedPrincipal::new(ids.remote_mesh, ids.remote_principal),
        FederationResourceScope::Volume {
            owner_mesh_id: ids.local_mesh,
            volume_id: ids.volume,
        },
        policy,
        1,
        UnixMicros::new(5),
        None,
    )?;
    apply(
        repository,
        5,
        context(24, ids.administrator, 25, 5, 4)?,
        &AuthoritativeCommand::IssueFederationGrant(IssueFederationGrant {
            grant,
            restrictions: BoundedItems::new(
                vec![
                    FederationGrantRestriction {
                        imposing_mesh_id: ids.local_mesh,
                        policy,
                    },
                    FederationGrantRestriction {
                        imposing_mesh_id: ids.remote_mesh,
                        policy,
                    },
                ],
                2,
            )?,
        }),
    )?;
    Ok(())
}

fn signed_projection(
    ids: FixtureIds,
    state: FederatedPrincipalState,
    identity_revision: u64,
    remote_key: &SigningKey,
) -> Result<UpsertFederatedPrincipalProjection, Box<dyn std::error::Error>> {
    let mut projection = UpsertFederatedPrincipalProjection {
        relationship_id: ids.relationship,
        home_mesh_id: ids.remote_mesh,
        principal_id: ids.remote_principal,
        kind: FederatedPrincipalKind::User,
        name: RecordName::new("Remote user")?,
        state,
        identity_revision,
        authority_epoch: 1,
        signer_generation: 1,
        signature: [0; 64],
    };
    projection.signature = remote_key.sign(&projection.signing_payload()).to_bytes();
    Ok(projection)
}

fn acknowledgement(
    ids: FixtureIds,
    rights: Rights,
    accepted_at: i64,
    remote_key: &SigningKey,
) -> Result<FederatedMutationAcknowledgement, Box<dyn std::error::Error>> {
    let mut acknowledgement = FederatedMutationAcknowledgement {
        source_operation_id: OperationId::from_bytes([40; 16])?,
        evidence: FederatedMutationEvidence::new(
            ids.grant,
            ids.relationship,
            FederatedPrincipal::new(ids.remote_mesh, ids.remote_principal),
            FederationResourceScope::Volume {
                owner_mesh_id: ids.local_mesh,
                volume_id: ids.volume,
            },
            1,
            UnixMicros::new(accepted_at),
            rights,
            0,
        ),
        payload_digest: [41; 32],
        signer_generation: 1,
        signature: [0; 64],
    };
    acknowledgement.signature = remote_key
        .sign(&acknowledgement.signing_payload())
        .to_bytes();
    Ok(acknowledgement)
}

fn identity(fingerprint: u8, signing_key: &SigningKey) -> FederationTrustIdentity {
    FederationTrustIdentity {
        generation: 1,
        certificate_fingerprint: [fingerprint; 32],
        verifying_key: signing_key.verifying_key().to_bytes(),
        valid_from: UnixMicros::new(1),
        valid_until: UnixMicros::new(100),
    }
}

#[derive(Clone, Copy)]
struct FixtureIds {
    administrator: PrincipalId,
    remote_principal: PrincipalId,
    partition: PartitionId,
    local_mesh: MeshId,
    remote_mesh: MeshId,
    relationship: FederationRelationshipId,
    grant: FederationGrantId,
    volume: VolumeId,
}

struct Fixture {
    _directory: tempfile::TempDir,
    repository: AuthoritativeRepository,
    ids: FixtureIds,
    remote_key: SigningKey,
}

impl Fixture {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let ids = FixtureIds {
            administrator: PrincipalId::from_bytes([1; 16])?,
            remote_principal: PrincipalId::from_bytes([2; 16])?,
            partition: PartitionId::from_bytes([3; 16])?,
            local_mesh: MeshId::from_bytes([4; 16])?,
            remote_mesh: MeshId::from_bytes([5; 16])?,
            relationship: FederationRelationshipId::from_bytes([6; 16])?,
            grant: FederationGrantId::from_bytes([7; 16])?,
            volume: VolumeId::from_bytes([8; 16])?,
        };
        let database = PartitionDatabase::open(
            &directory
                .path()
                .join("federated-mutation-admission.sqlite3"),
            ids.partition,
            UnixMicros::new(0),
        )?;
        Ok(Self {
            _directory: directory,
            repository: AuthoritativeRepository::new(database),
            ids,
            remote_key: SigningKey::from_bytes(&[9; 32]),
        })
    }
}

fn apply(
    repository: &mut AuthoritativeRepository,
    index: u64,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<(), RepositoryError> {
    repository
        .apply_committed(LogPosition { index, term: 1 }, context, command)
        .map(|_| ())
}

fn context(
    operation: u8,
    actor: PrincipalId,
    audit: u8,
    occurred_at: i64,
    expected_revision: u64,
) -> Result<CommandContext, Box<dyn std::error::Error>> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation; 16])?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes([audit; 16])?,
        occurred_at: UnixMicros::new(occurred_at),
        expected_revision: Some(Revision::new(expected_revision)),
    })
}
