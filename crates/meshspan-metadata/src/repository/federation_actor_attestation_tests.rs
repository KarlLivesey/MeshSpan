// SPDX-License-Identifier: GPL-2.0-only

use ed25519_dalek::{Signer, SigningKey};
use meshspan_domain::{
    AuditEventId, FederatedPrincipal, FederationRelationshipId, FederationRelationshipKind, HostId,
    MeshId, NodeId, OperationId, PartitionId, PrincipalId, Revision, RoleId, UnixMicros,
};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault, read_current_revision};
use super::{AuthoritativeRepository, EntityKind, LogPosition, RepositoryError};
use crate::{
    ApproveFederationRelationship, AuthoritativeCommand, BootstrapMesh, CommandContext,
    FederatedActorKind, FederatedActorState, FederationGovernanceDirection,
    FederationTrustIdentity, PartitionDatabase, ProposeFederationRelationship,
    RecordFederatedActorAttestation, RecordName,
};

#[test]
fn every_apply_boundary_rolls_back_complete_signed_actor_attestation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let mut repository = fixture.repository;
    prepare_relationship(&mut repository, fixture.ids, &fixture.remote_key)?;
    let command = AuthoritativeCommand::RecordFederatedActorAttestation(signed_attestation(
        fixture.ids,
        PrincipalId::from_bytes([60; 16])?,
        FederatedActorState::Active,
        1,
        1,
        &fixture.remote_key,
    )?);
    let mut database = repository.into_database();
    for (offset, fault) in all_apply_faults().into_iter().enumerate() {
        let seed = 61_u8.saturating_add(u8::try_from(offset)?);
        assert!(matches!(
            apply_committed_with_fault(
                &mut database,
                LogPosition { index: 4, term: 1 },
                context(
                    seed,
                    fixture.ids.administrator,
                    seed.saturating_add(4),
                    4,
                    3
                )?,
                &command,
                fault,
            ),
            Err(RepositoryError::InjectedFault)
        ));
        let retained: (i64, i64) = database.connection().query_row(
            "SELECT
                (SELECT count(*) FROM federation_actor_attestations),
                (SELECT count(*) FROM federation_actor_attestation_history)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(retained, (0, 0));
        assert_eq!(read_current_revision(&database)?, Revision::new(3));
    }
    Ok(())
}

const fn all_apply_faults() -> [ApplyFaultPoint; 4] {
    [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ]
}

#[test]
fn signed_attestation_is_monotonic_atomic_and_restart_safe()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let backup_directory = fixture.directory.path().to_path_buf();
    let file_path = fixture.file_path.clone();
    let mut repository = fixture.repository;
    prepare_relationship(&mut repository, fixture.ids, &fixture.remote_key)?;

    let principal_id = PrincipalId::from_bytes([30; 16])?;
    let first = signed_attestation(
        fixture.ids,
        principal_id,
        FederatedActorState::Active,
        1,
        1,
        &fixture.remote_key,
    )?;
    let receipt = repository.apply_committed(
        LogPosition { index: 4, term: 1 },
        context(31, fixture.ids.administrator, 32, 4, 3)?,
        &AuthoritativeCommand::RecordFederatedActorAttestation(first.clone()),
    )?;
    assert_eq!(receipt.entity.kind, EntityKind::FederatedActorAttestation);

    reject_forged_and_stale_updates(&mut repository, fixture.ids, &first)?;

    let second = signed_attestation(
        fixture.ids,
        principal_id,
        FederatedActorState::Suspended,
        2,
        1,
        &fixture.remote_key,
    )?;
    apply(
        &mut repository,
        5,
        context(37, fixture.ids.administrator, 38, 5, 4)?,
        &AuthoritativeCommand::RecordFederatedActorAttestation(second),
    )?;
    drop(repository);

    let database = PartitionDatabase::open(&file_path, fixture.ids.partition, UnixMicros::new(6))?;
    let repository = AuthoritativeRepository::new(database);
    let record = repository
        .federated_actor_attestation(
            fixture.ids.relationship,
            FederatedPrincipal::new(fixture.ids.remote_mesh, principal_id),
        )?
        .ok_or("attestation missing after restart")?;
    assert_eq!(record.kind, FederatedActorKind::User);
    assert_eq!(record.state, FederatedActorState::Suspended);
    assert_eq!(record.identity_revision, 2);
    assert_eq!(record.authority_epoch, 1);
    assert_eq!(record.display_name, "Remote user");
    let restored = super::federation_backup_test_support::backup_and_restore(
        &repository,
        &backup_directory,
        92,
    )?;
    assert_eq!(
        restored
            .federated_actor_attestation(
                fixture.ids.relationship,
                FederatedPrincipal::new(fixture.ids.remote_mesh, principal_id),
            )?
            .ok_or("attestation missing after restore")?
            .identity_revision,
        2
    );
    let database = restored.into_database();
    verify_history_count(&database, fixture.ids, principal_id, 2)?;
    database.connection().execute(
        "UPDATE federation_actor_attestations SET display_name = 'Tampered user'
         WHERE relationship_id = ?1 AND home_mesh_id = ?2 AND principal_id = ?3",
        rusqlite::params![
            fixture.ids.relationship.as_bytes().as_slice(),
            fixture.ids.remote_mesh.as_bytes().as_slice(),
            principal_id.as_bytes().as_slice(),
        ],
    )?;
    let repository = AuthoritativeRepository::new(database);
    assert!(matches!(
        repository.federated_actor_attestation(
            fixture.ids.relationship,
            FederatedPrincipal::new(fixture.ids.remote_mesh, principal_id),
        ),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

#[test]
fn attestation_rejects_wrong_home_swarm_and_authority_epoch()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let mut repository = fixture.repository;
    prepare_relationship(&mut repository, fixture.ids, &fixture.remote_key)?;
    let principal_id = PrincipalId::from_bytes([40; 16])?;

    let mut wrong_home = signed_attestation(
        fixture.ids,
        principal_id,
        FederatedActorState::Active,
        1,
        1,
        &fixture.remote_key,
    )?;
    wrong_home.home_mesh_id = MeshId::from_bytes([41; 16])?;
    wrong_home.signature = fixture
        .remote_key
        .sign(&wrong_home.signing_payload())
        .to_bytes();
    reject_without_advancing(&mut repository, fixture.ids, 4, 42, wrong_home)?;

    let wrong_epoch = signed_attestation(
        fixture.ids,
        principal_id,
        FederatedActorState::Active,
        1,
        2,
        &fixture.remote_key,
    )?;
    reject_without_advancing(&mut repository, fixture.ids, 4, 43, wrong_epoch)?;

    assert!(
        repository
            .federated_actor_attestation(
                fixture.ids.relationship,
                FederatedPrincipal::new(fixture.ids.remote_mesh, principal_id),
            )?
            .is_none()
    );
    Ok(())
}

fn reject_forged_and_stale_updates(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
    first: &RecordFederatedActorAttestation,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut forged = first.clone();
    forged.identity_revision = 2;
    forged.state = FederatedActorState::Suspended;
    reject_without_advancing(repository, ids, 5, 33, forged)?;

    let stale = first.clone();
    reject_without_advancing(repository, ids, 5, 35, stale)?;
    Ok(())
}

fn reject_without_advancing(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
    index: u64,
    operation: u8,
    command: RecordFederatedActorAttestation,
) -> Result<(), Box<dyn std::error::Error>> {
    let before = repository.current_revision()?;
    let result = repository.apply_committed(
        LogPosition { index, term: 1 },
        context(
            operation,
            ids.administrator,
            operation + 1,
            index,
            before.get(),
        )?,
        &AuthoritativeCommand::RecordFederatedActorAttestation(command),
    );
    assert!(matches!(result, Err(RepositoryError::InvalidCommand)));
    assert_eq!(repository.current_revision()?, before);
    Ok(())
}

fn verify_history_count(
    database: &PartitionDatabase,
    ids: FixtureIds,
    principal_id: PrincipalId,
    expected: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let count: i64 = database.connection().query_row(
        "SELECT count(*) FROM federation_actor_attestation_history
         WHERE relationship_id = ?1 AND home_mesh_id = ?2 AND principal_id = ?3",
        rusqlite::params![
            ids.relationship.as_bytes().as_slice(),
            ids.remote_mesh.as_bytes().as_slice(),
            principal_id.as_bytes().as_slice(),
        ],
        |row| row.get(0),
    )?;
    assert_eq!(count, expected);
    Ok(())
}

fn signed_attestation(
    ids: FixtureIds,
    principal_id: PrincipalId,
    state: FederatedActorState,
    identity_revision: u64,
    authority_epoch: u64,
    remote_key: &SigningKey,
) -> Result<RecordFederatedActorAttestation, Box<dyn std::error::Error>> {
    let mut command = RecordFederatedActorAttestation {
        relationship_id: ids.relationship,
        home_mesh_id: ids.remote_mesh,
        principal_id,
        kind: FederatedActorKind::User,
        name: RecordName::new("Remote user")?,
        state,
        identity_revision,
        authority_epoch,
        signer_generation: 1,
        signature: [0; 64],
    };
    command.signature = remote_key.sign(&command.signing_payload()).to_bytes();
    Ok(command)
}

fn prepare_relationship(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
    remote_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        1,
        context(3, ids.administrator, 4, 1, 0)?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: ids.local_mesh,
            mesh_name: RecordName::new("Local swarm")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([5; 16])?,
            host_id: HostId::from_bytes([6; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([7; 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        }),
    )?;
    apply(
        repository,
        2,
        context(8, ids.administrator, 9, 2, 1)?,
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
        context(10, ids.administrator, 11, 3, 2)?,
        &AuthoritativeCommand::ApproveFederationRelationship(ApproveFederationRelationship {
            relationship_id: ids.relationship,
            expected_authority_epoch: 1,
            local_identity: identity(1, 12, &SigningKey::from_bytes(&[13; 32])),
            remote_identity: identity(1, 14, remote_key),
            governance_proof: None,
        }),
    )?;
    Ok(())
}

fn identity(generation: u64, fingerprint: u8, signing_key: &SigningKey) -> FederationTrustIdentity {
    FederationTrustIdentity {
        generation,
        certificate_fingerprint: [fingerprint; 32],
        verifying_key: signing_key.verifying_key().to_bytes(),
        valid_from: UnixMicros::new(1),
        valid_until: UnixMicros::new(100),
    }
}

#[derive(Clone, Copy)]
struct FixtureIds {
    administrator: PrincipalId,
    partition: PartitionId,
    local_mesh: MeshId,
    remote_mesh: MeshId,
    relationship: FederationRelationshipId,
}

struct Fixture {
    directory: tempfile::TempDir,
    file_path: std::path::PathBuf,
    repository: AuthoritativeRepository,
    ids: FixtureIds,
    remote_key: SigningKey,
}

impl Fixture {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("federation-principals.sqlite3");
        let ids = FixtureIds {
            administrator: PrincipalId::from_bytes([1; 16])?,
            partition: PartitionId::from_bytes([2; 16])?,
            local_mesh: MeshId::from_bytes([20; 16])?,
            remote_mesh: MeshId::from_bytes([21; 16])?,
            relationship: FederationRelationshipId::from_bytes([22; 16])?,
        };
        let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(0))?;
        Ok(Self {
            directory,
            file_path,
            repository: AuthoritativeRepository::new(database),
            ids,
            remote_key: SigningKey::from_bytes(&[15; 32]),
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
    occurred_at: u64,
    expected_revision: u64,
) -> Result<CommandContext, Box<dyn std::error::Error>> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation; 16])?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes([audit; 16])?,
        occurred_at: UnixMicros::new(i64::try_from(occurred_at)?),
        expected_revision: Some(Revision::new(expected_revision)),
    })
}
