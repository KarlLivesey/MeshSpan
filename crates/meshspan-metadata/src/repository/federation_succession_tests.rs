// SPDX-License-Identifier: GPL-2.0-only

use ed25519_dalek::{Signer, SigningKey};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, DurationMicros, FederatedPrincipal, FederationGrant, FederationGrantId,
    FederationPolicy, FederationRelationshipId, FederationRelationshipKind,
    FederationResourceScope, FederationSuccessionId, HostId, MeshId, NodeId, OperationId,
    PartitionId, PrincipalId, Revision, RoleId, StorageFederationPolicy, StorageParticipation,
    UnixMicros,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault, read_current_revision};
use super::{
    AuthoritativeRepository, EntityKind, FederationSuccessionState, LogPosition, RepositoryError,
};

#[test]
fn every_apply_boundary_rolls_back_complete_signed_succession_designation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let mut repository = fixture.repository;
    prepare_relationship(&mut repository, fixture.ids)?;
    let command = AuthoritativeCommand::DesignateFederationSuccessor(designation(
        fixture.ids,
        1,
        vec![FederationSuccessionEdge {
            retiring_mesh_id: MeshId::from_bytes([60; 16])?,
            successor_mesh_id: fixture.ids.remote_mesh,
        }],
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
        let retained: (i64, i64, i64) = database.connection().query_row(
            "SELECT
                (SELECT count(*) FROM federation_ownership_successions),
                (SELECT count(*) FROM federation_ownership_succession_ancestry),
                (SELECT count(*) FROM federation_ownership_succession_events)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(retained, (0, 0, 0));
        assert_eq!(read_current_revision(&database)?, Revision::new(3));
    }
    Ok(())
}

#[test]
fn every_succession_transition_rolls_back_its_command_rows()
-> Result<(), Box<dyn std::error::Error>> {
    prove_designate_accept_activate_rollbacks()?;
    prove_designation_revocation_rollback()
}

fn prove_designate_accept_activate_rollbacks() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let mut repository = fixture.repository;
    prepare_relationship(&mut repository, fixture.ids)?;
    let designation = designation(fixture.ids, 1, vec![])?;
    let designation_digest = payload_digest(&designation.signing_payload());
    apply_succession_after_rollback(
        &mut repository,
        LogPosition { index: 4, term: 1 },
        context(70, fixture.ids.administrator, 71, 4, 3)?,
        &AuthoritativeCommand::DesignateFederationSuccessor(designation),
        fixture.ids.remote_mesh,
    )?;
    let acceptance = acceptance(fixture.ids, designation_digest, 1);
    let acceptance_digest = payload_digest(&acceptance.signing_payload());
    apply_succession_after_rollback(
        &mut repository,
        LogPosition { index: 5, term: 1 },
        context(72, fixture.ids.administrator, 73, 5, 4)?,
        &AuthoritativeCommand::AcceptFederationSuccessor(acceptance),
        fixture.ids.remote_mesh,
    )?;
    apply_succession_after_rollback(
        &mut repository,
        LogPosition { index: 6, term: 1 },
        context(74, fixture.ids.administrator, 75, 6, 5)?,
        &AuthoritativeCommand::ActivateFederationSuccessor(ActivateFederationSuccessor {
            succession_id: fixture.ids.succession,
            relationship_id: fixture.ids.relationship,
            retiring_mesh_id: fixture.ids.remote_mesh,
            successor_mesh_id: fixture.ids.local_mesh,
            expected_authority_epoch: 1,
            succession_epoch: 1,
            designation_digest,
            acceptance_digest,
            reason: "Atomic activation".to_owned(),
        }),
        fixture.ids.remote_mesh,
    )?;
    Ok(())
}

fn prove_designation_revocation_rollback() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let mut repository = fixture.repository;
    prepare_relationship(&mut repository, fixture.ids)?;
    let designation = designation(fixture.ids, 1, vec![])?;
    let designation_digest = payload_digest(&designation.signing_payload());
    apply(
        &mut repository,
        4,
        context(76, fixture.ids.administrator, 77, 4, 3)?,
        &AuthoritativeCommand::DesignateFederationSuccessor(designation),
    )?;
    let mut revocation = RevokeFederationSuccessorDesignation {
        succession_id: fixture.ids.succession,
        relationship_id: fixture.ids.relationship,
        retiring_mesh_id: fixture.ids.remote_mesh,
        successor_mesh_id: fixture.ids.local_mesh,
        expected_authority_epoch: 1,
        succession_epoch: 1,
        designation_digest,
        signer_generation: 1,
        reason: "Atomic dormant revocation".to_owned(),
        signature: [0; 64],
    };
    revocation.signature = remote_key().sign(&revocation.signing_payload()).to_bytes();
    apply_succession_after_rollback(
        &mut repository,
        LogPosition { index: 5, term: 1 },
        context(78, fixture.ids.administrator, 79, 5, 4)?,
        &AuthoritativeCommand::RevokeFederationSuccessorDesignation(revocation),
        fixture.ids.remote_mesh,
    )?;
    Ok(())
}

fn apply_succession_after_rollback(
    repository: &mut AuthoritativeRepository,
    position: LogPosition,
    context: CommandContext,
    command: &AuthoritativeCommand,
    retiring_mesh_id: MeshId,
) -> Result<(), Box<dyn std::error::Error>> {
    let before = repository.active_federation_successor(retiring_mesh_id)?;
    let revision = repository.current_revision()?;
    assert!(matches!(
        repository.apply_committed_with_fault(
            position,
            context,
            command,
            ApplyFaultPoint::AfterCommand,
        ),
        Err(RepositoryError::InjectedFault)
    ));
    assert_eq!(
        repository.active_federation_successor(retiring_mesh_id)?,
        before
    );
    assert_eq!(repository.current_revision()?, revision);
    assert!(
        repository
            .resolve_operation(context.operation_id)?
            .is_none()
    );
    repository.apply_committed(position, context, command)?;
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
use crate::{
    AcceptFederationSuccessor, ActivateFederationSuccessor, ApproveFederationRelationship,
    AuthoritativeCommand, BootstrapMesh, CommandContext, DesignateFederationSuccessor,
    FederationGovernanceDirection, FederationGrantRestriction, FederationSuccessionEdge,
    FederationTrustIdentity, IssueFederationGrant, PartitionDatabase,
    ProposeFederationRelationship, RecordName, RevokeFederationSuccessorDesignation,
};

#[test]
fn two_sided_succession_activates_fences_and_survives_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let backup_directory = fixture.directory.path().to_path_buf();
    let file_path = fixture.file_path.clone();
    let mut repository = fixture.repository;
    prepare_relationship(&mut repository, fixture.ids)?;
    let grant_id = FederationGrantId::from_bytes([29; 16])?;
    issue_storage_grant(&mut repository, fixture.ids, grant_id)?;
    assert!(repository.active_federation_grant(grant_id)?.is_some());

    let designation = designation(fixture.ids, 1, vec![])?;
    let designation_digest = payload_digest(&designation.signing_payload());
    let receipt = repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        context(30, fixture.ids.administrator, 31, 5, 4)?,
        &AuthoritativeCommand::DesignateFederationSuccessor(designation),
    )?;
    assert_eq!(receipt.entity.kind, EntityKind::FederationSuccession);

    let mut forged_acceptance = acceptance(fixture.ids, designation_digest, 1);
    forged_acceptance.signature = [8; 64];
    assert_rejected(
        &mut repository,
        fixture.ids,
        6,
        32,
        &AuthoritativeCommand::AcceptFederationSuccessor(forged_acceptance),
    )?;

    let accepted = acceptance(fixture.ids, designation_digest, 1);
    let acceptance_digest = payload_digest(&accepted.signing_payload());
    apply(
        &mut repository,
        6,
        context(34, fixture.ids.administrator, 35, 6, 5)?,
        &AuthoritativeCommand::AcceptFederationSuccessor(accepted),
    )?;
    apply(
        &mut repository,
        7,
        context(36, fixture.ids.administrator, 37, 7, 6)?,
        &AuthoritativeCommand::ActivateFederationSuccessor(ActivateFederationSuccessor {
            succession_id: fixture.ids.succession,
            relationship_id: fixture.ids.relationship,
            retiring_mesh_id: fixture.ids.remote_mesh,
            successor_mesh_id: fixture.ids.local_mesh,
            expected_authority_epoch: 1,
            succession_epoch: 1,
            designation_digest,
            acceptance_digest,
            reason: "Offline recovery material confirms permanent loss".to_owned(),
        }),
    )?;
    let active = repository
        .active_federation_successor(fixture.ids.remote_mesh)?
        .ok_or("active successor missing")?;
    assert_eq!(active.successor_mesh_id, fixture.ids.local_mesh);
    assert_eq!(active.state, FederationSuccessionState::Active);
    assert!(repository.active_federation_grant(grant_id)?.is_none());
    let replacement_grant = FederationGrantId::from_bytes([28; 16])?;
    assert_rejected(
        &mut repository,
        fixture.ids,
        8,
        38,
        &storage_grant_command(fixture.ids, replacement_grant)?,
    )?;
    drop(repository);

    let database = PartitionDatabase::open(&file_path, fixture.ids.partition, UnixMicros::new(9))?;
    let repository = AuthoritativeRepository::new(database);
    assert_eq!(
        repository
            .active_federation_successor(fixture.ids.remote_mesh)?
            .ok_or("active successor missing after restart")?
            .succession_epoch,
        1
    );
    let restored = super::federation_backup_test_support::backup_and_restore(
        &repository,
        &backup_directory,
        93,
    )?;
    assert_eq!(
        restored
            .active_federation_successor(fixture.ids.remote_mesh)?
            .ok_or("active successor missing after restore")?
            .succession_epoch,
        1
    );
    let database = restored.into_database();
    verify_events(&database, fixture.ids.succession, &[1, 2, 3])?;
    database.connection().execute(
        "UPDATE federation_ownership_successions SET acceptance_signature = zeroblob(64)
         WHERE succession_id = ?1",
        [fixture.ids.succession.as_bytes().as_slice()],
    )?;
    let repository = AuthoritativeRepository::new(database);
    assert!(matches!(
        repository.active_federation_successor(fixture.ids.remote_mesh),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

#[test]
fn dormant_designation_can_be_revoked_and_replaced_at_next_epoch()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let mut repository = fixture.repository;
    prepare_relationship(&mut repository, fixture.ids)?;
    let first = designation(fixture.ids, 1, vec![])?;
    let first_digest = payload_digest(&first.signing_payload());
    apply(
        &mut repository,
        4,
        context(40, fixture.ids.administrator, 41, 4, 3)?,
        &AuthoritativeCommand::DesignateFederationSuccessor(first),
    )?;
    let mut revocation = RevokeFederationSuccessorDesignation {
        succession_id: fixture.ids.succession,
        relationship_id: fixture.ids.relationship,
        retiring_mesh_id: fixture.ids.remote_mesh,
        successor_mesh_id: fixture.ids.local_mesh,
        expected_authority_epoch: 1,
        succession_epoch: 1,
        designation_digest: first_digest,
        signer_generation: 1,
        reason: "Successor agreement withdrawn before activation".to_owned(),
        signature: [0; 64],
    };
    revocation.signature = remote_key().sign(&revocation.signing_payload()).to_bytes();
    apply(
        &mut repository,
        5,
        context(42, fixture.ids.administrator, 43, 5, 4)?,
        &AuthoritativeCommand::RevokeFederationSuccessorDesignation(revocation),
    )?;
    assert!(
        repository
            .active_federation_successor(fixture.ids.remote_mesh)?
            .is_none()
    );

    let mut replacement_ids = fixture.ids;
    replacement_ids.succession = FederationSuccessionId::from_bytes([44; 16])?;
    apply(
        &mut repository,
        6,
        context(45, fixture.ids.administrator, 46, 6, 5)?,
        &AuthoritativeCommand::DesignateFederationSuccessor(designation(
            replacement_ids,
            2,
            vec![],
        )?),
    )?;
    let database = repository.into_database();
    let states: (i64, i64) = database.connection().query_row(
        "SELECT
            (SELECT state FROM federation_ownership_successions WHERE succession_id = ?1),
            (SELECT state FROM federation_ownership_successions WHERE succession_id = ?2)",
        rusqlite::params![
            fixture.ids.succession.as_bytes().as_slice(),
            replacement_ids.succession.as_bytes().as_slice(),
        ],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(states, (4, 1));
    Ok(())
}

#[test]
fn signed_ancestry_rejects_three_swarm_succession_cycle_atomically()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let mut repository = fixture.repository;
    prepare_relationship(&mut repository, fixture.ids)?;
    let middle = MeshId::from_bytes([50; 16])?;
    let circular = designation(
        fixture.ids,
        1,
        vec![
            FederationSuccessionEdge {
                retiring_mesh_id: middle,
                successor_mesh_id: fixture.ids.remote_mesh,
            },
            FederationSuccessionEdge {
                retiring_mesh_id: fixture.ids.local_mesh,
                successor_mesh_id: middle,
            },
        ],
    )?;
    assert_rejected(
        &mut repository,
        fixture.ids,
        4,
        51,
        &AuthoritativeCommand::DesignateFederationSuccessor(circular),
    )?;
    let database = repository.into_database();
    let count: i64 = database.connection().query_row(
        "SELECT count(*) FROM federation_ownership_successions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

fn designation(
    ids: FixtureIds,
    succession_epoch: u64,
    ancestry: Vec<FederationSuccessionEdge>,
) -> Result<DesignateFederationSuccessor, Box<dyn std::error::Error>> {
    let mut command = DesignateFederationSuccessor {
        succession_id: ids.succession,
        relationship_id: ids.relationship,
        retiring_mesh_id: ids.remote_mesh,
        successor_mesh_id: ids.local_mesh,
        expected_authority_epoch: 1,
        succession_epoch,
        ancestry: BoundedItems::new(ancestry, 64)?,
        signer_generation: 1,
        signature: [0; 64],
    };
    command.signature = remote_key().sign(&command.signing_payload()).to_bytes();
    Ok(command)
}

fn acceptance(
    ids: FixtureIds,
    designation_digest: [u8; 32],
    succession_epoch: u64,
) -> AcceptFederationSuccessor {
    let mut command = AcceptFederationSuccessor {
        succession_id: ids.succession,
        relationship_id: ids.relationship,
        retiring_mesh_id: ids.remote_mesh,
        successor_mesh_id: ids.local_mesh,
        expected_authority_epoch: 1,
        succession_epoch,
        designation_digest,
        signer_generation: 1,
        signature: [0; 64],
    };
    command.signature = local_key().sign(&command.signing_payload()).to_bytes();
    command
}

fn prepare_relationship(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        1,
        context(3, ids.administrator, 4, 1, 0)?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: ids.local_mesh,
            mesh_name: RecordName::new("Successor swarm")?,
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
            remote_name: RecordName::new("Retiring swarm")?,
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
            local_identity: identity(12, &local_key()),
            remote_identity: identity(13, &remote_key()),
            governance_proof: None,
        }),
    )?;
    Ok(())
}

fn issue_storage_grant(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
    grant_id: FederationGrantId,
) -> Result<(), Box<dyn std::error::Error>> {
    let command = storage_grant_command(ids, grant_id)?;
    apply(
        repository,
        4,
        context(24, ids.administrator, 25, 4, 3)?,
        &command,
    )?;
    Ok(())
}

fn storage_grant_command(
    ids: FixtureIds,
    grant_id: FederationGrantId,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    let policy = FederationPolicy::Storage(StorageFederationPolicy::new(
        100,
        StorageParticipation::new(true, true),
        Some(DurationMicros::new(100)),
    )?);
    let grant = FederationGrant::new(
        grant_id,
        ids.relationship,
        FederatedPrincipal::new(ids.local_mesh, ids.administrator),
        FederationResourceScope::StorageCapacity {
            provider_mesh_id: ids.remote_mesh,
        },
        policy,
        1,
        UnixMicros::new(3),
        Some(UnixMicros::new(100)),
    )?;
    let restrictions = BoundedItems::new(
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
    )?;
    Ok(AuthoritativeCommand::IssueFederationGrant(
        IssueFederationGrant {
            grant,
            restrictions,
        },
    ))
}

fn assert_rejected(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
    index: u64,
    operation: u8,
    command: &AuthoritativeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let before = repository.current_revision()?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index, term: 1 },
            context(
                operation,
                ids.administrator,
                operation + 1,
                index,
                before.get()
            )?,
            command,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, before);
    Ok(())
}

fn verify_events(
    database: &PartitionDatabase,
    succession_id: FederationSuccessionId,
    expected: &[i64],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut statement = database.connection().prepare(
        "SELECT event_kind FROM federation_ownership_succession_events
         WHERE succession_id = ?1 ORDER BY event_sequence",
    )?;
    let actual = statement
        .query_map([succession_id.as_bytes().as_slice()], |row| row.get(0))?
        .collect::<Result<Vec<i64>, _>>()?;
    assert_eq!(actual, expected);
    Ok(())
}

fn payload_digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

fn local_key() -> SigningKey {
    SigningKey::from_bytes(&[14; 32])
}

fn remote_key() -> SigningKey {
    SigningKey::from_bytes(&[15; 32])
}

fn identity(fingerprint: u8, key: &SigningKey) -> FederationTrustIdentity {
    FederationTrustIdentity {
        generation: 1,
        certificate_fingerprint: [fingerprint; 32],
        verifying_key: key.verifying_key().to_bytes(),
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
    succession: FederationSuccessionId,
}

struct Fixture {
    directory: tempfile::TempDir,
    file_path: std::path::PathBuf,
    repository: AuthoritativeRepository,
    ids: FixtureIds,
}

impl Fixture {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("federation-succession.sqlite3");
        let ids = FixtureIds {
            administrator: PrincipalId::from_bytes([1; 16])?,
            partition: PartitionId::from_bytes([2; 16])?,
            local_mesh: MeshId::from_bytes([20; 16])?,
            remote_mesh: MeshId::from_bytes([21; 16])?,
            relationship: FederationRelationshipId::from_bytes([22; 16])?,
            succession: FederationSuccessionId::from_bytes([23; 16])?,
        };
        let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(0))?;
        Ok(Self {
            directory,
            file_path,
            repository: AuthoritativeRepository::new(database),
            ids,
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
