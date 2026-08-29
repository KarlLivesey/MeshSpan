// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    AuditEventId, FederationRelationshipId, FederationRelationshipKind, HostId, MeshId, NodeId,
    OperationId, PartitionId, PrincipalId, Revision, RoleId, UnixMicros,
};
use tempfile::tempdir;

use super::{
    ApplyDisposition, AuthoritativeRepository, CommandReceipt, EntityKind,
    FederationRelationshipState, LogPosition, RepositoryError,
};
use crate::{
    ApproveFederationRelationship, AuthoritativeCommand, BootstrapMesh, CommandContext,
    FederationGovernanceDirection, FederationIdentityOwner, FederationTrustIdentity,
    PartitionDatabase, ProposeFederationRelationship, RecordName, RecoverFederationRelationship,
    RestrictFederationRelationship, RetireFederationRelationship, RevokeFederationRelationship,
    RotateFederationTrustIdentity,
};

#[test]
fn relationship_lifecycle_is_fenced_audited_replayable_and_restart_safe()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let file_path = fixture.file_path.clone();
    let mut repository = fixture.repository;
    bootstrap(&mut repository, fixture.ids)?;
    let relationship_id = FederationRelationshipId::from_bytes([20; 16])?;
    prepare_active_relationship(&mut repository, fixture.ids, relationship_id)?;
    let (retirement_context, retirement, receipt) =
        advance_relationship_to_retired(&mut repository, fixture.ids, relationship_id)?;
    assert_eq!(receipt.entity.kind, EntityKind::FederationRelationship);
    drop(repository);

    let database = PartitionDatabase::open(&file_path, fixture.ids.partition, UnixMicros::new(9))?;
    let mut repository = AuthoritativeRepository::new(database);
    let replay = repository.apply_committed(
        LogPosition { index: 9, term: 1 },
        retirement_context,
        &retirement,
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    verify_lifecycle(&repository.into_database(), relationship_id)
}

fn prepare_active_relationship(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
    relationship_id: FederationRelationshipId,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        2,
        context(21, ids.administrator, 22, 2, 1)?,
        &AuthoritativeCommand::ProposeFederationRelationship(ProposeFederationRelationship {
            relationship_id,
            remote_mesh_id: MeshId::from_bytes([23; 16])?,
            remote_name: RecordName::new("Remote swarm")?,
            kind: FederationRelationshipKind::Horizontal,
            governance_direction: FederationGovernanceDirection::None,
        }),
    )?;
    apply(
        repository,
        3,
        context(24, ids.administrator, 25, 3, 2)?,
        &AuthoritativeCommand::ApproveFederationRelationship(ApproveFederationRelationship {
            relationship_id,
            expected_authority_epoch: 1,
            local_identity: identity(1, 26, 27),
            remote_identity: identity(1, 28, 29),
        }),
    )?;
    let relationship = repository
        .federation_relationship(relationship_id)?
        .ok_or("approved relationship missing")?;
    assert_eq!(relationship.state, FederationRelationshipState::Active);
    assert_eq!(relationship.authority_epoch, 1);
    assert_eq!(
        repository
            .active_federation_trust_identity(relationship_id, FederationIdentityOwner::Remote,)?
            .ok_or("remote identity missing")?
            .identity,
        identity(1, 28, 29)
    );
    Ok(())
}

fn advance_relationship_to_retired(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
    relationship_id: FederationRelationshipId,
) -> Result<(CommandContext, AuthoritativeCommand, CommandReceipt), Box<dyn std::error::Error>> {
    let invalid_rotation =
        AuthoritativeCommand::RotateFederationTrustIdentity(RotateFederationTrustIdentity {
            relationship_id,
            expected_authority_epoch: 1,
            owner: FederationIdentityOwner::Remote,
            identity: identity(1, 30, 31),
        });
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 4, term: 1 },
            context(32, ids.administrator, 33, 4, 3)?,
            &invalid_rotation,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(3));

    apply(
        repository,
        4,
        context(34, ids.administrator, 35, 4, 3)?,
        &AuthoritativeCommand::RotateFederationTrustIdentity(RotateFederationTrustIdentity {
            relationship_id,
            expected_authority_epoch: 1,
            owner: FederationIdentityOwner::Remote,
            identity: identity(2, 36, 37),
        }),
    )?;
    apply(
        repository,
        5,
        context(38, ids.administrator, 39, 5, 4)?,
        &AuthoritativeCommand::RestrictFederationRelationship(RestrictFederationRelationship {
            relationship_id,
            expected_authority_epoch: 1,
            authority_epoch: 2,
            reason: "Peer-requested maintenance restriction".to_owned(),
        }),
    )?;
    apply(
        repository,
        6,
        context(40, ids.administrator, 41, 6, 5)?,
        &AuthoritativeCommand::RecoverFederationRelationship(RecoverFederationRelationship {
            relationship_id,
            expected_authority_epoch: 2,
            authority_epoch: 3,
            reason: "Mutual recovery proof accepted".to_owned(),
        }),
    )?;
    apply(
        repository,
        7,
        context(42, ids.administrator, 43, 7, 6)?,
        &AuthoritativeCommand::RevokeFederationRelationship(RevokeFederationRelationship {
            relationship_id,
            expected_authority_epoch: 3,
            authority_epoch: 4,
            reason: "Relationship ended by both swarms".to_owned(),
        }),
    )?;
    let retirement_context = context(44, ids.administrator, 45, 8, 7)?;
    let retirement =
        AuthoritativeCommand::RetireFederationRelationship(RetireFederationRelationship {
            relationship_id,
            expected_authority_epoch: 4,
            authority_epoch: 5,
            reason: "Retention window completed".to_owned(),
        });
    let receipt = repository.apply_committed(
        LogPosition { index: 8, term: 1 },
        retirement_context,
        &retirement,
    )?;
    Ok((retirement_context, retirement, receipt))
}

#[test]
fn approval_rejects_reflected_identity_and_rolls_back_both_sides()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let mut repository = fixture.repository;
    bootstrap(&mut repository, fixture.ids)?;
    let relationship_id = FederationRelationshipId::from_bytes([50; 16])?;
    apply(
        &mut repository,
        2,
        context(51, fixture.ids.administrator, 52, 2, 1)?,
        &AuthoritativeCommand::ProposeFederationRelationship(ProposeFederationRelationship {
            relationship_id,
            remote_mesh_id: MeshId::from_bytes([53; 16])?,
            remote_name: RecordName::new("Untrusted reflection")?,
            kind: FederationRelationshipKind::Governance,
            governance_direction: FederationGovernanceDirection::LocalGovernsRemote,
        }),
    )?;
    let reflected = identity(1, 54, 55);
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 3, term: 1 },
            context(56, fixture.ids.administrator, 57, 3, 2)?,
            &AuthoritativeCommand::ApproveFederationRelationship(ApproveFederationRelationship {
                relationship_id,
                expected_authority_epoch: 1,
                local_identity: reflected,
                remote_identity: reflected,
            }),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    let database = repository.into_database();
    let relationship = relationship_id.as_bytes();
    let (state, identities, edges): (i64, i64, i64) = database.connection().query_row(
        "SELECT state,
                (SELECT count(*) FROM federation_trust_identities WHERE relationship_id = ?1),
                (SELECT count(*) FROM federation_governance_edges WHERE relationship_id = ?1)
         FROM federation_relationships WHERE relationship_id = ?1",
        [relationship.as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!((state, identities, edges), (1, 0, 0));
    Ok(())
}

fn verify_lifecycle(
    database: &PartitionDatabase,
    relationship_id: FederationRelationshipId,
) -> Result<(), Box<dyn std::error::Error>> {
    let relationship = relationship_id.as_bytes();
    let row: (i64, i64, i64, i64, i64) = database.connection().query_row(
        "SELECT state, authority_epoch,
                (SELECT count(*) FROM federation_relationship_events
                 WHERE relationship_id = ?1),
                (SELECT count(*) FROM federation_trust_identities
                 WHERE relationship_id = ?1),
                (SELECT count(*) FROM federation_trust_identities
                 WHERE relationship_id = ?1 AND state = 1)
         FROM federation_relationships WHERE relationship_id = ?1",
        [relationship.as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    assert_eq!(row, (5, 5, 6, 3, 0));
    Ok(())
}

#[derive(Clone, Copy)]
struct FixtureIds {
    administrator: PrincipalId,
    partition: PartitionId,
}

struct Fixture {
    _directory: tempfile::TempDir,
    file_path: std::path::PathBuf,
    repository: AuthoritativeRepository,
    ids: FixtureIds,
}

impl Fixture {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("relationship.sqlite3");
        let ids = FixtureIds {
            administrator: PrincipalId::from_bytes([1; 16])?,
            partition: PartitionId::from_bytes([2; 16])?,
        };
        let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(0))?;
        Ok(Self {
            _directory: directory,
            file_path,
            repository: AuthoritativeRepository::new(database),
            ids,
        })
    }
}

fn bootstrap(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        1,
        context(3, ids.administrator, 4, 1, 0)?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([5; 16])?,
            mesh_name: RecordName::new("Local swarm")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([6; 16])?,
            host_id: HostId::from_bytes([7; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([8; 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        }),
    )?;
    Ok(())
}

fn identity(generation: u64, fingerprint: u8, key: u8) -> FederationTrustIdentity {
    FederationTrustIdentity {
        generation,
        certificate_fingerprint: [fingerprint; 32],
        verifying_key: [key; 32],
        valid_from: UnixMicros::new(1),
        valid_until: UnixMicros::new(100),
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
