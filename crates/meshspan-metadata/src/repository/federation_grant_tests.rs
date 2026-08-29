// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, DurationMicros, FederatedPrincipal, FederationGrant, FederationGrantId,
    FederationPolicy, FederationRelationshipId, FederationRelationshipKind,
    FederationResourceScope, HostId, MeshId, NodeId, OperationId, PartitionId, PrincipalId,
    Revision, RoleId, StorageFederationPolicy, StorageParticipation, UnixMicros,
};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault, read_current_revision};
use super::{
    AuthoritativeRepository, EntityKind, FederationGrantState, FederationGrantTerminationKind,
    LogPosition, RepositoryError,
};

#[test]
fn every_apply_boundary_rolls_back_complete_grant_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let (repository, first_id, ids) = repository_with_active_grant(100)?;
    let second_id = FederationGrantId::from_bytes([101; 16])?;
    let command = AuthoritativeCommand::ReplaceFederationGrant(ReplaceFederationGrant {
        predecessor_grant_id: first_id,
        grant: grant(ids, second_id, storage_policy(40, false)?)?,
        restrictions: restrictions(ids, 80, 40)?,
        restricts_authority: true,
        reason: "Atomic restriction replacement".to_owned(),
    });
    let mut database = repository.into_database();
    for (offset, fault) in all_apply_faults().into_iter().enumerate() {
        let seed = 104_u8.saturating_add(u8::try_from(offset)?);
        assert!(matches!(
            apply_committed_with_fault(
                &mut database,
                LogPosition { index: 5, term: 1 },
                context(seed, ids.administrator, seed.saturating_add(4), 5, 4)?,
                &command,
                fault,
            ),
            Err(RepositoryError::InjectedFault)
        ));
        let retained: (i64, i64, i64, i64, i64) = database.connection().query_row(
            "SELECT
                (SELECT count(*) FROM federation_grants),
                (SELECT state FROM federation_grants WHERE grant_id = ?1),
                (SELECT count(*) FROM federation_grant_restrictions),
                (SELECT count(*) FROM federation_grant_successions),
                (SELECT count(*) FROM federation_grant_terminations)",
            [first_id.as_bytes().as_slice()],
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
        assert_eq!(retained, (1, 1, 2, 0, 0));
        assert_eq!(read_current_revision(&database)?, Revision::new(4));
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
use crate::{
    ApproveFederationRelationship, AuthoritativeCommand, BootstrapMesh, CommandContext,
    FederationGovernanceDirection, FederationGrantRestriction, FederationTrustIdentity,
    IssueFederationGrant, PartitionDatabase, ProposeFederationRelationship, RecordName,
    ReplaceFederationGrant, RevokeFederationGrant,
};

#[test]
fn bilateral_grant_intersection_replacement_and_revocation_survive_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let backup_directory = fixture.directory.path().to_path_buf();
    let file_path = fixture.file_path.clone();
    let mut repository = fixture.repository;
    prepare_relationship(&mut repository, fixture.ids)?;

    let first_id = FederationGrantId::from_bytes([30; 16])?;
    let first_restrictions = restrictions(fixture.ids, 100, 50)?;
    let invalid = grant(fixture.ids, first_id, storage_policy(100, true)?)?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 4, term: 1 },
            context(31, fixture.ids.administrator, 32, 4, 3)?,
            &AuthoritativeCommand::IssueFederationGrant(IssueFederationGrant {
                grant: invalid,
                restrictions: first_restrictions.clone(),
            }),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(3));

    let first = grant(fixture.ids, first_id, storage_policy(50, false)?)?;
    let receipt = repository.apply_committed(
        LogPosition { index: 4, term: 1 },
        context(33, fixture.ids.administrator, 34, 4, 3)?,
        &AuthoritativeCommand::IssueFederationGrant(IssueFederationGrant {
            grant: first,
            restrictions: first_restrictions,
        }),
    )?;
    assert_eq!(receipt.entity.kind, EntityKind::FederationGrant);
    assert_effective_capacity(&repository, first_id, 50)?;

    let second_id = FederationGrantId::from_bytes([35; 16])?;
    let second = grant(fixture.ids, second_id, storage_policy(40, false)?)?;
    apply(
        &mut repository,
        5,
        context(36, fixture.ids.administrator, 37, 5, 4)?,
        &AuthoritativeCommand::ReplaceFederationGrant(ReplaceFederationGrant {
            predecessor_grant_id: first_id,
            grant: second,
            restrictions: restrictions(fixture.ids, 80, 40)?,
            restricts_authority: true,
            reason: "Partner reduced its storage ceiling".to_owned(),
        }),
    )?;
    assert!(repository.active_federation_grant(first_id)?.is_none());
    assert_effective_capacity(&repository, second_id, 40)?;
    drop(repository);

    let database = PartitionDatabase::open(&file_path, fixture.ids.partition, UnixMicros::new(6))?;
    let mut repository = AuthoritativeRepository::new(database);
    assert_effective_capacity(&repository, second_id, 40)?;
    reject_broadening_restriction(&mut repository, fixture.ids, second_id)?;
    apply(
        &mut repository,
        6,
        context(42, fixture.ids.administrator, 43, 6, 5)?,
        &AuthoritativeCommand::RevokeFederationGrant(RevokeFederationGrant {
            grant_id: second_id,
            expected_authority_epoch: 1,
            reason: "Storage agreement ended".to_owned(),
        }),
    )?;
    assert!(repository.active_federation_grant(second_id)?.is_none());
    let restored = super::federation_backup_test_support::backup_and_restore(
        &repository,
        &backup_directory,
        91,
    )?;
    assert!(restored.active_federation_grant(second_id)?.is_none());
    let first_record = restored
        .federation_grant(first_id)?
        .ok_or("restored predecessor grant missing")?;
    assert_eq!(first_record.state, FederationGrantState::Revoked);
    assert_eq!(first_record.successor_grant_id, Some(second_id));
    let first_termination = first_record.termination.ok_or("termination missing")?;
    assert_eq!(
        first_termination.kind,
        FederationGrantTerminationKind::Restricted
    );
    assert_eq!(
        first_termination.reason.as_deref(),
        Some("Partner reduced its storage ceiling")
    );
    let second_record = restored
        .federation_grant(second_id)?
        .ok_or("restored revoked grant missing")?;
    assert_eq!(second_record.predecessor_grant_id, Some(first_id));
    assert_eq!(
        second_record
            .termination
            .ok_or("direct revocation evidence missing")?
            .reason
            .as_deref(),
        Some("Storage agreement ended")
    );
    verify_history(&restored.into_database(), first_id, second_id)
}

#[test]
fn grant_reads_reject_missing_restrictions_terminations_and_substituted_lineage()
-> Result<(), Box<dyn std::error::Error>> {
    reject_missing_restriction()?;
    reject_missing_termination()?;
    reject_substituted_succession_reason()
}

fn reject_missing_restriction() -> Result<(), Box<dyn std::error::Error>> {
    let (repository, grant_id, ids) = repository_with_active_grant(80)?;
    let database = repository.into_database();
    assert!(
        database
            .connection()
            .execute(
                "DELETE FROM federation_grant_restrictions WHERE grant_id = ?1",
                [grant_id.as_bytes().as_slice()],
            )
            .is_err()
    );
    database
        .connection()
        .execute_batch("DROP TRIGGER federation_grant_restrictions_reject_delete;")?;
    database.connection().execute(
        "DELETE FROM federation_grant_restrictions
         WHERE grant_id = ?1 AND imposing_mesh_id = ?2",
        rusqlite::params![
            grant_id.as_bytes().as_slice(),
            ids.remote_mesh.as_bytes().as_slice(),
        ],
    )?;
    assert_corrupt_grant(database, grant_id);
    Ok(())
}

fn reject_missing_termination() -> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, grant_id, ids) = repository_with_active_grant(81)?;
    apply(
        &mut repository,
        5,
        context(90, ids.administrator, 91, 5, 4)?,
        &AuthoritativeCommand::RevokeFederationGrant(RevokeFederationGrant {
            grant_id,
            expected_authority_epoch: 1,
            reason: "Evidence removal test".to_owned(),
        }),
    )?;
    let database = repository.into_database();
    assert!(
        database
            .connection()
            .execute(
                "DELETE FROM federation_grant_terminations WHERE grant_id = ?1",
                [grant_id.as_bytes().as_slice()],
            )
            .is_err()
    );
    database.connection().execute_batch(
        "DROP TRIGGER federation_grant_terminations_reject_delete;
         DELETE FROM federation_grant_terminations;",
    )?;
    assert_corrupt_grant(database, grant_id);
    Ok(())
}

fn reject_substituted_succession_reason() -> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, first_id, ids) = repository_with_active_grant(84)?;
    let second_id = FederationGrantId::from_bytes([85; 16])?;
    apply(
        &mut repository,
        5,
        context(86, ids.administrator, 87, 5, 4)?,
        &AuthoritativeCommand::ReplaceFederationGrant(ReplaceFederationGrant {
            predecessor_grant_id: first_id,
            grant: grant(ids, second_id, storage_policy(40, false)?)?,
            restrictions: restrictions(ids, 80, 40)?,
            restricts_authority: true,
            reason: "Original exact reason".to_owned(),
        }),
    )?;
    let database = repository.into_database();
    database.connection().execute_batch(
        "DROP TRIGGER federation_grant_successions_reject_update;
         UPDATE federation_grant_successions SET reason = 'Substituted reason';",
    )?;
    assert_corrupt_grant(database, first_id);
    Ok(())
}

fn repository_with_active_grant(
    grant_seed: u8,
) -> Result<(AuthoritativeRepository, FederationGrantId, FixtureIds), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let ids = fixture.ids;
    let mut repository = fixture.repository;
    prepare_relationship(&mut repository, ids)?;
    let grant_id = FederationGrantId::from_bytes([grant_seed; 16])?;
    apply(
        &mut repository,
        4,
        context(
            grant_seed.saturating_add(1),
            ids.administrator,
            grant_seed.saturating_add(2),
            4,
            3,
        )?,
        &AuthoritativeCommand::IssueFederationGrant(IssueFederationGrant {
            grant: grant(ids, grant_id, storage_policy(50, false)?)?,
            restrictions: restrictions(ids, 100, 50)?,
        }),
    )?;
    Ok((repository, grant_id, ids))
}

fn assert_corrupt_grant(database: PartitionDatabase, grant_id: FederationGrantId) {
    let repository = AuthoritativeRepository::new(database);
    assert!(matches!(
        repository.federation_grant(grant_id),
        Err(RepositoryError::CorruptState)
    ));
}

fn reject_broadening_restriction(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
    predecessor: FederationGrantId,
) -> Result<(), Box<dyn std::error::Error>> {
    let broader_id = FederationGrantId::from_bytes([38; 16])?;
    let broader = grant(ids, broader_id, storage_policy(60, false)?)?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 6, term: 1 },
            context(39, ids.administrator, 40, 6, 5)?,
            &AuthoritativeCommand::ReplaceFederationGrant(ReplaceFederationGrant {
                predecessor_grant_id: predecessor,
                grant: broader,
                restrictions: restrictions(ids, 80, 60)?,
                restricts_authority: true,
                reason: "Attempted broadening".to_owned(),
            }),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(5));
    assert!(repository.active_federation_grant(broader_id)?.is_none());
    Ok(())
}

fn assert_effective_capacity(
    repository: &AuthoritativeRepository,
    grant_id: FederationGrantId,
    expected_bytes: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let record = repository
        .active_federation_grant(grant_id)?
        .ok_or("active grant missing")?;
    let FederationPolicy::Storage(policy) = record.grant.policy() else {
        return Err("storage policy expected".into());
    };
    assert_eq!(policy.maximum_storage_bytes(), expected_bytes);
    assert_eq!(record.restrictions.len(), 2);
    Ok(())
}

fn verify_history(
    database: &PartitionDatabase,
    first: FederationGrantId,
    second: FederationGrantId,
) -> Result<(), Box<dyn std::error::Error>> {
    let row: (i64, i64, i64, Vec<u8>) = database.connection().query_row(
        "SELECT
            (SELECT state FROM federation_grants WHERE grant_id = ?1),
            (SELECT state FROM federation_grants WHERE grant_id = ?2),
            (SELECT count(*) FROM federation_grant_successions
             WHERE predecessor_grant_id = ?1),
            (SELECT successor_grant_id FROM federation_grant_successions
             WHERE predecessor_grant_id = ?1)",
        rusqlite::params![first.as_bytes().as_slice(), second.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!((row.0, row.1, row.2), (3, 3, 1));
    assert_eq!(row.3.as_slice(), second.as_bytes());
    Ok(())
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
            remote_name: RecordName::new("Storage partner")?,
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
            local_identity: identity(1, 12, 13),
            remote_identity: identity(1, 14, 15),
            governance_proof: None,
        }),
    )
    .map_err(Into::into)
}

fn grant(
    ids: FixtureIds,
    grant_id: FederationGrantId,
    policy: FederationPolicy,
) -> Result<FederationGrant, Box<dyn std::error::Error>> {
    Ok(FederationGrant::new(
        grant_id,
        ids.relationship,
        FederatedPrincipal::new(ids.local_mesh, ids.administrator),
        FederationResourceScope::StorageCapacity {
            provider_mesh_id: ids.remote_mesh,
        },
        policy,
        1,
        UnixMicros::new(4),
        Some(UnixMicros::new(24)),
    )?)
}

fn restrictions(
    ids: FixtureIds,
    local_bytes: u64,
    remote_bytes: u64,
) -> Result<BoundedItems<FederationGrantRestriction>, Box<dyn std::error::Error>> {
    Ok(BoundedItems::new(
        vec![
            FederationGrantRestriction {
                imposing_mesh_id: ids.local_mesh,
                policy: storage_policy(local_bytes, true)?,
            },
            FederationGrantRestriction {
                imposing_mesh_id: ids.remote_mesh,
                policy: storage_policy(remote_bytes, false)?,
            },
        ],
        2,
    )?)
}

fn storage_policy(
    bytes: u64,
    counts_towards_protection: bool,
) -> Result<FederationPolicy, Box<dyn std::error::Error>> {
    Ok(FederationPolicy::Storage(StorageFederationPolicy::new(
        bytes,
        StorageParticipation::new(counts_towards_protection, true),
        Some(DurationMicros::new(20)),
    )?))
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
}

impl Fixture {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join("federation-grants.sqlite3");
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
        })
    }
}

fn identity(generation: u64, fingerprint: u8, key: u8) -> FederationTrustIdentity {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[key; 32]);
    FederationTrustIdentity {
        generation,
        certificate_fingerprint: [fingerprint; 32],
        verifying_key: signing_key.verifying_key().to_bytes(),
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
