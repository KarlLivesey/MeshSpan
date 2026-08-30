// SPDX-License-Identifier: GPL-2.0-only

use ed25519_dalek::SigningKey;
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, DurationMicros, FederatedPrincipal, FederationGrant, FederationGrantId,
    FederationPolicy, FederationRelationshipId, FederationRelationshipKind,
    FederationResourceScope, FederationStorageAllocation, FederationStorageAllocationId, HostId,
    MeshId, NodeId, OperationId, PartitionId, PrincipalId, Revision, RoleId,
    StorageFederationPolicy, StorageParticipation, TargetId, UnixMicros,
};
use tempfile::tempdir;

use super::apply::ApplyFaultPoint;
use super::{
    ApplyDisposition, AuthoritativeRepository, EntityKind, FederationStorageAllocationState,
    InvariantKind, LogPosition, PageLimit, RepositoryError,
};
use crate::{
    ApproveFederationRelationship, AuthoritativeCommand, BootstrapMesh, CommandContext,
    FederationGovernanceDirection, FederationGrantRestriction, FederationTrustIdentity,
    IssueFederationGrant, IssueFederationStorageAllocation, PartitionDatabase,
    ProposeFederationRelationship, RecordName, RevokeFederationRelationship,
    RevokeFederationStorageAllocation,
};

#[test]
fn bilateral_quota_is_disjoint_reusable_and_durable() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let file_path = fixture.file_path.clone();
    let ids = fixture.ids;
    let mut repository = fixture.repository;
    prepare_storage_authority(&mut repository, ids)?;

    let first = allocation(ids, 30, 31, 1, 20, 10, 20)?;
    let second = allocation(ids, 32, 33, 1, 30, 10, 20)?;
    let first_receipt = apply_allocation(&mut repository, 5, 34, ids, first)?;
    assert_eq!(
        first_receipt.entity.kind,
        EntityKind::FederationStorageAllocation
    );
    apply_allocation(&mut repository, 6, 35, ids, second)?;

    let over_limit = allocation(ids, 36, 37, 1, 1, 15, 19)?;
    assert!(matches!(
        repository.apply_committed(
            position(7),
            context(38, ids.administrator, 15, 6)?,
            &issue(over_limit),
        ),
        Err(RepositoryError::CapacityExceeded)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(6));
    assert!(
        repository
            .federation_storage_allocation(over_limit.allocation_id())?
            .is_none()
    );

    let reused = allocation(ids, 39, 40, 2, 50, 20, 30)?;
    let reused_receipt = apply_allocation(&mut repository, 7, 41, ids, reused)?;
    let replay = repository.apply_committed(
        position(8),
        context(41, ids.administrator, 7, 6)?,
        &issue(reused),
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.committed_revision, reused_receipt.committed_revision);

    let substituted = allocation(ids, 39, 42, 2, 49, 20, 30)?;
    assert!(matches!(
        repository.apply_committed(
            position(9),
            context(41, ids.administrator, 7, 6)?,
            &issue(substituted),
        ),
        Err(RepositoryError::OperationConflict)
    ));

    apply(
        &mut repository,
        9,
        context(43, ids.administrator, 25, 7)?,
        &AuthoritativeCommand::RevokeFederationStorageAllocation(
            RevokeFederationStorageAllocation {
                allocation_id: reused.allocation_id(),
                expected_allocation_revision: Revision::new(7),
                reason: "Provider target drained".to_owned(),
            },
        ),
    )?;
    let revoked = repository
        .federation_storage_allocation(reused.allocation_id())?
        .ok_or("revoked allocation missing")?;
    assert_eq!(revoked.state, FederationStorageAllocationState::Revoked);
    assert_eq!(revoked.revoked_at, Some(UnixMicros::new(25)));
    assert_eq!(revoked.revision, Revision::new(8));
    drop(repository);

    let reopened = AuthoritativeRepository::new(PartitionDatabase::open(
        &file_path,
        ids.partition,
        UnixMicros::new(31),
    )?);
    assert_eq!(
        reopened
            .federation_storage_allocation(first.allocation_id())?
            .ok_or("first allocation missing after reopen")?
            .allocation,
        first
    );
    assert_eq!(
        reopened
            .federation_storage_allocation(reused.allocation_id())?
            .ok_or("revoked allocation missing after reopen")?
            .state,
        FederationStorageAllocationState::Revoked
    );
    Ok(())
}

#[test]
fn issuance_revalidates_every_authority_fence() -> Result<(), Box<dyn std::error::Error>> {
    reject_stale_grant_revision()?;
    reject_unknown_provider_node()?;
    reject_outside_grant_interval()?;
    reject_non_provider_mesh_grant()?;
    reject_revoked_relationship()
}

#[test]
fn allocation_write_is_atomic_and_evidence_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::open()?;
    let ids = fixture.ids;
    let mut repository = fixture.repository;
    prepare_storage_authority(&mut repository, ids)?;
    let allocation = allocation(ids, 60, 61, 1, 20, 10, 20)?;
    let command = issue(allocation);
    assert!(matches!(
        repository.apply_committed_with_fault(
            position(5),
            context(62, ids.administrator, 5, 4)?,
            &command,
            ApplyFaultPoint::AfterCommand,
        ),
        Err(RepositoryError::InjectedFault)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(4));
    assert!(
        repository
            .federation_storage_allocation(allocation.allocation_id())?
            .is_none()
    );
    apply(
        &mut repository,
        5,
        context(62, ids.administrator, 5, 4)?,
        &command,
    )?;

    let database = repository.into_database();
    assert!(
        database
            .connection()
            .execute(
                "DELETE FROM federation_storage_allocations WHERE allocation_id = ?1",
                [allocation.allocation_id().as_bytes().as_slice()],
            )
            .is_err()
    );
    assert!(
        database
            .connection()
            .execute(
                "UPDATE federation_storage_allocations SET maximum_bytes = 1
                 WHERE allocation_id = ?1",
                [allocation.allocation_id().as_bytes().as_slice()],
            )
            .is_err()
    );
    database.connection().execute_batch(
        "DROP TRIGGER federation_storage_allocations_reject_identity_update;
         PRAGMA ignore_check_constraints = ON;
         UPDATE federation_storage_allocations SET maximum_bytes = -1;
         PRAGMA ignore_check_constraints = OFF;",
    )?;
    let corrupted = AuthoritativeRepository::new(database);
    assert!(matches!(
        corrupted.federation_storage_allocation(allocation.allocation_id()),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

#[test]
fn invariant_scan_detects_validly_shaped_quota_overcommit() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::open()?;
    let ids = fixture.ids;
    let mut repository = fixture.repository;
    prepare_storage_authority(&mut repository, ids)?;
    let first = allocation(ids, 63, 64, 1, 20, 10, 20)?;
    let second = allocation(ids, 65, 66, 1, 30, 10, 20)?;
    apply_allocation(&mut repository, 5, 67, ids, first)?;
    apply_allocation(&mut repository, 6, 68, ids, second)?;
    let database = repository.into_database();
    database.connection().execute_batch(
        "DROP TRIGGER federation_storage_allocations_reject_identity_update;
         UPDATE federation_storage_allocations SET maximum_bytes = 40
         WHERE allocation_id = X'3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F3F';",
    )?;
    let corrupted = AuthoritativeRepository::new(database);
    let report = corrupted.check_invariants(PageLimit::new(32)?)?;
    assert!(report.findings.iter().any(|finding| {
        finding.kind == InvariantKind::OvercommittedFederationStorageAllocation
    }));
    Ok(())
}

fn reject_stale_grant_revision() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let ids = fixture.ids;
    let mut repository = fixture.repository;
    prepare_storage_authority(&mut repository, ids)?;
    let value = allocation(ids, 70, 71, 1, 10, 10, 20)?;
    let command =
        AuthoritativeCommand::IssueFederationStorageAllocation(IssueFederationStorageAllocation {
            allocation: value,
            expected_grant_revision: Revision::new(3),
        });
    assert_invalid_without_revision(&mut repository, ids, &command)
}

fn reject_unknown_provider_node() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let ids = fixture.ids;
    let mut repository = fixture.repository;
    prepare_storage_authority(&mut repository, ids)?;
    let value = FederationStorageAllocation::new(
        FederationStorageAllocationId::from_bytes([72; 16])?,
        ids.grant,
        NodeId::from_bytes([73; 16])?,
        TargetId::from_bytes([74; 16])?,
        1,
        10,
        UnixMicros::new(10),
        UnixMicros::new(20),
    )?;
    assert_invalid_without_revision(&mut repository, ids, &issue(value))
}

fn reject_outside_grant_interval() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let ids = fixture.ids;
    let mut repository = fixture.repository;
    prepare_storage_authority(&mut repository, ids)?;
    let value = allocation(ids, 75, 76, 1, 10, 99, 101)?;
    assert_invalid_without_revision(&mut repository, ids, &issue(value))
}

fn reject_non_provider_mesh_grant() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let mut ids = fixture.ids;
    let mut repository = fixture.repository;
    prepare_relationship(&mut repository, ids)?;
    ids.grant = FederationGrantId::from_bytes([77; 16])?;
    issue_storage_grant(&mut repository, ids, ids.remote_mesh)?;
    let value = allocation(ids, 78, 79, 1, 10, 10, 20)?;
    assert_invalid_without_revision(&mut repository, ids, &issue(value))
}

fn reject_revoked_relationship() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::open()?;
    let ids = fixture.ids;
    let mut repository = fixture.repository;
    prepare_storage_authority(&mut repository, ids)?;
    apply(
        &mut repository,
        5,
        context(80, ids.administrator, 6, 4)?,
        &AuthoritativeCommand::RevokeFederationRelationship(RevokeFederationRelationship {
            relationship_id: ids.relationship,
            expected_authority_epoch: 1,
            authority_epoch: 2,
            reason: "Federation trust revoked".to_owned(),
        }),
    )?;
    let value = allocation(ids, 81, 82, 1, 10, 10, 20)?;
    assert!(matches!(
        repository.apply_committed(
            position(6),
            context(83, ids.administrator, 7, 5)?,
            &issue(value),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

fn assert_invalid_without_revision(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
    command: &AuthoritativeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        repository.apply_committed(position(5), context(90, ids.administrator, 5, 4)?, command,),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(4));
    Ok(())
}

fn prepare_storage_authority(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
) -> Result<(), Box<dyn std::error::Error>> {
    prepare_relationship(repository, ids)?;
    issue_storage_grant(repository, ids, ids.local_mesh)
}

fn prepare_relationship(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        1,
        context(3, ids.administrator, 1, 0)?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: ids.local_mesh,
            mesh_name: RecordName::new("Local swarm")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([5; 16])?,
            host_id: HostId::from_bytes([6; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: ids.provider_node,
            node_name: RecordName::new("Provider node")?,
            partition_name: RecordName::new("Root authority")?,
        }),
    )?;
    apply(
        repository,
        2,
        context(8, ids.administrator, 2, 1)?,
        &AuthoritativeCommand::ProposeFederationRelationship(ProposeFederationRelationship {
            relationship_id: ids.relationship,
            remote_mesh_id: ids.remote_mesh,
            remote_name: RecordName::new("Storage consumer")?,
            kind: FederationRelationshipKind::Horizontal,
            governance_direction: FederationGovernanceDirection::None,
        }),
    )?;
    apply(
        repository,
        3,
        context(9, ids.administrator, 3, 2)?,
        &AuthoritativeCommand::ApproveFederationRelationship(ApproveFederationRelationship {
            relationship_id: ids.relationship,
            expected_authority_epoch: 1,
            local_identity: identity(1, 10, 11),
            remote_identity: identity(1, 12, 13),
            governance_proof: None,
        }),
    )?;
    Ok(())
}

fn issue_storage_grant(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
    provider_mesh_id: MeshId,
) -> Result<(), Box<dyn std::error::Error>> {
    let subject_mesh = if provider_mesh_id == ids.local_mesh {
        ids.remote_mesh
    } else {
        ids.local_mesh
    };
    let effective = storage_policy(50, false)?;
    apply(
        repository,
        4,
        context(14, ids.administrator, 4, 3)?,
        &AuthoritativeCommand::IssueFederationGrant(IssueFederationGrant {
            grant: FederationGrant::new(
                ids.grant,
                ids.relationship,
                FederatedPrincipal::new(subject_mesh, ids.administrator),
                FederationResourceScope::StorageCapacity { provider_mesh_id },
                effective,
                1,
                UnixMicros::new(4),
                Some(UnixMicros::new(100)),
            )?,
            restrictions: BoundedItems::new(
                vec![
                    FederationGrantRestriction {
                        imposing_mesh_id: ids.local_mesh,
                        policy: storage_policy(80, true)?,
                    },
                    FederationGrantRestriction {
                        imposing_mesh_id: ids.remote_mesh,
                        policy: storage_policy(50, false)?,
                    },
                ],
                2,
            )?,
        }),
    )?;
    Ok(())
}

fn storage_policy(
    maximum_bytes: u64,
    counts_towards_protection: bool,
) -> Result<FederationPolicy, Box<dyn std::error::Error>> {
    Ok(FederationPolicy::Storage(StorageFederationPolicy::new(
        maximum_bytes,
        StorageParticipation::new(counts_towards_protection, true),
        Some(DurationMicros::new(200)),
    )?))
}

fn allocation(
    ids: FixtureIds,
    allocation_seed: u8,
    target_seed: u8,
    target_generation: u64,
    maximum_bytes: u64,
    valid_from: i64,
    valid_until: i64,
) -> Result<FederationStorageAllocation, Box<dyn std::error::Error>> {
    Ok(FederationStorageAllocation::new(
        FederationStorageAllocationId::from_bytes([allocation_seed; 16])?,
        ids.grant,
        ids.provider_node,
        TargetId::from_bytes([target_seed; 16])?,
        target_generation,
        maximum_bytes,
        UnixMicros::new(valid_from),
        UnixMicros::new(valid_until),
    )?)
}

const fn issue(allocation: FederationStorageAllocation) -> AuthoritativeCommand {
    AuthoritativeCommand::IssueFederationStorageAllocation(IssueFederationStorageAllocation {
        allocation,
        expected_grant_revision: Revision::new(4),
    })
}

fn apply_allocation(
    repository: &mut AuthoritativeRepository,
    index: u64,
    operation: u8,
    ids: FixtureIds,
    allocation: FederationStorageAllocation,
) -> Result<super::CommandReceipt, Box<dyn std::error::Error>> {
    Ok(repository.apply_committed(
        position(index),
        context(
            operation,
            ids.administrator,
            i64::try_from(index)?,
            index - 1,
        )?,
        &issue(allocation),
    )?)
}

fn apply(
    repository: &mut AuthoritativeRepository,
    index: u64,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<(), RepositoryError> {
    repository
        .apply_committed(position(index), context, command)
        .map(|_| ())
}

const fn position(index: u64) -> LogPosition {
    LogPosition { index, term: 1 }
}

fn context(
    operation: u8,
    actor: PrincipalId,
    occurred_at: i64,
    expected_revision: u64,
) -> Result<CommandContext, Box<dyn std::error::Error>> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation; 16])?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes([operation.saturating_add(100); 16])?,
        occurred_at: UnixMicros::new(occurred_at),
        expected_revision: Some(Revision::new(expected_revision)),
    })
}

#[derive(Clone, Copy)]
struct FixtureIds {
    administrator: PrincipalId,
    partition: PartitionId,
    local_mesh: MeshId,
    remote_mesh: MeshId,
    relationship: FederationRelationshipId,
    grant: FederationGrantId,
    provider_node: NodeId,
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
        let file_path = directory.path().join("federation-storage.sqlite3");
        let ids = FixtureIds {
            administrator: PrincipalId::from_bytes([1; 16])?,
            partition: PartitionId::from_bytes([2; 16])?,
            local_mesh: MeshId::from_bytes([20; 16])?,
            remote_mesh: MeshId::from_bytes([21; 16])?,
            relationship: FederationRelationshipId::from_bytes([22; 16])?,
            grant: FederationGrantId::from_bytes([23; 16])?,
            provider_node: NodeId::from_bytes([7; 16])?,
        };
        let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(1))?;
        Ok(Self {
            _directory: directory,
            file_path,
            repository: AuthoritativeRepository::new(database),
            ids,
        })
    }
}

fn identity(generation: u64, fingerprint: u8, key: u8) -> FederationTrustIdentity {
    let signing_key = SigningKey::from_bytes(&[key; 32]);
    FederationTrustIdentity {
        generation,
        certificate_fingerprint: [fingerprint; 32],
        verifying_key: signing_key.verifying_key().to_bytes(),
        valid_from: UnixMicros::new(1),
        valid_until: UnixMicros::new(200),
    }
}
