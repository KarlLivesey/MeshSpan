// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    AuditEventId, ComponentInstanceId, HostId, MeshId, NodeId, OperationId, PartitionId,
    PrincipalId, Revision, RoleId, TargetId, UnixMicros, WorkId,
};
use meshspan_work::{DrainScope, WorkDemand, WorkSignals, WorkSubject};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tempfile::tempdir;

use super::{ApplyDisposition, AuthoritativeRepository, EntityKind, LogPosition, RepositoryError};
use crate::{
    AuthoritativeCommand, BeginStorageTargetDrain, BootstrapMesh, CommandContext, CreateComponent,
    PartitionDatabase, QueueMaintenanceWork, RecordName, RegisterStorageTarget, StorageUsageLimit,
};

struct Fixture {
    _directory: TempDir,
    repository: AuthoritativeRepository,
    administrator: PrincipalId,
    node: NodeId,
    host: HostId,
    provider: ComponentInstanceId,
}

struct StoredTarget {
    node_id: Vec<u8>,
    host_id: Vec<u8>,
    provider_instance_id: Vec<u8>,
    generation: i64,
    usage_limit_kind: i64,
    usage_limit_value: i64,
}

struct StoredTargetGeneration {
    marker_fingerprint: Vec<u8>,
    backing_device_fingerprint: Option<Vec<u8>>,
    filesystem_fingerprint: Option<Vec<u8>>,
    state: i64,
}

#[test]
fn registered_target_binds_provider_topology_marker_and_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let context = context(30, fixture.administrator, 31, 30, Some(1))?;
    let command = target_command(&fixture, StorageUsageLimit::Percent(95))?;
    let receipt =
        fixture
            .repository
            .apply_committed(LogPosition { index: 2, term: 1 }, context, &command)?;
    assert_eq!(receipt.disposition, ApplyDisposition::Applied);
    assert_eq!(receipt.entity.kind, EntityKind::StorageTarget);
    assert_eq!(
        receipt.entity.id,
        TargetId::from_bytes([40; 16])?.as_bytes()
    );

    let replay =
        fixture
            .repository
            .apply_committed(LogPosition { index: 3, term: 1 }, context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);

    let provider_context = fixture
        .repository
        .storage_target_provider_context(fixture.node, TargetId::from_bytes([40; 16])?)?
        .ok_or("active provider context missing")?;
    assert_eq!(provider_context.mesh_id, MeshId::from_bytes([7; 16])?);
    assert_eq!(provider_context.node_id, fixture.node);
    assert_eq!(provider_context.target_id, TargetId::from_bytes([40; 16])?);
    assert_eq!(provider_context.generation, 1);
    assert_eq!(provider_context.usage_limit, StorageUsageLimit::Percent(95));
    assert_eq!(provider_context.policy_revision, Revision::new(2));
    assert_eq!(provider_context.catalogue_revision, Revision::new(2));
    assert_eq!(
        fixture.repository.storage_target_provider_context(
            NodeId::from_bytes([99; 16])?,
            TargetId::from_bytes([40; 16])?
        )?,
        None
    );

    let database = fixture.repository.into_database();
    let stored: StoredTarget = database.connection().query_row(
        "SELECT st.node_id, st.host_id, st.provider_instance_id, st.current_generation,
                st.usage_limit_kind, st.usage_limit_value
         FROM storage_targets AS st WHERE st.target_id = ?1",
        [TargetId::from_bytes([40; 16])?.as_bytes().as_slice()],
        |row| {
            Ok(StoredTarget {
                node_id: row.get(0)?,
                host_id: row.get(1)?,
                provider_instance_id: row.get(2)?,
                generation: row.get(3)?,
                usage_limit_kind: row.get(4)?,
                usage_limit_value: row.get(5)?,
            })
        },
    )?;
    assert_eq!(stored.node_id, fixture.node.as_bytes());
    assert_eq!(stored.host_id, fixture.host.as_bytes());
    assert_eq!(stored.provider_instance_id, fixture.provider.as_bytes());
    assert_eq!(
        (
            stored.generation,
            stored.usage_limit_kind,
            stored.usage_limit_value,
        ),
        (1, 1, 95),
    );
    let generation: StoredTargetGeneration = database.connection().query_row(
        "SELECT marker_fingerprint, backing_device_fingerprint,
                    filesystem_fingerprint, state
             FROM target_generations WHERE target_id = ?1 AND generation = 1",
        [TargetId::from_bytes([40; 16])?.as_bytes().as_slice()],
        |row| {
            Ok(StoredTargetGeneration {
                marker_fingerprint: row.get(0)?,
                backing_device_fingerprint: row.get(1)?,
                filesystem_fingerprint: row.get(2)?,
                state: row.get(3)?,
            })
        },
    )?;
    assert_eq!(generation.marker_fingerprint, vec![41; 32]);
    assert_eq!(generation.backing_device_fingerprint, Some(vec![42; 32]));
    assert_eq!(generation.filesystem_fingerprint, Some(vec![43; 32]));
    assert_eq!(generation.state, 1);
    Ok(())
}

#[test]
fn invalid_or_unbound_target_registration_fails_without_partial_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let invalid_cases = [
        RegisterStorageTarget {
            host_id: HostId::from_bytes([99; 16])?,
            ..target_value(&fixture, StorageUsageLimit::Percent(95))?
        },
        RegisterStorageTarget {
            marker_fingerprint: [0; 32],
            ..target_value(&fixture, StorageUsageLimit::Percent(95))?
        },
        RegisterStorageTarget {
            usage_limit: StorageUsageLimit::Percent(0),
            ..target_value(&fixture, StorageUsageLimit::Percent(95))?
        },
        RegisterStorageTarget {
            usage_limit: StorageUsageLimit::Bytes(u64::MAX),
            ..target_value(&fixture, StorageUsageLimit::Percent(95))?
        },
    ];
    for (offset, value) in invalid_cases.into_iter().enumerate() {
        let marker = u8::try_from(50 + offset)?;
        let result = fixture.repository.apply_committed(
            LogPosition { index: 2, term: 1 },
            context(marker, fixture.administrator, marker + 10, 30, Some(1))?,
            &AuthoritativeCommand::RegisterStorageTarget(value),
        );
        assert!(matches!(
            result,
            Err(RepositoryError::InvalidCommand
                | RepositoryError::CapacityExceeded
                | RepositoryError::Sqlite(_))
        ));
    }
    let database = fixture.repository.into_database();
    let target_count: i64 =
        database
            .connection()
            .query_row("SELECT count(*) FROM storage_targets", [], |row| row.get(0))?;
    let generation_count: i64 =
        database
            .connection()
            .query_row("SELECT count(*) FROM target_generations", [], |row| {
                row.get(0)
            })?;
    let component_count: i64 =
        database
            .connection()
            .query_row("SELECT count(*) FROM component_instances", [], |row| {
                row.get(0)
            })?;
    assert_eq!((target_count, generation_count), (0, 0));
    assert_eq!(component_count, 0);
    Ok(())
}

#[test]
fn registration_context_requires_the_exact_active_node_and_current_manager()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let context = fixture
        .repository
        .storage_target_registration_context(fixture.node, UnixMicros::new(11))?
        .ok_or("registration context was unavailable")?;
    assert_eq!(context.mesh_id, MeshId::from_bytes([7; 16])?);
    assert_eq!(context.node_id, fixture.node);
    assert_eq!(context.host_id, fixture.host);
    assert_eq!(context.actor_principal_id, fixture.administrator);
    assert_eq!(
        fixture.repository.storage_target_registration_context(
            NodeId::from_bytes([99; 16])?,
            UnixMicros::new(11),
        )?,
        None
    );
    Ok(())
}

#[test]
fn draining_target_is_readable_but_never_returned_as_writable()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    fixture.repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        context(30, fixture.administrator, 31, 30, Some(1))?,
        &target_command(&fixture, StorageUsageLimit::Percent(95))?,
    )?;
    let target_id = TargetId::from_bytes([40; 16])?;
    let database = fixture.repository.into_database();
    database.connection().execute(
        "UPDATE storage_targets SET state = 3, draining_at = 40, revision = 3
         WHERE target_id = ?1",
        [target_id.as_bytes().as_slice()],
    )?;
    let repository = AuthoritativeRepository::new(database);

    assert_eq!(
        repository.storage_target_provider_context(fixture.node, target_id)?,
        None
    );
    assert_eq!(
        repository.storage_target_provider_context_by_target(target_id)?,
        None
    );
    let readable = repository
        .readable_storage_target_provider_context(fixture.node, target_id)?
        .ok_or("draining provider was not readable")?;
    assert_eq!(readable.target_id, target_id);
    assert_eq!(readable.generation, 1);
    assert_eq!(
        repository.readable_storage_target_provider_context_by_target(target_id)?,
        Some(readable)
    );
    Ok(())
}

#[test]
fn target_drain_atomically_excludes_writes_and_queues_evacuating_work()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    fixture.repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        context(30, fixture.administrator, 31, 30, Some(1))?,
        &target_command(&fixture, StorageUsageLimit::Percent(95))?,
    )?;
    let target_id = TargetId::from_bytes([40; 16])?;
    let work_id = WorkId::from_bytes([50; 16])?;
    let command = AuthoritativeCommand::BeginStorageTargetDrain(BeginStorageTargetDrain {
        work: QueueMaintenanceWork {
            work_id,
            deduplication_key: [51; 32],
            subject: WorkSubject::Drain(DrainScope::Target {
                target_id,
                target_generation: 1,
            }),
            signals: WorkSignals {
                data_unavailable: false,
                remaining_recovery_margin: 1,
                protection_debt: 0,
                locality_debt: 0,
                instability: 0,
                access_heat: 0,
                created_at: UnixMicros::new(40),
                due_at: Some(UnixMicros::new(40)),
            },
            demand: WorkDemand {
                in_flight_bytes: 4_096,
            },
            next_attempt_at: UnixMicros::new(40),
        },
        allow_temporary_degraded: true,
        cleanup_requested: false,
    });
    let receipt = fixture.repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(52, fixture.administrator, 53, 40, Some(2))?,
        &command,
    )?;

    assert_eq!(receipt.entity.kind, EntityKind::StorageTarget);
    assert_eq!(receipt.entity.id, target_id.as_bytes());
    assert_eq!(
        fixture
            .repository
            .maintenance_work(work_id)?
            .ok_or("drain work missing")?
            .subject,
        WorkSubject::Drain(DrainScope::Target {
            target_id,
            target_generation: 1,
        })
    );
    assert_eq!(
        fixture
            .repository
            .storage_target_provider_context_by_target(target_id)?,
        None
    );
    assert!(
        fixture
            .repository
            .readable_storage_target_provider_context_by_target(target_id)?
            .is_some()
    );
    let stored = fixture.repository.into_database().connection().query_row(
        "SELECT allow_temporary_degraded, cleanup_requested, state, requested_at
         FROM storage_target_drains WHERE work_id = ?1",
        [work_id.as_bytes().as_slice()],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        },
    )?;
    assert_eq!(stored, (1, 0, 1, 40));
    Ok(())
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let partition = PartitionId::from_bytes([1; 16])?;
    let database = PartitionDatabase::open(
        &directory.path().join("storage-target.sqlite3"),
        partition,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let host = HostId::from_bytes([3; 16])?;
    let node = NodeId::from_bytes([4; 16])?;
    repository.apply_committed(
        LogPosition { index: 1, term: 1 },
        context(5, administrator, 6, 10, Some(0))?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([7; 16])?,
            mesh_name: RecordName::new("Storage target mesh")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([8; 16])?,
            host_id: host,
            host_name: RecordName::new("Host")?,
            node_id: node,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        }),
    )?;
    let provider = ComponentInstanceId::from_bytes([20; 16])?;
    Ok(Fixture {
        _directory: directory,
        repository,
        administrator,
        node,
        host,
        provider,
    })
}

fn target_command(
    fixture: &Fixture,
    usage_limit: StorageUsageLimit,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::RegisterStorageTarget(target_value(
        fixture,
        usage_limit,
    )?))
}

fn target_value(
    fixture: &Fixture,
    usage_limit: StorageUsageLimit,
) -> Result<RegisterStorageTarget, Box<dyn std::error::Error>> {
    Ok(RegisterStorageTarget {
        target_id: TargetId::from_bytes([40; 16])?,
        node_id: fixture.node,
        host_id: fixture.host,
        provider: provider_component(fixture.provider)?,
        name: RecordName::new("Primary folder")?,
        generation: 1,
        marker_fingerprint: [41; 32],
        backing_device_fingerprint: Some([42; 32]),
        filesystem_fingerprint: Some([43; 32]),
        usage_limit,
    })
}

fn provider_component(
    instance_id: ComponentInstanceId,
) -> Result<CreateComponent, Box<dyn std::error::Error>> {
    let configuration = b"{\"usage_limit\":\"per-target\"}".to_vec();
    Ok(CreateComponent {
        instance_id,
        component_kind: 1,
        name: RecordName::new("Folder storage provider")?,
        implementation_id: "meshspan-folder".to_owned(),
        contract_major: 1,
        contract_minor: 0,
        schema_version: 1,
        configuration_digest: Sha256::digest(&configuration).into(),
        canonical_configuration: configuration,
    })
}

fn context(
    operation: u8,
    actor: PrincipalId,
    audit: u8,
    occurred_at: i64,
    expected_revision: Option<u64>,
) -> Result<CommandContext, meshspan_domain::IdentifierError> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation; 16])?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes([audit; 16])?,
        occurred_at: UnixMicros::new(occurred_at),
        expected_revision: expected_revision.map(Revision::new),
    })
}
