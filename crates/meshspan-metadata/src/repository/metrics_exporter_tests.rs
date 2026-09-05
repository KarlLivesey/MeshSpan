// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    AuditEventId, HostId, MeshId, NodeId, OperationId, PartitionId, PrincipalId, RoleId, UnixMicros,
};
use tempfile::{TempDir, tempdir};

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::tests::{mark_test_recovery_verified, protected_bootstrap};
use super::{ApplyDisposition, AuthoritativeRepository, EntityKind, LogPosition, RepositoryError};
use crate::{
    AuthoritativeCommand, BootstrapMesh, CommandContext, ConfigureMetricsExporter,
    MetricsExporterPolicy, PartitionDatabase, RecordName,
};

struct Fixture {
    directory: TempDir,
    repository: AuthoritativeRepository,
    administrator: PrincipalId,
    partition: PartitionId,
}

#[test]
fn exporter_policy_defaults_off_and_replaces_with_exact_retries_and_sequences()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    assert_eq!(fixture.repository.metrics_exporter_configuration()?, None);
    let command = configure(0, true, vec![fixture.administrator]);
    let context = context(20, fixture.administrator)?;
    let encoded = crate::encode_authoritative_command(context, &command)?;
    let decoded = crate::decode_authoritative_command(&encoded)?;
    assert_eq!(decoded.context, context);
    assert_eq!(decoded.command, command);
    let receipt = fixture.repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        context,
        &decoded.command,
    )?;
    assert_eq!(receipt.entity.kind, EntityKind::ComponentInstance);
    let active = fixture
        .repository
        .metrics_exporter_configuration()?
        .ok_or("policy absent")?;
    assert_eq!(active.sequence, 1);
    assert_eq!(active.revision.get(), 2);
    assert_eq!(active.instance_id.as_bytes(), receipt.entity.id);
    assert!(active.policy.enabled);
    let replay =
        fixture
            .repository
            .apply_committed(LogPosition { index: 3, term: 1 }, context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.committed_revision, receipt.committed_revision);
    let disable = configure(1, false, vec![]);
    fixture.repository.apply_committed(
        LogPosition { index: 4, term: 1 },
        self::context(21, fixture.administrator)?,
        &disable,
    )?;
    let disabled = fixture
        .repository
        .metrics_exporter_configuration()?
        .ok_or("disabled policy absent")?;
    assert_eq!(disabled.sequence, 2);
    assert_eq!(disabled.revision.get(), 3);
    assert_eq!(disabled.policy, MetricsExporterPolicy::default());
    assert!(matches!(
        fixture.repository.apply_committed(
            LogPosition { index: 5, term: 1 },
            self::context(22, fixture.administrator)?,
            &command
        ),
        Err(RepositoryError::StaleRevision)
    ));
    assert_eq!(
        fixture.repository.metrics_exporter_configuration()?,
        Some(disabled)
    );
    let database = fixture.repository.into_database();
    let revisions: i64 = database.connection().query_row(
        "SELECT count(*) FROM component_configurations",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(revisions, 2);
    database.check_integrity()?;
    Ok(())
}

#[test]
fn exporter_policy_rolls_back_with_receipts_and_survives_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let command = configure(0, true, vec![fixture.administrator]);
    let context = context(20, fixture.administrator)?;
    let position = LogPosition { index: 2, term: 1 };
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        let mut database = fixture.repository.into_database();
        assert!(
            apply_committed_with_fault(&mut database, position, context, &command, fault).is_err()
        );
        fixture.repository = AuthoritativeRepository::new(database);
        assert_eq!(fixture.repository.metrics_exporter_configuration()?, None);
        assert_eq!(
            fixture.repository.resolve_operation(context.operation_id)?,
            None
        );
        assert_eq!(fixture.repository.current_revision()?.get(), 1);
    }
    fixture
        .repository
        .apply_committed(position, context, &command)?;
    let expected = fixture.repository.metrics_exporter_configuration()?;
    drop(fixture.repository);
    let reopened = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &fixture.directory.path().join("partition.sqlite3"),
        UnixMicros::new(30),
    )?);
    assert_eq!(reopened.metrics_exporter_configuration()?, expected);
    assert_eq!(reopened.partition_id(), fixture.partition);
    Ok(())
}

#[test]
fn exporter_policy_rejects_unknown_consumers_and_corrupt_stored_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let context = context(20, fixture.administrator)?;
    let position = LogPosition { index: 2, term: 1 };
    let unknown = configure(0, true, vec![PrincipalId::from_bytes([99; 16])?]);
    assert!(matches!(
        fixture
            .repository
            .apply_committed(position, context, &unknown),
        Err(RepositoryError::InvalidCommand)
    ));
    let configured = configure(0, true, vec![fixture.administrator]);
    fixture
        .repository
        .apply_committed(position, context, &configured)?;
    let database = fixture.repository.into_database();
    for corruption in [
        "UPDATE component_configurations SET config_digest = zeroblob(32)",
        "UPDATE component_configurations SET schema_version = 999",
        "UPDATE component_configurations SET state = 4",
        "UPDATE component_instances SET active_config_revision = 99",
        "UPDATE component_instances SET implementation_id = 'unknown-exporter'",
        "UPDATE component_configurations SET canonical_config = zeroblob(1032)",
    ] {
        database
            .connection()
            .execute_batch("SAVEPOINT corrupt_metrics")?;
        database.connection().execute(corruption, [])?;
        assert!(super::metrics_exporter::load(database.connection()).is_err());
        database
            .connection()
            .execute_batch("ROLLBACK TO corrupt_metrics; RELEASE corrupt_metrics")?;
        assert!(super::metrics_exporter::load(database.connection())?.is_some());
    }
    Ok(())
}

#[test]
fn exporter_policy_codec_rejects_noncanonical_or_unbounded_values()
-> Result<(), Box<dyn std::error::Error>> {
    let principal = PrincipalId::from_bytes([2; 16])?;
    let policy = MetricsExporterPolicy {
        enabled: true,
        allowed_principals: vec![principal],
    };
    let bytes = policy.encode()?;
    assert_eq!(MetricsExporterPolicy::decode(&bytes)?, policy);
    for offset in [3, 4, 5, 6] {
        let mut malformed = bytes.clone();
        malformed[offset] = 255;
        assert!(MetricsExporterPolicy::decode(&malformed).is_err());
    }
    for length in 0..bytes.len() {
        assert!(MetricsExporterPolicy::decode(&bytes[..length]).is_err());
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(MetricsExporterPolicy::decode(&extra).is_err());
    for principals in [vec![], vec![principal; 2], vec![principal; 65]] {
        assert!(
            MetricsExporterPolicy {
                enabled: true,
                allowed_principals: principals
            }
            .encode()
            .is_err()
        );
    }
    Ok(())
}

fn configure(
    expected_sequence: u64,
    enabled: bool,
    allowed_principals: Vec<PrincipalId>,
) -> AuthoritativeCommand {
    AuthoritativeCommand::ConfigureMetricsExporter(ConfigureMetricsExporter {
        expected_sequence,
        policy: MetricsExporterPolicy {
            enabled,
            allowed_principals,
        },
    })
}

fn context(
    seed: u8,
    actor: PrincipalId,
) -> Result<CommandContext, meshspan_domain::IdentifierError> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([seed; 16])?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes([seed + 100; 16])?,
        occurred_at: UnixMicros::new(i64::from(seed)),
        expected_revision: None,
    })
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let partition = PartitionId::from_bytes([1; 16])?;
    let database = PartitionDatabase::open(
        &directory.path().join("partition.sqlite3"),
        partition,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let mesh = MeshId::from_bytes([3; 16])?;
    repository.apply_committed(
        LogPosition { index: 1, term: 1 },
        context(4, administrator)?,
        &protected_bootstrap(BootstrapMesh {
            mesh_id: mesh,
            mesh_name: RecordName::new("Metrics mesh")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([6; 16])?,
            host_id: HostId::from_bytes([7; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([8; 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        })?,
    )?;
    mark_test_recovery_verified(&mut repository, mesh, administrator)?;
    Ok(Fixture {
        directory,
        repository,
        administrator,
        partition,
    })
}
