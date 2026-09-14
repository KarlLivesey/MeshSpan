// SPDX-License-Identifier: GPL-2.0-only

use super::{ApplyDisposition, AuthoritativeRepository, LogPosition, RepositoryError};
use crate::{
    AuthoritativeCommand, AuthoritativeCommandContext, BootstrapMesh, CommandContext,
    NodeCapabilityPrior, NodeCommandContext, PartitionDatabase, RecordName,
    RefreshNodeCapabilities,
};
use meshspan_domain::{
    AuditEventId, HostId, MeshId, NodeId, OperationId, PartitionId, PrincipalId, Revision, RoleId,
    UnixMicros,
};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn node_capability_refresh_bootstrap_absence_commits_truthful_actor_and_replays_after_restart()
-> TestResult {
    let (directory, mut repository, context, command) = fixture()?;
    assert!(repository.node_activation(command.node_id)?.is_none());
    assert!(
        repository
            .node_capability_presentation(command.node_id)?
            .is_none()
    );
    let wrapped = AuthoritativeCommand::RefreshNodeCapabilities(command);
    repository.preflight_entry(&[], AuthoritativeCommandContext::Node(context), &wrapped)?;
    assert!(
        repository
            .node_capability_presentation(command.node_id)?
            .is_none()
    );
    assert_eq!(repository.current_revision()?, Revision::new(1));
    let receipt = repository.apply_committed_entry(
        position(2),
        AuthoritativeCommandContext::Node(context),
        &wrapped,
    )?;
    assert_eq!(receipt.committed_revision, Revision::new(2));
    let actor: (Option<Vec<u8>>, Option<Vec<u8>>) = repository.database.connection().query_row(
        "SELECT actor_principal_id, actor_node_id FROM operations WHERE operation_id=?1",
        [context.operation_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(actor, (None, Some(command.node_id.as_bytes().to_vec())));
    let audit_actor: (Option<Vec<u8>>, Option<Vec<u8>>) =
        repository.database.connection().query_row(
            "SELECT actor_principal_id, actor_node_id FROM audit_events WHERE event_id=?1",
            [context.audit_event_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
    assert_eq!(audit_actor, actor);
    assert!(repository.node_activation(command.node_id)?.is_none());
    drop(repository.into_database());
    let database = PartitionDatabase::open(
        &directory.path().join("authority.sqlite3"),
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(30),
    )?;
    let mut reopened = AuthoritativeRepository::new(database);
    let replay = reopened.apply_committed_entry(
        position(3),
        AuthoritativeCommandContext::Node(context),
        &wrapped,
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    let current = reopened
        .node_capability_presentation(command.node_id)?
        .ok_or("current presentation missing")?;
    assert_eq!(current.capability_digest, [90; 32]);
    assert_eq!(current.revision, Revision::new(2));
    let mut changed = command;
    changed.capability_digest = [91; 32];
    assert!(matches!(
        reopened.apply_committed_entry(
            position(4),
            AuthoritativeCommandContext::Node(context),
            &AuthoritativeCommand::RefreshNodeCapabilities(changed)
        ),
        Err(RepositoryError::OperationConflict)
    ));
    Ok(())
}

#[test]
fn node_capability_refresh_rejects_wrong_actor_certificate_and_predecessor_without_mutation()
-> TestResult {
    let (_directory, mut repository, context, command) = fixture()?;
    let principal = CommandContext {
        operation_id: context.operation_id,
        actor_principal_id: PrincipalId::from_bytes([2; 16])?,
        audit_event_id: context.audit_event_id,
        occurred_at: context.occurred_at,
        expected_revision: None,
    };
    let wrapped = AuthoritativeCommand::RefreshNodeCapabilities(command);
    assert!(matches!(
        repository.apply_committed(position(2), principal, &wrapped),
        Err(RepositoryError::InvalidCommand)
    ));
    let mut wrong_actor = context;
    wrong_actor.actor_node_id = NodeId::from_bytes([99; 16])?;
    assert!(matches!(
        repository.apply_committed_entry(
            position(2),
            AuthoritativeCommandContext::Node(wrong_actor),
            &wrapped
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    for changed in [
        RefreshNodeCapabilities {
            incarnation: 2,
            ..command
        },
        RefreshNodeCapabilities {
            certificate_fingerprint: [9; 32],
            ..command
        },
        RefreshNodeCapabilities {
            prior: NodeCapabilityPrior::InitialActivation {
                revision: Revision::new(1),
                capability_digest: [9; 32],
            },
            ..command
        },
    ] {
        assert!(matches!(
            repository.apply_committed_entry(
                position(2),
                AuthoritativeCommandContext::Node(context),
                &AuthoritativeCommand::RefreshNodeCapabilities(changed)
            ),
            Err(RepositoryError::StaleRevision)
        ));
    }
    assert_eq!(repository.current_revision()?, Revision::new(1));
    assert!(
        repository
            .resolve_operation(context.operation_id)?
            .is_none()
    );
    assert!(
        repository
            .node_capability_presentation(command.node_id)?
            .is_none()
    );
    Ok(())
}

#[test]
fn node_capability_refresh_current_revision_fences_competing_reports() -> TestResult {
    let (_directory, mut repository, context, command) = fixture()?;
    repository.apply_committed_entry(
        position(2),
        AuthoritativeCommandContext::Node(context),
        &AuthoritativeCommand::RefreshNodeCapabilities(command),
    )?;
    let next_context = NodeCommandContext {
        operation_id: OperationId::from_bytes([81; 16])?,
        audit_event_id: AuditEventId::from_bytes([82; 16])?,
        ..context
    };
    let next = RefreshNodeCapabilities {
        capability_digest: [91; 32],
        prior: NodeCapabilityPrior::ExistingPresentation {
            revision: Revision::new(2),
            capability_digest: command.capability_digest,
        },
        ..command
    };
    repository.apply_committed_entry(
        position(3),
        AuthoritativeCommandContext::Node(next_context),
        &AuthoritativeCommand::RefreshNodeCapabilities(next),
    )?;
    let stale_context = NodeCommandContext {
        operation_id: OperationId::from_bytes([83; 16])?,
        audit_event_id: AuditEventId::from_bytes([84; 16])?,
        ..context
    };
    assert!(matches!(
        repository.apply_committed_entry(
            position(4),
            AuthoritativeCommandContext::Node(stale_context),
            &AuthoritativeCommand::RefreshNodeCapabilities(next)
        ),
        Err(RepositoryError::StaleRevision)
    ));
    assert!(matches!(
        repository.apply_committed_entry(
            position(4),
            AuthoritativeCommandContext::Node(stale_context),
            &AuthoritativeCommand::RefreshNodeCapabilities(command)
        ),
        Err(RepositoryError::StaleRevision)
    ));
    assert_eq!(
        repository
            .node_capability_presentation(command.node_id)?
            .ok_or("presentation")?
            .capability_digest,
        [91; 32]
    );
    Ok(())
}

fn fixture() -> Result<
    (
        TempDir,
        AuthoritativeRepository,
        NodeCommandContext,
        RefreshNodeCapabilities,
    ),
    Box<dyn std::error::Error>,
> {
    let directory = TempDir::new()?;
    let database = PartitionDatabase::open(
        &directory.path().join("authority.sqlite3"),
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    let principal = PrincipalId::from_bytes([2; 16])?;
    let node = NodeId::from_bytes([3; 16])?;
    let context =
        super::authentication_method_tests::context(4, principal, 5, 10, Some(Revision::ZERO))?;
    let bootstrap = super::tests::protected_bootstrap(BootstrapMesh {
        mesh_id: MeshId::from_bytes([6; 16])?,
        mesh_name: RecordName::new("Capability proof")?,
        administrator_id: principal,
        administrator_name: RecordName::new("Administrator")?,
        administrator_role_id: RoleId::from_bytes([7; 16])?,
        host_id: HostId::from_bytes([8; 16])?,
        host_name: RecordName::new("Host")?,
        node_id: node,
        node_name: RecordName::new("Node")?,
        partition_name: RecordName::new("Root")?,
    })?;
    repository.apply_committed(position(1), context, &bootstrap)?;
    let certificate = repository
        .active_node_certificate(node)?
        .ok_or("bootstrap certificate")?;
    let context = NodeCommandContext {
        operation_id: OperationId::from_bytes([80; 16])?,
        actor_node_id: node,
        audit_event_id: AuditEventId::from_bytes([79; 16])?,
        occurred_at: UnixMicros::new(20),
        expected_revision: None,
    };
    let command = RefreshNodeCapabilities {
        node_id: node,
        incarnation: certificate.incarnation,
        certificate_generation: certificate.generation,
        certificate_fingerprint: certificate.certificate_fingerprint,
        capability_digest: [90; 32],
        prior: NodeCapabilityPrior::InitialAdmittedCertificate {
            revision: certificate.revision,
            generation: certificate.generation,
            certificate_fingerprint: certificate.certificate_fingerprint,
        },
    };
    Ok((directory, repository, context, command))
}
fn position(index: u64) -> LogPosition {
    LogPosition { index, term: 1 }
}

#[test]
fn node_capability_migration_119_preserves_immutable_activation_without_inventing_current_support()
-> TestResult {
    let directory = TempDir::new()?;
    let path = directory.path().join("legacy.sqlite3");
    let mut connection = rusqlite::Connection::open(&path)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    crate::migration::migrate_partition_through(&mut connection, 118, 1)?;
    connection.execute("INSERT INTO hosts(host_id,display_name,canonical_name,state,created_at,revision) VALUES (?1,'Host','host',1,1,1)", [[1_u8;16].as_slice()])?;
    connection.execute("INSERT INTO nodes(node_id,host_id,display_name,canonical_name,state,current_incarnation,admitted_at,activated_at,revision) VALUES (?1,?2,'Node','node',2,1,1,2,1)", rusqlite::params![[2_u8;16].as_slice(),[1_u8;16].as_slice()])?;
    connection.execute("INSERT INTO node_activations(node_id,incarnation,private_endpoint,capability_digest,activated_at,revision) VALUES (?1,1,'localhost:9412',?2,2,1)", rusqlite::params![[2_u8;16].as_slice(),[3_u8;32].as_slice()])?;
    let legacy_digest: Vec<u8> = connection.query_row(
        "SELECT migration_digest FROM schema_migrations WHERE version=118",
        [],
        |row| row.get(0),
    )?;
    crate::migration::migrate_partition(&mut connection, 3)?;
    let activation: (i64, Vec<u8>, i64) = connection.query_row(
        "SELECT incarnation,capability_digest,revision FROM node_activations",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(activation, (1, vec![3; 32], 1));
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM node_capability_presentations",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(
        connection.query_row(
            "SELECT migration_digest FROM schema_migrations WHERE version=118",
            [],
            |row| row.get::<_, Vec<u8>>(0)
        )?,
        legacy_digest
    );
    assert_eq!(
        connection.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?,
        119
    );
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get::<_, i64>(0)
        })?,
        0
    );
    assert_eq!(
        connection.pragma_query_value(None, "quick_check", |row| row.get::<_, String>(0))?,
        "ok"
    );
    drop(connection);
    let mut reopened = rusqlite::Connection::open(path)?;
    crate::migration::migrate_partition(&mut reopened, 4)?;
    assert_eq!(
        reopened.query_row("SELECT COUNT(*) FROM node_activations", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    Ok(())
}

#[test]
fn local_capability_migration_17_preserves_bindings_and_starts_without_unverified_preimages()
-> TestResult {
    let directory = TempDir::new()?;
    let path = directory.path().join("local.sqlite3");
    let mut connection = rusqlite::Connection::open(&path)?;
    crate::migration::migrate_local_through(&mut connection, 16, 1)?;
    connection.execute(
        "INSERT INTO local_identity(singleton,node_id,schema_version) VALUES (1,?1,16)",
        [[1_u8; 16].as_slice()],
    )?;
    connection.execute("INSERT INTO local_component_bindings(instance_id,binding_kind,authoritative_config_revision,local_binding_payload,state,updated_at) VALUES (?1,1,3,?2,1,1)", rusqlite::params![[2_u8;16].as_slice(),[3_u8,4,5].as_slice()])?;
    drop(connection);
    let database =
        crate::LocalDatabase::open(&path, NodeId::from_bytes([1; 16])?, UnixMicros::new(2))?;
    assert_eq!(database.schema_version(), 17);
    assert!(database.node_capability_presentations()?.is_empty());
    assert_eq!(
        database.connection().query_row(
            "SELECT local_binding_payload FROM local_component_bindings",
            [],
            |row| row.get::<_, Vec<u8>>(0)
        )?,
        vec![3, 4, 5]
    );
    assert!(database.check_integrity()?.foreign_keys_ok);
    drop(database);
    assert!(
        crate::LocalDatabase::open_existing(&path, UnixMicros::new(3))?
            .node_capability_presentations()?
            .is_empty()
    );
    Ok(())
}

#[test]
fn first_capability_refresh_after_incarnation_advance_fences_the_immutable_activation() -> TestResult
{
    let (_directory, mut repository, context, mut command) = fixture()?;
    // Model a pre-presentation database after its admitted incarnation advances. Activation
    // remains historical, while the active certificate projection follows current admission.
    repository.database.connection().execute(
        "INSERT INTO node_activations(node_id,incarnation,private_endpoint,capability_digest,activated_at,revision) VALUES (?1,1,'localhost:9412',?2,10,1)",
        rusqlite::params![command.node_id.as_bytes().as_slice(), [88_u8; 32].as_slice()],
    )?;
    repository.database.connection().execute(
        "UPDATE nodes SET current_incarnation=2 WHERE node_id=?1",
        [command.node_id.as_bytes().as_slice()],
    )?;
    command.incarnation = 2;
    command.prior = NodeCapabilityPrior::InitialActivation {
        revision: Revision::new(1),
        capability_digest: [88; 32],
    };
    for invalid in [
        RefreshNodeCapabilities {
            incarnation: 1,
            ..command
        },
        RefreshNodeCapabilities {
            certificate_fingerprint: [77; 32],
            ..command
        },
        RefreshNodeCapabilities {
            prior: NodeCapabilityPrior::InitialActivation {
                revision: Revision::new(2),
                capability_digest: [88; 32],
            },
            ..command
        },
        RefreshNodeCapabilities {
            prior: NodeCapabilityPrior::InitialActivation {
                revision: Revision::new(1),
                capability_digest: [87; 32],
            },
            ..command
        },
    ] {
        assert!(matches!(
            repository.preflight_entry(
                &[],
                AuthoritativeCommandContext::Node(context),
                &AuthoritativeCommand::RefreshNodeCapabilities(invalid),
            ),
            Err(RepositoryError::StaleRevision)
        ));
    }
    assert_eq!(repository.current_revision()?, Revision::new(1));
    repository.apply_committed_entry(
        position(2),
        AuthoritativeCommandContext::Node(context),
        &AuthoritativeCommand::RefreshNodeCapabilities(command),
    )?;
    let presentation = repository
        .node_capability_presentation(command.node_id)?
        .ok_or("presentation")?;
    assert_eq!(presentation.incarnation, 2);
    assert_eq!(presentation.capability_digest, [90; 32]);
    let activation = repository
        .node_activation(command.node_id)?
        .ok_or("activation")?;
    assert_eq!(activation.incarnation, 1);
    assert_eq!(activation.capability_digest, [88; 32]);
    assert_eq!(activation.revision, Revision::new(1));
    Ok(())
}
