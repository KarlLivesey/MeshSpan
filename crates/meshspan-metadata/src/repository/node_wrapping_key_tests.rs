// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    AuditEventId, HostId, MeshId, NodeId, OperationId, PartitionId, PrincipalId, Revision, RoleId,
    UnixMicros,
};
use meshspan_secret_envelope::WrappingPrivateKey;
use tempfile::{TempDir, tempdir};

use super::{ApplyDisposition, AuthoritativeRepository, EntityKind, LogPosition, RepositoryError};
use crate::{
    AuthoritativeCommand, BootstrapMesh, CommandContext, PartitionDatabase, RecordName,
    RegisterNodeWrappingKey,
};

struct Fixture {
    _directory: TempDir,
    repository: AuthoritativeRepository,
    administrator: PrincipalId,
    node: NodeId,
}

#[test]
fn registered_public_key_is_exact_queryable_and_replay_safe()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let private_key = WrappingPrivateKey::from_bytes([31; 32])?;
    let public_key = private_key.public_key();
    let command = AuthoritativeCommand::RegisterNodeWrappingKey(RegisterNodeWrappingKey {
        node_id: fixture.node,
        generation: 1,
        public_key: public_key.as_bytes(),
        key_fingerprint: public_key.fingerprint(),
    });
    let context = context(20, fixture.administrator, 21, 20, Some(1))?;
    let receipt =
        fixture
            .repository
            .apply_committed(LogPosition { index: 2, term: 1 }, context, &command)?;
    assert_eq!(receipt.disposition, ApplyDisposition::Applied);
    assert_eq!(receipt.entity.kind, EntityKind::NodeWrappingKey);
    assert_eq!(receipt.entity.id, fixture.node.as_bytes());

    let stored = fixture
        .repository
        .node_wrapping_key(fixture.node)?
        .ok_or("node wrapping key missing")?;
    assert_eq!(stored.node_id, fixture.node);
    assert_eq!(stored.generation, 1);
    assert_eq!(stored.public_key, public_key);
    assert_eq!(stored.registered_at, UnixMicros::new(20));
    assert_eq!(stored.revision, Revision::new(2));

    let replay =
        fixture
            .repository
            .apply_committed(LogPosition { index: 3, term: 1 }, context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    Ok(())
}

#[test]
fn substituted_or_unbound_public_keys_fail_without_rows() -> Result<(), Box<dyn std::error::Error>>
{
    let mut fixture = fixture()?;
    let public_key = WrappingPrivateKey::from_bytes([41; 32])?.public_key();
    for (offset, command) in [
        RegisterNodeWrappingKey {
            node_id: fixture.node,
            generation: 1,
            public_key: public_key.as_bytes(),
            key_fingerprint: [0; 32],
        },
        RegisterNodeWrappingKey {
            node_id: NodeId::from_bytes([99; 16])?,
            generation: 1,
            public_key: public_key.as_bytes(),
            key_fingerprint: public_key.fingerprint(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        let marker = u8::try_from(30 + offset)?;
        let result = fixture.repository.apply_committed(
            LogPosition { index: 2, term: 1 },
            context(marker, fixture.administrator, marker + 10, 20, Some(1))?,
            &AuthoritativeCommand::RegisterNodeWrappingKey(command),
        );
        assert!(matches!(
            result,
            Err(RepositoryError::InvalidCommand | RepositoryError::Sqlite(_))
        ));
    }
    assert_eq!(fixture.repository.node_wrapping_key(fixture.node)?, None);
    Ok(())
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let database = PartitionDatabase::open(
        &directory.path().join("node-wrapping-key.sqlite3"),
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let node = NodeId::from_bytes([4; 16])?;
    repository.apply_committed(
        LogPosition { index: 1, term: 1 },
        context(5, administrator, 6, 10, Some(0))?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([7; 16])?,
            mesh_name: RecordName::new("Wrapping key mesh")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([8; 16])?,
            host_id: HostId::from_bytes([3; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: node,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        }),
    )?;
    Ok(Fixture {
        _directory: directory,
        repository,
        administrator,
        node,
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
