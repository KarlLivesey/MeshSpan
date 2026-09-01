// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    AuditEventId, FaultGroupClassId, FaultGroupId, HostId, MeshId, NodeId, OperationId,
    PartitionId, PrincipalId, Revision, RoleId, UnixMicros,
};
use tempfile::{TempDir, tempdir};

use super::{AuthoritativeRepository, EntityKind, LogPosition, PageLimit};
use crate::{
    AuthoritativeCommand, BootstrapMesh, CommandContext, CreateFaultGroup, PartitionDatabase,
    RecordName, SetHostFaultGroupMembership,
};

struct Fixture {
    _directory: TempDir,
    repository: AuthoritativeRepository,
    administrator: PrincipalId,
    host: HostId,
}

#[test]
fn machine_can_belong_to_multiple_overlapping_failure_groups()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let power = FaultGroupId::from_bytes([21; 16])?;
    let room = FaultGroupId::from_bytes([22; 16])?;
    for (offset, class, class_name, group, group_name) in [
        (2, [31; 16], "Power source", power, "UPS A"),
        (3, [32; 16], "Room", room, "Room 1"),
    ] {
        fixture.repository.apply_committed(
            LogPosition {
                index: offset,
                term: 1,
            },
            context(
                u8::try_from(offset + 40)?,
                fixture.administrator,
                u8::try_from(offset + 50)?,
                i64::try_from(offset + 10)?,
                Some(offset - 1),
            )?,
            &AuthoritativeCommand::CreateFaultGroup(CreateFaultGroup {
                class_id: FaultGroupClassId::from_bytes(class)?,
                class_name: RecordName::new(class_name)?,
                group_id: group,
                group_name: RecordName::new(group_name)?,
            }),
        )?;
    }
    for (index, group) in [(4, power), (5, room)] {
        let receipt = fixture.repository.apply_committed(
            LogPosition { index, term: 1 },
            context(
                u8::try_from(index + 40)?,
                fixture.administrator,
                u8::try_from(index + 50)?,
                i64::try_from(index + 10)?,
                Some(index - 1),
            )?,
            &AuthoritativeCommand::SetHostFaultGroupMembership(SetHostFaultGroupMembership {
                group_id: group,
                host_id: fixture.host,
                present: true,
            }),
        )?;
        assert_eq!(receipt.entity.kind, EntityKind::FaultGroupMembership);
    }

    let groups = fixture.repository.fault_groups(None, PageLimit::new(10)?)?;
    assert_eq!(groups.items.len(), 2);
    assert!(groups.next.is_none());
    let memberships = fixture
        .repository
        .fault_group_memberships(None, PageLimit::new(10)?)?;
    assert_eq!(memberships.items.len(), 2);
    assert!(
        memberships
            .items
            .iter()
            .all(|membership| membership.host_id == fixture.host)
    );
    Ok(())
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let database = PartitionDatabase::open(
        &directory.path().join("topology.sqlite3"),
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let host = HostId::from_bytes([3; 16])?;
    let mut repository = AuthoritativeRepository::new(database);
    repository.apply_committed(
        LogPosition { index: 1, term: 1 },
        context(5, administrator, 6, 10, Some(0))?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([7; 16])?,
            mesh_name: RecordName::new("Topology mesh")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([8; 16])?,
            host_id: host,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([4; 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        }),
    )?;
    Ok(Fixture {
        _directory: directory,
        repository,
        administrator,
        host,
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
