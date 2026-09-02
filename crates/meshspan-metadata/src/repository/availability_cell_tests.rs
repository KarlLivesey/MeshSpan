// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    AuditEventId, AvailabilityCellId, ComponentInstanceId, HostId, MeshId, NodeId, OperationId,
    PartitionId, PrincipalId, Revision, RoleId, TargetId, UnixMicros,
};
use sha2::{Digest, Sha256};

use super::{AuthoritativeRepository, EntityKind, LogPosition, PageLimit};
use crate::{
    AuthoritativeCommand, BootstrapMesh, CommandContext, CreateAvailabilityCell, CreateComponent,
    PartitionDatabase, RecordName, RegisterStorageTarget, SetHostAvailabilityCellMembership,
    SetTargetAvailabilityCellMembership, StorageUsageLimit,
};

#[test]
fn cells_and_overlapping_machine_target_memberships_are_authoritative()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, administrator, host_id, target_id) = fixture()?;
    let campus = AvailabilityCellId::from_bytes([20; 16])?;
    let building = AvailabilityCellId::from_bytes([21; 16])?;
    apply(
        &mut repository,
        3,
        administrator,
        &AuthoritativeCommand::CreateAvailabilityCell(CreateAvailabilityCell {
            cell_id: campus,
            name: RecordName::new("Campus")?,
            parent_cell_id: None,
        }),
    )?;
    let receipt = apply(
        &mut repository,
        4,
        administrator,
        &AuthoritativeCommand::CreateAvailabilityCell(CreateAvailabilityCell {
            cell_id: building,
            name: RecordName::new("Building A")?,
            parent_cell_id: Some(campus),
        }),
    )?;
    assert_eq!(receipt.entity.kind, EntityKind::AvailabilityCell);
    apply(
        &mut repository,
        5,
        administrator,
        &AuthoritativeCommand::SetHostAvailabilityCellMembership(
            SetHostAvailabilityCellMembership {
                cell_id: building,
                host_id,
                present: true,
            },
        ),
    )?;
    apply(
        &mut repository,
        6,
        administrator,
        &AuthoritativeCommand::SetTargetAvailabilityCellMembership(
            SetTargetAvailabilityCellMembership {
                cell_id: campus,
                target_id,
                present: true,
            },
        ),
    )?;

    let cells = repository.availability_cells(None, PageLimit::new(10)?)?;
    assert_eq!(cells.items.len(), 2);
    assert_eq!(cells.items[0].cell_id, building);
    assert_eq!(cells.items[0].parent_cell_id, Some(campus));
    assert_eq!(
        repository.target_availability_cells(target_id, host_id)?,
        vec![campus, building]
    );
    Ok(())
}

fn fixture()
-> Result<(AuthoritativeRepository, PrincipalId, HostId, TargetId), Box<dyn std::error::Error>> {
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let host_id = HostId::from_bytes([5; 16])?;
    let node_id = NodeId::from_bytes([6; 16])?;
    let target_id = TargetId::from_bytes([7; 16])?;
    let database = PartitionDatabase::open(
        std::path::Path::new(":memory:"),
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    apply(
        &mut repository,
        1,
        administrator,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([3; 16])?,
            mesh_name: RecordName::new("Availability proof")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([4; 16])?,
            host_id,
            host_name: RecordName::new("Host")?,
            node_id,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Authority")?,
        }),
    )?;
    let configuration = b"{\"usage_limit\":\"per-target\"}".to_vec();
    apply(
        &mut repository,
        2,
        administrator,
        &AuthoritativeCommand::RegisterStorageTarget(RegisterStorageTarget {
            target_id,
            node_id,
            host_id,
            provider: CreateComponent {
                instance_id: ComponentInstanceId::from_bytes([8; 16])?,
                component_kind: 1,
                name: RecordName::new("Folder storage provider")?,
                implementation_id: "meshspan-folder".to_owned(),
                contract_major: 1,
                contract_minor: 0,
                schema_version: 1,
                configuration_digest: Sha256::digest(&configuration).into(),
                canonical_configuration: configuration,
            },
            name: RecordName::new("Storage")?,
            generation: 1,
            marker_fingerprint: [9; 32],
            backing_device_fingerprint: Some([10; 32]),
            filesystem_fingerprint: Some([11; 32]),
            usage_limit: StorageUsageLimit::Bytes(1_000),
        }),
    )?;
    Ok((repository, administrator, host_id, target_id))
}

fn apply(
    repository: &mut AuthoritativeRepository,
    index: u64,
    administrator: PrincipalId,
    command: &AuthoritativeCommand,
) -> Result<super::CommandReceipt, Box<dyn std::error::Error>> {
    Ok(repository.apply_committed(
        LogPosition { index, term: 1 },
        CommandContext {
            operation_id: OperationId::from_bytes([u8::try_from(index)?; 16])?,
            actor_principal_id: administrator,
            audit_event_id: AuditEventId::from_bytes([u8::try_from(index + 20)?; 16])?,
            occurred_at: UnixMicros::new(i64::try_from(index)?),
            expected_revision: Some(Revision::new(index - 1)),
        },
        command,
    )?)
}
