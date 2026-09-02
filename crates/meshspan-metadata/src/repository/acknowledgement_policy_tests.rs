// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AcknowledgementPolicyId, AuditEventId, AvailabilityCellId, DurationMicros, HostId, MeshId,
    NodeId, OperationId, PartitionId, PrincipalId, Revision, RoleId, UnixMicros, VolumeId,
};

use super::{AuthoritativeRepository, EntityKind, LogPosition, PageLimit, RepositoryError};
use crate::{
    AcknowledgementCellRequirement, AcknowledgementCellRole, AcknowledgementConsistencyClass,
    AssignVolumeAcknowledgementPolicy, AuthoritativeCommand, BootstrapMesh, CommandContext,
    CreateAcknowledgementPolicy, CreateAvailabilityCell, PartitionDatabase, RecordName,
    StrongFallbackMode,
};

#[test]
fn volume_acknowledgement_policy_preserves_required_and_eventual_cells()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, administrator, volume_id) = fixture()?;
    let required = AvailabilityCellId::from_bytes([20; 16])?;
    let eventual = AvailabilityCellId::from_bytes([21; 16])?;
    for (index, cell_id, name) in [(2, required, "Head office"), (3, eventual, "Archive")] {
        apply(
            &mut repository,
            index,
            administrator,
            &AuthoritativeCommand::CreateAvailabilityCell(CreateAvailabilityCell {
                cell_id,
                name: RecordName::new(name)?,
                parent_cell_id: None,
            }),
        )?;
    }
    let policy_id = AcknowledgementPolicyId::from_bytes([22; 16])?;
    let create = AuthoritativeCommand::CreateAcknowledgementPolicy(CreateAcknowledgementPolicy {
        policy_id,
        name: RecordName::new("Required office, eventual archive")?,
        consistency: AcknowledgementConsistencyClass::Strong,
        minimum_durable_targets: 2,
        minimum_distinct_nodes: 2,
        strong_wait: Some(DurationMicros::new(5_000_000)),
        fallback: StrongFallbackMode::RemainPending,
        required_scenarios: BoundedItems::new(Vec::new(), 64)?,
        cells: BoundedItems::new(
            vec![
                AcknowledgementCellRequirement {
                    cell_id: required,
                    role: AcknowledgementCellRole::RequiredBeforeCommit,
                    minimum_durable_targets: Some(2),
                    minimum_distinct_nodes: Some(2),
                    local_protection_policy_id: None,
                },
                AcknowledgementCellRequirement {
                    cell_id: eventual,
                    role: AcknowledgementCellRole::Eventual,
                    minimum_durable_targets: None,
                    minimum_distinct_nodes: None,
                    local_protection_policy_id: None,
                },
            ],
            256,
        )?,
    });
    let receipt = apply(&mut repository, 4, administrator, &create)?;
    assert_eq!(receipt.entity.kind, EntityKind::AcknowledgementPolicy);
    apply(
        &mut repository,
        5,
        administrator,
        &AuthoritativeCommand::AssignVolumeAcknowledgementPolicy(
            AssignVolumeAcknowledgementPolicy {
                volume_id,
                policy_id,
            },
        ),
    )?;

    let selected = repository
        .volume_acknowledgement_policy(volume_id)?
        .ok_or("assigned acknowledgement policy was absent")?;
    assert_eq!(selected.policy_id, policy_id);
    assert_eq!(selected.revision, Revision::new(4));
    assert_eq!(
        selected.consistency,
        AcknowledgementConsistencyClass::Strong
    );
    assert_eq!(selected.cells.len(), 2);
    assert!(selected.cells.iter().any(|cell| {
        cell.cell_id == required && cell.role == AcknowledgementCellRole::RequiredBeforeCommit
    }));
    let page = repository.acknowledgement_policies(None, PageLimit::new(1)?)?;
    assert_eq!(page.items, vec![selected]);
    assert!(page.next.is_none());
    Ok(())
}

#[test]
fn invalid_eventual_deadline_advances_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, administrator, _) = fixture()?;
    let invalid = AuthoritativeCommand::CreateAcknowledgementPolicy(CreateAcknowledgementPolicy {
        policy_id: AcknowledgementPolicyId::from_bytes([30; 16])?,
        name: RecordName::new("Invalid eventual deadline")?,
        consistency: AcknowledgementConsistencyClass::Eventual,
        minimum_durable_targets: 1,
        minimum_distinct_nodes: 1,
        strong_wait: Some(DurationMicros::new(1)),
        fallback: StrongFallbackMode::RemainPending,
        required_scenarios: BoundedItems::new(Vec::new(), 64)?,
        cells: BoundedItems::new(Vec::new(), 256)?,
    });
    assert!(matches!(
        apply(&mut repository, 2, administrator, &invalid),
        Err(error) if matches!(error.downcast_ref::<RepositoryError>(), Some(RepositoryError::InvalidCommand))
    ));
    assert_eq!(repository.current_revision()?, Revision::new(1));
    Ok(())
}

fn fixture() -> Result<(AuthoritativeRepository, PrincipalId, VolumeId), Box<dyn std::error::Error>>
{
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let volume_id = VolumeId::from_bytes([9; 16])?;
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
            mesh_name: RecordName::new("Acknowledgement policy proof")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([4; 16])?,
            host_id: HostId::from_bytes([5; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([6; 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Authority")?,
        }),
    )?;
    repository.database.connection_mut().execute(
        "INSERT INTO volumes(
            volume_id, display_name, canonical_name, state, created_by, created_at, revision
         ) VALUES (?1, 'Acknowledgement volume', 'acknowledgement volume', 1, ?2, 10, 1)",
        rusqlite::params![
            volume_id.as_bytes().as_slice(),
            administrator.as_bytes().as_slice()
        ],
    )?;
    Ok((repository, administrator, volume_id))
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
            audit_event_id: AuditEventId::from_bytes([u8::try_from(index + 50)?; 16])?,
            occurred_at: UnixMicros::new(i64::try_from(index)?),
            expected_revision: Some(Revision::new(index - 1)),
        },
        command,
    )?)
}
