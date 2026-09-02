// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, AvailabilityCellId, DurationMicros, HostId, LocalityPolicyId,
    LocalityRequirementId, MeshId, NodeId, OperationId, PartitionId, PrincipalId, Revision, RoleId,
    UnixMicros, VolumeId,
};

use super::{AuthoritativeRepository, EntityKind, LogPosition, PageLimit, RepositoryError};
use crate::{
    AssignVolumeLocalityPolicy, AuthoritativeCommand, BootstrapMesh, CommandContext,
    CreateAvailabilityCell, CreateLocalityPolicy, LocalityRequirementConfiguration,
    PartitionDatabase, RecordName,
};

#[test]
fn volume_locality_policy_preserves_complete_local_requirements()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, administrator, volume_id) = fixture()?;
    let shop_a = AvailabilityCellId::from_bytes([20; 16])?;
    let shop_b = AvailabilityCellId::from_bytes([21; 16])?;
    for (index, cell_id, name) in [(2, shop_a, "Shop A"), (3, shop_b, "Shop B")] {
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
    let policy_id = LocalityPolicyId::from_bytes([22; 16])?;
    let create = AuthoritativeCommand::CreateLocalityPolicy(CreateLocalityPolicy {
        policy_id,
        name: RecordName::new("Both shops")?,
        maximum_lag: Some(DurationMicros::new(30_000_000)),
        requirements: BoundedItems::new(
            vec![
                LocalityRequirementConfiguration {
                    requirement_id: LocalityRequirementId::from_bytes([23; 16])?,
                    cell_id: shop_a,
                    local_protection_policy_id: None,
                },
                LocalityRequirementConfiguration {
                    requirement_id: LocalityRequirementId::from_bytes([24; 16])?,
                    cell_id: shop_b,
                    local_protection_policy_id: None,
                },
            ],
            64,
        )?,
    });
    let receipt = apply(&mut repository, 4, administrator, &create)?;
    assert_eq!(receipt.entity.kind, EntityKind::LocalityPolicy);
    apply(
        &mut repository,
        5,
        administrator,
        &AuthoritativeCommand::AssignVolumeLocalityPolicy(AssignVolumeLocalityPolicy {
            volume_id,
            policy_id,
        }),
    )?;

    let selected = repository
        .volume_locality_policy(volume_id)?
        .ok_or("assigned locality policy was absent")?;
    assert_eq!(selected.policy_id, policy_id);
    assert_eq!(selected.revision, Revision::new(4));
    assert_eq!(selected.maximum_lag, Some(DurationMicros::new(30_000_000)));
    assert_eq!(selected.requirements.len(), 2);
    assert_eq!(selected.requirements[0].cell_id, shop_a);
    assert_eq!(selected.requirements[1].cell_id, shop_b);
    let page = repository.locality_policies(None, PageLimit::new(1)?)?;
    assert_eq!(page.items.len(), 1);
    assert!(page.next.is_none());
    assert_eq!(page.items[0].display_name, "Both shops");
    Ok(())
}

#[test]
fn unknown_or_duplicate_cells_advance_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, administrator, _) = fixture()?;
    let cell_id = AvailabilityCellId::from_bytes([30; 16])?;
    apply(
        &mut repository,
        2,
        administrator,
        &AuthoritativeCommand::CreateAvailabilityCell(CreateAvailabilityCell {
            cell_id,
            name: RecordName::new("One cell")?,
            parent_cell_id: None,
        }),
    )?;
    let invalid = AuthoritativeCommand::CreateLocalityPolicy(CreateLocalityPolicy {
        policy_id: LocalityPolicyId::from_bytes([31; 16])?,
        name: RecordName::new("Duplicate cell")?,
        maximum_lag: None,
        requirements: BoundedItems::new(
            vec![
                LocalityRequirementConfiguration {
                    requirement_id: LocalityRequirementId::from_bytes([32; 16])?,
                    cell_id,
                    local_protection_policy_id: None,
                },
                LocalityRequirementConfiguration {
                    requirement_id: LocalityRequirementId::from_bytes([33; 16])?,
                    cell_id,
                    local_protection_policy_id: None,
                },
            ],
            64,
        )?,
    });
    assert!(matches!(
        apply(&mut repository, 3, administrator, &invalid),
        Err(error) if matches!(error.downcast_ref::<RepositoryError>(), Some(RepositoryError::InvalidCommand))
    ));
    assert_eq!(repository.current_revision()?, Revision::new(2));
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
            mesh_name: RecordName::new("Locality policy proof")?,
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
         ) VALUES (?1, 'Locality volume', 'locality volume', 1, ?2, 10, 1)",
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
            audit_event_id: AuditEventId::from_bytes([u8::try_from(index + 40)?; 16])?,
            occurred_at: UnixMicros::new(i64::try_from(index)?),
            expected_revision: Some(Revision::new(index - 1)),
        },
        command,
    )?)
}
