// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, FailureScenario, FailureTerm, HostId, MeshId, NodeId, OperationId, PartitionId,
    PrincipalId, ProtectionPolicyId, ProtectionScenarioId, Revision, RoleId, UnixMicros, VolumeId,
    machine_fault_class_id, storage_device_fault_class_id,
};

use super::{ApplyDisposition, AuthoritativeRepository, EntityKind, LogPosition, RepositoryError};
use crate::{
    AssignVolumeProtectionPolicy, AuthoritativeCommand, BootstrapMesh, CommandContext,
    CreateProtectionPolicy, PartitionDatabase, ProtectionScenarioConfiguration, RecordName,
};

#[test]
fn volume_policy_commits_complete_combined_failure_scenarios_and_replays()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, administrator, volume_id) = fixture()?;
    let policy_id = ProtectionPolicyId::from_bytes([20; 16])?;
    let command = policy(policy_id)?;
    let receipt = repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        context(21, administrator, 22, Some(1))?,
        &command,
    )?;
    assert_eq!(receipt.entity.kind, EntityKind::ProtectionPolicy);
    let replay = repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(21, administrator, 22, Some(1))?,
        &command,
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    assert_eq!(replay.committed_position, receipt.committed_position);

    repository.apply_committed(
        LogPosition { index: 4, term: 1 },
        context(23, administrator, 24, Some(2))?,
        &AuthoritativeCommand::AssignVolumeProtectionPolicy(AssignVolumeProtectionPolicy {
            volume_id,
            policy_id,
        }),
    )?;
    let selected = repository
        .volume_protection_policy(volume_id)?
        .ok_or("assigned volume policy was absent")?;
    assert_eq!(selected.policy_id, policy_id);
    assert_eq!(selected.revision, Revision::new(2));
    assert_eq!(selected.scenarios.len(), 2);
    assert_eq!(selected.scenarios[0].terms()[0].failure_count, 2);
    assert_eq!(selected.scenarios[1].terms()[0].failure_count, 3);
    Ok(())
}

#[test]
fn unknown_failure_class_or_policy_advances_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, administrator, volume_id) = fixture()?;
    let bad = AuthoritativeCommand::CreateProtectionPolicy(CreateProtectionPolicy {
        policy_id: ProtectionPolicyId::from_bytes([30; 16])?,
        name: RecordName::new("Unknown class")?,
        scenarios: BoundedItems::new(
            vec![ProtectionScenarioConfiguration {
                scenario_id: ProtectionScenarioId::from_bytes([31; 16])?,
                name: RecordName::new("Unknown")?,
                scenario: FailureScenario::new(vec![FailureTerm {
                    class_id: meshspan_domain::FaultGroupClassId::from_bytes([32; 16])?,
                    failure_count: 1,
                }])?,
            }],
            16,
        )?,
    });
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 2, term: 1 },
            context(33, administrator, 34, Some(1))?,
            &bad,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 2, term: 1 },
            context(35, administrator, 36, Some(1))?,
            &AuthoritativeCommand::AssignVolumeProtectionPolicy(AssignVolumeProtectionPolicy {
                volume_id,
                policy_id: ProtectionPolicyId::from_bytes([37; 16])?,
            }),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(1));
    assert!(repository.volume_protection_policy(volume_id)?.is_none());
    Ok(())
}

fn policy(
    policy_id: ProtectionPolicyId,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    let scenarios = [
        (40, "Any two machines", machine_fault_class_id(), 2),
        (
            41,
            "Any three storage devices",
            storage_device_fault_class_id(),
            3,
        ),
    ]
    .into_iter()
    .map(|(id, name, class_id, failure_count)| {
        Ok(ProtectionScenarioConfiguration {
            scenario_id: ProtectionScenarioId::from_bytes([id; 16])?,
            name: RecordName::new(name)?,
            scenario: FailureScenario::new(vec![FailureTerm {
                class_id,
                failure_count,
            }])?,
        })
    })
    .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    Ok(AuthoritativeCommand::CreateProtectionPolicy(
        CreateProtectionPolicy {
            policy_id,
            name: RecordName::new("Two machines and three devices")?,
            scenarios: BoundedItems::new(scenarios, 16)?,
        },
    ))
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
    repository.apply_committed(
        LogPosition { index: 1, term: 1 },
        context(10, administrator, 11, Some(0))?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([3; 16])?,
            mesh_name: RecordName::new("Protection policy proof")?,
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
         ) VALUES (?1, 'Policy volume', 'policy volume', 1, ?2, 10, 1)",
        rusqlite::params![
            volume_id.as_bytes().as_slice(),
            administrator.as_bytes().as_slice()
        ],
    )?;
    Ok((repository, administrator, volume_id))
}

fn context(
    operation: u8,
    actor: PrincipalId,
    audit: u8,
    expected_revision: Option<u64>,
) -> Result<CommandContext, meshspan_domain::IdentifierError> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation; 16])?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes([audit; 16])?,
        occurred_at: UnixMicros::new(100),
        expected_revision: expected_revision.map(Revision::new),
    })
}
