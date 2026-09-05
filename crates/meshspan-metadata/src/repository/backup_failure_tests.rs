// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::{BackupDestinationRecord, CreateFaultGroup, SetHostFaultGroupMembership};
use meshspan_domain::{FaultGroupClassId, FaultGroupId};

#[test]
fn distinct_drives_on_a_replica_host_still_overlap_machine_failure() -> TestResult {
    let mut fixture = fixture()?;
    add_target(&mut fixture, 20, 20)?;
    reconcile(&mut fixture)?;
    let destinations = fixture
        .repository
        .active_backup_destinations(None, PageLimit::new(10)?)?;
    assert_eq!(destinations.items.len(), 2);
    for destination in destinations.items {
        assert_eq!(
            destination.failure_relationship,
            BackupFailureRelationship::Overlapping
        );
        assert_ne!(destination.failure_evidence_digest, [0; 32]);
    }
    Ok(())
}

#[test]
fn current_group_changes_update_assessment_without_a_defaults_job() -> TestResult {
    let mut fixture = fixture()?;
    add_host_target(&mut fixture, 30)?;
    reconcile(&mut fixture)?;
    let initial = destination_for(&fixture, 30)?;
    assert_eq!(
        initial.failure_relationship,
        BackupFailureRelationship::Unknown
    );
    create_group(&mut fixture, 60, 61)?;
    create_group(&mut fixture, 62, 61)?;
    assign(&mut fixture, 4, 60, true)?;
    assert_eq!(
        destination_for(&fixture, 30)?.failure_relationship,
        BackupFailureRelationship::Unknown
    );
    assign(&mut fixture, 30, 62, true)?;
    let independent = destination_for(&fixture, 30)?;
    assert_eq!(
        independent.failure_relationship,
        BackupFailureRelationship::Independent
    );
    assert_ne!(
        independent.failure_evidence_digest,
        initial.failure_evidence_digest
    );
    assign(&mut fixture, 30, 60, true)?;
    let overlapping = destination_for(&fixture, 30)?;
    assert_eq!(
        overlapping.failure_relationship,
        BackupFailureRelationship::Overlapping
    );
    assert_ne!(
        overlapping.failure_evidence_digest,
        independent.failure_evidence_digest
    );
    assert_eq!(overlapping.revision, initial.revision); // Configuration was not edited.
    let exact = fixture
        .repository
        .backup_destination(overlapping.destination_id)?
        .ok_or("missing")?;
    assert_eq!(exact, overlapping);
    assign(&mut fixture, 30, 60, false)?;
    assert_eq!(
        destination_for(&fixture, 30)?.failure_relationship,
        BackupFailureRelationship::Independent
    );
    Ok(())
}

#[test]
fn unassigned_failure_classes_remove_independence_until_both_hosts_are_covered() -> TestResult {
    let mut fixture = fixture()?;
    add_host_target(&mut fixture, 30)?;
    create_group(&mut fixture, 60, 61)?;
    create_group(&mut fixture, 62, 61)?;
    assign(&mut fixture, 4, 60, true)?;
    assign(&mut fixture, 30, 62, true)?;
    reconcile(&mut fixture)?;
    assert_eq!(
        destination_for(&fixture, 30)?.failure_relationship,
        BackupFailureRelationship::Independent
    );
    create_group(&mut fixture, 63, 64)?;
    create_group(&mut fixture, 65, 64)?;
    assign(&mut fixture, 30, 65, true)?;
    assert_eq!(
        destination_for(&fixture, 30)?.failure_relationship,
        BackupFailureRelationship::Unknown
    );
    assign(&mut fixture, 4, 63, true)?;
    assert_eq!(
        destination_for(&fixture, 30)?.failure_relationship,
        BackupFailureRelationship::Independent
    );
    Ok(())
}

#[test]
fn local_independence_declarations_cannot_override_current_topology() -> TestResult {
    let mut fixture = fixture()?;
    reconcile(&mut fixture)?;
    let original = destination_for(&fixture, 9)?;
    apply(
        &mut fixture,
        &AuthoritativeCommand::ConfigureBackupDestination(ConfigureBackupDestination {
            destination_id: original.destination_id,
            expected_destination_revision: original.revision,
            name: RecordName::new("Claimed independent")?,
            binding: original.binding,
            failure_relationship: BackupFailureRelationship::Independent,
            failure_evidence_digest: [99; 32],
            enabled: false,
        }),
    )?;
    let actual = destination_for(&fixture, 9)?;
    assert_eq!(actual.state, BackupDestinationState::Paused);
    assert_eq!(
        actual.failure_relationship,
        BackupFailureRelationship::Overlapping
    );
    assert_ne!(actual.failure_evidence_digest, [99; 32]);
    Ok(())
}

#[test]
fn protection_evidence_loses_independence_immediately_when_power_is_shared() -> TestResult {
    let mut fixture = fixture()?;
    let local = BackupDestinationId::from_bytes([30; 16])?;
    let backup = BackupId::from_bytes([31; 16])?;
    configure_destination(&mut fixture, local)?;
    let claim = queue_and_claim(&mut fixture, backup)?;
    record_and_verify_backup(&mut fixture, local, backup, [35; 32], claim)?;
    add_host_target(&mut fixture, 30)?;
    create_group(&mut fixture, 60, 61)?;
    create_group(&mut fixture, 62, 61)?;
    assign(&mut fixture, 4, 60, true)?;
    assign(&mut fixture, 30, 62, true)?;
    reconcile(&mut fixture)?;
    let remote = destination_for(&fixture, 30)?;
    add_verified_copy(&mut fixture, backup, remote.destination_id)?;
    let before = fixture
        .repository
        .metadata_backup_protection_evidence(backup)?;
    assert_eq!((before.verified_copies, before.independent_copies), (2, 1));
    assign(&mut fixture, 30, 60, true)?;
    let after = fixture
        .repository
        .metadata_backup_protection_evidence(backup)?;
    assert_eq!((after.verified_copies, after.independent_copies), (2, 0));
    assert_ne!(after.digest, before.digest);
    assert_eq!(
        fixture
            .repository
            .backup_copy(backup, remote.destination_id)?
            .ok_or("copy missing")?
            .state,
        BackupCopyState::Verified
    );
    Ok(())
}

#[test]
fn newly_admitted_metadata_learner_adds_a_source_failure_boundary() -> TestResult {
    let mut fixture = fixture()?;
    add_host_target(&mut fixture, 30)?;
    create_group(&mut fixture, 60, 61)?;
    create_group(&mut fixture, 62, 61)?;
    assign(&mut fixture, 4, 60, true)?;
    assign(&mut fixture, 30, 62, true)?;
    reconcile(&mut fixture)?;
    assert_eq!(
        destination_for(&fixture, 30)?.failure_relationship,
        BackupFailureRelationship::Independent
    );
    let roles =
        crate::JoinRoles::new(crate::JoinRoles::STORAGE | crate::JoinRoles::METADATA_ELIGIBLE)?;
    add_host_target_with_roles(&mut fixture, 40, roles)?;
    assert_eq!(
        destination_for(&fixture, 30)?.failure_relationship,
        BackupFailureRelationship::Unknown
    );
    assign(&mut fixture, 40, 62, true)?;
    assert_eq!(
        destination_for(&fixture, 30)?.failure_relationship,
        BackupFailureRelationship::Overlapping
    );
    Ok(())
}

fn add_verified_copy(
    fixture: &mut Fixture,
    backup: BackupId,
    destination: BackupDestinationId,
) -> TestResult {
    apply(
        fixture,
        &AuthoritativeCommand::RecordBackupCopy(crate::RecordBackupCopy {
            backup_id: backup,
            destination_id: destination,
            provider_generation: 1,
            object_reference: "topology-proof-copy".to_owned(),
            byte_length: 4_512,
            copy_digest: [35; 32],
        }),
    )?;
    apply(
        fixture,
        &AuthoritativeCommand::VerifyBackupCopy(VerifyBackupCopy {
            backup_id: backup,
            destination_id: destination,
            provider_generation: 1,
            copy_digest: [35; 32],
        }),
    )?;
    Ok(())
}

fn destination_for(fixture: &Fixture, target: u8) -> TestResult<BackupDestinationRecord> {
    let target = TargetId::from_bytes([target; 16])?;
    fixture.repository.backup_destinations(None, PageLimit::new(10)?)?.items.into_iter()
        .find(|record| matches!(record.binding, BackupDestinationBinding::RegisteredTarget { target_id, .. } if target_id == target))
        .ok_or_else(|| "destination missing".into())
}

fn create_group(fixture: &mut Fixture, group: u8, class: u8) -> TestResult {
    apply(
        fixture,
        &AuthoritativeCommand::CreateFaultGroup(CreateFaultGroup {
            class_id: FaultGroupClassId::from_bytes([class; 16])?,
            class_name: RecordName::new(&format!("Class {class}"))?,
            group_id: FaultGroupId::from_bytes([group; 16])?,
            group_name: RecordName::new(&format!("Group {group}"))?,
        }),
    )?;
    Ok(())
}

fn assign(fixture: &mut Fixture, host: u8, group: u8, present: bool) -> TestResult {
    apply(
        fixture,
        &AuthoritativeCommand::SetHostFaultGroupMembership(SetHostFaultGroupMembership {
            host_id: HostId::from_bytes([host; 16])?,
            group_id: FaultGroupId::from_bytes([group; 16])?,
            present,
        }),
    )?;
    Ok(())
}
