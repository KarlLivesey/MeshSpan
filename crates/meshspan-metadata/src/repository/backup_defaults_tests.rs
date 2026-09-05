// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::{ReconcileMetadataBackupDefaults, RepositoryError};

#[path = "backup_failure_tests.rs"]
mod failure;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn defaults_create_a_useful_single_target_schedule_once() -> TestResult {
    let mut fixture = fixture()?;
    reconcile(&mut fixture)?;
    let schedule = fixture
        .repository
        .metadata_backup_schedule()?
        .ok_or("schedule missing")?;
    assert_eq!(schedule.interval, DurationMicros::new(86_400_000_000));
    assert_eq!(schedule.retained_generations, 3);
    assert_eq!(schedule.minimum_verified_copies, 1);
    assert_eq!(schedule.minimum_independent_copies, 0);
    assert!(schedule.enabled);
    let destinations = fixture
        .repository
        .active_backup_destinations(None, PageLimit::new(10)?)?;
    assert_eq!(destinations.items.len(), 1);
    assert_eq!(
        destinations.items[0].binding,
        BackupDestinationBinding::RegisteredTarget {
            target_id: fixture.target,
            target_generation: 1
        }
    );
    assert_eq!(
        destinations.items[0].failure_relationship,
        BackupFailureRelationship::Overlapping
    );
    assert_eq!(
        fixture.repository.metadata_backup_defaults_candidate()?,
        None
    );
    Ok(())
}

#[test]
fn defaults_grow_to_three_locations_and_prefer_distinct_known_devices() -> TestResult {
    let mut fixture = fixture()?;
    reconcile(&mut fixture)?;
    add_target(&mut fixture, 20, 14)?; // Alias of the first target's backing device.
    reconcile(&mut fixture)?;
    add_target(&mut fixture, 21, 21)?;
    add_target(&mut fixture, 22, 22)?;
    reconcile(&mut fixture)?;
    let page = fixture
        .repository
        .active_backup_destinations(None, PageLimit::new(10)?)?;
    let targets = page
        .items
        .iter()
        .map(|record| match record.binding {
            BackupDestinationBinding::RegisteredTarget { target_id, .. } => Ok(target_id),
            _ => Err("unexpected default provider"),
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    assert_eq!(
        targets,
        [
            fixture.target,
            TargetId::from_bytes([21; 16])?,
            TargetId::from_bytes([22; 16])?
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        fixture
            .repository
            .metadata_backup_schedule()?
            .ok_or("schedule missing")?
            .minimum_verified_copies,
        3
    );
    assert_eq!(
        fixture.repository.metadata_backup_defaults_candidate()?,
        None
    );
    let all = fixture
        .repository
        .backup_destinations(None, PageLimit::new(10)?)?;
    assert_eq!(
        all.items
            .iter()
            .filter(|record| record.state == BackupDestinationState::Paused)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn explicit_pause_and_custom_schedule_are_never_overwritten_by_defaults() -> TestResult {
    let mut fixture = fixture()?;
    reconcile(&mut fixture)?;
    let destination = fixture
        .repository
        .active_backup_destinations(None, PageLimit::new(1)?)?
        .items
        .remove(0);
    apply(
        &mut fixture,
        &AuthoritativeCommand::ConfigureBackupDestination(ConfigureBackupDestination {
            destination_id: destination.destination_id,
            expected_destination_revision: destination.revision,
            name: RecordName::new("Paused by administrator")?,
            binding: destination.binding,
            failure_relationship: BackupFailureRelationship::Unknown,
            failure_evidence_digest: [1; 32],
            enabled: false,
        }),
    )?;
    let schedule = fixture
        .repository
        .metadata_backup_schedule()?
        .ok_or("schedule missing")?;
    apply(
        &mut fixture,
        &AuthoritativeCommand::ConfigureMetadataBackupSchedule(ConfigureMetadataBackupSchedule {
            partition_id: schedule.partition_id,
            expected_schedule_sequence: schedule.sequence,
            interval: DurationMicros::new(42),
            retained_generations: 10,
            minimum_verified_copies: 2,
            minimum_independent_copies: 1,
            enabled: false,
            next_due_at: UnixMicros::new(100_000),
        }),
    )?;
    let explicit = fixture.repository.metadata_backup_schedule()?;
    add_target(&mut fixture, 20, 20)?;
    reconcile(&mut fixture)?;
    assert_eq!(fixture.repository.metadata_backup_schedule()?, explicit);
    assert_eq!(
        fixture
            .repository
            .backup_destination(destination.destination_id)?
            .ok_or("destination missing")?
            .state,
        BackupDestinationState::Paused
    );
    assert_eq!(
        fixture
            .repository
            .active_backup_destinations(None, PageLimit::new(10)?)?
            .items
            .len(),
        1
    );
    Ok(())
}

#[test]
fn stale_defaults_or_topology_proposals_leave_configuration_unchanged() -> TestResult {
    let mut fixture = fixture()?;
    let candidate = fixture
        .repository
        .metadata_backup_defaults_candidate()?
        .ok_or("candidate missing")?;
    add_target(&mut fixture, 20, 20)?;
    let before = fixture.repository.current_revision()?;
    assert!(
        matches!(apply(&mut fixture, &AuthoritativeCommand::ReconcileMetadataBackupDefaults(candidate)), Err(error)
        if matches!(error.downcast_ref::<RepositoryError>(), Some(RepositoryError::StaleRevision)))
    );
    assert_eq!(fixture.repository.current_revision()?, before);
    assert_eq!(fixture.repository.metadata_backup_schedule()?, None);
    reconcile(&mut fixture)?;
    assert_eq!(
        fixture
            .repository
            .active_backup_destinations(None, PageLimit::new(10)?)?
            .items
            .len(),
        2
    );
    Ok(())
}

#[test]
fn defaults_wire_contract_roundtrips_both_revision_fences() -> TestResult {
    let fixture = fixture()?;
    let candidate = fixture
        .repository
        .metadata_backup_defaults_candidate()?
        .ok_or("candidate missing")?;
    let command = AuthoritativeCommand::ReconcileMetadataBackupDefaults(candidate);
    let context = context(170, fixture.administrator, 171, 1000, 2)?;
    let bytes = crate::encode_authoritative_command(context, &command)?;
    assert_eq!(
        crate::decode_authoritative_command(&bytes)?.command,
        command
    );
    for length in 0..bytes.len() {
        assert!(crate::decode_authoritative_command(&bytes[..length]).is_err());
    }
    let invalid =
        AuthoritativeCommand::ReconcileMetadataBackupDefaults(ReconcileMetadataBackupDefaults {
            expected_topology_revision: Revision::new(0),
            ..candidate
        });
    assert!(crate::encode_authoritative_command(context, &invalid).is_err());
    Ok(())
}

#[test]
fn defaults_prefer_separate_hosts_and_reconsider_shared_power_groups() -> TestResult {
    use crate::{CreateFaultGroup, SetHostFaultGroupMembership};
    use meshspan_domain::{FaultGroupClassId, FaultGroupId};

    let mut fixture = fixture()?;
    for identity in [30, 40, 50] {
        add_host_target(&mut fixture, identity)?;
    }
    reconcile(&mut fixture)?;
    let group_id = FaultGroupId::from_bytes([60; 16])?;
    apply(
        &mut fixture,
        &AuthoritativeCommand::CreateFaultGroup(CreateFaultGroup {
            class_id: FaultGroupClassId::from_bytes([61; 16])?,
            class_name: RecordName::new("Power supply")?,
            group_id,
            group_name: RecordName::new("Shared UPS")?,
        }),
    )?;
    for identity in [4, 30] {
        apply(
            &mut fixture,
            &AuthoritativeCommand::SetHostFaultGroupMembership(SetHostFaultGroupMembership {
                host_id: HostId::from_bytes([identity; 16])?,
                group_id,
                present: true,
            }),
        )?;
    }
    reconcile(&mut fixture)?;
    let destinations = fixture
        .repository
        .active_backup_destinations(None, PageLimit::new(10)?)?;
    let expected = [
        fixture.target,
        TargetId::from_bytes([40; 16])?,
        TargetId::from_bytes([50; 16])?,
    ];
    assert_eq!(destinations.items.len(), expected.len());
    for destination in destinations.items {
        let BackupDestinationBinding::RegisteredTarget { target_id, .. } = destination.binding
        else {
            return Err("unexpected default binding".into());
        };
        assert!(expected.contains(&target_id));
        assert_eq!(
            destination.failure_relationship,
            if target_id == fixture.target {
                BackupFailureRelationship::Overlapping
            } else {
                BackupFailureRelationship::Unknown
            }
        );
    }
    assert_eq!(
        fixture.repository.metadata_backup_defaults_candidate()?,
        None
    );
    Ok(())
}

fn add_host_target(fixture: &mut Fixture, identity: u8) -> TestResult {
    add_host_target_with_roles(
        fixture,
        identity,
        crate::JoinRoles::new(crate::JoinRoles::STORAGE)?,
    )
}

fn add_host_target_with_roles(
    fixture: &mut Fixture,
    identity: u8,
    roles: crate::JoinRoles,
) -> TestResult {
    use crate::{ActivateNode, ConsumeJoinGrant, IssueJoinGrant};
    use meshspan_domain::JoinGrantId;

    let join_grant_id = JoinGrantId::from_bytes([identity; 16])?;
    let host_id = HostId::from_bytes([identity; 16])?;
    let node_id = NodeId::from_bytes([identity; 16])?;
    let private_endpoint = format!("backup-node-{identity}.meshspan.local:7443");
    apply(
        fixture,
        &AuthoritativeCommand::IssueJoinGrant(IssueJoinGrant {
            join_grant_id,
            secret_digest: [identity; 32],
            allowed_roles: roles,
            maximum_uses: 1,
            expires_at: UnixMicros::new(10_000),
        }),
    )?;
    let certificate_der = vec![identity; 32];
    apply(
        fixture,
        &AuthoritativeCommand::ConsumeJoinGrant(ConsumeJoinGrant {
            join_grant_id,
            secret_digest: [identity; 32],
            host_id,
            new_host_name: Some(RecordName::new(&format!("Host {identity}"))?),
            node_id,
            node_name: RecordName::new(&format!("Node {identity}"))?,
            incarnation: 1,
            requested_roles: roles,
            wrapping_public_key: [identity; 32],
            private_endpoint: private_endpoint.clone(),
            certificate_fingerprint: Sha256::digest(&certificate_der).into(),
            certificate_der,
            certificate_valid_until: UnixMicros::new(20_000),
        }),
    )?;
    apply(
        fixture,
        &AuthoritativeCommand::ActivateNode(ActivateNode {
            node_id,
            incarnation: 1,
            private_endpoint,
            capability_digest: [identity; 32],
        }),
    )?;
    register_target(fixture, identity, identity, (node_id, host_id))
}

#[test]
fn defaults_are_atomic_replayable_and_survive_reopening() -> TestResult {
    use crate::repository::apply::{ApplyFaultPoint, apply_committed_with_fault};

    let mut fixture = fixture()?;
    let candidate = fixture
        .repository
        .metadata_backup_defaults_candidate()?
        .ok_or("candidate missing")?;
    let command = AuthoritativeCommand::ReconcileMetadataBackupDefaults(candidate);
    let before = fixture.repository.current_revision()?;
    let context = context(240, fixture.administrator, 241, 1000, before.get())?;
    let position = LogPosition {
        index: before.get() + 1,
        term: 1,
    };
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        assert!(
            apply_committed_with_fault(
                &mut fixture.repository.database,
                position,
                context,
                &command,
                fault
            )
            .is_err()
        );
        assert_eq!(fixture.repository.current_revision()?, before);
        assert_eq!(
            fixture.repository.resolve_operation(context.operation_id)?,
            None
        );
        assert_eq!(fixture.repository.metadata_backup_schedule()?, None);
        assert_eq!(
            fixture.repository.metadata_backup_defaults_candidate()?,
            Some(candidate)
        );
        assert!(
            fixture
                .repository
                .backup_destinations(None, PageLimit::new(10)?)?
                .items
                .is_empty()
        );
    }
    let receipt = fixture
        .repository
        .apply_committed(position, context, &command)?;
    let schedule = fixture.repository.metadata_backup_schedule()?;
    let destination = fixture
        .repository
        .active_backup_destinations(None, PageLimit::new(1)?)?
        .items
        .remove(0);
    let reopened = PartitionDatabase::open(
        &fixture.directory.path().join("backup-catalogue.sqlite3"),
        fixture.partition,
        UnixMicros::new(2000),
    )?;
    fixture.repository = AuthoritativeRepository::new(reopened);
    let replay = fixture.repository.apply_committed(
        LogPosition {
            index: position.index + 1,
            term: 1,
        },
        context,
        &command,
    )?;
    assert_eq!(replay.disposition, super::super::ApplyDisposition::Replayed);
    assert_eq!(replay.committed_revision, receipt.committed_revision);
    assert_eq!(fixture.repository.metadata_backup_schedule()?, schedule);
    assert_eq!(
        fixture
            .repository
            .backup_destination(destination.destination_id)?,
        Some(destination)
    );
    assert_eq!(
        fixture.repository.metadata_backup_defaults_candidate()?,
        None
    );
    Ok(())
}

fn reconcile(fixture: &mut Fixture) -> TestResult {
    let command = fixture
        .repository
        .metadata_backup_defaults_candidate()?
        .ok_or("candidate missing")?;
    apply(
        fixture,
        &AuthoritativeCommand::ReconcileMetadataBackupDefaults(command),
    )?;
    Ok(())
}

fn add_target(fixture: &mut Fixture, identity: u8, device: u8) -> TestResult {
    register_target(
        fixture,
        identity,
        device,
        (fixture.node, HostId::from_bytes([4; 16])?),
    )
}

fn register_target(
    fixture: &mut Fixture,
    identity: u8,
    device: u8,
    location: (NodeId, HostId),
) -> TestResult {
    let configuration = b"{\"usage_limit\":\"per-target\"}".to_vec();
    apply(
        fixture,
        &AuthoritativeCommand::RegisterStorageTarget(RegisterStorageTarget {
            target_id: TargetId::from_bytes([identity; 16])?,
            node_id: location.0,
            host_id: location.1,
            provider: CreateComponent {
                instance_id: ComponentInstanceId::from_bytes([identity + 50; 16])?,
                component_kind: 1,
                name: RecordName::new(&format!("Provider {identity}"))?,
                implementation_id: "meshspan-folder".to_owned(),
                contract_major: 1,
                contract_minor: 0,
                schema_version: 1,
                configuration_digest: Sha256::digest(&configuration).into(),
                canonical_configuration: configuration,
            },
            name: RecordName::new(&format!("Folder {identity}"))?,
            generation: 1,
            marker_fingerprint: [identity; 32],
            backing_device_fingerprint: Some([device; 32]),
            filesystem_fingerprint: Some([device + 1; 32]),
            usage_limit: StorageUsageLimit::Bytes(1024 * 1024),
        }),
    )?;
    Ok(())
}

fn apply(
    fixture: &mut Fixture,
    command: &AuthoritativeCommand,
) -> TestResult<crate::CommandReceipt> {
    let revision = fixture.repository.current_revision()?.get();
    let identity = u8::try_from(revision + 170)?;
    Ok(fixture.repository.apply_committed(
        LogPosition {
            index: revision + 1,
            term: 1,
        },
        context(
            identity,
            fixture.administrator,
            identity,
            1000 + i64::try_from(revision)?,
            revision,
        )?,
        command,
    )?)
}
