// SPDX-License-Identifier: GPL-2.0-only

use std::fs::OpenOptions;
use std::io::Write;

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ActivationId, ActivationPolicyId, AssuranceLevel, AuditEventId, BackupId, DurationMicros,
    GrantId, GroupId, HostId, MeshId, NodeId, ObjectId, OperationId, OwnerSetId, PartitionId,
    PrincipalId, Revision, Rights, RoleId, UnixMicros, VolumeId,
};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::{
    ApplyDisposition, AuthoritativeRepository, LogPosition, PageLimit, PrincipalKind,
    RepositoryError, restore_partition_backup,
};
use crate::{
    ActivateGrant, ActivateGroup, AddGroupMember, AuthoritativeCommand, BootstrapMesh,
    CommandContext, CreateActivationPolicy, CreateGroup, CreateObject, CreateUser, CreateVolume,
    GrantInheritance, GrantPermission, NamespaceObjectKind, PartitionDatabase, PermissionScope,
    RecordName,
};

struct FixtureIds {
    administrator: PrincipalId,
    user: PrincipalId,
    second_user: PrincipalId,
    inner_group: GroupId,
    outer_group: GroupId,
    partition: PartitionId,
}

#[test]
fn vertical_repository_proof_survives_restart_and_exact_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("partition.sqlite3");
    let ids = fixture_ids()?;
    let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);

    let bootstrap_context = context(20, ids.administrator, 40, 100, Some(0))?;
    apply(
        &mut repository,
        1,
        bootstrap_context,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([7; 16])?,
            mesh_name: RecordName::new("Proof mesh")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([8; 16])?,
            host_id: HostId::from_bytes([9; 16])?,
            host_name: RecordName::new("Proof host")?,
            node_id: NodeId::from_bytes([10; 16])?,
            node_name: RecordName::new("Proof node")?,
            partition_name: RecordName::new("Authority")?,
        }),
    )?;
    apply(
        &mut repository,
        2,
        context(21, ids.administrator, 41, 101, Some(1))?,
        &AuthoritativeCommand::CreateUser(CreateUser {
            principal_id: ids.user,
            name: RecordName::new("Alex")?,
        }),
    )?;
    apply(
        &mut repository,
        3,
        context(22, ids.administrator, 42, 102, Some(2))?,
        &AuthoritativeCommand::CreateUser(CreateUser {
            principal_id: ids.second_user,
            name: RecordName::new("Blair")?,
        }),
    )?;
    create_groups_and_memberships(&mut repository, &ids)?;
    let policy_id = create_policy(&mut repository, &ids)?;
    let file_id = create_namespace(&mut repository, &ids)?;
    let grant_id = create_and_activate_grant(&mut repository, &ids, policy_id, file_id)?;

    verify_vertical_queries(&repository, &ids)?;

    let activation_context = context(32, ids.user, 52, 112, Some(12))?;
    let activation_command = AuthoritativeCommand::ActivateGrant(ActivateGrant {
        activation_id: ActivationId::from_bytes([33; 16])?,
        principal_id: ids.user,
        grant_id,
        policy_id,
        reason: "incident recovery".to_owned(),
        duration: DurationMicros::new(1_000),
        session_expires_at: UnixMicros::new(10_000),
        assurance: AssuranceLevel::MultiFactor,
        authentication_digest: [34; 32],
    });
    let replay = repository.apply_committed(
        LogPosition { index: 14, term: 1 },
        activation_context,
        &activation_command,
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.committed_position.index, 13);
    assert_eq!(replay.applied_position.index, 14);
    assert_eq!(replay.committed_revision, Revision::new(13));
    assert_eq!(repository.current_revision()?, Revision::new(13));
    drop(repository);

    let reopened = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(200))?;
    let repository = AuthoritativeRepository::new(reopened);
    let resolved = repository
        .resolve_operation(activation_context.operation_id)?
        .ok_or("committed operation was not resolved")?;
    assert_eq!(resolved.result_digest, replay.result_digest);
    assert_eq!(resolved.entity, replay.entity);
    assert_eq!(resolved.committed_position.index, 13);
    assert_eq!(resolved.applied_position.index, 14);
    assert_eq!(
        repository.into_database().check_integrity()?.schema_version,
        2
    );
    Ok(())
}

#[test]
fn request_path_queries_are_explicitly_bounded_and_indexed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("partition.sqlite3");
    let partition = PartitionId::from_bytes([70; 16])?;
    let database = PartitionDatabase::open(&file_path, partition, UnixMicros::new(1))?;
    assert!(matches!(
        PageLimit::new(0),
        Err(RepositoryError::InvalidPageLimit)
    ));
    assert!(matches!(
        PageLimit::new(1_001),
        Err(RepositoryError::InvalidPageLimit)
    ));

    let namespace_plan = query_plan(
        &database,
        "EXPLAIN QUERY PLAN
         SELECT object_id FROM namespace_objects INDEXED BY namespace_objects_by_parent
         WHERE volume_id = X'01010101010101010101010101010101'
           AND parent_object_id = X'02020202020202020202020202020202'
           AND state = 1 AND (canonical_name, object_id) > ('', X'00000000000000000000000000000000')
         ORDER BY canonical_name, object_id LIMIT 101",
    )?;
    assert!(namespace_plan.contains("namespace_objects_by_parent"));
    let membership_plan = query_plan(
        &database,
        "EXPLAIN QUERY PLAN
         SELECT member_principal_id FROM group_memberships
         WHERE containing_group_id = X'01010101010101010101010101010101'
           AND member_principal_id > X'00000000000000000000000000000000'
         ORDER BY member_principal_id LIMIT 101",
    )?;
    assert!(membership_plan.contains("sqlite_autoindex_group_memberships_1"));
    Ok(())
}

#[test]
fn backup_restore_verifies_exact_state_and_rejects_changed_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let database_path = directory.path().join("partition.sqlite3");
    let backup_path = directory.path().join("partition.backup.sqlite3");
    let restore_path = directory.path().join("restored.sqlite3");
    let tampered_restore_path = directory.path().join("tampered.sqlite3");
    let ids = fixture_ids()?;
    let database = PartitionDatabase::open(&database_path, ids.partition, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    let bootstrap_context = context(80, ids.administrator, 81, 100, Some(0))?;
    apply(
        &mut repository,
        1,
        bootstrap_context,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([82; 16])?,
            mesh_name: RecordName::new("Backup proof")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([83; 16])?,
            host_id: HostId::from_bytes([84; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([85; 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Authority")?,
        }),
    )?;
    let manifest = repository.create_backup(
        BackupId::from_bytes([86; 16])?,
        &backup_path,
        UnixMicros::new(200),
    )?;
    assert_eq!(manifest.state_revision, Revision::new(1));
    assert_eq!(manifest.applied_position, LogPosition { index: 1, term: 1 });
    let restored =
        restore_partition_backup(&backup_path, &restore_path, manifest, UnixMicros::new(201))?;
    let restored_repository = AuthoritativeRepository::new(restored);
    assert!(
        restored_repository
            .resolve_operation(bootstrap_context.operation_id)?
            .is_some()
    );
    assert!(matches!(
        restore_partition_backup(&backup_path, &restore_path, manifest, UnixMicros::new(202)),
        Err(RepositoryError::BackupDestinationExists)
    ));

    OpenOptions::new()
        .append(true)
        .open(&backup_path)?
        .write_all(&[0xff])?;
    assert!(matches!(
        restore_partition_backup(
            &backup_path,
            &tampered_restore_path,
            manifest,
            UnixMicros::new(203)
        ),
        Err(RepositoryError::BackupMismatch)
    ));
    Ok(())
}

#[test]
fn every_atomic_apply_stage_rolls_back_to_the_old_valid_state()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ids = fixture_ids()?;
    for (offset, fault) in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ]
    .into_iter()
    .enumerate()
    {
        let file_path = directory.path().join(format!("fault-{offset}.sqlite3"));
        let partition = PartitionId::from_bytes(
            [u8::try_from(90 + offset).map_err(|_| "fixture partition overflow")?; 16],
        )?;
        let mut database = PartitionDatabase::open(&file_path, partition, UnixMicros::new(1))?;
        let command = AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([100; 16])?,
            mesh_name: RecordName::new("Crash proof")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([101; 16])?,
            host_id: HostId::from_bytes([102; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([103; 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Authority")?,
        });
        let command_context = context(104, ids.administrator, 105, 100, Some(0))?;
        let interrupted = apply_committed_with_fault(
            &mut database,
            LogPosition { index: 1, term: 1 },
            command_context,
            &command,
            fault,
        );
        assert!(matches!(interrupted, Err(RepositoryError::InjectedFault)));
        let mut repository = AuthoritativeRepository::new(database);
        assert_eq!(repository.current_revision()?, Revision::ZERO);
        assert!(
            repository
                .resolve_operation(command_context.operation_id)?
                .is_none()
        );
        repository.apply_committed(LogPosition { index: 1, term: 1 }, command_context, &command)?;
        assert_eq!(repository.current_revision()?, Revision::new(1));
        assert!(repository.into_database().check_integrity()?.sqlite_ok);
    }
    Ok(())
}

#[test]
fn activation_required_group_is_self_activated_with_bounded_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("group-activation.sqlite3");
    let ids = fixture_ids()?;
    let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    let bootstrap = AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
        mesh_id: MeshId::from_bytes([110; 16])?,
        mesh_name: RecordName::new("Activation proof")?,
        administrator_id: ids.administrator,
        administrator_name: RecordName::new("Administrator")?,
        administrator_role_id: RoleId::from_bytes([111; 16])?,
        host_id: HostId::from_bytes([112; 16])?,
        host_name: RecordName::new("Host")?,
        node_id: NodeId::from_bytes([113; 16])?,
        node_name: RecordName::new("Node")?,
        partition_name: RecordName::new("Authority")?,
    });
    apply(
        &mut repository,
        1,
        context(114, ids.administrator, 115, 100, Some(0))?,
        &bootstrap,
    )?;
    apply(
        &mut repository,
        2,
        context(116, ids.administrator, 117, 101, Some(1))?,
        &AuthoritativeCommand::CreateUser(CreateUser {
            principal_id: ids.user,
            name: RecordName::new("Alex")?,
        }),
    )?;
    let policy_id = ActivationPolicyId::from_bytes([118; 16])?;
    apply(
        &mut repository,
        3,
        context(119, ids.administrator, 120, 102, Some(2))?,
        &AuthoritativeCommand::CreateActivationPolicy(CreateActivationPolicy {
            policy_id,
            maximum_duration: DurationMicros::new(5_000),
            reason_required: true,
            minimum_assurance: AssuranceLevel::RecentStepUp,
            valid_from: None,
            valid_until: None,
        }),
    )?;
    apply(
        &mut repository,
        4,
        context(121, ids.administrator, 122, 103, Some(3))?,
        &AuthoritativeCommand::CreateGroup(CreateGroup {
            group_id: ids.inner_group,
            name: RecordName::new("Privileged operators")?,
            activation_policy_id: Some(policy_id),
        }),
    )?;
    apply(
        &mut repository,
        5,
        context(123, ids.administrator, 124, 104, Some(4))?,
        &AuthoritativeCommand::AddGroupMember(AddGroupMember {
            containing_group_id: ids.inner_group,
            member_principal_id: ids.user,
            valid_from: None,
            valid_until: None,
            activation_required: true,
        }),
    )?;
    let activation_context = context(125, ids.user, 126, 105, Some(5))?;
    let activation = AuthoritativeCommand::ActivateGroup(ActivateGroup {
        activation_id: ActivationId::from_bytes([127; 16])?,
        principal_id: ids.user,
        group_id: ids.inner_group,
        policy_id,
        reason: "maintenance window".to_owned(),
        duration: DurationMicros::new(1_000),
        session_expires_at: UnixMicros::new(2_000),
        assurance: AssuranceLevel::RecentStepUp,
        authentication_digest: [128; 32],
    });
    let receipt = repository.apply_committed(
        LogPosition { index: 6, term: 1 },
        activation_context,
        &activation,
    )?;
    assert_eq!(receipt.committed_revision, Revision::new(6));
    drop(repository);
    let reopened = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(200))?;
    assert!(
        AuthoritativeRepository::new(reopened)
            .resolve_operation(activation_context.operation_id)?
            .is_some()
    );
    Ok(())
}

#[test]
fn conflicting_operation_and_group_cycle_roll_back_without_advancing()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("partition.sqlite3");
    let ids = fixture_ids()?;
    let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    let original_context = context(60, ids.administrator, 61, 100, Some(0))?;
    let original = AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
        mesh_id: MeshId::from_bytes([62; 16])?,
        mesh_name: RecordName::new("Mesh")?,
        administrator_id: ids.administrator,
        administrator_name: RecordName::new("Admin")?,
        administrator_role_id: RoleId::from_bytes([63; 16])?,
        host_id: HostId::from_bytes([64; 16])?,
        host_name: RecordName::new("Host")?,
        node_id: NodeId::from_bytes([65; 16])?,
        node_name: RecordName::new("Node")?,
        partition_name: RecordName::new("Authority")?,
    });
    apply(&mut repository, 1, original_context, &original)?;
    let conflict = repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        original_context,
        &AuthoritativeCommand::CreateUser(CreateUser {
            principal_id: ids.user,
            name: RecordName::new("Different")?,
        }),
    );
    assert!(matches!(conflict, Err(RepositoryError::OperationConflict)));
    assert_eq!(repository.current_revision()?, Revision::new(1));
    Ok(())
}

fn verify_vertical_queries(
    repository: &AuthoritativeRepository,
    ids: &FixtureIds,
) -> Result<(), Box<dyn std::error::Error>> {
    let principal = repository
        .principal(ids.user)?
        .ok_or("created user was not returned")?;
    assert_eq!(principal.kind, PrincipalKind::User);
    assert_eq!(principal.canonical_name, "alex");
    let root_children = repository.namespace_children(
        VolumeId::from_bytes([28; 16])?,
        ObjectId::from_bytes([29; 16])?,
        None,
        PageLimit::new(1)?,
    )?;
    assert_eq!(root_children.items.len(), 1);
    assert!(root_children.next.is_none());
    let members = repository.direct_group_members(ids.inner_group, None, PageLimit::new(1)?)?;
    assert_eq!(members.items, vec![ids.user]);
    assert!(members.next.is_none());
    assert!(
        repository
            .check_invariants(PageLimit::new(100)?)?
            .findings
            .is_empty()
    );
    Ok(())
}

fn create_groups_and_memberships(
    repository: &mut AuthoritativeRepository,
    ids: &FixtureIds,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        4,
        context(23, ids.administrator, 43, 103, Some(3))?,
        &AuthoritativeCommand::CreateGroup(CreateGroup {
            group_id: ids.inner_group,
            name: RecordName::new("Operators")?,
            activation_policy_id: None,
        }),
    )?;
    apply(
        repository,
        5,
        context(24, ids.administrator, 44, 104, Some(4))?,
        &AuthoritativeCommand::CreateGroup(CreateGroup {
            group_id: ids.outer_group,
            name: RecordName::new("Recovery team")?,
            activation_policy_id: None,
        }),
    )?;
    apply(
        repository,
        6,
        context(25, ids.administrator, 45, 105, Some(5))?,
        &AuthoritativeCommand::AddGroupMember(AddGroupMember {
            containing_group_id: ids.inner_group,
            member_principal_id: ids.user,
            valid_from: None,
            valid_until: None,
            activation_required: false,
        }),
    )?;
    apply(
        repository,
        7,
        context(26, ids.administrator, 46, 106, Some(6))?,
        &AuthoritativeCommand::AddGroupMember(AddGroupMember {
            containing_group_id: ids.outer_group,
            member_principal_id: ids.inner_group.principal_id(),
            valid_from: None,
            valid_until: None,
            activation_required: false,
        }),
    )?;
    Ok(())
}

fn create_policy(
    repository: &mut AuthoritativeRepository,
    ids: &FixtureIds,
) -> Result<ActivationPolicyId, Box<dyn std::error::Error>> {
    let policy_id = ActivationPolicyId::from_bytes([27; 16])?;
    apply(
        repository,
        8,
        context(27, ids.administrator, 47, 107, Some(7))?,
        &AuthoritativeCommand::CreateActivationPolicy(CreateActivationPolicy {
            policy_id,
            maximum_duration: DurationMicros::new(5_000),
            reason_required: true,
            minimum_assurance: AssuranceLevel::MultiFactor,
            valid_from: Some(UnixMicros::new(50)),
            valid_until: Some(UnixMicros::new(20_000)),
        }),
    )?;
    Ok(policy_id)
}

fn create_namespace(
    repository: &mut AuthoritativeRepository,
    ids: &FixtureIds,
) -> Result<ObjectId, Box<dyn std::error::Error>> {
    let volume_id = VolumeId::from_bytes([28; 16])?;
    let root_id = ObjectId::from_bytes([29; 16])?;
    let owners = BoundedItems::new(
        vec![ids.administrator, ids.user, ids.outer_group.principal_id()],
        1_024,
    )?;
    apply(
        repository,
        9,
        context(28, ids.administrator, 48, 108, Some(8))?,
        &AuthoritativeCommand::CreateVolume(CreateVolume {
            volume_id,
            name: RecordName::new("Shared")?,
            root_object_id: root_id,
            owner_set_id: OwnerSetId::from_bytes([30; 16])?,
            owners,
        }),
    )?;
    let folder_id = ObjectId::from_bytes([31; 16])?;
    apply(
        repository,
        10,
        context(29, ids.administrator, 49, 109, Some(9))?,
        &AuthoritativeCommand::CreateObject(CreateObject {
            object_id: folder_id,
            volume_id,
            parent_object_id: root_id,
            kind: NamespaceObjectKind::Folder,
            name: RecordName::new("Incidents")?,
            owner_set_id: OwnerSetId::from_bytes([31; 16])?,
            owners: BoundedItems::new(vec![ids.user, ids.outer_group.principal_id()], 1_024)?,
        }),
    )?;
    let file_id = ObjectId::from_bytes([32; 16])?;
    apply(
        repository,
        11,
        context(30, ids.administrator, 50, 110, Some(10))?,
        &AuthoritativeCommand::CreateObject(CreateObject {
            object_id: file_id,
            volume_id,
            parent_object_id: folder_id,
            kind: NamespaceObjectKind::File,
            name: RecordName::new("runbook.txt")?,
            owner_set_id: OwnerSetId::from_bytes([32; 16])?,
            owners: BoundedItems::new(vec![ids.user, ids.outer_group.principal_id()], 1_024)?,
        }),
    )?;
    Ok(file_id)
}

fn create_and_activate_grant(
    repository: &mut AuthoritativeRepository,
    ids: &FixtureIds,
    policy_id: ActivationPolicyId,
    file_id: ObjectId,
) -> Result<GrantId, Box<dyn std::error::Error>> {
    let volume_id = VolumeId::from_bytes([28; 16])?;
    let grant_id = GrantId::from_bytes([35; 16])?;
    apply(
        repository,
        12,
        context(31, ids.administrator, 51, 111, Some(11))?,
        &AuthoritativeCommand::GrantPermission(GrantPermission {
            grant_id,
            subject_principal_id: ids.outer_group.principal_id(),
            scope: PermissionScope::Object {
                volume_id,
                object_id: file_id,
            },
            rights: Rights::READ_DATA.union(Rights::WRITE_DATA),
            inheritance: GrantInheritance::Object,
            valid_from: Some(UnixMicros::new(100)),
            valid_until: Some(UnixMicros::new(9_000)),
            activation_policy_id: Some(policy_id),
        }),
    )?;
    let activation = AuthoritativeCommand::ActivateGrant(ActivateGrant {
        activation_id: ActivationId::from_bytes([33; 16])?,
        principal_id: ids.user,
        grant_id,
        policy_id,
        reason: "incident recovery".to_owned(),
        duration: DurationMicros::new(1_000),
        session_expires_at: UnixMicros::new(10_000),
        assurance: AssuranceLevel::MultiFactor,
        authentication_digest: [34; 32],
    });
    apply(
        repository,
        13,
        context(32, ids.user, 52, 112, Some(12))?,
        &activation,
    )?;
    Ok(grant_id)
}

fn apply(
    repository: &mut AuthoritativeRepository,
    index: u64,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<(), RepositoryError> {
    repository
        .apply_committed(LogPosition { index, term: 1 }, context, command)
        .map(|_| ())
}

fn context(
    operation_byte: u8,
    actor: PrincipalId,
    audit_byte: u8,
    occurred_at: i64,
    expected_revision: Option<u64>,
) -> Result<CommandContext, Box<dyn std::error::Error>> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation_byte; 16])?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes([audit_byte; 16])?,
        occurred_at: UnixMicros::new(occurred_at),
        expected_revision: expected_revision.map(Revision::new),
    })
}

fn fixture_ids() -> Result<FixtureIds, Box<dyn std::error::Error>> {
    Ok(FixtureIds {
        administrator: PrincipalId::from_bytes([2; 16])?,
        user: PrincipalId::from_bytes([3; 16])?,
        second_user: PrincipalId::from_bytes([4; 16])?,
        inner_group: GroupId::from_bytes([5; 16])?,
        outer_group: GroupId::from_bytes([6; 16])?,
        partition: PartitionId::from_bytes([1; 16])?,
    })
}

fn query_plan(
    database: &PartitionDatabase,
    sql: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut statement = database.connection().prepare(sql)?;
    let rows = statement.query_map([], |row| row.get::<_, String>(3))?;
    let mut plan = String::new();
    for row in rows {
        plan.push_str(&row?);
        plan.push('\n');
    }
    Ok(plan)
}
