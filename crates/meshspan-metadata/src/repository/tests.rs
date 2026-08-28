// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ActivationId, ActivationPolicyId, AssuranceLevel, AuditEventId, DurationMicros, GrantId,
    GroupId, HostId, MeshId, NodeId, ObjectId, OperationId, OwnerSetId, PartitionId, PrincipalId,
    Revision, Rights, RoleId, UnixMicros, VolumeId,
};
use tempfile::tempdir;

use super::{ApplyDisposition, AuthoritativeRepository, LogPosition, RepositoryError};
use crate::{
    ActivateGrant, AddGroupMember, AuthoritativeCommand, BootstrapMesh, CommandContext,
    CreateActivationPolicy, CreateGroup, CreateObject, CreateUser, CreateVolume, GrantInheritance,
    GrantPermission, NamespaceObjectKind, PartitionDatabase, PermissionScope, RecordName,
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
