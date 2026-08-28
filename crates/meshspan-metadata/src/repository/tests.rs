// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ActivationId, ActivationPolicyId, AssuranceLevel, AuditEventId, BackupId, ComponentInstanceId,
    DurationMicros, GrantId, GroupId, HandoffEvidence, HostId, JoinGrantId, MeshId, NodeId,
    ObjectId, OperationId, OwnerSetId, PartitionId, PrincipalId, QuorumPlanId, Revision, Rights,
    RoleId, ScopeId, ScopeRoute, SnapshotId, TagId, UnixMicros, VolumeId,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::{
    ApplyDisposition, AuthoritativeRepository, EntityKind, LogPosition, PageLimit, PreservedVote,
    PrincipalKind, RepositoryConformanceReport, RepositoryConformanceVector, RepositoryError,
    restore_partition_backup, restore_partition_snapshot, run_repository_conformance,
};
use crate::{
    ActivateGrant, ActivateGroup, ActivateScopeHandoff, AddGroupMember, AssignComponent, AttachTag,
    AuthoritativeCommand, BeginScopeHandoff, BootstrapMesh, CommandContext, ConfigureComponent,
    ConsumeJoinGrant, CreateActivationPolicy, CreateComponent, CreateGroup,
    CreateMetadataPartition, CreateObject, CreateScopeRoute, CreateTag, CreateUser, CreateVolume,
    DetachTag, FreezeScopeHandoff, GrantInheritance, GrantPermission, IssueJoinGrant, JoinRoles,
    NamespaceObjectKind, PartitionDatabase, PermissionScope, RecordName, RegisterRoutingSigner,
    ReplaceObjectOwners, RouteAttestation, TagTarget,
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
fn owner_replacement_is_atomic_validated_and_restart_safe() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let file_path = directory.path().join("owner-replacement.sqlite3");
    let ids = fixture_ids()?;
    let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    let object_id = prepare_owner_replacement_fixture(&mut repository, &ids)?;

    reject_invalid_owner_replacements(&mut repository, &ids, object_id)?;
    set_principal_state(&mut repository, ids.second_user, 2)?;
    assert_invalid_owner_replacement(
        &mut repository,
        &ids,
        object_id,
        214,
        OwnerSetId::from_bytes([215; 16])?,
        vec![ids.second_user],
    )?;
    set_principal_state(&mut repository, ids.second_user, 1)?;

    let replacement_context = context(216, ids.administrator, 217, 105, Some(5))?;
    let replacement = AuthoritativeCommand::ReplaceObjectOwners(ReplaceObjectOwners {
        object_id,
        owner_set_id: OwnerSetId::from_bytes([218; 16])?,
        owners: BoundedItems::new(vec![ids.second_user, ids.outer_group.principal_id()], 1_024)?,
    });
    let receipt = repository.apply_committed(
        LogPosition { index: 6, term: 1 },
        replacement_context,
        &replacement,
    )?;
    assert_eq!(receipt.entity.kind, EntityKind::NamespaceObject);
    assert_eq!(receipt.entity.id, object_id.as_bytes());

    let conflict = AuthoritativeCommand::ReplaceObjectOwners(ReplaceObjectOwners {
        object_id,
        owner_set_id: OwnerSetId::from_bytes([219; 16])?,
        owners: BoundedItems::new(vec![ids.administrator], 1_024)?,
    });
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 7, term: 1 },
            replacement_context,
            &conflict,
        ),
        Err(RepositoryError::OperationConflict)
    ));

    drop(repository.into_database());
    let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(106))?;
    let mut repository = AuthoritativeRepository::new(database);
    let replay = repository.apply_committed(
        LogPosition { index: 7, term: 1 },
        replacement_context,
        &replacement,
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    verify_replaced_owners(repository, &ids, object_id)
}

fn prepare_owner_replacement_fixture(
    repository: &mut AuthoritativeRepository,
    ids: &FixtureIds,
) -> Result<ObjectId, Box<dyn std::error::Error>> {
    apply(
        repository,
        1,
        context(190, ids.administrator, 191, 100, Some(0))?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([192; 16])?,
            mesh_name: RecordName::new("Owner replacement proof")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([193; 16])?,
            host_id: HostId::from_bytes([194; 16])?,
            host_name: RecordName::new("Owner host")?,
            node_id: NodeId::from_bytes([195; 16])?,
            node_name: RecordName::new("Owner node")?,
            partition_name: RecordName::new("Owner authority")?,
        }),
    )?;
    for (index, operation, audit, principal, name) in [
        (2, 196, 197, ids.user, "First owner"),
        (3, 198, 199, ids.second_user, "Second owner"),
    ] {
        apply(
            repository,
            index,
            context(
                operation,
                ids.administrator,
                audit,
                98 + i64::try_from(index)?,
                Some(index - 1),
            )?,
            &AuthoritativeCommand::CreateUser(CreateUser {
                principal_id: principal,
                name: RecordName::new(name)?,
            }),
        )?;
    }
    apply(
        repository,
        4,
        context(200, ids.administrator, 201, 103, Some(3))?,
        &AuthoritativeCommand::CreateGroup(CreateGroup {
            group_id: ids.outer_group,
            name: RecordName::new("Recovery owners")?,
            activation_policy_id: None,
        }),
    )?;
    let object_id = ObjectId::from_bytes([202; 16])?;
    apply(
        repository,
        5,
        context(203, ids.administrator, 204, 104, Some(4))?,
        &AuthoritativeCommand::CreateVolume(CreateVolume {
            volume_id: VolumeId::from_bytes([205; 16])?,
            name: RecordName::new("Owned volume")?,
            root_object_id: object_id,
            owner_set_id: OwnerSetId::from_bytes([206; 16])?,
            owners: BoundedItems::new(vec![ids.administrator], 1_024)?,
        }),
    )?;
    Ok(object_id)
}

fn reject_invalid_owner_replacements(
    repository: &mut AuthoritativeRepository,
    ids: &FixtureIds,
    object_id: ObjectId,
) -> Result<(), Box<dyn std::error::Error>> {
    for (operation, owner_set, target, owners) in [
        (207, 208, object_id, Vec::new()),
        (209, 210, object_id, vec![ids.user, ids.user]),
        (
            211,
            212,
            object_id,
            vec![PrincipalId::from_bytes([213; 16])?],
        ),
        (220, 221, ObjectId::from_bytes([222; 16])?, vec![ids.user]),
    ] {
        assert_invalid_owner_replacement(
            repository,
            ids,
            target,
            operation,
            OwnerSetId::from_bytes([owner_set; 16])?,
            owners,
        )?;
    }
    Ok(())
}

fn assert_invalid_owner_replacement(
    repository: &mut AuthoritativeRepository,
    ids: &FixtureIds,
    object_id: ObjectId,
    operation: u8,
    owner_set_id: OwnerSetId,
    owners: Vec<PrincipalId>,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 6, term: 1 },
            context(
                operation,
                ids.administrator,
                operation.saturating_add(1),
                105,
                Some(5),
            )?,
            &AuthoritativeCommand::ReplaceObjectOwners(ReplaceObjectOwners {
                object_id,
                owner_set_id,
                owners: BoundedItems::new(owners, 1_024)?,
            }),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(5));
    Ok(())
}

fn set_principal_state(
    repository: &mut AuthoritativeRepository,
    principal_id: PrincipalId,
    state: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let principal = principal_id.as_bytes();
    repository.database.connection_mut().execute(
        "UPDATE principals SET state = ?1 WHERE principal_id = ?2",
        rusqlite::params![state, principal.as_slice()],
    )?;
    Ok(())
}

fn verify_replaced_owners(
    repository: AuthoritativeRepository,
    ids: &FixtureIds,
    object_id: ObjectId,
) -> Result<(), Box<dyn std::error::Error>> {
    let invariant_report = repository.check_invariants(PageLimit::new(100)?)?;
    assert!(invariant_report.findings.is_empty());
    assert!(!invariant_report.truncated);
    let database = repository.into_database();
    let object = object_id.as_bytes();
    let old_set = OwnerSetId::from_bytes([206; 16])?.as_bytes();
    let new_set = OwnerSetId::from_bytes([218; 16])?.as_bytes();
    let (stored_set, object_revision, old_count, new_count, audit_count): (
        Vec<u8>,
        i64,
        i64,
        i64,
        i64,
    ) = database.connection().query_row(
        "SELECT
            n.owner_set_id,
            n.revision,
            (SELECT count(*) FROM object_owners WHERE owner_set_id = ?2),
            (SELECT count(*) FROM object_owners WHERE owner_set_id = ?3),
            (SELECT count(*) FROM audit_events WHERE operation_id = ?4)
         FROM namespace_objects n WHERE n.object_id = ?1",
        rusqlite::params![
            object.as_slice(),
            old_set.as_slice(),
            new_set.as_slice(),
            OperationId::from_bytes([216; 16])?.as_bytes().as_slice(),
        ],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    assert_eq!(stored_set, new_set);
    assert_eq!(
        (object_revision, old_count, new_count, audit_count),
        (6, 1, 2, 1)
    );
    let expected = BTreeSet::from([ids.second_user, ids.outer_group.principal_id()]);
    let mut statement = database.connection().prepare(
        "SELECT owner_principal_id FROM object_owners
         WHERE owner_set_id = ?1 ORDER BY owner_principal_id",
    )?;
    let rows = statement.query_map([new_set.as_slice()], |row| row.get::<_, Vec<u8>>(0))?;
    let actual = rows
        .map(|row| {
            let bytes: [u8; 16] = row?.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?;
            PrincipalId::from_bytes(bytes).map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn descriptive_tags_are_audited_idempotent_and_never_grant_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let ids = fixture_ids()?;
    let database = PartitionDatabase::open(
        &directory.path().join("tags.sqlite3"),
        ids.partition,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    apply(
        &mut repository,
        1,
        context(150, ids.administrator, 151, 100, Some(0))?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([152; 16])?,
            mesh_name: RecordName::new("Tag proof")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([153; 16])?,
            host_id: HostId::from_bytes([154; 16])?,
            host_name: RecordName::new("Tag host")?,
            node_id: NodeId::from_bytes([155; 16])?,
            node_name: RecordName::new("Tag node")?,
            partition_name: RecordName::new("Tag authority")?,
        }),
    )?;
    apply(
        &mut repository,
        2,
        context(156, ids.administrator, 157, 101, Some(1))?,
        &AuthoritativeCommand::CreateUser(CreateUser {
            principal_id: ids.user,
            name: RecordName::new("Tagged user")?,
        }),
    )?;
    let root_id = ObjectId::from_bytes([158; 16])?;
    apply(
        &mut repository,
        3,
        context(159, ids.administrator, 160, 102, Some(2))?,
        &AuthoritativeCommand::CreateVolume(CreateVolume {
            volume_id: VolumeId::from_bytes([161; 16])?,
            name: RecordName::new("Tagged volume")?,
            root_object_id: root_id,
            owner_set_id: OwnerSetId::from_bytes([162; 16])?,
            owners: BoundedItems::new(vec![ids.administrator], 1_024)?,
        }),
    )?;
    let tag_id = TagId::from_bytes([163; 16])?;
    apply(
        &mut repository,
        4,
        context(164, ids.administrator, 165, 103, Some(3))?,
        &AuthoritativeCommand::CreateTag(CreateTag {
            tag_id,
            name: RecordName::new("Needs Review")?,
        }),
    )?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 5, term: 1 },
            context(179, ids.administrator, 180, 104, Some(4))?,
            &AuthoritativeCommand::CreateTag(CreateTag {
                tag_id: TagId::from_bytes([181; 16])?,
                name: RecordName::new(&"x".repeat(129))?,
            }),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    prove_tag_attachment_semantics(&mut repository, &ids, root_id, tag_id)?;
    detach_tags_and_verify_no_authority(repository, &ids, root_id, tag_id)
}

fn prove_tag_attachment_semantics(
    repository: &mut AuthoritativeRepository,
    ids: &FixtureIds,
    root_id: ObjectId,
    tag_id: TagId,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        5,
        context(166, ids.administrator, 167, 104, Some(4))?,
        &AuthoritativeCommand::AttachTag(AttachTag {
            tag_id,
            target: TagTarget::Principal(ids.user),
        }),
    )?;
    let object_attachment_context = context(168, ids.administrator, 169, 105, Some(5))?;
    let object_attachment = AuthoritativeCommand::AttachTag(AttachTag {
        tag_id,
        target: TagTarget::Object(root_id),
    });
    let attached = repository.apply_committed(
        LogPosition { index: 6, term: 1 },
        object_attachment_context,
        &object_attachment,
    )?;
    let replay = repository.apply_committed(
        LogPosition { index: 7, term: 1 },
        object_attachment_context,
        &object_attachment,
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, attached.result_digest);

    for (operation, target) in [
        (182, TagTarget::Principal(ids.user)),
        (184, TagTarget::Object(ObjectId::from_bytes([185; 16])?)),
    ] {
        assert!(matches!(
            repository.apply_committed(
                LogPosition { index: 8, term: 1 },
                context(
                    operation,
                    ids.administrator,
                    operation.saturating_add(1),
                    106,
                    Some(6),
                )?,
                &AuthoritativeCommand::AttachTag(AttachTag { tag_id, target }),
            ),
            Err(RepositoryError::InvalidCommand)
        ));
    }

    let conflicting_attachment = AuthoritativeCommand::AttachTag(AttachTag {
        tag_id,
        target: TagTarget::Principal(ids.user),
    });
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 8, term: 1 },
            object_attachment_context,
            &conflicting_attachment,
        ),
        Err(RepositoryError::OperationConflict)
    ));
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 8, term: 1 },
            context(170, ids.user, 171, 106, Some(6))?,
            &AuthoritativeCommand::CreateGroup(CreateGroup {
                group_id: GroupId::from_bytes([172; 16])?,
                name: RecordName::new("Unauthorised despite tag")?,
                activation_policy_id: None,
            }),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

fn detach_tags_and_verify_no_authority(
    mut repository: AuthoritativeRepository,
    ids: &FixtureIds,
    root_id: ObjectId,
    tag_id: TagId,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        &mut repository,
        8,
        context(173, ids.administrator, 174, 107, Some(6))?,
        &AuthoritativeCommand::DetachTag(DetachTag {
            tag_id,
            target: TagTarget::Object(root_id),
        }),
    )?;
    apply(
        &mut repository,
        9,
        context(175, ids.administrator, 176, 108, Some(7))?,
        &AuthoritativeCommand::DetachTag(DetachTag {
            tag_id,
            target: TagTarget::Principal(ids.user),
        }),
    )?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 10, term: 1 },
            context(177, ids.administrator, 178, 109, Some(8))?,
            &AuthoritativeCommand::DetachTag(DetachTag {
                tag_id,
                target: TagTarget::Principal(ids.user),
            }),
        ),
        Err(RepositoryError::InvalidCommand)
    ));

    let database = repository.into_database();
    let (tag_count, attachment_count, owner_count, user_grants, audit_count): (
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = database.connection().query_row(
        "SELECT
            (SELECT count(*) FROM tags WHERE tag_id = ?1),
            (SELECT count(*) FROM object_tags WHERE tag_id = ?1)
                + (SELECT count(*) FROM principal_tags WHERE tag_id = ?1),
            (SELECT count(*) FROM object_owners WHERE owner_set_id = ?2),
            (SELECT count(*) FROM role_grants WHERE principal_id = ?3),
            (SELECT count(*) FROM audit_events WHERE operation_id IN (?4, ?5, ?6, ?7, ?8))",
        rusqlite::params![
            tag_id.as_bytes().as_slice(),
            OwnerSetId::from_bytes([162; 16])?.as_bytes().as_slice(),
            ids.user.as_bytes().as_slice(),
            OperationId::from_bytes([164; 16])?.as_bytes().as_slice(),
            OperationId::from_bytes([166; 16])?.as_bytes().as_slice(),
            OperationId::from_bytes([168; 16])?.as_bytes().as_slice(),
            OperationId::from_bytes([173; 16])?.as_bytes().as_slice(),
            OperationId::from_bytes([175; 16])?.as_bytes().as_slice(),
        ],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    assert_eq!((tag_count, attachment_count), (1, 0));
    assert_eq!((owner_count, user_grants), (1, 0));
    assert_eq!(audit_count, 5);
    Ok(())
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
        9
    );
    Ok(())
}

#[test]
fn administrator_join_grant_enrols_once_and_exact_replay_is_safe()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("partition.sqlite3");
    let ids = fixture_ids()?;
    let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    apply(
        &mut repository,
        1,
        context(130, ids.administrator, 131, 100, Some(0))?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([132; 16])?,
            mesh_name: RecordName::new("Join proof")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([133; 16])?,
            host_id: HostId::from_bytes([134; 16])?,
            host_name: RecordName::new("First host")?,
            node_id: NodeId::from_bytes([135; 16])?,
            node_name: RecordName::new("First node")?,
            partition_name: RecordName::new("Authority")?,
        }),
    )?;
    let grant_id = JoinGrantId::from_bytes([136; 16])?;
    let secret_digest = [137; 32];
    let roles =
        JoinRoles::new(JoinRoles::STORAGE | JoinRoles::GATEWAY | JoinRoles::METADATA_ELIGIBLE)?;
    apply(
        &mut repository,
        2,
        context(138, ids.administrator, 139, 200, Some(1))?,
        &AuthoritativeCommand::IssueJoinGrant(IssueJoinGrant {
            join_grant_id: grant_id,
            secret_digest,
            allowed_roles: roles,
            maximum_uses: 1,
            expires_at: UnixMicros::new(1_000),
        }),
    )?;

    let certificate_der = b"public certificate only".to_vec();
    let certificate_fingerprint: [u8; 32] = Sha256::digest(&certificate_der).into();
    let consume_context = context(140, ids.administrator, 141, 300, Some(2))?;
    let mut consume = ConsumeJoinGrant {
        join_grant_id: grant_id,
        secret_digest: [0; 32],
        host_id: HostId::from_bytes([142; 16])?,
        new_host_name: Some(RecordName::new("Second host")?),
        node_id: NodeId::from_bytes([143; 16])?,
        node_name: RecordName::new("Second node")?,
        incarnation: 1,
        requested_roles: roles,
        certificate_der,
        certificate_fingerprint,
        certificate_valid_until: UnixMicros::new(10_000),
    };
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 3, term: 1 },
            consume_context,
            &AuthoritativeCommand::ConsumeJoinGrant(consume.clone()),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(2));

    consume.secret_digest = secret_digest;
    let command = AuthoritativeCommand::ConsumeJoinGrant(consume);
    let applied =
        repository.apply_committed(LogPosition { index: 3, term: 1 }, consume_context, &command)?;
    assert_eq!(applied.entity.kind, super::EntityKind::Node);
    let replay =
        repository.apply_committed(LogPosition { index: 4, term: 1 }, consume_context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);

    assert_authoritative_join_projection(&repository)?;

    let database = repository.into_database();
    let (uses, nodes, learner, certificates): (i64, i64, i64, i64) =
        database.connection().query_row(
            "SELECT
                (SELECT used_count FROM join_grants WHERE join_grant_id = ?1),
                (SELECT count(*) FROM nodes WHERE node_id = ?2 AND current_incarnation = 1),
                (SELECT count(*) FROM partition_voters
                 WHERE partition_id = ?3 AND node_id = ?2 AND member_role = 2 AND state = 2),
                (SELECT count(*) FROM node_certificates
                 WHERE node_id = ?2 AND certificate_fingerprint = ?4 AND state = 1)",
            rusqlite::params![
                grant_id.as_bytes().as_slice(),
                NodeId::from_bytes([143; 16])?.as_bytes().as_slice(),
                ids.partition.as_bytes().as_slice(),
                certificate_fingerprint.as_slice(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    assert_eq!((uses, nodes, learner, certificates), (1, 1, 1, 1));
    Ok(())
}

fn assert_authoritative_join_projection(
    repository: &AuthoritativeRepository,
) -> Result<(), Box<dyn std::error::Error>> {
    let membership = repository
        .partition_membership()?
        .ok_or("partition membership was absent after bootstrap")?;
    assert_eq!(membership.revision(), Revision::new(1));
    assert_eq!(
        membership.active_voters(),
        &std::collections::BTreeMap::from([(NodeId::from_bytes([135; 16])?, 1)])
    );
    assert_eq!(
        membership.admitted_learners(),
        &std::collections::BTreeMap::from([(NodeId::from_bytes([143; 16])?, 1)])
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
fn consensus_snapshot_restores_exact_state_without_forgetting_receiver_vote()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let source_path = directory.path().join("snapshot-source.sqlite3");
    let snapshot_path = directory.path().join("snapshot.image.sqlite3");
    let restored_path = directory.path().join("snapshot-restored.sqlite3");
    let wrong_plan_path = directory.path().join("snapshot-wrong.sqlite3");
    let partition_id = PartitionId::from_bytes([101; 16])?;
    let administrator = PrincipalId::from_bytes([102; 16])?;
    let voter = NodeId::from_bytes([103; 16])?;
    let database = PartitionDatabase::open(&source_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap_snapshot_repository(&mut repository, administrator, voter)?;
    let plan = meshspan_consensus::compile_plan(meshspan_consensus::flat_plan(
        QuorumPlanId::from_bytes([111; 16])?,
        1,
        BTreeSet::from([voter]),
        BTreeSet::new(),
    )?)?;
    repository.initialise_consensus_quorum_plan(&plan, UnixMicros::new(19))?;
    let entry = meshspan_consensus::LogEntry::new(
        meshspan_consensus::LogPosition { term: 1, index: 1 },
        OperationId::from_bytes([110; 16])?,
        1,
        b"bootstrap-metadata".to_vec(),
    )?;
    repository.persist_consensus_mutation(
        1,
        &meshspan_consensus::DurableMutation {
            vote_state: Some((3, Some(voter))),
            truncate_from: None,
            append: vec![entry],
            membership_epoch: None,
            quorum_plan: None,
        },
        UnixMicros::new(20),
    )?;
    let manifest = repository.create_snapshot(
        SnapshotId::from_bytes([112; 16])?,
        &snapshot_path,
        &plan,
        UnixMicros::new(21),
    )?;
    let restored = restore_partition_snapshot(
        &snapshot_path,
        &restored_path,
        manifest,
        &plan,
        PreservedVote {
            current_term: 9,
            voted_for: Some(voter),
            membership_epoch: 1,
        },
        UnixMicros::new(22),
    )?;
    let restored = AuthoritativeRepository::new(restored);
    let durable = restored.load_consensus_state(1)?;
    assert_eq!((durable.current_term, durable.voted_for), (9, Some(voter)));
    assert_eq!(durable.applied_index, 1);

    let wrong_plan = meshspan_consensus::compile_plan(meshspan_consensus::flat_plan(
        QuorumPlanId::from_bytes([113; 16])?,
        2,
        BTreeSet::from([voter]),
        BTreeSet::new(),
    )?)?;
    assert!(matches!(
        restore_partition_snapshot(
            &snapshot_path,
            &wrong_plan_path,
            manifest,
            &wrong_plan,
            PreservedVote {
                current_term: 9,
                voted_for: Some(voter),
                membership_epoch: 1,
            },
            UnixMicros::new(23),
        ),
        Err(RepositoryError::SnapshotMismatch)
    ));
    Ok(())
}

fn bootstrap_snapshot_repository(
    repository: &mut AuthoritativeRepository,
    administrator: PrincipalId,
    voter: NodeId,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        1,
        context(104, administrator, 105, 10, Some(0))?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([106; 16])?,
            mesh_name: RecordName::new("Snapshot proof")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([107; 16])?,
            host_id: HostId::from_bytes([108; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: voter,
            node_name: RecordName::new("Voter")?,
            partition_name: RecordName::new("Authority")?,
        }),
    )?;
    Ok(())
}

#[test]
fn signed_scope_handoff_persists_without_a_dual_writer_window()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("routing.sqlite3");
    let source = PartitionId::from_bytes([121; 16])?;
    let destination = PartitionId::from_bytes([122; 16])?;
    let scope_id = ScopeId::from_bytes([123; 16])?;
    let administrator = PrincipalId::from_bytes([124; 16])?;
    let signer_node = NodeId::from_bytes([125; 16])?;
    let signing_key = SigningKey::from_bytes(&[126; 32]);
    let database = PartitionDatabase::open(&file_path, source, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap_routing_repository(&mut repository, administrator, signer_node)?;
    apply(
        &mut repository,
        2,
        context(131, administrator, 141, 11, Some(1))?,
        &AuthoritativeCommand::RegisterRoutingSigner(RegisterRoutingSigner {
            node_id: signer_node,
            generation: 1,
            verifying_key: signing_key.verifying_key().to_bytes(),
        }),
    )?;
    apply(
        &mut repository,
        3,
        context(132, administrator, 142, 12, Some(2))?,
        &AuthoritativeCommand::CreateMetadataPartition(CreateMetadataPartition {
            partition_id: destination,
            name: RecordName::new("Namespace two")?,
            partition_kind: 2,
        }),
    )?;

    let mut expected = ScopeRoute::new(scope_id, source, 1, 1)?;
    apply_route(
        &mut repository,
        4,
        administrator,
        &AuthoritativeCommand::CreateScopeRoute(CreateScopeRoute {
            scope_id,
            partition_id: source,
            routing_epoch: 1,
            attestation: attestation(&signing_key, signer_node, &expected),
        }),
    )?;
    expected.begin_handoff(destination, 2)?;
    apply_route(
        &mut repository,
        5,
        administrator,
        &AuthoritativeCommand::BeginScopeHandoff(BeginScopeHandoff {
            scope_id,
            destination_partition_id: destination,
            routing_epoch: 2,
            attestation: attestation(&signing_key, signer_node, &expected),
        }),
    )?;
    let evidence = HandoffEvidence {
        frozen_revision: Revision::new(5),
        snapshot_digest: [131; 32],
    };
    expected.freeze(2, evidence)?;
    apply_route(
        &mut repository,
        6,
        administrator,
        &AuthoritativeCommand::FreezeScopeHandoff(FreezeScopeHandoff {
            scope_id,
            routing_epoch: 2,
            evidence,
            attestation: attestation(&signing_key, signer_node, &expected),
        }),
    )?;
    assert!(!expected.permits_write(source, 2));
    assert!(!expected.permits_write(destination, 2));

    let mut active = expected;
    active.activate(destination, 2, evidence)?;
    reject_bad_route_signature(
        &mut repository,
        administrator,
        signer_node,
        &signing_key,
        scope_id,
        destination,
        evidence,
        &active,
    )?;
    apply_route(
        &mut repository,
        7,
        administrator,
        &AuthoritativeCommand::ActivateScopeHandoff(ActivateScopeHandoff {
            scope_id,
            destination_partition_id: destination,
            routing_epoch: 2,
            evidence,
            attestation: attestation(&signing_key, signer_node, &active),
        }),
    )?;
    verify_persisted_route(repository, scope_id, destination)?;
    Ok(())
}

fn bootstrap_routing_repository(
    repository: &mut AuthoritativeRepository,
    administrator: PrincipalId,
    signer_node: NodeId,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        1,
        context(130, administrator, 140, 10, Some(0))?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([127; 16])?,
            mesh_name: RecordName::new("Routing proof")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([128; 16])?,
            host_id: HostId::from_bytes([129; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: signer_node,
            node_name: RecordName::new("Signer")?,
            partition_name: RecordName::new("Catalogue")?,
        }),
    )?;
    Ok(())
}

fn apply_route(
    repository: &mut AuthoritativeRepository,
    index: u8,
    administrator: PrincipalId,
    command: &AuthoritativeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        u64::from(index),
        context(
            index + 130,
            administrator,
            index + 140,
            i64::from(index) + 10,
            Some(u64::from(index - 1)),
        )?,
        command,
    )?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "one complete invalid activation fixture"
)]
fn reject_bad_route_signature(
    repository: &mut AuthoritativeRepository,
    administrator: PrincipalId,
    signer_node: NodeId,
    signing_key: &SigningKey,
    scope_id: ScopeId,
    destination: PartitionId,
    evidence: HandoffEvidence,
    active: &ScopeRoute,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut invalid_attestation = attestation(signing_key, signer_node, active);
    invalid_attestation.signature[0] ^= 1;
    let rejected = repository.apply_committed(
        LogPosition { index: 7, term: 1 },
        context(150, administrator, 160, 16, Some(6))?,
        &AuthoritativeCommand::ActivateScopeHandoff(ActivateScopeHandoff {
            scope_id,
            destination_partition_id: destination,
            routing_epoch: 2,
            evidence,
            attestation: invalid_attestation,
        }),
    );
    assert!(
        matches!(rejected, Err(RepositoryError::InvalidCommand)),
        "{rejected:?}"
    );
    Ok(())
}

fn verify_persisted_route(
    repository: AuthoritativeRepository,
    scope_id: ScopeId,
    destination: PartitionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let database = repository.into_database();
    let scope = scope_id.as_bytes();
    let (owner, ownership_epoch, handoff_state): (Vec<u8>, i64, i64) =
        database.connection().query_row(
            "SELECT partition_id, ownership_epoch, handoff_state
             FROM partition_scopes WHERE scope_id = ?1",
            [scope.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    let history: i64 = database.connection().query_row(
        "SELECT count(*) FROM partition_routes WHERE scope_id = ?1",
        [scope.as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(owner.as_slice(), destination.as_bytes());
    assert_eq!((ownership_epoch, handoff_state, history), (2, 1, 4));
    Ok(())
}

fn attestation(
    signing_key: &SigningKey,
    signer_node_id: NodeId,
    route: &ScopeRoute,
) -> RouteAttestation {
    RouteAttestation {
        signer_node_id,
        signer_generation: 1,
        signature: signing_key.sign(&route.signing_payload()).to_bytes(),
    }
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
fn component_configuration_history_and_assignments_are_authoritative()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("components.sqlite3");
    let ids = fixture_ids()?;
    let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    apply(
        &mut repository,
        1,
        context(130, ids.administrator, 131, 100, Some(0))?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([132; 16])?,
            mesh_name: RecordName::new("Component proof")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([133; 16])?,
            host_id: HostId::from_bytes([134; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([135; 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Authority")?,
        }),
    )?;
    let instance_id = ComponentInstanceId::from_bytes([136; 16])?;
    let first = b"{}".to_vec();
    apply(
        &mut repository,
        2,
        context(137, ids.administrator, 138, 101, Some(1))?,
        &AuthoritativeCommand::CreateComponent(CreateComponent {
            instance_id,
            component_kind: 1,
            name: RecordName::new("Primary storage")?,
            implementation_id: "folder".to_owned(),
            contract_major: 1,
            contract_minor: 0,
            schema_version: 1,
            configuration_digest: Sha256::digest(&first).into(),
            canonical_configuration: first,
        }),
    )?;
    let second = br#"{"mode":"safe"}"#.to_vec();
    apply(
        &mut repository,
        3,
        context(139, ids.administrator, 140, 102, Some(2))?,
        &AuthoritativeCommand::ConfigureComponent(ConfigureComponent {
            instance_id,
            schema_version: 2,
            configuration_digest: Sha256::digest(&second).into(),
            canonical_configuration: second,
        }),
    )?;
    apply(
        &mut repository,
        4,
        context(141, ids.administrator, 142, 103, Some(3))?,
        &AuthoritativeCommand::AssignComponent(AssignComponent {
            instance_id,
            assignment_kind: 1,
            assignment_id: [132; 16],
            desired_state: 1,
        }),
    )?;
    assert_eq!(repository.current_revision()?, Revision::new(4));
    let database = repository.into_database();
    let (active_revision, history_count, assignment_count): (i64, i64, i64) =
        database.connection().query_row(
            "SELECT ci.active_config_revision,
                    (SELECT COUNT(*) FROM component_configurations cc
                     WHERE cc.instance_id = ci.instance_id),
                    (SELECT COUNT(*) FROM component_assignments ca
                     WHERE ca.instance_id = ci.instance_id)
             FROM component_instances ci WHERE ci.instance_id = ?1",
            [instance_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    assert_eq!(
        (active_revision, history_count, assignment_count),
        (2, 2, 1)
    );
    Ok(())
}

#[test]
fn conflicting_operation_rolls_back_without_advancing() -> Result<(), Box<dyn std::error::Error>> {
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

#[test]
fn repository_rejects_transitive_group_cycle_without_advancing()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("cycle.sqlite3");
    let ids = fixture_ids()?;
    let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    apply(
        &mut repository,
        1,
        context(150, ids.administrator, 151, 100, Some(0))?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([152; 16])?,
            mesh_name: RecordName::new("Cycle proof")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([153; 16])?,
            host_id: HostId::from_bytes([154; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([155; 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Authority")?,
        }),
    )?;
    for (index, operation, audit, group, name) in [
        (2, 156, 157, ids.inner_group, "Inner"),
        (3, 158, 159, ids.outer_group, "Outer"),
    ] {
        apply(
            &mut repository,
            index,
            context(
                operation,
                ids.administrator,
                audit,
                100 + i64::try_from(index).map_err(|_| "fixture index overflow")?,
                Some(index - 1),
            )?,
            &AuthoritativeCommand::CreateGroup(CreateGroup {
                group_id: group,
                name: RecordName::new(name)?,
                activation_policy_id: None,
            }),
        )?;
    }
    apply(
        &mut repository,
        4,
        context(160, ids.administrator, 161, 104, Some(3))?,
        &AuthoritativeCommand::AddGroupMember(AddGroupMember {
            containing_group_id: ids.inner_group,
            member_principal_id: ids.outer_group.principal_id(),
            valid_from: None,
            valid_until: None,
            activation_required: false,
        }),
    )?;
    let cycle = repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        context(162, ids.administrator, 163, 105, Some(4))?,
        &AuthoritativeCommand::AddGroupMember(AddGroupMember {
            containing_group_id: ids.outer_group,
            member_principal_id: ids.inner_group.principal_id(),
            valid_from: None,
            valid_until: None,
            activation_required: false,
        }),
    );
    assert!(matches!(cycle, Err(RepositoryError::InvalidCommand)));
    assert_eq!(repository.current_revision()?, Revision::new(4));
    assert!(
        repository
            .into_database()
            .check_integrity()?
            .foreign_keys_ok
    );
    Ok(())
}

#[test]
fn sqlite_passes_the_reusable_metadata_kernel_conformance_vector()
-> Result<(), Box<dyn std::error::Error>> {
    let ids = fixture_ids()?;
    let command_context = context(170, ids.administrator, 171, 100, Some(0))?;
    let command = AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
        mesh_id: MeshId::from_bytes([172; 16])?,
        mesh_name: RecordName::new("Conformance")?,
        administrator_id: ids.administrator,
        administrator_name: RecordName::new("Administrator")?,
        administrator_role_id: RoleId::from_bytes([173; 16])?,
        host_id: HostId::from_bytes([174; 16])?,
        host_name: RecordName::new("Host")?,
        node_id: NodeId::from_bytes([175; 16])?,
        node_name: RecordName::new("Node")?,
        partition_name: RecordName::new("Authority")?,
    });
    let conflict = AuthoritativeCommand::CreateUser(CreateUser {
        principal_id: ids.user,
        name: RecordName::new("Different input")?,
    });
    let vector = RepositoryConformanceVector {
        initial_position: LogPosition { index: 1, term: 1 },
        replay_position: LogPosition { index: 2, term: 1 },
        conflict_position: LogPosition { index: 3, term: 1 },
        context: command_context,
        command: &command,
        conflicting_command: &conflict,
    };
    let report = run_repository_conformance(&vector, || {
        let database =
            PartitionDatabase::open(Path::new(":memory:"), ids.partition, UnixMicros::new(1))?;
        Ok(AuthoritativeRepository::new(database))
    })?;
    assert_eq!(
        report,
        RepositoryConformanceReport {
            failures: Vec::new(),
        }
    );
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
