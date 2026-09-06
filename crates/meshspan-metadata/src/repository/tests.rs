// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use meshspan_backup::BackupError;
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ActivationId, ActivationPolicyId, ApiKeyId, AssuranceLevel, AuditEventId,
    AuthenticationMethodId, AuthenticationService, BackupId, ComponentInstanceId,
    DelegatedMetadataScope, DelegationAdmission, DurationMicros, EntropyError, GrantId, GroupId,
    HandoffEvidence, HostId, JoinGrantId, MeshId, MetadataKeyRange, MetadataOperationFamily,
    NodeId, ObjectId, OperationId, OwnerSetId, PartitionId, PrincipalId, QuorumPlanId,
    RandomSource, Revision, Rights, RoleId, RootDelegatedRoute, ScopeId, SessionId, SnapshotId,
    TagId, UnixMicros, VolumeId,
};
use meshspan_secret_envelope::{
    SecretContext, WrappingPrivateKey, WrappingPublicKey, encrypt_secret,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault, read_current_revision};
use super::{
    ApplyDisposition, AuthoritativeRepository, EncryptedBackupPaths, EncryptedRestorePaths,
    EntityKind, GroupMembershipEventKind, LogPosition, PageLimit, PreservedVote, PrincipalCursor,
    PrincipalKind, RepositoryConformanceReport, RepositoryConformanceVector, RepositoryError,
    restore_encrypted_partition_backup, restore_partition_backup, restore_partition_snapshot,
    run_repository_conformance,
};
use crate::{
    AbortScopeHandoff, ActivateGrant, ActivateGroup, ActivateScopeHandoff, AddGroupMember,
    AssignComponent, AttachTag, AuthoritativeCommand, BeginScopeHandoff, BootstrapMesh,
    BootstrapRecoveryIdentity, CommandContext, CommitSecretGeneration, ConfigureComponent,
    ConfirmRecoveryBundleSaved, ConsumeJoinGrant, CreateActivationPolicy,
    CreateAuthenticationMethod, CreateComponent, CreateGroup, CreateMetadataPartition,
    CreateObject, CreateScopeRoute, CreateTag, CreateUser, CreateVolume, DetachTag,
    FreezeScopeHandoff, GrantInheritance, GrantPermission, InstallScopeRouteProjection,
    IssueAuthenticationSession, IssueJoinGrant, JoinRoles, NamespaceObjectKind,
    NewAuthenticationCredential, PartitionDatabase, PermissionScope, RecordName,
    RegisterRoutingSigner, ReplaceObjectOwners, RevokeAuthenticationSession, RouteAttestation,
    SessionAuthenticationFactor, TagTarget, TotpAlgorithm, VOLUME_CONTENT_KEY_SECRET_KIND,
};

struct FixtureIds {
    administrator: PrincipalId,
    user: PrincipalId,
    second_user: PrincipalId,
    inner_group: GroupId,
    outer_group: GroupId,
    partition: PartitionId,
}

const TEST_RECOVERY_KEY_BYTES: [u8; 32] = [146; 32];

pub(super) fn protected_bootstrap(
    mesh: BootstrapMesh,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    let public_key = WrappingPublicKey::from_bytes(TEST_RECOVERY_KEY_BYTES)?;
    let certificate = vec![147; 64];
    let administrator_id = mesh.administrator_id;
    Ok(AuthoritativeCommand::BootstrapAppliance(Box::new(
        crate::test_support::bootstrap_appliance(
            mesh,
            CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([148; 16])?,
                principal_id: administrator_id,
                label: "Test bootstrap key".to_owned(),
                service_scope: 7,
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: ApiKeyId::from_bytes([149; 16])?,
                    key_digest: [150; 32],
                    smb_verifier_ciphertext: Some(vec![151; 65]),
                    scopes: 7,
                    valid_from: UnixMicros::new(1),
                },
            },
            Box::new(BootstrapRecoveryIdentity {
                public_wrapping_key: public_key.as_bytes(),
                key_fingerprint: public_key.fingerprint(),
                online_authority_certificate_digest: Sha256::digest(&certificate).into(),
                online_authority_certificate_der: certificate.clone(),
                root_certificate_digest: Sha256::digest(&certificate).into(),
                root_certificate_der: certificate,
                bundle_digest: [151; 32],
                save_challenge_commitment: [152; 32],
            }),
        )?,
    )))
}

pub(super) fn mark_test_recovery_verified(
    repository: &mut AuthoritativeRepository,
    mesh_id: MeshId,
    administrator: PrincipalId,
) -> Result<(), Box<dyn std::error::Error>> {
    let updated = repository.database.connection_mut().execute(
        "UPDATE mesh_recovery_authorities
         SET state = 2, verified_by = ?1, verified_at = 1
         WHERE mesh_id = ?2 AND state = 1",
        rusqlite::params![
            administrator.as_bytes().as_slice(),
            mesh_id.as_bytes().as_slice(),
        ],
    )?;
    if updated != 1 {
        return Err("test recovery authority was not pending".into());
    }
    Ok(())
}

pub(super) fn initial_test_volume_key(
    volume_id: VolumeId,
) -> Result<Box<CommitSecretGeneration>, Box<dyn std::error::Error>> {
    let context = SecretContext::new(VOLUME_CONTENT_KEY_SECRET_KIND, volume_id.as_bytes(), 1)?;
    let recipients = [
        WrappingPublicKey::from_bytes(TEST_RECOVERY_KEY_BYTES)?,
        crate::test_support::node_wrapping_private_key()?.public_key(),
    ];
    let (secret, recipients) =
        encrypt_secret(context, &[153; 32], &recipients, &mut VolumeKeyRandom(154))?;
    Ok(Box::new(CommitSecretGeneration {
        secret: secret.parts(),
        recipients: recipients
            .into_iter()
            .map(|recipient| recipient.parts())
            .collect(),
    }))
}

struct VolumeKeyRandom(u8);

impl RandomSource for VolumeKeyRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1).max(1);
        }
        Ok(())
    }
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
        &protected_bootstrap(BootstrapMesh {
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
        })?,
    )?;
    mark_test_recovery_verified(
        repository,
        MeshId::from_bytes([192; 16])?,
        ids.administrator,
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
            key_generation: initial_test_volume_key(VolumeId::from_bytes([205; 16])?)?,
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
        &protected_bootstrap(BootstrapMesh {
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
        })?,
    )?;
    mark_test_recovery_verified(
        &mut repository,
        MeshId::from_bytes([152; 16])?,
        ids.administrator,
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
            key_generation: initial_test_volume_key(VolumeId::from_bytes([161; 16])?)?,
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
        &protected_bootstrap(BootstrapMesh {
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
        })?,
    )?;
    mark_test_recovery_verified(
        &mut repository,
        MeshId::from_bytes([7; 16])?,
        ids.administrator,
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

    let activation_context = context(32, ids.user, 52, 113, Some(15))?;
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
        LogPosition { index: 17, term: 1 },
        activation_context,
        &activation_command,
    )?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.committed_position.index, 16);
    assert_eq!(replay.applied_position.index, 17);
    assert_eq!(replay.committed_revision, Revision::new(16));
    assert_eq!(repository.current_revision()?, Revision::new(16));
    drop(repository);

    let reopened = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(200))?;
    let repository = AuthoritativeRepository::new(reopened);
    let resolved = repository
        .resolve_operation(activation_context.operation_id)?
        .ok_or("committed operation was not resolved")?;
    assert_eq!(resolved.result_digest, replay.result_digest);
    assert_eq!(resolved.entity, replay.entity);
    assert_eq!(resolved.committed_position.index, 16);
    assert_eq!(resolved.applied_position.index, 17);
    assert_eq!(
        repository.into_database().check_integrity()?.schema_version,
        crate::migration::PARTITION_SCHEMA_VERSION
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
        &join_bootstrap(ids.administrator)?,
    )?;
    let grant_id = JoinGrantId::from_bytes([136; 16])?;
    let secret_digest = [137; 32];
    let roles =
        JoinRoles::new(JoinRoles::STORAGE | JoinRoles::GATEWAY | JoinRoles::METADATA_ELIGIBLE)?;
    let issue = AuthoritativeCommand::IssueJoinGrant(IssueJoinGrant {
        join_grant_id: grant_id,
        secret_digest,
        allowed_roles: roles,
        maximum_uses: 1,
        expires_at: UnixMicros::new(1_000),
    });
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 2, term: 1 },
            context(138, ids.administrator, 139, 150, Some(1))?,
            &issue,
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    confirm_bootstrap_recovery(&mut repository, ids.administrator)?;
    apply(
        &mut repository,
        3,
        context(138, ids.administrator, 139, 200, Some(2))?,
        &issue,
    )?;

    let certificate_der = b"public certificate only".to_vec();
    let certificate_fingerprint: [u8; 32] = Sha256::digest(&certificate_der).into();
    let consume_context = context(140, ids.administrator, 141, 300, Some(3))?;
    let mut consume = ConsumeJoinGrant {
        join_grant_id: grant_id,
        secret_digest: [0; 32],
        host_id: HostId::from_bytes([142; 16])?,
        new_host_name: Some(RecordName::new("Second host")?),
        node_id: NodeId::from_bytes([143; 16])?,
        node_name: RecordName::new("Second node")?,
        incarnation: 1,
        requested_roles: roles,
        wrapping_public_key: [144; 32],
        private_endpoint: "second-node.meshspan.local:7443".to_owned(),
        certificate_der,
        certificate_fingerprint,
        certificate_valid_until: UnixMicros::new(10_000),
    };
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 4, term: 1 },
            consume_context,
            &AuthoritativeCommand::ConsumeJoinGrant(consume.clone()),
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(3));

    consume.secret_digest = secret_digest;
    let command = AuthoritativeCommand::ConsumeJoinGrant(consume);
    let applied =
        repository.apply_committed(LogPosition { index: 4, term: 1 }, consume_context, &command)?;
    assert_eq!(applied.entity.kind, super::EntityKind::Node);
    let replay =
        repository.apply_committed(LogPosition { index: 5, term: 1 }, consume_context, &command)?;
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

fn confirm_bootstrap_recovery(
    repository: &mut AuthoritativeRepository,
    administrator: PrincipalId,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        2,
        context(144, administrator, 145, 175, Some(1))?,
        &AuthoritativeCommand::ConfirmRecoveryBundleSaved(ConfirmRecoveryBundleSaved {
            mesh_id: MeshId::from_bytes([132; 16])?,
            bundle_digest: [148; 32],
            save_challenge_commitment: [149; 32],
        }),
    )?;
    Ok(())
}

fn join_bootstrap(
    administrator: PrincipalId,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    let recovery_key = WrappingPublicKey::from_bytes([146; 32])?;
    let certificate = vec![147; 64];
    Ok(AuthoritativeCommand::BootstrapAppliance(Box::new(
        crate::test_support::bootstrap_appliance(
            BootstrapMesh {
                mesh_id: MeshId::from_bytes([132; 16])?,
                mesh_name: RecordName::new("Join proof")?,
                administrator_id: administrator,
                administrator_name: RecordName::new("Administrator")?,
                administrator_role_id: RoleId::from_bytes([133; 16])?,
                host_id: HostId::from_bytes([134; 16])?,
                host_name: RecordName::new("First host")?,
                node_id: NodeId::from_bytes([135; 16])?,
                node_name: RecordName::new("First node")?,
                partition_name: RecordName::new("Authority")?,
            },
            CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([150; 16])?,
                principal_id: administrator,
                label: "Initial API key".to_owned(),
                service_scope: 7,
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: ApiKeyId::from_bytes([151; 16])?,
                    key_digest: [152; 32],
                    smb_verifier_ciphertext: Some(vec![153; 65]),
                    scopes: 7,
                    valid_from: UnixMicros::new(100),
                },
            },
            Box::new(BootstrapRecoveryIdentity {
                public_wrapping_key: recovery_key.as_bytes(),
                key_fingerprint: recovery_key.fingerprint(),
                online_authority_certificate_digest: Sha256::digest(&certificate).into(),
                online_authority_certificate_der: certificate.clone(),
                root_certificate_digest: Sha256::digest(&certificate).into(),
                root_certificate_der: certificate,
                bundle_digest: [148; 32],
                save_challenge_commitment: [149; 32],
            }),
        )?,
    )))
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
    let federation_grant_plan = query_plan(
        &database,
        "EXPLAIN QUERY PLAN
         SELECT grant_id, revision FROM federation_grants
         WHERE relationship_id = X'01010101010101010101010101010101'
           AND revision > 1 AND revision <= 20
           AND (revision > 1
                OR (revision = 1 AND grant_id > X'00000000000000000000000000000000'))
         ORDER BY revision, grant_id LIMIT 101",
    )?;
    assert!(federation_grant_plan.contains("federation_grants_by_relationship_revision"));
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
    let (repository, bootstrap_context) = backup_repository(&database_path)?;
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
fn encrypted_backup_removes_plaintext_staging_and_restores_exact_state()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let database_path = directory.path().join("partition.sqlite3");
    let plaintext_staging = directory.path().join("backup.staging.sqlite3");
    let encrypted_path = directory.path().join("backup.msbackup");
    let restore_staging = directory.path().join("restore.staging.sqlite3");
    let restored_path = directory.path().join("restored.sqlite3");
    let (repository, bootstrap_context) = backup_repository(&database_path)?;
    let recovery_key = WrappingPrivateKey::from_bytes([87; 32])?;
    let manifest = repository.create_encrypted_backup(
        EncryptedBackupPaths {
            plaintext_staging: &plaintext_staging,
            encrypted_destination: &encrypted_path,
        },
        BackupId::from_bytes([88; 16])?,
        UnixMicros::new(300),
        &[recovery_key.public_key()],
        &mut VolumeKeyRandom(89),
    )?;
    assert!(!plaintext_staging.exists());
    assert!(encrypted_path.exists());

    let wrong_mesh_id = MeshId::from_bytes([90; 16])?;
    let wrong_mesh_manifest = super::EncryptedPartitionBackupManifest {
        partition: super::PartitionBackupManifest {
            mesh_id: wrong_mesh_id,
            ..manifest.partition
        },
        encrypted: meshspan_backup::BackupFileEvidence {
            source: meshspan_backup::BackupSourceManifest {
                mesh_id: wrong_mesh_id,
                ..manifest.encrypted.source
            },
            ..manifest.encrypted
        },
    };
    assert!(matches!(
        restore_encrypted_partition_backup(
            EncryptedRestorePaths {
                encrypted_source: &encrypted_path,
                plaintext_staging: &restore_staging,
                restored_destination: &restored_path,
            },
            wrong_mesh_manifest,
            &recovery_key,
            UnixMicros::new(301),
        ),
        Err(RepositoryError::EncryptedBackup(BackupError::Corrupt))
    ));
    assert!(!restore_staging.exists());

    let restored = restore_encrypted_partition_backup(
        EncryptedRestorePaths {
            encrypted_source: &encrypted_path,
            plaintext_staging: &restore_staging,
            restored_destination: &restored_path,
        },
        manifest,
        &recovery_key,
        UnixMicros::new(302),
    )?;
    assert!(!restore_staging.exists());
    assert!(
        AuthoritativeRepository::new(restored)
            .resolve_operation(bootstrap_context.operation_id)?
            .is_some()
    );
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

fn backup_repository(
    database_path: &Path,
) -> Result<(AuthoritativeRepository, CommandContext), Box<dyn std::error::Error>> {
    let ids = fixture_ids()?;
    let database = PartitionDatabase::open(database_path, ids.partition, UnixMicros::new(1))?;
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
    Ok((repository, bootstrap_context))
}

pub(super) fn bootstrap_snapshot_repository(
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
    let RoutingProofFixture {
        _directory: directory,
        mut repository,
        source,
        destination,
        scope_id,
        administrator,
        signer_node,
        signing_key,
    } = RoutingProofFixture::open()?;

    let scope = DelegatedMetadataScope::new(
        scope_id,
        MetadataOperationFamily::Namespace,
        MetadataKeyRange::All,
    )?;
    let mut expected = RootDelegatedRoute::new(source, scope, 1, 1)?;
    apply_route(
        &mut repository,
        4,
        administrator,
        &AuthoritativeCommand::CreateScopeRoute(CreateScopeRoute {
            root_partition_id: source,
            scope,
            routing_epoch: 1,
            attestation: attestation(&signing_key, signer_node, &expected),
        }),
    )?;
    reject_overlapping_root_scope(
        &mut repository,
        administrator,
        signer_node,
        &signing_key,
        source,
    )?;
    let admission = delegation_admission()?;
    expected.begin_delegation(destination, 2, admission)?;
    apply_route(
        &mut repository,
        5,
        administrator,
        &AuthoritativeCommand::BeginScopeHandoff(BeginScopeHandoff {
            scope_id,
            destination_partition_id: destination,
            routing_epoch: 2,
            admission,
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
    verify_persisted_route(&repository, directory.path(), scope_id, destination)?;
    Ok(())
}

#[test]
fn every_apply_boundary_rolls_back_permanent_root_scope_creation()
-> Result<(), Box<dyn std::error::Error>> {
    let RoutingProofFixture {
        _directory: _keep_directory_alive,
        repository,
        source,
        destination: _,
        scope_id,
        administrator,
        signer_node,
        signing_key,
    } = RoutingProofFixture::open()?;
    let scope = DelegatedMetadataScope::new(
        scope_id,
        MetadataOperationFamily::Namespace,
        MetadataKeyRange::All,
    )?;
    let route = RootDelegatedRoute::new(source, scope, 1, 1)?;
    let command = create_root_route(source, scope, signer_node, &signing_key, &route);
    let mut database = repository.into_database();
    for (offset, fault) in root_apply_faults().into_iter().enumerate() {
        let seed = 180_u8.saturating_add(u8::try_from(offset)?);
        assert!(matches!(
            apply_committed_with_fault(
                &mut database,
                LogPosition { index: 4, term: 1 },
                context(seed, administrator, seed.saturating_add(4), 14, Some(3))?,
                &command,
                fault,
            ),
            Err(RepositoryError::InjectedFault)
        ));
        let retained: (i64, i64, i64) = database.connection().query_row(
            "SELECT
                (SELECT count(*) FROM partition_scopes),
                (SELECT count(*) FROM root_delegated_scopes),
                (SELECT count(*) FROM partition_routes)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(retained, (0, 0, 0));
        assert_eq!(read_current_revision(&database)?, Revision::new(3));
    }
    Ok(())
}

#[test]
fn every_root_delegation_transition_rolls_back_its_command_rows()
-> Result<(), Box<dyn std::error::Error>> {
    prove_root_handoff_transition_rollbacks()?;
    prove_root_abort_transition_rollback()?;
    prove_child_projection_transition_rollback()
}

fn prove_root_handoff_transition_rollbacks() -> Result<(), Box<dyn std::error::Error>> {
    let RoutingProofFixture {
        _directory: _keep_directory_alive,
        mut repository,
        source,
        destination,
        scope_id,
        administrator,
        signer_node,
        signing_key,
    } = RoutingProofFixture::open()?;
    let scope = DelegatedMetadataScope::new(
        scope_id,
        MetadataOperationFamily::Namespace,
        MetadataKeyRange::All,
    )?;
    let mut route = RootDelegatedRoute::new(source, scope, 1, 1)?;
    apply_root_after_rollback(
        &mut repository,
        LogPosition { index: 4, term: 1 },
        context(200, administrator, 201, 14, Some(3))?,
        &create_root_route(source, scope, signer_node, &signing_key, &route),
        scope_id,
    )?;
    let admission = delegation_admission()?;
    route.begin_delegation(destination, 2, admission)?;
    apply_root_after_rollback(
        &mut repository,
        LogPosition { index: 5, term: 1 },
        context(202, administrator, 203, 15, Some(4))?,
        &AuthoritativeCommand::BeginScopeHandoff(BeginScopeHandoff {
            scope_id,
            destination_partition_id: destination,
            routing_epoch: 2,
            admission,
            attestation: attestation(&signing_key, signer_node, &route),
        }),
        scope_id,
    )?;
    let evidence = HandoffEvidence {
        frozen_revision: Revision::new(5),
        snapshot_digest: [204; 32],
    };
    route.freeze(2, evidence)?;
    apply_root_after_rollback(
        &mut repository,
        LogPosition { index: 6, term: 1 },
        context(205, administrator, 206, 16, Some(5))?,
        &AuthoritativeCommand::FreezeScopeHandoff(FreezeScopeHandoff {
            scope_id,
            routing_epoch: 2,
            evidence,
            attestation: attestation(&signing_key, signer_node, &route),
        }),
        scope_id,
    )?;
    route.activate(destination, 2, evidence)?;
    apply_root_after_rollback(
        &mut repository,
        LogPosition { index: 7, term: 1 },
        context(207, administrator, 208, 17, Some(6))?,
        &AuthoritativeCommand::ActivateScopeHandoff(ActivateScopeHandoff {
            scope_id,
            destination_partition_id: destination,
            routing_epoch: 2,
            evidence,
            attestation: attestation(&signing_key, signer_node, &route),
        }),
        scope_id,
    )?;
    assert_eq!(repository.root_delegated_route(scope_id)?, route);
    Ok(())
}

fn prove_root_abort_transition_rollback() -> Result<(), Box<dyn std::error::Error>> {
    let RoutingProofFixture {
        _directory: _keep_directory_alive,
        mut repository,
        source,
        destination,
        scope_id,
        administrator,
        signer_node,
        signing_key,
    } = RoutingProofFixture::open()?;
    let scope = DelegatedMetadataScope::new(
        scope_id,
        MetadataOperationFamily::Namespace,
        MetadataKeyRange::All,
    )?;
    let mut route = RootDelegatedRoute::new(source, scope, 1, 1)?;
    apply_route(
        &mut repository,
        4,
        administrator,
        &create_root_route(source, scope, signer_node, &signing_key, &route),
    )?;
    let admission = delegation_admission()?;
    route.begin_delegation(destination, 2, admission)?;
    apply_route(
        &mut repository,
        5,
        administrator,
        &AuthoritativeCommand::BeginScopeHandoff(BeginScopeHandoff {
            scope_id,
            destination_partition_id: destination,
            routing_epoch: 2,
            admission,
            attestation: attestation(&signing_key, signer_node, &route),
        }),
    )?;
    route.abort(3)?;
    apply_root_after_rollback(
        &mut repository,
        LogPosition { index: 6, term: 1 },
        context(209, administrator, 210, 16, Some(5))?,
        &AuthoritativeCommand::AbortScopeHandoff(AbortScopeHandoff {
            scope_id,
            routing_epoch: 3,
            reason_code: 1,
            attestation: attestation(&signing_key, signer_node, &route),
        }),
        scope_id,
    )?;
    assert_eq!(repository.root_delegated_route(scope_id)?, route);
    Ok(())
}

fn prove_child_projection_transition_rollback() -> Result<(), Box<dyn std::error::Error>> {
    let ProjectionProofFixture {
        _directory: _keep_directory_alive,
        root_repository: _,
        mut child_repository,
        destination,
        scope_id,
        administrator,
        signer_node,
        signing_key,
        mut route,
    } = ProjectionProofFixture::open()?;
    route.begin_delegation(destination, 2, delegation_admission()?)?;
    apply_root_after_rollback(
        &mut child_repository,
        LogPosition { index: 5, term: 1 },
        context(211, administrator, 212, 15, Some(4))?,
        &projection_command(signer_node, &signing_key, &route),
        scope_id,
    )?;
    assert_eq!(child_repository.root_delegated_route(scope_id)?, route);
    Ok(())
}

fn apply_root_after_rollback(
    repository: &mut AuthoritativeRepository,
    position: LogPosition,
    context: CommandContext,
    command: &AuthoritativeCommand,
    scope_id: ScopeId,
) -> Result<(), Box<dyn std::error::Error>> {
    let before = repository.root_delegated_route(scope_id).ok();
    let revision = repository.current_revision()?;
    assert!(matches!(
        repository.apply_committed_with_fault(
            position,
            context,
            command,
            ApplyFaultPoint::AfterCommand,
        ),
        Err(RepositoryError::InjectedFault)
    ));
    assert_eq!(repository.root_delegated_route(scope_id).ok(), before);
    assert_eq!(repository.current_revision()?, revision);
    assert!(
        repository
            .resolve_operation(context.operation_id)?
            .is_none()
    );
    repository.apply_committed(position, context, command)?;
    Ok(())
}

const fn root_apply_faults() -> [ApplyFaultPoint; 4] {
    [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ]
}

#[test]
fn child_route_projection_cannot_author_or_rewind_root_state()
-> Result<(), Box<dyn std::error::Error>> {
    let ProjectionProofFixture {
        _directory: _keep_directory_alive,
        mut root_repository,
        mut child_repository,
        destination,
        scope_id,
        administrator,
        signer_node,
        signing_key,
        mut route,
    } = ProjectionProofFixture::open()?;
    let admission = delegation_admission()?;
    route.begin_delegation(destination, 2, admission)?;
    let begin = AuthoritativeCommand::BeginScopeHandoff(BeginScopeHandoff {
        scope_id,
        destination_partition_id: destination,
        routing_epoch: 2,
        admission,
        attestation: attestation(&signing_key, signer_node, &route),
    });
    apply_route(&mut root_repository, 5, administrator, &begin)?;
    apply_projection(
        &mut child_repository,
        5,
        administrator,
        signer_node,
        &signing_key,
        &route,
    )?;
    assert_invalid_without_advancing(&mut child_repository, 6, administrator, &begin)?;

    let evidence = HandoffEvidence {
        frozen_revision: Revision::new(5),
        snapshot_digest: [166; 32],
    };
    route.freeze(2, evidence)?;
    apply_route(
        &mut root_repository,
        6,
        administrator,
        &AuthoritativeCommand::FreezeScopeHandoff(FreezeScopeHandoff {
            scope_id,
            routing_epoch: 2,
            evidence,
            attestation: attestation(&signing_key, signer_node, &route),
        }),
    )?;
    apply_projection(
        &mut child_repository,
        6,
        administrator,
        signer_node,
        &signing_key,
        &route,
    )?;

    let stale = route;
    route.activate(destination, 2, evidence)?;
    apply_route(
        &mut root_repository,
        7,
        administrator,
        &AuthoritativeCommand::ActivateScopeHandoff(ActivateScopeHandoff {
            scope_id,
            destination_partition_id: destination,
            routing_epoch: 2,
            evidence,
            attestation: attestation(&signing_key, signer_node, &route),
        }),
    )?;
    apply_projection(
        &mut child_repository,
        7,
        administrator,
        signer_node,
        &signing_key,
        &route,
    )?;
    let stale_projection = projection_command(signer_node, &signing_key, &stale);
    assert_invalid_without_advancing(&mut child_repository, 8, administrator, &stale_projection)?;
    assert_eq!(
        child_repository
            .root_delegated_route(scope_id)?
            .route()
            .source_partition(),
        destination
    );
    Ok(())
}

struct RoutingProofFixture {
    _directory: tempfile::TempDir,
    repository: AuthoritativeRepository,
    source: PartitionId,
    destination: PartitionId,
    scope_id: ScopeId,
    administrator: PrincipalId,
    signer_node: NodeId,
    signing_key: SigningKey,
}

impl RoutingProofFixture {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let source = PartitionId::from_bytes([121; 16])?;
        let destination = PartitionId::from_bytes([122; 16])?;
        let scope_id = ScopeId::from_bytes([123; 16])?;
        let administrator = PrincipalId::from_bytes([124; 16])?;
        let signer_node = NodeId::from_bytes([125; 16])?;
        let signing_key = SigningKey::from_bytes(&[126; 32]);
        let database = PartitionDatabase::open(
            &directory.path().join("routing.sqlite3"),
            source,
            UnixMicros::new(1),
        )?;
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
        Ok(Self {
            _directory: directory,
            repository,
            source,
            destination,
            scope_id,
            administrator,
            signer_node,
            signing_key,
        })
    }
}

struct ProjectionProofFixture {
    _directory: tempfile::TempDir,
    root_repository: AuthoritativeRepository,
    child_repository: AuthoritativeRepository,
    destination: PartitionId,
    scope_id: ScopeId,
    administrator: PrincipalId,
    signer_node: NodeId,
    signing_key: SigningKey,
    route: RootDelegatedRoute,
}

impl ProjectionProofFixture {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let RoutingProofFixture {
            _directory: directory,
            mut repository,
            source,
            destination,
            scope_id,
            administrator,
            signer_node,
            signing_key,
        } = RoutingProofFixture::open()?;
        let scope = DelegatedMetadataScope::new(
            scope_id,
            MetadataOperationFamily::Namespace,
            MetadataKeyRange::All,
        )?;
        let route = RootDelegatedRoute::new(source, scope, 1, 1)?;
        apply_route(
            &mut repository,
            4,
            administrator,
            &create_root_route(source, scope, signer_node, &signing_key, &route),
        )?;
        let mut child_repository = prepare_projection_repository(
            &directory.path().join("projection.sqlite3"),
            source,
            destination,
            administrator,
            signer_node,
            &signing_key,
        )?;
        apply_projection(
            &mut child_repository,
            4,
            administrator,
            signer_node,
            &signing_key,
            &route,
        )?;
        Ok(Self {
            _directory: directory,
            root_repository: repository,
            child_repository,
            destination,
            scope_id,
            administrator,
            signer_node,
            signing_key,
            route,
        })
    }
}

fn create_root_route(
    root_partition_id: PartitionId,
    scope: DelegatedMetadataScope,
    signer_node: NodeId,
    signing_key: &SigningKey,
    route: &RootDelegatedRoute,
) -> AuthoritativeCommand {
    AuthoritativeCommand::CreateScopeRoute(CreateScopeRoute {
        root_partition_id,
        scope,
        routing_epoch: route.route().routing_epoch(),
        attestation: attestation(signing_key, signer_node, route),
    })
}

fn prepare_projection_repository(
    file_path: &Path,
    root_partition_id: PartitionId,
    local_partition_id: PartitionId,
    administrator: PrincipalId,
    signer_node: NodeId,
    signing_key: &SigningKey,
) -> Result<AuthoritativeRepository, Box<dyn std::error::Error>> {
    let database = PartitionDatabase::open(file_path, local_partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    bootstrap_routing_repository(&mut repository, administrator, signer_node)?;
    apply(
        &mut repository,
        2,
        context(167, administrator, 168, 11, Some(1))?,
        &AuthoritativeCommand::RegisterRoutingSigner(RegisterRoutingSigner {
            node_id: signer_node,
            generation: 1,
            verifying_key: signing_key.verifying_key().to_bytes(),
        }),
    )?;
    apply(
        &mut repository,
        3,
        context(169, administrator, 170, 12, Some(2))?,
        &AuthoritativeCommand::CreateMetadataPartition(CreateMetadataPartition {
            partition_id: root_partition_id,
            name: RecordName::new("Permanent root projection")?,
            partition_kind: 1,
        }),
    )?;
    Ok(repository)
}

fn apply_projection(
    repository: &mut AuthoritativeRepository,
    index: u8,
    administrator: PrincipalId,
    signer_node: NodeId,
    signing_key: &SigningKey,
    route: &RootDelegatedRoute,
) -> Result<(), Box<dyn std::error::Error>> {
    apply_route(
        repository,
        index,
        administrator,
        &projection_command(signer_node, signing_key, route),
    )
}

fn projection_command(
    signer_node: NodeId,
    signing_key: &SigningKey,
    route: &RootDelegatedRoute,
) -> AuthoritativeCommand {
    AuthoritativeCommand::InstallScopeRouteProjection(InstallScopeRouteProjection {
        route: *route,
        attestation: attestation(signing_key, signer_node, route),
    })
}

fn assert_invalid_without_advancing(
    repository: &mut AuthoritativeRepository,
    index: u8,
    administrator: PrincipalId,
    command: &AuthoritativeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let revision = repository.current_revision()?;
    let rejected = repository.apply_committed(
        LogPosition {
            index: u64::from(index),
            term: 1,
        },
        context(
            index.wrapping_add(171),
            administrator,
            index.wrapping_add(181),
            i64::from(index) + 20,
            Some(revision.get()),
        )?,
        command,
    );
    assert!(matches!(rejected, Err(RepositoryError::InvalidCommand)));
    assert_eq!(repository.current_revision()?, revision);
    Ok(())
}

fn reject_overlapping_root_scope(
    repository: &mut AuthoritativeRepository,
    administrator: PrincipalId,
    signer_node: NodeId,
    signing_key: &SigningKey,
    root_partition_id: PartitionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let scope = DelegatedMetadataScope::new(
        ScopeId::from_bytes([163; 16])?,
        MetadataOperationFamily::Namespace,
        MetadataKeyRange::bounded([0; 16], [128; 16])?,
    )?;
    let route = RootDelegatedRoute::new(root_partition_id, scope, 1, 1)?;
    let revision = repository.current_revision()?;
    let rejected = repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        context(164, administrator, 165, 13, Some(revision.get()))?,
        &AuthoritativeCommand::CreateScopeRoute(CreateScopeRoute {
            root_partition_id,
            scope,
            routing_epoch: 1,
            attestation: attestation(signing_key, signer_node, &route),
        }),
    );
    assert!(matches!(rejected, Err(RepositoryError::InvalidCommand)));
    assert_eq!(repository.current_revision()?, revision);
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
    active: &RootDelegatedRoute,
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
    repository: &AuthoritativeRepository,
    backup_directory: &Path,
    scope_id: ScopeId,
    destination: PartitionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let root_route = repository.root_delegated_route(scope_id)?;
    assert_eq!(
        root_route.root_partition_id(),
        PartitionId::from_bytes([121; 16])?
    );
    assert_eq!(
        root_route.scope().family(),
        MetadataOperationFamily::Namespace
    );
    assert_eq!(root_route.route().source_partition(), destination);
    assert!(root_route.pending_admission().is_none());
    let restored = super::federation_backup_test_support::backup_and_restore(
        repository,
        backup_directory,
        95,
    )?;
    assert_eq!(
        restored
            .root_delegated_route(scope_id)?
            .route()
            .source_partition(),
        destination
    );
    let database = restored.into_database();
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
    assert!(
        database
            .connection()
            .execute(
                "UPDATE partition_routes SET route_payload = zeroblob(length(route_payload))
                 WHERE scope_id = ?1",
                [scope.as_slice()],
            )
            .is_err()
    );
    database.connection().execute_batch(
        "DROP TRIGGER partition_routes_reject_update;
         DROP TRIGGER partition_routes_reject_delete;
         UPDATE partition_routes SET route_payload = zeroblob(length(route_payload))
         WHERE transition_sequence = 3;
         DELETE FROM partition_routes WHERE routing_epoch = 1;",
    )?;
    let repository = AuthoritativeRepository::new(database);
    assert!(matches!(
        repository.root_delegated_route(scope_id),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

fn attestation(
    signing_key: &SigningKey,
    signer_node_id: NodeId,
    route: &RootDelegatedRoute,
) -> RouteAttestation {
    RouteAttestation {
        signer_node_id,
        signer_generation: 1,
        signature: signing_key.sign(&route.signing_payload()).to_bytes(),
    }
}

fn delegation_admission() -> Result<DelegationAdmission, meshspan_domain::DelegationError> {
    DelegationAdmission::new(3, 3, [161; 32], [162; 32], UnixMicros::new(12))
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
fn authentication_sessions_are_bounded_self_issued_and_immediately_revocable()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("authentication-sessions.sqlite3");
    let ids = fixture_ids()?;
    let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    apply(
        &mut repository,
        1,
        context(80, ids.administrator, 81, 100, Some(0))?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([82; 16])?,
            mesh_name: RecordName::new("Session proof")?,
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
    apply(
        &mut repository,
        2,
        context(86, ids.administrator, 87, 101, Some(1))?,
        &AuthoritativeCommand::CreateUser(CreateUser {
            principal_id: ids.user,
            name: RecordName::new("Session user")?,
        }),
    )?;

    let session_id = SessionId::from_bytes([88; 16])?;
    let factors = create_test_session_factors(&mut repository, 3, ids.user, 200, 140)?;
    let issue = AuthoritativeCommand::IssueAuthenticationSession(IssueAuthenticationSession {
        session_id,
        principal_id: ids.user,
        token_digest: [89; 32],
        csrf_digest: [90; 32],
        client_label: crate::SessionClientLabel::Missing,
        persistent_cookie: false,
        service: AuthenticationService::Https,
        factors: factors.clone(),
        expires_at: UnixMicros::new(1_000),
    });
    let issue_context = context(90, ids.user, 91, 200, Some(4))?;
    let receipt =
        repository.apply_committed(LogPosition { index: 5, term: 1 }, issue_context, &issue)?;
    assert_eq!(receipt.entity.kind, EntityKind::AuthenticationSession);
    assert_eq!(receipt.entity.id, session_id.as_bytes());

    let duplicate = AuthoritativeCommand::IssueAuthenticationSession(IssueAuthenticationSession {
        session_id: SessionId::from_bytes([92; 16])?,
        principal_id: ids.user,
        token_digest: [89; 32],
        csrf_digest: [91; 32],
        client_label: crate::SessionClientLabel::Missing,
        persistent_cookie: false,
        service: AuthenticationService::Https,
        factors,
        expires_at: UnixMicros::new(2_000),
    });
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 6, term: 1 },
            context(93, ids.user, 94, 201, Some(5))?,
            &duplicate,
        ),
        Err(RepositoryError::InvalidCommand)
    ));

    let revoke = AuthoritativeCommand::RevokeAuthenticationSession(RevokeAuthenticationSession {
        session_id,
        principal_id: ids.user,
    });
    let revoke_context = context(95, ids.user, 96, 202, Some(5))?;
    apply(&mut repository, 6, revoke_context, &revoke)?;
    assert_session_revocation_replay(&repository, revoke_context, session_id, ids.user)?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 7, term: 1 },
            context(97, ids.user, 98, 203, Some(6))?,
            &AuthoritativeCommand::RevokeAuthenticationSession(RevokeAuthenticationSession {
                session_id,
                principal_id: ids.user,
            }),
        ),
        Err(RepositoryError::InvalidCommand)
    ));

    drop(repository);
    let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(300))?;
    let stored: (Vec<u8>, i64, i64, i64) = database.connection().query_row(
        "SELECT token_digest, assurance, revoked_at, revision
         FROM authentication_sessions WHERE session_id = ?1",
        [session_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(stored, (vec![89; 32], 2, 202, 6));
    Ok(())
}

fn assert_session_revocation_replay(
    repository: &AuthoritativeRepository,
    context: CommandContext,
    session_id: SessionId,
    principal_id: PrincipalId,
) -> Result<(), Box<dyn std::error::Error>> {
    let replay = repository
        .resolve_session_revocation(context.operation_id, session_id, [89; 32], [90; 32])?
        .ok_or("revocation replay missing")?;
    assert_eq!(replay.session_id, session_id);
    assert_eq!(replay.principal_id, principal_id);
    assert_eq!(replay.revoked_at, UnixMicros::new(202));
    assert!(matches!(
        repository
            .resolve_session_revocation(context.operation_id, session_id, [91; 32], [90; 32],),
        Err(RepositoryError::OperationConflict)
    ));
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
    issue_group_activation_test_session(&mut repository, &ids)?;
    let activation_context = context(125, ids.user, 126, 105, Some(8))?;
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
        LogPosition { index: 9, term: 1 },
        activation_context,
        &activation,
    )?;
    assert_eq!(receipt.committed_revision, Revision::new(9));
    drop(repository);
    let reopened = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(200))?;
    assert!(
        AuthoritativeRepository::new(reopened)
            .resolve_operation(activation_context.operation_id)?
            .is_some()
    );
    Ok(())
}

fn issue_group_activation_test_session(
    repository: &mut AuthoritativeRepository,
    ids: &FixtureIds,
) -> Result<(), Box<dyn std::error::Error>> {
    let factors = create_test_session_factors(repository, 6, ids.user, 105, 150)?;
    apply(
        repository,
        8,
        context(129, ids.user, 130, 105, Some(7))?,
        &AuthoritativeCommand::IssueAuthenticationSession(IssueAuthenticationSession {
            session_id: SessionId::from_bytes([131; 16])?,
            principal_id: ids.user,
            token_digest: [128; 32],
            csrf_digest: [129; 32],
            client_label: crate::SessionClientLabel::Missing,
            persistent_cookie: false,
            service: AuthenticationService::Https,
            factors,
            expires_at: UnixMicros::new(2_000),
        }),
    )?;
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

#[test]
fn principal_administration_pages_are_ordered_bounded_and_kind_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let ids = fixture_ids()?;
    let database =
        PartitionDatabase::open(Path::new(":memory:"), ids.partition, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    apply(
        &mut repository,
        1,
        context(176, ids.administrator, 177, 100, Some(0))?,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([178; 16])?,
            mesh_name: RecordName::new("Principal paging")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Zulu administrator")?,
            administrator_role_id: RoleId::from_bytes([179; 16])?,
            host_id: HostId::from_bytes([180; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([181; 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Authority")?,
        }),
    )?;
    for (index, operation, audit, principal_id, name) in [
        (2, 182, 183, ids.user, "Bravo user"),
        (3, 184, 185, ids.second_user, "Alpha user"),
    ] {
        apply(
            &mut repository,
            index,
            context(
                operation,
                ids.administrator,
                audit,
                100 + i64::try_from(index)?,
                Some(index - 1),
            )?,
            &AuthoritativeCommand::CreateUser(CreateUser {
                principal_id,
                name: RecordName::new(name)?,
            }),
        )?;
    }
    let first = repository.principals(PrincipalKind::User, None, PageLimit::new(2)?)?;
    assert_eq!(
        first
            .items
            .iter()
            .map(|record| record.display_name.as_str())
            .collect::<Vec<_>>(),
        vec!["Alpha user", "Bravo user"]
    );
    let cursor = first.next.ok_or("expected another user page")?;
    let second = repository.principals(PrincipalKind::User, Some(&cursor), PageLimit::new(2)?)?;
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].display_name, "Zulu administrator");
    assert!(second.next.is_none());

    let substituted = PrincipalCursor::new(
        PrincipalKind::Group,
        cursor.canonical_name().to_owned(),
        cursor.principal_id(),
    );
    assert!(matches!(
        repository.principals(PrincipalKind::User, Some(&substituted), PageLimit::new(2)?,),
        Err(RepositoryError::StaleRevision)
    ));
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
    let memberships =
        repository.direct_group_memberships(ids.inner_group, None, PageLimit::new(1)?)?;
    assert_eq!(memberships.items.len(), 1);
    assert_eq!(memberships.items[0].member.principal_id, ids.user);
    assert_eq!(memberships.items[0].member.display_name, "Alex");
    assert_eq!(memberships.items[0].created_by, ids.administrator);
    assert!(!memberships.items[0].activation_required);
    assert!(memberships.next.is_none());
    let exact = repository
        .direct_group_membership(ids.inner_group, ids.user)?
        .ok_or("direct membership was not returned")?;
    assert_eq!(exact, memberships.items[0]);
    let event = repository
        .group_membership_event(ids.inner_group, exact.revision)?
        .ok_or("membership event was not returned")?;
    assert_eq!(event.group_id, ids.inner_group);
    assert_eq!(event.member_principal_id, ids.user);
    assert_eq!(event.kind, GroupMembershipEventKind::Added);
    assert_eq!(event.actor_principal_id, ids.administrator);
    assert_eq!(event.occurred_at, exact.created_at);
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
            key_generation: initial_test_volume_key(volume_id)?,
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
    let factors = create_test_session_factors(repository, 13, ids.user, 112, 160)?;
    apply(
        repository,
        15,
        context(36, ids.user, 53, 112, Some(14))?,
        &AuthoritativeCommand::IssueAuthenticationSession(IssueAuthenticationSession {
            session_id: SessionId::from_bytes([37; 16])?,
            principal_id: ids.user,
            token_digest: [34; 32],
            csrf_digest: [35; 32],
            client_label: crate::SessionClientLabel::Missing,
            persistent_cookie: false,
            service: AuthenticationService::Https,
            factors,
            expires_at: UnixMicros::new(10_000),
        }),
    )?;
    apply(
        repository,
        16,
        context(32, ids.user, 52, 113, Some(15))?,
        &activation,
    )?;
    Ok(grant_id)
}

fn create_test_session_factors(
    repository: &mut AuthoritativeRepository,
    first_index: u64,
    principal_id: PrincipalId,
    now: i64,
    seed: u8,
) -> Result<BoundedItems<SessionAuthenticationFactor>, Box<dyn std::error::Error>> {
    let api_method_id = AuthenticationMethodId::from_bytes([seed; 16])?;
    let totp_method_id = AuthenticationMethodId::from_bytes([seed.wrapping_add(1); 16])?;
    let key_id = ApiKeyId::from_bytes([seed.wrapping_add(2); 16])?;
    apply(
        repository,
        first_index,
        context(
            seed.wrapping_add(10),
            principal_id,
            seed.wrapping_add(11),
            now - 2,
            Some(first_index - 1),
        )?,
        &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id: api_method_id,
            principal_id,
            label: "Session API key".to_owned(),
            service_scope: AuthenticationService::Https.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::ApiKey {
                key_id,
                key_digest: [seed.wrapping_add(3); 32],
                smb_verifier_ciphertext: None,
                scopes: AuthenticationService::Https.api_key_login_scope(),
                valid_from: UnixMicros::new(now - 3),
            },
        }),
    )?;
    apply(
        repository,
        first_index + 1,
        context(
            seed.wrapping_add(12),
            principal_id,
            seed.wrapping_add(13),
            now - 1,
            Some(first_index),
        )?,
        &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id: totp_method_id,
            principal_id,
            label: "Session TOTP".to_owned(),
            service_scope: AuthenticationService::Https.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::Totp {
                secret_ciphertext: vec![seed.wrapping_add(4); 64],
                algorithm: TotpAlgorithm::Sha256,
                digits: 6,
                period_seconds: 30,
                accepted_step_window: 1,
            },
        }),
    )?;
    let accepted_step = u64::try_from(now)? / 30_000_000;
    Ok(BoundedItems::new(
        vec![
            SessionAuthenticationFactor::ApiKey {
                method_id: api_method_id,
                credential_generation: 1,
                method_revision: Revision::new(first_index),
                key_id,
            },
            SessionAuthenticationFactor::Totp {
                method_id: totp_method_id,
                credential_generation: 1,
                method_revision: Revision::new(first_index + 1),
                accepted_step,
            },
        ],
        8,
    )?)
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
