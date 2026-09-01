// SPDX-License-Identifier: GPL-2.0-only

use super::tests::{initial_test_volume_key, mark_test_recovery_verified, protected_bootstrap};
use super::{
    AccessAuthentication, AccessDecision, AccessDenial, AccessRequest, AuthoritativeRepository,
    BrowserSessionAccessRequest, BrowserSessionProtection, LogPosition, SessionAccessDecision,
    SessionAccessDenial, SessionAccessRequest,
};
use crate::{
    ActivateGrant, AddGroupMember, AuthoritativeCommand, BootstrapMesh, CommandContext,
    CreateActivationPolicy, CreateAuthenticationMethod, CreateGroup, CreateObject, CreateUser,
    CreateVolume, GrantInheritance, GrantPermission, IssueAuthenticationSession,
    NamespaceObjectKind, NewAuthenticationCredential, PartitionDatabase, PermissionScope,
    RecordName, RevokeAuthenticationMethod, SessionAuthenticationFactor, SetObjectGrantInheritance,
    TotpAlgorithm,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ActivationId, ActivationPolicyId, ApiKeyId, AssuranceLevel, AuditEventId,
    AuthenticationMethodId, AuthenticationService, DurationMicros, GrantId, GroupId, HostId,
    MeshId, NodeId, ObjectId, OperationId, OwnerSetId, PartitionId, PrincipalId, Revision, Rights,
    RoleId, SessionId, UnixMicros, VolumeId,
};
use std::collections::BTreeSet;

pub(super) struct Fixture {
    pub(super) repository: AuthoritativeRepository,
    pub(super) administrator: PrincipalId,
    pub(super) user: PrincipalId,
    pub(super) second_user: PrincipalId,
    pub(super) gateway: NodeId,
    pub(super) volume: VolumeId,
    pub(super) folder: ObjectId,
    pub(super) file: ObjectId,
    pub(super) next_revision: u64,
}

#[test]
fn nested_inherited_grant_is_bounded_and_admin_role_is_not_file_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = build_fixture(false)?;
    let user = fixture.user;
    let administrator = fixture.administrator;
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([40; 16])?,
        [41; 32],
    )?;
    issue_session(
        &mut fixture,
        administrator,
        SessionId::from_bytes([42; 16])?,
        [43; 32],
    )?;

    let decision =
        fixture
            .repository
            .evaluate_access(request(&fixture, [41; 32], Rights::READ_DATA, 200))?;
    let AccessDecision::Granted(capability) = decision else {
        return Err("nested grant was unexpectedly denied".into());
    };
    assert_eq!(capability.principal_id, fixture.user);
    assert_eq!(capability.expires_at, UnixMicros::new(700));
    assert_eq!(capability.identity_revision, Revision::new(11));
    assert_ne!(capability.capability_digest, [0; 32]);
    assert_eq!(
        fixture.repository.evaluate_access(request(
            &fixture,
            [41; 32],
            Rights::READ_DATA.union(Rights::WRITE_DATA),
            200,
        ))?,
        AccessDecision::Denied(AccessDenial::MissingRights)
    );
    assert_eq!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [41; 32], Rights::READ_DATA, 700,))?,
        AccessDecision::Denied(AccessDenial::MissingRights)
    );
    assert_eq!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [43; 32], Rights::READ_DATA, 200,))?,
        AccessDecision::Denied(AccessDenial::MissingRights)
    );
    Ok(())
}

#[test]
fn direct_headless_key_is_service_scoped_and_revoked_at_operation_time()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = build_fixture(false)?;
    let method_id = AuthenticationMethodId::from_bytes([70; 16])?;
    let key_id = ApiKeyId::from_bytes([71; 16])?;
    let key_digest = [72; 32];
    let user = fixture.user;
    apply(
        &mut fixture,
        user,
        130,
        AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id,
            principal_id: user,
            label: "Native API key".to_owned(),
            service_scope: AuthenticationService::HeadlessApi.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::ApiKey {
                key_id,
                key_digest,
                scopes: AuthenticationService::HeadlessApi.api_key_login_scope(),
                valid_from: UnixMicros::new(100),
            },
        }),
    )?;

    let mut direct = request(&fixture, key_digest, Rights::READ_DATA, 200);
    direct.authentication_service = AuthenticationService::HeadlessApi;
    let AccessDecision::Granted(capability) = fixture.repository.evaluate_access(direct)? else {
        return Err("current native API key was unexpectedly denied".into());
    };
    assert_eq!(
        capability.authentication,
        AccessAuthentication::ApiKey(key_id)
    );
    assert_eq!(
        capability.authentication_service,
        AuthenticationService::HeadlessApi
    );

    let mut wrong_service = direct;
    wrong_service.authentication_service = AuthenticationService::Https;
    assert_eq!(
        fixture.repository.evaluate_access(wrong_service)?,
        AccessDecision::Denied(AccessDenial::AuthenticationUnavailable)
    );

    apply(
        &mut fixture,
        user,
        210,
        AuthoritativeCommand::RevokeAuthenticationMethod(RevokeAuthenticationMethod {
            method_id,
            principal_id: user,
            reason: "operator revoked native API access".to_owned(),
        }),
    )?;
    direct.now = UnixMicros::new(220);
    assert_eq!(
        fixture.repository.evaluate_access(direct)?,
        AccessDecision::Denied(AccessDenial::AuthenticationUnavailable)
    );
    Ok(())
}

#[test]
fn browser_session_access_binds_cookie_identity_and_csrf_for_mutations()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = build_fixture(false)?;
    let session_id = SessionId::from_bytes([47; 16])?;
    let user = fixture.user;
    issue_session(&mut fixture, user, session_id, [48; 32])?;
    let session = SessionAccessRequest {
        token_digest: [48; 32],
        required_assurance: AssuranceLevel::SingleFactor,
        gateway_node_id: fixture.gateway,
        gateway_incarnation: 1,
        now: UnixMicros::new(200),
    };
    let read = BrowserSessionAccessRequest {
        expected_session_id: session_id,
        session,
        protection: BrowserSessionProtection::Read,
    };
    assert!(matches!(
        fixture.repository.evaluate_browser_session_access(read)?,
        SessionAccessDecision::Granted(_)
    ));
    let mutation = BrowserSessionAccessRequest {
        protection: BrowserSessionProtection::Mutation {
            csrf_digest: [50; 32],
        },
        ..read
    };
    assert!(matches!(
        fixture
            .repository
            .evaluate_browser_session_access(mutation)?,
        SessionAccessDecision::Granted(_)
    ));
    for rejected in [
        BrowserSessionAccessRequest {
            protection: BrowserSessionProtection::Mutation {
                csrf_digest: [51; 32],
            },
            ..read
        },
        BrowserSessionAccessRequest {
            expected_session_id: SessionId::from_bytes([52; 16])?,
            ..read
        },
    ] {
        assert_eq!(
            fixture
                .repository
                .evaluate_browser_session_access(rejected)?,
            SessionAccessDecision::Denied(SessionAccessDenial::Unavailable)
        );
    }
    Ok(())
}

#[test]
fn every_defined_right_is_independently_granted_and_bound_into_capability_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = build_fixture(false)?;
    let administrator = fixture.administrator;
    let user = fixture.user;
    let volume = fixture.volume;
    let file = fixture.file;
    for index in 0_u8..13 {
        let right = Rights::from_bits(1_u32 << index)?;
        apply(
            &mut fixture,
            administrator,
            130 + i64::from(index),
            AuthoritativeCommand::GrantPermission(GrantPermission {
                grant_id: GrantId::from_bytes([60 + index; 16])?,
                subject_principal_id: user,
                scope: PermissionScope::Object {
                    volume_id: volume,
                    object_id: file,
                },
                rights: right,
                inheritance: GrantInheritance::Object,
                valid_from: None,
                valid_until: Some(UnixMicros::new(700)),
                activation_policy_id: None,
            }),
        )?;
    }
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([73; 16])?,
        [74; 32],
    )?;

    let mut evidence = BTreeSet::new();
    for index in 0_u8..13 {
        let right = Rights::from_bits(1_u32 << index)?;
        let AccessDecision::Granted(capability) = fixture
            .repository
            .evaluate_access(request(&fixture, [74; 32], right, 220))?
        else {
            return Err(format!("defined right bit {index} was unexpectedly denied").into());
        };
        assert_eq!(capability.requested_rights, right);
        assert!(capability.effective_rights.contains(right));
        assert!(evidence.insert(capability.capability_digest));
    }
    let AccessDecision::Granted(all) =
        fixture
            .repository
            .evaluate_access(request(&fixture, [74; 32], Rights::ALL, 220))?
    else {
        return Err("combined complete rights set was unexpectedly denied".into());
    };
    assert_eq!(all.requested_rights, Rights::ALL);
    assert!(all.effective_rights.contains(Rights::ALL));
    assert_eq!(evidence.len(), 13);
    Ok(())
}

#[test]
fn activated_grant_contributes_only_for_its_exact_user_and_lifetime()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = build_fixture(true)?;
    let user = fixture.user;
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([44; 16])?,
        [45; 32],
    )?;
    assert_eq!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [45; 32], Rights::READ_DATA, 200,))?,
        AccessDecision::Denied(AccessDenial::MissingRights)
    );

    let policy_id = ActivationPolicyId::from_bytes([24; 16])?;
    let grant_id = GrantId::from_bytes([25; 16])?;
    apply(
        &mut fixture,
        user,
        210,
        AuthoritativeCommand::ActivateGrant(ActivateGrant {
            activation_id: ActivationId::from_bytes([46; 16])?,
            principal_id: user,
            grant_id,
            policy_id,
            reason: "recover one file".to_owned(),
            duration: DurationMicros::new(300),
            session_expires_at: UnixMicros::new(900),
            assurance: AssuranceLevel::MultiFactor,
            authentication_digest: [45; 32],
        }),
    )?;
    let AccessDecision::Granted(capability) =
        fixture
            .repository
            .evaluate_access(request(&fixture, [45; 32], Rights::READ_DATA, 220))?
    else {
        return Err("activated grant was unexpectedly denied".into());
    };
    assert_eq!(capability.expires_at, UnixMicros::new(510));
    assert_eq!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [45; 32], Rights::READ_DATA, 510,))?,
        AccessDecision::Denied(AccessDenial::MissingRights)
    );
    Ok(())
}

#[test]
fn sessions_are_fenced_by_identity_assurance_gateway_and_object()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = build_fixture(false)?;
    let user = fixture.user;
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([47; 16])?,
        [48; 32],
    )?;
    let mut access = request(&fixture, [48; 32], Rights::READ_DATA, 200);
    access.required_assurance = AssuranceLevel::RecentStepUp;
    assert!(matches!(
        fixture.repository.evaluate_access(access)?,
        AccessDecision::Granted(_)
    ));
    access.required_assurance = AssuranceLevel::SingleFactor;
    access.gateway_incarnation = 2;
    assert_eq!(
        fixture.repository.evaluate_access(access)?,
        AccessDecision::Denied(AccessDenial::GatewayUnavailable)
    );
    access.gateway_incarnation = 1;
    access.object_id = ObjectId::from_bytes([99; 16])?;
    assert_eq!(
        fixture.repository.evaluate_access(access)?,
        AccessDecision::Denied(AccessDenial::ObjectUnavailable)
    );
    let administrator = fixture.administrator;
    apply(
        &mut fixture,
        administrator,
        300,
        AuthoritativeCommand::CreateUser(CreateUser {
            principal_id: PrincipalId::from_bytes([49; 16])?,
            name: RecordName::new("New identity")?,
        }),
    )?;
    access.object_id = fixture.file;
    assert!(matches!(
        fixture.repository.evaluate_access(access)?,
        AccessDecision::Granted(_)
    ));
    Ok(())
}

#[test]
fn folder_boundary_stops_higher_grants_but_keeps_grants_scoped_at_the_folder()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = build_fixture(false)?;
    let administrator = fixture.administrator;
    let user = fixture.user;
    let volume = fixture.volume;
    apply(
        &mut fixture,
        administrator,
        120,
        AuthoritativeCommand::GrantPermission(GrantPermission {
            grant_id: GrantId::from_bytes([50; 16])?,
            subject_principal_id: user,
            scope: PermissionScope::Volume(volume),
            rights: Rights::WRITE_DATA,
            inheritance: GrantInheritance::Descendants,
            valid_from: None,
            valid_until: None,
            activation_policy_id: None,
        }),
    )?;
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([51; 16])?,
        [52; 32],
    )?;
    assert!(matches!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [52; 32], Rights::WRITE_DATA, 200,))?,
        AccessDecision::Granted(_)
    ));

    let folder = fixture.folder;
    apply(
        &mut fixture,
        administrator,
        210,
        AuthoritativeCommand::SetObjectGrantInheritance(SetObjectGrantInheritance {
            object_id: folder,
            stop_parent_grants: true,
        }),
    )?;
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([53; 16])?,
        [54; 32],
    )?;
    assert_eq!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [54; 32], Rights::WRITE_DATA, 220,))?,
        AccessDecision::Denied(AccessDenial::MissingRights)
    );
    assert!(matches!(
        fixture
            .repository
            .evaluate_access(request(&fixture, [54; 32], Rights::READ_DATA, 220,))?,
        AccessDecision::Granted(_)
    ));
    Ok(())
}

pub(super) fn build_fixture(
    activation_required: bool,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    build_fixture_at(std::path::Path::new(":memory:"), activation_required)
}

pub(super) fn build_fixture_at(
    file_path: &std::path::Path,
    activation_required: bool,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let partition = PartitionId::from_bytes([1; 16])?;
    let database = PartitionDatabase::open(file_path, partition, UnixMicros::new(1))?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let user = PrincipalId::from_bytes([3; 16])?;
    let second_user = PrincipalId::from_bytes([4; 16])?;
    let gateway = NodeId::from_bytes([10; 16])?;
    let mut fixture = Fixture {
        repository: AuthoritativeRepository::new(database),
        administrator,
        user,
        second_user,
        gateway,
        volume: VolumeId::from_bytes([20; 16])?,
        folder: ObjectId::from_bytes([21; 16])?,
        file: ObjectId::from_bytes([22; 16])?,
        next_revision: 1,
    };
    bootstrap(&mut fixture, partition)?;
    create_identities(&mut fixture)?;
    create_namespace(&mut fixture)?;
    create_grant(&mut fixture, activation_required)?;
    Ok(fixture)
}

pub(super) fn reopen_fixture(
    fixture: Fixture,
    file_path: &std::path::Path,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let Fixture {
        repository,
        administrator,
        user,
        second_user,
        gateway,
        volume,
        folder,
        file,
        next_revision,
    } = fixture;
    drop(repository.into_database());
    let partition = PartitionId::from_bytes([1; 16])?;
    let database = PartitionDatabase::open(file_path, partition, UnixMicros::new(300))?;
    Ok(Fixture {
        repository: AuthoritativeRepository::new(database),
        administrator,
        user,
        second_user,
        gateway,
        volume,
        folder,
        file,
        next_revision,
    })
}

fn bootstrap(
    fixture: &mut Fixture,
    partition: PartitionId,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        fixture,
        fixture.administrator,
        100,
        protected_bootstrap(BootstrapMesh {
            mesh_id: MeshId::from_bytes([5; 16])?,
            mesh_name: RecordName::new("Access proof")?,
            administrator_id: fixture.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([6; 16])?,
            host_id: HostId::from_bytes([7; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: fixture.gateway,
            node_name: RecordName::new("Gateway")?,
            partition_name: RecordName::new(&partition.to_string())?,
        })?,
    )?;
    mark_test_recovery_verified(
        &mut fixture.repository,
        MeshId::from_bytes([5; 16])?,
        fixture.administrator,
    )
}

fn create_identities(fixture: &mut Fixture) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        fixture,
        fixture.administrator,
        101,
        AuthoritativeCommand::CreateUser(CreateUser {
            principal_id: fixture.user,
            name: RecordName::new("User")?,
        }),
    )?;
    apply(
        fixture,
        fixture.administrator,
        102,
        AuthoritativeCommand::CreateUser(CreateUser {
            principal_id: fixture.second_user,
            name: RecordName::new("Owner")?,
        }),
    )?;
    let inner = GroupId::from_bytes([11; 16])?;
    let outer = GroupId::from_bytes([12; 16])?;
    apply(
        fixture,
        fixture.administrator,
        103,
        AuthoritativeCommand::CreateGroup(CreateGroup {
            group_id: inner,
            name: RecordName::new("Inner")?,
            activation_policy_id: None,
        }),
    )?;
    apply(
        fixture,
        fixture.administrator,
        104,
        AuthoritativeCommand::CreateGroup(CreateGroup {
            group_id: outer,
            name: RecordName::new("Outer")?,
            activation_policy_id: None,
        }),
    )?;
    add_member(fixture, inner, fixture.user, 800, 105)?;
    add_member(fixture, outer, inner.principal_id(), 850, 106)
}

pub(super) fn add_member(
    fixture: &mut Fixture,
    group: GroupId,
    member: PrincipalId,
    valid_until: i64,
    now: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        fixture,
        fixture.administrator,
        now,
        AuthoritativeCommand::AddGroupMember(AddGroupMember {
            containing_group_id: group,
            member_principal_id: member,
            valid_from: None,
            valid_until: Some(UnixMicros::new(valid_until)),
            activation_required: false,
        }),
    )
}

fn create_namespace(fixture: &mut Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let root = ObjectId::from_bytes([23; 16])?;
    apply(
        fixture,
        fixture.administrator,
        107,
        AuthoritativeCommand::CreateVolume(CreateVolume {
            volume_id: fixture.volume,
            name: RecordName::new("Volume")?,
            root_object_id: root,
            owner_set_id: OwnerSetId::from_bytes([30; 16])?,
            owners: owners(fixture.second_user)?,
            key_generation: initial_test_volume_key(fixture.volume)?,
        }),
    )?;
    apply(
        fixture,
        fixture.administrator,
        108,
        AuthoritativeCommand::CreateObject(CreateObject {
            object_id: fixture.folder,
            volume_id: fixture.volume,
            parent_object_id: root,
            kind: NamespaceObjectKind::Folder,
            name: RecordName::new("Folder")?,
            owner_set_id: OwnerSetId::from_bytes([31; 16])?,
            owners: owners(fixture.second_user)?,
        }),
    )?;
    apply(
        fixture,
        fixture.administrator,
        109,
        AuthoritativeCommand::CreateObject(CreateObject {
            object_id: fixture.file,
            volume_id: fixture.volume,
            parent_object_id: fixture.folder,
            kind: NamespaceObjectKind::File,
            name: RecordName::new("File")?,
            owner_set_id: OwnerSetId::from_bytes([32; 16])?,
            owners: owners(fixture.second_user)?,
        }),
    )
}

fn create_grant(
    fixture: &mut Fixture,
    activation_required: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy_id = if activation_required {
        let policy_id = ActivationPolicyId::from_bytes([24; 16])?;
        apply(
            fixture,
            fixture.administrator,
            110,
            AuthoritativeCommand::CreateActivationPolicy(CreateActivationPolicy {
                policy_id,
                maximum_duration: DurationMicros::new(500),
                reason_required: true,
                minimum_assurance: AssuranceLevel::MultiFactor,
                valid_from: None,
                valid_until: Some(UnixMicros::new(650)),
            }),
        )?;
        Some(policy_id)
    } else {
        None
    };
    apply(
        fixture,
        fixture.administrator,
        111,
        AuthoritativeCommand::GrantPermission(GrantPermission {
            grant_id: GrantId::from_bytes([25; 16])?,
            subject_principal_id: GroupId::from_bytes([12; 16])?.principal_id(),
            scope: PermissionScope::Object {
                volume_id: fixture.volume,
                object_id: fixture.folder,
            },
            rights: Rights::READ_DATA.union(Rights::READ_ATTRIBUTES),
            inheritance: GrantInheritance::Descendants,
            valid_from: Some(UnixMicros::new(150)),
            valid_until: Some(UnixMicros::new(700)),
            activation_policy_id: policy_id,
        }),
    )
}

pub(super) fn issue_session(
    fixture: &mut Fixture,
    principal: PrincipalId,
    session_id: SessionId,
    token_digest: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let seed = session_id.as_bytes()[0];
    let api_method_id = AuthenticationMethodId::from_bytes([seed; 16])?;
    let totp_method_id = AuthenticationMethodId::from_bytes([seed.wrapping_add(1); 16])?;
    let api_revision = fixture.next_revision;
    apply(
        fixture,
        principal,
        118,
        AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id: api_method_id,
            principal_id: principal,
            label: "Session API key".to_owned(),
            service_scope: AuthenticationService::Https.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::ApiKey {
                key_id: ApiKeyId::from_bytes([seed.wrapping_add(2); 16])?,
                key_digest: [seed.wrapping_add(3); 32],
                scopes: AuthenticationService::Https.api_key_login_scope(),
                valid_from: UnixMicros::new(100),
            },
        }),
    )?;
    let totp_revision = fixture.next_revision;
    apply(
        fixture,
        principal,
        119,
        AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id: totp_method_id,
            principal_id: principal,
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
    apply(
        fixture,
        principal,
        120,
        AuthoritativeCommand::IssueAuthenticationSession(IssueAuthenticationSession {
            session_id,
            principal_id: principal,
            token_digest,
            csrf_digest: [seed.wrapping_add(3); 32],
            client_label: crate::SessionClientLabel::Missing,
            persistent_cookie: false,
            service: AuthenticationService::Https,
            factors: BoundedItems::new(
                vec![
                    SessionAuthenticationFactor::ApiKey {
                        method_id: api_method_id,
                        credential_generation: 1,
                        method_revision: Revision::new(api_revision),
                        key_id: ApiKeyId::from_bytes([seed.wrapping_add(2); 16])?,
                    },
                    SessionAuthenticationFactor::Totp {
                        method_id: totp_method_id,
                        credential_generation: 1,
                        method_revision: Revision::new(totp_revision),
                        accepted_step: 0,
                    },
                ],
                8,
            )?,
            expires_at: UnixMicros::new(900),
        }),
    )
}

pub(super) fn request(
    fixture: &Fixture,
    token_digest: [u8; 32],
    requested_rights: Rights,
    now: i64,
) -> AccessRequest {
    AccessRequest {
        authentication_service: AuthenticationService::Https,
        credential_digest: token_digest,
        required_assurance: AssuranceLevel::SingleFactor,
        gateway_node_id: fixture.gateway,
        gateway_incarnation: 1,
        volume_id: fixture.volume,
        object_id: fixture.file,
        requested_rights,
        now: UnixMicros::new(now),
    }
}

pub(super) fn apply(
    fixture: &mut Fixture,
    actor: PrincipalId,
    now: i64,
    command: AuthoritativeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let revision = fixture.next_revision;
    let operation_byte = u8::try_from(100 + revision)?;
    fixture.repository.apply_committed(
        LogPosition {
            index: revision,
            term: 1,
        },
        CommandContext {
            operation_id: OperationId::from_bytes([operation_byte; 16])?,
            actor_principal_id: actor,
            audit_event_id: AuditEventId::from_bytes([operation_byte.wrapping_add(80); 16])?,
            occurred_at: UnixMicros::new(now),
            expected_revision: Some(Revision::new(revision - 1)),
        },
        &command,
    )?;
    drop(command);
    fixture.next_revision += 1;
    Ok(())
}

fn owners(principal: PrincipalId) -> Result<BoundedItems<PrincipalId>, Box<dyn std::error::Error>> {
    Ok(BoundedItems::new(vec![principal], 1_024)?)
}
