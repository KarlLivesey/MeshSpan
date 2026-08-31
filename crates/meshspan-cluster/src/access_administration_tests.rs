// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ApiKeyId, AssuranceLevel, AuditEventId, AuthenticationMethodId, AuthenticationService, GrantId,
    HostId, MeshId, NodeId, ObjectId, OperationId, OwnerSetId, PartitionId, PrincipalId, Revision,
    Rights, RoleId, SessionId, UnixMicros, VolumeId,
};
use meshspan_filesystem::FilesystemAccessContext;
use meshspan_metadata::{
    AccessDenial, AuthoritativeCommand, AuthoritativeRepository, BootstrapMesh, CommandContext,
    CreateAuthenticationMethod, CreateUser, CreateVolume, GrantInheritance, GrantPermission,
    IssueAuthenticationSession, LogPosition, NewAuthenticationCredential, PageLimit,
    PartitionDatabase, PermissionScope, RecordName, RevokePermissionGrant, SessionAccessDenial,
    SessionAuthenticationFactor, TotpAlgorithm,
};

use crate::{
    AccessAdministrationAuthority, AccessAdministrationError, MetadataAccessAdministration,
};

#[derive(Clone, Copy)]
struct TestIds {
    partition: PartitionId,
    administrator: PrincipalId,
    user: PrincipalId,
    gateway: NodeId,
    volume: VolumeId,
    root: ObjectId,
    grant: GrantId,
    administrator_token: [u8; 32],
    user_token: [u8; 32],
}

struct Fixture {
    repository: AuthoritativeRepository,
    ids: TestIds,
}

#[test]
fn administration_pages_recheck_object_self_and_system_authority_before_disclosure()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = build_fixture()?;
    assert_authorised_views(&fixture)?;
    assert_authentication_precedes_projection_validation(&fixture)?;
    apply(
        &mut fixture.repository,
        11,
        fixture.ids.administrator,
        &AuthoritativeCommand::RevokePermissionGrant(RevokePermissionGrant {
            grant_id: fixture.ids.grant,
            reason: "No longer required".to_owned(),
        }),
    )?;
    assert_revocation_is_immediate(&fixture)?;
    Ok(())
}

fn build_fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let ids = TestIds {
        partition: PartitionId::from_bytes([1; 16])?,
        administrator: PrincipalId::from_bytes([2; 16])?,
        user: PrincipalId::from_bytes([3; 16])?,
        gateway: NodeId::from_bytes([4; 16])?,
        volume: VolumeId::from_bytes([5; 16])?,
        root: ObjectId::from_bytes([6; 16])?,
        grant: GrantId::from_bytes([7; 16])?,
        administrator_token: [8; 32],
        user_token: [9; 32],
    };
    let database = PartitionDatabase::open(
        std::path::Path::new(":memory:"),
        ids.partition,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    create_identity_and_permissions(&mut repository, ids)?;
    issue_sessions(&mut repository, ids)?;
    Ok(Fixture { repository, ids })
}

fn create_identity_and_permissions(
    repository: &mut AuthoritativeRepository,
    ids: TestIds,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        1,
        ids.administrator,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: MeshId::from_bytes([10; 16])?,
            mesh_name: RecordName::new("Administration proof")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([11; 16])?,
            host_id: HostId::from_bytes([12; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: ids.gateway,
            node_name: RecordName::new("Gateway")?,
            partition_name: RecordName::new(&ids.partition.to_string())?,
        }),
    )?;
    apply(
        repository,
        2,
        ids.administrator,
        &AuthoritativeCommand::CreateUser(CreateUser {
            principal_id: ids.user,
            name: RecordName::new("User")?,
        }),
    )?;
    apply(
        repository,
        3,
        ids.administrator,
        &AuthoritativeCommand::CreateVolume(CreateVolume {
            volume_id: ids.volume,
            name: RecordName::new("Volume")?,
            root_object_id: ids.root,
            owner_set_id: OwnerSetId::from_bytes([13; 16])?,
            owners: BoundedItems::new(vec![ids.administrator], 1_024)?,
        }),
    )?;
    apply(
        repository,
        4,
        ids.administrator,
        &AuthoritativeCommand::GrantPermission(GrantPermission {
            grant_id: ids.grant,
            subject_principal_id: ids.user,
            scope: object_scope(ids),
            rights: Rights::READ_PERMISSIONS,
            inheritance: GrantInheritance::Object,
            valid_from: None,
            valid_until: None,
            activation_policy_id: None,
        }),
    )
}

fn issue_sessions(
    repository: &mut AuthoritativeRepository,
    ids: TestIds,
) -> Result<(), Box<dyn std::error::Error>> {
    let administrator_factors = create_factors(repository, 5, ids.administrator, 40, true)?;
    let user_factors = create_factors(repository, 7, ids.user, 50, false)?;
    apply(
        repository,
        9,
        ids.administrator,
        &AuthoritativeCommand::IssueAuthenticationSession(IssueAuthenticationSession {
            session_id: SessionId::from_bytes([14; 16])?,
            principal_id: ids.administrator,
            token_digest: ids.administrator_token,
            csrf_digest: [24; 32],
            client_label: meshspan_metadata::SessionClientLabel::Missing,
            persistent_cookie: false,
            service: AuthenticationService::Https,
            factors: administrator_factors,
            expires_at: UnixMicros::new(500),
        }),
    )?;
    apply(
        repository,
        10,
        ids.user,
        &AuthoritativeCommand::IssueAuthenticationSession(IssueAuthenticationSession {
            session_id: SessionId::from_bytes([15; 16])?,
            principal_id: ids.user,
            token_digest: ids.user_token,
            csrf_digest: [25; 32],
            client_label: meshspan_metadata::SessionClientLabel::Missing,
            persistent_cookie: false,
            service: AuthenticationService::Https,
            factors: user_factors,
            expires_at: UnixMicros::new(500),
        }),
    )
}

fn create_factors(
    repository: &mut AuthoritativeRepository,
    first_revision: u64,
    principal_id: PrincipalId,
    seed: u8,
    include_totp: bool,
) -> Result<BoundedItems<SessionAuthenticationFactor>, Box<dyn std::error::Error>> {
    let api_method_id = AuthenticationMethodId::from_bytes([seed; 16])?;
    let totp_method_id = AuthenticationMethodId::from_bytes([seed.wrapping_add(1); 16])?;
    let key_id = ApiKeyId::from_bytes([seed.wrapping_add(2); 16])?;
    apply(
        repository,
        first_revision,
        principal_id,
        &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id: api_method_id,
            principal_id,
            label: "API key".to_owned(),
            service_scope: AuthenticationService::Https.scope_bit(),
            expires_at: None,
            credential: NewAuthenticationCredential::ApiKey {
                key_id,
                key_digest: [seed.wrapping_add(3); 32],
                scopes: AuthenticationService::Https.api_key_login_scope(),
                valid_from: UnixMicros::new(100),
            },
        }),
    )?;
    apply(
        repository,
        first_revision + 1,
        principal_id,
        &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
            method_id: totp_method_id,
            principal_id,
            label: "TOTP".to_owned(),
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
    let mut factors = vec![SessionAuthenticationFactor::ApiKey {
        method_id: api_method_id,
        credential_generation: 1,
        method_revision: Revision::new(first_revision),
        key_id,
    }];
    if include_totp {
        factors.push(SessionAuthenticationFactor::Totp {
            method_id: totp_method_id,
            credential_generation: 1,
            method_revision: Revision::new(first_revision + 1),
            accepted_step: 0,
        });
    }
    Ok(BoundedItems::new(factors, 8)?)
}

fn assert_authorised_views(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let ids = fixture.ids;
    let administration = MetadataAccessAdministration::new(&fixture.repository);
    let user_context = context(ids.user_token, ids.gateway, AssuranceLevel::SingleFactor);
    let owners = administration.object_owners(
        user_context,
        ids.volume,
        ids.root,
        None,
        PageLimit::new(10)?,
    )?;
    assert_eq!(owners.items.len(), 1);
    assert!(matches!(
        owners.authority,
        AccessAdministrationAuthority::Object(capability)
            if capability.principal_id == ids.user
                && capability.requested_rights == Rights::READ_PERMISSIONS
    ));
    let grants = administration.permission_grants_for_scope(
        user_context,
        ids.volume,
        ids.root,
        object_scope(ids),
        None,
        PageLimit::new(10)?,
    )?;
    assert_eq!(grants.items.len(), 1);
    assert_eq!(grants.items[0].grant_id, ids.grant);
    assert_self_views(&administration, ids, user_context)?;
    assert_system_manager_view(&administration, ids)?;
    Ok(())
}

fn assert_self_views(
    administration: &MetadataAccessAdministration<'_>,
    ids: TestIds,
    user_context: FilesystemAccessContext,
) -> Result<(), Box<dyn std::error::Error>> {
    let grants = administration.permission_grants_for_subject(
        user_context,
        ids.user,
        None,
        PageLimit::new(10)?,
    )?;
    assert_eq!(grants.items.len(), 1);
    let activations =
        administration.access_activations(user_context, ids.user, None, PageLimit::new(10)?)?;
    assert!(activations.items.is_empty());
    assert!(matches!(
        administration.permission_grants_for_subject(
            user_context,
            ids.administrator,
            None,
            PageLimit::new(10)?,
        ),
        Err(AccessAdministrationError::SubjectForbidden)
    ));
    Ok(())
}

fn assert_system_manager_view(
    administration: &MetadataAccessAdministration<'_>,
    ids: TestIds,
) -> Result<(), Box<dyn std::error::Error>> {
    let context = context(
        ids.administrator_token,
        ids.gateway,
        AssuranceLevel::RecentStepUp,
    );
    let managed = administration.permission_grants_for_subject(
        context,
        ids.user,
        None,
        PageLimit::new(10)?,
    )?;
    assert!(matches!(
        managed.authority,
        AccessAdministrationAuthority::Session(capability)
            if capability.principal_id == ids.administrator && capability.is_system_manager()
    ));
    Ok(())
}

fn assert_authentication_precedes_projection_validation(
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let ids = fixture.ids;
    let administration = MetadataAccessAdministration::new(&fixture.repository);
    assert!(matches!(
        administration.permission_grants_for_scope(
            context([0; 32], ids.gateway, AssuranceLevel::SingleFactor),
            ids.volume,
            ids.root,
            PermissionScope::Volume(VolumeId::from_bytes([99; 16])?),
            None,
            PageLimit::new(10)?,
        ),
        Err(AccessAdministrationError::ObjectDenied(
            AccessDenial::AuthenticationUnavailable
        ))
    ));
    assert!(matches!(
        administration.permission_grants_for_subject(
            context(ids.user_token, ids.gateway, AssuranceLevel::RecentStepUp,),
            ids.user,
            None,
            PageLimit::new(10)?,
        ),
        Err(AccessAdministrationError::SessionDenied(
            SessionAccessDenial::InsufficientAssurance
        ))
    ));
    let mut wrong_incarnation = context(ids.user_token, ids.gateway, AssuranceLevel::SingleFactor);
    wrong_incarnation.gateway_incarnation = 2;
    assert!(matches!(
        administration.access_activations(wrong_incarnation, ids.user, None, PageLimit::new(10)?,),
        Err(AccessAdministrationError::SessionDenied(
            SessionAccessDenial::Unavailable
        ))
    ));
    assert!(matches!(
        administration.permission_grants_for_scope(
            context(ids.user_token, ids.gateway, AssuranceLevel::SingleFactor,),
            ids.volume,
            ids.root,
            PermissionScope::Volume(VolumeId::from_bytes([99; 16])?),
            None,
            PageLimit::new(10)?,
        ),
        Err(AccessAdministrationError::ScopeMismatch)
    ));
    Ok(())
}

fn assert_revocation_is_immediate(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let ids = fixture.ids;
    let administration = MetadataAccessAdministration::new(&fixture.repository);
    let stale = context(ids.user_token, ids.gateway, AssuranceLevel::SingleFactor);
    assert!(matches!(
        administration.object_owners(stale, ids.volume, ids.root, None, PageLimit::new(10)?,),
        Err(AccessAdministrationError::ObjectDenied(
            AccessDenial::StaleIdentity
        ))
    ));
    assert!(matches!(
        administration.permission_grants_for_subject(
            context([0; 32], ids.gateway, AssuranceLevel::SingleFactor),
            ids.user,
            None,
            PageLimit::new(10)?,
        ),
        Err(AccessAdministrationError::SessionDenied(
            SessionAccessDenial::Unavailable
        ))
    ));
    Ok(())
}

fn object_scope(ids: TestIds) -> PermissionScope {
    PermissionScope::Object {
        volume_id: ids.volume,
        object_id: ids.root,
    }
}

fn context(
    token_digest: [u8; 32],
    gateway_node_id: NodeId,
    required_assurance: AssuranceLevel,
) -> FilesystemAccessContext {
    FilesystemAccessContext {
        authentication_service: AuthenticationService::Https,
        credential_digest: token_digest,
        required_assurance,
        gateway_node_id,
        gateway_incarnation: 1,
        now: UnixMicros::new(200),
    }
}

fn apply(
    repository: &mut AuthoritativeRepository,
    revision: u64,
    actor_principal_id: PrincipalId,
    command: &AuthoritativeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let operation = u8::try_from(revision)?;
    let audit = u8::try_from(revision + 30)?;
    repository.apply_committed(
        LogPosition {
            index: revision,
            term: 1,
        },
        CommandContext {
            operation_id: OperationId::from_bytes([operation; 16])?,
            actor_principal_id,
            audit_event_id: AuditEventId::from_bytes([audit; 16])?,
            occurred_at: UnixMicros::new(i64::try_from(revision + 100)?),
            expected_revision: Some(Revision::new(revision - 1)),
        },
        command,
    )?;
    Ok(())
}
