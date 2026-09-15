// SPDX-License-Identifier: GPL-2.0-only

//! File-backed enrollment followed by the ordinary independent session workflow.

use super::{UserEnrollmentAuthority, UserEnrollmentError, UserEnrollmentService};
use crate::create_session_tests::{RepositorySessionAuthority, bootstrap};
use crate::passkey_test_support::CountingRandom;
use crate::{
    BrowserRequestProtection, BrowserSessionAuthenticator, CreateSessionResult,
    CreateSessionService, GatewaySessionIdentity, IdentityAdministrationController,
    IdentityAdministrationService, IdentityAdministrator,
};
use axum::http::{HeaderMap, HeaderValue, header::COOKIE};
use meshspan_api_contract::{
    CreateSessionRequest, IssueUserEnrollmentRequest, RedeemUserEnrollmentApiKeyRequest,
    decode_create_session_request, decode_create_user_request,
    decode_issue_user_enrollment_request, decode_redeem_user_enrollment_api_key_request,
    decode_revoke_user_enrollment_request,
};
use meshspan_domain::{
    ApiKeyIssuanceKey, AssuranceLevel, ClaimBundle, InitialBootstrapMaterial, OperationId,
    PrincipalId, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, LogPosition, PartitionDatabase,
    PrincipalRecord, RepositoryError, UserEnrollmentRecord,
};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn enrollment_creates_independent_sign_in_and_recovers_only_exact_live_response() -> TestResult {
    let mut fixture = fixture()?;
    let key = ApiKeyIssuanceKey::from_bytes([21; 32])?;
    let issue_request = issue_request(fixture.recipient_revision)?;
    let invitation = fixture.service.issue(
        fixture.administrator,
        &fixture.recipient,
        &issue_request,
        &key,
    )?;
    let request = redeem_request(&invitation.token)?;
    let first = fixture
        .service
        .redeem_api_key(&request, &key, UnixMicros::new(30))?;
    let replay = fixture
        .service
        .redeem_api_key(&request, &key, UnixMicros::new(31))?;
    assert!(first == replay);
    let mut changed = redeem_request(&invitation.token)?;
    changed.label = serde_json::from_value(serde_json::json!("Changed"))?;
    assert!(matches!(
        fixture
            .service
            .redeem_api_key(&changed, &key, UnixMicros::new(32)),
        Err(UserEnrollmentError::Conflict)
    ));
    let mut second = redeem_request(&invitation.token)?;
    second.operation_id =
        meshspan_api_contract::OperationId::parse("00000000-0000-4000-8000-000000000099")
            .ok_or("operation")?;
    assert!(matches!(
        fixture
            .service
            .redeem_api_key(&second, &key, UnixMicros::new(33)),
        Err(UserEnrollmentError::Rejected)
    ));
    assert!(matches!(
        fixture
            .service
            .redeem_api_key(&request, &key, UnixMicros::new(100)),
        Err(UserEnrollmentError::Rejected)
    ));
    let mut login = CreateSessionService::new(fixture.service.into_authority());
    let session = login.create(&login_request(&first.secret)?, UnixMicros::new(40))?;
    let authority = login.into_authority();
    let capability = BrowserSessionAuthenticator::new(&authority, fixture.gateway).authenticate(
        &headers(&session)?,
        BrowserRequestProtection::Read,
        AssuranceLevel::SingleFactor,
        UnixMicros::new(41),
    )?;
    assert_eq!(
        meshspan_api_contract::PrincipalId::from_uuid_bytes(capability.principal_id.as_bytes())
            .ok_or("principal")?,
        fixture.recipient
    );
    assert_ne!(capability.principal_id, fixture.administrator.principal_id);
    assert!(!capability.is_system_manager());
    Ok(())
}

#[test]
fn revoked_invitation_stops_secret_recovery_without_revoking_created_key() -> TestResult {
    let mut fixture = fixture()?;
    let key = ApiKeyIssuanceKey::from_bytes([21; 32])?;
    let invitation = fixture.service.issue(
        fixture.administrator,
        &fixture.recipient,
        &issue_request(fixture.recipient_revision)?,
        &key,
    )?;
    let request = redeem_request(&invitation.token)?;
    let key_response = fixture
        .service
        .redeem_api_key(&request, &key, UnixMicros::new(30))?;
    let current = fixture
        .service
        .authority
        .enrollment(OperationId::from_bytes(
            crate::create_mesh_setup::parse_uuid(invitation.operation_id.as_str())?,
        )?)?
        .ok_or("invitation")?;
    let revoke = decode_revoke_user_enrollment_request(&serde_json::to_vec(
        &serde_json::json!({ "operation_id": "00000000-0000-4000-8000-000000000060", "expected_revision": current.revision.get() }),
    )?)?;
    fixture.service.revoke(
        IdentityAdministrator {
            now: UnixMicros::new(31),
            ..fixture.administrator
        },
        &invitation.operation_id,
        &revoke,
    )?;
    assert!(matches!(
        fixture
            .service
            .redeem_api_key(&request, &key, UnixMicros::new(32)),
        Err(UserEnrollmentError::Rejected)
    ));
    assert!(matches!(
        fixture.service.issue(
            fixture.administrator,
            &fixture.recipient,
            &issue_request(fixture.recipient_revision)?,
            &key
        ),
        Err(UserEnrollmentError::Rejected)
    ));
    let mut login = CreateSessionService::new(fixture.service.into_authority());
    assert!(
        login
            .create(&login_request(&key_response.secret)?, UnixMicros::new(40))
            .is_ok()
    );
    Ok(())
}

struct Fixture {
    _directory: TempDir,
    service: UserEnrollmentService<RepositorySessionAuthority>,
    administrator: IdentityAdministrator,
    recipient: meshspan_api_contract::PrincipalId,
    recipient_revision: u64,
    gateway: GatewaySessionIdentity,
}
fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let operation = OperationId::from_bytes([8; 16])?;
    let claim = ClaimBundle::generate(&mut CountingRandom::default())?;
    let material = InitialBootstrapMaterial::derive(
        &claim,
        operation,
        InitialBootstrapMaterial::node_id([99; 32])?,
    )?;
    let database = PartitionDatabase::open(
        &directory.path().join("root.sqlite3"),
        material.partition_id,
        UnixMicros::new(1),
    )?;
    let mut authority = RepositorySessionAuthority {
        repository: meshspan_metadata::AuthoritativeRepository::new(database),
        next_index: 1,
    };
    bootstrap(&mut authority, &material, operation)?;
    let administrator = IdentityAdministrator {
        principal_id: material.administrator_id,
        now: UnixMicros::new(20),
    };
    let gateway = GatewaySessionIdentity::new(material.node_id, 1)?;
    let mut identities = IdentityAdministrationService::new(authority, gateway);
    let user = identities.create_user(administrator, decode_create_user_request(&serde_json::to_vec(&serde_json::json!({"operation_id": "00000000-0000-4000-8000-000000000010", "display_name": "Second user"}))?)?)?;
    Ok(Fixture {
        _directory: directory,
        service: UserEnrollmentService::new(identities.into_authority(), gateway),
        administrator,
        recipient: user.principal.principal_id,
        recipient_revision: user.principal.revision,
        gateway,
    })
}
fn issue_request(revision: u64) -> Result<IssueUserEnrollmentRequest, Box<dyn std::error::Error>> {
    Ok(decode_issue_user_enrollment_request(&serde_json::to_vec(
        &serde_json::json!({"operation_id": "00000000-0000-4000-8000-000000000020", "expected_principal_revision": revision, "expires_at_epoch_micros": 100}),
    )?)?)
}
fn redeem_request(
    token: &str,
) -> Result<RedeemUserEnrollmentApiKeyRequest, Box<dyn std::error::Error>> {
    Ok(decode_redeem_user_enrollment_api_key_request(
        &serde_json::to_vec(
            &serde_json::json!({"operation_id": "00000000-0000-4000-8000-000000000030", "token": token, "label": "First credential", "scopes": ["https_session", "headless_api"], "expires_at_epoch_micros": null}),
        )?,
    )?)
}
fn login_request(secret: &str) -> Result<CreateSessionRequest, Box<dyn std::error::Error>> {
    Ok(decode_create_session_request(&serde_json::to_vec(
        &serde_json::json!({"operation_id": "00000000-0000-4000-8000-000000000040", "authentication": {"method": "api_key", "secret": secret}, "client_label": null, "remember": false}),
    )?)?)
}
fn headers(session: &CreateSessionResult) -> Result<HeaderMap, Box<dyn std::error::Error>> {
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&format!(
            "meshspan_session={}",
            session.bearer.expose_encoded().as_str()
        ))?,
    );
    headers.insert(
        crate::browser_session::CSRF_HEADER,
        HeaderValue::from_str(session.csrf.expose_encoded().as_str())?,
    );
    Ok(headers)
}

impl UserEnrollmentAuthority for RepositorySessionAuthority {
    fn refresh_enrollment_authority(
        &self,
        requested_at: UnixMicros,
    ) -> Result<UnixMicros, UserEnrollmentError> {
        Ok(requested_at)
    }
    fn enrollment(
        &self,
        operation: OperationId,
    ) -> Result<Option<UserEnrollmentRecord>, UserEnrollmentError> {
        self.repository
            .user_enrollment(operation)
            .map_err(|error| repository_error(&error))
    }
    fn enrollment_principal(
        &self,
        principal: PrincipalId,
    ) -> Result<Option<PrincipalRecord>, UserEnrollmentError> {
        self.repository
            .principal(principal)
            .map_err(|error| repository_error(&error))
    }
    fn enrollment_manager(
        &self,
        principal: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, UserEnrollmentError> {
        self.repository
            .principal_is_system_manager(principal, now)
            .map_err(|error| repository_error(&error))
    }
    fn enrollment_operation_time(
        &self,
        operation: OperationId,
    ) -> Result<Option<UnixMicros>, UserEnrollmentError> {
        self.repository
            .operation_status(operation)
            .map(|status| status.map(|value| value.started_at))
            .map_err(|error| repository_error(&error))
    }
    fn commit_enrollment(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, UserEnrollmentError> {
        let result = self
            .repository
            .apply_committed(
                LogPosition {
                    index: self.next_index,
                    term: 1,
                },
                context,
                command,
            )
            .map_err(|error| repository_error(&error))?;
        self.next_index += 1;
        Ok(result)
    }
}
fn repository_error(error: &RepositoryError) -> UserEnrollmentError {
    match error {
        RepositoryError::InvalidCommand => UserEnrollmentError::Rejected,
        RepositoryError::OperationConflict => UserEnrollmentError::Conflict,
        _ => UserEnrollmentError::Failed,
    }
}

#[test]
fn isolated_authority_cannot_replay_secret_from_cached_consent() -> TestResult {
    let mut fixture = fixture()?;
    let key = ApiKeyIssuanceKey::from_bytes([21; 32])?;
    let invitation = fixture.service.issue(
        fixture.administrator,
        &fixture.recipient,
        &issue_request(fixture.recipient_revision)?,
        &key,
    )?;
    let request = redeem_request(&invitation.token)?;
    fixture
        .service
        .redeem_api_key(&request, &key, UnixMicros::new(30))?;
    let authority = FreshnessFault {
        inner: fixture.service.into_authority(),
        reads: std::cell::Cell::new(0),
        expires_after_read: false,
    };
    let mut service = UserEnrollmentService::new(authority, fixture.gateway);
    assert!(matches!(
        service.redeem_api_key(&request, &key, UnixMicros::new(31)),
        Err(UserEnrollmentError::Unavailable)
    ));
    Ok(())
}

#[test]
fn expiration_during_commit_never_releases_the_committed_secret() -> TestResult {
    let mut fixture = fixture()?;
    let key = ApiKeyIssuanceKey::from_bytes([21; 32])?;
    let invitation = fixture.service.issue(
        fixture.administrator,
        &fixture.recipient,
        &issue_request(fixture.recipient_revision)?,
        &key,
    )?;
    let request = redeem_request(&invitation.token)?;
    let authority = FreshnessFault {
        inner: fixture.service.into_authority(),
        reads: std::cell::Cell::new(0),
        expires_after_read: true,
    };
    let mut service = UserEnrollmentService::new(authority, fixture.gateway);
    assert!(matches!(
        service.redeem_api_key(&request, &key, UnixMicros::new(30)),
        Err(UserEnrollmentError::Rejected)
    ));
    let invitation_id = OperationId::from_bytes(crate::create_mesh_setup::parse_uuid(
        invitation.operation_id.as_str(),
    )?)?;
    assert!(matches!(
        service
            .authority
            .enrollment(invitation_id)?
            .ok_or("invitation")?
            .state,
        meshspan_metadata::UserEnrollmentState::Redeemed(_)
    ));
    Ok(())
}

struct FreshnessFault {
    inner: RepositorySessionAuthority,
    reads: std::cell::Cell<u8>,
    expires_after_read: bool,
}
impl crate::BrowserSessionAuthority for FreshnessFault {
    fn evaluate_browser_session(
        &self,
        request: meshspan_metadata::BrowserSessionAccessRequest,
    ) -> Result<meshspan_metadata::SessionAccessDecision, crate::BrowserSessionAuthorityError> {
        self.inner.evaluate_browser_session(request)
    }
}
impl UserEnrollmentAuthority for FreshnessFault {
    fn refresh_enrollment_authority(
        &self,
        requested_at: UnixMicros,
    ) -> Result<UnixMicros, UserEnrollmentError> {
        if !self.expires_after_read {
            return Err(UserEnrollmentError::Unavailable);
        }
        let reads = self.reads.get();
        self.reads.set(reads + 1);
        Ok(if reads == 0 {
            requested_at
        } else {
            UnixMicros::new(100)
        })
    }
    fn enrollment(
        &self,
        operation: OperationId,
    ) -> Result<Option<UserEnrollmentRecord>, UserEnrollmentError> {
        self.inner.enrollment(operation)
    }
    fn enrollment_principal(
        &self,
        principal: PrincipalId,
    ) -> Result<Option<PrincipalRecord>, UserEnrollmentError> {
        self.inner.enrollment_principal(principal)
    }
    fn enrollment_manager(
        &self,
        principal: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, UserEnrollmentError> {
        self.inner.enrollment_manager(principal, now)
    }
    fn enrollment_operation_time(
        &self,
        operation: OperationId,
    ) -> Result<Option<UnixMicros>, UserEnrollmentError> {
        self.inner.enrollment_operation_time(operation)
    }
    fn commit_enrollment(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, UserEnrollmentError> {
        self.inner.commit_enrollment(context, command)
    }
}
