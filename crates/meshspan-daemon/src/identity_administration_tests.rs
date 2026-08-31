// SPDX-License-Identifier: GPL-2.0-only

use axum::body::{Body, to_bytes};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use meshspan_api_contract::{
    CreatePrincipalResponse, ListPrincipalsResponse, decode_create_api_key_request,
    decode_create_session_request,
};
use meshspan_domain::{
    ApiKeyId, ApiKeyIssuanceKey, AssuranceLevel, AuthenticationService, ClaimBundle,
    DurationMicros, InitialBootstrapMaterial, OperationId, PrincipalId, UnixMicros,
};
use meshspan_metadata::{
    ApiKeyAuthentication, AuthoritativeCommand, CommandContext, EntityKind, LogPosition, Page,
    PageLimit, PartitionDatabase, PrincipalCursor, PrincipalKind, PrincipalRecord, RepositoryError,
};
use tempfile::tempdir;
use tower::ServiceExt;

use crate::api_http::current_time;
use crate::browser_session::CSRF_HEADER;
use crate::create_session_tests::{RepositorySessionAuthority, bootstrap};
use crate::passkey_test_support::CountingRandom;
use crate::{
    ApiKeyIssuanceService, CreateSessionService, GatewaySessionIdentity,
    IdentityAdministrationAuthority, IdentityAdministrationAuthorityError,
    IdentityAdministrationCommit, IdentityAdministrationService, NativeApiKeyAuthority,
    NativeApiKeyAuthorityError, identity_administration_api_router,
};

#[tokio::test]
async fn manager_http_creates_replays_and_pages_real_committed_identities()
-> Result<(), Box<dyn std::error::Error>> {
    let (authority, material, session, headless_key) = fixture()?;
    let router = identity_administration_api_router(IdentityAdministrationService::new(
        authority,
        GatewaySessionIdentity::new(material.node_id, 1)?,
    ))?;
    let first_request = creation_request(
        "/api/latest/admin/users",
        "00000000-0000-4000-8000-000000000041",
        "Alex",
        &session,
    )?;
    let first = router.clone().oneshot(first_request).await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_body = to_bytes(first.into_body(), 8_192).await?;
    let first_response: CreatePrincipalResponse = serde_json::from_slice(&first_body)?;
    assert_eq!(first_response.principal.display_name, "Alex");

    let replay = router
        .clone()
        .oneshot(creation_request(
            "/api/latest/admin/users",
            "00000000-0000-4000-8000-000000000041",
            "Alex",
            &session,
        )?)
        .await?;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(to_bytes(replay.into_body(), 8_192).await?, first_body);

    let changed = router
        .clone()
        .oneshot(creation_request(
            "/api/latest/admin/users",
            "00000000-0000-4000-8000-000000000041",
            "Changed",
            &session,
        )?)
        .await?;
    assert_eq!(changed.status(), StatusCode::CONFLICT);

    for (operation, name) in [
        ("00000000-0000-4000-8000-000000000042", "Beta"),
        ("00000000-0000-4000-8000-000000000043", "Operators"),
    ] {
        let endpoint = if name == "Operators" {
            "/api/latest/admin/groups"
        } else {
            "/api/latest/admin/users"
        };
        let response = router
            .clone()
            .oneshot(creation_request(endpoint, operation, name, &session)?)
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let first_page = router
        .clone()
        .oneshot(read_request("/api/latest/admin/users?limit=1", &session)?)
        .await?;
    assert_eq!(first_page.status(), StatusCode::OK);
    let page: ListPrincipalsResponse =
        serde_json::from_slice(&to_bytes(first_page.into_body(), 16_384).await?)?;
    assert_eq!(page.principals.len(), 1);
    let next = page.next_page_url.ok_or("expected next user page")?;
    let second_page = router
        .clone()
        .oneshot(read_request(&next, &session)?)
        .await?;
    assert_eq!(second_page.status(), StatusCode::OK);
    let page: ListPrincipalsResponse =
        serde_json::from_slice(&to_bytes(second_page.into_body(), 16_384).await?)?;
    assert_eq!(page.principals.len(), 1);
    assert!(page.next_page_url.is_some());

    let headless = router
        .clone()
        .oneshot(headless_creation_request(
            "/api/latest/admin/groups",
            "00000000-0000-4000-8000-000000000044",
            "Headless operators",
            &headless_key,
        )?)
        .await?;
    assert_eq!(headless.status(), StatusCode::CREATED);

    let mut ambiguous = headless_creation_request(
        "/api/latest/admin/users",
        "00000000-0000-4000-8000-000000000045",
        "Ambiguous",
        &headless_key,
    )?;
    add_session_headers(ambiguous.headers_mut(), &session, true)?;
    assert_eq!(
        router.clone().oneshot(ambiguous).await?.status(),
        StatusCode::UNAUTHORIZED
    );

    let unauthenticated = Request::post("/api/latest/admin/users")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(vec![b'x'; 2_049]))?;
    let response = router.oneshot(unauthenticated).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

impl IdentityAdministrationAuthority for RepositorySessionAuthority {
    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, IdentityAdministrationAuthorityError> {
        self.repository
            .principal_is_system_manager(principal_id, now)
            .map_err(|error| map_repository_error(&error))
    }

    fn principals(
        &self,
        kind: PrincipalKind,
        after: Option<&PrincipalCursor>,
        limit: PageLimit,
    ) -> Result<Page<PrincipalRecord, PrincipalCursor>, IdentityAdministrationAuthorityError> {
        self.repository
            .principals(kind, after, limit)
            .map_err(|error| map_repository_error(&error))
    }

    fn principal(
        &self,
        principal_id: PrincipalId,
    ) -> Result<Option<PrincipalRecord>, IdentityAdministrationAuthorityError> {
        self.repository
            .principal(principal_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn resolve_principal_creation(
        &self,
        operation_id: OperationId,
        kind: PrincipalKind,
    ) -> Result<Option<IdentityAdministrationCommit>, IdentityAdministrationAuthorityError> {
        self.repository
            .resolve_operation(operation_id)
            .map_err(|error| map_repository_error(&error))?
            .map(|receipt| {
                let principal_id = PrincipalId::from_bytes(receipt.entity.id)
                    .map_err(|_| IdentityAdministrationAuthorityError::Failed)?;
                let record = self
                    .repository
                    .principal(principal_id)
                    .map_err(|error| map_repository_error(&error))?
                    .ok_or(IdentityAdministrationAuthorityError::Failed)?;
                commit(receipt, kind, record.created_at)
            })
            .transpose()
    }

    fn commit_or_resolve_principal_creation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
        kind: PrincipalKind,
    ) -> Result<IdentityAdministrationCommit, IdentityAdministrationAuthorityError> {
        let expected_digest = command.request_digest(context);
        if let Some(commit) = self.resolve_principal_creation(context.operation_id, kind)? {
            if commit.request_digest != expected_digest {
                return Err(IdentityAdministrationAuthorityError::Conflict);
            }
            return Ok(commit);
        }
        self.repository
            .apply_committed(
                LogPosition {
                    index: self.next_index,
                    term: 1,
                },
                context,
                command,
            )
            .map_err(|error| map_repository_error(&error))?;
        self.next_index = self.next_index.saturating_add(1);
        self.resolve_principal_creation(context.operation_id, kind)?
            .ok_or(IdentityAdministrationAuthorityError::Failed)
    }
}

impl NativeApiKeyAuthority for RepositorySessionAuthority {
    fn authenticate_native_api_key(
        &self,
        key_id: ApiKeyId,
        digest: [u8; 32],
        required_assurance: AssuranceLevel,
        now: UnixMicros,
    ) -> Result<Option<ApiKeyAuthentication>, NativeApiKeyAuthorityError> {
        self.repository
            .authenticate_api_key_for_operation(
                digest,
                AuthenticationService::HeadlessApi,
                AuthenticationService::HeadlessApi.api_key_login_scope(),
                required_assurance,
                now,
            )
            .map(|authentication| authentication.filter(|value| value.key_id == key_id))
            .map_err(|error| match map_repository_error(&error) {
                IdentityAdministrationAuthorityError::Unavailable => {
                    NativeApiKeyAuthorityError::Unavailable
                }
                IdentityAdministrationAuthorityError::Conflict
                | IdentityAdministrationAuthorityError::Failed => {
                    NativeApiKeyAuthorityError::Failed
                }
            })
    }
}

fn commit(
    receipt: meshspan_metadata::CommandReceipt,
    kind: PrincipalKind,
    occurred_at: UnixMicros,
) -> Result<IdentityAdministrationCommit, IdentityAdministrationAuthorityError> {
    let expected = match kind {
        PrincipalKind::User => EntityKind::User,
        PrincipalKind::Group => EntityKind::Group,
        PrincipalKind::Service => return Err(IdentityAdministrationAuthorityError::Failed),
    };
    if receipt.entity.kind != expected {
        return Err(IdentityAdministrationAuthorityError::Failed);
    }
    Ok(IdentityAdministrationCommit {
        request_digest: receipt.request_digest,
        result_digest: receipt.result_digest,
        principal_id: PrincipalId::from_bytes(receipt.entity.id)
            .map_err(|_| IdentityAdministrationAuthorityError::Failed)?,
        committed_revision: receipt.committed_revision.get(),
        occurred_at,
    })
}

fn map_repository_error(error: &RepositoryError) -> IdentityAdministrationAuthorityError {
    match error {
        RepositoryError::OperationConflict
        | RepositoryError::InvalidCommand
        | RepositoryError::Sqlite(_) => IdentityAdministrationAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Io(_) => {
            IdentityAdministrationAuthorityError::Unavailable
        }
        _ => IdentityAdministrationAuthorityError::Failed,
    }
}

fn fixture() -> Result<
    (
        RepositorySessionAuthority,
        InitialBootstrapMaterial,
        crate::CreateSessionResult,
        String,
    ),
    Box<dyn std::error::Error>,
> {
    let claim = ClaimBundle::generate(&mut CountingRandom::default())?;
    let bootstrap_operation = OperationId::from_bytes([8; 16])?;
    let material = InitialBootstrapMaterial::derive(&claim, bootstrap_operation)?;
    let directory = tempdir()?;
    let database = PartitionDatabase::open(
        &directory.path().join("root.sqlite3"),
        material.partition_id,
        UnixMicros::new(1),
    )?;
    let mut authority = RepositorySessionAuthority {
        repository: meshspan_metadata::AuthoritativeRepository::new(database),
        next_index: 1,
    };
    bootstrap(&mut authority, &material, bootstrap_operation)?;
    let request = decode_create_session_request(&serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000040",
        "authentication": {
            "method": "api_key",
            "secret": material.api_key.expose_encoded().as_str()
        },
        "client_label": null,
        "remember": false
    }))?)?;
    let now = current_time().ok_or("wall clock is unavailable")?;
    let mut sessions = CreateSessionService::new(authority);
    let session = sessions.create(&request, now)?;
    let mut issuance_headers = HeaderMap::new();
    add_session_headers(&mut issuance_headers, &session, true)?;
    let authority = sessions.into_authority();
    let gateway = GatewaySessionIdentity::new(material.node_id, 1)?;
    let mut issuance_service =
        ApiKeyIssuanceService::new(authority, ApiKeyIssuanceKey::from_bytes([91; 32])?, gateway);
    let issuance = decode_create_api_key_request(&serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000046",
        "label": "Headless administration proof",
        "scopes": ["headless_api"],
        "expires_at_epoch_micros": null
    }))?)?;
    let issued_key = issuance_service.issue(
        &issuance,
        &issuance_headers,
        now.checked_add(DurationMicros::new(1))
            .ok_or("test clock overflow")?,
    )?;
    Ok((
        issuance_service.into_authority(),
        material,
        session,
        issued_key.secret,
    ))
}

fn creation_request(
    endpoint: &str,
    operation_id: &str,
    display_name: &str,
    session: &crate::CreateSessionResult,
) -> Result<Request<Body>, Box<dyn std::error::Error>> {
    let mut request = Request::post(endpoint)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({
            "operation_id": operation_id,
            "display_name": display_name
        }))?))?;
    add_session_headers(request.headers_mut(), session, true)?;
    Ok(request)
}

fn read_request(
    endpoint: &str,
    session: &crate::CreateSessionResult,
) -> Result<Request<Body>, Box<dyn std::error::Error>> {
    let mut request = Request::get(endpoint).body(Body::empty())?;
    add_session_headers(request.headers_mut(), session, false)?;
    Ok(request)
}

fn headless_creation_request(
    endpoint: &str,
    operation_id: &str,
    display_name: &str,
    key: &str,
) -> Result<Request<Body>, Box<dyn std::error::Error>> {
    Ok(Request::post(endpoint)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {key}"))
        .body(Body::from(serde_json::to_vec(&serde_json::json!({
            "operation_id": operation_id,
            "display_name": display_name
        }))?))?)
}

fn add_session_headers(
    headers: &mut HeaderMap,
    session: &crate::CreateSessionResult,
    mutation: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&format!(
            "meshspan_session={}",
            session.bearer.expose_encoded().as_str()
        ))?,
    );
    if mutation {
        headers.insert(
            CSRF_HEADER,
            HeaderValue::from_str(session.csrf.expose_encoded().as_str())?,
        );
    }
    Ok(())
}
