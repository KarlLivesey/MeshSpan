// SPDX-License-Identifier: GPL-2.0-only

use axum::body::{Body, to_bytes};
use axum::http::header::COOKIE;
use axum::http::{HeaderValue, Request, StatusCode};
use meshspan_api_contract::{
    CreateSessionRequest, RevokeCurrentSessionResponse, decode_create_session_request,
};
use meshspan_domain::{
    AuthenticationOperationClass, AuthenticationService, ClaimBundle, EntropyError,
    InitialBootstrapMaterial, OperationId, RandomSource, Revision, UnixMicros,
};
use meshspan_metadata::{
    ApiKeyAuthentication, ApiKeySessionReplay, AuthenticationPolicy, AuthoritativeCommand,
    AuthoritativeRepository, BootstrapAppliance, BootstrapMesh, BrowserSessionAccessRequest,
    CommandContext, CreateAuthenticationMethod, LogPosition, NewAuthenticationCredential,
    PartitionDatabase, RecordName, RepositoryError, SessionAccessDecision, SessionRevocationReplay,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use tower::ServiceExt;

use crate::{
    BrowserSessionAuthority, BrowserSessionAuthorityError, CreateSessionError,
    CreateSessionService, GatewaySessionIdentity, RevokeCurrentSessionService, SessionAuthority,
    SessionAuthorityError, SessionCommit, SessionRevocationAuthority,
    SessionRevocationAuthorityError, SessionRevocationCommit, revoke_current_session_api_router,
    session_api_router,
};

const OPERATION_TEXT: &str = "00000000-0000-4000-8000-000000000011";
const REVOCATION_OPERATION_TEXT: &str = "00000000-0000-4000-8000-000000000012";

#[test]
fn api_key_session_commits_exact_delivery_intent_and_changed_retry_conflicts()
-> Result<(), Box<dyn std::error::Error>> {
    let claim = ClaimBundle::generate(&mut SequentialRandom(1))?;
    let bootstrap_operation = OperationId::from_bytes([8; 16])?;
    let material = InitialBootstrapMaterial::derive(&claim, bootstrap_operation)?;
    let directory = tempdir()?;
    let database = PartitionDatabase::open(
        &directory.path().join("root.sqlite3"),
        material.partition_id,
        UnixMicros::new(1),
    )?;
    let mut authority = RepositorySessionAuthority {
        repository: AuthoritativeRepository::new(database),
        next_index: 1,
    };
    bootstrap(&mut authority, &material, bootstrap_operation)?;
    let api_key = material.api_key.expose_encoded();
    let session_request = request(&api_key, false)?;
    let mut service = CreateSessionService::new(authority);
    let first = service.create(&session_request, UnixMicros::new(20))?;
    let retry = service.create(&session_request, UnixMicros::new(20))?;
    assert_eq!(first.response.session_id, retry.response.session_id);
    assert_eq!(first.response.expires_at_epoch_micros, 43_200_000_020);
    assert_eq!(first.bearer.expose_encoded(), retry.bearer.expose_encoded());
    assert_eq!(first.csrf.expose_encoded(), retry.csrf.expose_encoded());
    assert_ne!(first.bearer.token_digest(), first.csrf.token_digest());

    let changed = request(&api_key, true)?;
    assert!(matches!(
        service.create(&changed, UnixMicros::new(20)),
        Err(CreateSessionError::Authority(
            SessionAuthorityError::Conflict
        ))
    ));
    Ok(())
}

#[tokio::test]
async fn public_http_session_round_trip_commits_and_replays_real_sqlite_state()
-> Result<(), Box<dyn std::error::Error>> {
    let claim = ClaimBundle::generate(&mut SequentialRandom(1))?;
    let bootstrap_operation = OperationId::from_bytes([8; 16])?;
    let material = InitialBootstrapMaterial::derive(&claim, bootstrap_operation)?;
    let directory = tempdir()?;
    let database = PartitionDatabase::open(
        &directory.path().join("root.sqlite3"),
        material.partition_id,
        UnixMicros::new(1),
    )?;
    let mut authority = RepositorySessionAuthority {
        repository: AuthoritativeRepository::new(database),
        next_index: 1,
    };
    bootstrap(&mut authority, &material, bootstrap_operation)?;
    let api_key = material.api_key.expose_encoded();
    let router = session_api_router(CreateSessionService::new(authority))?;
    let first = router
        .clone()
        .oneshot(http_request(&api_key, false)?)
        .await?;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_cookie = first
        .headers()
        .get("set-cookie")
        .ok_or("session cookie missing")?
        .clone();
    let first_csrf = first
        .headers()
        .get("meshspan-csrf-token")
        .ok_or("CSRF token missing")?
        .clone();
    let first_body = to_bytes(first.into_body(), 2_048).await?;

    let replay = router
        .clone()
        .oneshot(http_request(&api_key, false)?)
        .await?;
    assert_eq!(replay.status(), StatusCode::CREATED);
    assert_eq!(replay.headers().get("set-cookie"), Some(&first_cookie));
    assert_eq!(
        replay.headers().get("meshspan-csrf-token"),
        Some(&first_csrf)
    );
    assert_eq!(to_bytes(replay.into_body(), 2_048).await?, first_body);

    let changed = router.oneshot(http_request(&api_key, true)?).await?;
    assert_eq!(changed.status(), StatusCode::CONFLICT);
    assert!(changed.headers().get("set-cookie").is_none());
    assert!(changed.headers().get("meshspan-csrf-token").is_none());
    Ok(())
}

#[tokio::test]
async fn public_revocation_commits_then_replays_after_the_session_is_unusable()
-> Result<(), Box<dyn std::error::Error>> {
    let claim = ClaimBundle::generate(&mut SequentialRandom(1))?;
    let bootstrap_operation = OperationId::from_bytes([8; 16])?;
    let material = InitialBootstrapMaterial::derive(&claim, bootstrap_operation)?;
    let directory = tempdir()?;
    let database = PartitionDatabase::open(
        &directory.path().join("root.sqlite3"),
        material.partition_id,
        UnixMicros::new(1),
    )?;
    let mut authority = RepositorySessionAuthority {
        repository: AuthoritativeRepository::new(database),
        next_index: 1,
    };
    bootstrap(&mut authority, &material, bootstrap_operation)?;
    let mut creation = CreateSessionService::new(authority);
    let issued_at = UnixMicros::new(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros(),
    )?);
    let created = creation.create(
        &request(&material.api_key.expose_encoded(), false)?,
        issued_at,
    )?;
    let bearer = created.bearer.expose_encoded();
    let cookie = format!("meshspan_session={}", bearer.as_str());
    let csrf = created.csrf.expose_encoded();
    let gateway = GatewaySessionIdentity::new(material.node_id, 1)?;
    let router = revoke_current_session_api_router(RevokeCurrentSessionService::new(
        creation.into_authority(),
        gateway,
    ))?;

    let first = router
        .clone()
        .oneshot(revocation_request(
            &cookie,
            &csrf,
            REVOCATION_OPERATION_TEXT,
        )?)
        .await?;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        first.headers().get("set-cookie"),
        Some(&HeaderValue::from_static(
            "meshspan_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"
        ))
    );
    let first_body = to_bytes(first.into_body(), 2_048).await?;
    let result = serde_json::from_slice::<RevokeCurrentSessionResponse>(&first_body)?;
    assert_eq!(result.operation_id.as_str(), REVOCATION_OPERATION_TEXT);

    let replay = router
        .clone()
        .oneshot(revocation_request(
            &cookie,
            &csrf,
            REVOCATION_OPERATION_TEXT,
        )?)
        .await?;
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(to_bytes(replay.into_body(), 2_048).await?, first_body);

    let different_operation = router
        .oneshot(revocation_request(
            &cookie,
            &csrf,
            "00000000-0000-4000-8000-000000000013",
        )?)
        .await?;
    assert_eq!(different_operation.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

fn bootstrap(
    authority: &mut RepositorySessionAuthority,
    material: &InitialBootstrapMaterial,
    operation_id: OperationId,
) -> Result<(), Box<dyn std::error::Error>> {
    let command = AuthoritativeCommand::BootstrapAppliance(BootstrapAppliance {
        mesh: BootstrapMesh {
            mesh_id: material.mesh_id,
            mesh_name: RecordName::new("Test mesh")?,
            administrator_id: material.administrator_id,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: material.administrator_role_id,
            host_id: material.host_id,
            host_name: RecordName::new("Test host")?,
            node_id: material.node_id,
            node_name: RecordName::new("Test node")?,
            partition_name: RecordName::new("Root authority")?,
        },
        authentication: CreateAuthenticationMethod {
            method_id: material.authentication_method_id,
            principal_id: material.administrator_id,
            label: "Initial API key".to_owned(),
            service_scope: 1 | 2 | 4,
            expires_at: None,
            credential: NewAuthenticationCredential::ApiKey {
                key_id: material.api_key.key_id(),
                key_digest: material.api_key.secret_digest(),
                scopes: 1,
                valid_from: UnixMicros::new(10),
            },
        },
    });
    authority.repository.apply_committed(
        LogPosition { index: 1, term: 1 },
        CommandContext {
            operation_id,
            actor_principal_id: material.administrator_id,
            audit_event_id: material.audit_event_id,
            occurred_at: UnixMicros::new(10),
            expected_revision: Some(Revision::ZERO),
        },
        &command,
    )?;
    authority.next_index = 2;
    Ok(())
}

fn request(
    api_key: &str,
    remember: bool,
) -> Result<CreateSessionRequest, Box<dyn std::error::Error>> {
    let value = serde_json::json!({
        "operation_id": OPERATION_TEXT,
        "authentication": { "method": "api_key", "secret": api_key },
        "client_label": null,
        "remember": remember
    });
    Ok(decode_create_session_request(&serde_json::to_vec(&value)?)?)
}

fn http_request(
    api_key: &str,
    remember: bool,
) -> Result<Request<Body>, Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": OPERATION_TEXT,
        "authentication": { "method": "api_key", "secret": api_key },
        "client_label": null,
        "remember": remember
    }))?;
    Ok(Request::post("/api/latest/sessions")
        .header("content-type", "application/json")
        .body(Body::from(body))?)
}

fn revocation_request(
    cookie: &str,
    csrf: &str,
    operation_id: &str,
) -> Result<Request<Body>, Box<dyn std::error::Error>> {
    let body = serde_json::to_vec(&serde_json::json!({ "operation_id": operation_id }))?;
    Ok(Request::post("/api/latest/sessions/current/revocations")
        .header("content-type", "application/json")
        .header(COOKIE, cookie)
        .header("meshspan-csrf-token", csrf)
        .body(Body::from(body))?)
}

struct RepositorySessionAuthority {
    repository: AuthoritativeRepository,
    next_index: u64,
}

impl SessionAuthority for RepositorySessionAuthority {
    fn authenticate_api_key(
        &self,
        digest: [u8; 32],
        now: UnixMicros,
    ) -> Result<Option<ApiKeyAuthentication>, SessionAuthorityError> {
        self.repository
            .authenticate_api_key(
                digest,
                AuthenticationService::Https,
                AuthenticationService::Https.api_key_login_scope(),
                now,
            )
            .map_err(|error| map_repository_error(&error))
    }

    fn session_policy(&self) -> Result<AuthenticationPolicy, SessionAuthorityError> {
        self.repository
            .authentication_policy(
                AuthenticationService::Https,
                AuthenticationOperationClass::SessionEstablishment,
            )
            .map_err(|error| map_repository_error(&error))
    }

    fn resolve_api_key_session(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<ApiKeySessionReplay>, SessionAuthorityError> {
        self.repository
            .resolve_api_key_session(operation_id)
            .map_err(|error| map_repository_error(&error))
    }

    fn commit_or_resolve(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<SessionCommit, SessionAuthorityError> {
        let request_digest = command.request_digest(context);
        if let Some(receipt) = self
            .repository
            .resolve_operation(context.operation_id)
            .map_err(|error| map_repository_error(&error))?
        {
            if receipt.request_digest != request_digest {
                return Err(SessionAuthorityError::Conflict);
            }
            return Ok(SessionCommit {
                result_digest: receipt.result_digest,
            });
        }
        let receipt = self
            .repository
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
        Ok(SessionCommit {
            result_digest: receipt.result_digest,
        })
    }
}

impl BrowserSessionAuthority for RepositorySessionAuthority {
    fn evaluate_browser_session(
        &self,
        request: BrowserSessionAccessRequest,
    ) -> Result<SessionAccessDecision, BrowserSessionAuthorityError> {
        self.repository
            .evaluate_browser_session_access(request)
            .map_err(|error| match map_repository_error(&error) {
                SessionAuthorityError::Unavailable => BrowserSessionAuthorityError::Unavailable,
                SessionAuthorityError::Conflict | SessionAuthorityError::Failed => {
                    BrowserSessionAuthorityError::Failed
                }
            })
    }
}

impl SessionRevocationAuthority for RepositorySessionAuthority {
    fn resolve_revocation(
        &self,
        operation_id: OperationId,
        session_id: meshspan_domain::SessionId,
        token_digest: [u8; 32],
        csrf_digest: [u8; 32],
    ) -> Result<Option<SessionRevocationReplay>, SessionRevocationAuthorityError> {
        self.repository
            .resolve_session_revocation(operation_id, session_id, token_digest, csrf_digest)
            .map_err(|error| map_revocation_repository_error(&error))
    }

    fn commit_or_resolve_revocation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<SessionRevocationCommit, SessionRevocationAuthorityError> {
        let request_digest = command.request_digest(context);
        if let Some(receipt) = self
            .repository
            .resolve_operation(context.operation_id)
            .map_err(|error| map_revocation_repository_error(&error))?
        {
            if receipt.request_digest != request_digest {
                return Err(SessionRevocationAuthorityError::Conflict);
            }
            return Ok(SessionRevocationCommit {
                result_digest: receipt.result_digest,
            });
        }
        let receipt = self
            .repository
            .apply_committed(
                LogPosition {
                    index: self.next_index,
                    term: 1,
                },
                context,
                command,
            )
            .map_err(|error| map_revocation_repository_error(&error))?;
        self.next_index = self.next_index.saturating_add(1);
        Ok(SessionRevocationCommit {
            result_digest: receipt.result_digest,
        })
    }
}

fn map_repository_error(error: &RepositoryError) -> SessionAuthorityError {
    match error {
        RepositoryError::OperationConflict => SessionAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            SessionAuthorityError::Unavailable
        }
        _ => SessionAuthorityError::Failed,
    }
}

fn map_revocation_repository_error(error: &RepositoryError) -> SessionRevocationAuthorityError {
    match error {
        RepositoryError::OperationConflict => SessionRevocationAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            SessionRevocationAuthorityError::Unavailable
        }
        _ => SessionRevocationAuthorityError::Failed,
    }
}

struct SequentialRandom(u8);

impl RandomSource for SequentialRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}
