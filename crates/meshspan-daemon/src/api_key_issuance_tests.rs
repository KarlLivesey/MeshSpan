// SPDX-License-Identifier: GPL-2.0-only

use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use meshspan_api_contract::{
    CreateApiKeyRequest, decode_create_api_key_request, decode_create_session_request,
};
use meshspan_domain::{
    ApiKeyIssuanceKey, AuthenticationMethodKind, ClaimBundle, InitialBootstrapMaterial,
    OperationId, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, LogPosition, PartitionDatabase, RepositoryError,
};
use tempfile::tempdir;

use crate::browser_session::CSRF_HEADER;
use crate::create_session_tests::{RepositorySessionAuthority, bootstrap};
use crate::passkey_test_support::CountingRandom;
use crate::{
    ApiKeyIssuanceAuthority, ApiKeyIssuanceAuthorityError, ApiKeyIssuanceCommit,
    ApiKeyIssuanceError, ApiKeyIssuanceService, CreateSessionService, GatewaySessionIdentity,
};

#[test]
fn issued_key_replays_across_gateways_logs_in_and_rejects_changed_input()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let bootstrap_operation = OperationId::from_bytes([8; 16])?;
    let claim = ClaimBundle::generate(&mut CountingRandom::default())?;
    let material = InitialBootstrapMaterial::derive(&claim, bootstrap_operation)?;
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
    let mut sessions = CreateSessionService::new(authority);
    let session = sessions.create(&initial_session_request(&material)?, UnixMicros::new(20))?;
    let headers = browser_headers(&session)?;
    let authority = sessions.into_authority();
    let gateway = GatewaySessionIdentity::new(material.node_id, 1)?;
    let request = issuance_request("Automation and SMB", None)?;
    let mut issuer =
        ApiKeyIssuanceService::new(authority, ApiKeyIssuanceKey::from_bytes([21; 32])?, gateway);
    let first = issuer
        .issue(&request, &headers, UnixMicros::new(30))
        .map_err(|error| format!("initial issuance failed: {error:?}"))?;
    assert_eq!(first.created_at_epoch_micros, 30);
    assert_eq!(first.valid_from_epoch_micros, 30);
    assert_eq!(first.scopes.len(), 3);
    assert_eq!(
        first.expires_at_epoch_micros,
        Some(30 + 90 * 24 * 60 * 60 * 1_000_000)
    );

    let authority = issuer.into_authority();
    let mut replay_issuer =
        ApiKeyIssuanceService::new(authority, ApiKeyIssuanceKey::from_bytes([21; 32])?, gateway);
    let replay = replay_issuer
        .issue(&request, &headers, UnixMicros::new(40))
        .map_err(|error| format!("cross-gateway replay failed: {error:?}"))?;
    assert!(replay == first);
    let changed = issuance_request("Changed label", None)?;
    assert!(matches!(
        replay_issuer.issue(&changed, &headers, UnixMicros::new(41)),
        Err(ApiKeyIssuanceError::Conflict)
    ));

    let authority = replay_issuer.into_authority();
    let mut login = CreateSessionService::new(authority);
    let session = login.create(&issued_session_request(&first.secret)?, UnixMicros::new(42))?;
    assert_eq!(session.response.expires_at_epoch_micros, 43_200_000_042);
    Ok(())
}

impl ApiKeyIssuanceAuthority for RepositorySessionAuthority {
    fn resolve_api_key_issuance(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<ApiKeyIssuanceCommit>, ApiKeyIssuanceAuthorityError> {
        self.repository
            .resolve_authentication_method_creation(operation_id, AuthenticationMethodKind::ApiKey)
            .map_err(|error| map_repository_error(&error))?
            .map(|replay| {
                Ok(ApiKeyIssuanceCommit {
                    request_digest: replay.request_digest,
                    result_digest: replay.result_digest,
                    method_id: replay.method_id,
                    principal_id: replay.principal_id,
                    created_at: replay.created_at,
                })
            })
            .transpose()
    }

    fn commit_or_resolve_api_key_issuance(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<ApiKeyIssuanceCommit, ApiKeyIssuanceAuthorityError> {
        let expected_digest = command.request_digest(context);
        if let Some(replay) = self
            .repository
            .resolve_authentication_method_creation(
                context.operation_id,
                AuthenticationMethodKind::ApiKey,
            )
            .map_err(|error| map_repository_error(&error))?
        {
            if replay.request_digest != expected_digest {
                return Err(ApiKeyIssuanceAuthorityError::Conflict);
            }
            return Ok(commit(replay));
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
        self.repository
            .resolve_authentication_method_creation(
                context.operation_id,
                AuthenticationMethodKind::ApiKey,
            )
            .map_err(|error| map_repository_error(&error))?
            .map(commit)
            .ok_or(ApiKeyIssuanceAuthorityError::Failed)
    }
}

fn commit(replay: meshspan_metadata::AuthenticationMethodCreationReplay) -> ApiKeyIssuanceCommit {
    ApiKeyIssuanceCommit {
        request_digest: replay.request_digest,
        result_digest: replay.result_digest,
        method_id: replay.method_id,
        principal_id: replay.principal_id,
        created_at: replay.created_at,
    }
}

fn issuance_request(
    label: &str,
    expiry: Option<serde_json::Value>,
) -> Result<CreateApiKeyRequest, Box<dyn std::error::Error>> {
    let mut value = serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000031",
        "label": label,
        "scopes": ["https_session", "headless_api", "smb_session"]
    });
    if let Some(expiry) = expiry {
        value["expires_at_epoch_micros"] = expiry;
    }
    Ok(decode_create_api_key_request(&serde_json::to_vec(&value)?)?)
}

fn initial_session_request(
    material: &InitialBootstrapMaterial,
) -> Result<meshspan_api_contract::CreateSessionRequest, Box<dyn std::error::Error>> {
    session_request(
        "00000000-0000-4000-8000-000000000030",
        material.api_key.expose_encoded().as_str(),
    )
}

fn issued_session_request(
    secret: &str,
) -> Result<meshspan_api_contract::CreateSessionRequest, Box<dyn std::error::Error>> {
    session_request("00000000-0000-4000-8000-000000000032", secret)
}

fn session_request(
    operation_id: &str,
    secret: &str,
) -> Result<meshspan_api_contract::CreateSessionRequest, Box<dyn std::error::Error>> {
    Ok(decode_create_session_request(&serde_json::to_vec(
        &serde_json::json!({
            "operation_id": operation_id,
            "authentication": { "method": "api_key", "secret": secret },
            "client_label": null,
            "remember": false
        }),
    )?)?)
}

fn browser_headers(
    result: &crate::CreateSessionResult,
) -> Result<HeaderMap, Box<dyn std::error::Error>> {
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&format!(
            "meshspan_session={}",
            result.bearer.expose_encoded().as_str()
        ))?,
    );
    headers.insert(
        CSRF_HEADER,
        HeaderValue::from_str(result.csrf.expose_encoded().as_str())?,
    );
    Ok(headers)
}

fn map_repository_error(error: &RepositoryError) -> ApiKeyIssuanceAuthorityError {
    match error {
        RepositoryError::OperationConflict => ApiKeyIssuanceAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            ApiKeyIssuanceAuthorityError::Unavailable
        }
        _ => ApiKeyIssuanceAuthorityError::Failed,
    }
}
