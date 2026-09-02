// SPDX-License-Identifier: GPL-2.0-only

use axum::http::header::COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use meshspan_api_contract::{
    CreateApiKeyRequest, RevokeAuthenticationMethodRequest, decode_create_api_key_request,
    decode_create_session_request, decode_revoke_authentication_method_request,
};
use meshspan_domain::{
    ApiKeyIssuanceKey, ClaimBundle, InitialBootstrapMaterial, OperationId, UnixMicros,
};
use meshspan_metadata::{
    AuthenticationMethodRevocationReplay, AuthoritativeCommand, CommandContext, LogPosition,
    PartitionDatabase, RepositoryError,
};
use tempfile::tempdir;

use crate::browser_session::CSRF_HEADER;
use crate::create_session_tests::{RepositorySessionAuthority, bootstrap};
use crate::passkey_test_support::CountingRandom;
use crate::{
    ApiKeyIssuanceService, AuthenticationMethodRevocationAuthority,
    AuthenticationMethodRevocationAuthorityError, AuthenticationMethodRevocationCommit,
    AuthenticationMethodRevocationError, AuthenticationMethodRevocationService, CreateSessionError,
    CreateSessionService, GatewaySessionIdentity,
};

#[test]
fn owned_method_revocation_replays_and_immediately_fences_the_key_and_derived_session()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let bootstrap_operation = OperationId::from_bytes([8; 16])?;
    let claim = ClaimBundle::generate(&mut CountingRandom::default())?;
    let material = InitialBootstrapMaterial::derive(
        &claim,
        bootstrap_operation,
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
    bootstrap(&mut authority, &material, bootstrap_operation)?;
    let mut sessions = CreateSessionService::new(authority);
    let initial_session = sessions.create(
        &session_request(48, material.api_key.expose_encoded().as_str())?,
        UnixMicros::new(20),
    )?;
    let initial_headers = browser_headers(&initial_session)?;
    let authority = sessions.into_authority();
    let mut issuance = ApiKeyIssuanceService::new(
        authority,
        ApiKeyIssuanceKey::from_bytes([21; 32])?,
        crate::SmbVerifierEnvelopeKey::from_parts([22; 32], [23; 32])?,
        1,
        GatewaySessionIdentity::new(material.node_id, 1)?,
    )?;
    let api_key_response =
        issuance.issue(&issuance_request()?, &initial_headers, UnixMicros::new(30))?;
    let authority = issuance.into_authority();

    let mut key_login_service = CreateSessionService::new(authority);
    let key_session = key_login_service.create(
        &session_request(50, &api_key_response.secret)?,
        UnixMicros::new(40),
    )?;
    let key_session_headers = browser_headers(&key_session)?;
    let authority = key_login_service.into_authority();

    let gateway = GatewaySessionIdentity::new(material.node_id, 1)?;
    let request = revocation_request("Rotating the automation credential")?;
    let mut revoker = AuthenticationMethodRevocationService::new(authority, gateway);
    let first = revoker.revoke(
        &api_key_response.method_id,
        &request,
        &initial_headers,
        UnixMicros::new(50),
    )?;
    assert_eq!(first.method_id, api_key_response.method_id);
    assert_eq!(first.revoked_at_epoch_micros, 50);
    let replay = revoker.revoke(
        &api_key_response.method_id,
        &request,
        &initial_headers,
        UnixMicros::new(60),
    )?;
    assert_eq!(replay, first);
    assert!(matches!(
        revoker.revoke(
            &api_key_response.method_id,
            &revocation_request("Changed reason")?,
            &initial_headers,
            UnixMicros::new(61),
        ),
        Err(AuthenticationMethodRevocationError::Conflict)
    ));
    assert!(matches!(
        revoker.revoke(
            &api_key_response.method_id,
            &revocation_request_with_operation(52, "Already revoked")?,
            &key_session_headers,
            UnixMicros::new(62),
        ),
        Err(AuthenticationMethodRevocationError::Authentication(_))
    ));

    let authority = revoker.into_authority();
    let mut rejected_login = CreateSessionService::new(authority);
    assert!(matches!(
        rejected_login.create(
            &session_request(53, &api_key_response.secret)?,
            UnixMicros::new(63)
        ),
        Err(CreateSessionError::Rejected)
    ));
    Ok(())
}

impl AuthenticationMethodRevocationAuthority for RepositorySessionAuthority {
    fn resolve_authentication_method_revocation(
        &self,
        operation_id: OperationId,
    ) -> Result<
        Option<AuthenticationMethodRevocationCommit>,
        AuthenticationMethodRevocationAuthorityError,
    > {
        self.repository
            .resolve_authentication_method_revocation(operation_id)
            .map_err(|error| map_repository_error(&error))?
            .map(|replay| Ok(commit(replay)))
            .transpose()
    }

    fn commit_or_resolve_authentication_method_revocation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<AuthenticationMethodRevocationCommit, AuthenticationMethodRevocationAuthorityError>
    {
        let expected_digest = command.request_digest(context);
        if let Some(replay) = self
            .repository
            .resolve_authentication_method_revocation(context.operation_id)
            .map_err(|error| map_repository_error(&error))?
        {
            if replay.request_digest != expected_digest {
                return Err(AuthenticationMethodRevocationAuthorityError::Conflict);
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
            .resolve_authentication_method_revocation(context.operation_id)
            .map_err(|error| map_repository_error(&error))?
            .map(commit)
            .ok_or(AuthenticationMethodRevocationAuthorityError::Failed)
    }
}

fn commit(replay: AuthenticationMethodRevocationReplay) -> AuthenticationMethodRevocationCommit {
    AuthenticationMethodRevocationCommit {
        request_digest: replay.request_digest,
        result_digest: replay.result_digest,
        method_id: replay.method_id,
        principal_id: replay.principal_id,
        actor_principal_id: replay.actor_principal_id,
        revoked_at: replay.revoked_at,
    }
}

fn issuance_request() -> Result<CreateApiKeyRequest, Box<dyn std::error::Error>> {
    Ok(decode_create_api_key_request(&serde_json::to_vec(
        &serde_json::json!({
            "operation_id": "00000000-0000-4000-8000-000000000031",
            "label": "Automation",
            "scopes": ["https_session", "headless_api"]
        }),
    )?)?)
}

fn revocation_request(
    reason: &str,
) -> Result<RevokeAuthenticationMethodRequest, Box<dyn std::error::Error>> {
    revocation_request_with_operation(51, reason)
}

fn revocation_request_with_operation(
    suffix: u8,
    reason: &str,
) -> Result<RevokeAuthenticationMethodRequest, Box<dyn std::error::Error>> {
    Ok(decode_revoke_authentication_method_request(
        &serde_json::to_vec(&serde_json::json!({
            "operation_id": format!("00000000-0000-4000-8000-{suffix:012x}"),
            "reason": reason
        }))?,
    )?)
}

fn session_request(
    suffix: u8,
    secret: &str,
) -> Result<meshspan_api_contract::CreateSessionRequest, Box<dyn std::error::Error>> {
    Ok(decode_create_session_request(&serde_json::to_vec(
        &serde_json::json!({
            "operation_id": format!("00000000-0000-4000-8000-{suffix:012x}"),
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

fn map_repository_error(error: &RepositoryError) -> AuthenticationMethodRevocationAuthorityError {
    match error {
        RepositoryError::OperationConflict => {
            AuthenticationMethodRevocationAuthorityError::Conflict
        }
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            AuthenticationMethodRevocationAuthorityError::Unavailable
        }
        _ => AuthenticationMethodRevocationAuthorityError::Failed,
    }
}
