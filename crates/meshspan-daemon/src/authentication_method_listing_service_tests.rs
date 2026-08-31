// SPDX-License-Identifier: GPL-2.0-only

use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::{HeaderMap, HeaderValue};
use meshspan_api_contract::{
    AuthenticationMethodDetails, AuthenticationMethodState, ListAuthenticationMethodsQuery,
    decode_create_session_request,
};
use meshspan_domain::{
    ClaimBundle, EntropyError, InitialBootstrapMaterial, OperationId, RandomSource, UnixMicros,
};
use meshspan_metadata::{
    AuthenticationMethodCursor, AuthenticationMethodRecord, Page, PageLimit, PartitionDatabase,
    RepositoryError,
};
use tempfile::tempdir;

use crate::create_session_tests::{RepositorySessionAuthority, bootstrap};
use crate::{
    AuthenticationMethodListingAuthority, AuthenticationMethodListingAuthorityError,
    AuthenticationMethodListingError, AuthenticationMethodListingService, CreateSessionService,
    GatewaySessionIdentity,
};

#[test]
fn real_sqlite_inventory_authenticates_browser_sessions_and_rejects_mixed_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let claim = ClaimBundle::generate(&mut SequentialRandom::default())?;
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
    let session_request =
        decode_create_session_request(&serde_json::to_vec(&serde_json::json!({
            "operation_id": "00000000-0000-4000-8000-000000000082",
            "authentication": {
                "method": "api_key",
                "secret": material.api_key.expose_encoded().as_str()
            },
            "client_label": "Authentication inventory proof",
            "remember": false
        }))?)?;
    let mut session_service = CreateSessionService::new(authority);
    let session = session_service.create(&session_request, UnixMicros::new(20))?;
    let service = AuthenticationMethodListingService::new(
        session_service.into_authority(),
        GatewaySessionIdentity::new(material.node_id, 1)?,
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&format!(
            "meshspan_session={}",
            session.bearer.expose_encoded().as_str()
        ))?,
    );

    let response = service.list(
        &headers,
        &ListAuthenticationMethodsQuery {
            cursor: None,
            limit: Some(10),
        },
        UnixMicros::new(21),
    )?;
    assert_eq!(response.methods.len(), 1);
    let method = response.methods.first().ok_or("method evidence missing")?;
    assert_eq!(method.label, "Initial API key");
    assert_eq!(method.state, AuthenticationMethodState::Active);
    assert!(matches!(
        method.details,
        AuthenticationMethodDetails::ApiKey { .. }
    ));
    assert!(response.next_page_url.is_none());

    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!(
            "Bearer {}",
            material.api_key.expose_encoded().as_str()
        ))?,
    );
    assert_eq!(
        service.list(
            &headers,
            &ListAuthenticationMethodsQuery::default(),
            UnixMicros::new(21),
        ),
        Err(AuthenticationMethodListingError::Rejected)
    );
    Ok(())
}

impl AuthenticationMethodListingAuthority for RepositorySessionAuthority {
    fn authentication_methods(
        &self,
        principal_id: meshspan_domain::PrincipalId,
        after: Option<AuthenticationMethodCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<AuthenticationMethodRecord, AuthenticationMethodCursor>,
        AuthenticationMethodListingAuthorityError,
    > {
        self.repository
            .authentication_methods(principal_id, after, limit)
            .map_err(|error| map_repository_error(&error))
    }
}

fn map_repository_error(error: &RepositoryError) -> AuthenticationMethodListingAuthorityError {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            AuthenticationMethodListingAuthorityError::Unavailable
        }
        _ => AuthenticationMethodListingAuthorityError::Failed,
    }
}

#[derive(Default)]
struct SequentialRandom(u8);

impl RandomSource for SequentialRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}
