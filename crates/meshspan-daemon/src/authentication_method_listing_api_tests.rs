// SPDX-License-Identifier: GPL-2.0-only

use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use meshspan_api_contract::{
    ApiError, AuthenticationMethodDetails, AuthenticationMethodId, AuthenticationMethodState,
    AuthenticationMethodSummary, ListAuthenticationMethodsQuery, ListAuthenticationMethodsResponse,
};
use meshspan_domain::UnixMicros;
use tower::ServiceExt;

use crate::{
    AuthenticationMethodListingController, AuthenticationMethodListingError,
    authentication_method_listing_api_router,
};

#[tokio::test]
async fn inventory_endpoint_returns_one_validated_page_and_exact_query()
-> Result<(), Box<dyn std::error::Error>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let router = authentication_method_listing_api_router(FakeController {
        outcome: FakeOutcome::Page(page(None)?),
        seen: Arc::clone(&seen),
    })?;
    let response = router
        .oneshot(
            Request::get(
                "/api/latest/users/current/authentication-methods?limit=1&cursor=v1.am.aa",
            )
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16_384).await?;
    let page: ListAuthenticationMethodsResponse = serde_json::from_slice(&body)?;
    assert_eq!(page.methods.len(), 1);
    assert_eq!(page.methods[0].label, "Laptop passkey");
    let seen = seen.lock().map_err(|_| "poisoned query evidence")?;
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].limit, Some(1));
    assert_eq!(
        seen[0]
            .cursor
            .as_ref()
            .map(meshspan_api_contract::AuthenticationMethodCursor::as_str),
        Some("v1.am.aa")
    );
    Ok(())
}

#[tokio::test]
async fn inventory_endpoint_rejects_ambiguous_queries_before_controller_work()
-> Result<(), Box<dyn std::error::Error>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let router = authentication_method_listing_api_router(FakeController {
        outcome: FakeOutcome::Page(page(None)?),
        seen: Arc::clone(&seen),
    })?;
    for uri in [
        "/api/latest/users/current/authentication-methods?limit=0",
        "/api/latest/users/current/authentication-methods?limit=1&limit=2",
        "/api/latest/users/current/authentication-methods?cursor=%GG",
        "/api/latest/users/current/authentication-methods?unknown=true",
    ] {
        let response = router
            .clone()
            .oneshot(Request::get(uri).body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    assert!(
        seen.lock()
            .map_err(|_| "poisoned query evidence")?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn inventory_endpoint_maps_closed_failures_without_leaking_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    for (error, expected) in [
        (
            AuthenticationMethodListingError::Rejected,
            StatusCode::UNAUTHORIZED,
        ),
        (
            AuthenticationMethodListingError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            AuthenticationMethodListingError::InvalidRequest,
            StatusCode::BAD_REQUEST,
        ),
        (
            AuthenticationMethodListingError::Failed,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ] {
        let response = authentication_method_listing_api_router(FakeController {
            outcome: FakeOutcome::Error(error),
            seen: Arc::new(Mutex::new(Vec::new())),
        })?
        .oneshot(
            Request::get("/api/latest/users/current/authentication-methods").body(Body::empty())?,
        )
        .await?;
        assert_eq!(response.status(), expected);
        let body = to_bytes(response.into_body(), 16_384).await?;
        let error: ApiError = serde_json::from_slice(&body)?;
        assert!(!error.message.contains("credential"));
    }
    Ok(())
}

#[tokio::test]
async fn inventory_endpoint_refuses_substituted_outgoing_pagination()
-> Result<(), Box<dyn std::error::Error>> {
    let response = authentication_method_listing_api_router(FakeController {
        outcome: FakeOutcome::Page(page(Some("/api/latest/admin/users".to_owned()))?),
        seen: Arc::new(Mutex::new(Vec::new())),
    })?
    .oneshot(Request::get("/api/latest/users/current/authentication-methods").body(Body::empty())?)
    .await?;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}

#[derive(Clone)]
struct FakeController {
    outcome: FakeOutcome,
    seen: Arc<Mutex<Vec<ListAuthenticationMethodsQuery>>>,
}

impl AuthenticationMethodListingController for FakeController {
    fn list_authentication_methods(
        &mut self,
        _headers: &axum::http::HeaderMap,
        query: ListAuthenticationMethodsQuery,
        _now: UnixMicros,
    ) -> Result<ListAuthenticationMethodsResponse, AuthenticationMethodListingError> {
        self.seen
            .lock()
            .map_err(|_| AuthenticationMethodListingError::Unavailable)?
            .push(query);
        match &self.outcome {
            FakeOutcome::Page(page) => Ok(page.clone()),
            FakeOutcome::Error(error) => Err(*error),
        }
    }
}

#[derive(Clone)]
enum FakeOutcome {
    Page(ListAuthenticationMethodsResponse),
    Error(AuthenticationMethodListingError),
}

fn page(
    next_page_url: Option<String>,
) -> Result<ListAuthenticationMethodsResponse, Box<dyn std::error::Error>> {
    Ok(ListAuthenticationMethodsResponse {
        methods: vec![AuthenticationMethodSummary {
            method_id: AuthenticationMethodId::from_uuid_bytes(versioned(1))
                .ok_or("invalid method")?,
            label: "Laptop passkey".to_owned(),
            state: AuthenticationMethodState::Active,
            details: AuthenticationMethodDetails::Passkey {
                backup_eligible: true,
                backup_state: true,
            },
            created_at_epoch_micros: 10,
            last_used_at_epoch_micros: Some(11),
            expires_at_epoch_micros: None,
            revision: 2,
        }],
        next_page_url,
    })
}

fn versioned(seed: u8) -> [u8; 16] {
    let mut value = [seed; 16];
    value[6] = 0x41;
    value[8] = 0x81;
    value
}
