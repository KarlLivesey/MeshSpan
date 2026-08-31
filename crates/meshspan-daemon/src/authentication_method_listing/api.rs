// SPDX-License-Identifier: GPL-2.0-only

//! Bounded HTTP boundary for current-user authentication-method inventory.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::routing::get;
use meshspan_api_contract::{
    ApiErrorCode, AuthenticationMethodCursor, ListAuthenticationMethodsQuery,
    ListAuthenticationMethodsResponse, encode_list_authentication_methods_response,
    generate_openapi,
};
use meshspan_domain::UnixMicros;
use thiserror::Error;

use super::{
    AuthenticationMethodListingAuthority, AuthenticationMethodListingError,
    AuthenticationMethodListingService,
};
use crate::api_http::{
    current_time, error_response, internal_error_response, issue, json_response, request_identifier,
};

/// Synchronous inventory boundary executed on a blocking worker.
pub trait AuthenticationMethodListingController: Send + 'static {
    /// Returns one bounded current-user authentication-method page.
    ///
    /// # Errors
    ///
    /// Returns only stable request, authentication, availability or integrity failures.
    fn list_authentication_methods(
        &mut self,
        headers: &HeaderMap,
        query: ListAuthenticationMethodsQuery,
        now: UnixMicros,
    ) -> Result<ListAuthenticationMethodsResponse, AuthenticationMethodListingError>;
}

impl<A> AuthenticationMethodListingController for AuthenticationMethodListingService<A>
where
    A: AuthenticationMethodListingAuthority + Send + 'static,
{
    fn list_authentication_methods(
        &mut self,
        headers: &HeaderMap,
        query: ListAuthenticationMethodsQuery,
        now: UnixMicros,
    ) -> Result<ListAuthenticationMethodsResponse, AuthenticationMethodListingError> {
        self.list(headers, &query, now)
    }
}

struct ApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for ApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds the rolling current-user authentication-method inventory endpoint.
///
/// # Errors
///
/// Fails when the Rust-authored contract or schema header cannot be generated.
pub fn authentication_method_listing_api_router<C>(
    controller: C,
) -> Result<Router, AuthenticationMethodListingApiError>
where
    C: AuthenticationMethodListingController,
{
    let document = generate_openapi()?;
    let state = ApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/users/current/authentication-methods",
            get(list::<C>),
        )
        .with_state(state))
}

async fn list<C>(State(state): State<ApiState<C>>, request: Request) -> Response<Body>
where
    C: AuthenticationMethodListingController,
{
    let request_id = request_identifier();
    let Ok(query) = parse_query(request.uri().query()) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "authentication-method query is invalid",
            request_id,
            None,
            vec![issue("", "query")],
            state.schema_digest,
        );
    };
    let Some(now) = current_time() else {
        return failed_closed(request_id, state.schema_digest);
    };
    let headers = request.headers().clone();
    execute(state, request_id, headers, query, now).await
}

async fn execute<C>(
    state: ApiState<C>,
    request_id: String,
    headers: HeaderMap,
    query: ListAuthenticationMethodsQuery,
    now: UnixMicros,
) -> Response<Body>
where
    C: AuthenticationMethodListingController,
{
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| AuthenticationMethodListingError::Unavailable)?
            .list_authentication_methods(&headers, query, now)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_list_authentication_methods_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed_closed(request_id, state.schema_digest),
        },
        Ok(Err(error)) => service_error(error, request_id, state.schema_digest),
        Err(_) => failed_closed(request_id, state.schema_digest),
    }
}

fn parse_query(raw_query: Option<&str>) -> Result<ListAuthenticationMethodsQuery, ()> {
    let Some(raw_query) = raw_query.filter(|value| !value.is_empty()) else {
        return Ok(ListAuthenticationMethodsQuery::default());
    };
    if raw_query.len() > 4_096 || !valid_percent_encoding(raw_query.as_bytes()) {
        return Err(());
    }
    let mut query = ListAuthenticationMethodsQuery::default();
    let mut cursor_seen = false;
    let mut limit_seen = false;
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "cursor" if !cursor_seen => {
                cursor_seen = true;
                query.cursor =
                    Some(AuthenticationMethodCursor::from_encoded(value.into_owned()).ok_or(())?);
            }
            "limit" if !limit_seen => {
                limit_seen = true;
                query.limit = Some(
                    value
                        .parse::<u16>()
                        .ok()
                        .filter(|value| (1..=256).contains(value))
                        .ok_or(())?,
                );
            }
            _ => return Err(()),
        }
    }
    Ok(query)
}

fn valid_percent_encoding(value: &[u8]) -> bool {
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'%' {
            if index + 2 >= value.len()
                || !value[index + 1].is_ascii_hexdigit()
                || !value[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn service_error(
    error: AuthenticationMethodListingError,
    request_id: String,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let (status, code, message) = match error {
        AuthenticationMethodListingError::InvalidRequest => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "authentication-method query is invalid",
        ),
        AuthenticationMethodListingError::Rejected => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        AuthenticationMethodListingError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "authentication authority is temporarily unavailable",
        ),
        AuthenticationMethodListingError::Failed => {
            return failed_closed(request_id, schema_digest);
        }
    };
    error_response(
        status,
        code,
        message,
        request_id,
        None,
        Vec::new(),
        schema_digest,
    )
}

fn failed_closed(request_id: String, schema_digest: HeaderValue) -> Response<Body> {
    internal_error_response(
        request_id,
        None,
        schema_digest,
        "authentication-method inventory failed closed",
    )
}

/// Router construction failure.
#[derive(Debug, Error)]
pub enum AuthenticationMethodListingApiError {
    /// The authoritative `OpenAPI` document could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
