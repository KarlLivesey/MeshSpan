// SPDX-License-Identifier: GPL-2.0-only

//! Bounded HTTP boundary for manager-only manual DNS challenge tasks.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::get;
use meshspan_api_contract::{
    ApiErrorCode, ListManualDnsTasksQuery, ManualDnsTaskCursor,
    encode_list_manual_dns_tasks_response, generate_openapi,
};
use thiserror::Error;

use crate::api_http::{
    current_time, error_response, internal_error_response, json_response, request_identifier,
};
use crate::native_query::has_valid_percent_encoding;
use crate::{
    BrowserRequestProtection, ManualDnsTaskAdministrationController,
    ManualDnsTaskAdministrationError,
};

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

/// Builds the authenticated deadline-ordered manual DNS task route.
///
/// # Errors
///
/// Fails when the Rust-authored contract or schema header cannot be generated.
pub fn manual_dns_task_administration_api_router<C>(
    controller: C,
) -> Result<Router, ManualDnsTaskAdministrationApiError>
where
    C: ManualDnsTaskAdministrationController,
{
    let document = generate_openapi()?;
    Ok(Router::new()
        .route(
            "/api/latest/admin/certificate-tasks/manual-dns",
            get(list::<C>),
        )
        .with_state(ApiState {
            controller: Arc::new(Mutex::new(controller)),
            schema_digest: HeaderValue::from_str(document.digest())?,
        }))
}

async fn list<C>(State(state): State<ApiState<C>>, request: Request) -> Response<Body>
where
    C: ManualDnsTaskAdministrationController,
{
    let request_id = request_identifier();
    let Some(now) = current_time() else {
        return failed(&state, request_id);
    };
    let controller = Arc::clone(&state.controller);
    let headers = request.headers().clone();
    let authentication = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| ManualDnsTaskAdministrationError::Unavailable)?
            .authenticate(&headers, BrowserRequestProtection::Read, now)
    })
    .await;
    let administrator = match authentication {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => return service_error(&state, error, request_id),
        Err(_) => return failed(&state, request_id),
    };
    let Ok(query) = parse_query(request.uri().query()) else {
        return service_error(
            &state,
            ManualDnsTaskAdministrationError::InvalidInput,
            request_id,
        );
    };
    let controller = Arc::clone(&state.controller);
    match tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| ManualDnsTaskAdministrationError::Unavailable)?
            .list_manual_dns_tasks(administrator, query)
    })
    .await
    {
        Ok(Ok(response)) => match encode_list_manual_dns_tasks_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed(&state, request_id),
        },
        Ok(Err(error)) => service_error(&state, error, request_id),
        Err(_) => failed(&state, request_id),
    }
}

fn parse_query(raw_query: Option<&str>) -> Result<ListManualDnsTasksQuery, ()> {
    let Some(raw_query) = raw_query.filter(|value| !value.is_empty()) else {
        return Ok(ListManualDnsTasksQuery::default());
    };
    if raw_query.len() > 4_096 || !has_valid_percent_encoding(raw_query.as_bytes()) {
        return Err(());
    }
    let mut query = ListManualDnsTasksQuery::default();
    let mut cursor_seen = false;
    let mut limit_seen = false;
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "cursor" if !cursor_seen => {
                cursor_seen = true;
                query.cursor =
                    Some(ManualDnsTaskCursor::from_encoded(value.into_owned()).ok_or(())?);
            }
            "limit" if !limit_seen => {
                limit_seen = true;
                query.limit = Some(value.parse::<u16>().map_err(|_| ())?);
            }
            _ => return Err(()),
        }
    }
    Ok(query)
}

fn service_error<C>(
    state: &ApiState<C>,
    error: ManualDnsTaskAdministrationError,
    request_id: String,
) -> Response<Body> {
    let (status, code, message) = match error {
        ManualDnsTaskAdministrationError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "manual DNS task query is invalid",
        ),
        ManualDnsTaskAdministrationError::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        ManualDnsTaskAdministrationError::Forbidden => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "system-manager authority is required",
        ),
        ManualDnsTaskAdministrationError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "certificate authority is temporarily unavailable",
        ),
        ManualDnsTaskAdministrationError::Failed => return failed(state, request_id),
    };
    error_response(
        status,
        code,
        message,
        request_id,
        None,
        Vec::new(),
        state.schema_digest.clone(),
    )
}

fn failed<C>(state: &ApiState<C>, request_id: String) -> Response<Body> {
    internal_error_response(
        request_id,
        None,
        state.schema_digest.clone(),
        "manual DNS task administration failed closed",
    )
}

/// Router-construction failure.
#[derive(Debug, Error)]
pub enum ManualDnsTaskAdministrationApiError {
    /// The authoritative public contract could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
