// SPDX-License-Identifier: GPL-2.0-only

//! Bounded manager-only mesh topology routes.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::routing::{get, put};
use meshspan_api_contract::{
    ApiErrorCode, BoundaryError, ListFaultGroupMembershipsResponse, ListFaultGroupsResponse,
    ListTopologyNodesResponse, ListTopologyQuery, ListTopologyTargetsResponse,
    MAX_TOPOLOGY_MUTATION_BYTES, TopologyCursor, decode_create_fault_group_request,
    decode_set_fault_group_membership_request, encode_create_fault_group_response,
    encode_list_fault_group_memberships_response, encode_list_fault_groups_response,
    encode_list_topology_nodes_response, encode_list_topology_targets_response,
    encode_set_fault_group_membership_response, generate_openapi,
};
use thiserror::Error;

use super::{IdentityAdministrator, TopologyAdministrationController, TopologyAdministrationError};
use crate::BrowserRequestProtection;
use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    issue, json_response, request_identifier,
};
use crate::native_query::has_valid_percent_encoding;

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

#[derive(Clone, Copy)]
enum InventoryKind {
    Nodes,
    Targets,
    FaultGroups,
    Memberships,
}

enum InventoryPage {
    Nodes(ListTopologyNodesResponse),
    Targets(ListTopologyTargetsResponse),
    FaultGroups(ListFaultGroupsResponse),
    Memberships(ListFaultGroupMembershipsResponse),
}

/// Builds rolling manager-only mesh topology administration routes.
///
/// # Errors
///
/// Fails if the Rust-authored contract or schema-digest header cannot be generated.
pub fn topology_administration_api_router<C>(
    controller: C,
) -> Result<Router, TopologyAdministrationApiError>
where
    C: TopologyAdministrationController,
{
    let document = generate_openapi()?;
    Ok(Router::new()
        .route("/api/latest/admin/topology/nodes", get(list_nodes::<C>))
        .route("/api/latest/admin/topology/targets", get(list_targets::<C>))
        .route(
            "/api/latest/admin/topology/fault-groups",
            get(list_fault_groups::<C>).post(create_fault_group::<C>),
        )
        .route(
            "/api/latest/admin/topology/fault-group-memberships",
            get(list_memberships::<C>),
        )
        .route(
            "/api/latest/admin/topology/fault-groups/{group_id}/hosts/{host_id}",
            put(set_membership::<C>),
        )
        .with_state(ApiState {
            controller: Arc::new(Mutex::new(controller)),
            schema_digest: HeaderValue::from_str(document.digest())?,
        }))
}

async fn list_nodes<C>(State(state): State<ApiState<C>>, request: Request) -> Response<Body>
where
    C: TopologyAdministrationController,
{
    list(state, request, InventoryKind::Nodes).await
}

async fn list_targets<C>(State(state): State<ApiState<C>>, request: Request) -> Response<Body>
where
    C: TopologyAdministrationController,
{
    list(state, request, InventoryKind::Targets).await
}

async fn list_fault_groups<C>(State(state): State<ApiState<C>>, request: Request) -> Response<Body>
where
    C: TopologyAdministrationController,
{
    list(state, request, InventoryKind::FaultGroups).await
}

async fn list_memberships<C>(State(state): State<ApiState<C>>, request: Request) -> Response<Body>
where
    C: TopologyAdministrationController,
{
    list(state, request, InventoryKind::Memberships).await
}

async fn list<C>(state: ApiState<C>, request: Request, kind: InventoryKind) -> Response<Body>
where
    C: TopologyAdministrationController,
{
    let request_id = request_identifier();
    let administrator = match authenticate(
        &state,
        request.headers(),
        BrowserRequestProtection::Read,
        request_id.clone(),
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let Ok(query) = parse_query(request.uri().query()) else {
        return public_error(
            &state,
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "topology-list query is invalid",
            request_id,
            vec![issue("", "query")],
        );
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        let controller = controller
            .lock()
            .map_err(|_| TopologyAdministrationError::Unavailable)?;
        match kind {
            InventoryKind::Nodes => controller
                .list_nodes(administrator, query)
                .map(InventoryPage::Nodes),
            InventoryKind::Targets => controller
                .list_targets(administrator, query)
                .map(InventoryPage::Targets),
            InventoryKind::FaultGroups => controller
                .list_fault_groups(administrator, query)
                .map(InventoryPage::FaultGroups),
            InventoryKind::Memberships => controller
                .list_fault_group_memberships(administrator, query)
                .map(InventoryPage::Memberships),
        }
    })
    .await;
    match execution {
        Ok(Ok(page)) => encode_page(&state, page, request_id),
        Ok(Err(error)) => service_error(&state, error, request_id),
        Err(_) => service_error(&state, TopologyAdministrationError::Unavailable, request_id),
    }
}

async fn create_fault_group<C>(State(state): State<ApiState<C>>, request: Request) -> Response<Body>
where
    C: TopologyAdministrationController,
{
    let request_id = request_identifier();
    let (administrator, body) = match authenticated_body(&state, request, request_id.clone()).await
    {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let decoded = match decode_create_fault_group_request(&body) {
        Ok(value) => value,
        Err(error) => return boundary_error(&state, error, request_id),
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| TopologyAdministrationError::Unavailable)?
            .create_fault_group(administrator, decoded)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_create_fault_group_response(&response) {
            Ok(body) => json_response(StatusCode::CREATED, body, state.schema_digest),
            Err(_) => failed(&state, request_id),
        },
        Ok(Err(error)) => service_error(&state, error, request_id),
        Err(_) => service_error(&state, TopologyAdministrationError::Unavailable, request_id),
    }
}

async fn set_membership<C>(
    State(state): State<ApiState<C>>,
    Path((group_id, host_id)): Path<(String, String)>,
    request: Request,
) -> Response<Body>
where
    C: TopologyAdministrationController,
{
    let request_id = request_identifier();
    let (administrator, body) = match authenticated_body(&state, request, request_id.clone()).await
    {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let decoded = match decode_set_fault_group_membership_request(&body) {
        Ok(value) => value,
        Err(error) => return boundary_error(&state, error, request_id),
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| TopologyAdministrationError::Unavailable)?
            .set_fault_group_membership(administrator, &group_id, &host_id, decoded)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_set_fault_group_membership_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest),
            Err(_) => failed(&state, request_id),
        },
        Ok(Err(error)) => service_error(&state, error, request_id),
        Err(_) => service_error(&state, TopologyAdministrationError::Unavailable, request_id),
    }
}

async fn authenticate<C>(
    state: &ApiState<C>,
    headers: &HeaderMap,
    protection: BrowserRequestProtection,
    request_id: String,
) -> Result<IdentityAdministrator, Box<Response<Body>>>
where
    C: TopologyAdministrationController,
{
    let Some(now) = current_time() else {
        return Err(Box::new(failed(state, request_id)));
    };
    let headers = headers.clone();
    let controller = Arc::clone(&state.controller);
    match tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| TopologyAdministrationError::Unavailable)?
            .authenticate(&headers, protection, now)
    })
    .await
    {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(Box::new(service_error(state, error, request_id))),
        Err(_) => Err(Box::new(failed(state, request_id))),
    }
}

async fn authenticated_body<C>(
    state: &ApiState<C>,
    request: Request,
    request_id: String,
) -> Result<(IdentityAdministrator, Bytes), Box<Response<Body>>>
where
    C: TopologyAdministrationController,
{
    let administrator = authenticate(
        state,
        request.headers(),
        BrowserRequestProtection::Mutation,
        request_id.clone(),
    )
    .await?;
    if !has_json_content_type(request.headers()) {
        return Err(Box::new(public_error(
            state,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ApiErrorCode::InvalidRequest,
            "topology mutation requires application/json",
            request_id,
            Vec::new(),
        )));
    }
    let body = to_bytes(request.into_body(), MAX_TOPOLOGY_MUTATION_BYTES)
        .await
        .map_err(|_| {
            Box::new(public_error(
                state,
                StatusCode::PAYLOAD_TOO_LARGE,
                ApiErrorCode::InvalidRequest,
                "topology mutation body exceeds its bound",
                request_id,
                Vec::new(),
            ))
        })?;
    Ok((administrator, body))
}

fn parse_query(raw_query: Option<&str>) -> Result<ListTopologyQuery, ()> {
    let Some(raw_query) = raw_query.filter(|value| !value.is_empty()) else {
        return Ok(ListTopologyQuery::default());
    };
    if raw_query.len() > 4_096 || !has_valid_percent_encoding(raw_query.as_bytes()) {
        return Err(());
    }
    let mut query = ListTopologyQuery::default();
    let mut cursor_seen = false;
    let mut limit_seen = false;
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "cursor" if !cursor_seen => {
                cursor_seen = true;
                query.cursor = Some(TopologyCursor::from_encoded(value.into_owned()).ok_or(())?);
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

fn encode_page<C>(state: &ApiState<C>, page: InventoryPage, request_id: String) -> Response<Body> {
    let encoded = match page {
        InventoryPage::Nodes(value) => encode_list_topology_nodes_response(&value),
        InventoryPage::Targets(value) => encode_list_topology_targets_response(&value),
        InventoryPage::FaultGroups(value) => encode_list_fault_groups_response(&value),
        InventoryPage::Memberships(value) => encode_list_fault_group_memberships_response(&value),
    };
    match encoded {
        Ok(body) => json_response(StatusCode::OK, body, state.schema_digest.clone()),
        Err(_) => failed(state, request_id),
    }
}

fn boundary_error<C>(
    state: &ApiState<C>,
    error: BoundaryError,
    request_id: String,
) -> Response<Body> {
    let status = if matches!(error, BoundaryError::BodyTooLarge { .. }) {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        StatusCode::BAD_REQUEST
    };
    public_error(
        state,
        status,
        ApiErrorCode::InvalidRequest,
        "topology mutation body is invalid",
        request_id,
        boundary_issues(error),
    )
}

fn service_error<C>(
    state: &ApiState<C>,
    error: TopologyAdministrationError,
    request_id: String,
) -> Response<Body> {
    let (status, code, message) = match error {
        TopologyAdministrationError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "topology request is invalid",
        ),
        TopologyAdministrationError::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        TopologyAdministrationError::Forbidden => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "system-manager authority is required",
        ),
        TopologyAdministrationError::Conflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "topology operation conflicts with committed state",
        ),
        TopologyAdministrationError::NotFound => (
            StatusCode::NOT_FOUND,
            ApiErrorCode::NotFound,
            "machine or fault group was not found",
        ),
        TopologyAdministrationError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "topology authority is temporarily unavailable",
        ),
        TopologyAdministrationError::Failed => return failed(state, request_id),
    };
    public_error(state, status, code, message, request_id, Vec::new())
}

fn public_error<C>(
    state: &ApiState<C>,
    status: StatusCode,
    code: ApiErrorCode,
    message: &str,
    request_id: String,
    issues: Vec<meshspan_api_contract::ApiErrorIssue>,
) -> Response<Body> {
    error_response(
        status,
        code,
        message,
        request_id,
        None,
        issues,
        state.schema_digest.clone(),
    )
}

fn failed<C>(state: &ApiState<C>, request_id: String) -> Response<Body> {
    internal_error_response(
        request_id,
        None,
        state.schema_digest.clone(),
        "topology administration failed closed",
    )
}

/// Router-construction failures for topology administration.
#[derive(Debug, Error)]
pub enum TopologyAdministrationApiError {
    /// OpenAPI generation failed.
    #[error("topology administration OpenAPI generation failed: {0}")]
    OpenApi(#[from] serde_json::Error),
    /// Schema digest was not a valid HTTP header.
    #[error("topology administration schema digest is invalid: {0}")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
