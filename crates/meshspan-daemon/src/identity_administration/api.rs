// SPDX-License-Identifier: GPL-2.0-only

//! Bounded manager-only user/group administration routes.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::routing::get;
use meshspan_api_contract::{
    AddGroupMemberRequest, AddGroupMemberResponse, ApiErrorCode, BoundaryError, CreateGroupRequest,
    CreatePrincipalResponse, CreateUserRequest, GroupMembershipCursor, ListGroupMembershipsQuery,
    ListGroupMembershipsResponse, ListPrincipalsQuery, ListPrincipalsResponse,
    MAX_CREATE_PRINCIPAL_BYTES, MAX_GROUP_MEMBERSHIP_MUTATION_BYTES, PrincipalCursor, PrincipalId,
    PrincipalKind, RemoveGroupMemberRequest, RemoveGroupMemberResponse,
    decode_add_group_member_request, decode_create_group_request, decode_create_user_request,
    decode_remove_group_member_request, encode_add_group_member_response,
    encode_create_principal_response, encode_list_group_memberships_response,
    encode_list_principals_response, encode_remove_group_member_response, generate_openapi,
};
use thiserror::Error;

use super::{IdentityAdministrationController, IdentityAdministrationError, IdentityAdministrator};
use crate::BrowserRequestProtection;
use crate::api_http::{
    boundary_issues, current_time, error_response, has_json_content_type, internal_error_response,
    issue, json_response, request_identifier,
};
use crate::native_query::has_valid_percent_encoding;

struct IdentityAdministrationApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for IdentityAdministrationApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds rolling manager-only user and group administration routes.
///
/// # Errors
///
/// Fails if the Rust-authored contract or schema-digest header cannot be generated.
pub fn identity_administration_api_router<C>(
    controller: C,
) -> Result<Router, IdentityAdministrationApiError>
where
    C: IdentityAdministrationController,
{
    let document = generate_openapi()?;
    let state = IdentityAdministrationApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/admin/users",
            get(list_users::<C>).post(create_user::<C>),
        )
        .route(
            "/api/latest/admin/groups",
            get(list_groups::<C>).post(create_group::<C>),
        )
        .route(
            "/api/latest/admin/groups/{group_id}/members",
            get(list_group_members::<C>).post(add_group_member::<C>),
        )
        .route(
            "/api/latest/admin/groups/{group_id}/members/{member_principal_id}/removals",
            axum::routing::post(remove_group_member::<C>),
        )
        .with_state(state))
}

async fn list_users<C>(
    State(state): State<IdentityAdministrationApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: IdentityAdministrationController,
{
    list(state, request, PrincipalKind::User).await
}

async fn list_groups<C>(
    State(state): State<IdentityAdministrationApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: IdentityAdministrationController,
{
    list(state, request, PrincipalKind::Group).await
}

async fn list<C>(
    state: IdentityAdministrationApiState<C>,
    request: Request,
    kind: PrincipalKind,
) -> Response<Body>
where
    C: IdentityAdministrationController,
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
            "identity-list query is invalid",
            request_id,
            vec![issue("", "query")],
        );
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| IdentityAdministrationError::Unavailable)?
            .list_principals(administrator, kind, query)
    })
    .await;
    match execution {
        Ok(Ok(response)) => encoded_page(&state, &response, request_id),
        Ok(Err(error)) => service_error(&state, error, request_id, None),
        Err(_) => service_error(
            &state,
            IdentityAdministrationError::Unavailable,
            request_id,
            None,
        ),
    }
}

async fn create_user<C>(
    State(state): State<IdentityAdministrationApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: IdentityAdministrationController,
{
    let request_id = request_identifier();
    let (administrator, body) = match authenticated_body(
        &state,
        request,
        MAX_CREATE_PRINCIPAL_BYTES,
        "identity-creation body exceeds its bound",
        request_id.clone(),
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let decoded = match decode_create_user_request(&body) {
        Ok(value) => value,
        Err(error) => return boundary_error(&state, error, request_id),
    };
    execute_creation(
        state,
        administrator,
        decoded,
        request_id,
        IdentityAdministrationController::create_user,
    )
    .await
}

async fn create_group<C>(
    State(state): State<IdentityAdministrationApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: IdentityAdministrationController,
{
    let request_id = request_identifier();
    let (administrator, body) = match authenticated_body(
        &state,
        request,
        MAX_CREATE_PRINCIPAL_BYTES,
        "identity-creation body exceeds its bound",
        request_id.clone(),
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let decoded = match decode_create_group_request(&body) {
        Ok(value) => value,
        Err(error) => return boundary_error(&state, error, request_id),
    };
    execute_creation(
        state,
        administrator,
        decoded,
        request_id,
        IdentityAdministrationController::create_group,
    )
    .await
}

async fn list_group_members<C>(
    Path(group_id): Path<String>,
    State(state): State<IdentityAdministrationApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: IdentityAdministrationController,
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
    let (Some(group_id), Ok(query)) = (
        PrincipalId::parse(&group_id),
        parse_membership_query(request.uri().query()),
    ) else {
        return public_error(
            &state,
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "group-membership path or query is invalid",
            request_id,
            vec![issue("", "query")],
        );
    };
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| IdentityAdministrationError::Unavailable)?
            .list_group_memberships(administrator, &group_id, query)
    })
    .await;
    match execution {
        Ok(Ok(response)) => encoded_membership_page(&state, &response, request_id),
        Ok(Err(error)) => service_error(&state, error, request_id, None),
        Err(_) => service_error(
            &state,
            IdentityAdministrationError::Unavailable,
            request_id,
            None,
        ),
    }
}

async fn add_group_member<C>(
    Path(group_id): Path<String>,
    State(state): State<IdentityAdministrationApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: IdentityAdministrationController,
{
    let request_id = request_identifier();
    let (administrator, body) = match authenticated_body(
        &state,
        request,
        MAX_GROUP_MEMBERSHIP_MUTATION_BYTES,
        "group-membership body exceeds its bound",
        request_id.clone(),
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let Some(group_id) = PrincipalId::parse(&group_id) else {
        return invalid_membership_path(&state, request_id);
    };
    let decoded = match decode_add_group_member_request(&body) {
        Ok(value) => value,
        Err(error) => return boundary_error(&state, error, request_id),
    };
    execute_membership_addition(state, administrator, group_id, decoded, request_id).await
}

async fn remove_group_member<C>(
    Path((group_id, member_principal_id)): Path<(String, String)>,
    State(state): State<IdentityAdministrationApiState<C>>,
    request: Request,
) -> Response<Body>
where
    C: IdentityAdministrationController,
{
    let request_id = request_identifier();
    let (administrator, body) = match authenticated_body(
        &state,
        request,
        MAX_GROUP_MEMBERSHIP_MUTATION_BYTES,
        "group-membership body exceeds its bound",
        request_id.clone(),
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let (Some(group_id), Some(member_principal_id)) = (
        PrincipalId::parse(&group_id),
        PrincipalId::parse(&member_principal_id),
    ) else {
        return invalid_membership_path(&state, request_id);
    };
    let decoded = match decode_remove_group_member_request(&body) {
        Ok(value) => value,
        Err(error) => return boundary_error(&state, error, request_id),
    };
    execute_membership_removal(
        state,
        administrator,
        group_id,
        member_principal_id,
        decoded,
        request_id,
    )
    .await
}

async fn execute_membership_addition<C>(
    state: IdentityAdministrationApiState<C>,
    administrator: IdentityAdministrator,
    group_id: PrincipalId,
    request: AddGroupMemberRequest,
    request_id: String,
) -> Response<Body>
where
    C: IdentityAdministrationController,
{
    let operation_id = request.operation_id.clone();
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| IdentityAdministrationError::Unavailable)?
            .add_group_member(administrator, &group_id, request)
    })
    .await;
    membership_addition_response(&state, execution, request_id, operation_id)
}

async fn execute_membership_removal<C>(
    state: IdentityAdministrationApiState<C>,
    administrator: IdentityAdministrator,
    group_id: PrincipalId,
    member_principal_id: PrincipalId,
    request: RemoveGroupMemberRequest,
    request_id: String,
) -> Response<Body>
where
    C: IdentityAdministrationController,
{
    let operation_id = request.operation_id.clone();
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| IdentityAdministrationError::Unavailable)?
            .remove_group_member(administrator, &group_id, &member_principal_id, request)
    })
    .await;
    membership_removal_response(&state, execution, request_id, operation_id)
}

async fn execute_creation<C, Q>(
    state: IdentityAdministrationApiState<C>,
    administrator: IdentityAdministrator,
    request: Q,
    request_id: String,
    create: fn(
        &mut C,
        IdentityAdministrator,
        Q,
    ) -> Result<CreatePrincipalResponse, IdentityAdministrationError>,
) -> Response<Body>
where
    C: IdentityAdministrationController,
    Q: CreationRequest + Send + 'static,
{
    let operation_id = request.operation_id().clone();
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        let mut controller = controller
            .lock()
            .map_err(|_| IdentityAdministrationError::Unavailable)?;
        create(&mut controller, administrator, request)
    })
    .await;
    match execution {
        Ok(Ok(response)) => match encode_create_principal_response(&response) {
            Ok(body) => json_response(StatusCode::CREATED, body, state.schema_digest),
            Err(_) => failed_closed(&state, request_id, Some(operation_id)),
        },
        Ok(Err(error)) => service_error(&state, error, request_id, Some(operation_id)),
        Err(_) => service_error(
            &state,
            IdentityAdministrationError::Unavailable,
            request_id,
            Some(operation_id),
        ),
    }
}

async fn authenticated_body<C>(
    state: &IdentityAdministrationApiState<C>,
    request: Request,
    maximum_bytes: usize,
    oversized_message: &'static str,
    request_id: String,
) -> Result<(IdentityAdministrator, Bytes), Box<Response<Body>>>
where
    C: IdentityAdministrationController,
{
    if !has_json_content_type(request.headers()) {
        return Err(Box::new(public_error(
            state,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ApiErrorCode::InvalidRequest,
            "content type must be application/json",
            request_id,
            vec![issue("", "content_type")],
        )));
    }
    let administrator = authenticate(
        state,
        request.headers(),
        BrowserRequestProtection::Mutation,
        request_id.clone(),
    )
    .await?;
    to_bytes(request.into_body(), maximum_bytes)
        .await
        .map(|body| (administrator, body))
        .map_err(|_| {
            Box::new(public_error(
                state,
                StatusCode::PAYLOAD_TOO_LARGE,
                ApiErrorCode::InvalidRequest,
                oversized_message,
                request_id,
                vec![issue("", "max_bytes")],
            ))
        })
}

async fn authenticate<C>(
    state: &IdentityAdministrationApiState<C>,
    headers: &HeaderMap,
    protection: BrowserRequestProtection,
    request_id: String,
) -> Result<IdentityAdministrator, Box<Response<Body>>>
where
    C: IdentityAdministrationController,
{
    let Some(now) = current_time() else {
        return Err(Box::new(failed_closed(state, request_id, None)));
    };
    let headers = headers.clone();
    let controller = Arc::clone(&state.controller);
    tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| IdentityAdministrationError::Unavailable)?
            .authenticate(&headers, protection, now)
    })
    .await
    .map_err(|_| IdentityAdministrationError::Unavailable)
    .and_then(|result| result)
    .map_err(|error| Box::new(service_error(state, error, request_id, None)))
}

fn parse_query(raw_query: Option<&str>) -> Result<ListPrincipalsQuery, ()> {
    let Some(raw_query) = raw_query.filter(|value| !value.is_empty()) else {
        return Ok(ListPrincipalsQuery::default());
    };
    if raw_query.len() > 4_096 || !has_valid_percent_encoding(raw_query.as_bytes()) {
        return Err(());
    }
    let mut query = ListPrincipalsQuery::default();
    let mut cursor_seen = false;
    let mut limit_seen = false;
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "cursor" if !cursor_seen => {
                cursor_seen = true;
                query.cursor = Some(PrincipalCursor::from_encoded(value.into_owned()).ok_or(())?);
            }
            "limit" if !limit_seen => {
                limit_seen = true;
                query.limit = Some(
                    value
                        .parse::<u16>()
                        .ok()
                        .filter(|value| *value > 0)
                        .ok_or(())?,
                );
            }
            _ => return Err(()),
        }
    }
    Ok(query)
}

fn parse_membership_query(raw_query: Option<&str>) -> Result<ListGroupMembershipsQuery, ()> {
    let Some(raw_query) = raw_query.filter(|value| !value.is_empty()) else {
        return Ok(ListGroupMembershipsQuery::default());
    };
    if raw_query.len() > 4_096 || !has_valid_percent_encoding(raw_query.as_bytes()) {
        return Err(());
    }
    let mut query = ListGroupMembershipsQuery::default();
    let mut cursor_seen = false;
    let mut limit_seen = false;
    for (name, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match name.as_ref() {
            "cursor" if !cursor_seen => {
                cursor_seen = true;
                query.cursor =
                    Some(GroupMembershipCursor::from_encoded(value.into_owned()).ok_or(())?);
            }
            "limit" if !limit_seen => {
                limit_seen = true;
                query.limit = Some(
                    value
                        .parse::<u16>()
                        .ok()
                        .filter(|value| *value > 0)
                        .ok_or(())?,
                );
            }
            _ => return Err(()),
        }
    }
    Ok(query)
}

fn encoded_page<C>(
    state: &IdentityAdministrationApiState<C>,
    response: &ListPrincipalsResponse,
    request_id: String,
) -> Response<Body> {
    match encode_list_principals_response(response) {
        Ok(body) => json_response(StatusCode::OK, body, state.schema_digest.clone()),
        Err(_) => failed_closed(state, request_id, None),
    }
}

fn encoded_membership_page<C>(
    state: &IdentityAdministrationApiState<C>,
    response: &ListGroupMembershipsResponse,
    request_id: String,
) -> Response<Body> {
    match encode_list_group_memberships_response(response) {
        Ok(body) => json_response(StatusCode::OK, body, state.schema_digest.clone()),
        Err(_) => failed_closed(state, request_id, None),
    }
}

fn membership_addition_response<C>(
    state: &IdentityAdministrationApiState<C>,
    execution: Result<
        Result<AddGroupMemberResponse, IdentityAdministrationError>,
        tokio::task::JoinError,
    >,
    request_id: String,
    operation_id: meshspan_api_contract::OperationId,
) -> Response<Body> {
    match execution {
        Ok(Ok(response)) => match encode_add_group_member_response(&response) {
            Ok(body) => json_response(StatusCode::CREATED, body, state.schema_digest.clone()),
            Err(_) => failed_closed(state, request_id, Some(operation_id)),
        },
        Ok(Err(error)) => service_error(state, error, request_id, Some(operation_id)),
        Err(_) => service_error(
            state,
            IdentityAdministrationError::Unavailable,
            request_id,
            Some(operation_id),
        ),
    }
}

fn membership_removal_response<C>(
    state: &IdentityAdministrationApiState<C>,
    execution: Result<
        Result<RemoveGroupMemberResponse, IdentityAdministrationError>,
        tokio::task::JoinError,
    >,
    request_id: String,
    operation_id: meshspan_api_contract::OperationId,
) -> Response<Body> {
    match execution {
        Ok(Ok(response)) => match encode_remove_group_member_response(&response) {
            Ok(body) => json_response(StatusCode::OK, body, state.schema_digest.clone()),
            Err(_) => failed_closed(state, request_id, Some(operation_id)),
        },
        Ok(Err(error)) => service_error(state, error, request_id, Some(operation_id)),
        Err(_) => service_error(
            state,
            IdentityAdministrationError::Unavailable,
            request_id,
            Some(operation_id),
        ),
    }
}

fn invalid_membership_path<C>(
    state: &IdentityAdministrationApiState<C>,
    request_id: String,
) -> Response<Body> {
    public_error(
        state,
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
        "group-membership path is invalid",
        request_id,
        vec![issue("", "path")],
    )
}

fn boundary_error<C>(
    state: &IdentityAdministrationApiState<C>,
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
        "identity-administration request is invalid",
        request_id,
        boundary_issues(error),
    )
}

fn service_error<C>(
    state: &IdentityAdministrationApiState<C>,
    error: IdentityAdministrationError,
    request_id: String,
    operation_id: Option<meshspan_api_contract::OperationId>,
) -> Response<Body> {
    let (status, code, message) = match error {
        IdentityAdministrationError::InvalidInput => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "identity-administration input is invalid",
        ),
        IdentityAdministrationError::Unauthenticated => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication was rejected",
        ),
        IdentityAdministrationError::Forbidden => (
            StatusCode::FORBIDDEN,
            ApiErrorCode::Forbidden,
            "system-manager authority is required",
        ),
        IdentityAdministrationError::Conflict => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "identity operation conflicts with committed state",
        ),
        IdentityAdministrationError::NotFound => (
            StatusCode::NOT_FOUND,
            ApiErrorCode::NotFound,
            "identity-administration resource was not found",
        ),
        IdentityAdministrationError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "identity authority is temporarily unavailable",
        ),
        IdentityAdministrationError::Failed => {
            return failed_closed(state, request_id, operation_id);
        }
    };
    error_response(
        status,
        code,
        message,
        request_id,
        operation_id,
        Vec::new(),
        state.schema_digest.clone(),
    )
}

fn public_error<C>(
    state: &IdentityAdministrationApiState<C>,
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

fn failed_closed<C>(
    state: &IdentityAdministrationApiState<C>,
    request_id: String,
    operation_id: Option<meshspan_api_contract::OperationId>,
) -> Response<Body> {
    internal_error_response(
        request_id,
        operation_id,
        state.schema_digest.clone(),
        "identity-administration failed closed",
    )
}

trait CreationRequest {
    fn operation_id(&self) -> &meshspan_api_contract::OperationId;
}

impl CreationRequest for CreateUserRequest {
    fn operation_id(&self) -> &meshspan_api_contract::OperationId {
        &self.operation_id
    }
}

impl CreationRequest for CreateGroupRequest {
    fn operation_id(&self) -> &meshspan_api_contract::OperationId {
        &self.operation_id
    }
}

/// Identity-administration router construction failure.
#[derive(Debug, Error)]
pub enum IdentityAdministrationApiError {
    /// The authoritative `OpenAPI` document could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
