// SPDX-License-Identifier: GPL-2.0-only

//! Native namespace mutation routes with authentication before body consumption.

mod response;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, Response, StatusCode};
use axum::routing::post;
use meshspan_api_contract::{
    BoundaryError, CreateDirectoryRequest, DeleteObjectRequest, MAX_NAMESPACE_MUTATION_BYTES,
    OperationId, RenameObjectRequest, VolumeId, decode_create_directory_request,
    decode_delete_object_request, decode_rename_object_request, encode_create_directory_response,
    encode_delete_object_response, encode_rename_object_response, generate_openapi,
};
use meshspan_filesystem::FilesystemAccessContext;
use thiserror::Error;

use super::{NativeNamespaceMutationController, NativeNamespaceMutationError};
use crate::api_http::{current_time, has_json_content_type, request_identifier};
use crate::{FileApiAuthenticationError, NativeFileRequestProtection};

struct NamespaceMutationApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for NamespaceMutationApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds all rolling specialised namespace-mutation routes.
///
/// # Errors
///
/// Fails if the Rust-authored contract or schema-digest header cannot be generated.
pub fn native_namespace_mutation_api_router<C>(
    controller: C,
) -> Result<Router, NativeNamespaceMutationApiError>
where
    C: NativeNamespaceMutationController,
{
    let document = generate_openapi()?;
    let state = NamespaceMutationApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/volumes/{volume_id}/directories",
            post(create_directory::<C>),
        )
        .route(
            "/api/latest/volumes/{volume_id}/renames",
            post(rename_object::<C>),
        )
        .route(
            "/api/latest/volumes/{volume_id}/deletions",
            post(delete_object::<C>),
        )
        .with_state(state))
}

async fn create_directory<C>(
    State(state): State<NamespaceMutationApiState<C>>,
    Path(volume_id): Path<String>,
    request: Request,
) -> Response<Body>
where
    C: NativeNamespaceMutationController,
{
    execute_json_mutation(
        state,
        volume_id,
        request,
        decode_create_directory_request,
        |controller, context, volume_id, request: CreateDirectoryRequest| {
            controller.create_directory(context, volume_id, request)
        },
        encode_create_directory_response,
        StatusCode::CREATED,
    )
    .await
}

async fn rename_object<C>(
    State(state): State<NamespaceMutationApiState<C>>,
    Path(volume_id): Path<String>,
    request: Request,
) -> Response<Body>
where
    C: NativeNamespaceMutationController,
{
    execute_json_mutation(
        state,
        volume_id,
        request,
        decode_rename_object_request,
        |controller, context, volume_id, request: RenameObjectRequest| {
            controller.rename_object(context, volume_id, request)
        },
        encode_rename_object_response,
        StatusCode::OK,
    )
    .await
}

async fn delete_object<C>(
    State(state): State<NamespaceMutationApiState<C>>,
    Path(volume_id): Path<String>,
    request: Request,
) -> Response<Body>
where
    C: NativeNamespaceMutationController,
{
    execute_json_mutation(
        state,
        volume_id,
        request,
        decode_delete_object_request,
        |controller, context, volume_id, request: DeleteObjectRequest| {
            controller.delete_object(context, volume_id, request)
        },
        encode_delete_object_response,
        StatusCode::OK,
    )
    .await
}

async fn execute_json_mutation<C, Q, S>(
    state: NamespaceMutationApiState<C>,
    volume_id: String,
    request: Request,
    decode: fn(&[u8]) -> Result<Q, BoundaryError>,
    service: fn(
        &mut C,
        FilesystemAccessContext,
        &str,
        Q,
    ) -> Result<S, NativeNamespaceMutationError>,
    encode: fn(&S) -> Result<Vec<u8>, BoundaryError>,
    success_status: StatusCode,
) -> Response<Body>
where
    C: NativeNamespaceMutationController,
    Q: HasOperationId + Send + 'static,
    S: Send + 'static,
{
    let request_id = request_identifier();
    if VolumeId::parse(&volume_id).is_none() || !has_json_content_type(request.headers()) {
        return response::invalid_envelope(request_id, state.schema_digest);
    }
    let (context, body) = match authenticated_body(&state, request, request_id.clone()).await {
        Ok(value) => value,
        Err(error) => return *error,
    };
    let request = match decode(&body) {
        Ok(value) => value,
        Err(error) => {
            return response::boundary_error(error, request_id, None, state.schema_digest);
        }
    };
    let operation_id = Some(request.operation_id().clone());
    let controller = Arc::clone(&state.controller);
    let execution = tokio::task::spawn_blocking(move || {
        let mut controller = controller
            .lock()
            .map_err(|_| MutationExecutionError::Unavailable)?;
        service(&mut controller, context, &volume_id, request)
            .map_err(MutationExecutionError::Service)
    })
    .await;
    match execution {
        Ok(Ok(result)) => response::encoded_success(
            encode(&result),
            success_status,
            request_id,
            operation_id,
            state.schema_digest,
        ),
        Ok(Err(error)) => response::execution(error, request_id, operation_id, state.schema_digest),
        Err(_) => response::execution(
            MutationExecutionError::Unavailable,
            request_id,
            operation_id,
            state.schema_digest,
        ),
    }
}

async fn authenticated_body<C>(
    state: &NamespaceMutationApiState<C>,
    request: Request,
    request_id: String,
) -> Result<(FilesystemAccessContext, Bytes), Box<Response<Body>>>
where
    C: NativeNamespaceMutationController,
{
    let now = current_time().ok_or_else(|| {
        Box::new(response::execution(
            MutationExecutionError::Unavailable,
            request_id.clone(),
            None,
            state.schema_digest.clone(),
        ))
    })?;
    let headers = request.headers().clone();
    let controller = Arc::clone(&state.controller);
    let context = tokio::task::spawn_blocking(move || {
        controller
            .lock()
            .map_err(|_| MutationExecutionError::Unavailable)?
            .authenticate(&headers, NativeFileRequestProtection::Mutation, now)
            .map_err(MutationExecutionError::Authentication)
    })
    .await
    .map_err(|_| MutationExecutionError::Unavailable)
    .and_then(|result| result)
    .map_err(|error| {
        Box::new(response::execution(
            error,
            request_id.clone(),
            None,
            state.schema_digest.clone(),
        ))
    })?;
    to_bytes(request.into_body(), MAX_NAMESPACE_MUTATION_BYTES)
        .await
        .map(|body| (context, body))
        .map_err(|_| {
            Box::new(response::body_too_large(
                request_id,
                state.schema_digest.clone(),
            ))
        })
}

trait HasOperationId {
    fn operation_id(&self) -> &OperationId;
}

impl HasOperationId for CreateDirectoryRequest {
    fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }
}

impl HasOperationId for RenameObjectRequest {
    fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }
}

impl HasOperationId for DeleteObjectRequest {
    fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }
}

#[derive(Clone, Copy)]
enum MutationExecutionError {
    Authentication(FileApiAuthenticationError),
    Service(NativeNamespaceMutationError),
    Unavailable,
}

/// Native namespace-mutation router construction failure.
#[derive(Debug, Error)]
pub enum NativeNamespaceMutationApiError {
    /// The authoritative `OpenAPI` document could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
