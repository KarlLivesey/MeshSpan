// SPDX-License-Identifier: GPL-2.0-only

//! Native upload routes with authentication before request-body consumption.

mod mutation;
mod read;
mod response;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, HeaderValue};
use axum::routing::{get, post, put};
use meshspan_api_contract::generate_openapi;
use meshspan_filesystem::FilesystemAccessContext;
use thiserror::Error;

use super::{NativeUploadController, NativeUploadError};
use crate::{FileApiAuthenticationError, NativeFileRequestProtection};

pub(super) struct NativeUploadApiState<C> {
    controller: Arc<Mutex<C>>,
    schema_digest: HeaderValue,
}

impl<C> Clone for NativeUploadApiState<C> {
    fn clone(&self) -> Self {
        Self {
            controller: Arc::clone(&self.controller),
            schema_digest: self.schema_digest.clone(),
        }
    }
}

/// Builds every rolling native resumable-upload route.
///
/// # Errors
///
/// Fails if the Rust-authored contract or schema-digest header cannot be generated.
pub fn native_upload_api_router<C>(controller: C) -> Result<Router, NativeUploadApiError>
where
    C: NativeUploadController,
{
    let document = generate_openapi()?;
    let state = NativeUploadApiState {
        controller: Arc::new(Mutex::new(controller)),
        schema_digest: HeaderValue::from_str(document.digest())?,
    };
    Ok(Router::new()
        .route(
            "/api/latest/volumes/{volume_id}/uploads",
            post(mutation::begin_upload::<C>),
        )
        .route(
            "/api/latest/uploads/{upload_id}",
            get(read::get_upload::<C>),
        )
        .route(
            "/api/latest/uploads/{upload_id}/ranges",
            get(read::list_upload_ranges::<C>),
        )
        .route(
            "/api/latest/uploads/{upload_id}/ranges/{offset}",
            put(mutation::write_upload_range::<C>),
        )
        .route(
            "/api/latest/uploads/{upload_id}/commits",
            post(mutation::commit_upload::<C>),
        )
        .route(
            "/api/latest/uploads/{upload_id}/aborts",
            post(mutation::abort_upload::<C>),
        )
        .with_state(state))
}

pub(super) async fn authenticate<C>(
    state: &NativeUploadApiState<C>,
    headers: HeaderMap,
    protection: NativeFileRequestProtection,
    now: meshspan_domain::UnixMicros,
) -> Result<FilesystemAccessContext, UploadExecutionError>
where
    C: NativeUploadController,
{
    execute(state, move |controller| {
        controller
            .authenticate(&headers, protection, now)
            .map_err(UploadExecutionError::Authentication)
    })
    .await
}

pub(super) async fn execute<C, T, F>(
    state: &NativeUploadApiState<C>,
    operation: F,
) -> Result<T, UploadExecutionError>
where
    C: NativeUploadController,
    T: Send + 'static,
    F: FnOnce(&mut C) -> Result<T, UploadExecutionError> + Send + 'static,
{
    let controller = Arc::clone(&state.controller);
    tokio::task::spawn_blocking(move || {
        let mut controller = controller
            .lock()
            .map_err(|_| UploadExecutionError::Unavailable)?;
        operation(&mut controller)
    })
    .await
    .map_err(|_| UploadExecutionError::Unavailable)?
}

#[derive(Clone, Copy)]
pub(super) enum UploadExecutionError {
    Authentication(FileApiAuthenticationError),
    Service(NativeUploadError),
    Unavailable,
}

/// Native upload router construction failure.
#[derive(Debug, Error)]
pub enum NativeUploadApiError {
    /// The authoritative `OpenAPI` document could not be generated.
    #[error("public API contract generation failed")]
    Contract(#[from] serde_json::Error),
    /// The generated schema digest could not be represented as an HTTP header.
    #[error("public API schema digest is invalid")]
    Header(#[from] axum::http::header::InvalidHeaderValue),
}
