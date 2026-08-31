// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated upload status and bounded range-page handlers.

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{Response, StatusCode};
use meshspan_api_contract::{
    UploadId, encode_list_upload_ranges_response, encode_upload_status_response,
};

use super::{NativeUploadApiState, UploadExecutionError, authenticate, execute, response};
use crate::NativeFileRequestProtection;
use crate::api_http::{current_time, request_identifier};
use crate::native_upload_api::NativeUploadController;
use crate::native_upload_api::codec::parse_range_page_query;

pub(super) async fn get_upload<C>(
    State(state): State<NativeUploadApiState<C>>,
    Path(upload_id): Path<String>,
    request: Request,
) -> Response<Body>
where
    C: NativeUploadController,
{
    let request_id = request_identifier();
    if UploadId::parse(&upload_id).is_none() {
        return response::invalid(
            StatusCode::BAD_REQUEST,
            "upload identifier is invalid",
            request_id,
            None,
            Vec::new(),
            state.schema_digest,
        );
    }
    let Some(now) = current_time() else {
        return response::execution(
            UploadExecutionError::Unavailable,
            request_id,
            None,
            state.schema_digest,
        );
    };
    let context = match authenticate(
        &state,
        request.headers().clone(),
        NativeFileRequestProtection::Read,
        now,
    )
    .await
    {
        Ok(context) => context,
        Err(error) => {
            return response::execution(error, request_id, None, state.schema_digest);
        }
    };
    let execution = execute(&state, move |controller| {
        controller
            .get_upload(context, &upload_id)
            .map_err(UploadExecutionError::Service)
    })
    .await;
    match execution {
        Ok(result) => match encode_upload_status_response(&result) {
            Ok(body) => response::success(StatusCode::OK, body, state.schema_digest.clone()),
            Err(_) => response::execution(
                UploadExecutionError::Service(crate::native_upload_api::NativeUploadError::Failed),
                request_id,
                None,
                state.schema_digest,
            ),
        },
        Err(error) => response::execution(error, request_id, None, state.schema_digest),
    }
}

pub(super) async fn list_upload_ranges<C>(
    State(state): State<NativeUploadApiState<C>>,
    Path(upload_id): Path<String>,
    request: Request,
) -> Response<Body>
where
    C: NativeUploadController,
{
    let request_id = request_identifier();
    let (Some(_), Ok(page_request)) = (
        UploadId::parse(&upload_id),
        parse_range_page_query(request.uri().query()),
    ) else {
        return response::invalid(
            StatusCode::BAD_REQUEST,
            "upload range query is invalid",
            request_id,
            None,
            Vec::new(),
            state.schema_digest,
        );
    };
    let Some(now) = current_time() else {
        return response::execution(
            UploadExecutionError::Unavailable,
            request_id,
            None,
            state.schema_digest,
        );
    };
    let context = match authenticate(
        &state,
        request.headers().clone(),
        NativeFileRequestProtection::Read,
        now,
    )
    .await
    {
        Ok(context) => context,
        Err(error) => {
            return response::execution(error, request_id, None, state.schema_digest);
        }
    };
    let execution = execute(&state, move |controller| {
        controller
            .list_upload_ranges(context, &upload_id, page_request)
            .map_err(UploadExecutionError::Service)
    })
    .await;
    match execution {
        Ok(result) => match encode_list_upload_ranges_response(&result) {
            Ok(body) => response::success(StatusCode::OK, body, state.schema_digest.clone()),
            Err(_) => response::execution(
                UploadExecutionError::Service(crate::native_upload_api::NativeUploadError::Failed),
                request_id,
                None,
                state.schema_digest,
            ),
        },
        Err(error) => response::execution(error, request_id, None, state.schema_digest),
    }
}
