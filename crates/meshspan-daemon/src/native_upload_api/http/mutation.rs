// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated upload mutations with strict bounded body consumption.

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Path, Request, State};
use axum::http::{Response, StatusCode};
use meshspan_api_contract::{
    BoundaryError, MAX_ABORT_UPLOAD_BYTES, MAX_BEGIN_UPLOAD_BYTES, MAX_COMMIT_UPLOAD_BYTES,
    MAX_UPLOAD_RANGE_BYTES, OperationId, UploadId, VolumeId, decode_abort_upload_request,
    decode_begin_upload_request, decode_commit_upload_request, encode_abort_upload_response,
    encode_begin_upload_response, encode_commit_upload_response,
    encode_write_upload_range_response,
};
use meshspan_contracts::BoundedBytes;
use meshspan_filesystem::FilesystemAccessContext;

use super::{NativeUploadApiState, UploadExecutionError, authenticate, execute, response};
use crate::NativeFileRequestProtection;
use crate::api_http::{
    boundary_issues, current_time, has_content_type, has_json_content_type, issue,
    request_identifier,
};
use crate::native_upload_api::codec::{parse_range_headers, parse_range_offset};
use crate::native_upload_api::{
    NativeUploadController, NativeUploadError, UploadRangeWriteRequest,
};

pub(super) async fn begin_upload<C>(
    State(state): State<NativeUploadApiState<C>>,
    Path(volume_id): Path<String>,
    request: Request,
) -> Response<Body>
where
    C: NativeUploadController,
{
    let request_id = request_identifier();
    if VolumeId::parse(&volume_id).is_none() || !has_json_content_type(request.headers()) {
        return invalid_envelope(request_id, state.schema_digest);
    }
    let (context, bytes) =
        match authenticated_body(&state, request, MAX_BEGIN_UPLOAD_BYTES, request_id.clone()).await
        {
            Ok(value) => value,
            Err(response) => return *response,
        };
    let request = match decode_begin_upload_request(&bytes) {
        Ok(request) => request,
        Err(error) => return boundary_error(error, request_id, None, state.schema_digest),
    };
    let operation_id = Some(request.operation_id.clone());
    let execution = execute(&state, move |controller| {
        controller
            .begin_upload(context, &volume_id, request)
            .map_err(UploadExecutionError::Service)
    })
    .await;
    match execution {
        Ok(result) => encoded_success(
            encode_begin_upload_response(&result),
            StatusCode::CREATED,
            request_id,
            operation_id,
            state.schema_digest,
        ),
        Err(error) => response::execution(error, request_id, operation_id, state.schema_digest),
    }
}

pub(super) async fn commit_upload<C>(
    State(state): State<NativeUploadApiState<C>>,
    Path(upload_id): Path<String>,
    request: Request,
) -> Response<Body>
where
    C: NativeUploadController,
{
    let request_id = request_identifier();
    if UploadId::parse(&upload_id).is_none() || !has_json_content_type(request.headers()) {
        return invalid_envelope(request_id, state.schema_digest);
    }
    let (context, bytes) = match authenticated_body(
        &state,
        request,
        MAX_COMMIT_UPLOAD_BYTES,
        request_id.clone(),
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let request = match decode_commit_upload_request(&bytes) {
        Ok(request) => request,
        Err(error) => return boundary_error(error, request_id, None, state.schema_digest),
    };
    let operation_id = Some(request.operation_id.clone());
    let execution = execute(&state, move |controller| {
        controller
            .commit_upload(context, &upload_id, request)
            .map_err(UploadExecutionError::Service)
    })
    .await;
    match execution {
        Ok(result) => encoded_success(
            encode_commit_upload_response(&result),
            StatusCode::OK,
            request_id,
            operation_id,
            state.schema_digest,
        ),
        Err(error) => response::execution(error, request_id, operation_id, state.schema_digest),
    }
}

pub(super) async fn abort_upload<C>(
    State(state): State<NativeUploadApiState<C>>,
    Path(upload_id): Path<String>,
    request: Request,
) -> Response<Body>
where
    C: NativeUploadController,
{
    let request_id = request_identifier();
    if UploadId::parse(&upload_id).is_none() || !has_json_content_type(request.headers()) {
        return invalid_envelope(request_id, state.schema_digest);
    }
    let (context, bytes) =
        match authenticated_body(&state, request, MAX_ABORT_UPLOAD_BYTES, request_id.clone()).await
        {
            Ok(value) => value,
            Err(response) => return *response,
        };
    let request = match decode_abort_upload_request(&bytes) {
        Ok(request) => request,
        Err(error) => return boundary_error(error, request_id, None, state.schema_digest),
    };
    let operation_id = Some(request.operation_id.clone());
    let execution = execute(&state, move |controller| {
        controller
            .abort_upload(context, &upload_id, request)
            .map_err(UploadExecutionError::Service)
    })
    .await;
    match execution {
        Ok(result) => encoded_success(
            encode_abort_upload_response(&result),
            StatusCode::OK,
            request_id,
            operation_id,
            state.schema_digest,
        ),
        Err(error) => response::execution(error, request_id, operation_id, state.schema_digest),
    }
}

pub(super) async fn write_upload_range<C>(
    State(state): State<NativeUploadApiState<C>>,
    Path((upload_id, offset)): Path<(String, String)>,
    request: Request,
) -> Response<Body>
where
    C: NativeUploadController,
{
    let request_id = request_identifier();
    let fields = match (
        UploadId::parse(&upload_id),
        parse_range_offset(&offset),
        parse_range_headers(request.headers()),
        has_content_type(request.headers(), "application/octet-stream"),
    ) {
        (Some(_), Ok(offset), Ok(headers), true) => (offset, headers),
        _ => return invalid_envelope(request_id, state.schema_digest),
    };
    let operation_id = Some(fields.1.operation_id.clone());
    let (context, bytes) =
        match authenticated_body(&state, request, MAX_UPLOAD_RANGE_BYTES, request_id.clone()).await
        {
            Ok(value) => value,
            Err(response) => return *response,
        };
    let bytes = match BoundedBytes::copy_from(&bytes, MAX_UPLOAD_RANGE_BYTES) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        _ => {
            return response::invalid(
                StatusCode::BAD_REQUEST,
                "upload range body is invalid",
                request_id,
                operation_id,
                vec![issue("", "range_bytes")],
                state.schema_digest,
            );
        }
    };
    let range = UploadRangeWriteRequest {
        operation_id: fields.1.operation_id,
        stage_fence: fields.1.stage_fence,
        offset: fields.0,
        content_blake3: fields.1.content_blake3,
        bytes,
    };
    let execution = execute(&state, move |controller| {
        controller
            .write_upload_range(context, &upload_id, range)
            .map_err(UploadExecutionError::Service)
    })
    .await;
    match execution {
        Ok(result) => encoded_success(
            encode_write_upload_range_response(&result),
            StatusCode::OK,
            request_id,
            operation_id,
            state.schema_digest,
        ),
        Err(error) => response::execution(error, request_id, operation_id, state.schema_digest),
    }
}

async fn authenticated_body<C>(
    state: &NativeUploadApiState<C>,
    request: Request,
    maximum_bytes: usize,
    request_id: String,
) -> Result<(FilesystemAccessContext, Bytes), Box<Response<Body>>>
where
    C: NativeUploadController,
{
    let Some(now) = current_time() else {
        return Err(Box::new(response::execution(
            UploadExecutionError::Unavailable,
            request_id,
            None,
            state.schema_digest.clone(),
        )));
    };
    let context = authenticate(
        state,
        request.headers().clone(),
        NativeFileRequestProtection::Mutation,
        now,
    )
    .await
    .map_err(|error| {
        Box::new(response::execution(
            error,
            request_id.clone(),
            None,
            state.schema_digest.clone(),
        ))
    })?;
    let bytes = to_bytes(request.into_body(), maximum_bytes)
        .await
        .map_err(|_| {
            Box::new(response::invalid(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds its byte limit",
                request_id,
                None,
                vec![issue("", "max_bytes")],
                state.schema_digest.clone(),
            ))
        })?;
    Ok((context, bytes))
}

fn encoded_success(
    encoded: Result<Vec<u8>, BoundaryError>,
    status: StatusCode,
    request_id: String,
    operation_id: Option<OperationId>,
    schema_digest: axum::http::HeaderValue,
) -> Response<Body> {
    match encoded {
        Ok(body) => response::success(status, body, schema_digest),
        Err(_) => response::execution(
            UploadExecutionError::Service(NativeUploadError::Failed),
            request_id,
            operation_id,
            schema_digest,
        ),
    }
}

fn boundary_error(
    error: BoundaryError,
    request_id: String,
    operation_id: Option<OperationId>,
    schema_digest: axum::http::HeaderValue,
) -> Response<Body> {
    match error {
        BoundaryError::InvalidSchema(_)
        | BoundaryError::DecodeMismatch
        | BoundaryError::EncodeMismatch => response::execution(
            UploadExecutionError::Service(NativeUploadError::Failed),
            request_id,
            operation_id,
            schema_digest,
        ),
        error => response::invalid(
            StatusCode::BAD_REQUEST,
            "request does not satisfy the public upload contract",
            request_id,
            operation_id,
            boundary_issues(error),
            schema_digest,
        ),
    }
}

fn invalid_envelope(request_id: String, schema_digest: axum::http::HeaderValue) -> Response<Body> {
    response::invalid(
        StatusCode::BAD_REQUEST,
        "upload request envelope is invalid",
        request_id,
        None,
        Vec::new(),
        schema_digest,
    )
}
