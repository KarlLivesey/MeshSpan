// SPDX-License-Identifier: GPL-2.0-only

//! Stable native-upload HTTP response and error mapping.

use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};
use meshspan_api_contract::{ApiErrorCode, ApiErrorIssue, OperationId};

use super::UploadExecutionError;
use crate::FileApiAuthenticationError;
use crate::api_http::{error_response, internal_error_response, json_response};

pub(super) fn success(
    status: StatusCode,
    body: Vec<u8>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    json_response(status, body, schema_digest)
}

pub(super) fn invalid(
    status: StatusCode,
    message: &'static str,
    request_id: String,
    operation_id: Option<OperationId>,
    issues: Vec<ApiErrorIssue>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    error_response(
        status,
        ApiErrorCode::InvalidRequest,
        message,
        request_id,
        operation_id,
        issues,
        schema_digest,
    )
}

pub(super) fn execution(
    error: UploadExecutionError,
    request_id: String,
    operation_id: Option<OperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let (status, code, message) = match error {
        UploadExecutionError::Authentication(FileApiAuthenticationError::Rejected)
        | UploadExecutionError::Service(super::super::NativeUploadError::AccessDenied) => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication or access was rejected",
        ),
        UploadExecutionError::Service(super::super::NativeUploadError::InvalidInput) => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "upload request is invalid",
        ),
        UploadExecutionError::Service(super::super::NativeUploadError::NotFound) => (
            StatusCode::NOT_FOUND,
            ApiErrorCode::NotFound,
            "upload, volume or destination was not found",
        ),
        UploadExecutionError::Service(super::super::NativeUploadError::OperationConflict) => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "upload operation identity conflicts with existing input",
        ),
        UploadExecutionError::Service(
            super::super::NativeUploadError::StateConflict
            | super::super::NativeUploadError::Incomplete,
        ) => (
            StatusCode::CONFLICT,
            ApiErrorCode::StateConflict,
            "upload checkpoint, fence or namespace state is not current",
        ),
        UploadExecutionError::Unavailable
        | UploadExecutionError::Authentication(FileApiAuthenticationError::AuthorityUnavailable)
        | UploadExecutionError::Service(super::super::NativeUploadError::Unavailable) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "upload authority or storage is temporarily unavailable",
        ),
        UploadExecutionError::Authentication(
            FileApiAuthenticationError::InvalidGateway
            | FileApiAuthenticationError::AuthorityFailed,
        )
        | UploadExecutionError::Service(super::super::NativeUploadError::Failed) => {
            return internal_error_response(
                request_id,
                operation_id,
                schema_digest,
                "native upload API failed closed",
            );
        }
    };
    error_response(
        status,
        code,
        message,
        request_id,
        operation_id,
        Vec::new(),
        schema_digest,
    )
}
