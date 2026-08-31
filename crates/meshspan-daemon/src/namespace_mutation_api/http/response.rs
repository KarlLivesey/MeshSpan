// SPDX-License-Identifier: GPL-2.0-only

//! Stable namespace-mutation HTTP responses and closed error mapping.

use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode};
use meshspan_api_contract::{ApiErrorCode, BoundaryError, OperationId};

use super::MutationExecutionError;
use crate::FileApiAuthenticationError;
use crate::api_http::{
    boundary_issues, error_response, internal_error_response, issue, json_response,
};
use crate::namespace_mutation_api::NativeNamespaceMutationError;

pub(super) fn encoded_success(
    encoded: Result<Vec<u8>, BoundaryError>,
    status: StatusCode,
    request_id: String,
    operation_id: Option<OperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    match encoded {
        Ok(body) => json_response(status, body, schema_digest),
        Err(_) => execution(
            MutationExecutionError::Service(NativeNamespaceMutationError::Failed),
            request_id,
            operation_id,
            schema_digest,
        ),
    }
}

pub(super) fn boundary_error(
    error: BoundaryError,
    request_id: String,
    operation_id: Option<OperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    match error {
        BoundaryError::InvalidSchema(_)
        | BoundaryError::DecodeMismatch
        | BoundaryError::EncodeMismatch => execution(
            MutationExecutionError::Service(NativeNamespaceMutationError::Failed),
            request_id,
            operation_id,
            schema_digest,
        ),
        error => error_response(
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "request does not satisfy the namespace-mutation contract",
            request_id,
            operation_id,
            boundary_issues(error),
            schema_digest,
        ),
    }
}

pub(super) fn invalid_envelope(request_id: String, schema_digest: HeaderValue) -> Response<Body> {
    error_response(
        StatusCode::BAD_REQUEST,
        ApiErrorCode::InvalidRequest,
        "namespace-mutation request envelope is invalid",
        request_id,
        None,
        Vec::new(),
        schema_digest,
    )
}

pub(super) fn body_too_large(request_id: String, schema_digest: HeaderValue) -> Response<Body> {
    error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        ApiErrorCode::InvalidRequest,
        "request body exceeds its byte limit",
        request_id,
        None,
        vec![issue("", "max_bytes")],
        schema_digest,
    )
}

pub(super) fn execution(
    error: MutationExecutionError,
    request_id: String,
    operation_id: Option<OperationId>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let (status, code, message) = match error {
        MutationExecutionError::Authentication(FileApiAuthenticationError::Rejected)
        | MutationExecutionError::Service(NativeNamespaceMutationError::AccessDenied) => (
            StatusCode::UNAUTHORIZED,
            ApiErrorCode::Unauthenticated,
            "authentication or access was rejected",
        ),
        MutationExecutionError::Service(NativeNamespaceMutationError::InvalidInput) => (
            StatusCode::BAD_REQUEST,
            ApiErrorCode::InvalidRequest,
            "namespace mutation is invalid",
        ),
        MutationExecutionError::Service(NativeNamespaceMutationError::NotFound) => (
            StatusCode::NOT_FOUND,
            ApiErrorCode::NotFound,
            "volume or namespace target was not found",
        ),
        MutationExecutionError::Service(NativeNamespaceMutationError::OperationConflict) => (
            StatusCode::CONFLICT,
            ApiErrorCode::OperationConflict,
            "operation identity conflicts with existing input",
        ),
        MutationExecutionError::Service(NativeNamespaceMutationError::StateConflict) => (
            StatusCode::CONFLICT,
            ApiErrorCode::StateConflict,
            "namespace state is no longer current",
        ),
        MutationExecutionError::Unavailable
        | MutationExecutionError::Authentication(
            FileApiAuthenticationError::AuthorityUnavailable,
        )
        | MutationExecutionError::Service(NativeNamespaceMutationError::Unavailable) => (
            StatusCode::SERVICE_UNAVAILABLE,
            ApiErrorCode::Busy,
            "namespace authority or storage is temporarily unavailable",
        ),
        MutationExecutionError::Authentication(
            FileApiAuthenticationError::InvalidGateway
            | FileApiAuthenticationError::AuthorityFailed,
        )
        | MutationExecutionError::Service(NativeNamespaceMutationError::Failed) => {
            return internal_error_response(
                request_id,
                operation_id,
                schema_digest,
                "native namespace-mutation API failed closed",
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
