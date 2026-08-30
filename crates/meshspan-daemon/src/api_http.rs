// SPDX-License-Identifier: GPL-2.0-only

//! Shared public HTTP envelope, contract headers and bounded error helpers.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use meshspan_api_contract::{
    ApiError, ApiErrorCode, ApiErrorIssue, BoundaryError, OperationId as ApiOperationId,
    encode_api_error,
};
use meshspan_domain::UnixMicros;
use sha2::{Digest, Sha256};

use crate::create_mesh_setup::format_uuid;

pub(crate) const API_VERSION_HEADER: HeaderName = HeaderName::from_static("meshspan-api-version");
pub(crate) const API_SCHEMA_HEADER: HeaderName = HeaderName::from_static("meshspan-api-schema");
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(crate) fn error_response(
    status: StatusCode,
    code: ApiErrorCode,
    message: &str,
    request_id: String,
    operation_id: Option<ApiOperationId>,
    issues: Vec<ApiErrorIssue>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let error = ApiError {
        code,
        message: message.to_owned(),
        request_id,
        operation_id,
        issues,
    };
    if let Ok(body) = encode_api_error(&error) {
        json_response(status, body, schema_digest)
    } else {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        response
    }
}

pub(crate) fn json_response(
    status: StatusCode,
    body: Vec<u8>,
    schema_digest: HeaderValue,
) -> Response<Body> {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(API_VERSION_HEADER, HeaderValue::from_static("latest"));
    response
        .headers_mut()
        .insert(API_SCHEMA_HEADER, schema_digest);
    response
}

pub(crate) fn internal_error_response(
    request_id: String,
    operation_id: Option<ApiOperationId>,
    schema_digest: HeaderValue,
    message: &'static str,
) -> Response<Body> {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        ApiErrorCode::InternalContract,
        message,
        request_id,
        operation_id,
        Vec::new(),
        schema_digest,
    )
}

pub(crate) fn boundary_issues(error: BoundaryError) -> Vec<ApiErrorIssue> {
    match error {
        BoundaryError::BodyTooLarge { .. } => vec![issue("", "max_bytes")],
        BoundaryError::MalformedJson => vec![issue("", "json")],
        BoundaryError::Invalid { issues } => issues
            .into_iter()
            .map(|issue| ApiErrorIssue {
                path: issue.path,
                constraint: issue.constraint,
            })
            .collect(),
        BoundaryError::InvalidSchema(_)
        | BoundaryError::DecodeMismatch
        | BoundaryError::EncodeMismatch => Vec::new(),
    }
}

pub(crate) fn issue(path: &str, constraint: &str) -> ApiErrorIssue {
    ApiErrorIssue {
        path: path.to_owned(),
        constraint: constraint.to_owned(),
    }
}

pub(crate) fn has_json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value.to_str().is_ok_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
    })
}

pub(crate) fn current_time() -> Option<UnixMicros> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_micros();
    i64::try_from(micros).ok().map(UnixMicros::new)
}

pub(crate) fn request_identifier() -> String {
    let mut bytes = [0_u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut digest = Sha256::new();
        digest.update(b"meshspan.request-id.fallback.v1");
        digest.update(std::process::id().to_be_bytes());
        digest.update(sequence.to_be_bytes());
        digest.update(since_epoch.to_be_bytes());
        bytes.copy_from_slice(&digest.finalize()[..16]);
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format_uuid(bytes)
}
