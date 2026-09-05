// SPDX-License-Identifier: GPL-2.0-only

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};

use axum::body::{Body, Bytes, HttpBody, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    ConfigureBackupDestinationRequest, ConfigureBackupDestinationResponse,
    ListBackupDestinationsQuery, ListBackupDestinationsResponse,
};
use meshspan_domain::UnixMicros;
use tower::ServiceExt;

use crate::{BackupDestinationController, BackupDestinationError, backup_destination_api_router};

#[tokio::test]
async fn backup_destination_rejection_does_not_poll_the_body()
-> Result<(), Box<dyn std::error::Error>> {
    let polled = Arc::new(AtomicBool::new(false));
    let response = backup_destination_api_router(Controller {
        reject_commit: false,
        invalid_receipt: false,
    })?
    .oneshot(
        Request::put("/api/latest/admin/backups/destinations")
            .body(Body::new(BodyProbe(Arc::clone(&polled))))?,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!polled.load(Ordering::SeqCst));
    let error: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    assert_eq!(error["code"], "unauthenticated");
    Ok(())
}

#[tokio::test]
async fn backup_destination_http_validates_body_and_outgoing_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    for (body, expected) in [
        (serde_json::to_string(&request())?, StatusCode::OK),
        ("not-json".to_owned(), StatusCode::BAD_REQUEST),
        (" ".repeat(2049), StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let response = backup_destination_api_router(Controller {
            reject_commit: false,
            invalid_receipt: false,
        })?
        .oneshot(http_request(body)?)
        .await?;
        assert_eq!(response.status(), expected);
    }
    let rejected = backup_destination_api_router(Controller {
        reject_commit: true,
        invalid_receipt: false,
    })?
    .oneshot(http_request(serde_json::to_string(&request())?)?)
    .await?;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    let invalid = backup_destination_api_router(Controller {
        reject_commit: false,
        invalid_receipt: true,
    })?
    .oneshot(http_request(serde_json::to_string(&request())?)?)
    .await?;
    assert_eq!(invalid.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}

fn http_request(body: String) -> Result<Request<Body>, axum::http::Error> {
    Request::put("/api/latest/admin/backups/destinations")
        .header("content-type", "application/json")
        .header("x-test-auth", "yes")
        .body(Body::from(body))
}

#[tokio::test]
async fn backup_destination_inventory_authenticates_before_query_parsing()
-> Result<(), Box<dyn std::error::Error>> {
    for (query, authenticated, expected) in [
        ("?limit=0", false, StatusCode::UNAUTHORIZED),
        ("?limit=0", true, StatusCode::BAD_REQUEST),
        ("?limit=1&limit=2", true, StatusCode::BAD_REQUEST),
        ("?cursor=%zz", true, StatusCode::BAD_REQUEST),
        ("?unexpected=1", true, StatusCode::BAD_REQUEST),
        ("?limit=1", true, StatusCode::OK),
    ] {
        let mut request = Request::get(format!("/api/latest/admin/backups/destinations{query}"));
        if authenticated {
            request = request.header("x-test-auth", "yes");
        }
        let response = backup_destination_api_router(Controller {
            reject_commit: false,
            invalid_receipt: false,
        })?
        .oneshot(request.body(Body::empty())?)
        .await?;
        assert_eq!(response.status(), expected, "query {query}");
    }
    Ok(())
}

fn request() -> serde_json::Value {
    serde_json::json!({ "operation_id": "01900000-0000-7000-8000-000000000001",
        "destination_id": "01900000-0000-7000-8000-000000000002", "expected_revision": 0,
        "name": "Recovery", "target_id": "01900000-0000-7000-8000-000000000003",
        "target_generation": "1", "enabled": true })
}

struct Controller {
    reject_commit: bool,
    invalid_receipt: bool,
}

impl BackupDestinationController for Controller {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        _mutation: bool,
        _now: UnixMicros,
    ) -> Result<(), BackupDestinationError> {
        (headers
            .get("x-test-auth")
            .is_some_and(|value| value == "yes"))
        .then_some(())
        .ok_or(BackupDestinationError::Unauthenticated)
    }

    fn list(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        _query: ListBackupDestinationsQuery,
    ) -> Result<ListBackupDestinationsResponse, BackupDestinationError> {
        self.authenticate(headers, false, now)?;
        Ok(ListBackupDestinationsResponse {
            destinations: Vec::new(),
            next_page_url: None,
        })
    }

    fn configure(
        &mut self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: ConfigureBackupDestinationRequest,
    ) -> Result<ConfigureBackupDestinationResponse, BackupDestinationError> {
        self.authenticate(headers, false, now)?;
        if self.reject_commit {
            return Err(BackupDestinationError::Unauthenticated);
        }
        Ok(ConfigureBackupDestinationResponse {
            operation_id: request.operation_id,
            destination_id: request.destination_id,
            committed_revision: if self.invalid_receipt { 0 } else { 7 },
        })
    }
}

struct BodyProbe(Arc<AtomicBool>);

impl HttpBody for BodyProbe {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
        self.0.store(true, Ordering::SeqCst);
        Poll::Ready(None)
    }
}
