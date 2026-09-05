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
    BackupScheduleResponse, ConfigureBackupScheduleRequest, ConfigureBackupScheduleResponse,
};
use meshspan_domain::UnixMicros;
use tower::ServiceExt;

use crate::{BackupScheduleController, BackupScheduleError, backup_schedule_api_router};

#[tokio::test]
async fn backup_policy_rejection_does_not_poll_the_body() -> Result<(), Box<dyn std::error::Error>>
{
    let polled = Arc::new(AtomicBool::new(false));
    let response = backup_schedule_api_router(Controller {
        reject_commit: false,
        invalid_receipt: false,
    })?
    .oneshot(
        Request::put("/api/latest/admin/backups/schedule")
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
async fn backup_policy_http_validates_body_and_outgoing_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    for (body, expected) in [
        (serde_json::to_string(&request())?, StatusCode::OK),
        ("not-json".to_owned(), StatusCode::BAD_REQUEST),
        (" ".repeat(2049), StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let response = backup_schedule_api_router(Controller {
            reject_commit: false,
            invalid_receipt: false,
        })?
        .oneshot(http_request(body)?)
        .await?;
        assert_eq!(response.status(), expected);
    }
    let rejected = backup_schedule_api_router(Controller {
        reject_commit: true,
        invalid_receipt: false,
    })?
    .oneshot(http_request(serde_json::to_string(&request())?)?)
    .await?;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    let invalid = backup_schedule_api_router(Controller {
        reject_commit: false,
        invalid_receipt: true,
    })?
    .oneshot(http_request(serde_json::to_string(&request())?)?)
    .await?;
    assert_eq!(invalid.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}

fn http_request(body: String) -> Result<Request<Body>, axum::http::Error> {
    Request::put("/api/latest/admin/backups/schedule")
        .header("content-type", "application/json")
        .header("x-test-auth", "yes")
        .body(Body::from(body))
}

fn request() -> serde_json::Value {
    serde_json::json!({ "operation_id": "01900000-0000-7000-8000-000000000001",
        "expected_sequence": 0, "policy": { "enabled": true, "interval_seconds": 3600,
            "retained_generations": 7, "minimum_verified_copies": 2, "minimum_independent_copies": 1 } })
}

struct Controller {
    reject_commit: bool,
    invalid_receipt: bool,
}

impl BackupScheduleController for Controller {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        _now: UnixMicros,
    ) -> Result<(), BackupScheduleError> {
        (headers
            .get("x-test-auth")
            .is_some_and(|value| value == "yes"))
        .then_some(())
        .ok_or(BackupScheduleError::Unauthenticated)
    }

    fn read(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<BackupScheduleResponse, BackupScheduleError> {
        self.authenticate(headers, now)?;
        Ok(BackupScheduleResponse {
            partition_id: "01900000-0000-7000-8000-000000000002".to_owned(),
            schedule: None,
        })
    }

    fn configure(
        &mut self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: ConfigureBackupScheduleRequest,
    ) -> Result<ConfigureBackupScheduleResponse, BackupScheduleError> {
        self.authenticate(headers, now)?;
        if self.reject_commit {
            return Err(BackupScheduleError::Unauthenticated);
        }
        Ok(ConfigureBackupScheduleResponse {
            operation_id: request.operation_id,
            sequence: 1,
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
