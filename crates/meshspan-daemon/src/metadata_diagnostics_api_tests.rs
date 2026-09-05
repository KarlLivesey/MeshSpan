// SPDX-License-Identifier: GPL-2.0-only

use crate::runtime_observations::RuntimeObservationSource as _;
use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use meshspan_api_contract::{MetadataDiagnosticsResponse, RuntimeDiagnosticsResponse};
use meshspan_domain::UnixMicros;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tower::ServiceExt;

use crate::metadata_diagnostics::{DiagnosticsError as Error, MetadataDiagnosticsController};

#[derive(Default)]
struct Controller {
    collections: Arc<AtomicUsize>,
    revoked: AtomicBool,
    revoke_on_collect: bool,
    invalid_output: bool,
    runtime: Option<RuntimeDiagnosticsResponse>,
}

impl MetadataDiagnosticsController for Controller {
    fn collect_runtime(&self) -> Option<RuntimeDiagnosticsResponse> {
        self.runtime.clone()
    }
    fn authenticate(&self, headers: &HeaderMap, _now: UnixMicros) -> Result<(), Error> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(Error::Forbidden);
        }
        match headers
            .get("x-test-auth")
            .and_then(|value| value.to_str().ok())
        {
            Some("manager") => Ok(()),
            Some("user") => Err(Error::Forbidden),
            _ => Err(Error::Unauthenticated),
        }
    }

    fn collect(
        &self,
        _now: UnixMicros,
        check: &dyn Fn() -> Result<(), Error>,
    ) -> Result<MetadataDiagnosticsResponse, Error> {
        check()?;
        self.collections.fetch_add(1, Ordering::Relaxed);
        self.revoked
            .store(self.revoke_on_collect, Ordering::Release);
        let mut value = fixture()?;
        if self.invalid_output {
            value.daemon_version = "sensitive/raw/path".to_owned();
        }
        Ok(value)
    }
}

fn fixture() -> Result<MetadataDiagnosticsResponse, Error> {
    serde_json::from_value(serde_json::json!({
        "mesh_id": "11111111-1111-4111-8111-111111111111",
        "partition_id": "22222222-2222-4222-8222-222222222222",
        "node_id": "33333333-3333-4333-8333-333333333333",
        "daemon_version": "0.1.0", "collected_at_epoch_micros": 100,
        "revision_before": "1", "revision_after": "1", "consensus": null,
        "nodes": {"items": [], "truncated": false},
        "targets": {"items": [], "truncated": false},
        "recent_operations": {"items": [], "truncated": false}
    }))
    .map_err(|_| Error::Failed)
}

struct BlockingController {
    base: Controller,
    started: Arc<tokio::sync::Notify>,
    release: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

impl MetadataDiagnosticsController for BlockingController {
    fn authenticate(&self, headers: &HeaderMap, now: UnixMicros) -> Result<(), Error> {
        self.base.authenticate(headers, now)
    }

    fn collect(
        &self,
        now: UnixMicros,
        check: &dyn Fn() -> Result<(), Error>,
    ) -> Result<MetadataDiagnosticsResponse, Error> {
        let release = self.release.lock().map_err(|_| Error::Failed)?.take();
        if let Some(release) = release {
            self.started.notify_one();
            release.blocking_recv().map_err(|_| Error::Failed)?;
        }
        self.base.collect(now, check)
    }
}

#[tokio::test]
async fn metadata_diagnostics_cancellation_retains_admission_until_the_worker_stops()
-> Result<(), Box<dyn std::error::Error>> {
    let started = Arc::new(tokio::sync::Notify::new());
    let (release, released) = tokio::sync::oneshot::channel();
    let controller = BlockingController {
        base: Controller::default(),
        started: Arc::clone(&started),
        release: std::sync::Mutex::new(Some(released)),
    };
    let collections = Arc::clone(&controller.base.collections);
    let router = crate::metadata_diagnostics_api::router(controller)?;
    let request = || {
        Request::get("/api/latest/admin/diagnostics/metadata")
            .header("x-test-auth", "manager")
            .body(Body::empty())
    };
    let first = tokio::spawn(router.clone().oneshot(request()?));
    tokio::time::timeout(std::time::Duration::from_secs(5), started.notified()).await?;
    first.abort();
    assert!(first.await.is_err_and(|error| error.is_cancelled()));
    assert_eq!(
        router
            .clone()
            .oneshot(
                Request::get("/api/latest/admin/diagnostics/bundle")
                    .header("x-test-auth", "manager")
                    .body(Body::empty())?
            )
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(collections.load(Ordering::Relaxed), 0);
    release
        .send(())
        .map_err(|()| "worker stopped prematurely")?;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let response = router.clone().oneshot(request()?).await?;
            if response.status() == StatusCode::OK {
                break;
            }
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
    .await??;
    assert_eq!(collections.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn metadata_diagnostics_authenticates_before_collection_and_input_checks()
-> Result<(), Box<dyn std::error::Error>> {
    for (auth, query, body, expected, count) in [
        ("", "?raw=secret", "", StatusCode::UNAUTHORIZED, 0),
        ("user", "", "", StatusCode::FORBIDDEN, 0),
        ("manager", "?raw=secret", "", StatusCode::BAD_REQUEST, 0),
        (
            "manager",
            "",
            "unframed payload",
            StatusCode::BAD_REQUEST,
            0,
        ),
        ("manager", "", "", StatusCode::OK, 1),
    ] {
        let controller = Controller::default();
        let collections = Arc::clone(&controller.collections);
        let response = crate::metadata_diagnostics_api::router(controller)?
            .oneshot(
                Request::get(format!("/api/latest/admin/diagnostics/metadata{query}"))
                    .header("x-test-auth", auth)
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(response.status(), expected);
        assert_eq!(collections.load(Ordering::Relaxed), count);
        assert_eq!(response.headers()["cache-control"], "no-store");
        if expected == StatusCode::OK {
            assert_eq!(
                response.headers()["content-disposition"],
                "attachment; filename=\"meshspan-metadata-diagnostics.json\""
            );
            let bytes = to_bytes(response.into_body(), 262_144).await?;
            assert_eq!(
                serde_json::from_slice::<MetadataDiagnosticsResponse>(&bytes)?,
                fixture()?
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn metadata_diagnostics_suppresses_output_after_revocation_or_contract_failure()
-> Result<(), Box<dyn std::error::Error>> {
    for (revoke, invalid, expected) in [
        (true, false, StatusCode::FORBIDDEN),
        (false, true, StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let controller = Controller {
            revoke_on_collect: revoke,
            invalid_output: invalid,
            ..Controller::default()
        };
        let response = crate::metadata_diagnostics_api::router(controller)?
            .oneshot(
                Request::get("/api/latest/admin/diagnostics/metadata")
                    .header("x-test-auth", "manager")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), expected);
        let bytes = to_bytes(response.into_body(), 4096).await?;
        let body = std::str::from_utf8(&bytes)?;
        assert!(!body.contains("sensitive/raw/path"));
        assert!(!body.contains("revision_before"));
    }
    Ok(())
}

#[tokio::test]
async fn diagnostic_bundle_shares_authentication_and_validates_runtime_output()
-> Result<(), Box<dyn std::error::Error>> {
    for (auth, query, invalid, revoke, expected) in [
        ("", "?unsafe=true", false, false, StatusCode::UNAUTHORIZED),
        ("user", "", false, false, StatusCode::FORBIDDEN),
        (
            "manager",
            "?unsafe=true",
            false,
            false,
            StatusCode::BAD_REQUEST,
        ),
        (
            "manager",
            "",
            true,
            false,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        ("manager", "", false, true, StatusCode::FORBIDDEN),
        ("manager", "", false, false, StatusCode::OK),
    ] {
        let observations = crate::runtime_observations::RuntimeObservations::default();
        let mut runtime = observations.snapshot().ok_or("snapshot missing")?.project();
        if invalid {
            runtime.dropped_updates.0 = "18446744073709551616".to_owned();
        }
        let controller = Controller {
            runtime: Some(runtime.clone()),
            revoke_on_collect: revoke,
            ..Controller::default()
        };
        let response = crate::metadata_diagnostics_api::router(controller)?
            .oneshot(
                Request::get(format!("/api/latest/admin/diagnostics/bundle{query}"))
                    .header("x-test-auth", auth)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), expected);
        assert_eq!(response.headers()["cache-control"], "no-store");
        if expected == StatusCode::OK {
            assert_eq!(
                response.headers()["content-disposition"],
                "attachment; filename=\"meshspan-diagnostics.json\""
            );
            let bytes = to_bytes(response.into_body(), 524_288).await?;
            let bundle: meshspan_api_contract::DiagnosticsBundleResponse =
                serde_json::from_slice(&bytes)?;
            assert_eq!(bundle.metadata, fixture()?);
            assert_eq!(bundle.runtime, Some(runtime));
        }
    }
    Ok(())
}
