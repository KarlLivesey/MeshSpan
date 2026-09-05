// SPDX-License-Identifier: GPL-2.0-only

use crate::metrics_exporter_service::{
    MetricsAccess, MetricsError as Error, MetricsExporterController,
};
use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, Request, StatusCode},
};
use meshspan_api_contract::{
    ConfigureMetricsExporterRequest, ConfigureMetricsExporterResponse, MetricsExporterResponse,
};
use meshspan_contracts::{RuntimeMetric, RuntimeMetricSnapshot};
use meshspan_domain::UnixMicros;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tower::ServiceExt;

#[derive(Default)]
struct Controller {
    enabled: AtomicBool,
    collections: Arc<AtomicUsize>,
    revoke_on_collect: bool,
    invalid_configuration: bool,
    release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    started: tokio::sync::Notify,
}

impl MetricsExporterController for Arc<Controller> {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        _now: UnixMicros,
        access: MetricsAccess,
    ) -> Result<(), Error> {
        let role = headers
            .get("x-test-auth")
            .and_then(|value| value.to_str().ok())
            .ok_or(Error::Unauthenticated)?;
        match access {
            MetricsAccess::ReadConfiguration | MetricsAccess::Configure if role == "manager" => {
                Ok(())
            }
            MetricsAccess::Scrape if role == "reader" && self.enabled.load(Ordering::Acquire) => {
                Ok(())
            }
            _ => Err(Error::Forbidden),
        }
    }
    fn configuration(&self) -> Result<MetricsExporterResponse, Error> {
        if self.invalid_configuration {
            return serde_json::from_value(
                serde_json::json!({"configuration": {"sequence": 0, "committed_revision": 2,
                "policy": {"enabled": false, "allowed_principals": []}}}),
            )
            .map_err(|_| Error::Failed);
        }
        Ok(MetricsExporterResponse {
            configuration: None,
        })
    }
    fn configure(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        request: ConfigureMetricsExporterRequest,
    ) -> Result<ConfigureMetricsExporterResponse, Error> {
        self.authenticate(headers, now, MetricsAccess::Configure)?;
        self.enabled
            .store(request.policy.enabled, Ordering::Release);
        Ok(ConfigureMetricsExporterResponse {
            operation_id: request.operation_id,
            sequence: 1,
            committed_revision: 2,
        })
    }
    fn collect(&self) -> Result<RuntimeMetricSnapshot, Error> {
        self.collections.fetch_add(1, Ordering::Relaxed);
        if let Some(release) = self.release.lock().map_err(|_| Error::Failed)?.take() {
            self.started.notify_one();
            release.blocking_recv().map_err(|_| Error::Failed)?;
        }
        if self.revoke_on_collect {
            self.enabled.store(false, Ordering::Release);
        }
        RuntimeMetricSnapshot::new(vec![RuntimeMetric::TargetProbePasses(2)])
            .map_err(|_| Error::Failed)
    }
}

fn request(
    method: &str,
    endpoint: &str,
    role: Option<&str>,
    body: Vec<u8>,
) -> Result<Request<Body>, axum::http::Error> {
    let mut request = Request::builder()
        .method(method)
        .uri(endpoint)
        .header("content-type", "application/json");
    if let Some(role) = role {
        request = request.header("x-test-auth", role);
    }
    request.body(Body::from(body))
}

#[tokio::test]
async fn metrics_scrape_authenticates_before_collection_and_does_not_grant_managers_implicit_access()
-> Result<(), Box<dyn std::error::Error>> {
    let controller = Arc::new(Controller::default());
    let router = crate::metrics_exporter_api::router(Arc::clone(&controller))?;
    for (endpoint, role, expected) in [
        (
            "/api/latest/metrics?expensive=true",
            None,
            StatusCode::UNAUTHORIZED,
        ),
        ("/api/latest/metrics", Some("reader"), StatusCode::FORBIDDEN),
        (
            "/api/latest/metrics",
            Some("manager"),
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(
            router
                .clone()
                .oneshot(request("GET", endpoint, role, vec![])?)
                .await?
                .status(),
            expected
        );
    }
    assert_eq!(controller.collections.load(Ordering::Relaxed), 0);
    controller.enabled.store(true, Ordering::Release);
    let response = router
        .clone()
        .oneshot(request(
            "GET",
            "/api/latest/metrics?all=true",
            Some("reader"),
            vec![],
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = router
        .oneshot(request(
            "GET",
            "/api/latest/metrics",
            Some("reader"),
            vec![],
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        crate::OPENMETRICS_CONTENT_TYPE
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let body = to_bytes(response.into_body(), crate::MAX_OPENMETRICS_BYTES).await?;
    assert_eq!(
        body.as_ref(),
        crate::encode_openmetrics(&RuntimeMetricSnapshot::new(vec![
            RuntimeMetric::TargetProbePasses(2)
        ])?)?
    );
    assert_eq!(controller.collections.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn metrics_scrape_revalidates_grants_after_collection_and_rejects_invalid_configuration_output()
-> Result<(), Box<dyn std::error::Error>> {
    let controller = Arc::new(Controller {
        enabled: AtomicBool::new(true),
        revoke_on_collect: true,
        invalid_configuration: true,
        ..Controller::default()
    });
    let router = crate::metrics_exporter_api::router(controller)?;
    let rejected = router
        .clone()
        .oneshot(request(
            "GET",
            "/api/latest/metrics",
            Some("reader"),
            vec![],
        )?)
        .await?;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    let invalid = router
        .oneshot(request(
            "GET",
            "/api/latest/admin/metrics/exporter",
            Some("manager"),
            vec![],
        )?)
        .await?;
    assert_eq!(invalid.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}

#[tokio::test]
async fn metrics_configuration_rejects_unauthenticated_oversized_and_malformed_bodies()
-> Result<(), Box<dyn std::error::Error>> {
    let controller = Arc::new(Controller::default());
    let router = crate::metrics_exporter_api::router(Arc::clone(&controller))?;
    let endpoint = "/api/latest/admin/metrics/exporter";
    for (role, body, expected) in [
        (None, b"invalid".to_vec(), StatusCode::UNAUTHORIZED),
        (Some("reader"), b"invalid".to_vec(), StatusCode::FORBIDDEN),
        (Some("manager"), b"{}".to_vec(), StatusCode::BAD_REQUEST),
        (
            Some("manager"),
            vec![0; meshspan_api_contract::MAX_CONFIGURE_METRICS_EXPORTER_BYTES + 1],
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        assert_eq!(
            router
                .clone()
                .oneshot(request("PUT", endpoint, role, body)?)
                .await?
                .status(),
            expected
        );
    }
    let value = serde_json::json!({"operation_id": "10000000-0000-4000-8000-000000000001", "expected_sequence": 0,
        "policy": {"enabled": true, "allowed_principals": ["10000000-0000-4000-8000-000000000002"]}});
    let response = router
        .oneshot(request(
            "PUT",
            endpoint,
            Some("manager"),
            serde_json::to_vec(&value)?,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let receipt: ConfigureMetricsExporterResponse =
        serde_json::from_slice(&to_bytes(response.into_body(), 8192).await?)?;
    assert_eq!(receipt.sequence, 1);
    assert_eq!(receipt.committed_revision, 2);
    assert!(controller.enabled.load(Ordering::Acquire));
    Ok(())
}

#[tokio::test]
async fn cancelled_metrics_collection_retains_worker_admission_until_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let (send, receive) = tokio::sync::oneshot::channel();
    let controller = Arc::new(Controller {
        enabled: AtomicBool::new(true),
        release: Mutex::new(Some(receive)),
        ..Controller::default()
    });
    let router = crate::metrics_exporter_api::router(Arc::clone(&controller))?;
    let started = controller.started.notified();
    let active = tokio::spawn(router.clone().oneshot(request(
        "GET",
        "/api/latest/metrics",
        Some("reader"),
        vec![],
    )?));
    tokio::time::timeout(std::time::Duration::from_secs(2), started).await?;
    active.abort();
    assert!(active.await.is_err());
    let busy = router
        .clone()
        .oneshot(request(
            "GET",
            "/api/latest/admin/metrics/exporter",
            Some("manager"),
            vec![],
        )?)
        .await?;
    assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
    send.send(())
        .map_err(|()| "collector ended before release")?;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let response = router
                .clone()
                .oneshot(request(
                    "GET",
                    "/api/latest/metrics",
                    Some("reader"),
                    vec![],
                )?)
                .await?;
            if response.status() != StatusCode::SERVICE_UNAVAILABLE {
                assert_eq!(response.status(), StatusCode::OK);
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    assert_eq!(controller.collections.load(Ordering::Relaxed), 2);
    Ok(())
}
