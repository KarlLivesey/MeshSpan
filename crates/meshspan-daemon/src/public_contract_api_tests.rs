// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, Request, StatusCode};
use meshspan_api_contract::{HealthResponse, HealthStatus, generate_openapi};
use tower::ServiceExt as _;

use super::{ReadinessSource, public_contract_api_router};
use crate::api_http::{API_SCHEMA_HEADER, API_VERSION_HEADER};

#[tokio::test]
async fn health_and_openapi_share_the_exact_rust_authored_contract() -> Result<(), Box<dyn Error>> {
    let readiness = Arc::new(TestReadiness::new(HealthStatus::Ready));
    let router = public_contract_api_router(readiness.clone())?;
    let health_response = router
        .clone()
        .oneshot(Request::get("/api/latest/health").body(Body::empty())?)
        .await?;
    assert_eq!(health_response.status(), StatusCode::OK);
    assert_eq!(
        health_response.headers().get(API_VERSION_HEADER),
        Some(&HeaderValue::from_static("latest"))
    );
    let digest = health_response
        .headers()
        .get(API_SCHEMA_HEADER)
        .ok_or("missing schema digest")?
        .clone();
    let health: HealthResponse =
        serde_json::from_slice(&to_bytes(health_response.into_body(), 65_536).await?)?;
    assert_eq!(health.status, HealthStatus::Ready);
    assert_eq!(health.schema_digest, digest.to_str()?);

    readiness.set(HealthStatus::Degraded);
    let degraded_response = router
        .clone()
        .oneshot(Request::get("/api/latest/health").body(Body::empty())?)
        .await?;
    let degraded: HealthResponse =
        serde_json::from_slice(&to_bytes(degraded_response.into_body(), 65_536).await?)?;
    assert_eq!(degraded.status, HealthStatus::Degraded);

    let contract_response = router
        .oneshot(Request::get("/api/latest/openapi.json").body(Body::empty())?)
        .await?;
    assert_eq!(contract_response.status(), StatusCode::OK);
    assert_eq!(
        contract_response.headers().get(API_SCHEMA_HEADER),
        Some(&digest)
    );
    let contract: serde_json::Value =
        serde_json::from_slice(&to_bytes(contract_response.into_body(), 4 * 1_024 * 1_024).await?)?;
    assert_eq!(&contract, generate_openapi()?.value());
    Ok(())
}

struct TestReadiness(AtomicU8);

impl TestReadiness {
    fn new(status: HealthStatus) -> Self {
        Self(AtomicU8::new(encode_status(status)))
    }

    fn set(&self, status: HealthStatus) {
        self.0.store(encode_status(status), Ordering::Release);
    }
}

impl ReadinessSource for TestReadiness {
    fn status(&self) -> HealthStatus {
        match self.0.load(Ordering::Acquire) {
            0 => HealthStatus::Starting,
            1 => HealthStatus::Ready,
            _ => HealthStatus::Degraded,
        }
    }
}

const fn encode_status(status: HealthStatus) -> u8 {
    match status {
        HealthStatus::Starting => 0,
        HealthStatus::Ready => 1,
        HealthStatus::Degraded => 2,
    }
}
