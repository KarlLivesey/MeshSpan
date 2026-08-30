// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use meshspan_api_contract::{SetupState, SetupStatusResponse};
use tower::ServiceExt;

use crate::{SetupStateSnapshot, setup_api_router};

#[tokio::test]
async fn anonymous_status_tracks_only_the_coarse_lifecycle_state()
-> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(SetupStateSnapshot::new(SetupState::ClaimRequired));
    let router = setup_api_router(Arc::clone(&state))?;
    assert_status(&router, SetupState::ClaimRequired).await?;
    state.store(SetupState::Configuring);
    assert_status(&router, SetupState::Configuring).await?;
    state.store(SetupState::Configured);
    assert_status(&router, SetupState::Configured).await
}

async fn assert_status(
    router: &axum::Router,
    expected: SetupState,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = router
        .clone()
        .oneshot(Request::get("/api/latest/setup/status").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("meshspan-api-version"),
        Some(&"latest".parse()?)
    );
    let schema = response
        .headers()
        .get("meshspan-api-schema")
        .ok_or("schema header missing")?
        .to_str()?;
    assert!(schema.starts_with("sha256:"));
    assert_eq!(schema.len(), 71);
    let bytes = to_bytes(response.into_body(), 1_024).await?;
    assert_eq!(
        serde_json::from_slice::<SetupStatusResponse>(&bytes)?,
        SetupStatusResponse { state: expected }
    );
    Ok(())
}
