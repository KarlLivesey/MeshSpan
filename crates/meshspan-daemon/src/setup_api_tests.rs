// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use meshspan_api_contract::{SetupState, SetupStatusResponse};
use meshspan_domain::{ClaimId, NodeId, OperationId, UnixMicros};
use meshspan_metadata::{LocalDatabase, LocalSetupKind, NewLocalClaim, NewLocalSetup};
use tempfile::tempdir;
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

#[tokio::test]
async fn durable_claim_and_setup_evidence_drive_status_after_each_transition()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let mut database = LocalDatabase::open(
        &directory.path().join("local.sqlite3"),
        NodeId::from_bytes([1; 16])?,
        UnixMicros::new(1),
    )?;
    let claim_id = ClaimId::from_bytes([2; 16])?;
    database.create_local_claim(NewLocalClaim {
        claim_id,
        node_public_key_fingerprint: [3; 32],
        secret_digest: [4; 32],
        created_at: UnixMicros::new(10),
    })?;
    let snapshot = Arc::new(SetupStateSnapshot::new(SetupState::Configuring));
    let router = setup_api_router(Arc::clone(&snapshot))?;
    assert_eq!(snapshot.reconcile(&database)?, SetupState::ClaimRequired);
    assert_status(&router, SetupState::ClaimRequired).await?;

    let setup = NewLocalSetup {
        operation_id: OperationId::from_bytes([5; 16])?,
        claim_id,
        claim_secret_digest: [4; 32],
        kind: LocalSetupKind::CreateMesh,
        request_digest: [6; 32],
        created_at: UnixMicros::new(11),
    };
    database.prepare_local_setup(setup)?;
    assert_eq!(snapshot.reconcile(&database)?, SetupState::Configuring);
    database.record_local_setup_authority_commit(
        setup.operation_id,
        [7; 32],
        UnixMicros::new(20),
    )?;
    assert_eq!(snapshot.reconcile(&database)?, SetupState::Configuring);
    database.complete_local_setup(
        setup.operation_id,
        setup.claim_id,
        setup.claim_secret_digest,
        UnixMicros::new(30),
    )?;
    assert_eq!(snapshot.reconcile(&database)?, SetupState::Configured);
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
