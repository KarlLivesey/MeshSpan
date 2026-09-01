// SPDX-License-Identifier: GPL-2.0-only

use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use meshspan_api_contract::{
    ApiError, ListVolumesQuery, ListVolumesResponse, NamespaceRight, VolumeId, VolumeState,
    VolumeSummary,
};
use meshspan_domain::UnixMicros;
use tower::ServiceExt;

use crate::{VolumeInventoryController, VolumeInventoryError, volume_inventory_api_router};

#[tokio::test]
async fn endpoint_returns_one_validated_page_and_exact_query()
-> Result<(), Box<dyn std::error::Error>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let router = volume_inventory_api_router(FakeController {
        outcome: FakeOutcome::Page(page(None)?),
        seen: Arc::clone(&seen),
    })?;
    let response = router
        .oneshot(
            Request::get("/api/latest/volumes?limit=1&cursor=v1.vol.aa.bb").body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16_384).await?;
    let response: ListVolumesResponse = serde_json::from_slice(&body)?;
    assert_eq!(response.volumes[0].name, "Shared files");
    let seen = seen.lock().map_err(|_| "poisoned query evidence")?;
    assert_eq!(seen[0].limit, Some(1));
    assert_eq!(
        seen[0]
            .cursor
            .as_ref()
            .map(meshspan_api_contract::VolumeCursor::as_str),
        Some("v1.vol.aa.bb")
    );
    Ok(())
}

#[tokio::test]
async fn endpoint_rejects_ambiguous_queries_before_controller_work()
-> Result<(), Box<dyn std::error::Error>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let router = volume_inventory_api_router(FakeController {
        outcome: FakeOutcome::Page(page(None)?),
        seen: Arc::clone(&seen),
    })?;
    for uri in [
        "/api/latest/volumes?limit=0",
        "/api/latest/volumes?limit=1&limit=2",
        "/api/latest/volumes?cursor=%GG",
        "/api/latest/volumes?unknown=true",
    ] {
        let response = router
            .clone()
            .oneshot(Request::get(uri).body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    assert!(
        seen.lock()
            .map_err(|_| "poisoned query evidence")?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn endpoint_maps_closed_failures_without_leaking_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    for (error, expected) in [
        (VolumeInventoryError::Rejected, StatusCode::UNAUTHORIZED),
        (
            VolumeInventoryError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            VolumeInventoryError::InvalidRequest,
            StatusCode::BAD_REQUEST,
        ),
        (
            VolumeInventoryError::Failed,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ] {
        let response = volume_inventory_api_router(FakeController {
            outcome: FakeOutcome::Error(error),
            seen: Arc::new(Mutex::new(Vec::new())),
        })?
        .oneshot(Request::get("/api/latest/volumes").body(Body::empty())?)
        .await?;
        assert_eq!(response.status(), expected);
        let body = to_bytes(response.into_body(), 16_384).await?;
        let error: ApiError = serde_json::from_slice(&body)?;
        assert!(!error.message.contains("credential"));
    }
    Ok(())
}

#[derive(Clone)]
struct FakeController {
    outcome: FakeOutcome,
    seen: Arc<Mutex<Vec<ListVolumesQuery>>>,
}

impl VolumeInventoryController for FakeController {
    fn list_volumes(
        &mut self,
        _headers: &axum::http::HeaderMap,
        query: ListVolumesQuery,
        _now: UnixMicros,
    ) -> Result<ListVolumesResponse, VolumeInventoryError> {
        self.seen
            .lock()
            .map_err(|_| VolumeInventoryError::Unavailable)?
            .push(query);
        match &self.outcome {
            FakeOutcome::Page(page) => Ok(page.clone()),
            FakeOutcome::Error(error) => Err(*error),
        }
    }
}

#[derive(Clone)]
enum FakeOutcome {
    Page(ListVolumesResponse),
    Error(VolumeInventoryError),
}

fn page(next_page_url: Option<String>) -> Result<ListVolumesResponse, Box<dyn std::error::Error>> {
    Ok(ListVolumesResponse {
        volumes: vec![VolumeSummary {
            volume_id: VolumeId::from_uuid_bytes(versioned(1)).ok_or("invalid volume")?,
            name: "Shared files".to_owned(),
            state: VolumeState::Active,
            effective_rights: vec![
                NamespaceRight::Traverse,
                NamespaceRight::List,
                NamespaceRight::ReadData,
            ],
            created_at_epoch_micros: 10,
            revision: 2,
        }],
        next_page_url,
    })
}

fn versioned(seed: u8) -> [u8; 16] {
    let mut value = [seed; 16];
    value[6] = 0x41;
    value[8] = 0x81;
    value
}
