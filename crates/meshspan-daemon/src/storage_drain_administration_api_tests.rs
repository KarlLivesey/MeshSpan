// SPDX-License-Identifier: GPL-2.0-only

use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    BeginStorageDrainRequest, BeginStorageDrainResponse, ListStorageDrainsQuery,
    ListStorageDrainsResponse, StorageDrainScope, StorageDrainState, StorageDrainSummary,
};
use meshspan_domain::{PrincipalId, UnixMicros};
use tower::ServiceExt;

use crate::{
    BrowserRequestProtection, IdentityAdministrator, StorageDrainAdministrationController,
    StorageDrainAdministrationError, storage_drain_administration_api_router,
};

const OPERATION_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

#[tokio::test]
async fn unauthenticated_drain_is_rejected_before_its_body_is_consumed()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let router = storage_drain_administration_api_router(FakeController {
        calls: Arc::clone(&calls),
    })?;
    let response = router
        .oneshot(
            Request::post("/api/latest/admin/storage-drains")
                .header("content-type", "application/json")
                .body(Body::from("{"))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        calls.lock().map_err(|_| "poisoned calls")?.as_slice(),
        ["authenticate"]
    );
    Ok(())
}

#[tokio::test]
async fn manager_can_admit_list_and_resolve_the_same_exact_drain()
-> Result<(), Box<dyn std::error::Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let router = storage_drain_administration_api_router(FakeController {
        calls: Arc::clone(&calls),
    })?;
    let request = BeginStorageDrainRequest {
        operation_id: serde_json::from_str(&format!("\"{OPERATION_ID}\""))?,
        scope: StorageDrainScope::Node {
            node_id: "223e4567-e89b-42d3-a456-426614174000".to_owned(),
            incarnation: "7".to_owned(),
        },
        allow_temporary_degraded: true,
        cleanup_requested: false,
    };
    let admitted = router
        .clone()
        .oneshot(
            Request::post("/api/latest/admin/storage-drains")
                .header("content-type", "application/json")
                .header("x-test-auth", "accepted")
                .body(Body::from(serde_json::to_vec(&request)?))?,
        )
        .await?;
    assert_eq!(admitted.status(), StatusCode::ACCEPTED);
    let admitted: BeginStorageDrainResponse =
        serde_json::from_slice(&to_bytes(admitted.into_body(), 16_384).await?)?;
    assert_eq!(admitted.operation_id, request.operation_id);
    assert_eq!(admitted.drain, summary());

    let listed = router
        .clone()
        .oneshot(
            Request::get("/api/latest/admin/storage-drains?limit=1")
                .header("x-test-auth", "accepted")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed: ListStorageDrainsResponse =
        serde_json::from_slice(&to_bytes(listed.into_body(), 16_384).await?)?;
    assert_eq!(listed.drains, vec![summary()]);

    let resolved = router
        .oneshot(
            Request::get(format!("/api/latest/admin/storage-drains/{OPERATION_ID}"))
                .header("x-test-auth", "accepted")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(resolved.status(), StatusCode::OK);
    let resolved: StorageDrainSummary =
        serde_json::from_slice(&to_bytes(resolved.into_body(), 16_384).await?)?;
    assert_eq!(resolved, summary());
    assert_eq!(
        calls.lock().map_err(|_| "poisoned calls")?.as_slice(),
        [
            "authenticate",
            "begin",
            "authenticate",
            "list",
            "authenticate",
            "get"
        ]
    );
    Ok(())
}

struct FakeController {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl StorageDrainAdministrationController for FakeController {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        _protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, StorageDrainAdministrationError> {
        self.record("authenticate")?;
        if headers
            .get("x-test-auth")
            .and_then(|value| value.to_str().ok())
            != Some("accepted")
        {
            return Err(StorageDrainAdministrationError::Unauthenticated);
        }
        Ok(IdentityAdministrator {
            principal_id: PrincipalId::from_bytes([7; 16])
                .map_err(|_| StorageDrainAdministrationError::Failed)?,
            now,
        })
    }

    fn begin_storage_drain(
        &mut self,
        _administrator: IdentityAdministrator,
        request: BeginStorageDrainRequest,
    ) -> Result<BeginStorageDrainResponse, StorageDrainAdministrationError> {
        self.record("begin")?;
        Ok(BeginStorageDrainResponse {
            operation_id: request.operation_id,
            drain: summary(),
        })
    }

    fn get_storage_drain(
        &self,
        _administrator: IdentityAdministrator,
        drain_id: &str,
    ) -> Result<StorageDrainSummary, StorageDrainAdministrationError> {
        self.record("get")?;
        (drain_id == OPERATION_ID)
            .then(summary)
            .ok_or(StorageDrainAdministrationError::NotFound)
    }

    fn list_storage_drains(
        &self,
        _administrator: IdentityAdministrator,
        query: ListStorageDrainsQuery,
    ) -> Result<ListStorageDrainsResponse, StorageDrainAdministrationError> {
        self.record("list")?;
        if query.limit != Some(1) {
            return Err(StorageDrainAdministrationError::InvalidInput);
        }
        Ok(ListStorageDrainsResponse {
            drains: vec![summary()],
            next_page_url: None,
        })
    }
}

impl FakeController {
    fn record(&self, call: &'static str) -> Result<(), StorageDrainAdministrationError> {
        self.calls
            .lock()
            .map_err(|_| StorageDrainAdministrationError::Unavailable)?
            .push(call);
        Ok(())
    }
}

fn summary() -> StorageDrainSummary {
    StorageDrainSummary {
        drain_id: OPERATION_ID.to_owned(),
        scope: StorageDrainScope::Node {
            node_id: "223e4567-e89b-42d3-a456-426614174000".to_owned(),
            incarnation: "7".to_owned(),
        },
        allow_temporary_degraded: true,
        cleanup_requested: false,
        state: StorageDrainState::Evacuating,
        requested_at_epoch_micros: 1,
        safe_at_epoch_micros: None,
        revision: 1,
        status_url: format!("/api/latest/admin/storage-drains/{OPERATION_ID}"),
    }
}
